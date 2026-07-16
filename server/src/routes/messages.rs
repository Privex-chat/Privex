// Message queue endpoints (docs 8.1/11). Sealed Sender: the authenticated
// caller's id is used ONLY for rate limiting - it is NEVER stored. The stored
// row has no sender, no message type, no read/delivery state.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;

use crate::auth::extract::AuthUser;
use crate::db::queries::message_queue;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::routes::valid_user_id;
use crate::state::AppState;
use crate::validate;

const ONE_HOUR: i64 = 3600;
const THIRTY_DAYS: i64 = 30 * 24 * 3600;
const SIXTY_DAYS: i64 = 60 * 24 * 3600;

/// Per-message TTL (docs 4.12): sender-chosen `ttl_seconds` clamped to
/// [1 hour, 60 days]; absent = 30-day default. Clamped, not rejected: an
/// out-of-range value degrades to the nearest enforced bound instead of
/// failing a send whose ratchet step has already been consumed client-side.
fn clamp_ttl(ttl_seconds: Option<i64>) -> i64 {
    ttl_seconds.unwrap_or(THIRTY_DAYS).clamp(ONE_HOUR, SIXTY_DAYS)
}

/// A random v4-shaped UUID for dropped cover-traffic responses (so the reply is
/// indistinguishable from a real enqueue).
fn random_message_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[derive(Deserialize)]
pub struct SendReq {
    recipient_id: String,
    content: String,            // base64 Sealed Sender blob
    csam_proof: Option<String>, // base64, image messages only
    ttl_seconds: Option<i64>,   // per-message TTL override (docs 4.12), clamped
}

#[derive(Serialize)]
pub struct SendResp {
    queued: bool,
    message_id: String,
    expires_at: i64,
}

pub async fn send(
    AuthUser(sender): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<SendReq>,
) -> Result<Json<SendResp>, ApiError> {
    // Rate limit per authenticated sender (docs 11: 120 / 60s). The sender id is
    // only ever a Redis HMAC key - never stored with the message.
    let allowed = rds::check_rate_limit(
        &st.redis,
        &st.config.redis_ns_key,
        "msgsend",
        &sender,
        120,
        60,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    if !allowed {
        return Err(ApiError::rate_limited());
    }

    if !valid_user_id(&body.recipient_id) {
        return Err(ApiError::bad_request());
    }

    let content = validate::validate_b64(&body.content, validate::MAX_CONTENT_B64_BYTES)?;
    let csam = match &body.csam_proof {
        Some(p) => Some(validate::validate_b64(p, validate::MAX_CSAM_PROOF_B64_BYTES)?),
        None => None,
    };

    let now = now_unix();
    let expires_at = now + clamp_ttl(body.ttl_seconds);

    // Cover traffic (docs 5.3): messages addressed to a non-existent mailbox are
    // silently dropped - stored nowhere - but the response is indistinguishable
    // from a real send so an observer can't tell cover from real.
    let recipient_exists =
        crate::db::queries::key_directory::user_exists(&st.db, &body.recipient_id)
            .await
            .map_err(|_| ApiError::internal())?;
    if !recipient_exists {
        return Ok(Json(SendResp {
            queued: true,
            message_id: random_message_id(),
            expires_at,
        }));
    }

    let message_id = message_queue::enqueue(
        &st.db,
        &body.recipient_id,
        &content,
        csam.as_deref(),
        now as i32,
        expires_at as i32,
        content.len() as i32,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    // Always enqueued (above). If the recipient is online, also push now - the
    // row stays in the DB until the recipient ACKs.
    let pushed = crate::ws::messages::message_json(
        &st.config.time_signing_key,
        &message_id.to_string(),
        STANDARD.encode(&content),
        now,
    );
    st.online.send(&body.recipient_id, pushed);

    Ok(Json(SendResp {
        queued: true,
        message_id: message_id.to_string(),
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct AckReq {
    message_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct AckResp {
    deleted: u64,
}

pub async fn ack(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<AckReq>,
) -> Result<Json<AckResp>, ApiError> {
    // Acks are cheap deletes but still per-request DB work; bound the call rate
    // (batching keeps legit clients far under this) and the batch size.
    crate::routes::rate_limit(&st, "msgack", &user, 200, 60).await?;
    if body.message_ids.len() > 500 {
        return Err(ApiError::bad_request());
    }
    let mut ids = Vec::with_capacity(body.message_ids.len());
    for s in &body.message_ids {
        ids.push(Uuid::parse_str(s).map_err(|_| ApiError::bad_request())?);
    }
    // Hard-delete; scoped to the caller's own mailbox.
    let deleted = message_queue::ack_messages(&st.db, &user, &ids)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(AckResp { deleted }))
}

#[cfg(test)]
mod tests {
    use super::{clamp_ttl, ONE_HOUR, SIXTY_DAYS, THIRTY_DAYS};

    #[test]
    fn ttl_defaults_and_clamps() {
        assert_eq!(clamp_ttl(None), THIRTY_DAYS); // absent → default
        assert_eq!(clamp_ttl(Some(6 * 3600)), 6 * 3600); // in range → as requested
        assert_eq!(clamp_ttl(Some(ONE_HOUR)), ONE_HOUR); // exact bounds pass
        assert_eq!(clamp_ttl(Some(SIXTY_DAYS)), SIXTY_DAYS);
        assert_eq!(clamp_ttl(Some(0)), ONE_HOUR); // below floor → floor
        assert_eq!(clamp_ttl(Some(-5)), ONE_HOUR); // negative → floor
        assert_eq!(clamp_ttl(Some(i64::MAX)), SIXTY_DAYS); // above cap → cap
    }
}
