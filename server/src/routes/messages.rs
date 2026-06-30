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

const THIRTY_DAYS: i64 = 30 * 24 * 3600;

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
}

#[derive(Serialize)]
pub struct SendResp {
    queued: bool,
    message_id: String,
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
        &st.config.session_hmac_key,
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

    let content = STANDARD
        .decode(&body.content)
        .map_err(|_| ApiError::bad_request())?;
    if content.is_empty() {
        return Err(ApiError::bad_request());
    }
    let csam = match &body.csam_proof {
        Some(p) => Some(STANDARD.decode(p).map_err(|_| ApiError::bad_request())?),
        None => None,
    };

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
        }));
    }

    let now = now_unix();
    let message_id = message_queue::enqueue(
        &st.db,
        &body.recipient_id,
        &content,
        csam.as_deref(),
        now as i32,
        (now + THIRTY_DAYS) as i32,
        content.len() as i32,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    // Always enqueued (above). If the recipient is online, also push now - the
    // row stays in the DB until the recipient ACKs.
    let pushed =
        crate::ws::messages::message_json(&message_id.to_string(), STANDARD.encode(&content), now);
    st.online.send(&body.recipient_id, pushed);

    Ok(Json(SendResp {
        queued: true,
        message_id: message_id.to_string(),
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
