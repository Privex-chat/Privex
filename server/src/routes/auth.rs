// Authentication endpoints (docs 4.9 / 11). No request bodies, user_ids, IPs,
// or tokens are ever logged.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::extract::AuthUser;
use crate::auth::{sig, token};
use fips204::ml_dsa_65;
use crate::crypto::pow_difficulty::{self, compute_difficulty, record_challenge_request, unix_ts_ms};
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::routes::valid_user_id;
use crate::state::AppState;
use crate::validate;
use sqlx::types::Uuid;

// --- POST /auth/pow_challenge ---

/// Argon2id Layer-2 parameters echoed to the client (docs 8.5.1). Absent on
/// legacy SHA-only challenges (rollback mode) - old clients ignore the field,
/// new clients solve legacy challenges when it is absent.
#[derive(Serialize)]
pub struct PowArgonResp {
    m_cost_kib: u32,
    t_cost: u32,
    difficulty: u32,
}

#[derive(Serialize)]
pub struct PowChallengeResp {
    challenge_id: String,
    challenge: String, // hex
    /// SHA-256 leading-zero-bit target. For hybrid challenges this is the
    /// PRE-FILTER difficulty (already reduced by the argon bits, so total
    /// nonce-grinding work stays ~2^final).
    difficulty: u32,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    argon: Option<PowArgonResp>,
}

pub async fn pow_challenge(State(st): State<AppState>) -> Result<Json<PowChallengeResp>, ApiError> {
    // Endpoint-wide cap: unauthenticated Redis write per call. This cap also
    // bounds the server's own hybrid VERIFICATION cost - every verify must
    // first consume a challenge issued here, so at most `limit` Argon2id
    // evaluations per window can ever be forced on the server.
    crate::routes::rate_limit(&st, "powchal", "global", 60, 60).await?;
    let mut data = [0u8; 32];
    getrandom::getrandom(&mut data).map_err(|_| ApiError::internal())?;
    let mut id_raw = [0u8; 16];
    getrandom::getrandom(&mut id_raw).map_err(|_| ApiError::internal())?;
    id_raw[6] = (id_raw[6] & 0x0f) | 0x40;
    id_raw[8] = (id_raw[8] & 0x3f) | 0x80;
    let id = Uuid::from_bytes(id_raw);

    let now = now_unix();
    let expires_at = now + 10 * 60;

    record_challenge_request(&st.redis)
        .await
        .map_err(|_| ApiError::internal())?;
    let final_difficulty = compute_difficulty(&st.redis)
        .await
        .map_err(|_| ApiError::internal())?
        .final_difficulty;

    // Hybrid split (docs 8.5.1): pressure drives BOTH layers from one number.
    let (sha_difficulty, argon) = if st.config.pow_argon2_enabled {
        let bits = pow_difficulty::argon_difficulty(final_difficulty);
        (
            pow_difficulty::sha_difficulty_for_hybrid(final_difficulty, bits),
            Some(crate::powcheck::ArgonParams {
                m_cost_kib: pow_difficulty::ARGON_M_COST_KIB,
                t_cost: pow_difficulty::ARGON_T_COST,
                difficulty: bits,
            }),
        )
    } else {
        (final_difficulty, None)
    };

    rds::store_pow_challenge(
        &st.redis,
        &id.to_string(),
        &data,
        sha_difficulty,
        argon,
        unix_ts_ms(),
        10 * 60,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(PowChallengeResp {
        challenge_id: id.to_string(),
        challenge: hex::encode(data),
        difficulty: sha_difficulty,
        expires_at,
        argon: argon.map(|a| PowArgonResp {
            m_cost_kib: a.m_cost_kib,
            t_cost: a.t_cost,
            difficulty: a.difficulty,
        }),
    }))
}

// --- POST /auth/challenge ---

#[derive(Deserialize)]
pub struct ChallengeReq {
    user_id: String,
}

#[derive(Serialize)]
pub struct ChallengeResp {
    challenge: String, // hex
    expires_at: i64,
}

pub async fn challenge(
    State(st): State<AppState>,
    Json(body): Json<ChallengeReq>,
) -> Result<Json<ChallengeResp>, ApiError> {
    if !valid_user_id(&body.user_id) {
        return Err(ApiError::bad_request());
    }
    // Bound the unauthenticated Redis write per target (anti-DoS / anti-grief of a
    // legit user's in-flight challenge).
    crate::routes::rate_limit(&st, "authchal", &body.user_id, 30, 60).await?;
    let mut c = [0u8; 32];
    getrandom::getrandom(&mut c).map_err(|_| ApiError::internal())?;
    let now = now_unix();

    rds::store_challenge(
        &st.redis,
        &st.config.redis_ns_key,
        &body.user_id,
        &c,
        90,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(ChallengeResp {
        challenge: hex::encode(c),
        expires_at: now + 90,
    }))
}

// --- POST /auth/verify ---

#[derive(Deserialize)]
pub struct VerifyReq {
    user_id: String,
    challenge: String, // hex
    sig_ed: String,    // hex
    sig_dil: String,   // hex
    timestamp: i64,
}

#[derive(Serialize)]
pub struct VerifyResp {
    session_token: String,
    expires_at: i64,
}

pub async fn verify(
    State(st): State<AppState>,
    Json(body): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, ApiError> {
    // Every failure below returns the SAME generic 401 - no oracle.
    if !valid_user_id(&body.user_id) {
        return Err(ApiError::unauthorized());
    }

    // Validate input hex field lengths BEFORE any Oracle-able operation.
    if !validate::validate_hex_str_exact(&body.challenge, validate::CHALLENGE_HEX_CHARS) {
        return Err(ApiError::unauthorized());
    }
    // Ed25519 sig is 64 bytes = 128 hex chars (ED25519_SIG_LEN is the byte count).
    if !validate::validate_hex_str_exact(&body.sig_ed, validate::ED25519_SIG_LEN * 2) {
        return Err(ApiError::unauthorized());
    }

    // Resource-abuse cap, 5 / 60s per user (docs 11 - PVX-20). Legit use is ~1
    // verify per boot restore + one silent renewal every ~22h.
    let allowed = rds::check_rate_limit(
        &st.redis,
        &st.config.redis_ns_key,
        "authverify",
        &body.user_id,
        5,
        60,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    if !allowed {
        return Err(ApiError::rate_limited());
    }

    let stored = rds::take_challenge(&st.redis, &st.config.redis_ns_key, &body.user_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let stored = stored.ok_or_else(ApiError::unauthorized)?;

    let submitted = hex::decode(&body.challenge).map_err(|_| ApiError::unauthorized())?;
    if submitted != stored {
        return Err(ApiError::unauthorized());
    }

    let now = now_unix();
    if !validate::validate_timestamp(body.timestamp, now) {
        return Err(ApiError::unauthorized());
    }
    // Specific ±5 min window for auth challenge (stricter than general drift).
    if (now - body.timestamp).abs() > 300 {
        return Err(ApiError::unauthorized());
    }

    let bundle = crate::db::queries::key_directory::get_key(&st.db, &body.user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let sig_ed = hex::decode(&body.sig_ed).map_err(|_| ApiError::unauthorized())?;
    let sig_dil = validate::validate_hex_max(&body.sig_dil, ml_dsa_65::SIG_LEN)
        .map_err(|_| ApiError::unauthorized())?;

    // Timing-oracle defense (PVX-08): an unknown user does the SAME hybrid
    // verification work against fixed dummy keys before the same generic 401,
    // so response latency cannot confirm whether a px_id exists.
    let Some(bundle) = bundle else {
        let _ = sig::dummy_verify_auth_challenge(
            &stored,
            &body.user_id,
            body.timestamp,
            &sig_ed,
            &sig_dil,
        );
        return Err(ApiError::unauthorized());
    };

    if !sig::verify_auth_challenge(
        &stored,
        &body.user_id,
        body.timestamp,
        &sig_ed,
        &bundle.ik_ed25519,
        &sig_dil,
        &bundle.ik_dilithium3,
    ) {
        return Err(ApiError::unauthorized());
    }

    let session_token = token::mint(&st.config.token_mac_key, &body.user_id, now);
    Ok(Json(VerifyResp {
        session_token,
        expires_at: now + token::TTL_SECS,
    }))
}

// --- POST /auth/ws_ticket ---
// Browsers can't set X-Privex-Auth on a WebSocket. Authenticate normally here,
// then mint a short-lived single-use ticket to carry in Sec-WebSocket-Protocol.

const WS_TICKET_TTL: i64 = 60;

#[derive(Serialize)]
pub struct WsTicketResp {
    ticket: String,
    expires_at: i64,
}

pub async fn ws_ticket(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<WsTicketResp>, ApiError> {
    // Bound ticket minting per user → bounds devlink rendezvous rooms a single
    // account can open.
    crate::routes::rate_limit(&st, "wsticket", &user_id, 60, 60).await?;
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| ApiError::internal())?;
    let ticket = hex::encode(raw);

    rds::store_ws_ticket(
        &st.redis,
        &st.config.redis_ns_key,
        &ticket,
        &user_id,
        WS_TICKET_TTL,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(WsTicketResp {
        ticket,
        expires_at: now_unix() + WS_TICKET_TTL,
    }))
}

// --- POST /auth/logout_all ---
// "Log out everywhere": set a revocation cutoff so every session token issued
// before now (incl. the one making this call) becomes invalid. NOTE: the guide
// framed this as SPK rotation invalidating tokens, but this server's tokens are
// HMAC/TTL and SPK-independent - real revocation is the correct mechanism. SPK
// rotation (a separate /keys/spk/rotate call) is orthogonal forward secrecy.

#[derive(Serialize)]
pub struct LogoutAllResp {
    revoked: bool,
}

pub async fn logout_all(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<LogoutAllResp>, ApiError> {
    // Cheap Redis write, but bound it anyway (each call extends the rev: key TTL).
    crate::routes::rate_limit(&st, "logoutall", &user_id, 10, 60).await?;
    // cutoff = now+1 so EVERY token issued in this second or earlier (incl. the
    // caller's) is revoked; a fresh login must wait until the next second.
    rds::set_revoke_cutoff(
        &st.redis,
        &st.config.redis_ns_key,
        &user_id,
        now_unix() + 1,
        token::TTL_SECS,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    Ok(Json(LogoutAllResp { revoked: true }))
}
