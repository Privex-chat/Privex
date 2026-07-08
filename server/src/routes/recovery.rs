// Account recovery - OPAQUE (docs 6.1). The server never sees the password or
// any password-derived value; it only relays OPRF messages and stores an opaque
// encrypted envelope. Recovery LOGIN issues a normal 24h session token.
//
// Register-setup (start/finish) is AUTHENTICATED - the account owner provisions
// their OPAQUE record after registering keys. LOGIN (init/complete) is
// UNAUTHENTICATED (the user lost their device and only has their password) and
// returns a GENERIC 401 on any failure.
//
// DEFERRED (documented): Shamir-share contact retrieval and device linking.
// `GET /recovery/shares/{user_id}` "for a recovery contact" cannot be built
// without storing the social graph (the recovery_shares schema intentionally has
// no contact_id). A relationship-free design needs a share_id rendezvous flow;
// deferred rather than weaken the privacy model. Device linking needs multi-
// device WS fan-out (also deferred).

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::extract::AuthUser;
use crate::auth::token;
use crate::crypto::opaque;
use crate::db::queries::opaque as opaque_db;
use crate::db::queries::opaque::OpaqueLoginRecord;
use crate::db::queries::recovery_shares;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::routes::valid_user_id;
use crate::state::AppState;
use crate::validate;

const LOGIN_TTL: i64 = 120; // seconds; OPAQUE login state is short-lived

fn random_hex(len: usize) -> Result<String, ApiError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(bytes))
}

fn record_tag(record: &OpaqueLoginRecord) -> String {
    let mut h = Sha256::new();
    h.update(&record.oprf_record);
    h.update(&record.envelope);
    h.update(&record.envelope_mac);
    hex::encode(h.finalize())
}

// --- GET /recovery/opaque/status (auth) ---

#[derive(Serialize)]
pub struct OpaqueStatusResp {
    enabled: bool,
}

pub async fn opaque_status(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<OpaqueStatusResp>, ApiError> {
    crate::routes::rate_limit(&st, "opqstatus", &user_id, 120, 60).await?;
    let enabled = opaque_db::opaque_record_exists(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(OpaqueStatusResp { enabled }))
}

// --- POST /recovery/opaque/register/start (auth) ---

#[derive(Deserialize)]
pub struct RegStartReq {
    registration_request: String, // hex
}
#[derive(Serialize)]
pub struct RegStartResp {
    registration_response: String, // hex
}

pub async fn opaque_register_start(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<RegStartReq>,
) -> Result<Json<RegStartResp>, ApiError> {
    crate::routes::rate_limit(&st, "opqregstart", &user_id, 10, 600).await?;
    let setup =
        opaque::load_setup(&st.config.opaque_server_setup).map_err(|_| ApiError::internal())?;
    let request = validate::validate_opaque_wire(&body.registration_request)?;
    let response = opaque::register_start(&setup, &request, user_id.as_bytes())
        .map_err(|_| ApiError::bad_request())?;
    Ok(Json(RegStartResp {
        registration_response: hex::encode(response),
    }))
}

// --- POST /recovery/opaque/register/finish (auth) ---

#[derive(Deserialize)]
pub struct RegFinishReq {
    registration_upload: String, // hex
    envelope: String,            // hex
    envelope_mac: String,        // hex
}
#[derive(Serialize)]
pub struct RegFinishResp {
    stored: bool,
}

pub async fn opaque_register_finish(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<RegFinishReq>,
) -> Result<Json<RegFinishResp>, ApiError> {
    crate::routes::rate_limit(&st, "opqregfinish", &user_id, 10, 600).await?;
    let upload = validate::validate_opaque_wire(&body.registration_upload)?;
    let record = opaque::register_finish(&upload).map_err(|_| ApiError::bad_request())?;
    let envelope = validate::validate_hex_exact(&body.envelope, validate::OPAQUE_ENVELOPE_BYTES)?;
    let envelope_mac = validate::validate_hex_exact(&body.envelope_mac, validate::OPAQUE_ENVELOPE_MAC_BYTES)?;

    let now = now_unix();
    opaque_db::upsert_opaque_record(
        &st.db,
        &user_id,
        &record,
        &envelope,
        &envelope_mac,
        now as i32,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    Ok(Json(RegFinishResp { stored: true }))
}

// --- DELETE /recovery/opaque (auth) ---

#[derive(Serialize)]
pub struct OpaqueDeleteResp {
    enabled: bool,
}

pub async fn opaque_delete(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<OpaqueDeleteResp>, ApiError> {
    crate::routes::rate_limit(&st, "opqdelete", &user_id, 10, 600).await?;
    opaque_db::delete_opaque_record(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(OpaqueDeleteResp { enabled: false }))
}

// --- POST /recovery/opaque/init (no auth) ---

#[derive(Deserialize)]
pub struct LoginInitReq {
    user_id: String,
    credential_request: String, // hex
    // PoW gate: this is an unauthenticated endpoint that runs an OPRF + a Redis
    // write per call against a TARGET user_id. Requiring a solved PoW makes a
    // probe cost compute and keeps it off the free-enumeration / OPRF-DoS path.
    pow: crate::routes::PowProof,
}
#[derive(Serialize)]
pub struct LoginInitResp {
    login_id: String,
    credential_response: String, // hex
    envelope: String,            // hex
    envelope_mac: String,        // hex
}

pub async fn opaque_login_init(
    State(st): State<AppState>,
    Json(body): Json<LoginInitReq>,
) -> Result<Json<LoginInitResp>, ApiError> {
    if !valid_user_id(&body.user_id) {
        return Err(ApiError::unauthorized());
    }
    // PoW gate FIRST (before the per-target counter or any OPRF work).
    crate::routes::verify_pow(&st, &body.pow).await?;
    // Unauthenticated + runs an OPRF + a Redis write per call → bound per target.
    crate::routes::rate_limit(&st, "opqinit", &body.user_id, 10, 60).await?;
    let setup =
        opaque::load_setup(&st.config.opaque_server_setup).map_err(|_| ApiError::internal())?;
    let request = validate::validate_opaque_wire(&body.credential_request)
        .map_err(|_| ApiError::unauthorized())?;

    // Missing record → opaque-ke fabricates an indistinguishable response and a
    // dummy envelope is returned, so a probe can't tell if the user exists.
    let record = opaque_db::get_opaque_login_record(&st.db, &body.user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let (response, login_state) = opaque::login_start(
        &setup,
        record.as_ref().map(|r| r.oprf_record.as_slice()),
        &request,
        body.user_id.as_bytes(),
    )
    .map_err(|_| ApiError::unauthorized())?;

    let mut id_raw = [0u8; 32];
    getrandom::getrandom(&mut id_raw).map_err(|_| ApiError::internal())?;
    let login_id = hex::encode(id_raw);
    let login_record_tag = record.as_ref().map(record_tag);

    rds::store_login_state(
        &st.redis,
        &st.config.session_hmac_key,
        &login_id,
        &body.user_id,
        login_record_tag.as_deref(),
        &login_state,
        LOGIN_TTL,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    let (envelope, envelope_mac) = match &record {
        Some(r) => (hex::encode(&r.envelope), hex::encode(&r.envelope_mac)),
        None => (
            random_hex(validate::OPAQUE_ENVELOPE_BYTES)?,
            random_hex(validate::OPAQUE_ENVELOPE_MAC_BYTES)?,
        ),
    };

    Ok(Json(LoginInitResp {
        login_id,
        credential_response: hex::encode(response),
        envelope,
        envelope_mac,
    }))
}

// --- POST /recovery/opaque/complete (no auth) ---

#[derive(Deserialize)]
pub struct LoginCompleteReq {
    login_id: String,
    credential_finalization: String, // hex
}
#[derive(Serialize)]
pub struct LoginCompleteResp {
    session_token: String,
    expires_at: i64,
}

pub async fn opaque_login_complete(
    State(st): State<AppState>,
    Json(body): Json<LoginCompleteReq>,
) -> Result<Json<LoginCompleteResp>, ApiError> {
    // Unauthenticated → endpoint-wide cap (the login_id is single-use + unguessable,
    // so this just bounds churn / brute attempts).
    crate::routes::rate_limit(&st, "opqcomplete", "global", 120, 60).await?;
    // Single-use consume of the login state (GETDEL).
    let consumed = rds::take_login_state(&st.redis, &st.config.session_hmac_key, &body.login_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let (user_id, login_record_tag, login_state) = consumed.ok_or_else(ApiError::unauthorized)?;

    let finalization = validate::validate_opaque_wire(&body.credential_finalization)
        .map_err(|_| ApiError::unauthorized())?;
    opaque::login_finish(&login_state, &finalization).map_err(|_| ApiError::unauthorized())?;
    let current_record = opaque_db::get_opaque_login_record(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;
    match (current_record.as_ref(), login_record_tag.as_deref()) {
        (Some(record), Some(tag)) if record_tag(record) == tag => {}
        _ => return Err(ApiError::unauthorized()),
    }

    // Verified → issue the normal 24h session token.
    let now = now_unix();
    Ok(Json(LoginCompleteResp {
        session_token: token::mint(&st.config.session_hmac_key, &user_id, now),
        expires_at: now + token::TTL_SECS,
    }))
}

// --- POST /recovery/shares/store (auth) ---
// Stores the owner's Shamir recovery shares, each already sealed to a recovery
// contact's public key. The server never learns which contacts hold them.
// NOTE: RETRIEVAL ("recover via contacts") stays deferred - a relationship-free
// share rendezvous is needed (see the module header). This is setup only.

#[derive(Deserialize)]
pub struct ShareItem {
    share_index: i16,
    encrypted_share: String, // hex
}

#[derive(Deserialize)]
pub struct StoreSharesReq {
    shares: Vec<ShareItem>,
}

#[derive(Serialize)]
pub struct StoreSharesResp {
    stored: i64,
}

pub async fn store_shares(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<StoreSharesReq>,
) -> Result<Json<StoreSharesResp>, ApiError> {
    // Setup-only endpoint (a few calls per lifetime) - bound DB row growth.
    crate::routes::rate_limit(&st, "shares", &user_id, 10, 600).await?;
    if body.shares.is_empty() || body.shares.len() > validate::MAX_SHARES_BATCH {
        return Err(ApiError::bad_request());
    }
    // Each share index must be in range (1-255), and no duplicates.
    for s in &body.shares {
        if !validate::validate_share_index(s.share_index) {
            return Err(ApiError::bad_request());
        }
    }
    let indices: Vec<i16> = body.shares.iter().map(|s| s.share_index).collect();
    if !validate::validate_no_duplicate_indices(&indices) {
        return Err(ApiError::bad_request());
    }
    for s in &body.shares {
        let bytes = validate::validate_hex_max(
            &s.encrypted_share,
            validate::MAX_SHARE_BYTES,
        )?;
        recovery_shares::store_share(&st.db, &user_id, s.share_index, &bytes)
            .await
            .map_err(|_| ApiError::internal())?;
    }
    let stored = recovery_shares::count_shares(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(StoreSharesResp { stored }))
}
