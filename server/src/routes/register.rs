// POST /keys/register (docs 11). PoW-gated (no IP). Stores the public key
// bundle and one-time prekeys, and appends a KT log entry - all atomically.
// NEVER stores ip/email/phone/name/device info.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::sig;
use crate::crypto::pow_difficulty;
use crate::db::queries::key_directory::KeyBundle;
use crate::db::queries::register;
use crate::error::ApiError;
use crate::now_unix;
use crate::routes::{hexd, valid_user_id, PowProof};
use crate::state::AppState;
use crate::validate;

#[derive(Deserialize)]
pub struct OpkReq {
    opk_id: i32,
    opk_x25519_pub: String, // hex
}

#[derive(Deserialize)]
pub struct RegisterReq {
    user_id: String,
    ik_ed25519_pub: String,
    ik_dilithium3_pub: String,
    ik_x25519_pub: String,
    spk_x25519_pub: String,
    spk_sig_ed: String,
    spk_sig_dil: String,
    kyber1024_pub: String,
    opks: Vec<OpkReq>,
    pow: PowProof,
}

#[derive(Serialize)]
pub struct RegisterResp {
    registered: bool,
}

pub async fn register(
    State(st): State<AppState>,
    Json(body): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    if !valid_user_id(&body.user_id) {
        return Err(ApiError::bad_request());
    }
    if body.opks.len() < validate::MIN_OPKS_PER_REGISTRATION
        || body.opks.len() > validate::MAX_OPKS_PER_REGISTRATION
    {
        return Err(ApiError::bad_request());
    }

    crate::routes::verify_pow(&st, &body.pow).await?;
    let now = now_unix();

    let ik_ed = hexd(&body.ik_ed25519_pub)?;
    let ik_dil = hexd(&body.ik_dilithium3_pub)?;
    let ik_x = hexd(&body.ik_x25519_pub)?;
    let spk = hexd(&body.spk_x25519_pub)?;
    let spk_sig_ed = hexd(&body.spk_sig_ed)?;
    let spk_sig_dil = hexd(&body.spk_sig_dil)?;
    let kyber = hexd(&body.kyber1024_pub)?;

    validate::validate_identity_key(&ik_ed)?;
    validate::validate_dilithium_pk(&ik_dil)?;
    validate::validate_x25519_pub(&ik_x)?;
    validate::validate_x25519_pub(&spk)?;
    validate::validate_ed25519_sig(&spk_sig_ed)?;
    validate::validate_dilithium_sig(&spk_sig_dil)?;
    validate::validate_kyber_pub(&kyber)?;

    validate::validate_user_id_integrity(&body.user_id, &ik_ed)?;

    // Server-side SPK signature check: the signed prekey must be signed by BOTH
    // submitted identity keys (signing input = spk_x25519_pub bytes). This does
    // NOT replace the client's own SPK verification of FETCHED bundles before
    // pqxdh_initiate - clients must still verify what they download.
    if !sig::verify_hybrid(&spk, &spk_sig_ed, &ik_ed, &spk_sig_dil, &ik_dil) {
        return Err(ApiError::bad_request());
    }

    // --- decode OPKs ---
    let mut opks = Vec::with_capacity(body.opks.len());
    for opk in &body.opks {
        let opk_pub = hexd(&opk.opk_x25519_pub)?;
        validate::validate_x25519_pub(&opk_pub)?;
        opks.push((opk.opk_id, opk_pub));
    }

    // KT leaf bundle hash - canonical over ALL public fields incl SPK sigs.
    let bundle_hash = hex::encode(crate::crypto::kt_log::bundle_hash(
        &ik_ed,
        &ik_dil,
        &ik_x,
        &spk,
        &spk_sig_ed,
        &spk_sig_dil,
        &kyber,
    ));

    let bundle = KeyBundle {
        user_id: body.user_id.clone(),
        ik_ed25519: ik_ed,
        ik_dilithium3: ik_dil,
        ik_x25519: ik_x,
        spk_x25519: spk,
        spk_sig_ed,
        spk_sig_dil,
        kyber1024_pub: kyber,
        spk_created_at: now as i32,
        created_at: now as i32,
    };

    match register::register_user(
        &st.db,
        register::NewRegistration {
            bundle: &bundle,
            opks: &opks,
            bundle_hash: &bundle_hash,
            now: now as i32,
        },
    )
    .await
    {
        Ok(()) => {
            if pow_difficulty::record_registration(&st.redis)
                .await
                .is_err()
            {
                tracing::error!(
                    event = "registration_counter_write_failed",
                    severity = "critical"
                );
            }
            Ok(Json(RegisterResp { registered: true }))
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::conflict()),
        Err(_) => Err(ApiError::internal()),
    }
}
