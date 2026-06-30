// POST /keys/register (docs 11). PoW-gated (no IP). Stores the public key
// bundle and one-time prekeys, and appends a KT log entry - all atomically.
// NEVER stores ip/email/phone/name/device info.

use axum::extract::State;
use axum::Json;
use fips203::ml_kem_1024;
use fips204::ml_dsa_65;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::sig;
use crate::crypto::pow_difficulty;
use crate::db::queries::key_directory::KeyBundle;
use crate::db::queries::register;
use crate::error::ApiError;
use crate::now_unix;
use crate::routes::{hexd, valid_user_id, PowProof};
use crate::state::AppState;

const ED25519_PUB: usize = 32;
const ED25519_SIG: usize = 64;
const X25519_PUB: usize = 32;
const MIN_REGISTRATION_OPKS: usize = 1;
const MAX_REGISTRATION_OPKS: usize = 200;

fn require_len(bytes: &[u8], expected: usize) -> Result<(), ApiError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ApiError::bad_request())
    }
}

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
    // OPAQUE recovery setup is a SEPARATE authenticated step
    // (/recovery/opaque/register/*), not part of key registration.
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
    if body.opks.len() < MIN_REGISTRATION_OPKS || body.opks.len() > MAX_REGISTRATION_OPKS {
        return Err(ApiError::bad_request());
    }

    // --- PoW: gate all expensive registration work behind a valid solution. ---
    crate::routes::verify_pow(&st, &body.pow).await?;
    let now = now_unix();

    let ik_ed = hexd(&body.ik_ed25519_pub)?;
    let ik_dil = hexd(&body.ik_dilithium3_pub)?;
    let ik_x = hexd(&body.ik_x25519_pub)?;
    let spk = hexd(&body.spk_x25519_pub)?;
    let spk_sig_ed = hexd(&body.spk_sig_ed)?;
    let spk_sig_dil = hexd(&body.spk_sig_dil)?;
    let kyber = hexd(&body.kyber1024_pub)?;

    // Byte-length validation against the real algorithm sizes.
    require_len(&ik_ed, ED25519_PUB)?;
    require_len(&ik_dil, ml_dsa_65::PK_LEN)?;
    require_len(&ik_x, X25519_PUB)?;
    require_len(&spk, X25519_PUB)?;
    require_len(&spk_sig_ed, ED25519_SIG)?;
    require_len(&spk_sig_dil, ml_dsa_65::SIG_LEN)?;
    require_len(&kyber, ml_kem_1024::EK_LEN)?;

    // user_id integrity: must equal px_ + hex(SHA-256(ik_ed25519)[..16]).
    let expected = format!("px_{}", hex::encode(&Sha256::digest(&ik_ed)[..16]));
    if expected != body.user_id {
        return Err(ApiError::bad_request());
    }

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
        require_len(&opk_pub, X25519_PUB)?;
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
