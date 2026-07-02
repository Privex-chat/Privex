// Key directory + Key Transparency endpoints (docs 8.2 / 11).
//
// Encoding convention: ALL key-material/binary fields here are HEX. (Message
// and blob payloads elsewhere use base64; key material is hex everywhere.)
//
// CLIENT REQUIREMENT (web app must do this before pqxdh_initiate):
//   1. Verify the KT inclusion proof against a signed root (kt_verify_inclusion).
//   2. Verify the SPK hybrid signature over spk_x25519 (verify_hybrid).
// The server returns the proof on every bundle fetch; it never returns a bundle
// without one.

use axum::extract::{Path, State};
use axum::Json;
use ed25519_dalek::{Signer, SigningKey};
use fips204::ml_dsa_65;
use serde::{Deserialize, Serialize};

use crate::auth::extract::AuthUser;
use crate::auth::sig;
use crate::crypto::kt_log as ktree;
use crate::db::queries::key_directory as kd;
use crate::db::queries::kt_log as ktdb;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::routes::{hexd, valid_user_id, PowProof};
use crate::state::AppState;
use crate::ws::messages::ServerMsg;

const ED25519_SIG: usize = 64;
const X25519_PUB: usize = 32;

/// Body for the PoW-gated public fetches (key bundle + KT proof). Requiring a
/// solved single-use PoW per fetch is what closes the account-enumeration,
/// OPK-drain, and activity-charting oracle WITHOUT an IP/identity rate limit -
/// each probe now costs real compute, and a flood drives global difficulty up.
#[derive(Deserialize)]
pub struct PowFetchReq {
    pow: PowProof,
}

fn sign_root(seed: &[u8; 32], root: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(root).to_bytes()
}

fn entries_to_leaves(entries: &[ktdb::KtEntry]) -> Result<Vec<[u8; 32]>, ApiError> {
    entries
        .iter()
        .map(|e| {
            let bh = hex::decode(&e.bundle_hash).map_err(|_| ApiError::internal())?;
            Ok(ktree::leaf_hash(&e.user_id, &bh, e.timestamp as i64))
        })
        .collect()
}

#[derive(Serialize)]
pub struct ProofNodeResp {
    left: bool,
    hash: String, // hex
}

#[derive(Serialize)]
pub struct KtProofResp {
    leaf: String, // hex
    path: Vec<ProofNodeResp>,
    root: String,        // hex
    root_sig_ed: String, // hex Ed25519 sig over the 32-byte root
    timestamp: i64,      // entry timestamp (needed to reconstruct the leaf)
}

async fn build_kt_proof(st: &AppState, user_id: &str) -> Result<Option<KtProofResp>, ApiError> {
    let entries = ktdb::list_all_entries(&st.db)
        .await
        .map_err(|_| ApiError::internal())?;
    let leaves = entries_to_leaves(&entries)?;

    // The user's latest entry = the last one (entries are seq-ordered).
    let idx = match entries.iter().rposition(|e| e.user_id == user_id) {
        Some(i) => i,
        None => return Ok(None),
    };

    let root = ktree::compute_root(&leaves);
    let proof = ktree::inclusion_proof(&leaves, idx);
    let sig = sign_root(&st.config.kt_signing_key, &root);

    Ok(Some(KtProofResp {
        leaf: hex::encode(leaves[idx]),
        path: proof
            .iter()
            .map(|p| ProofNodeResp {
                left: p.left,
                hash: hex::encode(p.hash),
            })
            .collect(),
        root: hex::encode(root),
        root_sig_ed: hex::encode(sig),
        timestamp: entries[idx].timestamp as i64,
    }))
}

// --- POST /keys/{user_id} (public, PoW-gated) ---
// Was an unauthenticated GET; now requires a solved single-use PoW in the body so
// account enumeration / OPK drain / activity charting all cost real compute. The
// auto-add-back path (receiveMessage) makes NO server call - it learns the peer
// key from the sealed PqxdhInit - so only the deliberate adder pays this PoW.

#[derive(Serialize)]
pub struct KeyBundleResp {
    user_id: String,
    ik_ed25519: String,
    ik_dilithium3: String,
    ik_x25519: String,
    spk_x25519: String,
    spk_sig_ed: String,
    spk_sig_dil: String,
    kyber1024_pub: String,
    opk: Option<String>,
    opk_id: Option<i32>,
    kt_proof: KtProofResp,
}

pub async fn get_key_bundle(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
    Json(body): Json<PowFetchReq>,
) -> Result<Json<KeyBundleResp>, ApiError> {
    if !valid_user_id(&user_id) {
        return Err(ApiError::bad_request());
    }

    // PoW gate FIRST: you cannot even touch the per-target counter (let alone
    // learn whether the user exists or consume an OPK) without burning a solve.
    crate::routes::verify_pow(&st, &body.pow).await?;

    // Anti-enumeration / anti-OPK-drain: bound fetches per target (docs 11:
    // 30/60s). Keyed by HMAC of the fetched user_id - never the raw id. Kept as
    // defense in depth behind the PoW.
    let allowed = rds::check_rate_limit(
        &st.redis,
        &st.config.session_hmac_key,
        "keyfetch",
        &user_id,
        30,
        60,
    )
    .await
    .map_err(|e| {
        tracing::error!("Redis rate limit failed: {:?}", e);
        ApiError::internal()
    })?;
    if !allowed {
        return Err(ApiError::rate_limited());
    }

    let b = kd::get_key(&st.db, &user_id)
        .await
        .map_err(|e| {
            tracing::error!("get_key failed: {:?}", e);
            ApiError::internal()
        })?
        .ok_or_else(ApiError::not_found)?;

    // Consume exactly one OPK atomically (None if exhausted → client relies on
    // the prekey_low signal + replenish).
    let opk = kd::take_one_time_prekey(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // If this fetch drained the owner's OPKs below the threshold, nudge them to
    // replenish over WS (best-effort; only if they're online).
    if opk.is_some() {
        if let Ok(remaining) = kd::list_opk_count(&st.db, &user_id).await {
            if remaining < 20 {
                let msg =
                    serde_json::to_string(&ServerMsg::PrekeyLow { remaining }).unwrap_or_default();
                st.online.send(&user_id, msg);
            }
        }
    }

    // Never return a bundle without a proof.
    let kt_proof = build_kt_proof(&st, &user_id).await?.ok_or_else(|| {
        tracing::error!("build_kt_proof returned None for existing user!");
        ApiError::internal()
    })?;

    Ok(Json(KeyBundleResp {
        user_id: b.user_id,
        ik_ed25519: hex::encode(b.ik_ed25519),
        ik_dilithium3: hex::encode(b.ik_dilithium3),
        ik_x25519: hex::encode(b.ik_x25519),
        spk_x25519: hex::encode(b.spk_x25519),
        spk_sig_ed: hex::encode(b.spk_sig_ed),
        spk_sig_dil: hex::encode(b.spk_sig_dil),
        kyber1024_pub: hex::encode(b.kyber1024_pub),
        opk: opk.as_ref().map(|(_, p)| hex::encode(p)),
        opk_id: opk.as_ref().map(|(id, _)| *id),
        kt_proof,
    }))
}

// --- POST /keys/kt/proof/{user_id} (public, PoW-gated) ---
// The other per-target existence oracle (404 if the user has no KT entry) + an
// O(N) log scan. PoW-gated like the bundle fetch so periodic key-change
// re-verification costs compute and can't be turned into a free enumeration probe.

pub async fn kt_proof(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
    Json(body): Json<PowFetchReq>,
) -> Result<Json<KtProofResp>, ApiError> {
    if !valid_user_id(&user_id) {
        return Err(ApiError::bad_request());
    }
    crate::routes::verify_pow(&st, &body.pow).await?;
    // Unauthenticated + O(N) full-log scan per call → bound per target (behind PoW).
    crate::routes::rate_limit(&st, "ktproof", &user_id, 30, 60).await?;
    build_kt_proof(&st, &user_id)
        .await?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

// --- GET /keys/kt/root (public) ---

#[derive(Serialize)]
pub struct KtRootResp {
    root: String,
    root_sig_ed: String,
    timestamp: i64,
}

pub async fn kt_root(State(st): State<AppState>) -> Result<Json<KtRootResp>, ApiError> {
    // Unauthenticated + O(N) full-log scan + Merkle root per call → endpoint-wide cap.
    crate::routes::rate_limit(&st, "ktroot", "global", 120, 60).await?;
    let entries = ktdb::list_all_entries(&st.db)
        .await
        .map_err(|_| ApiError::internal())?;
    let leaves = entries_to_leaves(&entries)?;
    let root = ktree::compute_root(&leaves);
    let sig = sign_root(&st.config.kt_signing_key, &root);
    Ok(Json(KtRootResp {
        root: hex::encode(root),
        root_sig_ed: hex::encode(sig),
        timestamp: now_unix(),
    }))
}

// --- POST /keys/prekeys/replenish (auth) ---

#[derive(Deserialize)]
pub struct OpkItem {
    opk_id: i32,
    opk_x25519_pub: String, // hex
}

#[derive(Deserialize)]
pub struct ReplenishReq {
    opks: Vec<OpkItem>,
}

#[derive(Serialize)]
pub struct ReplenishResp {
    stored: i64,
}

// NOTE: replenishment does NOT append a KT log entry. The KT log covers only
// identity/SPK/Kyber bundle state (which bundle_hash hashes); one-time prekeys
// are ephemeral, single-use inventory and are intentionally out of KT scope.
pub async fn replenish(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<ReplenishReq>,
) -> Result<Json<ReplenishResp>, ApiError> {
    // Bound the batch + the call rate so a token can't grow the prekey table without
    // limit (each OPK is a row).
    if body.opks.is_empty() || body.opks.len() > 200 {
        return Err(ApiError::bad_request());
    }
    crate::routes::rate_limit(&st, "replenish", &user_id, 20, 60).await?;
    let mut stored = 0i64;
    for item in &body.opks {
        let pk = hexd(&item.opk_x25519_pub)?;
        if pk.len() != X25519_PUB {
            return Err(ApiError::bad_request());
        }
        // rows_affected is 0 for a duplicate opk_id → stored reflects only the
        // OPKs actually added.
        stored += kd::insert_one_time_prekey(&st.db, &user_id, item.opk_id, &pk)
            .await
            .map_err(|_| ApiError::internal())? as i64;
    }
    Ok(Json(ReplenishResp { stored }))
}

// --- POST /keys/spk/rotate (auth) ---

#[derive(Deserialize)]
pub struct SpkRotateReq {
    spk_x25519_pub: String,
    spk_sig_ed: String,
    spk_sig_dil: String,
}

#[derive(Serialize)]
pub struct SpkRotateResp {
    rotated: bool,
}

pub async fn spk_rotate(
    AuthUser(user_id): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<SpkRotateReq>,
) -> Result<Json<SpkRotateResp>, ApiError> {
    // Each rotation appends an immutable KT entry that EVERY bundle fetch O(N)-scans
    // - a global cost, not just this user's. 30/hour is generous vs. legit use
    // (scheduled rotation is ~monthly; recovery does one rotate per recovery).
    crate::routes::rate_limit(&st, "spkrotate", &user_id, 30, 3600).await?;
    let spk = hexd(&body.spk_x25519_pub)?;
    let sig_ed = hexd(&body.spk_sig_ed)?;
    let sig_dil = hexd(&body.spk_sig_dil)?;
    if spk.len() != X25519_PUB || sig_ed.len() != ED25519_SIG || sig_dil.len() != ml_dsa_65::SIG_LEN
    {
        return Err(ApiError::bad_request());
    }

    let b = kd::get_key(&st.db, &user_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)?;

    // Server verifies the new SPK is signed by the stored identity keys.
    if !sig::verify_hybrid(&spk, &sig_ed, &b.ik_ed25519, &sig_dil, &b.ik_dilithium3) {
        return Err(ApiError::bad_request());
    }

    let now = now_unix();
    kd::update_spk(&st.db, &user_id, &spk, &sig_ed, &sig_dil, now as i32)
        .await
        .map_err(|_| ApiError::internal())?;

    // Append a KT entry for the rotated bundle (immutable log; old entry stays).
    let new_hash = hex::encode(ktree::bundle_hash(
        &b.ik_ed25519,
        &b.ik_dilithium3,
        &b.ik_x25519,
        &spk,
        &sig_ed,
        &sig_dil,
        &b.kyber1024_pub,
    ));
    let prev = ktdb::get_root(&st.db)
        .await
        .map_err(|_| ApiError::internal())?
        .map(|r| r.bundle_hash);
    ktdb::append_entry(
        &st.db,
        &user_id,
        &new_hash,
        "spk_rotate",
        now as i32,
        prev.as_deref(),
    )
    .await
    .map_err(|_| ApiError::internal())?;

    // key_change_alert is NOT pushed server-side: by design the server holds no
    // social graph, so it cannot know who this user's contacts are. Clients
    // detect key changes by periodically re-fetching contacts' bundles and
    // re-verifying the KT proof. (Deferred-by-design, not a missing feature.)

    Ok(Json(SpkRotateResp { rotated: true }))
}
