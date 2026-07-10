pub mod auth;
pub mod blobs;
pub mod config;
pub mod health;
pub mod history;
pub mod keys;
pub mod messages;
pub mod recovery;
pub mod register;

use crate::crypto::pow_difficulty;
use crate::error::ApiError;
use crate::state::AppState;
use crate::validate;

/// A submitted Proof-of-Work solution (shared by every PoW-gated endpoint:
/// registration + the public, target-revealing key/recovery fetches). Mirrors the
/// hashcash wire: a nonce over a server-issued challenge whose SHA-256 has
/// `difficulty` leading zero bits.
#[derive(serde::Deserialize)]
pub(crate) struct PowProof {
    pub challenge_id: String,
    pub nonce: u64,
    pub solution_hash: String, // hex
}

fn suspicion_severity(suspicion: u32) -> &'static str {
    match suspicion {
        0..=10 => "warn",
        11..=30 => "high",
        _ => "critical",
    }
}

/// Aggregate-only: logs a too-fast solve with no user/request/network identifier.
fn log_suspicious_pow_solve(suspicion: u32, solve_time_ms: u64, min_expected: u64, difficulty: u32) {
    match suspicion_severity(suspicion) {
        sev @ ("critical" | "high") => tracing::error!(
            event = "suspicious_pow_solve",
            severity = sev,
            suspicion,
            solve_ms = solve_time_ms,
            min_expected_ms = min_expected,
            difficulty,
        ),
        sev => tracing::warn!(
            event = "suspicious_pow_solve",
            severity = sev,
            suspicion,
            solve_ms = solve_time_ms,
            min_expected_ms = min_expected,
            difficulty,
        ),
    }
}

/// Consume + verify a single-use PoW solution. Returns 400 on any failure (unknown
/// / used / expired challenge, wrong length, bad math). A valid-but-impossibly-fast
/// solve is ACCEPTED but bumps aggregate suspicion (raising difficulty for everyone)
/// - never rejected, since fast hardware is legitimate. No IP/user/identity is read
/// or logged. This is the only privacy-preserving gate for the public,
/// target-revealing endpoints (key fetch, KT proof, OPAQUE login init).
///
/// The scheme is whatever was BOUND to the challenge at issue time: legacy
/// SHA-only, or the Argon2id hybrid (docs 8.5.1). The server's own Argon2id
/// verification work is bounded by the /auth/pow_challenge issuance cap (a
/// verify requires consuming a real challenge) and by the cheap SHA pre-filter
/// inside hybrid_valid (garbage dies before the memory-hard evaluation).
pub(crate) async fn verify_pow(st: &AppState, pow: &PowProof) -> Result<(), ApiError> {
    // Validate PoW proof structure BEFORE touching Redis
    if !validate::validate_pow_challenge_id(&pow.challenge_id) {
        return Err(ApiError::bad_request());
    }
    let sol = validate::validate_solution_hash(&pow.solution_hash)?;

    let cid = sqlx::types::Uuid::parse_str(&pow.challenge_id).map_err(|_| ApiError::bad_request())?;
    let now_ms = pow_difficulty::unix_ts_ms();
    let consumed = crate::rds::take_pow_challenge(&st.redis, &cid.to_string())
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::bad_request)?; // unknown / used / expired

    let (valid, min_expected) = match consumed.argon {
        Some(argon) => {
            // The Argon2id evaluation is tens of ms of sync CPU + a 32 MiB
            // allocation - run it off the async worker threads. Total server
            // exposure stays bounded by the challenge-issuance cap.
            let challenge = consumed.challenge_data.clone();
            let nonce = pow.nonce;
            let sha_difficulty = consumed.difficulty;
            let sol_owned = sol.clone();
            let valid = tokio::task::spawn_blocking(move || {
                crate::powcheck::hybrid_valid(&challenge, nonce, sha_difficulty, &argon, &sol_owned)
            })
            .await
            .map_err(|_| ApiError::internal())?;
            (
                valid,
                pow_difficulty::minimum_hybrid_solve_ms(consumed.difficulty, argon.difficulty),
            )
        }
        None => (
            crate::powcheck::pow_valid(&consumed.challenge_data, pow.nonce, consumed.difficulty, &sol),
            pow_difficulty::minimum_solve_ms(consumed.difficulty),
        ),
    };
    if !valid {
        return Err(ApiError::bad_request());
    }

    let solve_time_ms = now_ms.saturating_sub(consumed.issued_at_ms);
    if solve_time_ms < min_expected {
        let suspicion = pow_difficulty::increment_suspicion(&st.redis).await.unwrap_or(0);
        log_suspicious_pow_solve(suspicion, solve_time_ms, min_expected, consumed.difficulty);
    }
    Ok(())
}

/// Fixed-window rate limit guard. `identity` is "global" for endpoint-wide caps or
/// a user_id/target for per-subject caps; it is only ever an HMAC key in Redis,
/// never stored raw. Returns 429 when exceeded.
pub(crate) async fn rate_limit(
    st: &AppState,
    scope: &str,
    identity: &str,
    limit: i64,
    window_secs: i64,
) -> Result<(), ApiError> {
    let ok = crate::rds::check_rate_limit(
        &st.redis,
        &st.config.redis_ns_key,
        scope,
        identity,
        limit,
        window_secs,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    if ok {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

// Delegates to the central validation module.
pub(crate) fn valid_user_id(s: &str) -> bool {
    validate::validate_px_id(s)
}

pub(crate) fn hexd(s: &str) -> Result<Vec<u8>, ApiError> {
    // Used for variable-length hex fields (like OPK keys); max 4KB is generous.
    validate::validate_hex_max(s, 4096)
}

/// A blob chunk_id is exactly 64 lowercase hex chars (a SHA-256 digest).
pub(crate) fn valid_chunk_id(s: &str) -> bool {
    validate::validate_chunk_id(s)
}
