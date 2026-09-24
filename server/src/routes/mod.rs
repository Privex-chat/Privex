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

/// How long a verify may wait for a memory-hard evaluation slot before giving up
/// with 429. Issuance is uncapped (stateless tickets), so this bound - not an
/// issuance limit - is what keeps a burst of pre-filter-passing solutions from
/// queueing without limit. Legit load never waits anywhere near this long.
const POW_VERIFY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Verify a single-use PoW solution against a signed ticket (pow_ticket.rs).
/// Returns 400 on any failure (forged / expired / replayed ticket, bad math). A
/// valid-but-impossibly-fast solve is ACCEPTED but bumps aggregate suspicion
/// (raising difficulty for everyone) - never rejected, since fast hardware is
/// legitimate. No IP/user/identity is read or logged. This is the only
/// privacy-preserving gate for the public, target-revealing endpoints (key
/// fetch, KT proof, OPAQUE login init, share fetch, rendezvous post).
///
/// Order matters - each step only runs if the cheaper one before it passed:
///   1. ticket MAC + expiry (no I/O)
///   2. SHA-256 pre-filter (one hash). Garbage stops here WITHOUT consuming the
///      ticket: it leaves no Redis state and costs the server one hash the
///      attacker could compute locally, so it's neither an oracle nor a work loop.
///   3. mark the ticket spent (Redis SET NX) - anything reaching real
///      verification work consumes its ticket, valid or not (docs 8.5).
///   4. Argon2id layer (hybrid tickets), off the async threads, bounded by the
///      concurrency semaphore.
pub(crate) async fn verify_pow(st: &AppState, pow: &PowProof) -> Result<(), ApiError> {
    let now_ms = pow_difficulty::unix_ts_ms();
    let sol = validate::validate_solution_hash(&pow.solution_hash)?;
    let ticket = crate::pow_ticket::open(&st.config.pow_ticket_key, &pow.challenge_id)
        .ok_or_else(ApiError::bad_request)?;
    let now = crate::now_unix();
    if now >= ticket.expires_at {
        return Err(ApiError::bad_request());
    }
    if !crate::powcheck::sha_prefilter_ok(&ticket.challenge, pow.nonce, ticket.difficulty) {
        return Err(ApiError::bad_request());
    }
    let first_use =
        crate::rds::spend_pow_ticket(&st.redis, &ticket.id, ticket.expires_at - now + 1)
            .await
            .map_err(|_| ApiError::internal())?;
    if !first_use {
        return Err(ApiError::bad_request()); // replay
    }

    let (valid, min_expected) = match ticket.argon {
        Some(argon) => {
            // The Argon2id evaluation is tens of ms of sync CPU + a ~32 MiB
            // allocation - run it off the async worker threads, and cap how many
            // run at once (peak memory). Waiting for a slot is bounded too.
            let _permit = tokio::time::timeout(POW_VERIFY_WAIT, st.pow_verify_sem.acquire())
                .await
                .map_err(|_| ApiError::rate_limited())?
                .map_err(|_| ApiError::internal())?;
            let challenge = ticket.challenge;
            let nonce = pow.nonce;
            let sha_difficulty = ticket.difficulty;
            let sol_owned = sol.clone();
            let valid = tokio::task::spawn_blocking(move || {
                crate::powcheck::hybrid_valid(&challenge, nonce, sha_difficulty, &argon, &sol_owned)
            })
            .await
            .map_err(|_| ApiError::internal())?;
            (
                valid,
                pow_difficulty::minimum_hybrid_solve_ms(ticket.difficulty, argon.difficulty),
            )
        }
        None => (
            crate::powcheck::pow_valid(&ticket.challenge, pow.nonce, ticket.difficulty, &sol),
            pow_difficulty::minimum_solve_ms(ticket.difficulty),
        ),
    };
    if !valid {
        return Err(ApiError::bad_request());
    }

    let solve_time_ms = now_ms.saturating_sub(ticket.issued_at_ms);
    if solve_time_ms < min_expected {
        let suspicion = pow_difficulty::increment_suspicion(&st.redis)
            .await
            .unwrap_or(0);
        log_suspicious_pow_solve(suspicion, solve_time_ms, min_expected, ticket.difficulty);
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
