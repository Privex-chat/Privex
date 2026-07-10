// Redis access (deadpool-redis). NO raw user_id ever stored as a key: every key
// is namespaced by HMAC-SHA256(redis_ns_key, identity) - a purpose-bound subkey
// of the root secret (PVX-24), separate from the session-token MAC key. Redis
// runs with no persistence (save "" / appendonly no) - nothing here touches disk.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use deadpool_redis::{redis, Pool};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn keyed(server_key: &[u8; 32], scope: &str, identity: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(server_key).expect("hmac key");
    mac.update(scope.as_bytes());
    mac.update(b":");
    mac.update(identity.as_bytes());
    format!("{scope}:{}", hex::encode(mac.finalize().into_bytes()))
}

/// Fixed-window rate limit. Returns true if the call is within the limit.
pub async fn check_rate_limit(
    pool: &Pool,
    server_key: &[u8; 32],
    scope: &str,
    identity: &str,
    limit: i64,
    window_secs: i64,
) -> anyhow::Result<bool> {
    let key = format!("rl:{}", keyed(server_key, scope, identity));
    let mut conn = pool.get().await?;
    let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;
    if count == 1 {
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(window_secs)
            .query_async(&mut conn)
            .await?;
    }
    Ok(count <= limit)
}

/// Store an auth challenge for a user (single-use, short TTL).
pub async fn store_challenge(
    pool: &Pool,
    server_key: &[u8; 32],
    user_id: &str,
    challenge: &[u8],
    ttl_secs: i64,
) -> anyhow::Result<()> {
    let key = format!("chal:{}", keyed(server_key, "chal", user_id));
    let mut conn = pool.get().await?;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(challenge)
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

/// Store a single-use WebSocket auth ticket → user_id (short TTL). The Redis
/// key is the HMAC of the ticket, never the raw ticket.
pub async fn store_ws_ticket(
    pool: &Pool,
    server_key: &[u8; 32],
    ticket: &str,
    user_id: &str,
    ttl_secs: i64,
) -> anyhow::Result<()> {
    let key = format!("wst:{}", keyed(server_key, "wst", ticket));
    let mut conn = pool.get().await?;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(user_id)
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

/// Atomically consume a WebSocket ticket, returning the user_id (single use).
pub async fn take_ws_ticket(
    pool: &Pool,
    server_key: &[u8; 32],
    ticket: &str,
) -> anyhow::Result<Option<String>> {
    let key = format!("wst:{}", keyed(server_key, "wst", ticket));
    let mut conn = pool.get().await?;
    let value: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut conn)
        .await?;
    Ok(value)
}

/// Store OPAQUE login state for an in-flight recovery (TTL-bound, single-use).
/// The Redis key is the HMAC of a random login_id; the value carries the
/// user_id + OPAQUE record tag + serialized ServerLogin state. The record
/// tag makes recovery toggles immediate: a login started before disable or
/// password-reset cannot mint a session after the record changes.
#[derive(Serialize, Deserialize)]
struct StoredLoginState {
    user_id: String,
    record_tag: Option<String>,
    state: String,
}

pub async fn store_login_state(
    pool: &Pool,
    server_key: &[u8; 32],
    login_id: &str,
    user_id: &str,
    record_tag: Option<&str>,
    state: &[u8],
    ttl_secs: i64,
) -> anyhow::Result<()> {
    let key = format!("opq:{}", keyed(server_key, "opq", login_id));
    let value = serde_json::to_string(&StoredLoginState {
        user_id: user_id.to_string(),
        record_tag: record_tag.map(str::to_string),
        state: STANDARD.encode(state),
    })?;
    let mut conn = pool.get().await?;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(value)
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

/// Atomically consume OPAQUE login state → (user_id, ServerLogin state).
pub async fn take_login_state(
    pool: &Pool,
    server_key: &[u8; 32],
    login_id: &str,
) -> anyhow::Result<Option<(String, Option<String>, Vec<u8>)>> {
    let key = format!("opq:{}", keyed(server_key, "opq", login_id));
    let mut conn = pool.get().await?;
    let value: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut conn)
        .await?;
    match value {
        Some(v) => {
            if let Ok(stored) = serde_json::from_str::<StoredLoginState>(&v) {
                let state = STANDARD.decode(stored.state)?;
                Ok(Some((stored.user_id, stored.record_tag, state)))
            } else {
                // Graceful deployment fallback for login states created by the
                // previous value format. Callers treat these as stale because
                // they have no matching record version.
                let (user_id, b64) = v
                    .split_once('|')
                    .ok_or_else(|| anyhow::anyhow!("corrupt"))?;
                let state = STANDARD.decode(b64)?;
                Ok(Some((user_id.to_string(), None, state)))
            }
        }
        None => Ok(None),
    }
}

/// Atomically fetch-and-delete a user's challenge (single use → replay-proof).
pub async fn take_challenge(
    pool: &Pool,
    server_key: &[u8; 32],
    user_id: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let key = format!("chal:{}", keyed(server_key, "chal", user_id));
    let mut conn = pool.get().await?;
    let value: Option<Vec<u8>> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut conn)
        .await?;
    Ok(value)
}

/// Token revocation cutoff: every session token issued BEFORE this unix time is
/// invalid (used by "log out everywhere"). Keyed by HMAC(user_id); TTL = token
/// TTL, after which all older tokens have already expired.
pub async fn set_revoke_cutoff(
    pool: &Pool,
    server_key: &[u8; 32],
    user_id: &str,
    cutoff: i64,
    ttl_secs: i64,
) -> anyhow::Result<()> {
    let key = format!("rev:{}", keyed(server_key, "rev", user_id));
    let mut conn = pool.get().await?;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(cutoff)
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

pub async fn get_revoke_cutoff(
    pool: &Pool,
    server_key: &[u8; 32],
    user_id: &str,
) -> anyhow::Result<Option<i64>> {
    let key = format!("rev:{}", keyed(server_key, "rev", user_id));
    let mut conn = pool.get().await?;
    let value: Option<i64> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
    Ok(value)
}

pub struct PowChallenge {
    pub challenge_data: Vec<u8>,
    pub difficulty: u32,
    pub issued_at_ms: u64,
    /// Argon2id Layer-2 parameters (docs 8.5.1). None = legacy SHA-only
    /// challenge; Some = hybrid, verified with powcheck::hybrid_valid.
    pub argon: Option<crate::powcheck::ArgonParams>,
}

#[derive(Serialize, Deserialize)]
struct StoredPowChallenge {
    challenge: String,
    difficulty: u32,
    issued_at_ms: u64,
    used: bool,
    // Absent on records written before the hybrid rollout → serde default None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon_m_cost_kib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon_t_cost: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon_difficulty: Option<u32>,
}

fn pow_challenge_key(challenge_id: &str) -> String {
    format!("pow:challenge:{challenge_id}")
}

/// Hard ceiling on the per-verify Argon2id memory a stored challenge may
/// request. The server only ever ISSUES `ARGON_M_COST_KIB` (32 MiB); this caps
/// the blast radius if a challenge is ever tampered (Redis compromise) so a
/// single verify can't be coerced into a pathological allocation. 64 MiB leaves
/// 2x headroom for a future memory-cost bump (docs 8.5.1 escalation) — raise
/// this in lockstep if the issued cost is ever raised past it.
const MAX_ARGON_M_COST_KIB: u32 = 64 * 1024;

fn validate_argon(argon: &crate::powcheck::ArgonParams) -> anyhow::Result<()> {
    // Argon2 spec minimum m is 8 KiB/lane.
    if !(8..=MAX_ARGON_M_COST_KIB).contains(&argon.m_cost_kib)
        || !(1..=8).contains(&argon.t_cost)
        || !(1..=16).contains(&argon.difficulty)
    {
        anyhow::bail!("invalid argon pow params");
    }
    Ok(())
}

fn decode_pow_challenge(value: &str) -> anyhow::Result<Option<PowChallenge>> {
    let stored: StoredPowChallenge = serde_json::from_str(value)?;
    if stored.used {
        return Ok(None);
    }
    if !(1..=31).contains(&stored.difficulty) {
        anyhow::bail!("invalid pow difficulty");
    }
    let challenge_data = hex::decode(stored.challenge)?;
    if challenge_data.len() != 32 {
        anyhow::bail!("invalid pow challenge length");
    }
    let argon = match (stored.argon_m_cost_kib, stored.argon_t_cost, stored.argon_difficulty) {
        (Some(m), Some(t), Some(d)) => {
            let a = crate::powcheck::ArgonParams {
                m_cost_kib: m,
                t_cost: t,
                difficulty: d,
            };
            validate_argon(&a)?;
            Some(a)
        }
        (None, None, None) => None,
        _ => anyhow::bail!("invalid argon pow params"),
    };
    Ok(Some(PowChallenge {
        challenge_data,
        difficulty: stored.difficulty,
        issued_at_ms: stored.issued_at_ms,
        argon,
    }))
}

pub async fn store_pow_challenge(
    pool: &Pool,
    challenge_id: &str,
    challenge_data: &[u8],
    difficulty: u32,
    argon: Option<crate::powcheck::ArgonParams>,
    issued_at_ms: u64,
    ttl_secs: i64,
) -> anyhow::Result<()> {
    if challenge_data.len() != 32 {
        anyhow::bail!("invalid pow challenge length");
    }
    if !(1..=31).contains(&difficulty) {
        anyhow::bail!("invalid pow difficulty");
    }
    if let Some(a) = &argon {
        validate_argon(a)?;
    }
    let value = serde_json::to_string(&StoredPowChallenge {
        challenge: hex::encode(challenge_data),
        difficulty,
        issued_at_ms,
        used: false,
        argon_m_cost_kib: argon.map(|a| a.m_cost_kib),
        argon_t_cost: argon.map(|a| a.t_cost),
        argon_difficulty: argon.map(|a| a.difficulty),
    })?;
    let key = pow_challenge_key(challenge_id);
    let mut conn = pool.get().await?;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(value)
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(())
}

pub async fn take_pow_challenge(
    pool: &Pool,
    challenge_id: &str,
) -> anyhow::Result<Option<PowChallenge>> {
    let key = pow_challenge_key(challenge_id);
    let mut conn = pool.get().await?;
    let value: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut conn)
        .await?;
    match value {
        Some(value) => decode_pow_challenge(&value),
        None => Ok(None),
    }
}

#[cfg(test)]
mod pow_challenge_tests {
    use super::decode_pow_challenge;

    // Records written BEFORE the hybrid rollout have no argon fields and must
    // keep decoding as legacy SHA-only challenges (rolling deploy safety).
    #[test]
    fn decodes_legacy_record_without_argon_fields() {
        let legacy = r#"{"challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","difficulty":22,"issued_at_ms":1,"used":false}"#;
        let c = decode_pow_challenge(legacy).unwrap().unwrap();
        assert_eq!(c.difficulty, 22);
        assert!(c.argon.is_none());
    }

    #[test]
    fn decodes_hybrid_record_and_rejects_partial_or_bogus_params() {
        let hybrid = r#"{"challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","difficulty":21,"issued_at_ms":1,"used":false,"argon_m_cost_kib":32768,"argon_t_cost":1,"argon_difficulty":1}"#;
        let c = decode_pow_challenge(hybrid).unwrap().unwrap();
        let a = c.argon.unwrap();
        assert_eq!((a.m_cost_kib, a.t_cost, a.difficulty), (32768, 1, 1));

        // Partial argon fields are corrupt, not legacy.
        let partial = r#"{"challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","difficulty":21,"issued_at_ms":1,"used":false,"argon_m_cost_kib":32768}"#;
        assert!(decode_pow_challenge(partial).is_err());

        // Out-of-range params are rejected at decode.
        let bogus = r#"{"challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","difficulty":21,"issued_at_ms":1,"used":false,"argon_m_cost_kib":4,"argon_t_cost":1,"argon_difficulty":1}"#;
        assert!(decode_pow_challenge(bogus).is_err());
    }
}
