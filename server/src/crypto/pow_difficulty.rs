// Dynamic PoW difficulty for registration. All Redis keys here are aggregate
// counters or random challenge IDs; no IPs, user IDs, emails, or phone numbers.

use std::time::{SystemTime, UNIX_EPOCH};

use deadpool_redis::{redis, Pool as RedisPool};

const REG_WINDOW_TTL_SECS: u64 = 300;
const SUSPICION_TTL_SECS: u64 = 3600;
const MANAGER_TICK_LOCK_TTL_SECS: u64 = 25;

pub struct DifficultyState {
    pub registration_difficulty: u32,
    pub challenge_difficulty: u32,
    pub base_difficulty: u32,
    pub suspicion_bonus: u32,
    pub final_difficulty: u32,
    pub recent_registrations: u32,
    pub recent_challenges: u32,
    pub suspicion: u32,
}

pub fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

pub fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

async fn get_u32(redis: &RedisPool, key: &str) -> anyhow::Result<u32> {
    let mut conn = redis.get().await?;
    let value: Option<i64> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
    Ok(value.unwrap_or(0).max(0).min(u32::MAX as i64) as u32)
}

async fn recent_count(redis: &RedisPool, prefix: &str) -> anyhow::Result<u32> {
    let minute = unix_ts() / 60;
    let keys = [
        format!("{prefix}:{minute}"),
        format!("{prefix}:{}", minute.saturating_sub(1)),
        format!("{prefix}:{}", minute.saturating_sub(2)),
    ];

    let mut conn = redis.get().await?;
    let mut cmd = redis::cmd("MGET");
    for key in &keys {
        cmd.arg(key);
    }
    let counts: Vec<Option<i64>> = cmd.query_async(&mut conn).await?;
    let total: u64 = counts
        .into_iter()
        .flatten()
        .filter(|count| *count > 0)
        .map(|count| count as u64)
        .sum();
    Ok(total.min(u32::MAX as u64) as u32)
}

async fn incr_expiring(redis: &RedisPool, key: String, ttl_secs: u64) -> anyhow::Result<u32> {
    let mut conn = redis.get().await?;
    let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;
    let _: () = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await?;
    Ok(count.max(0).min(u32::MAX as i64) as u32)
}

pub async fn get_recent_reg_count(redis: &RedisPool) -> anyhow::Result<u32> {
    recent_count(redis, "reg:window").await
}

pub async fn get_recent_challenge_count(redis: &RedisPool) -> anyhow::Result<u32> {
    recent_count(redis, "reg:challenge_rate").await
}

pub async fn get_suspicion(redis: &RedisPool) -> anyhow::Result<u32> {
    get_u32(redis, "reg:suspicion").await
}

fn registration_difficulty(reg_count: u32) -> u32 {
    match reg_count {
        0..=5 => 22,
        6..=15 => 23,
        16..=40 => 25,
        41..=100 => 27,
        101..=300 => 29,
        _ => 31,
    }
}

fn challenge_difficulty(challenge_count: u32) -> u32 {
    match challenge_count {
        0..=30 => 22,
        31..=100 => 23,
        101..=300 => 25,
        301..=1_000 => 27,
        1_001..=3_000 => 29,
        _ => 31,
    }
}

fn suspicion_bonus(suspicion: u32) -> u32 {
    match suspicion {
        0..=10 => 0,
        11..=30 => 1,
        31..=60 => 2,
        _ => 3,
    }
}

pub async fn compute_difficulty(redis: &RedisPool) -> anyhow::Result<DifficultyState> {
    let reg_count = get_recent_reg_count(redis).await?;
    let challenge_count = get_recent_challenge_count(redis).await?;
    let registration_difficulty = registration_difficulty(reg_count);
    let challenge_difficulty = challenge_difficulty(challenge_count);
    let base = registration_difficulty.max(challenge_difficulty);
    let suspicion = get_suspicion(redis).await?;
    let bonus = suspicion_bonus(suspicion);

    Ok(DifficultyState {
        registration_difficulty,
        challenge_difficulty,
        base_difficulty: base,
        suspicion_bonus: bonus,
        final_difficulty: (base + bonus).min(31),
        recent_registrations: reg_count,
        recent_challenges: challenge_count,
        suspicion,
    })
}

pub fn minimum_solve_ms(difficulty: u32) -> u64 {
    match difficulty {
        20 => 30,
        21 => 60,
        22 => 100,
        23 => 200,
        24 => 400,
        25 => 800,
        26 => 1_600,
        27 => 3_200,
        28 => 6_400,
        29 => 12_800,
        30 => 25_600,
        31 => 51_200,
        _ => 100,
    }
}

// --- Argon2id Layer 2 (docs 8.5.1) ---
//
// The memory-hard layer that blunts GPU/ASIC advantage: SHA-256 alone is what
// mining hardware is optimized for; every Argon2id evaluation instead demands
// its own ARGON_M_COST_KIB of memory bandwidth. Parameters are bound to each
// challenge at issue time (stored in Redis), so changing these constants never
// breaks an in-flight challenge.

/// 32 MiB per evaluation - the same cost class as the app-lock KDF, chosen so a
/// mid-range phone browser solves one eval in a few hundred ms while a GPU rig
/// is memory-bandwidth-bound instead of compute-bound.
pub const ARGON_M_COST_KIB: u32 = 32 * 1024;
pub const ARGON_T_COST: u32 = 1;

/// Leading-zero-bit target over the Argon2id output, derived from the SAME
/// pressure state as the SHA difficulty: baseline 1 bit (expected 2 evals),
/// climbing to 4 bits (expected 16 evals) at the difficulty-31 ceiling.
pub fn argon_difficulty(final_difficulty: u32) -> u32 {
    (1 + final_difficulty.saturating_sub(22) / 3).min(4)
}

/// SHA pre-filter bits for a hybrid challenge: the total nonce-grinding work
/// stays ~2^final (expected SHA hashes = 2^(sha + argon)), so turning the
/// hybrid on does NOT slow honest clients' SHA phase - it adds the memory-hard
/// evals on top. Floor of 12 keeps the pre-filter meaningful (bounds server
/// verification to solutions that already cost ~4k hashes).
pub fn sha_difficulty_for_hybrid(final_difficulty: u32, argon_difficulty: u32) -> u32 {
    final_difficulty.saturating_sub(argon_difficulty).max(12)
}

/// Suspicion floor for a hybrid solve. The SHA hash runs for EVERY nonce, and a
/// full solution takes ~2^(sha+argon) nonces on average (that's the whole
/// "total work stays 2^final" design), so the SHA floor must use the COMBINED
/// bits, not just the pre-filter bits. Plus the ~2^argon Argon2id evaluations
/// at a conservative 15 ms each (fast native hardware; browsers take 10-30x
/// longer). Both are conservative underestimates, so this stays a floor that
/// only flags impossibly-fast solves, not merely fast hardware.
pub fn minimum_hybrid_solve_ms(sha_difficulty: u32, argon_difficulty: u32) -> u64 {
    minimum_solve_ms(sha_difficulty + argon_difficulty) + (1u64 << argon_difficulty.min(16)) * 15
}

pub async fn record_challenge_request(redis: &RedisPool) -> anyhow::Result<()> {
    let minute = unix_ts() / 60;
    incr_expiring(
        redis,
        format!("reg:challenge_rate:{minute}"),
        REG_WINDOW_TTL_SECS,
    )
    .await
    .map(|_| ())
}

pub async fn record_registration(redis: &RedisPool) -> anyhow::Result<()> {
    let minute = unix_ts() / 60;
    incr_expiring(redis, format!("reg:window:{minute}"), REG_WINDOW_TTL_SECS)
        .await
        .map(|_| ())
}

pub async fn increment_suspicion(redis: &RedisPool) -> anyhow::Result<u32> {
    incr_expiring(redis, "reg:suspicion".to_string(), SUSPICION_TTL_SECS).await
}

pub async fn decrement_suspicion(redis: &RedisPool) -> anyhow::Result<u32> {
    let mut conn = redis.get().await?;
    let count: i64 = redis::cmd("EVAL")
        .arg(
            r#"
local v = tonumber(redis.call('GET', KEYS[1]) or '0')
if v <= 1 then
  if v > 0 then
    redis.call('DEL', KEYS[1])
  end
  return 0
end
v = redis.call('DECR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return v
"#,
        )
        .arg(1)
        .arg("reg:suspicion")
        .arg(SUSPICION_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    Ok(count.max(0).min(u32::MAX as i64) as u32)
}

pub async fn try_acquire_manager_tick(redis: &RedisPool) -> anyhow::Result<bool> {
    let mut conn = redis.get().await?;
    let acquired: Option<String> = redis::cmd("SET")
        .arg("reg:difficulty_manager:tick")
        .arg(unix_ts().to_string())
        .arg("NX")
        .arg("EX")
        .arg(MANAGER_TICK_LOCK_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    Ok(acquired.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_pressure_thresholds() {
        assert_eq!(registration_difficulty(0), 22);
        assert_eq!(registration_difficulty(5), 22);
        assert_eq!(registration_difficulty(6), 23);
        assert_eq!(registration_difficulty(16), 25);
        assert_eq!(registration_difficulty(41), 27);
        assert_eq!(registration_difficulty(101), 29);
        assert_eq!(registration_difficulty(301), 31);
    }

    #[test]
    fn challenge_pressure_thresholds() {
        assert_eq!(challenge_difficulty(0), 22);
        assert_eq!(challenge_difficulty(30), 22);
        assert_eq!(challenge_difficulty(31), 23);
        assert_eq!(challenge_difficulty(101), 25);
        assert_eq!(challenge_difficulty(301), 27);
        assert_eq!(challenge_difficulty(1_001), 29);
        assert_eq!(challenge_difficulty(3_001), 31);
    }

    #[test]
    fn suspicion_bonus_thresholds() {
        assert_eq!(suspicion_bonus(0), 0);
        assert_eq!(suspicion_bonus(10), 0);
        assert_eq!(suspicion_bonus(11), 1);
        assert_eq!(suspicion_bonus(31), 2);
        assert_eq!(suspicion_bonus(61), 3);
    }

    #[test]
    fn argon_layer_scales_with_pressure() {
        // Baseline → 1 bit; ceiling → 4 bits.
        assert_eq!(argon_difficulty(22), 1);
        assert_eq!(argon_difficulty(25), 2);
        assert_eq!(argon_difficulty(28), 3);
        assert_eq!(argon_difficulty(31), 4);
        // Below-baseline (test configs) never underflows.
        assert_eq!(argon_difficulty(8), 1);
    }

    #[test]
    fn hybrid_sha_bits_preserve_total_work() {
        // sha + argon == final at every pressure level (down to the floor).
        for f in 22..=31 {
            let a = argon_difficulty(f);
            assert_eq!(sha_difficulty_for_hybrid(f, a) + a, f);
        }
        // Tiny test difficulties clamp to the floor instead of underflowing.
        assert_eq!(sha_difficulty_for_hybrid(8, 1), 12);
    }

    #[test]
    fn hybrid_minimum_uses_combined_sha_bits() {
        // final 22 = 21 SHA + 1 argon: combined-22 SHA floor (100ms) + 2^1*15ms.
        assert_eq!(minimum_hybrid_solve_ms(21, 1), 100 + 30);
        // Ceiling final 31 = 27 SHA + 4 argon: combined-31 SHA floor (51200ms)
        // + 2^4*15ms. (The pre-filter-only floor would undercount by 16x.)
        assert_eq!(minimum_hybrid_solve_ms(27, 4), 51_200 + 240);
    }
}
