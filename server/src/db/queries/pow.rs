// Proof-of-Work challenge queries (registration anti-spam, no IP).
use sqlx::types::Uuid;
use sqlx::PgPool;

pub struct UnusedChallenge {
    pub challenge_data: Vec<u8>,
    pub difficulty: i16,
}

/// Fetch an unused, unexpired challenge's data so the solution can be checked.
pub async fn get_unused_challenge(
    pool: &PgPool,
    challenge_id: Uuid,
    now: i32,
) -> sqlx::Result<Option<UnusedChallenge>> {
    sqlx::query_as!(
        UnusedChallenge,
        r#"SELECT challenge_data, difficulty FROM pow_challenges
           WHERE challenge_id = $1 AND used = FALSE AND expires_at >= $2"#,
        challenge_id,
        now
    )
    .fetch_optional(pool)
    .await
}

pub async fn issue_challenge(
    pool: &PgPool,
    difficulty: i16,
    challenge_data: &[u8],
    issued_at: i32,
    expires_at: i32,
) -> sqlx::Result<Uuid> {
    let row = sqlx::query!(
        r#"INSERT INTO pow_challenges (difficulty, challenge_data, issued_at, expires_at)
           VALUES ($1, $2, $3, $4)
           RETURNING challenge_id"#,
        difficulty,
        challenge_data,
        issued_at,
        expires_at,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.challenge_id)
}

/// Atomically consume a challenge: marks it used iff it is unused and unexpired.
/// Returns true if this call consumed it (prevents replay).
pub async fn verify_and_consume(pool: &PgPool, challenge_id: Uuid, now: i32) -> sqlx::Result<bool> {
    let row = sqlx::query!(
        r#"UPDATE pow_challenges SET used = TRUE
           WHERE challenge_id = $1 AND used = FALSE AND expires_at >= $2
           RETURNING challenge_id"#,
        challenge_id,
        now,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Remove expired or already-used challenges. Returns the number removed.
pub async fn cleanup_expired(pool: &PgPool, now: i32) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"DELETE FROM pow_challenges WHERE expires_at < $1 OR used = TRUE"#,
        now
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
