// Ephemeral social-recovery rendezvous (docs 4.2 path 3 retrieval). A random
// recovery_id names a transient bucket; contacts POST shares (sealed to the
// owner's ephemeral key), the owner GETs them. No account/contact id is ever
// stored - the server cannot link a bucket to any user (Law 3). UNLOGGED + TTL.
use sqlx::PgPool;

/// Append a re-sealed share to a rendezvous bucket. Callers enforce the per-bucket
/// cap (via `count`) BEFORE inserting so a bucket can't be flooded unboundedly.
pub async fn post(
    db: &PgPool,
    recovery_id: &str,
    blob: &[u8],
    created_at: i32,
    expires_at: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO recovery_rendezvous (recovery_id, blob, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
        recovery_id,
        blob,
        created_at,
        expires_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Live (non-expired) blob count in a bucket - the per-bucket flood cap check.
pub async fn count(db: &PgPool, recovery_id: &str, now: i32) -> sqlx::Result<i64> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM recovery_rendezvous
         WHERE recovery_id = $1 AND expires_at > $2",
        recovery_id,
        now,
    )
    .fetch_one(db)
    .await?;
    Ok(row.n.unwrap_or(0))
}

/// All live blobs posted to a bucket (the owner polls this). Expired rows are
/// filtered here and swept separately, so a stale bucket returns nothing.
pub async fn list(db: &PgPool, recovery_id: &str, now: i32) -> sqlx::Result<Vec<Vec<u8>>> {
    let rows = sqlx::query!(
        "SELECT blob FROM recovery_rendezvous
         WHERE recovery_id = $1 AND expires_at > $2 ORDER BY id",
        recovery_id,
        now,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| r.blob).collect())
}

/// Delete expired rendezvous rows. Returns the count removed.
pub async fn cleanup_expired(db: &PgPool, now: i32) -> sqlx::Result<u64> {
    let result = sqlx::query!("DELETE FROM recovery_rendezvous WHERE expires_at < $1", now)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}
