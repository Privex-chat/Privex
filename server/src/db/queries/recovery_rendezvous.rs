// Ephemeral social-recovery rendezvous (docs 4.2 path 3 retrieval). A random
// recovery_id names a transient bucket; contacts POST shares (sealed to the
// owner's ephemeral key), the owner GETs them. No account/contact id is ever
// stored - the server cannot link a bucket to any user (Law 3). UNLOGGED + TTL.
use sqlx::PgPool;

/// Append a re-sealed share to a rendezvous bucket, enforcing the per-bucket flood
/// cap ATOMICALLY. Returns `false` (nothing inserted) when the bucket is already at
/// `max` live blobs. The count + insert run under a per-bucket advisory xact lock
/// so concurrent posts to the same recovery_id can't both pass the check and blow
/// past the cap (a plain count-then-insert, even as one conditional statement, races
/// under MVCC snapshots). Different buckets proceed in parallel.
pub async fn post(
    db: &PgPool,
    recovery_id: &str,
    blob: &[u8],
    now: i32,
    expires_at: i32,
    max: i64,
) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1)::int8)", recovery_id)
        .execute(&mut *tx)
        .await?;
    let n = sqlx::query!(
        "SELECT COUNT(*) AS n FROM recovery_rendezvous
         WHERE recovery_id = $1 AND expires_at > $2",
        recovery_id,
        now,
    )
    .fetch_one(&mut *tx)
    .await?
    .n
    .unwrap_or(0);
    if n >= max {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query!(
        "INSERT INTO recovery_rendezvous (recovery_id, blob, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
        recovery_id,
        blob,
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
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
