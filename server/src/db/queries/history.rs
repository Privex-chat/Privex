// Encrypted chat-history backup blobs (history sync Option A). Each row is an
// opaque AES-256-GCM blob the server can't read. Scoped by user_id (from the auth
// token); a caller only ever sees / deletes their own. blob_id = the client msg_id
// (or "contact:<px_id>" sidecar) so re-uploads are idempotent.
use sqlx::PgPool;

pub struct HistoryBlob {
    pub blob_id: String,
    pub ciphertext: Vec<u8>,
    pub created_at: i32,
}

/// Insert or refresh one blob. DO UPDATE (not DO NOTHING) so a re-upload after a
/// status change (e.g. queued → sent) overwrites the stale copy.
pub async fn upsert(
    db: &PgPool,
    user_id: &str,
    blob_id: &str,
    ciphertext: &[u8],
    created_at: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO history_blobs (user_id, blob_id, ciphertext, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, blob_id)
         DO UPDATE SET ciphertext = EXCLUDED.ciphertext, created_at = EXCLUDED.created_at",
        user_id,
        blob_id,
        ciphertext,
        created_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// One page, oldest-first, after the strict composite cursor (after_created_at,
/// after_blob_id). Pass (0, "") for the first page. The strict `>` over both columns
/// guarantees forward progress even when many rows share one created_at second.
pub async fn list(
    db: &PgPool,
    user_id: &str,
    after_created_at: i32,
    after_blob_id: &str,
    limit: i64,
) -> sqlx::Result<Vec<HistoryBlob>> {
    sqlx::query_as!(
        HistoryBlob,
        r#"SELECT blob_id, ciphertext, created_at
           FROM history_blobs
           WHERE user_id = $1
             AND (created_at > $2 OR (created_at = $2 AND blob_id > $3))
           ORDER BY created_at, blob_id
           LIMIT $4"#,
        user_id,
        after_created_at,
        after_blob_id,
        limit,
    )
    .fetch_all(db)
    .await
}

/// (count, total ciphertext bytes) for the Settings indicator + restore probe.
pub async fn stats(db: &PgPool, user_id: &str) -> sqlx::Result<(i64, i64)> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!", COALESCE(SUM(LENGTH(ciphertext)), 0) AS "bytes!"
           FROM history_blobs WHERE user_id = $1"#,
        user_id,
    )
    .fetch_one(db)
    .await?;
    Ok((row.n, row.bytes))
}

/// Delete every blob for this user (turning backup off). Immediate, permanent.
pub async fn delete_all(db: &PgPool, user_id: &str) -> sqlx::Result<u64> {
    let r = sqlx::query!("DELETE FROM history_blobs WHERE user_id = $1", user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}
