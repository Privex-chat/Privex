// Message queue queries. Sealed Sender blobs; hard-deleted on ACK.
use sqlx::types::Uuid;
use sqlx::PgPool;

pub struct QueuedMessage {
    pub message_id: Uuid,
    pub content: Vec<u8>,
    pub queued_at: i32,
}

pub async fn enqueue(
    pool: &PgPool,
    recipient_id: &str,
    content: &[u8],
    csam_proof: Option<&[u8]>,
    queued_at: i32,
    expires_at: i32,
    size_bytes: i32,
) -> sqlx::Result<Uuid> {
    let row = sqlx::query!(
        r#"INSERT INTO message_queue
           (recipient_id, content, csam_proof, queued_at, expires_at, size_bytes)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING message_id"#,
        recipient_id,
        content,
        csam_proof,
        queued_at,
        expires_at,
        size_bytes,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.message_id)
}

pub async fn dequeue_for_recipient(
    pool: &PgPool,
    recipient_id: &str,
) -> sqlx::Result<Vec<QueuedMessage>> {
    sqlx::query_as!(
        QueuedMessage,
        r#"SELECT message_id, content, queued_at
           FROM message_queue WHERE recipient_id = $1 ORDER BY queued_at"#,
        recipient_id
    )
    .fetch_all(pool)
    .await
}

/// Delete messages past their expiry (queued_at + 30 days). Returns the count.
pub async fn cleanup_expired(pool: &PgPool, now: i32) -> sqlx::Result<u64> {
    let result = sqlx::query!(r#"DELETE FROM message_queue WHERE expires_at < $1"#, now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Hard-delete acknowledged messages owned by this recipient. Scoping by
/// recipient_id means a caller can only delete their own mail. Returns the
/// number removed.
pub async fn ack_messages(
    pool: &PgPool,
    recipient_id: &str,
    message_ids: &[Uuid],
) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"DELETE FROM message_queue
           WHERE message_id = ANY($1) AND recipient_id = $2"#,
        message_ids,
        recipient_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
