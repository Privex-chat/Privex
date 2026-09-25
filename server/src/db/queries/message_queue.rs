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

/// One page of a recipient's queue queued at or before `until`, strictly after
/// the (queued_at, message_id) cursor, oldest first. Paging keeps connect-time
/// delivery memory at one page however large the mailbox is.
pub async fn dequeue_page(
    pool: &PgPool,
    recipient_id: &str,
    until: i32,
    after: (i32, Uuid),
    limit: i64,
) -> sqlx::Result<Vec<QueuedMessage>> {
    sqlx::query_as!(
        QueuedMessage,
        r#"SELECT message_id, content, queued_at
           FROM message_queue
           WHERE recipient_id = $1 AND queued_at <= $2
             AND (queued_at, message_id) > ($3, $4)
           ORDER BY queued_at, message_id
           LIMIT $5"#,
        recipient_id,
        until,
        after.0,
        after.1,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// (message count, total bytes) currently queued for a recipient.
pub async fn mailbox_usage(pool: &PgPool, recipient_id: &str) -> sqlx::Result<(i64, i64)> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!", COALESCE(SUM(size_bytes), 0)::BIGINT AS "bytes!"
           FROM message_queue WHERE recipient_id = $1"#,
        recipient_id
    )
    .fetch_one(pool)
    .await?;
    Ok((row.count, row.bytes))
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
