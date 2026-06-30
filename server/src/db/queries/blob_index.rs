// Blob index queries. Index only - encrypted chunks live in the object store.
use sqlx::PgPool;

pub async fn store_blob(
    pool: &PgPool,
    chunk_id: &str,
    storage_path: &str,
    size_bytes: i32,
    expires_at: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"INSERT INTO blob_index (chunk_id, storage_path, size_bytes, expires_at)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (chunk_id) DO NOTHING"#,
        chunk_id,
        storage_path,
        size_bytes,
        expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_blob_path(pool: &PgPool, chunk_id: &str) -> sqlx::Result<Option<String>> {
    let row = sqlx::query!(
        r#"SELECT storage_path FROM blob_index WHERE chunk_id = $1"#,
        chunk_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.storage_path))
}

pub async fn mark_downloaded(pool: &PgPool, chunk_id: &str) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE blob_index SET downloaded = TRUE WHERE chunk_id = $1"#,
        chunk_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark a blob downloaded and pull its expiry in to `download_expiry` if that's
/// sooner (24h after first download, or the original 7-day TTL - whichever is
/// first). Returns true if the chunk exists.
pub async fn mark_downloaded_and_expire(
    pool: &PgPool,
    chunk_id: &str,
    download_expiry: i32,
) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        r#"UPDATE blob_index
           SET downloaded = TRUE, expires_at = LEAST(expires_at, $2)
           WHERE chunk_id = $1"#,
        chunk_id,
        download_expiry,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Hard-delete a single blob index row. Returns true if a row was removed.
pub async fn delete_blob(pool: &PgPool, chunk_id: &str) -> sqlx::Result<bool> {
    let result = sqlx::query!(r#"DELETE FROM blob_index WHERE chunk_id = $1"#, chunk_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub struct ExpiredBlob {
    pub chunk_id: String,
    pub storage_path: String,
}

/// Expired blobs (for object-store deletion before the index rows are removed).
pub async fn list_expired(pool: &PgPool, now: i32) -> sqlx::Result<Vec<ExpiredBlob>> {
    sqlx::query_as!(
        ExpiredBlob,
        r#"SELECT chunk_id, storage_path FROM blob_index WHERE expires_at < $1"#,
        now
    )
    .fetch_all(pool)
    .await
}

/// Remove expired blob index rows. Returns the number removed.
pub async fn cleanup_expired(pool: &PgPool, now: i32) -> sqlx::Result<u64> {
    let result = sqlx::query!(r#"DELETE FROM blob_index WHERE expires_at < $1"#, now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
