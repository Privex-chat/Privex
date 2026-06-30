// Key Transparency log queries. Append-only, hash-chained.
use sqlx::PgPool;

pub struct KtRoot {
    pub seq: i64,
    pub bundle_hash: String,
}

pub async fn append_entry(
    pool: &PgPool,
    user_id: &str,
    bundle_hash: &str,
    operation: &str,
    timestamp: i32,
    prev_hash: Option<&str>,
) -> sqlx::Result<i64> {
    let row = sqlx::query!(
        r#"INSERT INTO kt_log (user_id, bundle_hash, operation, timestamp, prev_hash)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING seq"#,
        user_id,
        bundle_hash,
        operation,
        timestamp,
        prev_hash,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.seq)
}

pub struct KtEntry {
    pub user_id: String,
    pub bundle_hash: String,
    pub timestamp: i32,
}

/// All entries in append order (by seq). The Merkle tree is built over these.
/// O(N) full scan - acceptable for Phase 1; optimize with a cached tree later.
pub async fn list_all_entries(pool: &PgPool) -> sqlx::Result<Vec<KtEntry>> {
    sqlx::query_as!(
        KtEntry,
        r#"SELECT user_id, bundle_hash, timestamp FROM kt_log ORDER BY seq"#
    )
    .fetch_all(pool)
    .await
}

/// The current log head (latest entry). The published signed Merkle root is
/// computed from the full table by the KT-log session; this returns the tip.
pub async fn get_root(pool: &PgPool) -> sqlx::Result<Option<KtRoot>> {
    sqlx::query_as!(
        KtRoot,
        r#"SELECT seq, bundle_hash FROM kt_log ORDER BY seq DESC LIMIT 1"#
    )
    .fetch_optional(pool)
    .await
}

/// Fetch a single entry by sequence number. The full Merkle inclusion proof
/// (leaf + path + root) is built in the dedicated KT-log session; this is the
/// leaf lookup it builds on.
pub async fn get_inclusion_proof(
    pool: &PgPool,
    seq: i64,
) -> sqlx::Result<Option<(String, String)>> {
    let row = sqlx::query!(
        r#"SELECT bundle_hash, user_id FROM kt_log WHERE seq = $1"#,
        seq
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.bundle_hash, r.user_id)))
}
