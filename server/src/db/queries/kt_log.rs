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

/// Repair missing KT log entries after an unclean shutdown.
/// `kt_log` was UNLOGGED and could be truncated on crash while `key_directory`
/// (LOGGED) survives. This rebuilds entries from `key_directory` data for any
/// user missing from the KT log.
pub async fn repair_kt_log(pool: &PgPool) -> sqlx::Result<()> {
    use sqlx::FromRow;

    #[derive(FromRow)]
    struct KdRow {
        user_id: String,
        ik_ed25519: Vec<u8>,
        ik_dilithium3: Vec<u8>,
        ik_x25519: Vec<u8>,
        spk_x25519: Vec<u8>,
        spk_sig_ed: Vec<u8>,
        spk_sig_dil: Vec<u8>,
        kyber1024_pub: Vec<u8>,
        created_at: i32,
    }

    let rows: Vec<KdRow> = sqlx::query_as(
        r#"SELECT kd.user_id, kd.ik_ed25519, kd.ik_dilithium3, kd.ik_x25519,
                  kd.spk_x25519, kd.spk_sig_ed, kd.spk_sig_dil, kd.kyber1024_pub, kd.created_at
           FROM key_directory kd
           LEFT JOIN kt_log kl ON kl.user_id = kd.user_id
           WHERE kl.user_id IS NULL
           ORDER BY kd.created_at"#,
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    tracing::info!(
        event = "kt_log_repair",
        missing = rows.len(),
        "rebuilding kt_log entries after unclean shutdown"
    );

    // Chain to the current tail of the log (if any).
    let prev_hash: Option<String> = sqlx::query_scalar(
        "SELECT bundle_hash FROM kt_log ORDER BY seq DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    .flatten();

    let mut tx = pool.begin().await?;
    let mut prev = prev_hash;

    for row in &rows {
        let bh = crate::crypto::kt_log::bundle_hash(
            &row.ik_ed25519,
            &row.ik_dilithium3,
            &row.ik_x25519,
            &row.spk_x25519,
            &row.spk_sig_ed,
            &row.spk_sig_dil,
            &row.kyber1024_pub,
        );
        let bundle_hash_hex = hex::encode(bh);

        sqlx::query(
            r#"INSERT INTO kt_log (user_id, bundle_hash, operation, timestamp, prev_hash)
               VALUES ($1, $2, 'register', $3, $4)"#,
        )
        .bind(&row.user_id)
        .bind(&bundle_hash_hex)
        .bind(row.created_at)
        .bind(&prev)
        .execute(&mut *tx)
        .await?;

        prev = Some(bundle_hash_hex);
    }

    tx.commit().await
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
