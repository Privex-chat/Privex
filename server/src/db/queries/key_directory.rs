// Key directory + one-time prekeys queries.
use sqlx::PgPool;

pub struct KeyBundle {
    pub user_id: String,
    pub ik_ed25519: Vec<u8>,
    pub ik_dilithium3: Vec<u8>,
    pub ik_x25519: Vec<u8>,
    pub spk_x25519: Vec<u8>,
    pub spk_sig_ed: Vec<u8>,
    pub spk_sig_dil: Vec<u8>,
    pub kyber1024_pub: Vec<u8>,
    pub spk_created_at: i32,
    pub created_at: i32,
}

pub async fn insert_key(pool: &PgPool, b: &KeyBundle) -> sqlx::Result<()> {
    sqlx::query!(
        r#"INSERT INTO key_directory
           (user_id, ik_ed25519, ik_dilithium3, ik_x25519, spk_x25519,
            spk_sig_ed, spk_sig_dil, kyber1024_pub, spk_created_at, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        b.user_id,
        b.ik_ed25519,
        b.ik_dilithium3,
        b.ik_x25519,
        b.spk_x25519,
        b.spk_sig_ed,
        b.spk_sig_dil,
        b.kyber1024_pub,
        b.spk_created_at,
        b.created_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_key(pool: &PgPool, user_id: &str) -> sqlx::Result<Option<KeyBundle>> {
    sqlx::query_as!(
        KeyBundle,
        r#"SELECT user_id, ik_ed25519, ik_dilithium3, ik_x25519, spk_x25519,
                  spk_sig_ed, spk_sig_dil, kyber1024_pub, spk_created_at, created_at
           FROM key_directory WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(pool)
    .await
}

pub async fn update_spk(
    pool: &PgPool,
    user_id: &str,
    spk_x25519: &[u8],
    spk_sig_ed: &[u8],
    spk_sig_dil: &[u8],
    spk_created_at: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE key_directory
           SET spk_x25519 = $2, spk_sig_ed = $3, spk_sig_dil = $4, spk_created_at = $5
           WHERE user_id = $1"#,
        user_id,
        spk_x25519,
        spk_sig_ed,
        spk_sig_dil,
        spk_created_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// True if the user has a key-directory entry (a real mailbox). Used to drop
/// cover-traffic messages addressed to non-existent recipients (docs 5.3).
pub async fn user_exists(pool: &PgPool, user_id: &str) -> sqlx::Result<bool> {
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM key_directory WHERE user_id = $1)"#,
        user_id
    )
    .fetch_one(pool)
    .await?;
    Ok(exists.unwrap_or(false))
}

pub async fn list_opk_count(pool: &PgPool, user_id: &str) -> sqlx::Result<i64> {
    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = $1"#,
        user_id
    )
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0))
}

/// Insert one prekey. Returns the number of rows actually inserted (0 on a
/// duplicate opk_id, thanks to ON CONFLICT DO NOTHING).
pub async fn insert_one_time_prekey(
    pool: &PgPool,
    user_id: &str,
    opk_id: i32,
    opk_x25519_pub: &[u8],
) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"INSERT INTO one_time_prekeys (user_id, opk_id, opk_x25519_pub)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id, opk_id) DO NOTHING"#,
        user_id,
        opk_id,
        opk_x25519_pub,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Serve exactly one prekey and delete it (single-use). None if exhausted.
/// Uses FOR UPDATE SKIP LOCKED so concurrent fetches claim DIFFERENT prekeys
/// (never the same one).
pub async fn take_one_time_prekey(
    pool: &PgPool,
    user_id: &str,
) -> sqlx::Result<Option<(i32, Vec<u8>)>> {
    let row = sqlx::query!(
        r#"WITH claimed AS (
               SELECT user_id, opk_id FROM one_time_prekeys
               WHERE user_id = $1
               ORDER BY opk_id
               FOR UPDATE SKIP LOCKED
               LIMIT 1
           )
           DELETE FROM one_time_prekeys o
           USING claimed c
           WHERE o.user_id = c.user_id AND o.opk_id = c.opk_id
           RETURNING o.opk_id, o.opk_x25519_pub"#,
        user_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.opk_id, r.opk_x25519_pub)))
}
