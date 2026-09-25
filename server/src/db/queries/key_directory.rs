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

/// Serialize every write to ONE user's prekey inventory (per-user transaction
/// lock, released at commit/rollback; other users proceed in parallel). Under
/// READ COMMITTED, two overlapping replacements would otherwise both commit and
/// leave the UNION of their sets - prekeys whose private halves only one device
/// holds - and an additive batch could land inside a replacement.
async fn lock_user_opks(conn: &mut sqlx::PgConnection, user_id: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtext('opk:' || $1)::int8)",
        user_id
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Insert prekeys; returns how many were actually added (a duplicate opk_id is
/// skipped by ON CONFLICT DO NOTHING).
async fn insert_opks(
    conn: &mut sqlx::PgConnection,
    user_id: &str,
    opks: &[(i32, Vec<u8>)],
) -> sqlx::Result<u64> {
    let mut stored = 0;
    for (opk_id, opk_x25519_pub) in opks {
        stored += sqlx::query!(
            r#"INSERT INTO one_time_prekeys (user_id, opk_id, opk_x25519_pub)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id, opk_id) DO NOTHING"#,
            user_id,
            opk_id,
            opk_x25519_pub,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
    }
    Ok(stored)
}

/// Add a batch of prekeys to a user's inventory, as one locked transaction.
/// Returns the number actually added.
pub async fn add_one_time_prekeys(
    pool: &PgPool,
    user_id: &str,
    opks: &[(i32, Vec<u8>)],
) -> sqlx::Result<u64> {
    let mut tx = pool.begin().await?;
    lock_user_opks(&mut tx, user_id).await?;
    let stored = insert_opks(&mut tx, user_id, opks).await?;
    tx.commit().await?;
    Ok(stored)
}

/// Atomically REPLACE a user's whole one-time-prekey inventory (used by account
/// recovery). The previous prekeys' private halves died with the lost device, so
/// any left behind would still be served to peers, whose first message the
/// recovered device could then never decrypt. Returns the number stored.
pub async fn replace_one_time_prekeys(
    pool: &PgPool,
    user_id: &str,
    opks: &[(i32, Vec<u8>)],
) -> sqlx::Result<u64> {
    let mut tx = pool.begin().await?;
    lock_user_opks(&mut tx, user_id).await?;
    sqlx::query!(
        r#"DELETE FROM one_time_prekeys WHERE user_id = $1"#,
        user_id
    )
    .execute(&mut *tx)
    .await?;
    let stored = insert_opks(&mut tx, user_id, opks).await?;
    tx.commit().await?;
    Ok(stored)
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
