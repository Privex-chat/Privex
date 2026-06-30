// Atomic registration: key bundle + one-time prekeys + KT log entry, all in one
// transaction. Stores ONLY public keys and encrypted blobs -
// never ip/email/phone/name/device info.

use sqlx::PgPool;

use super::key_directory::KeyBundle;

pub struct NewRegistration<'a> {
    pub bundle: &'a KeyBundle,
    pub opks: &'a [(i32, Vec<u8>)],
    pub bundle_hash: &'a str, // hex SHA-256 of the key bundle (KT leaf)
    pub now: i32,
}

pub async fn register_user(pool: &PgPool, reg: NewRegistration<'_>) -> sqlx::Result<()> {
    let b = reg.bundle;
    let mut tx = pool.begin().await?;

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
    .execute(&mut *tx)
    .await?;

    for (opk_id, opk_pub) in reg.opks {
        sqlx::query!(
            r#"INSERT INTO one_time_prekeys (user_id, opk_id, opk_x25519_pub)
               VALUES ($1, $2, $3)"#,
            b.user_id,
            opk_id,
            opk_pub,
        )
        .execute(&mut *tx)
        .await?;
    }

    // OPAQUE recovery setup is provisioned later via the authenticated
    // /recovery/opaque/register/* flow - not at key registration.

    // KT log entry, chained to the current head.
    let prev = sqlx::query!(r#"SELECT bundle_hash FROM kt_log ORDER BY seq DESC LIMIT 1"#)
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| r.bundle_hash);

    sqlx::query!(
        r#"INSERT INTO kt_log (user_id, bundle_hash, operation, timestamp, prev_hash)
           VALUES ($1, $2, 'register', $3, $4)"#,
        b.user_id,
        reg.bundle_hash,
        reg.now,
        prev,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}
