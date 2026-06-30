// Shamir recovery shares (docs 4.2 path 3). Each row is an opaque encrypted blob
// (a share sealed to a recovery contact's public key). The server stores only the
// owner + share index + ciphertext - never which contacts hold the shares (the
// social graph is intentionally absent; see the recovery_shares migration).
use sqlx::PgPool;

pub async fn store_share(
    db: &PgPool,
    user_id: &str,
    share_index: i16,
    encrypted_share: &[u8],
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO recovery_shares (user_id, share_index, encrypted_share)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, share_index)
         DO UPDATE SET encrypted_share = EXCLUDED.encrypted_share",
        user_id,
        share_index,
        encrypted_share,
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn count_shares(db: &PgPool, user_id: &str) -> sqlx::Result<i64> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM recovery_shares WHERE user_id = $1",
        user_id,
    )
    .fetch_one(db)
    .await?;
    Ok(row.n.unwrap_or(0))
}
