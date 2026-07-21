// Shamir recovery shares (docs 4.2 path 3). Each row is an opaque encrypted blob
// (a share sealed to a recovery contact's public key). The server stores only the
// owner + share index + ciphertext - never which contacts hold the shares (the
// social graph is intentionally absent; see the recovery_shares migration).
use sqlx::PgPool;

/// All stored shares for a user, ordered by index. Served (PoW-gated) to whoever
/// drives a recovery: the blobs are sealed to contact keys, so they are useless to
/// anyone but the specific contact who holds the matching private key. Returned to
/// the RECOVERING OWNER's contacts so each can find + decrypt the one sealed to them.
pub async fn get_all_shares(db: &PgPool, user_id: &str) -> sqlx::Result<Vec<(i16, Vec<u8>)>> {
    let rows = sqlx::query!(
        "SELECT share_index, encrypted_share FROM recovery_shares
         WHERE user_id = $1 ORDER BY share_index",
        user_id,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.share_index, r.encrypted_share))
        .collect())
}

/// Replace a user's ENTIRE recovery-share set atomically (delete-all + insert-all
/// in one transaction). Re-running setup with a changed contact set must never
/// leave stale higher-index shares from a previous, larger set behind.
pub async fn replace_all_shares(
    db: &PgPool,
    user_id: &str,
    shares: &[(i16, Vec<u8>)],
) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    // Serialize concurrent replacements FOR THE SAME USER (two devices re-running
    // setup at once could otherwise interleave DELETE+INSERT under READ COMMITTED
    // snapshots and leave a merged set). Per-user xact lock; other users proceed
    // in parallel. Released automatically at commit/rollback.
    sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1)::int8)", user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DELETE FROM recovery_shares WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await?;
    for (share_index, encrypted_share) in shares {
        sqlx::query!(
            "INSERT INTO recovery_shares (user_id, share_index, encrypted_share)
             VALUES ($1, $2, $3)",
            user_id,
            share_index,
            encrypted_share,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}
