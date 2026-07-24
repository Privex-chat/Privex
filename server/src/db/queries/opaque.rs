// OPAQUE record queries. Server stores the OPRF record + encrypted envelope it
// cannot decrypt. NEVER any function of the password.
use sqlx::{PgPool, Row};

pub struct OpaqueRecord {
    pub oprf_record: Vec<u8>,
    pub envelope: Vec<u8>,
    pub envelope_mac: Vec<u8>,
}

pub struct OpaqueLoginRecord {
    pub oprf_record: Vec<u8>,
    pub envelope: Vec<u8>,
    pub envelope_mac: Vec<u8>,
}

pub async fn get_opaque_record(pool: &PgPool, user_id: &str) -> sqlx::Result<Option<OpaqueRecord>> {
    sqlx::query_as!(
        OpaqueRecord,
        r#"SELECT oprf_record, envelope, envelope_mac
           FROM opaque_records WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_opaque_login_record(
    pool: &PgPool,
    user_id: &str,
) -> sqlx::Result<Option<OpaqueLoginRecord>> {
    let row = sqlx::query(
        "SELECT oprf_record, envelope, envelope_mac \
         FROM opaque_records WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| OpaqueLoginRecord {
        oprf_record: r.get("oprf_record"),
        envelope: r.get("envelope"),
        envelope_mac: r.get("envelope_mac"),
    }))
}

pub async fn opaque_record_exists(pool: &PgPool, user_id: &str) -> sqlx::Result<bool> {
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM opaque_records WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(exists.is_some())
}

/// Insert or replace the user's OPAQUE record (recovery setup). The row may not
/// exist yet (registration no longer pre-creates a placeholder).
pub async fn upsert_opaque_record(
    pool: &PgPool,
    user_id: &str,
    oprf_record: &[u8],
    envelope: &[u8],
    envelope_mac: &[u8],
    now: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"INSERT INTO opaque_records
           (user_id, oprf_record, envelope, envelope_mac, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)
           ON CONFLICT (user_id) DO UPDATE SET
               oprf_record  = EXCLUDED.oprf_record,
               envelope     = EXCLUDED.envelope,
               envelope_mac = EXCLUDED.envelope_mac,
               updated_at   = EXCLUDED.updated_at"#,
        user_id,
        oprf_record,
        envelope,
        envelope_mac,
        now,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_opaque_record(
    pool: &PgPool,
    user_id: &str,
    oprf_record: &[u8],
    envelope: &[u8],
    envelope_mac: &[u8],
    updated_at: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE opaque_records
           SET oprf_record = $2, envelope = $3, envelope_mac = $4, updated_at = $5
           WHERE user_id = $1"#,
        user_id,
        oprf_record,
        envelope,
        envelope_mac,
        updated_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_opaque_record(pool: &PgPool, user_id: &str) -> sqlx::Result<u64> {
    let result = sqlx::query("DELETE FROM opaque_records WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
