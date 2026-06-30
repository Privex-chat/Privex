// Database layer. Connection string comes from DATABASE_URL only - never
// hardcoded. Pool: min 2, max 20 (docs Session 7).
#![allow(dead_code)] // query fns are wired into routes in later sessions

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub mod queries;

/// Build the Postgres pool from an explicit URL (min 2, max 20).
pub async fn init_pool_with(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await?;
    Ok(pool)
}

/// Build the Postgres pool from `DATABASE_URL`.
pub async fn init_pool() -> anyhow::Result<PgPool> {
    let url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    init_pool_with(&url).await
}

/// Apply the embedded migrations (server/migrations).
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
