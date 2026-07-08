// Privex server library. main.rs is a thin wrapper; integration tests build the
// router via `app()` against a real Postgres + Redis.
//
// Logging policy: ONLY startup/shutdown lifecycle events with static names. No
// request, connection, or per-handler logging. No user_id, IP, token, body, or
// key material is ever logged anywhere.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::http::HeaderValue;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod powcheck;
pub mod rds;
pub mod routes;
pub mod state;
pub mod store;
pub mod tasks;
pub mod validate;
pub mod ws;

// Generated Protobuf types (prost). Package `privex` → single file `privex.rs`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/privex.rs"));
}

use config::Config;
use state::AppState;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn init_redis(url: &str) -> anyhow::Result<deadpool_redis::Pool> {
    let cfg = deadpool_redis::Config::from_url(url);
    let pool = cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    Ok(pool)
}

/// Build application state with an explicit object store (used by tests with an
/// in-memory store).
pub async fn build_state_with_store(
    config: Config,
    store: Arc<dyn store::ObjectStore>,
) -> anyhow::Result<AppState> {
    let db = db::init_pool_with(&config.database_url).await?;
    db::run_migrations(&db).await?;
    // Rebuild missing kt_log entries if the previous UNLOGGED table was
    // truncated by an unclean shutdown (key_directory is LOGGED and survived).
    if let Err(e) = db::queries::kt_log::repair_kt_log(&db).await {
        tracing::warn!(event = "kt_log_repair_error", error = %e);
    }
    let redis = init_redis(&config.redis_url)?;
    Ok(AppState {
        db,
        redis,
        config: Arc::new(config),
        store,
        online: Arc::new(ws::state::Online::new()),
        devlink: Arc::new(ws::devlink::DevlinkRooms::new()),
    })
}

/// Build application state for production: DB pool (+ migrations), Redis pool,
/// and an S3-compatible object store from config (fails fast if unconfigured).
pub async fn build_state(config: Config) -> anyhow::Result<AppState> {
    let store = Arc::new(store::S3Store::from_config(&config));
    build_state_with_store(config, store).await
}

/// Delete expired queued messages and blobs (objects + index rows). PoW challenge
/// state lives in Redis with TTLs; the old table cleanup is retained only for
/// migration compatibility.
pub async fn cleanup_expired(state: &AppState) -> anyhow::Result<()> {
    let now = now_unix() as i32;
    db::queries::message_queue::cleanup_expired(&state.db, now).await?;
    db::queries::pow::cleanup_expired(&state.db, now).await?;

    // Blobs: remove the objects first, then the index rows.
    for blob in db::queries::blob_index::list_expired(&state.db, now).await? {
        let _ = state.store.delete(&blob.storage_path).await; // best-effort
    }
    db::queries::blob_index::cleanup_expired(&state.db, now).await?;
    Ok(())
}

/// Periodic expiry sweep (every 10 minutes).
fn spawn_cleanup(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            let _ = cleanup_expired(&state).await;
        }
    });
}

/// The Axum router. No logging/tracing layers are mounted - by design.
pub fn app(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(if origins.is_empty() {
            AllowOrigin::any()
        } else {
            AllowOrigin::list(origins)
        });

    Router::new()
        .route("/config/client", get(routes::config::client_settings))
        .route("/health", get(routes::health::health))
        .route(
            "/auth/pow_challenge",
            post(routes::auth::pow_challenge).layer(DefaultBodyLimit::max(1024)),
        )
        .route("/auth/challenge", post(routes::auth::challenge))
        .route("/auth/verify", post(routes::auth::verify))
        .route("/auth/ws_ticket", post(routes::auth::ws_ticket))
        .route("/auth/logout_all", post(routes::auth::logout_all))
        .route(
            "/keys/register",
            post(routes::register::register).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/keys/prekeys/replenish", post(routes::keys::replenish))
        .route("/keys/spk/rotate", post(routes::keys::spk_rotate))
        .route("/keys/kt/root", get(routes::keys::kt_root))
        // PoW-gated public fetches: POST carries the solved challenge (a GET can't
        // hold a body). Small body cap - just the PoW proof.
        .route(
            "/keys/kt/proof/:user_id",
            post(routes::keys::kt_proof).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/keys/:user_id",
            post(routes::keys::get_key_bundle).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/recovery/opaque/register/start",
            post(routes::recovery::opaque_register_start).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/recovery/opaque/register/finish",
            post(routes::recovery::opaque_register_finish).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/recovery/opaque/status",
            get(routes::recovery::opaque_status),
        )
        .route(
            "/recovery/opaque",
            axum::routing::delete(routes::recovery::opaque_delete),
        )
        .route(
            "/recovery/opaque/init",
            post(routes::recovery::opaque_login_init).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/recovery/opaque/complete",
            post(routes::recovery::opaque_login_complete).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/recovery/shares/store",
            post(routes::recovery::store_shares),
        )
        .route(
            "/messages/send",
            // ~256 KiB cap: one padded Sealed Sender message, not a file.
            post(routes::messages::send).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route("/messages/ack", post(routes::messages::ack))
        .route(
            "/history/blobs",
            // Batched encrypted history records (Option A). ~2 MiB per batch.
            post(routes::history::upload)
                .get(routes::history::list)
                .delete(routes::history::delete_all)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route("/history/status", get(routes::history::status))
        .route(
            "/blobs/:chunk_id",
            post(routes::blobs::upload)
                .get(routes::blobs::download)
                .delete(routes::blobs::delete)
                // ~5 MiB cap: a single 4 MiB encrypted chunk + overhead.
                .layer(DefaultBodyLimit::max(5 * 1024 * 1024)),
        )
        .route("/v1/ws", get(ws::handler::ws_route))
        .route("/v1/devlink/:rid", get(ws::devlink::devlink_route))
        .layer(cors)
        .with_state(state)
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("privex_server=info,warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Run the server: load config, build state, bind BIND_ADDR, serve with
/// graceful shutdown.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let config = Config::from_env()?;
    let bind_addr = config.bind_addr.clone();

    tracing::info!("server_starting");
    // The KT signing PUBLIC key (not secret). Operators pin this in the client
    // build / distribute it out-of-band so clients can verify KT roots without
    // trusting the signing server. Logging a public key is not a PII/secret leak.
    tracing::info!(kt_signing_pub = %config.kt_signing_pub_hex(), "kt_signer");
    // Delivery-timestamp signer (docs 9.6) - also a PUBLIC key, pinned client-side.
    tracing::info!(time_signing_pub = %config.time_signing_pub_hex(), "time_signer");
    let state = build_state(config).await?;
    tracing::info!("migrations_applied");

    spawn_cleanup(state.clone());
    tokio::spawn(tasks::difficulty_manager::run(state.redis.clone()));

    let app = app(state);
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!("server_listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("server_shutdown");
    Ok(())
}

#[cfg(test)]
mod proto_tests {
    use super::proto::TextMessage;
    use prost::Message;

    // Shared wire vector - keep in sync with packages/protocol/test.
    const EXPECTED_HEX: &str = "0a0c68656c6c6f207072697665781080b4edb306";

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn textmessage_encode_matches_vector() {
        let m = TextMessage {
            body: "hello privex".to_string(),
            sent_at: 1_719_360_000,
            expires_after_seconds: 0,
        };
        assert_eq!(to_hex(&m.encode_to_vec()), EXPECTED_HEX);
    }
}
