// Liveness + readiness probes (PVX-02).
//
// /health/live  - process is up. Cheap constant 200. K8s livenessProbe target.
// /health/ready - dependencies reachable (Postgres, Redis, object store). Returns
//                 503 if any is down so K8s stops routing to / restarts the pod
//                 instead of sending traffic to a broken one.
// /health       - retained alias for /health/live (external monitors / proxies).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use deadpool_redis::redis;
use serde_json::{json, Value};

use crate::state::AppState;

/// Liveness: the process is running. No dependency checks, no metadata.
pub async fn health_live() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: every hard dependency answers. 200 when all pass, 503 otherwise,
/// with a body naming which check failed (no user data - just dependency names).
pub async fn health_ready(State(st): State<AppState>) -> (StatusCode, Json<Value>) {
    // Run the three probes concurrently so readiness waits only for the slowest
    // dependency, not their sum. A get of a missing key returns Ok(None); only a
    // transport/auth failure errs, so it's a cheap store reachability probe.
    let (db_ok, redis_ok, store_ok) = tokio::join!(
        async { sqlx::query("SELECT 1").execute(&st.db).await.is_ok() },
        redis_ping(&st.redis),
        async { st.store.get("__health_probe__").await.is_ok() },
    );

    let ready = db_ok && redis_ok && store_ok;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ready": ready,
            "checks": { "db": db_ok, "redis": redis_ok, "store": store_ok },
        })),
    )
}

async fn redis_ping(pool: &deadpool_redis::Pool) -> bool {
    match pool.get().await {
        Ok(mut conn) => redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .is_ok(),
        Err(_) => false,
    }
}
