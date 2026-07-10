// Liveness + readiness probes (PVX-02).
//
// /health/live  - process is up. Cheap constant 200. K8s livenessProbe target.
// /health/ready - dependencies reachable (Postgres, Redis, object store). Returns
//                 503 if any is down so K8s stops routing to / restarts the pod
//                 instead of sending traffic to a broken one.
// /health       - retained alias for /health/live (external monitors / proxies).

use std::time::{Duration, Instant};

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

/// Readiness cache TTL. /health/ready is public and unauthenticated but each
/// probe costs a Postgres query + Redis PING + an object-store GET (real money
/// on S3/R2 op pricing) - an unauthenticated hammer must not amplify into
/// dependency load. Probes run at most once per TTL per process; every request
/// in between is answered from memory (state.ready_cache). 2 s is far fresher
/// than any LB probe interval.
const READY_CACHE_TTL: Duration = Duration::from_secs(2);

/// Readiness: every hard dependency answers. 200 when all pass, 503 otherwise,
/// with a body naming which check failed (no user data - just dependency names).
pub async fn health_ready(State(st): State<AppState>) -> (StatusCode, Json<Value>) {
    // Hold the cache lock across the whole check→probe→update so concurrent
    // misses SINGLE-FLIGHT: exactly one probe runs per TTL, the rest await the
    // guard and read the just-written result. (Serializing readiness requests is
    // fine - they're rare, and single-flighting is the point of the cache.)
    let mut guard = st.ready_cache.lock().await;
    let (db_ok, redis_ok, store_ok) = match guard
        .as_ref()
        .filter(|(at, _)| at.elapsed() < READY_CACHE_TTL)
        .map(|(_, checks)| *checks)
    {
        Some(checks) => checks,
        None => {
            // Run the three probes concurrently so readiness waits only for the
            // slowest dependency, not their sum. A get of a missing key returns
            // Ok(None); only a transport/auth failure errs, so it's a cheap
            // store reachability probe.
            let checks = tokio::join!(
                async { sqlx::query("SELECT 1").execute(&st.db).await.is_ok() },
                redis_ping(&st.redis),
                async { st.store.get("__health_probe__").await.is_ok() },
            );
            *guard = Some((Instant::now(), checks));
            checks
        }
    };
    drop(guard);

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
