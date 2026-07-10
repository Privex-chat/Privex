use std::sync::Arc;
use std::time::Instant;

use deadpool_redis::Pool as RedisPool;
use sqlx::PgPool;
use tokio::sync::{Mutex, Semaphore};

use crate::config::Config;
use crate::kt_cache::KtCache;
use crate::store::ObjectStore;
use crate::ws::devlink::DevlinkRooms;
use crate::ws::state::Online;

/// Short-TTL cache of the last /health/ready probe result (see routes/health.rs).
/// A tokio Mutex so the readiness handler can hold it across the async probe and
/// single-flight concurrent misses (only one probe per TTL, not a herd).
pub type ReadyCache = Arc<Mutex<Option<(Instant, (bool, bool, bool))>>>;

/// Caps concurrent Argon2id hybrid-PoW verifications (see routes::verify_pow).
/// Each eval is a ~32 MiB allocation; without a bound an attacker who
/// precomputes SHA-prefilter-passing nonces could burst enough concurrent
/// verifies to exhaust memory. Legit verify load is far below this cap.
pub const POW_VERIFY_MAX_CONCURRENCY: usize = 4;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: RedisPool,
    pub config: Arc<Config>,
    pub store: Arc<dyn ObjectStore>,
    pub online: Arc<Online>,
    pub devlink: Arc<DevlinkRooms>,
    /// Cached KT Merkle tree - rebuilt only when the log grows (PVX-23).
    pub kt_cache: KtCache,
    /// Last readiness probe result - bounds unauthenticated /health/ready
    /// hammering to one dependency probe per TTL.
    pub ready_cache: ReadyCache,
    /// Bounds concurrent memory-hard PoW verifications (OOM DoS guard).
    pub pow_verify_sem: Arc<Semaphore>,
}
