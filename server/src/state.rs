use std::sync::{Arc, Mutex};
use std::time::Instant;

use deadpool_redis::Pool as RedisPool;
use sqlx::PgPool;

use crate::config::Config;
use crate::kt_cache::KtCache;
use crate::store::ObjectStore;
use crate::ws::devlink::DevlinkRooms;
use crate::ws::state::Online;

/// Short-TTL cache of the last /health/ready probe result (see routes/health.rs).
pub type ReadyCache = Arc<Mutex<Option<(Instant, (bool, bool, bool))>>>;

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
}
