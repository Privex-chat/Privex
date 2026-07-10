use std::sync::Arc;

use deadpool_redis::Pool as RedisPool;
use sqlx::PgPool;

use crate::config::Config;
use crate::kt_cache::KtCache;
use crate::store::ObjectStore;
use crate::ws::devlink::DevlinkRooms;
use crate::ws::state::Online;

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
}
