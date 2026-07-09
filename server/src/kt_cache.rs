// Cached Key Transparency Merkle tree (PVX-23). The KT log is append-only, so a
// snapshot is valid until an entry is appended. Rebuilding the whole tree on
// every key fetch (and every periodic re-verify) made each fetch an O(N) CPU +
// full-table-scan hotspot; here the read path is a COUNT plus an Arc clone, and
// the O(N) rebuild runs only when the log actually grew.
//
// ponytail: count-gated full rebuild, not an incremental Merkle append. Simplest
// thing that is always fresh; make it incremental only if append rate makes the
// occasional full rebuild a bottleneck.

use std::sync::{Arc, Mutex};

use sqlx::PgPool;

use crate::crypto::kt_log as ktree;
use crate::db::queries::kt_log as ktdb;

pub struct KtSnapshot {
    /// Number of entries this snapshot was built from = its cache key.
    pub len: i64,
    pub entries: Vec<ktdb::KtEntry>,
    pub leaves: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

#[derive(Clone, Default)]
pub struct KtCache {
    inner: Arc<Mutex<Option<Arc<KtSnapshot>>>>,
}

impl KtCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot consistent with the current log length. Rebuilds only when an
    /// entry has been appended since the last build.
    pub async fn snapshot(&self, pool: &PgPool) -> sqlx::Result<Arc<KtSnapshot>> {
        let len = ktdb::count_entries(pool).await?;
        if let Some(snap) = self.current() {
            if snap.len == len {
                return Ok(snap);
            }
        }
        // Rebuild WITHOUT holding the lock across the await. A concurrent append
        // between the count and the list just means the next call rebuilds again
        // (self-healing) - the snapshot's own len is what we cache against.
        let entries = ktdb::list_all_entries(pool).await?;
        let leaves = entries_to_leaves(&entries);
        let root = ktree::compute_root(&leaves);
        let snap = Arc::new(KtSnapshot {
            len: entries.len() as i64,
            entries,
            leaves,
            root,
        });
        *self.inner.lock().unwrap() = Some(snap.clone());
        Ok(snap)
    }

    fn current(&self) -> Option<Arc<KtSnapshot>> {
        self.inner.lock().unwrap().clone()
    }
}

/// Recompute the Merkle leaves for the entries, in append order. Invalid hex in
/// the stored bundle_hash is impossible (we wrote it) but treated as an all-zero
/// leaf rather than panicking.
fn entries_to_leaves(entries: &[ktdb::KtEntry]) -> Vec<[u8; 32]> {
    entries
        .iter()
        .map(|e| {
            let bh = hex::decode(&e.bundle_hash).unwrap_or_default();
            ktree::leaf_hash(&e.user_id, &bh, e.timestamp as i64)
        })
        .collect()
}
