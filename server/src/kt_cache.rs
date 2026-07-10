// Cached Key Transparency Merkle tree (PVX-23). The KT log is append-only, so a
// snapshot is valid until an entry is appended. Rebuilding the whole tree on
// every key fetch (and every periodic re-verify) made each fetch an O(N) CPU +
// full-table-scan hotspot; here the read path is a single O(1) MAX(seq) lookup
// plus an Arc clone, and the O(N) rebuild runs only when the log actually grew.
//
// Rebuilds are single-flighted: after a cache miss, exactly one task rebuilds
// while the others await it, instead of a thundering herd all scanning the log
// right after a registration. The fast path (cache hit) never touches that gate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;

use crate::crypto::kt_log as ktree;
use crate::db::queries::kt_log as ktdb;

pub struct KtSnapshot {
    /// The log's latest `seq` when this snapshot was built = its cache key.
    pub generation: i64,
    pub entries: Vec<ktdb::KtEntry>,
    pub leaves: Vec<[u8; 32]>,
    pub root: [u8; 32],
    /// user_id -> index of that user's LATEST entry (O(1) proof lookup, PVX-23).
    pub index_by_user: HashMap<String, usize>,
}

#[derive(Clone, Default)]
pub struct KtCache {
    current: Arc<Mutex<Option<Arc<KtSnapshot>>>>,
    // Single-flight gate: serializes rebuilds only (not cache hits). A tokio
    // Mutex so it can be held across the DB await; the std Mutex above is never
    // held across an await.
    rebuild: Arc<tokio::sync::Mutex<()>>,
}

impl KtCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot consistent with the current log length. Rebuilds only when an
    /// entry has been appended since the last build, and only one task at a time.
    pub async fn snapshot(&self, pool: &PgPool) -> anyhow::Result<Arc<KtSnapshot>> {
        // Fast path: cache hit without taking the rebuild gate.
        let gen = ktdb::latest_seq(pool).await?;
        if let Some(snap) = self.get() {
            if snap.generation == gen {
                return Ok(snap);
            }
        }

        // Slow path: hold the single-flight gate so concurrent misses don't all
        // rebuild. Re-read the generation under the gate (another task may have
        // rebuilt while we waited) and re-check the cache before scanning.
        let _guard = self.rebuild.lock().await;
        let gen = ktdb::latest_seq(pool).await?;
        if let Some(snap) = self.get() {
            if snap.generation == gen {
                return Ok(snap);
            }
        }

        let entries = ktdb::list_all_entries(pool).await?;
        let leaves = entries_to_leaves(&entries)?;
        let root = ktree::compute_root(&leaves);
        let mut index_by_user = HashMap::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            // seq order: a later entry overwrites an earlier one -> latest index.
            index_by_user.insert(e.user_id.clone(), i);
        }
        let snap = Arc::new(KtSnapshot {
            generation: gen,
            entries,
            leaves,
            root,
            index_by_user,
        });
        *self.current.lock().unwrap() = Some(snap.clone());
        Ok(snap)
    }

    fn get(&self) -> Option<Arc<KtSnapshot>> {
        self.current.lock().unwrap().clone()
    }
}

/// Recompute the Merkle leaves for the entries, in append order. The stored
/// bundle_hash is always valid 64-hex (we wrote it), but a corrupt value must
/// FAIL LOUD - a zeroed leaf would silently change the signed root and break
/// every client's inclusion proof (a KT-MITM detection failure). So decode
/// fallibly and require exactly 32 bytes.
fn entries_to_leaves(entries: &[ktdb::KtEntry]) -> anyhow::Result<Vec<[u8; 32]>> {
    entries
        .iter()
        .map(|e| {
            let bh = hex::decode(&e.bundle_hash)
                .map_err(|_| anyhow::anyhow!("kt_log: non-hex bundle_hash for {}", e.user_id))?;
            if bh.len() != 32 {
                anyhow::bail!("kt_log: bundle_hash not 32 bytes for {}", e.user_id);
            }
            Ok(ktree::leaf_hash(&e.user_id, &bh, e.timestamp as i64))
        })
        .collect()
}
