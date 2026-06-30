// In-memory online map: user_id -> outbound channel. NEVER persisted. Cleared
// on disconnect. Used to push messages to currently-connected recipients.
//
// ponytail: one connection per user (a reconnect replaces the previous sender).
// Multi-device fan-out lands when device linking does.

use dashmap::DashMap;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Default)]
pub struct Online {
    map: DashMap<String, UnboundedSender<String>>,
}

impl Online {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, user_id: &str, tx: UnboundedSender<String>) {
        self.map.insert(user_id.to_string(), tx);
    }

    pub fn remove(&self, user_id: &str) {
        self.map.remove(user_id);
    }

    /// Best-effort push to a connected user. Returns false if offline or the
    /// channel is closed.
    pub fn send(&self, user_id: &str, msg: String) -> bool {
        match self.map.get(user_id) {
            Some(tx) => tx.send(msg).is_ok(),
            None => false,
        }
    }
}
