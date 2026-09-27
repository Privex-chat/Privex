// In-memory online map: user_id -> the account's open connections, newest last.
// NEVER persisted or logged; a connection is listed only while its socket is open.
//
// Live pushes go to the NEWEST connection only - the single-mailbox model
// (KNOWN_LIMITATIONS): an incoming message lands on whichever device acks it
// first, so fanning it out to every connection would let one that can't decrypt
// it ack (delete) it before the one that can. When a connection closes it removes
// only ITSELF, and the newest one still open takes over live delivery - an older
// socket closing must never cut off a newer one, and the newest closing must hand
// delivery back to one that's still open.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Default)]
pub struct Online {
    map: DashMap<String, Vec<UnboundedSender<String>>>,
}

impl Online {
    pub fn new() -> Self {
        Self::default()
    }

    /// A connection opened: it becomes the account's live-delivery target.
    pub fn insert(&self, user_id: &str, tx: UnboundedSender<String>) {
        self.map.entry(user_id.to_string()).or_default().push(tx);
    }

    /// A connection closed: drop just that one (the entry goes once none are left).
    pub fn remove(&self, user_id: &str, tx: &UnboundedSender<String>) {
        if let Entry::Occupied(mut e) = self.map.entry(user_id.to_string()) {
            e.get_mut().retain(|c| !c.same_channel(tx));
            if e.get().is_empty() {
                e.remove();
            }
        }
    }

    /// Best-effort push to the account's newest open connection (falling back to
    /// an older one if the newest is already closing). Returns false if none took
    /// it - the message is persisted first, so it still arrives on the next connect.
    pub fn send(&self, user_id: &str, msg: String) -> bool {
        let Some(conns) = self.map.get(user_id) else {
            return false;
        };
        let mut msg = msg;
        for tx in conns.iter().rev() {
            match tx.send(msg) {
                Ok(()) => return true,
                Err(SendError(back)) => msg = back,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Online;
    use tokio::sync::mpsc::unbounded_channel;

    const U: &str = "px_00000000000000000000000000000001";

    #[test]
    fn pushes_go_to_the_newest_connection() {
        let online = Online::new();
        let (a, mut ra) = unbounded_channel();
        let (b, mut rb) = unbounded_channel();
        online.insert(U, a);
        online.insert(U, b);
        assert!(online.send(U, "m".into()));
        assert_eq!(rb.try_recv().unwrap(), "m");
        assert!(ra.try_recv().is_err(), "only the newest is live");
    }

    #[test]
    fn an_older_connection_closing_keeps_the_newer_live() {
        let online = Online::new();
        let (a, _ra) = unbounded_channel();
        let (b, mut rb) = unbounded_channel();
        online.insert(U, a.clone());
        online.insert(U, b);
        online.remove(U, &a);
        assert!(online.send(U, "m".into()));
        assert_eq!(rb.try_recv().unwrap(), "m");
    }

    #[test]
    fn the_newest_closing_hands_delivery_back() {
        let online = Online::new();
        let (a, mut ra) = unbounded_channel();
        let (b, _rb) = unbounded_channel();
        online.insert(U, a);
        online.insert(U, b.clone());
        online.remove(U, &b);
        assert!(online.send(U, "m".into()));
        assert_eq!(ra.try_recv().unwrap(), "m");
    }

    #[test]
    fn a_dead_newest_falls_through_and_the_last_close_clears_the_entry() {
        let online = Online::new();
        let (a, mut ra) = unbounded_channel();
        let (b, rb) = unbounded_channel();
        online.insert(U, a.clone());
        online.insert(U, b.clone());
        drop(rb); // newest socket already gone, not yet removed
        assert!(online.send(U, "m".into()));
        assert_eq!(ra.try_recv().unwrap(), "m");

        online.remove(U, &b);
        online.remove(U, &a);
        assert!(!online.send(U, "m".into()), "offline once every connection closed");
        assert!(online.map.is_empty(), "no entry left behind");
    }
}
