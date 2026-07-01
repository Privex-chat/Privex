// Device-link rendezvous relay (history sync Option B). A blind forwarder: two
// devices of the SAME account connect to GET /v1/devlink/:rendezvous_id and the
// server pipes frames between them verbatim. It NEVER reads or stores content -
// every frame after the public-key hello is end-to-end encrypted under a channel
// key the two devices derive (X25519); the relay sees only ciphertext, like a file
// transfer. Keyed by the rendezvous_id (a shared secret from the QR), NOT by
// user_id, since both peers are the same user and the per-user online map only
// holds one connection.
//
// No connection/content logging of any kind.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::error::ApiError;
use crate::rds;
use crate::state::AppState;

// A transfer (including the wait for the second device, ~QR 5-min validity) is
// capped; a single relayed frame is bounded so a peer can't exhaust memory.
const MAX_SESSION_SECS: u64 = 600;
const PING_SECS: u64 = 25;
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Default)]
struct Room {
    peers: [Option<UnboundedSender<String>>; 2],
}

#[derive(Default)]
pub struct DevlinkRooms {
    rooms: DashMap<String, Room>,
}

impl DevlinkRooms {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a slot in the rendezvous room. Returns the slot index, or None if the
    /// room already holds two peers (a third connection is rejected).
    fn join(&self, rid: &str, tx: UnboundedSender<String>) -> Option<usize> {
        let mut room = self.rooms.entry(rid.to_string()).or_default();
        if room.peers[0].is_none() {
            room.peers[0] = Some(tx);
            Some(0)
        } else if room.peers[1].is_none() {
            room.peers[1] = Some(tx);
            Some(1)
        } else {
            None
        }
    }

    /// Forward a frame to the OTHER peer in the room (best-effort).
    fn forward(&self, rid: &str, from: usize, msg: String) {
        if let Some(room) = self.rooms.get(rid) {
            if let Some(tx) = room.peers[1 - from].as_ref() {
                let _ = tx.send(msg);
            }
        }
    }

    fn leave(&self, rid: &str, slot: usize) {
        if let Some(mut room) = self.rooms.get_mut(rid) {
            room.peers[slot] = None;
            if room.peers[0].is_none() && room.peers[1].is_none() {
                drop(room);
                self.rooms.remove(rid);
            }
        }
    }
}

/// rendezvous_id = 16 random bytes → 32 lowercase hex chars.
fn valid_rid(s: &str) -> bool {
    s.len() == 32
        && s.as_bytes()
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub async fn devlink_route(
    ws: WebSocketUpgrade,
    State(st): State<AppState>,
    Path(rid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !valid_rid(&rid) {
        return Err(ApiError::bad_request());
    }
    // Origin validation: reject WebSocket upgrades from disallowed origins.
    crate::ws::handler::check_ws_origin(&st, &headers)?;

    // Same browser-safe ticket auth as /v1/ws. Any authenticated user may connect;
    // the rendezvous_id (a QR secret) is what pairs the two devices.
    let proto = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let ticket = proto
        .split(',')
        .map(|s| s.trim())
        .find(|s| *s != "privex" && !s.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    rds::take_ws_ticket(&st.redis, &st.config.session_hmac_key, ticket)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)?;

    let st2 = st.clone();
    Ok(ws
        .protocols(["privex"])
        .on_upgrade(move |socket| handle(socket, st2, rid)))
}

fn peer_event(event: &str) -> String {
    format!("{{\"t\":\"{event}\"}}")
}

async fn handle(socket: WebSocket, st: AppState, rid: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = unbounded_channel::<String>();
    let slot = match st.devlink.join(&rid, tx) {
        Some(s) => s,
        None => {
            let _ = sink.send(Message::Close(None)).await; // room full
            return;
        }
    };

    // Tell whoever is already waiting that a peer just joined.
    st.devlink.forward(&rid, slot, peer_event("peer_joined"));

    // Writer: relay outbound frames + keepalive ping; the whole session is capped.
    let mut writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(Duration::from_secs(PING_SECS));
        ping.tick().await;
        let deadline = tokio::time::sleep(Duration::from_secs(MAX_SESSION_SECS));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                out = rx.recv() => match out {
                    Some(t) => {
                        if sink.send(Message::Text(t)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = &mut writer => break,
            inbound = stream.next() => {
                let msg = match inbound {
                    Some(Ok(m)) => m,
                    _ => break,
                };
                match msg {
                    Message::Text(t) => {
                        if t.len() > MAX_FRAME_BYTES {
                            break; // oversized frame → drop the session
                        }
                        st.devlink.forward(&rid, slot, t);
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    writer.abort();
    st.devlink.forward(&rid, slot, peer_event("peer_left"));
    st.devlink.leave(&rid, slot);
}
