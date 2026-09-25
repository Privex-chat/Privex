// WebSocket endpoint GET /v1/ws.
//
// Browsers cannot set custom headers on a WebSocket, so auth is a single-use
// ticket carried in `Sec-WebSocket-Protocol`: the client opens
// `new WebSocket(url, ["privex", <ticket>])`. The server consumes the ticket
// (Redis GETDEL) BEFORE accepting the socket. Tokens are never read from query
// params. No connection/request logging of any kind.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use sqlx::types::Uuid;

use crate::db::queries::message_queue;
use crate::error::ApiError;
use crate::rds;
use crate::state::AppState;
use crate::ws::messages::{message_json, ping_json, ClientMsg};

/// Queued messages fetched + sent per page when a client connects.
const BACKLOG_PAGE: i64 = 200;

pub async fn ws_route(
    ws: WebSocketUpgrade,
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Origin validation: reject WebSocket upgrades from disallowed origins.
    check_ws_origin(&st, &headers)?;

    // Sec-WebSocket-Protocol: "privex, <ticket>"
    let proto = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let ticket = proto
        .split(',')
        .map(|s| s.trim())
        .find(|s| *s != "privex" && !s.is_empty())
        .ok_or_else(ApiError::unauthorized)?;

    let user_id = rds::take_ws_ticket(&st.redis, &st.config.redis_ns_key, ticket)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)?;

    // Echo the "privex" subprotocol so the handshake completes for browsers.
    let st2 = st.clone();
    Ok(ws
        .protocols(["privex"])
        .on_upgrade(move |socket| handle_socket(socket, st2, user_id)))
}

/// Validate the `Origin` header against the configured allowlist. An empty
/// allowlist accepts all origins - reachable only via Config::for_test, since
/// Config::from_env rejects an empty WS_ALLOWED_ORIGINS at startup (PVX-09).
/// Checked BEFORE consuming the single-use ticket so a rejected request doesn't
/// burn it.
pub(crate) fn check_ws_origin(st: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if st.config.ws_allowed_origins.is_empty() {
        return Ok(());
    }
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if st.config.ws_allowed_origins.iter().any(|o| o == origin) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

async fn handle_socket(socket: WebSocket, st: AppState, user_id: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    st.online.insert(&user_id, tx.clone());
    // Anything queued from here on is pushed live through `tx`; the backlog below
    // covers what was queued before. (Same-second arrivals may come twice, as
    // before; the client de-duplicates by message id.)
    let backlog_until = crate::now_unix() as i32;

    let ping_secs = st.config.ws_ping_secs.max(1);
    let alive = Arc::new(AtomicBool::new(true));

    // Writer: streams the backlog, then forwards outbound messages and runs the
    // heartbeat.
    let writer_alive = alive.clone();
    let backlog_st = st.clone();
    let backlog_user = user_id.clone();
    let mut writer = tokio::spawn(async move {
        // Offline backlog, one page at a time. sink.send awaits the socket, so a
        // big mailbox streams with backpressure instead of being loaded into
        // memory whole. Messages stay in the DB until the client ACKs.
        let mut after = (i32::MIN, Uuid::nil());
        loop {
            let Ok(page) = message_queue::dequeue_page(
                &backlog_st.db,
                &backlog_user,
                backlog_until,
                after,
                BACKLOG_PAGE,
            )
            .await
            else {
                break;
            };
            for m in &page {
                let frame = message_json(
                    &backlog_st.config.time_signing_key,
                    &m.message_id.to_string(),
                    base64_content(&m.content),
                    m.queued_at as i64,
                );
                if sink.send(Message::Text(frame)).await.is_err() {
                    return;
                }
            }
            match page.last() {
                Some(last) if page.len() as i64 == BACKLOG_PAGE => {
                    after = (last.queued_at, last.message_id)
                }
                _ => break,
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(ping_secs));
        interval.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                outbound = rx.recv() => match outbound {
                    Some(text) => {
                        if sink.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = interval.tick() => {
                    // No inbound traffic since the last ping → dead connection.
                    if !writer_alive.swap(false, Ordering::SeqCst) {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    if sink.send(Message::Text(ping_json())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Reader: handle client frames until the socket or writer ends.
    loop {
        tokio::select! {
            _ = &mut writer => break,
            inbound = stream.next() => {
                let msg = match inbound {
                    Some(Ok(m)) => m,
                    _ => break,
                };
                match msg {
                    Message::Text(text) => {
                        alive.store(true, Ordering::SeqCst);
                        if let Ok(cm) = serde_json::from_str::<ClientMsg>(&text) {
                            match cm {
                                ClientMsg::Ack { message_ids } => {
                                    let ids: Vec<Uuid> = message_ids
                                        .iter()
                                        .filter_map(|s| Uuid::parse_str(s).ok())
                                        .collect();
                                    let _ =
                                        message_queue::ack_messages(&st.db, &user_id, &ids).await;
                                }
                                ClientMsg::Pong => {}
                            }
                        }
                    }
                    Message::Pong(_) | Message::Ping(_) => {
                        alive.store(true, Ordering::SeqCst);
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    writer.abort();
    st.online.remove(&user_id);
}

fn base64_content(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}
