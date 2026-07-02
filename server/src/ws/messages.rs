// WebSocket wire messages (docs 11). JSON, tagged by `type`. `content` is the
// base64 Sealed Sender blob - the server never sees plaintext.

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Message {
        message_id: String,
        content: String, // base64
        queued_at: i64,
        // Signed delivery timestamp (docs 9.6): server_ts = time of THIS delivery
        // (client drift check); queued_at above = arrival time (ordering anchor).
        // server_ts_sig = hex Ed25519 over be64(server_ts)||be64(queued_at)||message_id
        // with the dedicated TIME_SIGNING_KEY (public half pinned client-side).
        server_ts: i64,
        server_ts_sig: String, // hex
    },
    PrekeyLow {
        remaining: i64,
    },
    KeyChangeAlert {
        user_id: String,
    },
    Ping,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Ack { message_ids: Vec<String> },
    Pong,
}

/// Build a message-delivery frame with a freshly signed timestamp (docs 9.6).
pub fn message_json(
    time_signing_key: &[u8; 32],
    message_id: &str,
    content_b64: String,
    queued_at: i64,
) -> String {
    let server_ts = crate::now_unix();
    let sig =
        crate::crypto::time_signing::sign_delivery(time_signing_key, server_ts, queued_at, message_id);
    serde_json::to_string(&ServerMsg::Message {
        message_id: message_id.to_string(),
        content: content_b64,
        queued_at,
        server_ts,
        server_ts_sig: hex::encode(sig),
    })
    .unwrap_or_default()
}

pub fn ping_json() -> String {
    serde_json::to_string(&ServerMsg::Ping).unwrap_or_default()
}
