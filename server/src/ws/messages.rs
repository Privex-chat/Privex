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

pub fn message_json(message_id: &str, content_b64: String, queued_at: i64) -> String {
    serde_json::to_string(&ServerMsg::Message {
        message_id: message_id.to_string(),
        content: content_b64,
        queued_at,
    })
    .unwrap_or_default()
}

pub fn ping_json() -> String {
    serde_json::to_string(&ServerMsg::Ping).unwrap_or_default()
}
