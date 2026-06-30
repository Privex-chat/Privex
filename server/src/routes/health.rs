use axum::Json;
use serde_json::{json, Value};

/// Liveness probe. Returns only `{ "status": "ok" }` - no version, no metadata.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
