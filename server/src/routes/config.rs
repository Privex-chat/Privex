use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

pub async fn client_settings(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "file_uploads_enabled": st.config.file_uploads_enabled,
    }))
}
