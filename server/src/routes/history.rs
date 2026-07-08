// Encrypted chat-history backup endpoints (history sync Option A). OPT-IN feature.
// All routes are AuthUser-gated and scoped to the caller: a user can only upload,
// page, count, or delete THEIR OWN blobs. The server stores opaque ciphertext it
// can never read (encrypted under the client's history_key). The only metadata it
// can observe is per-user blob volume - the documented tradeoff of enabling backup.

use axum::extract::{Query, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::extract::AuthUser;
use crate::db::queries::history;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::state::AppState;
use crate::validate;

#[derive(Deserialize)]
pub struct BlobIn {
    blob_id: String,
    ciphertext: String, // base64
}

#[derive(Deserialize)]
pub struct UploadReq {
    blobs: Vec<BlobIn>,
}

#[derive(Serialize)]
pub struct UploadResp {
    stored: usize,
}

pub async fn upload(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Json(body): Json<UploadReq>,
) -> Result<Json<UploadResp>, ApiError> {
    // Backfill is bursty (a fresh enable uploads the whole local history in batches).
    let allowed = rds::check_rate_limit(
        &st.redis,
        &st.config.session_hmac_key,
        "histup",
        &user,
        600,
        60,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    if !allowed {
        return Err(ApiError::rate_limited());
    }

    if body.blobs.is_empty() || body.blobs.len() > validate::MAX_HISTORY_BATCH {
        return Err(ApiError::bad_request());
    }

    let now = now_unix() as i32;
    let mut stored = 0;
    for b in &body.blobs {
        // blob_id must be non-empty, not too long, and contain only safe chars.
        let safe_id = validate::sanitize_string(&b.blob_id, validate::MAX_HISTORY_BLOB_ID_CHARS)?;
        let ct = validate::validate_b64(&b.ciphertext, validate::MAX_HISTORY_BLOB_BYTES)?;
        history::upsert(&st.db, &user, &safe_id, &ct, now)
            .await
            .map_err(|_| ApiError::internal())?;
        stored += 1;
    }
    Ok(Json(UploadResp { stored }))
}

#[derive(Deserialize)]
pub struct ListParams {
    after: Option<String>, // "<created_at>:<blob_id>" cursor; absent = from the start
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct BlobOut {
    blob_id: String,
    ciphertext: String, // base64
    created_at: i32,
}

#[derive(Serialize)]
pub struct ListResp {
    blobs: Vec<BlobOut>,
    next: Option<String>,
}

pub async fn list(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResp>, ApiError> {
    crate::routes::rate_limit(&st, "histlist", &user, 120, 60).await?;
    let limit = validate::validate_page_limit(params.limit, 200, 500);
    let (after_at, after_id) = match &params.after {
        Some(c) => validate::validate_history_cursor(c)?,
        None => (0, String::new()),
    };

    let rows = history::list(&st.db, &user, after_at, &after_id, limit)
        .await
        .map_err(|_| ApiError::internal())?;

    // A full page implies there may be more → hand back a cursor from the last row.
    let next = if rows.len() as i64 == limit {
        rows.last()
            .map(|r| format!("{}:{}", r.created_at, r.blob_id))
    } else {
        None
    };
    let blobs = rows
        .into_iter()
        .map(|r| BlobOut {
            blob_id: r.blob_id,
            ciphertext: STANDARD.encode(&r.ciphertext),
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(ListResp { blobs, next }))
}

#[derive(Serialize)]
pub struct StatusResp {
    count: i64,
    bytes: i64,
}

pub async fn status(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<StatusResp>, ApiError> {
    crate::routes::rate_limit(&st, "histstat", &user, 120, 60).await?;
    let (count, bytes) = history::stats(&st.db, &user)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(StatusResp { count, bytes }))
}

#[derive(Serialize)]
pub struct DeleteResp {
    deleted: u64,
}

pub async fn delete_all(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
) -> Result<Json<DeleteResp>, ApiError> {
    crate::routes::rate_limit(&st, "histdel", &user, 10, 600).await?;
    let deleted = history::delete_all(&st.db, &user)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(DeleteResp { deleted }))
}
