// Blob store endpoints (docs 4.7/11). The server is a dumb content-addressed
// store: the chunk_id MUST equal SHA-256(uploaded bytes). It keeps no filename,
// MIME type, owner, uploader, or any plaintext metadata - only the index row.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::extract::AuthUser;
use crate::db::queries::blob_index;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
use crate::routes::valid_chunk_id;
use crate::state::AppState;
use crate::validate;

const SEVEN_DAYS: i64 = 7 * 24 * 3600;
const ONE_DAY: i64 = 24 * 3600;

pub async fn upload(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Path(chunk_id): Path<String>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.config.file_uploads_enabled {
        return Err(ApiError::forbidden());
    }
    // Reject oversized uploads before any processing.
    if body.len() > validate::MAX_BLOB_UPLOAD_BYTES {
        return Err(ApiError::bad_request());
    }
    let allowed = rds::check_rate_limit(
        &st.redis,
        &st.config.redis_ns_key,
        "blobput",
        &user,
        60,
        60,
    )
    .await
    .map_err(|_| ApiError::internal())?;
    if !allowed {
        return Err(ApiError::rate_limited());
    }
    if body.is_empty() || !valid_chunk_id(&chunk_id) {
        return Err(ApiError::bad_request());
    }

    // Content-addressing: chunk_id must be the SHA-256 of the bytes.
    let digest = hex::encode(Sha256::digest(&body));
    if digest != chunk_id {
        return Err(ApiError::bad_request());
    }

    st.store
        .put(&chunk_id, body.to_vec())
        .await
        .map_err(|_| ApiError::internal())?;

    let now = now_unix();
    let expires_at = now + SEVEN_DAYS;
    blob_index::store_blob(
        &st.db,
        &chunk_id,
        &chunk_id,
        body.len() as i32,
        expires_at as i32,
    )
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({ "stored": true, "expires_at": expires_at })))
}

pub async fn download(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Path(chunk_id): Path<String>,
) -> Result<Response, ApiError> {
    if !st.config.file_uploads_enabled {
        return Err(ApiError::forbidden());
    }
    // Each hit streams up to 4 MiB from the object store → bound per user
    // (120 chunks/min ≈ 480 MB/min, generous for legit file receives).
    crate::routes::rate_limit(&st, "blobget", &user, 120, 60).await?;
    if !valid_chunk_id(&chunk_id) {
        return Err(ApiError::bad_request());
    }
    let path = blob_index::get_blob_path(&st.db, &chunk_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::not_found)?;

    let bytes = st
        .store
        .get(&path)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::not_found)?;

    // First download schedules deletion 24h later (or keep the 7-day TTL if
    // that is sooner).
    let now = now_unix();
    blob_index::mark_downloaded_and_expire(&st.db, &chunk_id, (now + ONE_DAY) as i32)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

/// Delete is intentionally ownership-blind: the index stores no owner/uploader
/// (that's the privacy design). Consequently, knowledge of a chunk_id acts as a
/// capability to delete that chunk. chunk_ids are SHA-256 of encrypted content
/// and are shared only inside E2E-encrypted file manifests, so this is
/// acceptable; there is deliberately no owner to check against.
pub async fn delete(
    AuthUser(user): AuthUser,
    State(st): State<AppState>,
    Path(chunk_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !st.config.file_uploads_enabled {
        return Err(ApiError::forbidden());
    }
    crate::routes::rate_limit(&st, "blobdel", &user, 60, 60).await?;
    if !valid_chunk_id(&chunk_id) {
        return Err(ApiError::bad_request());
    }
    st.store
        .delete(&chunk_id)
        .await
        .map_err(|_| ApiError::internal())?;
    blob_index::delete_blob(&st.db, &chunk_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({ "deleted": true })))
}
