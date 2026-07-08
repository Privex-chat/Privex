// API errors. Responses are intentionally GENERIC - no user_id, no reason
// detail, no internal error text ever reaches the client or the logs.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    msg: &'static str,
}

impl ApiError {
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            msg: "unauthorized",
        }
    }
    pub fn bad_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            msg: "bad request",
        }
    }
    pub fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            msg: "rate limited",
        }
    }
    pub fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            msg: "conflict",
        }
    }
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            msg: "not found",
        }
    }
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            msg: "forbidden",
        }
    }
    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            msg: "internal error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.status, Json(json!({ "error": self.msg }))).into_response();
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        resp
    }
}
