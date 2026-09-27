// Authenticated-user extractor. Reads the session token from the X-Privex-Auth
// HEADER only - never from a URL/query string (those can land in proxy logs).
// Any failure is a generic 401. Tokens are stateless (HMAC + 24 h expiry): the
// server keeps no session list and no revocation record.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::token;
use crate::error::ApiError;
use crate::now_unix;
use crate::state::AppState;

pub struct AuthUser(pub String);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let header = parts
            .headers
            .get("x-privex-auth")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::unauthorized)?;
        let user_id = token::verify(&state.config.token_mac_key, header, now_unix())
            .ok_or_else(ApiError::unauthorized)?;
        Ok(AuthUser(user_id))
    }
}
