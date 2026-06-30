// Authenticated-user extractor. Reads the session token from the X-Privex-Auth
// HEADER only - never from a URL/query string (those can land in proxy logs).
// Any failure is a generic 401.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::token;
use crate::error::ApiError;
use crate::now_unix;
use crate::rds;
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
        let (user_id, issued_at) =
            token::verify_with_iat(&state.config.session_hmac_key, header, now_unix())
                .ok_or_else(ApiError::unauthorized)?;

        // "Log out everywhere": reject tokens issued before the user's revocation
        // cutoff. Fail-open on a Redis error - tokens still expire in 24h, and a
        // cache outage shouldn't lock everyone out (availability over a 24h-bounded
        // revocation window).
        if let Ok(Some(cutoff)) =
            rds::get_revoke_cutoff(&state.redis, &state.config.session_hmac_key, &user_id).await
        {
            if issued_at < cutoff {
                return Err(ApiError::unauthorized());
            }
        }
        Ok(AuthUser(user_id))
    }
}
