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
            token::verify_with_iat(&state.config.token_mac_key, header, now_unix())
                .ok_or_else(ApiError::unauthorized)?;

        // "Log out everywhere": reject tokens issued before the user's revocation
        // cutoff. Fail CLOSED on a Redis error - revocation is the only kill switch
        // for a stolen token, so "cannot confirm validity" must reject. Availability
        // cost is nil in practice: nearly every endpoint already 500s when Redis is
        // down (rate limits, challenges, tickets all live there). 500 (not 401) so
        // clients treat it as transient, not as a bad token.
        let cutoff =
            rds::get_revoke_cutoff(&state.redis, &state.config.redis_ns_key, &user_id)
                .await
                .map_err(|_| ApiError::internal())?;
        if let Some(cutoff) = cutoff {
            if issued_at < cutoff {
                return Err(ApiError::unauthorized());
            }
        }
        Ok(AuthUser(user_id))
    }
}
