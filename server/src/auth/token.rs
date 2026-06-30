// Session tokens: base64url(payload_json) "." base64url(HMAC-SHA256(payload)).
// 24-hour TTL (docs 4.9 - avoids the timing signature of short-lived tokens).
// Carried in the X-Privex-Auth header only, never in a URL/query string.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const TTL_SECS: i64 = 24 * 3600;

#[derive(Serialize, Deserialize)]
struct TokenPayload {
    user_id: String,
    issued_at: i64,
    expires_at: i64,
    jti: String,
}

fn random_jti() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("rng");
    hex::encode(b)
}

pub fn mint(key: &[u8; 32], user_id: &str, now: i64) -> String {
    let payload = TokenPayload {
        user_id: user_id.to_string(),
        issued_at: now,
        expires_at: now + TTL_SECS,
        jti: random_jti(),
    };
    let pj = serde_json::to_vec(&payload).expect("serialize token payload");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(&pj);
    let tag = mac.finalize().into_bytes();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&pj),
        URL_SAFE_NO_PAD.encode(tag)
    )
}

/// Returns the user_id if the token is authentic and unexpired, else None.
pub fn verify(key: &[u8; 32], token: &str, now: i64) -> Option<String> {
    verify_with_iat(key, token, now).map(|(user_id, _)| user_id)
}

/// Like `verify`, but also returns the token's `issued_at` so a caller can apply
/// a revocation cutoff ("log out everywhere" invalidates tokens issued earlier).
pub fn verify_with_iat(key: &[u8; 32], token: &str, now: i64) -> Option<(String, i64)> {
    let (p_b64, t_b64) = token.split_once('.')?;
    let pj = URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let tag = URL_SAFE_NO_PAD.decode(t_b64).ok()?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).ok()?;
    mac.update(&pj);
    mac.verify_slice(&tag).ok()?;

    let payload: TokenPayload = serde_json::from_slice(&pj).ok()?;
    if now >= payload.expires_at {
        return None;
    }
    Some((payload.user_id, payload.issued_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_verify_roundtrip_and_failures() {
        let key = [7u8; 32];
        let now = 1_000_000;
        let token = mint(&key, "px_00000000000000000000000000000001", now);

        assert_eq!(
            verify(&key, &token, now).as_deref(),
            Some("px_00000000000000000000000000000001")
        );
        // expired
        assert!(verify(&key, &token, now + TTL_SECS).is_none());
        // wrong key
        assert!(verify(&[8u8; 32], &token, now).is_none());
        // tampered
        let mut bad = token.clone();
        bad.push('x');
        assert!(verify(&key, &bad, now).is_none());
    }
}
