// Stateless login challenges (docs 4.9). A challenge is a MAC the server can
// re-check, not a row it stores:
//
//   challenge (32 bytes) = nonce(8) || expires_at u32 BE (4) || tag(20)
//   tag = HMAC-SHA256(key, DOMAIN || user_id || nonce || expires_at)[..20]
//
// Storing one challenge per account (overwritten by every new request) plus a
// per-account attempt limit let anyone who knew a px_id keep that user logged
// out: request challenges to overwrite theirs, or burn their attempts with
// garbage. Now any number of challenges can be outstanding for an account, and
// a challenge is only marked used once a VALID signature over it has been
// presented (routes/auth.rs::verify) - which only the key holder can produce.
// The client-visible format (32 bytes, hex) is unchanged.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN: &[u8] = b"privex-auth-challenge-v1";
const NONCE_LEN: usize = 8;
const TAG_LEN: usize = 20;
pub const CHALLENGE_LEN: usize = NONCE_LEN + 4 + TAG_LEN; // 32
/// How long a challenge stays valid (seconds).
pub const TTL_SECS: i64 = 90;
/// Clock slack between servers when checking a challenge's expiry.
const SKEW_SECS: i64 = 30;

fn tag(key: &[u8; 32], user_id: &str, body: &[u8]) -> HmacSha256 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(DOMAIN);
    mac.update(user_id.as_bytes());
    mac.update(body);
    mac
}

/// A fresh challenge for `user_id`, valid for TTL_SECS from `now`.
pub fn mint(key: &[u8; 32], user_id: &str, now: i64) -> anyhow::Result<[u8; CHALLENGE_LEN]> {
    let mut out = [0u8; CHALLENGE_LEN];
    getrandom::getrandom(&mut out[..NONCE_LEN]).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let expires_at = u32::try_from(now + TTL_SECS)?;
    out[NONCE_LEN..NONCE_LEN + 4].copy_from_slice(&expires_at.to_be_bytes());
    let t = tag(key, user_id, &out[..NONCE_LEN + 4])
        .finalize()
        .into_bytes();
    out[NONCE_LEN + 4..].copy_from_slice(&t[..TAG_LEN]);
    Ok(out)
}

/// True if `challenge` was minted by this server for `user_id` and hasn't
/// expired. The MAC is compared in constant time. Single use is the caller's job.
pub fn check(key: &[u8; 32], user_id: &str, challenge: &[u8], now: i64) -> bool {
    if challenge.len() != CHALLENGE_LEN {
        return false;
    }
    let (body, t) = challenge.split_at(NONCE_LEN + 4);
    if tag(key, user_id, body).verify_truncated_left(t).is_err() {
        return false;
    }
    let expires_at = u32::from_be_bytes(body[NONCE_LEN..].try_into().unwrap()) as i64;
    // Not expired, and not implausibly far in the future (defence in depth: only
    // this server can mint, and it never issues more than TTL_SECS ahead).
    now <= expires_at && expires_at <= now + TTL_SECS + SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3u8; 32];
    const ALICE: &str = "px_00000000000000000000000000000001";
    const BOB: &str = "px_00000000000000000000000000000002";

    #[test]
    fn roundtrip_and_uniqueness() {
        let c = mint(&KEY, ALICE, 1_000).unwrap();
        assert!(check(&KEY, ALICE, &c, 1_000));
        assert!(check(&KEY, ALICE, &c, 1_000 + TTL_SECS));
        assert_ne!(c, mint(&KEY, ALICE, 1_000).unwrap(), "random nonce");
    }

    #[test]
    fn rejects_other_user_key_tamper_expiry_and_length() {
        let c = mint(&KEY, ALICE, 1_000).unwrap();
        assert!(!check(&KEY, BOB, &c, 1_000), "bound to the user");
        assert!(!check(&[4u8; 32], ALICE, &c, 1_000), "wrong key");
        for i in 0..CHALLENGE_LEN {
            let mut t = c;
            t[i] ^= 1;
            assert!(!check(&KEY, ALICE, &t, 1_000), "tamper @{i}");
        }
        assert!(!check(&KEY, ALICE, &c, 1_000 + TTL_SECS + 1), "expired");
        assert!(
            check(&KEY, ALICE, &c, 1_000 - SKEW_SECS),
            "small clock skew ok"
        );
        assert!(
            !check(&KEY, ALICE, &c, 1_000 - SKEW_SECS - 1),
            "issued in the future"
        );
        assert!(!check(&KEY, ALICE, &c[..31], 1_000), "length");
    }
}
