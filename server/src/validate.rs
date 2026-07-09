// Central input validation - every user-supplied value must pass through one of
// these functions BEFORE it reaches business logic or a database query. This
// module is the single source of truth for input size, format, and content bounds.

use crate::error::ApiError;
use sha2::{Digest, Sha256};

// --------------- size/length constants ---------------

pub const PX_ID_LEN: usize = 35;
pub const PX_ID_PREFIX: &str = "px_";

pub const ED25519_PUB_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const X25519_PUB_LEN: usize = 32;

pub const CHUNK_ID_CHARS: usize = 64;
pub const SHA256_HEX_CHARS: usize = 64;

pub const OPAQUE_MAX_WIRE_BYTES: usize = 4096;
pub const OPAQUE_ENVELOPE_BYTES: usize = 116;
pub const OPAQUE_ENVELOPE_MAC_BYTES: usize = 32;

pub const MAX_OPKS_PER_REPLENISH: usize = 200;
pub const MAX_OPKS_PER_REGISTRATION: usize = 200;
pub const MIN_OPKS_PER_REGISTRATION: usize = 1;

pub const MAX_ACK_BATCH: usize = 500;
pub const MAX_HISTORY_BATCH: usize = 500;
pub const MAX_HISTORY_BLOB_BYTES: usize = 256 * 1024;
pub const MAX_HISTORY_BLOB_ID_CHARS: usize = 64;

pub const MAX_SHARES_BATCH: usize = 10;
pub const MAX_SHARE_BYTES: usize = 4096;

pub const MAX_DEVLINK_FRAME_BYTES: usize = 2 * 1024 * 1024;

pub const WS_TICKET_HEX_CHARS: usize = 64;
pub const DEVLINK_RID_HEX_CHARS: usize = 32;
pub const CHALLENGE_HEX_CHARS: usize = 64;

pub const DIFFICULTY_MIN: u32 = 1;
pub const DIFFICULTY_MAX: u32 = 31;

pub const MIN_PASSPHRASE_CHARS: usize = 6;
pub const MAX_PASSPHRASE_CHARS: usize = 512;
pub const MAX_MESSAGE_TEXT_CHARS: usize = 65536;
pub const MAX_CONTENT_B64_BYTES: usize = 260 * 1024; // ~256K sealed sender blob + overhead
pub const MAX_CSAM_PROOF_B64_BYTES: usize = 1024 * 1024;

pub const MAX_TIMESTAMP_DRIFT_SECS: i64 = 86400; // +/-1 day from now

pub const MAX_BLOB_UPLOAD_BYTES: usize = 5 * 1024 * 1024; // 5 MiB per chunk

// --------------- core validators ---------------

/// Validate a Privex ID: `px_` + 32 lowercase hex chars.
pub fn validate_px_id(s: &str) -> bool {
    s.len() == PX_ID_LEN
        && s.starts_with(PX_ID_PREFIX)
        && s.as_bytes()[3..]
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate and decode a hex string expected to decode to exactly `exact_bytes`.
pub fn validate_hex_exact(s: &str, exact_bytes: usize) -> Result<Vec<u8>, ApiError> {
    if s.len() != exact_bytes.saturating_mul(2) {
        return Err(ApiError::bad_request());
    }
    hex::decode(s).map_err(|_| ApiError::bad_request())
}

/// Validate and decode a hex string with a maximum decoded byte length.
pub fn validate_hex_max(s: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    if s.len() > max_bytes.saturating_mul(2) || s.len() % 2 != 0 {
        return Err(ApiError::bad_request());
    }
    hex::decode(s).map_err(|_| ApiError::bad_request())
}

/// Validate a hex string has exactly `exact_chars` hex chars (no decode).
pub fn validate_hex_str_exact(s: &str, exact_chars: usize) -> bool {
    s.len() == exact_chars
        && s.as_bytes()
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b))
}

/// Validate and decode a base64 string with a maximum decoded byte length.
pub fn validate_b64(s: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD.decode(s).map_err(|_| ApiError::bad_request())?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(ApiError::bad_request());
    }
    Ok(bytes)
}

/// Validate a content-addressed chunk_id: exactly 64 lowercase hex chars (SHA-256).
pub fn validate_chunk_id(s: &str) -> bool {
    s.len() == CHUNK_ID_CHARS
        && s.as_bytes()
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate a UUID v4 string.
pub fn validate_uuid(s: &str) -> bool {
    sqlx::types::Uuid::parse_str(s).is_ok()
}

/// Validate a WebSocket ticket: exactly 64 lowercase hex chars.
pub fn validate_ws_ticket(s: &str) -> bool {
    validate_hex_str_exact(s, WS_TICKET_HEX_CHARS)
}

/// Validate a devlink rendezvous_id: exactly 32 lowercase hex chars.
pub fn validate_devlink_rid(s: &str) -> bool {
    validate_hex_str_exact(s, DEVLINK_RID_HEX_CHARS)
}

/// Validate a PoW challenge_id is a valid UUID.
pub fn validate_pow_challenge_id(s: &str) -> bool {
    validate_uuid(s)
}

/// Validate the solution_hash field of a PoW proof: exactly 32 bytes (64 hex).
pub fn validate_solution_hash(s: &str) -> Result<Vec<u8>, ApiError> {
    validate_hex_exact(s, 32)
}

/// Validate a timestamp is within acceptable drift from the current time.
pub fn validate_timestamp(ts: i64, now: i64) -> bool {
    let drift = now.saturating_sub(ts).unsigned_abs();
    drift < MAX_TIMESTAMP_DRIFT_SECS as u64
}

/// Sanitize a user-supplied string: trim whitespace, reject control chars,
/// enforce a maximum UTF-8 byte length.
pub fn sanitize_string(s: &str, max_byte_len: usize) -> Result<String, ApiError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request());
    }
    if trimmed.len() > max_byte_len {
        return Err(ApiError::bad_request());
    }
    // Reject ASCII control characters (0x00-0x1F, except 0x09 tab, 0x0A newline)
    if trimmed.bytes().any(|b| b < 0x20 && b != 0x09 && b != 0x0A) {
        return Err(ApiError::bad_request());
    }
    Ok(trimmed.to_string())
}

/// Validate a history `blob_id`: a UUID msg_id or a `contact:<px_id>`-style key.
/// Restricted to `[A-Za-z0-9:_-]`, 1..=64 chars - far tighter than the general
/// `sanitize_string` (which allowed tabs/newlines/arbitrary UTF-8) that this
/// key never needs (PVX-18). Parameterized in SQL either way, but hygiene.
pub fn validate_history_blob_id(s: &str) -> Result<String, ApiError> {
    let ok = !s.is_empty()
        && s.len() <= MAX_HISTORY_BLOB_ID_CHARS
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-');
    if ok {
        Ok(s.to_string())
    } else {
        Err(ApiError::bad_request())
    }
}

/// Validate a recovery share index is in the accepted range (1-255).
pub fn validate_share_index(idx: i16) -> bool {
    (1..=255).contains(&idx)
}

/// Validate an OPAQUE wire message size and hex format.
pub fn validate_opaque_wire(s: &str) -> Result<Vec<u8>, ApiError> {
    validate_hex_max(s, OPAQUE_MAX_WIRE_BYTES)
}

/// Validate the history cursor `after` format: `created_at:blob_id`.
pub fn validate_history_cursor(cursor: &str) -> Result<(i32, String), ApiError> {
    let colon = cursor.find(':').ok_or_else(ApiError::bad_request)?;
    let after_at = cursor[..colon].parse::<i32>().map_err(|_| ApiError::bad_request())?;
    let b = &cursor[colon + 1..];
    if b.is_empty() || b.len() > MAX_HISTORY_BLOB_ID_CHARS {
        return Err(ApiError::bad_request());
    }
    // blob_id must match the same character set accepted by sanitize_string
    if b.bytes().any(|c| c < 0x20 && c != 0x09 && c != 0x0A) {
        return Err(ApiError::bad_request());
    }
    Ok((after_at, b.to_string()))
}

/// Validate the page `limit` parameter for list endpoints. Returns clamped value.
pub fn validate_page_limit(limit: Option<i64>, default: i64, max: i64) -> i64 {
    limit.unwrap_or(default).clamp(1, max)
}

/// Validate that a share_index is not a duplicate in a batch.
pub fn validate_no_duplicate_indices(indices: &[i16]) -> bool {
    let mut sorted = indices.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.len() == indices.len()
}

/// Validate that a string value for an enum-like field contains only safe chars.
pub fn validate_safe_enum(s: &str, allowed: &[&str]) -> bool {
    allowed.contains(&s)
}

/// Validate identity key material lengths (bundle registration).
pub fn validate_identity_key(ik_ed: &[u8]) -> Result<(), ApiError> {
    require_len(ik_ed, ED25519_PUB_LEN)
}

pub fn validate_dilithium_pk(ik_dil: &[u8]) -> Result<(), ApiError> {
    require_len(ik_dil, fips204::ml_dsa_65::PK_LEN)
}

pub fn validate_x25519_pub(pk: &[u8]) -> Result<(), ApiError> {
    require_len(pk, X25519_PUB_LEN)
}

pub fn validate_ed25519_sig(sig: &[u8]) -> Result<(), ApiError> {
    require_len(sig, ED25519_SIG_LEN)
}

pub fn validate_dilithium_sig(sig: &[u8]) -> Result<(), ApiError> {
    require_len(sig, fips204::ml_dsa_65::SIG_LEN)
}

pub fn validate_kyber_pub(pk: &[u8]) -> Result<(), ApiError> {
    require_len(pk, fips203::ml_kem_1024::EK_LEN)
}

fn require_len(bytes: &[u8], expected: usize) -> Result<(), ApiError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ApiError::bad_request())
    }
}

/// Validate `message_ids` array for ACK: each must be a valid UUID, total <= MAX_ACK_BATCH.
pub fn validate_message_ids(ids: &[String]) -> Result<Vec<sqlx::types::Uuid>, ApiError> {
    if ids.is_empty() || ids.len() > MAX_ACK_BATCH {
        return Err(ApiError::bad_request());
    }
    let mut parsed = Vec::with_capacity(ids.len());
    for s in ids {
        let uuid = sqlx::types::Uuid::parse_str(s).map_err(|_| ApiError::bad_request())?;
        parsed.push(uuid);
    }
    Ok(parsed)
}

/// Verify the user_id integrity: px_ + hex(SHA-256(ik_ed25519)[..16]).
pub fn validate_user_id_integrity(user_id: &str, ik_ed25519: &[u8]) -> Result<(), ApiError> {
    let expected = format!("px_{}", hex::encode(&Sha256::digest(ik_ed25519)[..16]));
    if expected != user_id {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn px_id_valid() {
        assert!(validate_px_id("px_0000000000000000000000000000000a"));
        assert!(!validate_px_id("px_0000000000000000000000000000000")); // too short
        assert!(!validate_px_id("px_0000000000000000000000000000000gg")); // invalid char
        assert!(!validate_px_id("PX_00000000000000000000000000000001")); // uppercase prefix
    }

    #[test]
    fn hex_exact() {
        assert!(validate_hex_exact("aabb", 2).is_ok());
        assert!(validate_hex_exact("aabb", 3).is_err()); // wrong decode len
        assert!(validate_hex_exact("aabg", 2).is_err()); // invalid hex char
        assert!(validate_hex_exact("aabbcc", 2).is_err()); // wrong hex len
    }

    #[test]
    fn sanitize_string_works() {
        assert_eq!(sanitize_string("  hello  ", 100).unwrap(), "hello");
        assert!(sanitize_string("", 100).is_err());
        assert!(sanitize_string("he\x00llo", 100).is_err()); // null byte
        assert!(sanitize_string("hello\nworld", 100).is_ok()); // newline OK
        assert!(sanitize_string("hello\tworld", 100).is_ok()); // tab OK
    }

    #[test]
    fn chunk_id_valid() {
        assert!(validate_chunk_id(&"a".repeat(64)));
        assert!(!validate_chunk_id(&"a".repeat(63))); // too short
        assert!(!validate_chunk_id(&"A".repeat(64))); // uppercase
        assert!(!validate_chunk_id(&"g".repeat(64))); // invalid hex
    }

    #[test]
    fn uuid_valid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!validate_uuid("not-a-uuid"));
        assert!(!validate_uuid(""));
    }

    #[test]
    fn timestamp_valid() {
        let now = 1_000_000_000i64;
        assert!(validate_timestamp(now, now));
        assert!(validate_timestamp(now - 86399, now)); // within drift
        assert!(!validate_timestamp(now - 86401, now)); // beyond drift
        assert!(!validate_timestamp(i64::MIN, 0)); // extreme negative, no panic
        assert!(!validate_timestamp(0, i64::MAX)); // extreme positive, no panic
    }

    #[test]
    fn share_index_range() {
        assert!(validate_share_index(1));
        assert!(validate_share_index(128));
        assert!(validate_share_index(255));
        assert!(!validate_share_index(0));
        assert!(!validate_share_index(256));
        assert!(!validate_share_index(-1));
    }

    #[test]
    fn history_blob_id() {
        assert!(validate_history_blob_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_history_blob_id("contact:px_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6").is_ok());
        assert!(validate_history_blob_id("").is_err()); // empty
        assert!(validate_history_blob_id(&"a".repeat(65)).is_err()); // too long
        assert!(validate_history_blob_id("has space").is_err());
        assert!(validate_history_blob_id("tab\there").is_err());
        assert!(validate_history_blob_id("new\nline").is_err());
        assert!(validate_history_blob_id("slash/../etc").is_err());
    }

    #[test]
    fn history_cursor() {
        assert!(validate_history_cursor("100:abc").is_ok());
        assert!(validate_history_cursor(":").is_err());
        assert!(validate_history_cursor("abc:").is_err());
        assert!(validate_history_cursor("").is_err());
        assert!(validate_history_cursor("100:contact:px_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p").is_ok());
        assert!(validate_history_cursor("100:hello world").is_ok());
    }

    #[test]
    fn page_limit_clamping() {
        assert_eq!(validate_page_limit(None, 200, 500), 200);
        assert_eq!(validate_page_limit(Some(10), 200, 500), 10);
        assert_eq!(validate_page_limit(Some(1000), 200, 500), 500);
        assert_eq!(validate_page_limit(Some(0), 200, 500), 1);
    }

    #[test]
    fn no_dup_indices() {
        assert!(validate_no_duplicate_indices(&[1, 2, 3]));
        assert!(!validate_no_duplicate_indices(&[1, 1, 2]));
    }
}
