// Signed delivery timestamps (docs 9.6). The server is the only time anchor -
// no external NTP (an NTP query would leak the client's IP). Every WebSocket
// message delivery carries `server_ts` (time of delivery) + `queued_at` (time of
// arrival at the server) signed with a DEDICATED Ed25519 key whose PUBLIC half is
// pinned in the client binary (like the KT signing key; rotated via app update).
//
// Why two timestamps under one signature: `server_ts` (≈ now at delivery) is what
// the client compares its local clock against - valid even for a message that sat
// queued for days. `queued_at` (enqueue time) is the ordering anchor - a message
// received while offline must sort by when it ARRIVED, not when it was delivered.
//
// The signature covers nothing sensitive: both values are timestamps the server
// necessarily knows, attached OUTSIDE the encrypted content.

use ed25519_dalek::{Signer, SigningKey};

/// Canonical signing input: be64(server_ts) || be64(queued_at) || message_id utf8.
/// The client MUST byte-match this (apps/web services/time-sync.ts).
pub fn signing_input(server_ts: i64, queued_at: i64, message_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + message_id.len());
    buf.extend_from_slice(&(server_ts as u64).to_be_bytes());
    buf.extend_from_slice(&(queued_at as u64).to_be_bytes());
    buf.extend_from_slice(message_id.as_bytes());
    buf
}

/// Ed25519 signature (64 bytes, hex on the wire) over the canonical input.
pub fn sign_delivery(seed: &[u8; 32], server_ts: i64, queued_at: i64, message_id: &str) -> [u8; 64] {
    SigningKey::from_bytes(seed)
        .sign(&signing_input(server_ts, queued_at, message_id))
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn sign_verify_and_tamper() {
        let seed = [11u8; 32];
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let sig = sign_delivery(&seed, 1_900_000_000, 1_899_999_000, "msg-1");

        let ok = signing_input(1_900_000_000, 1_899_999_000, "msg-1");
        assert!(vk.verify(&ok, &Signature::from_bytes(&sig)).is_ok());

        // Any field change breaks the signature.
        for bad in [
            signing_input(1_900_000_001, 1_899_999_000, "msg-1"),
            signing_input(1_900_000_000, 1_899_999_001, "msg-1"),
            signing_input(1_900_000_000, 1_899_999_000, "msg-2"),
        ] {
            assert!(vk.verify(&bad, &Signature::from_bytes(&sig)).is_err());
        }
    }
}
