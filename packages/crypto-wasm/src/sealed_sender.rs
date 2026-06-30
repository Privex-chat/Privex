// Sealed Sender (docs 4.5). The sender's certificate is encrypted to the
// recipient's X25519 identity key, so the server-visible wrapper carries no
// sender identity - only an ephemeral pubkey, the sealed cert, and the message.
//
// Time is passed in (`now_unix`) rather than read from a clock:
// wasm32-unknown-unknown has no clock, and it keeps these functions pure.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::to_array;
use crate::{sign_raw, verify_raw};

#[derive(Serialize, Deserialize)]
struct SenderCertificate {
    sender_id: String,
    sender_ed_pub: Vec<u8>,
    sender_dil_pub: Vec<u8>,
    valid_until: u64, // unix seconds
}

#[derive(Serialize, Deserialize)]
struct SignedSenderCert {
    cert: SenderCertificate,
    sig_ed: Vec<u8>,
    sig_dil: Vec<u8>,
}

fn sealed_sender_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(b"sealed_sender", &mut key).expect("hkdf 32");
    key
}

/// Build a signed sender certificate (docs 4.5 step 1).
#[wasm_bindgen]
pub fn generate_sender_cert(
    sender_id: String,
    ed_priv: &[u8],
    ed_pub: &[u8],
    dil_priv: &[u8],
    dil_pub: &[u8],
    now_unix: u64,
    valid_seconds: u64,
) -> Result<Vec<u8>, JsError> {
    let cert = SenderCertificate {
        sender_id,
        sender_ed_pub: ed_pub.to_vec(),
        sender_dil_pub: dil_pub.to_vec(),
        valid_until: now_unix + valid_seconds,
    };
    let cert_bytes = bincode::serialize(&cert).map_err(|e| JsError::new(&e.to_string()))?;
    let (sig_ed, sig_dil) = sign_raw(&cert_bytes, ed_priv, dil_priv)?;

    bincode::serialize(&SignedSenderCert {
        cert,
        sig_ed,
        sig_dil,
    })
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Wrap a message for the recipient (docs 4.5 steps 2-3). `message` is the
/// already-ratchet-encrypted payload; the cert hides the sender identity.
/// Wire layout: eph_pub(32) | nonce(24) | u32 cert_len | enc_cert | message.
#[wasm_bindgen]
pub fn sealed_sender_encrypt(
    message: &[u8],
    sender_cert: &[u8],
    recipient_ik_pub: &[u8],
) -> Result<Vec<u8>, JsError> {
    let recipient = XPublicKey::from(to_array::<32>(recipient_ik_pub, "recipient_ik_pub")?);

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let mut key = sealed_sender_key(shared.as_bytes());

    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| JsError::new(&e.to_string()))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let enc_cert = cipher
        .encrypt(XNonce::from_slice(&nonce), sender_cert)
        .map_err(|_| JsError::new("seal sender cert"))?;
    key.zeroize();

    let mut blob = Vec::with_capacity(32 + 24 + 4 + enc_cert.len() + message.len());
    blob.extend_from_slice(eph_pub.as_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&(enc_cert.len() as u32).to_le_bytes());
    blob.extend_from_slice(&enc_cert);
    blob.extend_from_slice(message);
    Ok(blob)
}

#[wasm_bindgen(getter_with_clone)]
pub struct SealedDecryptResult {
    pub plaintext: Vec<u8>,
    pub sender_id: String,
    /// The Ed25519 identity key the cert is signed by. Callers MUST pin this to a
    /// known contact's key (the px_id alone is not enough to trust on first use).
    pub sender_ed_pub: Vec<u8>,
    pub sender_verified: bool,
}

/// Open a sealed-sender blob (docs 4.5 step 5). `sender_verified` is true only
/// when BOTH cert signatures verify, the cert has not expired, AND the claimed
/// sender_id is the px_id DERIVED from the cert's own ed25519 key - otherwise a
/// sender could sign a cert with their own key while claiming a victim's px_id.
#[wasm_bindgen]
pub fn sealed_sender_decrypt(
    blob: &[u8],
    recipient_ik_priv: &[u8],
    now_unix: u64,
) -> Result<SealedDecryptResult, JsError> {
    if blob.len() < 60 {
        return Err(JsError::new("sealed blob too short"));
    }
    let eph_pub = to_array::<32>(&blob[0..32], "eph_pub")?;
    let nonce = &blob[32..56];
    let cert_len = u32::from_le_bytes([blob[56], blob[57], blob[58], blob[59]]) as usize;
    let cert_end = 60 + cert_len;
    if cert_end > blob.len() {
        return Err(JsError::new("sealed blob: bad cert length"));
    }
    let enc_cert = &blob[60..cert_end];
    let message = &blob[cert_end..];

    let ik = StaticSecret::from(to_array::<32>(recipient_ik_priv, "recipient_ik_priv")?);
    let shared = ik.diffie_hellman(&XPublicKey::from(eph_pub));
    let mut key = sealed_sender_key(shared.as_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let cert_bytes = cipher
        .decrypt(XNonce::from_slice(nonce), enc_cert)
        .map_err(|_| JsError::new("open sealed cert (wrong recipient or tampered)"))?;
    key.zeroize();

    let signed: SignedSenderCert =
        bincode::deserialize(&cert_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let cert_bytes_for_verify =
        bincode::serialize(&signed.cert).map_err(|e| JsError::new(&e.to_string()))?;

    let sig_ok = verify_raw(
        &cert_bytes_for_verify,
        &signed.sig_ed,
        &signed.cert.sender_ed_pub,
        &signed.sig_dil,
        &signed.cert.sender_dil_pub,
    );
    // Bind the claimed id to the signing key: px_id MUST be derived from the cert's
    // own ed25519 key, else a real identity could impersonate any px_id.
    let id_ok = signed.cert.sender_id == crate::user_id_from_ed25519(&signed.cert.sender_ed_pub);
    let sender_verified = sig_ok && id_ok && signed.cert.valid_until >= now_unix;

    Ok(SealedDecryptResult {
        plaintext: message.to_vec(),
        sender_id: signed.cert.sender_id,
        sender_ed_pub: signed.cert.sender_ed_pub,
        sender_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_identity_keypairs;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn sealed_sender_roundtrip_and_no_identity_leak() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        // The sender_id MUST be the px_id derived from the cert's own ed key.
        let sender_id = crate::user_id_from_ed25519(&alice.ed25519_pub);

        let cert = generate_sender_cert(
            sender_id.clone(),
            &alice.ed25519_priv,
            &alice.ed25519_pub,
            &alice.dilithium3_priv,
            &alice.dilithium3_pub,
            1000,
            86_400,
        )
        .unwrap();

        let message = b"this is a ratchet ciphertext stand-in";
        let blob = sealed_sender_encrypt(message, &cert, &bob.x25519_pub).unwrap();

        // The sender id must NOT appear in the outer wrapper.
        assert!(!contains(&blob, sender_id.as_bytes()));

        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.plaintext, message);
        assert_eq!(res.sender_id, sender_id);
        assert_eq!(res.sender_ed_pub, alice.ed25519_pub);
        assert!(res.sender_verified);
    }

    #[test]
    fn forged_sender_id_is_not_verified() {
        // A real identity signs a cert claiming SOMEONE ELSE'S px_id. Sigs are
        // valid, but the id is not derived from the signing key → not verified.
        let attacker = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let victim_id = "px_victim0000000000000000000000a".to_string();

        let cert = generate_sender_cert(
            victim_id.clone(),
            &attacker.ed25519_priv,
            &attacker.ed25519_pub,
            &attacker.dilithium3_priv,
            &attacker.dilithium3_pub,
            1000,
            86_400,
        )
        .unwrap();
        let blob = sealed_sender_encrypt(b"spoof", &cert, &bob.x25519_pub).unwrap();
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.sender_id, victim_id);
        assert!(!res.sender_verified); // id not bound to the signing key
    }

    #[test]
    fn expired_cert_is_not_verified() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();

        let cert = generate_sender_cert(
            crate::user_id_from_ed25519(&alice.ed25519_pub),
            &alice.ed25519_priv,
            &alice.ed25519_pub,
            &alice.dilithium3_priv,
            &alice.dilithium3_pub,
            1000,
            100,
        )
        .unwrap();
        let blob = sealed_sender_encrypt(b"m", &cert, &bob.x25519_pub).unwrap();

        // now past valid_until (1000 + 100)
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 5000).unwrap();
        assert!(!res.sender_verified);
    }

    // wrong-recipient (an Err path) is covered in the Node integration test -
    // JsError can't be constructed on a non-wasm host target.
}
