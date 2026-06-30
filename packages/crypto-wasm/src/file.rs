// File CEK lifecycle (docs 4.7). The bulk chunk encryption (AES-256-GCM + HKDF +
// SHA-256) runs in the browser via the Web Crypto API; this module covers only
// the parts Web Crypto can't do cleanly: generating the CEK and wrapping it for
// the recipient with an X25519 ephemeral + XChaCha20-Poly1305.

use wasm_bindgen::prelude::*;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::to_array;

const WRAP_INFO: &[u8] = b"file_cek_wrap";
const NONCE_LEN: usize = 24;

fn wrap_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(WRAP_INFO, &mut key).expect("hkdf 32");
    key
}

/// Random 32-byte Content Encryption Key (docs 4.7 step 1).
#[wasm_bindgen]
pub fn generate_cek() -> Result<Vec<u8>, JsError> {
    let mut cek = vec![0u8; 32];
    OsRng.fill_bytes(&mut cek);
    Ok(cek)
}

/// The CEK wrapped for a recipient + the ephemeral public key they need to unwrap.
#[wasm_bindgen(getter_with_clone)]
pub struct WrappedCek {
    /// nonce(24) || XChaCha20-Poly1305(wrap_key, CEK)
    pub wrapped: Vec<u8>,
    pub eph_pub: Vec<u8>,
}

/// Wrap the CEK for the recipient (docs 4.7 step 5): X25519(eph, IK_recipient) →
/// HKDF → XChaCha20-Poly1305(CEK).
#[wasm_bindgen]
pub fn wrap_cek(cek: &[u8], recipient_ik_x25519_pub: &[u8]) -> Result<WrappedCek, JsError> {
    let recipient = XPublicKey::from(to_array::<32>(recipient_ik_x25519_pub, "recipient_ik_pub")?);
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let mut key = wrap_key(shared.as_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), cek)
        .map_err(|_| JsError::new("wrap cek"))?;
    key.zeroize();

    let mut wrapped = Vec::with_capacity(NONCE_LEN + ct.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    Ok(WrappedCek {
        wrapped,
        eph_pub: eph_pub.as_bytes().to_vec(),
    })
}

/// Unwrap the CEK (docs 4.7 receive step 2): X25519(IK_recipient_priv, eph_pub) →
/// HKDF → XChaCha20-Poly1305 decrypt.
#[wasm_bindgen]
pub fn unwrap_cek(
    wrapped: &[u8],
    eph_pub: &[u8],
    my_ik_x25519_priv: &[u8],
) -> Result<Vec<u8>, JsError> {
    if wrapped.len() < NONCE_LEN + 16 {
        return Err(JsError::new("wrapped cek too short"));
    }
    let eph = XPublicKey::from(to_array::<32>(eph_pub, "eph_pub")?);
    let my = StaticSecret::from(to_array::<32>(my_ik_x25519_priv, "my_ik_priv")?);
    let shared = my.diffie_hellman(&eph);
    let mut key = wrap_key(shared.as_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let cek = cipher
        .decrypt(XNonce::from_slice(&wrapped[..NONCE_LEN]), &wrapped[NONCE_LEN..])
        .map_err(|_| JsError::new("unwrap cek (wrong recipient or tampered)"))?;
    key.zeroize();
    Ok(cek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_identity_keypairs;

    #[test]
    fn cek_wrap_roundtrip() {
        let bob = generate_identity_keypairs().unwrap();
        let cek = generate_cek().unwrap();
        assert_eq!(cek.len(), 32);

        let w = wrap_cek(&cek, &bob.x25519_pub).unwrap();
        let got = unwrap_cek(&w.wrapped, &w.eph_pub, &bob.x25519_priv).unwrap();
        assert_eq!(got, cek);
        // Wrong-recipient (Err path) is covered in the Node integration test -
        // JsError can't be constructed on a non-wasm host target.
    }
}
