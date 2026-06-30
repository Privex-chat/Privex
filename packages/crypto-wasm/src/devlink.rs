// Device-to-device history transfer (history sync Option B). The two devices each
// generate an EPHEMERAL X25519 keypair, exchange public keys (one via the QR, one
// over the relay), and derive a SHARED symmetric channel key. X25519 is symmetric,
// so both sides compute the same key; the relay only ever forwards ciphertext.
//
// Only the DH + HKDF lives here (Web Crypto X25519 is avoided for browser compat,
// matching the file-CEK module). The per-frame AEAD (AES-256-GCM) runs in the
// browser via Web Crypto (Law 6) under this key.
use wasm_bindgen::prelude::*;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::to_array;

const DEVLINK_INFO: &[u8] = b"privex_devicelink_v1";

/// Derive the 32-byte device-link channel key: HKDF-SHA256(X25519(my_priv, their_pub)).
/// Reuse generate_x25519_prekey() for the ephemeral keypair on each device.
#[wasm_bindgen]
pub fn devlink_channel_key(
    my_x25519_priv: &[u8],
    their_x25519_pub: &[u8],
) -> Result<Vec<u8>, JsError> {
    let my = StaticSecret::from(to_array::<32>(my_x25519_priv, "my_x25519_priv")?);
    let their = XPublicKey::from(to_array::<32>(their_x25519_pub, "their_x25519_pub")?);
    let mut shared = my.diffie_hellman(&their).to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut key = vec![0u8; 32];
    hk.expand(DEVLINK_INFO, &mut key).map_err(|_| JsError::new("hkdf expand"))?;
    shared.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_x25519_prekey;

    #[test]
    fn channel_key_agreement_is_symmetric() {
        let a = generate_x25519_prekey();
        let b = generate_x25519_prekey();
        let ka = devlink_channel_key(&a.private_key, &b.public_key).unwrap();
        let kb = devlink_channel_key(&b.private_key, &a.public_key).unwrap();
        assert_eq!(ka, kb, "both devices must derive the same channel key");
        assert_eq!(ka.len(), 32);

        // A different peer key → a different channel key.
        let c = generate_x25519_prekey();
        let kc = devlink_channel_key(&a.private_key, &c.public_key).unwrap();
        assert_ne!(ka, kc);
    }
}
