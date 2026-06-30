// BIP-39 seed phrase recovery (docs 4.2 path 4 / 6). 24 words from 256-bit
// entropy; deterministic re-derivation of the full identity from the mnemonic.

use wasm_bindgen::prelude::*;

use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::identity::{identity_from_seeds, to_array, IdentityKeypairs};

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf 32");
    okm
}

/// 32 bytes of entropy → 24-word BIP-39 mnemonic.
#[wasm_bindgen]
pub fn generate_seed_phrase(entropy: &[u8]) -> Result<String, JsError> {
    let ent = to_array::<32>(entropy, "entropy")?;
    let mnemonic = Mnemonic::from_entropy(&ent).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Mnemonic → 32-byte master seed (docs 4.2: BIP39 seed under a fixed Privex
/// passphrase, then HKDF to the master seed).
#[wasm_bindgen]
pub fn seed_phrase_to_master_seed(mnemonic: &str) -> Result<Vec<u8>, JsError> {
    let parsed = Mnemonic::parse_normalized(mnemonic).map_err(|e| JsError::new(&e.to_string()))?;
    let seed = parsed.to_seed("PRIVEX_SEED_V1"); // 64 bytes
    Ok(hkdf32(&seed, b"privex_master_seed_v1").to_vec())
}

/// Master seed → full identity, deterministically (docs 4.2). Same seed always
/// yields the same keypairs.
#[wasm_bindgen]
pub fn derive_keypairs_from_seed(master_seed: &[u8]) -> Result<IdentityKeypairs, JsError> {
    let ms = to_array::<32>(master_seed, "master_seed")?;
    identity_from_seeds(
        hkdf32(&ms, b"ed25519_ik"),
        hkdf32(&ms, b"x25519_spk"),
        hkdf32(&ms, b"dilithium3_ik"),
        hkdf32(&ms, b"kyber_pk"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_phrase_roundtrip_same_keypairs() {
        let entropy = [0x42u8; 32];
        let phrase = generate_seed_phrase(&entropy).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        let master = seed_phrase_to_master_seed(&phrase).unwrap();
        let k1 = derive_keypairs_from_seed(&master).unwrap();

        // Re-derive from the same phrase → identical keypairs.
        let master2 = seed_phrase_to_master_seed(&phrase).unwrap();
        let k2 = derive_keypairs_from_seed(&master2).unwrap();

        assert_eq!(k1.ed25519_pub, k2.ed25519_pub);
        assert_eq!(k1.ed25519_priv, k2.ed25519_priv);
        assert_eq!(k1.dilithium3_pub, k2.dilithium3_pub);
        assert_eq!(k1.dilithium3_priv, k2.dilithium3_priv);
        assert_eq!(k1.kyber1024_pub, k2.kyber1024_pub);
        assert_eq!(k1.kyber1024_priv, k2.kyber1024_priv);
        assert_eq!(k1.x25519_pub, k2.x25519_pub);
        assert_eq!(k1.x25519_priv, k2.x25519_priv);
    }

    // invalid-mnemonic (an Err path) is covered in the Node integration test -
    // JsError can't be constructed on a non-wasm host target.
}
