// Identity keypair generation (docs 4.1). Hybrid: classical (Ed25519 + X25519)
// and post-quantum (ML-DSA-65 = Dilithium3, ML-KEM-1024 = Kyber1024). All from
// audited pure-Rust crates - no custom crypto.

use wasm_bindgen::prelude::*;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use fips203::ml_kem_1024;
use fips203::traits::{KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::SerDes as SigSerDes;

use sha2::{Digest, Sha256};

/// All keypairs for one Privex identity. Private fields are returned to the
/// caller (the browser) which is responsible for encrypting them at rest.
#[wasm_bindgen(getter_with_clone)]
pub struct IdentityKeypairs {
    pub ed25519_pub: Vec<u8>,
    pub ed25519_priv: Vec<u8>, // 32-byte Ed25519 seed
    pub dilithium3_pub: Vec<u8>,
    pub dilithium3_priv: Vec<u8>,
    pub kyber1024_pub: Vec<u8>,
    pub kyber1024_priv: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub x25519_priv: Vec<u8>,
}

#[wasm_bindgen]
pub fn generate_identity_keypairs() -> Result<IdentityKeypairs, JsError> {
    // Ed25519 (signing identity)
    let ed = SigningKey::generate(&mut OsRng);
    let ed25519_pub = ed.verifying_key().to_bytes().to_vec();
    let ed25519_priv = ed.to_bytes().to_vec(); // 32-byte seed; SigningKey zeroizes on drop

    // X25519 (DH identity used by PQXDH)
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_pub = XPublicKey::from(&x_secret).to_bytes().to_vec();
    let x25519_priv = x_secret.to_bytes().to_vec();

    // Dilithium3 (ML-DSA-65)
    let (dpk, dsk) = ml_dsa_65::try_keygen().map_err(JsError::new)?;
    let dilithium3_pub = dpk.into_bytes().to_vec();
    let dilithium3_priv = dsk.into_bytes().to_vec();

    // Kyber1024 (ML-KEM-1024)
    let (kek, kdk) = ml_kem_1024::KG::try_keygen().map_err(JsError::new)?;
    let kyber1024_pub = kek.into_bytes().to_vec();
    let kyber1024_priv = kdk.into_bytes().to_vec();

    Ok(IdentityKeypairs {
        ed25519_pub,
        ed25519_priv,
        dilithium3_pub,
        dilithium3_priv,
        kyber1024_pub,
        kyber1024_priv,
        x25519_pub,
        x25519_priv,
    })
}

/// A standalone X25519 keypair for the signed prekey (SPK) and one-time prekeys
/// (OPK) - separate from the identity DH key (docs 4.3 prekey system). Random,
/// not seed-derived: prekeys are ephemeral and rotate, so recovery generates
/// fresh ones rather than restoring these.
#[wasm_bindgen(getter_with_clone)]
pub struct X25519Keypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[wasm_bindgen]
pub fn generate_x25519_prekey() -> X25519Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    X25519Keypair {
        public_key: XPublicKey::from(&secret).to_bytes().to_vec(),
        private_key: secret.to_bytes().to_vec(),
    }
}

/// Pseudonymous user id (docs 4.1): `px_` + hex(SHA-256(ed25519_pub)[..16]).
#[wasm_bindgen]
pub fn user_id_from_ed25519(ed25519_pub: &[u8]) -> String {
    let digest = Sha256::digest(ed25519_pub);
    format!("px_{}", hex::encode(&digest[..16]))
}

/// Deterministically build all keypairs from four 32-byte seeds. Same seeds →
/// same identity (docs 4.2 seed-phrase recovery). PQ keygen is driven by a
/// ChaCha20 RNG seeded from the given bytes.
pub(crate) fn identity_from_seeds(
    ed_seed: [u8; 32],
    x_seed: [u8; 32],
    dil_seed: [u8; 32],
    kyber_seed: [u8; 32],
) -> Result<IdentityKeypairs, JsError> {
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let ed = SigningKey::from_bytes(&ed_seed);
    let ed25519_pub = ed.verifying_key().to_bytes().to_vec();
    let ed25519_priv = ed.to_bytes().to_vec();

    let x_secret = StaticSecret::from(x_seed);
    let x25519_pub = XPublicKey::from(&x_secret).to_bytes().to_vec();
    let x25519_priv = x_secret.to_bytes().to_vec();

    let mut dil_rng = ChaCha20Rng::from_seed(dil_seed);
    let (dpk, dsk) = ml_dsa_65::try_keygen_with_rng(&mut dil_rng).map_err(JsError::new)?;
    let dilithium3_pub = dpk.into_bytes().to_vec();
    let dilithium3_priv = dsk.into_bytes().to_vec();

    let mut kyber_rng = ChaCha20Rng::from_seed(kyber_seed);
    let (kek, kdk) = ml_kem_1024::KG::try_keygen_with_rng(&mut kyber_rng).map_err(JsError::new)?;
    let kyber1024_pub = kek.into_bytes().to_vec();
    let kyber1024_priv = kdk.into_bytes().to_vec();

    Ok(IdentityKeypairs {
        ed25519_pub,
        ed25519_priv,
        dilithium3_pub,
        dilithium3_priv,
        kyber1024_pub,
        kyber1024_priv,
        x25519_pub,
        x25519_priv,
    })
}

/// Helper: copy a slice into a fixed array with a descriptive error.
pub(crate) fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{what}: expected {N} bytes, got {}", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_prekey_pub_matches_priv() {
        let kp = generate_x25519_prekey();
        assert_eq!(kp.private_key.len(), 32);
        assert_eq!(kp.public_key.len(), 32);
        // The returned public key is the X25519 base-point mult of the private.
        let priv_arr = to_array::<32>(&kp.private_key, "priv").unwrap();
        let expected = XPublicKey::from(&StaticSecret::from(priv_arr)).to_bytes().to_vec();
        assert_eq!(kp.public_key, expected);
    }
}
