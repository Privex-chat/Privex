// App-lock key derivation. The passphrase that gates the device wraps the data key,
// so the wrapping key MUST be memory-hard to slow offline brute-force of a copied
// IndexedDB (a short PIN still has a guessing ceiling - the UI enforces length, and
// the biometric/WebAuthn factor is the truly brute-force-proof path). Argon2id with
// caller-supplied cost so the parameters are stored alongside the wrap and can be
// tuned without breaking existing locks.
use wasm_bindgen::prelude::*;

use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id(password, salt) → 32-byte key-wrapping key. p (lanes) is fixed at 1
/// (browsers are single-threaded for this); m_cost is in KiB, t_cost is iterations.
#[wasm_bindgen]
pub fn applock_derive_key(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
) -> Result<Vec<u8>, JsError> {
    if salt.len() < 16 {
        return Err(JsError::new("salt too short"));
    }
    let params = Params::new(m_cost, t_cost, 1, Some(32)).map_err(|_| JsError::new("argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| JsError::new("argon2 derive"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_and_salt_dependent() {
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        // Small params keep the test fast; production uses much higher m_cost.
        let a = applock_derive_key(b"correct horse", &salt1, 64, 1).unwrap();
        let b = applock_derive_key(b"correct horse", &salt1, 64, 1).unwrap();
        let c = applock_derive_key(b"correct horse", &salt2, 64, 1).unwrap();
        let d = applock_derive_key(b"wrong horse", &salt1, 64, 1).unwrap();
        assert_eq!(a, b, "same inputs → same key");
        assert_eq!(a.len(), 32);
        assert_ne!(a, c, "different salt → different key");
        assert_ne!(a, d, "different password → different key");
    }
}
