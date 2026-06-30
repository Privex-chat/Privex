// Key Transparency client verification (docs 8.2). Byte-for-byte mirror of the
// server's Merkle hashing (server/src/crypto/kt_log.rs): domain-separated
// 0x00 leaf / 0x01 node, fixed bundle field order, big-endian u64 timestamp.
//
// The web app MUST call kt_verify_inclusion on every fetched peer bundle before
// pqxdh_initiate, and separately verify the root signature + the SPK hybrid sig.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// SHA-256 over all public bundle fields (incl ik_x25519 + both SPK sigs).
#[wasm_bindgen]
pub fn kt_bundle_hash(
    ik_ed25519: &[u8],
    ik_dilithium3: &[u8],
    ik_x25519: &[u8],
    spk_x25519: &[u8],
    spk_sig_ed: &[u8],
    spk_sig_dil: &[u8],
    kyber1024_pub: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [
        ik_ed25519,
        ik_dilithium3,
        ik_x25519,
        spk_x25519,
        spk_sig_ed,
        spk_sig_dil,
        kyber1024_pub,
    ] {
        h.update(part);
    }
    h.finalize().to_vec()
}

/// Leaf = SHA-256(0x00 || user_id || bundle_hash || timestamp_be_u64).
#[wasm_bindgen]
pub fn kt_leaf_hash(user_id: &str, bundle_hash: &[u8], timestamp: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(user_id.as_bytes());
    h.update(bundle_hash);
    h.update(timestamp.to_be_bytes());
    h.finalize().to_vec()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify a Merkle inclusion proof. `proof_flat` is a sequence of 33-byte nodes:
/// byte 0 = side (1 = sibling on the left), bytes 1..33 = sibling hash.
#[wasm_bindgen]
pub fn kt_verify_inclusion(leaf: &[u8], proof_flat: &[u8], root: &[u8]) -> bool {
    if leaf.len() != 32 || root.len() != 32 || proof_flat.len() % 33 != 0 {
        return false;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(leaf);
    for chunk in proof_flat.chunks(33) {
        let mut sib = [0u8; 32];
        sib.copy_from_slice(&chunk[1..33]);
        h = if chunk[0] == 1 {
            node_hash(&sib, &h)
        } else {
            node_hash(&h, &sib)
        };
    }
    h.as_slice() == root
}

/// Verify the KT log root signature: Ed25519 over the raw 32-byte root, made with
/// the server's KT signing key (server/src/crypto/kt_log.rs::sign_root). Clients
/// MUST pin `pinned_ed_pub` out-of-band (distributed with the app build, NEVER
/// trusted from the server) and call this on every fetched root BEFORE trusting an
/// inclusion proof - kt_verify_inclusion only proves membership in the GIVEN root,
/// not that the root is authentic.
#[wasm_bindgen]
pub fn kt_verify_root_sig(root: &[u8], sig_ed: &[u8], pinned_ed_pub: &[u8]) -> bool {
    let pk: [u8; 32] = match pinned_ed_pub.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig: [u8; 64] = match sig_ed.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    vk.verify(root, &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn root_sig_verifies_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&[9u8; 32]); // mirrors the server's for_test key
        let pk = sk.verifying_key().to_bytes().to_vec();
        let root = [0xabu8; 32];
        let sig = sk.sign(&root).to_bytes().to_vec();

        assert!(kt_verify_root_sig(&root, &sig, &pk));
        // tampered root → reject
        let mut bad_root = root;
        bad_root[0] ^= 1;
        assert!(!kt_verify_root_sig(&bad_root, &sig, &pk));
        // wrong pinned key → reject
        let other = SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes().to_vec();
        assert!(!kt_verify_root_sig(&root, &sig, &other));
    }
}
