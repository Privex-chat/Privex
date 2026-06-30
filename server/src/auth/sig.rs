// Server-side hybrid signature verification (Ed25519 + Dilithium3). BOTH must
// verify (docs 4.1 strict mode). Used by /auth/verify against the directory keys.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier as DsaVerifier};

pub fn verify_hybrid(
    msg: &[u8],
    sig_ed: &[u8],
    ed_pub: &[u8],
    sig_dil: &[u8],
    dil_pub: &[u8],
) -> bool {
    verify_ed25519(msg, sig_ed, ed_pub) && verify_dilithium3(msg, sig_dil, dil_pub)
}

fn verify_ed25519(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    let pk_arr: [u8; 32] = match pubkey.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    vk.verify(msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

fn verify_dilithium3(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    let pk = match pubkey
        .try_into()
        .ok()
        .and_then(|a: [u8; ml_dsa_65::PK_LEN]| ml_dsa_65::PublicKey::try_from_bytes(a).ok())
    {
        Some(k) => k,
        None => return false,
    };
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    pk.verify(msg, &sig_arr, &[])
}

/// Canonical signing input for /auth/verify (docs 4.9): challenge bytes ||
/// user_id utf8 || timestamp big-endian u64. The client MUST build this exact
/// layout when signing.
pub fn challenge_signing_input(challenge: &[u8], user_id: &str, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(challenge.len() + user_id.len() + 8);
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(user_id.as_bytes());
    buf.extend_from_slice(&(timestamp as u64).to_be_bytes());
    buf
}
