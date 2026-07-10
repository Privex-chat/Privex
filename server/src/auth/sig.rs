// Server-side hybrid signature verification (Ed25519 + Dilithium3). BOTH must
// verify (docs 4.1 strict mode). Used by /auth/verify against the directory keys.

use std::sync::OnceLock;

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
    // Non-short-circuiting `&` (not `&&`): BOTH verifications always run, so the
    // time taken never depends on which one fails. Combined with the random dummy
    // keys below, the absent-user path in /auth/verify does the same work as a
    // present-user path, leaving no existence timing oracle (PVX-08).
    verify_ed25519(msg, sig_ed, ed_pub) & verify_dilithium3(msg, sig_dil, dil_pub)
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

/// Domain-separation context for auth-challenge signatures (PVX-21). Other
/// signing contexts (SPK, sender cert) get their own tags in a future protocol
/// version bump - they have stored/in-flight signatures a prefix would break.
pub const AUTH_CONTEXT_V1: &[u8] = b"privex-auth-v1";

/// LEGACY signing input for /auth/verify (docs 4.9): challenge bytes ||
/// user_id utf8 || timestamp big-endian u64. Accepted transitionally while
/// cached PWA clients still sign without the context tag.
pub fn challenge_signing_input(challenge: &[u8], user_id: &str, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(challenge.len() + user_id.len() + 8);
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(user_id.as_bytes());
    buf.extend_from_slice(&(timestamp as u64).to_be_bytes());
    buf
}

/// Current signing input: AUTH_CONTEXT_V1 || legacy layout. The client MUST
/// build this exact layout when signing (crypto/onboarding-crypto.ts).
pub fn challenge_signing_input_v1(challenge: &[u8], user_id: &str, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AUTH_CONTEXT_V1.len() + challenge.len() + user_id.len() + 8);
    buf.extend_from_slice(AUTH_CONTEXT_V1);
    buf.extend_from_slice(&challenge_signing_input(challenge, user_id, timestamp));
    buf
}

/// Verify an auth-challenge signature against BOTH accepted layouts: v1
/// (domain-separated) first, legacy as a transitional fallback. Remove the
/// fallback once pre-context PWA builds have aged out of caches.
pub fn verify_auth_challenge(
    challenge: &[u8],
    user_id: &str,
    timestamp: i64,
    sig_ed: &[u8],
    ed_pub: &[u8],
    sig_dil: &[u8],
    dil_pub: &[u8],
) -> bool {
    let v1 = challenge_signing_input_v1(challenge, user_id, timestamp);
    if verify_hybrid(&v1, sig_ed, ed_pub, sig_dil, dil_pub) {
        return true;
    }
    let legacy = challenge_signing_input(challenge, user_id, timestamp);
    verify_hybrid(&legacy, sig_ed, ed_pub, sig_dil, dil_pub)
}

// Dummy verification keys for the absent-user path of /auth/verify (PVX-08): the
// same verification work runs whether or not the user exists, so response timing
// can't distinguish real from unknown px_ids. Both halves use process-local
// CSPRNG entropy generated once at first use - a REPRODUCIBLE seed would let an
// attacker craft a signature that validates against the known dummy key, making
// the dummy path do more work than a present-user path and reopening the oracle.
// The private halves are discarded - no submitted signature can validate here.
static DUMMY_KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

fn dummy_keys() -> &'static (Vec<u8>, Vec<u8>) {
    DUMMY_KEYS.get_or_init(|| {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("rng");
        let ed = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let (dil_pub, _dil_priv) = ml_dsa_65::try_keygen().expect("dilithium keygen");
        (ed, dil_pub.into_bytes().to_vec())
    })
}

/// Timing-equalizing stand-in for `verify_auth_challenge` when the user does
/// not exist. Always returns false (by construction).
pub fn dummy_verify_auth_challenge(
    challenge: &[u8],
    user_id: &str,
    timestamp: i64,
    sig_ed: &[u8],
    sig_dil: &[u8],
) -> bool {
    let (ed_pub, dil_pub) = dummy_keys();
    verify_auth_challenge(challenge, user_id, timestamp, sig_ed, ed_pub, sig_dil, dil_pub)
}
