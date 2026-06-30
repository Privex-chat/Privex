// Privex crypto-wasm - Part 1: identity, hybrid signatures, PQXDH.
// Pure-Rust audited primitives only (no custom crypto, no C toolchain).
// Sessions 4–6 add Double Ratchet, Sealed Sender, OPAQUE, Shamir, PoW, PSI.

mod applock;
mod devlink;
mod file;
mod identity;
mod kt;
mod pow;
mod pqxdh;
mod psi;
mod ratchet;
mod recovery;
mod sealed_sender;
mod seed;
mod shamir;
mod util;

pub use identity::{
    generate_identity_keypairs, generate_x25519_prekey, user_id_from_ed25519, IdentityKeypairs,
    X25519Keypair,
};
pub use pqxdh::{pqxdh_initiate, pqxdh_respond, PqxdhInitMessage, PqxdhInitResult, PreKeyBundle};
pub use ratchet::{
    ratchet_decrypt, ratchet_encrypt, ratchet_init_alice, ratchet_init_bob, DecryptResult,
    RatchetResult,
};
pub use sealed_sender::{
    generate_sender_cert, sealed_sender_decrypt, sealed_sender_encrypt, SealedDecryptResult,
};
pub use recovery::{
    opaque_login_finish, opaque_login_start, opaque_register_finish, opaque_register_start,
    OpaqueLoginFinish, OpaqueLoginStart, OpaqueRegistrationFinish, OpaqueRegistrationStart,
};
pub use applock::applock_derive_key;
pub use devlink::devlink_channel_key;
pub use file::{generate_cek, unwrap_cek, wrap_cek, WrappedCek};
pub use kt::{kt_bundle_hash, kt_leaf_hash, kt_verify_inclusion, kt_verify_root_sig};
pub use pow::{pow_solve, pow_solve_native, pow_verify, PowSolution};
pub use psi::{psi_blind_hash, psi_check_membership, psi_unblind, PSIBlindResult};
pub use seed::{derive_keypairs_from_seed, generate_seed_phrase, seed_phrase_to_master_seed};
pub use shamir::{shamir_reconstruct, shamir_split};
pub use util::{hkdf_derive, pdq_hash};

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as DsaSerDes, Signer as DsaSigner, Verifier as DsaVerifier};

use identity::to_array;

/// Combined Ed25519 + Dilithium3 signature over the same data (docs 4.1).
#[wasm_bindgen(getter_with_clone)]
pub struct HybridSignature {
    pub sig_ed25519: Vec<u8>,
    pub sig_dilithium3: Vec<u8>,
}

/// Sign `data` with both identity private keys. `ed_priv` is the 32-byte seed.
#[wasm_bindgen]
pub fn sign_hybrid(data: &[u8], ed_priv: &[u8], dil_priv: &[u8]) -> Result<HybridSignature, JsError> {
    let (sig_ed25519, sig_dilithium3) = sign_raw(data, ed_priv, dil_priv)?;
    Ok(HybridSignature {
        sig_ed25519,
        sig_dilithium3,
    })
}

/// Internal: returns the two signatures as plain byte vecs (reused by Sealed
/// Sender to sign certificates).
pub(crate) fn sign_raw(
    data: &[u8],
    ed_priv: &[u8],
    dil_priv: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), JsError> {
    let mut seed = to_array::<32>(ed_priv, "ed_priv")?;
    let signing = SigningKey::from_bytes(&seed);
    let sig_ed = signing.sign(data).to_bytes().to_vec();
    seed.zeroize();

    let sk = ml_dsa_65::PrivateKey::try_from_bytes(
        dil_priv
            .try_into()
            .map_err(|_| JsError::new("dil_priv: wrong length"))?,
    )
    .map_err(JsError::new)?;
    let sig_dil = sk.try_sign(data, &[]).map_err(JsError::new)?.to_vec();

    Ok((sig_ed, sig_dil))
}

/// Verify a hybrid signature. BOTH signatures must be valid (docs 4.1 strict
/// mode) - returns false if either fails.
#[wasm_bindgen]
pub fn verify_hybrid(
    data: &[u8],
    sig_ed: &[u8],
    ed_pub: &[u8],
    sig_dil: &[u8],
    dil_pub: &[u8],
) -> bool {
    verify_raw(data, sig_ed, ed_pub, sig_dil, dil_pub)
}

/// Internal: BOTH signatures must verify (reused by Sealed Sender cert check).
pub(crate) fn verify_raw(
    data: &[u8],
    sig_ed: &[u8],
    ed_pub: &[u8],
    sig_dil: &[u8],
    dil_pub: &[u8],
) -> bool {
    verify_ed25519(data, sig_ed, ed_pub) && verify_dilithium3(data, sig_dil, dil_pub)
}

fn verify_ed25519(data: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
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
    vk.verify(data, &Signature::from_bytes(&sig_arr)).is_ok()
}

fn verify_dilithium3(data: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
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
    pk.verify(data, &sig_arr, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

    #[test]
    fn user_id_format() {
        let id = user_id_from_ed25519(&[0u8; 32]);
        assert!(id.starts_with("px_"));
        assert_eq!(id.len(), 3 + 32); // "px_" + 16 bytes hex
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let k = generate_identity_keypairs().unwrap();
        let data = b"identity assertion";
        let sig = sign_hybrid(data, &k.ed25519_priv, &k.dilithium3_priv).unwrap();

        assert!(verify_hybrid(
            data,
            &sig.sig_ed25519,
            &k.ed25519_pub,
            &sig.sig_dilithium3,
            &k.dilithium3_pub,
        ));

        // Tampered data must fail.
        assert!(!verify_hybrid(
            b"different data",
            &sig.sig_ed25519,
            &k.ed25519_pub,
            &sig.sig_dilithium3,
            &k.dilithium3_pub,
        ));

        // A bad Ed25519 sig fails even with a valid Dilithium sig.
        let mut bad = sig.sig_ed25519.clone();
        bad[0] ^= 0xff;
        assert!(!verify_hybrid(
            data,
            &bad,
            &k.ed25519_pub,
            &sig.sig_dilithium3,
            &k.dilithium3_pub,
        ));
    }

    #[test]
    fn pqxdh_initiate_respond_agree() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();

        // Bob's SPK and OPK are separate X25519 keys (docs 4.3 prekey system).
        let spk = StaticSecret::random_from_rng(OsRng);
        let opk = StaticSecret::random_from_rng(OsRng);
        let spk_pub = XPublicKey::from(&spk).to_bytes().to_vec();
        let opk_pub = XPublicKey::from(&opk).to_bytes().to_vec();

        let bundle = PreKeyBundle::new(
            bob.x25519_pub.clone(),
            spk_pub,
            opk_pub,
            bob.kyber1024_pub.clone(),
        );

        let init = pqxdh_initiate(&alice.x25519_priv, &bundle).unwrap();
        assert!(init.opk_used);

        let msg = PqxdhInitMessage::new(
            init.alice_ik_pub.clone(),
            init.alice_ek_pub.clone(),
            init.kyber_ciphertext.clone(),
            init.opk_used,
        );
        let bob_secret = pqxdh_respond(
            &msg,
            &bob.x25519_priv,
            &spk.to_bytes(),
            &opk.to_bytes(),
            &bob.kyber1024_priv,
        )
        .unwrap();

        assert_eq!(init.shared_secret, bob_secret);
        assert_eq!(init.shared_secret.len(), 32);
    }

    // Drained OPK supply: server returns an empty OPK → 3-DH PQXDH must still
    // agree (docs 4.3 / X3DH OPK is optional).
    #[test]
    fn pqxdh_no_opk_agree() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();

        let spk = StaticSecret::random_from_rng(OsRng);
        let spk_pub = XPublicKey::from(&spk).to_bytes().to_vec();

        // Empty OPK in the bundle → no-OPK path.
        let bundle = PreKeyBundle::new(
            bob.x25519_pub.clone(),
            spk_pub,
            Vec::new(),
            bob.kyber1024_pub.clone(),
        );

        let init = pqxdh_initiate(&alice.x25519_priv, &bundle).unwrap();
        assert!(!init.opk_used);

        let msg = PqxdhInitMessage::new(
            init.alice_ik_pub.clone(),
            init.alice_ek_pub.clone(),
            init.kyber_ciphertext.clone(),
            init.opk_used,
        );
        // No OPK private key needed when opk_used is false.
        let bob_secret =
            pqxdh_respond(&msg, &bob.x25519_priv, &spk.to_bytes(), &[], &bob.kyber1024_priv).unwrap();

        assert_eq!(init.shared_secret, bob_secret);
    }
}
