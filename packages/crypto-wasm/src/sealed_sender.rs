// Sealed Sender (docs 4.5). The sender's certificate is encrypted to the
// recipient's X25519 identity key, so the server-visible wrapper carries no
// sender identity - only an ephemeral pubkey, the sealed cert, and the message.
//
// Time is passed in (`now_unix`) rather than read from a clock:
// wasm32-unknown-unknown has no clock, and it keeps these functions pure.

use bincode::Options as _;
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

/// v1 (legacy) certificate. Still accepted from not-yet-updated senders, but it
/// binds NO X25519 key, so it can never authenticate a PQXDH handshake.
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

/// v2 certificate: also binds the sender's X25519 identity key - the key PQXDH
/// authenticates the sender with (DH1). A certificate is reused for 24 h across
/// every recipient, so without this binding anyone who ever received one could
/// attach it to their OWN handshake and be accepted as the sender. With it, a
/// replayed certificate forces the attacker to use the real sender's X25519 key,
/// whose private half they lack, so the handshake cannot decrypt. Authentication
/// stays implicit (deniable, as in X3DH): nothing is signed per recipient.
///
/// The new field is LAST so an app that hasn't updated yet, parsing this as v1,
/// reads the original fields unchanged and simply fails signature verification.
#[derive(Serialize, Deserialize)]
struct SenderCertificateV2 {
    sender_id: String,
    sender_ed_pub: Vec<u8>,
    sender_dil_pub: Vec<u8>,
    valid_until: u64, // unix seconds
    sender_x25519_pub: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SignedSenderCertV2 {
    cert: SenderCertificateV2,
    sig_ed: Vec<u8>,
    sig_dil: Vec<u8>,
}

/// Domain tag for v2 signatures, so a v1 and a v2 signature can never be
/// mistaken for one another.
const CERT_V2_CONTEXT: &[u8] = b"privex-sender-cert-v2";

/// The byte encoding bincode::serialize has always used (fixed-width ints,
/// little-endian), but parsing is EXACT-length: a v1 certificate is too short to
/// parse as v2, and a v2 certificate has trailing bytes as v1.
fn bin() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn v2_signing_input(cert: &SenderCertificateV2) -> Result<Vec<u8>, JsError> {
    let mut msg = CERT_V2_CONTEXT.to_vec();
    msg.extend(
        bin()
            .serialize(cert)
            .map_err(|e| JsError::new(&e.to_string()))?,
    );
    Ok(msg)
}

fn sealed_sender_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(b"sealed_sender", &mut key).expect("hkdf 32");
    key
}

/// Build a signed (v2) sender certificate (docs 4.5 step 1), binding the
/// sender's X25519 identity key alongside the signing keys.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn generate_sender_cert(
    sender_id: String,
    ed_priv: &[u8],
    ed_pub: &[u8],
    dil_priv: &[u8],
    dil_pub: &[u8],
    x25519_pub: &[u8],
    now_unix: u64,
    valid_seconds: u64,
) -> Result<Vec<u8>, JsError> {
    let x25519_pub = to_array::<32>(x25519_pub, "x25519_pub")?;
    let cert = SenderCertificateV2 {
        sender_id,
        sender_ed_pub: ed_pub.to_vec(),
        sender_dil_pub: dil_pub.to_vec(),
        valid_until: now_unix + valid_seconds,
        sender_x25519_pub: x25519_pub.to_vec(),
    };
    let (sig_ed, sig_dil) = sign_raw(&v2_signing_input(&cert)?, ed_priv, dil_priv)?;

    bin()
        .serialize(&SignedSenderCertV2 {
            cert,
            sig_ed,
            sig_dil,
        })
        .map_err(|e| JsError::new(&e.to_string()))
}

/// A parsed certificate and whether its signatures verify (expiry and the
/// px_id binding are checked by the caller).
struct OpenedCert {
    sender_id: String,
    sender_ed_pub: Vec<u8>,
    /// Empty for a legacy v1 certificate (no X25519 binding).
    sender_x25519_pub: Vec<u8>,
    valid_until: u64,
    sig_ok: bool,
}

fn open_cert(cert_bytes: &[u8]) -> Result<OpenedCert, JsError> {
    if let Ok(s) = bin().deserialize::<SignedSenderCertV2>(cert_bytes) {
        let sig_ok = s.cert.sender_x25519_pub.len() == 32
            && verify_raw(
                &v2_signing_input(&s.cert)?,
                &s.sig_ed,
                &s.cert.sender_ed_pub,
                &s.sig_dil,
                &s.cert.sender_dil_pub,
            );
        return Ok(OpenedCert {
            sender_id: s.cert.sender_id,
            sender_ed_pub: s.cert.sender_ed_pub,
            sender_x25519_pub: s.cert.sender_x25519_pub,
            valid_until: s.cert.valid_until,
            sig_ok,
        });
    }
    // Legacy v1 from a sender that hasn't updated yet.
    let s: SignedSenderCert = bin()
        .deserialize(cert_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let msg = bin()
        .serialize(&s.cert)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig_ok = verify_raw(
        &msg,
        &s.sig_ed,
        &s.cert.sender_ed_pub,
        &s.sig_dil,
        &s.cert.sender_dil_pub,
    );
    Ok(OpenedCert {
        sender_id: s.cert.sender_id,
        sender_ed_pub: s.cert.sender_ed_pub,
        sender_x25519_pub: Vec::new(),
        valid_until: s.cert.valid_until,
        sig_ok,
    })
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
    /// The X25519 identity key the (v2) certificate binds; empty for a legacy v1
    /// certificate. A PQXDH handshake is authentic only when its initiator key
    /// equals this AND sender_verified is true.
    pub sender_x25519_pub: Vec<u8>,
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

    let cert = open_cert(&cert_bytes)?;
    // Bind the claimed id to the signing key: px_id MUST be derived from the cert's
    // own ed25519 key, else a real identity could impersonate any px_id.
    let id_ok = cert.sender_id == crate::user_id_from_ed25519(&cert.sender_ed_pub);
    let sender_verified = cert.sig_ok && id_ok && cert.valid_until >= now_unix;

    Ok(SealedDecryptResult {
        plaintext: message.to_vec(),
        sender_id: cert.sender_id,
        sender_ed_pub: cert.sender_ed_pub,
        sender_x25519_pub: cert.sender_x25519_pub,
        sender_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_identity_keypairs;
    use crate::IdentityKeypairs;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn cert_for(k: &IdentityKeypairs, sender_id: String, now: u64, valid: u64) -> Vec<u8> {
        generate_sender_cert(
            sender_id,
            &k.ed25519_priv,
            &k.ed25519_pub,
            &k.dilithium3_priv,
            &k.dilithium3_pub,
            &k.x25519_pub,
            now,
            valid,
        )
        .unwrap()
    }

    /// A legacy v1 certificate exactly as released clients produced it.
    fn legacy_v1_cert(k: &IdentityKeypairs, now: u64, valid: u64) -> Vec<u8> {
        let cert = SenderCertificate {
            sender_id: crate::user_id_from_ed25519(&k.ed25519_pub),
            sender_ed_pub: k.ed25519_pub.clone(),
            sender_dil_pub: k.dilithium3_pub.clone(),
            valid_until: now + valid,
        };
        let cert_bytes = bincode::serialize(&cert).unwrap();
        let (sig_ed, sig_dil) = sign_raw(&cert_bytes, &k.ed25519_priv, &k.dilithium3_priv).unwrap();
        bincode::serialize(&SignedSenderCert {
            cert,
            sig_ed,
            sig_dil,
        })
        .unwrap()
    }

    #[test]
    fn sealed_sender_roundtrip_and_no_identity_leak() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        // The sender_id MUST be the px_id derived from the cert's own ed key.
        let sender_id = crate::user_id_from_ed25519(&alice.ed25519_pub);

        let cert = cert_for(&alice, sender_id.clone(), 1000, 86_400);

        let message = b"this is a ratchet ciphertext stand-in";
        let blob = sealed_sender_encrypt(message, &cert, &bob.x25519_pub).unwrap();

        // The sender id must NOT appear in the outer wrapper.
        assert!(!contains(&blob, sender_id.as_bytes()));

        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.plaintext, message);
        assert_eq!(res.sender_id, sender_id);
        assert_eq!(res.sender_ed_pub, alice.ed25519_pub);
        // v2 binds the sender's X25519 identity key.
        assert_eq!(res.sender_x25519_pub, alice.x25519_pub);
        assert!(res.sender_verified);
    }

    #[test]
    fn forged_sender_id_is_not_verified() {
        // A real identity signs a cert claiming SOMEONE ELSE'S px_id. Sigs are
        // valid, but the id is not derived from the signing key → not verified.
        let attacker = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let victim_id = "px_victim0000000000000000000000a".to_string();

        let cert = cert_for(&attacker, victim_id.clone(), 1000, 86_400);
        let blob = sealed_sender_encrypt(b"spoof", &cert, &bob.x25519_pub).unwrap();
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.sender_id, victim_id);
        assert!(!res.sender_verified); // id not bound to the signing key
    }

    #[test]
    fn expired_cert_is_not_verified() {
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();

        let cert = cert_for(
            &alice,
            crate::user_id_from_ed25519(&alice.ed25519_pub),
            1000,
            100,
        );
        let blob = sealed_sender_encrypt(b"m", &cert, &bob.x25519_pub).unwrap();

        // now past valid_until (1000 + 100)
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 5000).unwrap();
        assert!(!res.sender_verified);
    }

    #[test]
    fn tampered_x25519_binding_is_not_verified() {
        // Swap the bound X25519 key for the attacker's own inside Alice's signed
        // v2 cert: the signature covers it, so verification must fail.
        let alice = generate_identity_keypairs().unwrap();
        let mallory = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let cert = cert_for(
            &alice,
            crate::user_id_from_ed25519(&alice.ed25519_pub),
            1000,
            86_400,
        );
        let mut signed: SignedSenderCertV2 = bin().deserialize(&cert).unwrap();
        signed.cert.sender_x25519_pub = mallory.x25519_pub.clone();
        let tampered = bin().serialize(&signed).unwrap();

        let blob = sealed_sender_encrypt(b"m", &tampered, &bob.x25519_pub).unwrap();
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.sender_x25519_pub, mallory.x25519_pub);
        assert!(!res.sender_verified);
    }

    #[test]
    fn legacy_v1_cert_verifies_but_binds_no_x25519() {
        // A not-yet-updated sender: still verified (so existing-session messages
        // keep flowing), but it can never authenticate a handshake.
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let cert = legacy_v1_cert(&alice, 1000, 86_400);
        let blob = sealed_sender_encrypt(b"m", &cert, &bob.x25519_pub).unwrap();
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert!(res.sender_verified);
        assert!(res.sender_x25519_pub.is_empty());
        assert_eq!(res.sender_ed_pub, alice.ed25519_pub);
    }

    #[test]
    fn versions_never_parse_as_each_other() {
        let alice = generate_identity_keypairs().unwrap();
        let id = crate::user_id_from_ed25519(&alice.ed25519_pub);
        let v1 = legacy_v1_cert(&alice, 1000, 86_400);
        let v2 = cert_for(&alice, id, 1000, 86_400);
        assert!(bin().deserialize::<SignedSenderCertV2>(&v1).is_err());
        assert!(bin().deserialize::<SignedSenderCert>(&v2).is_err());
    }

    #[test]
    fn released_app_reading_v2_parses_it_but_does_not_verify_it() {
        // What an app that hasn't reloaded yet does with a v2 cert: its lenient
        // bincode::deserialize (trailing bytes allowed) still parses it, so the
        // message is delivered, but the signatures can't check out - it shows as
        // "unverified" rather than being trusted or lost.
        let alice = generate_identity_keypairs().unwrap();
        let id = crate::user_id_from_ed25519(&alice.ed25519_pub);
        let v2 = cert_for(&alice, id.clone(), 1000, 86_400);
        let old: SignedSenderCert = bincode::deserialize(&v2).unwrap();
        assert_eq!(old.cert.sender_id, id);
        let msg = bincode::serialize(&old.cert).unwrap();
        assert!(!verify_raw(
            &msg,
            &old.sig_ed,
            &old.cert.sender_ed_pub,
            &old.sig_dil,
            &old.cert.sender_dil_pub,
        ));
    }

    // wrong-recipient (an Err path) is covered in the Node integration test -
    // JsError can't be constructed on a non-wasm host target.
}
