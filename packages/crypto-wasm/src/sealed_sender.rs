// Sealed Sender (docs 4.5). The sender's certificate AND the message envelope
// are encrypted to the recipient's X25519 identity key, so the server-visible
// blob is a version byte, an ephemeral pubkey, a nonce and ciphertext - nothing
// else. (The legacy v1 format encrypted only the certificate and appended the
// envelope in the clear, exposing the PQXDH initiator key - which identifies
// the sender via the public key directory - and the ratchet headers, which
// link messages into threads. v1 is still READ, for senders that haven't
// reloaded yet, but never written.)
//
// Time is passed in (`now_unix`) rather than read from a clock:
// wasm32-unknown-unknown has no clock, and it keeps these functions pure.

use bincode::Options as _;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
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

/// First byte of a v2 sealed blob.
const SEALED_V2: u8 = 0x02;
/// version(1) || eph_pub(32) || nonce(24) - authenticated as associated data.
const V2_HEADER_LEN: usize = 1 + 32 + 24;
const V2_KEY_INFO: &[u8] = b"privex_sealed_sender_v2";
const V1_KEY_INFO: &[u8] = b"sealed_sender";

fn sealed_sender_key(shared: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).expect("hkdf 32");
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
/// MessageEnvelope (ratchet header + ciphertext, and PQXDH init fields on a
/// first message); it is encrypted together with the certificate, so neither
/// the sender nor anything that could identify them or link messages is
/// visible outside.
/// Wire (v2): 0x02 | eph_pub(32) | nonce(24) |
///            XChaCha20-Poly1305(u32le cert_len | cert | message, aad = first 57 bytes)
#[wasm_bindgen]
pub fn sealed_sender_encrypt(
    message: &[u8],
    sender_cert: &[u8],
    recipient_ik_pub: &[u8],
) -> Result<Vec<u8>, JsError> {
    let recipient = XPublicKey::from(to_array::<32>(recipient_ik_pub, "recipient_ik_pub")?);
    let cert_len = u32::try_from(sender_cert.len()).map_err(|_| JsError::new("cert too large"))?;

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let mut key = sealed_sender_key(shared.as_bytes(), V2_KEY_INFO);

    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| JsError::new(&e.to_string()))?;

    let mut header = Vec::with_capacity(V2_HEADER_LEN);
    header.push(SEALED_V2);
    header.extend_from_slice(eph_pub.as_bytes());
    header.extend_from_slice(&nonce);

    let mut inner = Vec::with_capacity(4 + sender_cert.len() + message.len());
    inner.extend_from_slice(&cert_len.to_le_bytes());
    inner.extend_from_slice(sender_cert);
    inner.extend_from_slice(message);

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &header,
            },
        )
        .map_err(|_| JsError::new("seal message"))?;
    key.zeroize();

    let mut blob = header;
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Open a v2 blob to (cert, message). None if it isn't v2 or doesn't
/// authenticate for this recipient - never constructs a JsError, so the legacy
/// fallback below stays reachable.
fn open_v2(blob: &[u8], ik: &StaticSecret) -> Option<(Vec<u8>, Vec<u8>)> {
    if blob.len() < V2_HEADER_LEN + 16 || blob[0] != SEALED_V2 {
        return None;
    }
    let (header, sealed) = blob.split_at(V2_HEADER_LEN);
    let eph_pub: [u8; 32] = header[1..33].try_into().ok()?;
    let shared = ik.diffie_hellman(&XPublicKey::from(eph_pub));
    let mut key = sealed_sender_key(shared.as_bytes(), V2_KEY_INFO);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    let inner = cipher
        .decrypt(
            XNonce::from_slice(&header[33..57]),
            Payload {
                msg: sealed,
                aad: header,
            },
        )
        .ok();
    key.zeroize();
    let inner = inner?;
    let cert_len = u32::from_le_bytes(inner.get(0..4)?.try_into().ok()?) as usize;
    let cert_end = 4usize.checked_add(cert_len)?;
    let cert = inner.get(4..cert_end)?.to_vec();
    Some((cert, inner[cert_end..].to_vec()))
}

/// Open a legacy v1 blob: eph_pub(32) | nonce(24) | u32le cert_len | enc_cert | message.
fn open_v1(blob: &[u8], ik: &StaticSecret) -> Result<(Vec<u8>, Vec<u8>), JsError> {
    if blob.len() < 60 {
        return Err(JsError::new("sealed blob too short"));
    }
    let eph_pub = to_array::<32>(&blob[0..32], "eph_pub")?;
    let nonce = &blob[32..56];
    let cert_len = u32::from_le_bytes([blob[56], blob[57], blob[58], blob[59]]) as usize;
    // Checked: on 32-bit wasm, 60 + a near-u32::MAX length wraps, and the slice
    // below would then panic (a trap that can leave the whole module unusable).
    let cert_end = match 60usize.checked_add(cert_len) {
        Some(end) if end <= blob.len() => end,
        _ => return Err(JsError::new("sealed blob: bad cert length")),
    };
    let enc_cert = &blob[60..cert_end];
    let message = &blob[cert_end..];

    let shared = ik.diffie_hellman(&XPublicKey::from(eph_pub));
    let mut key = sealed_sender_key(shared.as_bytes(), V1_KEY_INFO);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| JsError::new("xchacha key"))?;
    let cert_bytes = cipher.decrypt(XNonce::from_slice(nonce), enc_cert);
    key.zeroize(); // on the failure path too
    let cert_bytes =
        cert_bytes.map_err(|_| JsError::new("open sealed cert (wrong recipient or tampered)"))?;
    Ok((cert_bytes, message.to_vec()))
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
    let ik = StaticSecret::from(to_array::<32>(recipient_ik_priv, "recipient_ik_priv")?);
    // v2 first. A legacy v1 blob whose random eph_pub happens to start with the
    // version byte just fails v2 authentication and opens as v1.
    let (cert_bytes, message) = match open_v2(blob, &ik) {
        Some(opened) => opened,
        None => open_v1(blob, &ik)?,
    };

    let cert = open_cert(&cert_bytes)?;
    // Bind the claimed id to the signing key: px_id MUST be derived from the cert's
    // own ed25519 key, else a real identity could impersonate any px_id.
    let id_ok = cert.sender_id == crate::user_id_from_ed25519(&cert.sender_ed_pub);
    let sender_verified = cert.sig_ok && id_ok && cert.valid_until >= now_unix;

    Ok(SealedDecryptResult {
        plaintext: message,
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

    /// A legacy v1 blob exactly as released clients produced it, with a caller-
    /// chosen ephemeral key: eph_pub | nonce | u32le cert_len | enc_cert | message.
    fn legacy_v1_blob(eph: StaticSecret, message: &[u8], cert: &[u8], recipient: &[u8]) -> Vec<u8> {
        let recipient = XPublicKey::from(to_array::<32>(recipient, "r").unwrap());
        let eph_pub = XPublicKey::from(&eph);
        let key = sealed_sender_key(eph.diffie_hellman(&recipient).as_bytes(), V1_KEY_INFO);
        let nonce = [7u8; 24];
        let enc_cert = XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(XNonce::from_slice(&nonce), cert)
            .unwrap();
        let mut blob = eph_pub.as_bytes().to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&(enc_cert.len() as u32).to_le_bytes());
        blob.extend_from_slice(&enc_cert);
        blob.extend_from_slice(message);
        blob
    }

    #[test]
    fn v2_blob_hides_the_whole_envelope() {
        // A first message's envelope carries the sender's X25519 identity key
        // (PQXDH init) and the ratchet header. None of it may be visible outside.
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let cert = cert_for(
            &alice,
            crate::user_id_from_ed25519(&alice.ed25519_pub),
            1000,
            86_400,
        );
        let mut envelope = b"ratchet-header-marker".to_vec();
        envelope.extend_from_slice(&alice.x25519_pub);

        let blob = sealed_sender_encrypt(&envelope, &cert, &bob.x25519_pub).unwrap();
        assert_eq!(blob[0], SEALED_V2);
        assert!(!contains(&blob, &alice.x25519_pub), "initiator key exposed");
        assert!(
            !contains(&blob, b"ratchet-header-marker"),
            "envelope exposed"
        );
        assert!(!contains(&blob, &cert[..64]), "certificate exposed");

        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.plaintext, envelope);
        assert!(res.sender_verified);
    }

    #[test]
    fn legacy_v1_blob_still_opens() {
        // Senders that haven't reloaded still send v1 during the rollout.
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let cert = legacy_v1_cert(&alice, 1000, 86_400);
        let blob = legacy_v1_blob(
            StaticSecret::random_from_rng(OsRng),
            b"legacy envelope",
            &cert,
            &bob.x25519_pub,
        );
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.plaintext, b"legacy envelope");
        assert!(res.sender_verified);
    }

    #[test]
    fn legacy_v1_blob_starting_with_the_version_byte_still_opens() {
        // ~1 in 256 v1 blobs have an eph_pub whose first byte equals SEALED_V2.
        // The v2 attempt fails authentication and the blob opens as v1.
        let alice = generate_identity_keypairs().unwrap();
        let bob = generate_identity_keypairs().unwrap();
        let eph = loop {
            let e = StaticSecret::random_from_rng(OsRng);
            if XPublicKey::from(&e).as_bytes()[0] == SEALED_V2 {
                break e;
            }
        };
        let cert = legacy_v1_cert(&alice, 1000, 86_400);
        let blob = legacy_v1_blob(eph, b"ambiguous first byte", &cert, &bob.x25519_pub);
        assert_eq!(blob[0], SEALED_V2);
        let res = sealed_sender_decrypt(&blob, &bob.x25519_priv, 2000).unwrap();
        assert_eq!(res.plaintext, b"ambiguous first byte");
        assert!(res.sender_verified);
    }

    // wrong-recipient and tampering (Err paths) are covered in the Node
    // integration test - JsError can't be constructed on a non-wasm host target.
}
