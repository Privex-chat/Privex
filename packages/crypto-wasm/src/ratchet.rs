// Double Ratchet (docs 4.4), assembled from audited primitives (X25519 + HKDF +
// AES-256-GCM). Per-message keys, forward secrecy, break-in recovery, and
// out-of-order delivery via skipped message keys.
//
// Session state crosses the wasm boundary as bincode bytes so the caller can
// store it (encrypted) in IndexedDB. Each call takes the old state and returns
// a new one - no hidden mutable state in the module.
//
// ponytail: the doc's separate HMAC `mac` field is replaced by AES-GCM with the
// message header as AAD - the GCM tag authenticates header+ciphertext in one
// shot. Equivalent security, less code.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::to_array;

const MAX_SKIP: u32 = 1000; // ponytail: cap skipped keys to bound DoS memory
const PAD_BLOCK: usize = 1024;

#[derive(Serialize, Deserialize, Clone)]
struct SessionState {
    rk: [u8; 32],
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr_pub: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: BTreeMap<(Vec<u8>, u32), [u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    dh_pub: [u8; 32],
    pn: u32,
    n: u32,
}

// --- KDFs (docs 4.4) ---

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"PrivexRootKDF", &mut okm).expect("hkdf 64");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, ck)
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, ck);
    let mut next_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    hk.expand(b"chain_adv", &mut next_ck).expect("hkdf 32");
    hk.expand(b"msg_key", &mut mk).expect("hkdf 32");
    (next_ck, mk)
}

fn msg_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut okm = [0u8; 44];
    hk.expand(b"PrivexMsgKeys", &mut okm).expect("hkdf 44");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, nonce)
}

fn dh(priv32: &[u8; 32], pub32: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv32);
    let public = XPublicKey::from(*pub32);
    *secret.diffie_hellman(&public).as_bytes()
}

// --- padding (docs 4.4: pad to 1024-byte boundary before encryption) ---

fn pad(plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let content_len = 4 + plaintext.len();
    let target = content_len.div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    let mut padding = vec![0u8; target - content_len];
    getrandom::getrandom(&mut padding).map_err(|e| JsError::new(&e.to_string()))?;
    out.extend_from_slice(&padding);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, JsError> {
    if padded.len() < 4 {
        return Err(JsError::new("padded message too short"));
    }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if 4 + len > padded.len() {
        return Err(JsError::new("invalid pad length"));
    }
    Ok(padded[4..4 + len].to_vec())
}

// --- AEAD ---

fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| JsError::new("aes key"))?;
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| JsError::new("aes-gcm encrypt"))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| JsError::new("aes key"))?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| JsError::new("aes-gcm decrypt/auth failed"))
}

fn decrypt_with(mk: &[u8; 32], ct: &[u8], header_aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let (mut key, nonce) = msg_keys(mk);
    let padded = aes_decrypt(&key, &nonce, ct, header_aad)?;
    key.zeroize();
    unpad(&padded)
}

fn ser(st: &SessionState) -> Result<Vec<u8>, JsError> {
    bincode::serialize(st).map_err(|e| JsError::new(&e.to_string()))
}
fn de(bytes: &[u8]) -> Result<SessionState, JsError> {
    bincode::deserialize(bytes).map_err(|e| JsError::new(&e.to_string()))
}

// --- session init from a PQXDH shared secret (docs 4.3 → 4.4 handoff) ---

/// Initiator (Alice): she already knows Bob's ratchet public (his signed prekey).
#[wasm_bindgen]
pub fn ratchet_init_alice(shared_secret: &[u8], bob_ratchet_pub: &[u8]) -> Result<Vec<u8>, JsError> {
    let rk0 = to_array::<32>(shared_secret, "shared_secret")?;
    let dhr = to_array::<32>(bob_ratchet_pub, "bob_ratchet_pub")?;

    let dhs_secret = StaticSecret::random_from_rng(OsRng);
    let dhs_priv = dhs_secret.to_bytes();
    let dhs_pub = XPublicKey::from(&dhs_secret).to_bytes();

    let (rk, cks) = kdf_rk(&rk0, &dh(&dhs_priv, &dhr));

    ser(&SessionState {
        rk,
        dhs_priv,
        dhs_pub,
        dhr_pub: Some(dhr),
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: BTreeMap::new(),
    })
}

/// Responder (Bob): his ratchet keypair is the signed prekey Alice used.
#[wasm_bindgen]
pub fn ratchet_init_bob(
    shared_secret: &[u8],
    bob_ratchet_priv: &[u8],
    bob_ratchet_pub: &[u8],
) -> Result<Vec<u8>, JsError> {
    let rk0 = to_array::<32>(shared_secret, "shared_secret")?;
    let dhs_priv = to_array::<32>(bob_ratchet_priv, "bob_ratchet_priv")?;
    let dhs_pub = to_array::<32>(bob_ratchet_pub, "bob_ratchet_pub")?;

    ser(&SessionState {
        rk: rk0,
        dhs_priv,
        dhs_pub,
        dhr_pub: None,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: BTreeMap::new(),
    })
}

// --- encrypt ---

#[wasm_bindgen(getter_with_clone)]
pub struct RatchetResult {
    pub ciphertext: Vec<u8>,
    pub new_session_state: Vec<u8>,
    pub message_header: Vec<u8>,
}

#[wasm_bindgen]
pub fn ratchet_encrypt(session_state: &[u8], plaintext: &[u8]) -> Result<RatchetResult, JsError> {
    let mut st = de(session_state)?;
    let cks = st
        .cks
        .ok_or_else(|| JsError::new("no sending chain - initialize the session first"))?;

    let (next_ck, mut mk) = kdf_ck(&cks);
    st.cks = Some(next_ck);

    let header = Header {
        dh_pub: st.dhs_pub,
        pn: st.pn,
        n: st.ns,
    };
    st.ns += 1;
    let header_bytes = bincode::serialize(&header).map_err(|e| JsError::new(&e.to_string()))?;

    let mut padded = pad(plaintext)?;
    let (mut key, nonce) = msg_keys(&mk);
    let ciphertext = aes_encrypt(&key, &nonce, &padded, &header_bytes)?;
    key.zeroize();
    mk.zeroize();
    padded.zeroize();

    Ok(RatchetResult {
        ciphertext,
        new_session_state: ser(&st)?,
        message_header: header_bytes,
    })
}

// --- decrypt ---

#[wasm_bindgen(getter_with_clone)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub new_session_state: Vec<u8>,
}

#[wasm_bindgen]
pub fn ratchet_decrypt(
    session_state: &[u8],
    ciphertext: &[u8],
    message_header: &[u8],
) -> Result<DecryptResult, JsError> {
    let mut st = de(session_state)?;
    let header: Header =
        bincode::deserialize(message_header).map_err(|e| JsError::new(&e.to_string()))?;

    // 1. A skipped (out-of-order) message we already derived a key for.
    if let Some(mut mk) = st.skipped.remove(&(header.dh_pub.to_vec(), header.n)) {
        let plaintext = decrypt_with(&mk, ciphertext, message_header)?;
        mk.zeroize();
        return Ok(DecryptResult {
            plaintext,
            new_session_state: ser(&st)?,
        });
    }

    // 2. New ratchet key → flush the old receiving chain, then DH-ratchet.
    let is_new = match st.dhr_pub {
        Some(d) => d != header.dh_pub,
        None => true,
    };
    if is_new {
        skip_recv(&mut st, header.pn)?;
        dh_ratchet(&mut st, &header);
    }

    // 3. Skip forward within the current chain to this message number.
    skip_recv(&mut st, header.n)?;

    // 4. Derive this message's key and decrypt.
    let ckr = st
        .ckr
        .ok_or_else(|| JsError::new("no receiving chain"))?;
    let (next_ck, mut mk) = kdf_ck(&ckr);
    st.ckr = Some(next_ck);
    st.nr += 1;
    let plaintext = decrypt_with(&mk, ciphertext, message_header)?;
    mk.zeroize();

    Ok(DecryptResult {
        plaintext,
        new_session_state: ser(&st)?,
    })
}

fn skip_recv(st: &mut SessionState, until: u32) -> Result<(), JsError> {
    match st.ckr {
        Some(mut ckr) => {
            if until > st.nr.saturating_add(MAX_SKIP) {
                return Err(JsError::new("too many skipped messages"));
            }
            while st.nr < until {
                let (next_ck, mk) = kdf_ck(&ckr);
                ckr = next_ck;
                if let Some(d) = st.dhr_pub {
                    st.skipped.insert((d.to_vec(), st.nr), mk);
                }
                st.nr += 1;
            }
            st.ckr = Some(ckr);
            Ok(())
        }
        None if until > st.nr => Err(JsError::new("cannot skip without a receiving chain")),
        None => Ok(()),
    }
}

fn dh_ratchet(st: &mut SessionState, header: &Header) {
    st.pn = st.ns;
    st.ns = 0;
    st.nr = 0;
    st.dhr_pub = Some(header.dh_pub);

    let (rk1, ckr) = kdf_rk(&st.rk, &dh(&st.dhs_priv, &header.dh_pub));
    st.rk = rk1;
    st.ckr = Some(ckr);

    let new_secret = StaticSecret::random_from_rng(OsRng);
    st.dhs_priv = new_secret.to_bytes();
    st.dhs_pub = XPublicKey::from(&new_secret).to_bytes();

    let (rk2, cks) = kdf_rk(&st.rk, &dh(&st.dhs_priv, &header.dh_pub));
    st.rk = rk2;
    st.cks = Some(cks);
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fresh session pair sharing a fixed secret + Bob ratchet keypair.
    fn pair() -> (Vec<u8>, Vec<u8>) {
        let shared = [7u8; 32];
        let bob_ratchet = StaticSecret::random_from_rng(OsRng);
        let bob_priv = bob_ratchet.to_bytes();
        let bob_pub = XPublicKey::from(&bob_ratchet).to_bytes();
        let alice = ratchet_init_alice(&shared, &bob_pub).unwrap();
        let bob = ratchet_init_bob(&shared, &bob_priv, &bob_pub).unwrap();
        (alice, bob)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut alice, mut bob) = pair();

        let r = ratchet_encrypt(&alice, b"hello bob").unwrap();
        alice = r.new_session_state;
        let d = ratchet_decrypt(&bob, &r.ciphertext, &r.message_header).unwrap();
        bob = d.new_session_state;
        assert_eq!(d.plaintext, b"hello bob");

        // Bob replies (exercises the receiver→sender DH ratchet).
        let r2 = ratchet_encrypt(&bob, b"hi alice").unwrap();
        let d2 = ratchet_decrypt(&alice, &r2.ciphertext, &r2.message_header).unwrap();
        assert_eq!(d2.plaintext, b"hi alice");
    }

    #[test]
    fn padding_is_1024_boundary() {
        let (alice, _bob) = pair();
        let r = ratchet_encrypt(&alice, b"x").unwrap(); // 1-byte message
        // padded plaintext is exactly 1024; GCM adds a 16-byte tag.
        assert_eq!(r.ciphertext.len(), 1024 + 16);
        assert_eq!((r.ciphertext.len() - 16) % 1024, 0);
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = pair();

        let m1 = ratchet_encrypt(&alice, b"one").unwrap();
        alice = m1.new_session_state;
        let m2 = ratchet_encrypt(&alice, b"two").unwrap();
        alice = m2.new_session_state;
        let m3 = ratchet_encrypt(&alice, b"three").unwrap();

        // Deliver out of order: 1, 3, then 2.
        let d1 = ratchet_decrypt(&bob, &m1.ciphertext, &m1.message_header).unwrap();
        bob = d1.new_session_state;
        assert_eq!(d1.plaintext, b"one");

        let d3 = ratchet_decrypt(&bob, &m3.ciphertext, &m3.message_header).unwrap();
        bob = d3.new_session_state;
        assert_eq!(d3.plaintext, b"three");

        let d2 = ratchet_decrypt(&bob, &m2.ciphertext, &m2.message_header).unwrap();
        assert_eq!(d2.plaintext, b"two"); // recovered from a skipped key
    }

    #[test]
    fn state_survives_serialize_reload() {
        // The API already passes state as bytes; simulate IndexedDB store/reload
        // by cloning the Vec between calls.
        let (alice, bob) = pair();
        let r = ratchet_encrypt(&alice, b"persisted").unwrap();
        let reloaded_bob = bob.clone();
        let d = ratchet_decrypt(&reloaded_bob, &r.ciphertext, &r.message_header).unwrap();
        assert_eq!(d.plaintext, b"persisted");
    }
}
