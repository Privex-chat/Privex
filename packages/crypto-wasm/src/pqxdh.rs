// PQXDH key agreement (docs 4.3): X3DH over X25519 + ML-KEM-1024 (Kyber)
// encapsulation. The DH "identity key" is the X25519 identity key from
// generate_identity_keypairs (signing stays with Ed25519).

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use rand_core::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, SerDes};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::identity::to_array;

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf-sha256 expand 32 bytes");
    okm
}

/// Bob's public prekey bundle, as Alice fetches it from the key directory.
#[wasm_bindgen]
pub struct PreKeyBundle {
    ik_x25519_pub: Vec<u8>,
    spk_x25519_pub: Vec<u8>,
    opk_x25519_pub: Vec<u8>,
    kyber1024_pub: Vec<u8>,
}

#[wasm_bindgen]
impl PreKeyBundle {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ik_x25519_pub: Vec<u8>,
        spk_x25519_pub: Vec<u8>,
        opk_x25519_pub: Vec<u8>,
        kyber1024_pub: Vec<u8>,
    ) -> PreKeyBundle {
        PreKeyBundle {
            ik_x25519_pub,
            spk_x25519_pub,
            opk_x25519_pub,
            kyber1024_pub,
        }
    }
}

/// The initial message Alice sends Bob so he can derive the same secret.
/// `opk_used` tells Bob whether Alice's bundle included a one-time prekey, so he
/// uses the matching 3- or 4-DH path. (Which OPK - the opk_id - is carried at the
/// app layer; Bob maps it to the right private key before calling respond.)
#[wasm_bindgen]
pub struct PqxdhInitMessage {
    alice_ik_pub: Vec<u8>,
    alice_ek_pub: Vec<u8>,
    kyber_ciphertext: Vec<u8>,
    opk_used: bool,
}

#[wasm_bindgen]
impl PqxdhInitMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        alice_ik_pub: Vec<u8>,
        alice_ek_pub: Vec<u8>,
        kyber_ciphertext: Vec<u8>,
        opk_used: bool,
    ) -> PqxdhInitMessage {
        PqxdhInitMessage {
            alice_ik_pub,
            alice_ek_pub,
            kyber_ciphertext,
            opk_used,
        }
    }
}

/// Result of initiating: the shared secret (kept by Alice) plus the wire fields
/// to send to Bob (his `PqxdhInitMessage`).
#[wasm_bindgen(getter_with_clone)]
pub struct PqxdhInitResult {
    pub shared_secret: Vec<u8>,
    pub alice_ik_pub: Vec<u8>,
    pub alice_ek_pub: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    /// True iff the fetched bundle carried a one-time prekey (4-DH). When the
    /// server's OPK supply is drained it returns none → 3-DH (still secure;
    /// docs 4.3 / X3DH: OPK is optional). Echo this into the init message.
    pub opk_used: bool,
}

/// Alice initiates against Bob's bundle (docs 4.3 initiator + Kyber encapsulate).
#[wasm_bindgen]
pub fn pqxdh_initiate(
    my_ik_x25519_priv: &[u8],
    bundle: &PreKeyBundle,
) -> Result<PqxdhInitResult, JsError> {
    let ik_a = StaticSecret::from(to_array::<32>(my_ik_x25519_priv, "ik_priv")?);
    let ik_a_pub = XPublicKey::from(&ik_a);
    let ek_a = StaticSecret::random_from_rng(OsRng);
    let ek_a_pub = XPublicKey::from(&ek_a);

    let ik_b = XPublicKey::from(to_array::<32>(&bundle.ik_x25519_pub, "ik_b")?);
    let spk_b = XPublicKey::from(to_array::<32>(&bundle.spk_x25519_pub, "spk_b")?);

    let dh1 = ik_a.diffie_hellman(&spk_b);
    let dh2 = ek_a.diffie_hellman(&ik_b);
    let dh3 = ek_a.diffie_hellman(&spk_b);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // OPK is optional (X3DH): an empty opk in the bundle means the server's OPK
    // supply was drained → drop DH4. Bob must take the matching path (opk_used).
    let opk_used = !bundle.opk_x25519_pub.is_empty();
    if opk_used {
        let opk_b = XPublicKey::from(to_array::<32>(&bundle.opk_x25519_pub, "opk_b")?);
        ikm.extend_from_slice(ek_a.diffie_hellman(&opk_b).as_bytes());
    }
    let x3dh_secret = hkdf32(&ikm, b"PQXDH_v1");
    ikm.zeroize();

    // Kyber: encapsulate to Bob's KEM public key.
    let kem_pub = ml_kem_1024::EncapsKey::try_from_bytes(
        bundle
            .kyber1024_pub
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("kyber1024_pub: wrong length"))?,
    )
    .map_err(JsError::new)?;
    let (ssk, ct) = kem_pub.try_encaps().map_err(JsError::new)?;
    let kyber_secret = ssk.into_bytes();
    let kyber_ciphertext = ct.into_bytes().to_vec();

    let mut final_ikm = Vec::with_capacity(64);
    final_ikm.extend_from_slice(&x3dh_secret);
    final_ikm.extend_from_slice(&kyber_secret);
    let shared = hkdf32(&final_ikm, b"PQXDH_v1_final");
    final_ikm.zeroize();

    Ok(PqxdhInitResult {
        shared_secret: shared.to_vec(),
        alice_ik_pub: ik_a_pub.to_bytes().to_vec(),
        alice_ek_pub: ek_a_pub.to_bytes().to_vec(),
        kyber_ciphertext,
        opk_used,
    })
}

/// Bob responds (docs 4.3 responder + Kyber decapsulate). Returns the shared
/// secret, which must equal Alice's.
#[wasm_bindgen]
pub fn pqxdh_respond(
    msg: &PqxdhInitMessage,
    my_ik_x25519_priv: &[u8],
    my_spk_x25519_priv: &[u8],
    my_opk_x25519_priv: &[u8],
    my_kyber_priv: &[u8],
) -> Result<Vec<u8>, JsError> {
    let ik_a_pub = XPublicKey::from(to_array::<32>(&msg.alice_ik_pub, "alice_ik")?);
    let ek_a_pub = XPublicKey::from(to_array::<32>(&msg.alice_ek_pub, "alice_ek")?);

    let ik_b = StaticSecret::from(to_array::<32>(my_ik_x25519_priv, "ik_priv")?);
    let spk_b = StaticSecret::from(to_array::<32>(my_spk_x25519_priv, "spk_priv")?);

    let dh1 = spk_b.diffie_hellman(&ik_a_pub);
    let dh2 = ik_b.diffie_hellman(&ek_a_pub);
    let dh3 = spk_b.diffie_hellman(&ek_a_pub);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    // Match Alice's path: when she used an OPK, fold in DH4 with our OPK private
    // key. When she didn't (drained supply), `my_opk_x25519_priv` is ignored and
    // may be empty.
    if msg.opk_used {
        let opk_b = StaticSecret::from(to_array::<32>(my_opk_x25519_priv, "opk_priv")?);
        ikm.extend_from_slice(opk_b.diffie_hellman(&ek_a_pub).as_bytes());
    }
    let x3dh_secret = hkdf32(&ikm, b"PQXDH_v1");
    ikm.zeroize();

    // Kyber: decapsulate with Bob's KEM private key.
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(
        my_kyber_priv
            .try_into()
            .map_err(|_| JsError::new("kyber priv: wrong length"))?,
    )
    .map_err(JsError::new)?;
    let ct = ml_kem_1024::CipherText::try_from_bytes(
        msg.kyber_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("kyber ciphertext: wrong length"))?,
    )
    .map_err(JsError::new)?;
    let ssk = dk.try_decaps(&ct).map_err(JsError::new)?;
    let kyber_secret = ssk.into_bytes();

    let mut final_ikm = Vec::with_capacity(64);
    final_ikm.extend_from_slice(&x3dh_secret);
    final_ikm.extend_from_slice(&kyber_secret);
    let shared = hkdf32(&final_ikm, b"PQXDH_v1_final");
    final_ikm.zeroize();

    Ok(shared.to_vec())
}
