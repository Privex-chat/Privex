// OPAQUE password recovery (docs 4.2 / 6.1). The password never leaves WASM as
// a hash or derivative - JS passes the raw password the user typed (which it
// already has) and receives only OPAQUE protocol messages + an encrypted
// envelope. The export_key derived inside OPAQUE wraps the user's key bundle.
//
// Key-stretching function is Argon2id (Argon2::default()), via opaque-ke's
// "argon2" feature - offline-dictionary resistance per docs 6.1.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};

type HmacSha256 = Hmac<Sha256>;

/// Privex OPAQUE cipher suite: Ristretto255 OPRF + Triple-DH key exchange.
pub(crate) struct PrivexCipherSuite;
impl opaque_ke::CipherSuite for PrivexCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = argon2::Argon2<'static>;
}

// --- envelope: wrap the key bundle with the OPAQUE export_key ---

fn derive_envelope_keys(export_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, export_key);
    let mut enc_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    hk.expand(b"privex_envelope_enc", &mut enc_key).expect("hkdf 32");
    hk.expand(b"privex_envelope_auth", &mut auth_key).expect("hkdf 32");
    (enc_key, auth_key)
}

fn wrap_envelope(export_key: &[u8], key_material: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (enc_key, auth_key) = derive_envelope_keys(export_key);
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&enc_key).map_err(|_| "aes key".to_string())?;
    let ct = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), key_material)
        .map_err(|_| "envelope encrypt".to_string())?;

    let mut envelope = nonce.to_vec();
    envelope.extend_from_slice(&ct);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("hmac key");
    mac.update(&envelope);
    let tag = mac.finalize().into_bytes().to_vec();
    Ok((envelope, tag))
}

fn unwrap_envelope(export_key: &[u8], envelope: &[u8], mac: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.len() < 12 {
        return Err("envelope too short".into());
    }
    let (enc_key, auth_key) = derive_envelope_keys(export_key);

    let mut verifier = <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("hmac key");
    verifier.update(envelope);
    verifier
        .verify_slice(mac)
        .map_err(|_| "envelope MAC mismatch".to_string())?;

    let (nonce, ct) = envelope.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&enc_key).map_err(|_| "aes key".to_string())?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ct)
        .map_err(|_| "envelope decrypt".to_string())
}

/// The login server response bundles the OPAQUE credential response with the
/// stored envelope (docs 11 /recovery/opaque/init returns both).
#[derive(Serialize, Deserialize)]
pub(crate) struct LoginServerResponse {
    pub credential_response: Vec<u8>,
    pub envelope: Vec<u8>,
    pub envelope_mac: Vec<u8>,
}

// --- core client logic (host-testable: String errors, no wasm types) ---

pub(crate) fn register_start_core(password: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let result = ClientRegistration::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok((
        result.message.serialize().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

pub(crate) fn register_finish_core(
    client_state: &[u8],
    server_response: &[u8],
    key_material: &[u8],
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let state =
        ClientRegistration::<PrivexCipherSuite>::deserialize(client_state).map_err(|e| e.to_string())?;
    let response =
        RegistrationResponse::<PrivexCipherSuite>::deserialize(server_response).map_err(|e| e.to_string())?;

    let result = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| e.to_string())?;

    let (envelope, envelope_mac) = wrap_envelope(&result.export_key, key_material)?;
    Ok((envelope, envelope_mac, result.message.serialize().to_vec()))
}

pub(crate) fn login_start_core(password: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let result =
        ClientLogin::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).map_err(|e| e.to_string())?;
    Ok((
        result.message.serialize().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

/// Returns (key_material, session_key, finalization). `finalization` is the
/// OPAQUE KE3 message - the client MUST send it to the server's
/// /recovery/opaque/complete so the server can verify the login (via
/// ServerLogin::finish) and issue a session token.
pub(crate) fn login_finish_core(
    client_state: &[u8],
    server_response: &[u8],
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let parsed: LoginServerResponse =
        bincode::deserialize(server_response).map_err(|e| e.to_string())?;
    let response = CredentialResponse::<PrivexCipherSuite>::deserialize(&parsed.credential_response)
        .map_err(|e| e.to_string())?;
    let state =
        ClientLogin::<PrivexCipherSuite>::deserialize(client_state).map_err(|e| e.to_string())?;

    let result = state
        .finish(
            password.as_bytes(),
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|e| e.to_string())?;

    let key_material = unwrap_envelope(&result.export_key, &parsed.envelope, &parsed.envelope_mac)?;
    Ok((
        key_material,
        result.session_key.to_vec(),
        result.message.serialize().to_vec(),
    ))
}

// --- wasm wrappers ---

#[wasm_bindgen(getter_with_clone)]
pub struct OpaqueRegistrationStart {
    pub message: Vec<u8>,
    pub client_state: Vec<u8>,
}

#[wasm_bindgen]
pub fn opaque_register_start(password: &str) -> Result<OpaqueRegistrationStart, JsError> {
    let (message, client_state) = register_start_core(password).map_err(|e| JsError::new(&e))?;
    Ok(OpaqueRegistrationStart {
        message,
        client_state,
    })
}

#[wasm_bindgen(getter_with_clone)]
pub struct OpaqueRegistrationFinish {
    pub envelope: Vec<u8>,
    pub envelope_mac: Vec<u8>,
    pub upload_message: Vec<u8>,
}

/// `password` is re-passed (OPAQUE's finish needs it; the client state never
/// stores it, so it cannot leak through the returned blob).
#[wasm_bindgen]
pub fn opaque_register_finish(
    client_state: &[u8],
    server_response: &[u8],
    key_material: &[u8],
    password: &str,
) -> Result<OpaqueRegistrationFinish, JsError> {
    let (envelope, envelope_mac, upload_message) =
        register_finish_core(client_state, server_response, key_material, password)
            .map_err(|e| JsError::new(&e))?;
    Ok(OpaqueRegistrationFinish {
        envelope,
        envelope_mac,
        upload_message,
    })
}

#[wasm_bindgen(getter_with_clone)]
pub struct OpaqueLoginStart {
    pub message: Vec<u8>,
    pub client_state: Vec<u8>,
}

#[wasm_bindgen]
pub fn opaque_login_start(password: &str, _user_id: &str) -> Result<OpaqueLoginStart, JsError> {
    let (message, client_state) = login_start_core(password).map_err(|e| JsError::new(&e))?;
    Ok(OpaqueLoginStart {
        message,
        client_state,
    })
}

#[wasm_bindgen(getter_with_clone)]
pub struct OpaqueLoginFinish {
    pub key_material: Vec<u8>,
    pub session_key: Vec<u8>,
    pub finalization: Vec<u8>, // OPAQUE KE3 → send to /recovery/opaque/complete
    pub success: bool,
}

/// `server_response` is a bincode `LoginServerResponse` (credential response +
/// stored envelope). Wrong password makes OPAQUE finish fail → Err.
#[wasm_bindgen]
pub fn opaque_login_finish(
    client_state: &[u8],
    server_response: &[u8],
    password: &str,
) -> Result<OpaqueLoginFinish, JsError> {
    let (key_material, session_key, finalization) =
        login_finish_core(client_state, server_response, password).map_err(|e| JsError::new(&e))?;
    Ok(OpaqueLoginFinish {
        key_material,
        session_key,
        finalization,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
    };

    // Full register → login round trip, driving the server side in-process.
    #[test]
    fn opaque_full_roundtrip() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<PrivexCipherSuite>::new(&mut rng);
        let password = "correct horse battery staple";
        let key_material = b"the-user-serialized-identity-key-bundle".to_vec();
        let cred_id = b"px_user0000000000000000000000000";

        // REGISTER
        let (reg_msg, reg_state) = register_start_core(password).unwrap();
        let req = opaque_ke::RegistrationRequest::deserialize(&reg_msg).unwrap();
        let server_reg = ServerRegistration::<PrivexCipherSuite>::start(&server_setup, req, cred_id)
            .unwrap();
        let server_reg_resp = server_reg.message.serialize().to_vec();

        let (envelope, envelope_mac, upload) =
            register_finish_core(&reg_state, &server_reg_resp, &key_material, password).unwrap();
        let upload_msg = opaque_ke::RegistrationUpload::deserialize(&upload).unwrap();
        let password_file = ServerRegistration::<PrivexCipherSuite>::finish(upload_msg);

        // LOGIN
        let (login_msg, login_state) = login_start_core(password).unwrap();
        let cred_req = opaque_ke::CredentialRequest::deserialize(&login_msg).unwrap();
        let server_login = ServerLogin::<PrivexCipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(password_file),
            cred_req,
            cred_id,
            ServerLoginStartParameters::default(),
        )
        .unwrap();
        let cred_resp = server_login.message.serialize().to_vec();

        let lsr = bincode::serialize(&LoginServerResponse {
            credential_response: cred_resp,
            envelope,
            envelope_mac,
        })
        .unwrap();

        let (recovered, client_sk, finalization) =
            login_finish_core(&login_state, &lsr, password).unwrap();
        assert_eq!(recovered, key_material);

        // Complete the AKE on the server: the finalization must verify and both
        // sides derive the same session key.
        let fin = opaque_ke::CredentialFinalization::deserialize(&finalization).unwrap();
        let server_finish = server_login.state.finish(fin).unwrap();
        assert_eq!(client_sk, server_finish.session_key.to_vec());
    }

    #[test]
    fn wrong_password_fails_login() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<PrivexCipherSuite>::new(&mut rng);
        let cred_id = b"px_user0000000000000000000000000";

        let (reg_msg, reg_state) = register_start_core("right-password").unwrap();
        let req = opaque_ke::RegistrationRequest::deserialize(&reg_msg).unwrap();
        let server_reg =
            ServerRegistration::<PrivexCipherSuite>::start(&server_setup, req, cred_id).unwrap();
        let (envelope, envelope_mac, upload) = register_finish_core(
            &reg_state,
            &server_reg.message.serialize().to_vec(),
            b"key-material",
            "right-password",
        )
        .unwrap();
        let password_file = ServerRegistration::<PrivexCipherSuite>::finish(
            opaque_ke::RegistrationUpload::deserialize(&upload).unwrap(),
        );

        let (login_msg, login_state) = login_start_core("WRONG-password").unwrap();
        let cred_req = opaque_ke::CredentialRequest::deserialize(&login_msg).unwrap();
        let server_login = ServerLogin::<PrivexCipherSuite>::start(
            &mut rng,
            &server_setup,
            Some(password_file),
            cred_req,
            cred_id,
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        let lsr = bincode::serialize(&LoginServerResponse {
            credential_response: server_login.message.serialize().to_vec(),
            envelope,
            envelope_mac,
        })
        .unwrap();

        assert!(login_finish_core(&login_state, &lsr, "WRONG-password").is_err());
    }
}
