// OPAQUE server-side (docs 6.1). Same cipher suite as packages/crypto-wasm:
// Ristretto255 OPRF + Triple-DH + Argon2id KSF. The server holds a long-term
// ServerSetup (loaded from env, NEVER generated fresh on startup in prod) and
// per-user OPAQUE records. It never sees the password or any password-derived
// value - only OPRF messages and an opaque encrypted envelope.

use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand_core::OsRng;

/// Must match packages/crypto-wasm/src/recovery.rs::PrivexCipherSuite exactly.
pub struct PrivexCipherSuite;
impl opaque_ke::CipherSuite for PrivexCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = argon2::Argon2<'static>;
}

type Setup = ServerSetup<PrivexCipherSuite>;

/// Generate a fresh ServerSetup (used to provision OPAQUE_SERVER_SETUP, and by
/// tests). Returns the serialized bytes.
pub fn new_setup() -> Vec<u8> {
    Setup::new(&mut OsRng).serialize().to_vec()
}

pub fn load_setup(bytes: &[u8]) -> Result<Setup, ()> {
    Setup::deserialize(bytes).map_err(|_| ())
}

/// Server OPRF evaluation for registration. Stores nothing.
pub fn register_start(setup: &Setup, request: &[u8], credential_id: &[u8]) -> Result<Vec<u8>, ()> {
    let req = RegistrationRequest::<PrivexCipherSuite>::deserialize(request).map_err(|_| ())?;
    let res = ServerRegistration::start(setup, req, credential_id).map_err(|_| ())?;
    Ok(res.message.serialize().to_vec())
}

/// Finalize registration → the server's OPAQUE record (to be stored).
pub fn register_finish(upload: &[u8]) -> Result<Vec<u8>, ()> {
    let upload = RegistrationUpload::<PrivexCipherSuite>::deserialize(upload).map_err(|_| ())?;
    let record = ServerRegistration::<PrivexCipherSuite>::finish(upload);
    Ok(record.serialize().to_vec())
}

/// Begin a login. `record` is the stored OPAQUE record, or None for a missing
/// user (opaque-ke fabricates an indistinguishable response → no enumeration).
/// Returns (credential_response, serialized ServerLogin state).
pub fn login_start(
    setup: &Setup,
    record: Option<&[u8]>,
    request: &[u8],
    credential_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let req = CredentialRequest::<PrivexCipherSuite>::deserialize(request).map_err(|_| ())?;
    let password_file = match record {
        Some(r) => Some(ServerRegistration::<PrivexCipherSuite>::deserialize(r).map_err(|_| ())?),
        None => None,
    };
    let result = ServerLogin::start(
        &mut OsRng,
        setup,
        password_file,
        req,
        credential_id,
        ServerLoginStartParameters::default(),
    )
    .map_err(|_| ())?;
    Ok((
        result.message.serialize().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

/// Verify the client's KE3 finalization against the stored login state. Ok(())
/// means the client proved knowledge of the password.
pub fn login_finish(login_state: &[u8], finalization: &[u8]) -> Result<(), ()> {
    let state = ServerLogin::<PrivexCipherSuite>::deserialize(login_state).map_err(|_| ())?;
    let fin =
        CredentialFinalization::<PrivexCipherSuite>::deserialize(finalization).map_err(|_| ())?;
    state.finish(fin).map_err(|_| ())?;
    Ok(())
}
