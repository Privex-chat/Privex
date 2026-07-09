// Configuration - loaded from environment variables only. No config files with
// secrets. Required vars cause a startup error if missing.

use anyhow::{anyhow, Context, Result};
use secrecy::SecretString;

pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub redis_url: String,
    /// HMAC key for session tokens. 32 bytes, never logged, never leaves process.
    pub session_hmac_key: [u8; 32],
    /// Ed25519 seed for signing published KT roots. 32 bytes.
    pub kt_signing_key: [u8; 32],
    /// Ed25519 seed for signing WS delivery timestamps (docs 9.6). 32 bytes,
    /// DEDICATED key (separate from KT + session HMAC); public half pinned in
    /// the client binary.
    pub time_signing_key: [u8; 32],
    /// Serialized OPAQUE ServerSetup (the server's long-term OPAQUE key). Loaded
    /// from env in production - NEVER generated fresh on startup.
    pub opaque_server_setup: Vec<u8>,
    /// PoW leading-zero-bit difficulty for registration challenges.
    pub pow_difficulty: i16,
    /// WebSocket heartbeat interval (seconds).
    pub ws_ping_secs: u64,
    pub r2_bucket: String,
    pub r2_endpoint: String,
    pub r2_region: String,
    pub r2_access_key: SecretString,
    pub r2_secret_key: SecretString,
    pub file_uploads_enabled: bool,
    pub turn_secret: SecretString,
    pub cors_origins: Vec<String>,
    /// Allowed WebSocket `Origin` headers. Required non-empty from the env
    /// (startup error otherwise); an empty list (tests only) allows all.
    pub ws_allowed_origins: Vec<String>,
}

fn req(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("missing required env var: {key}"))
}

fn secret(key: &str) -> SecretString {
    SecretString::from(std::env::var(key).unwrap_or_default())
}

/// Required comma-separated origin list. Empty/missing is a startup error so a
/// misconfigured deploy can never fall back to allow-all (PVX-09).
fn req_origins(key: &str) -> Result<Vec<String>> {
    parse_origins(key, &req(key)?)
}

fn parse_origins(key: &str, raw: &str) -> Result<Vec<String>> {
    let origins: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if origins.is_empty() {
        return Err(anyhow!("{key} must list at least one origin (comma-separated)"));
    }
    Ok(origins)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let key_hex = req("SESSION_HMAC_KEY")?;
        let key_bytes = hex::decode(key_hex.trim())
            .context("SESSION_HMAC_KEY must be hex (e.g. `openssl rand -hex 32`)")?;
        let session_hmac_key: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("SESSION_HMAC_KEY must be exactly 32 bytes (64 hex chars)"))?;

        let kt_hex = req("KT_SIGNING_KEY")?;
        let kt_bytes =
            hex::decode(kt_hex.trim()).context("KT_SIGNING_KEY must be hex (Ed25519 seed)")?;
        let kt_signing_key: [u8; 32] = kt_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("KT_SIGNING_KEY must be exactly 32 bytes (64 hex chars)"))?;

        let ts_hex = req("TIME_SIGNING_KEY")?;
        let ts_bytes =
            hex::decode(ts_hex.trim()).context("TIME_SIGNING_KEY must be hex (Ed25519 seed)")?;
        let time_signing_key: [u8; 32] = ts_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("TIME_SIGNING_KEY must be exactly 32 bytes (64 hex chars)"))?;

        use base64::Engine as _;
        let opaque_b64 = req("OPAQUE_SERVER_SETUP")?;
        let opaque_server_setup = base64::engine::general_purpose::STANDARD
            .decode(opaque_b64.trim())
            .context("OPAQUE_SERVER_SETUP must be base64 (a serialized ServerSetup)")?;

        let pow_difficulty = std::env::var("POW_DIFFICULTY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(22);
        let ws_ping_secs = std::env::var("WS_PING_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        Ok(Config {
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            database_url: req("DATABASE_URL")?,
            redis_url: req("REDIS_URL")?,
            session_hmac_key,
            kt_signing_key,
            time_signing_key,
            opaque_server_setup,
            pow_difficulty,
            ws_ping_secs,
            // Object storage is REQUIRED in production - fail fast if missing.
            r2_bucket: req("R2_BUCKET")?,
            r2_endpoint: req("R2_ENDPOINT")?,
            r2_region: std::env::var("R2_REGION").unwrap_or_else(|_| "auto".into()),
            r2_access_key: SecretString::from(req("R2_ACCESS_KEY")?),
            r2_secret_key: SecretString::from(req("R2_SECRET_KEY")?),
            file_uploads_enabled: std::env::var("FILE_UPLOADS_ENABLED")
                .ok()
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(true),
            turn_secret: secret("TURN_SECRET"),
            // Fail CLOSED: an unset/empty origin allowlist must stop the server,
            // never silently become allow-all. (Tests bypass via Config::for_test.)
            cors_origins: req_origins("CORS_ORIGIN")?,
            ws_allowed_origins: req_origins("WS_ALLOWED_ORIGINS")?,
        })
    }

    /// Ed25519 PUBLIC key (hex) for the KT root signer. Safe to log/publish -
    /// it MUST be pinned in the client out-of-band. Clients must NOT trust a KT
    /// public key fetched from the same server that signs the roots.
    pub fn kt_signing_pub_hex(&self) -> String {
        use ed25519_dalek::SigningKey;
        let vk = SigningKey::from_bytes(&self.kt_signing_key).verifying_key();
        hex::encode(vk.to_bytes())
    }

    /// Ed25519 PUBLIC key (hex) for the delivery-timestamp signer (docs 9.6).
    /// Safe to log - clients pin it in the binary, never trusting it from the
    /// same server that signs the timestamps.
    pub fn time_signing_pub_hex(&self) -> String {
        use ed25519_dalek::SigningKey;
        let vk = SigningKey::from_bytes(&self.time_signing_key).verifying_key();
        hex::encode(vk.to_bytes())
    }

    /// Construct a config directly (used by integration tests - avoids mutating
    /// process-global env). NOTE: unlike from_env, this permits an empty
    /// ws_allowed_origins (tests connect without an Origin header).
    pub fn for_test(
        database_url: String,
        redis_url: String,
        session_hmac_key: [u8; 32],
        pow_difficulty: i16,
    ) -> Self {
        Config {
            bind_addr: "127.0.0.1:0".into(),
            database_url,
            redis_url,
            session_hmac_key,
            kt_signing_key: [9u8; 32], // deterministic test KT signer
            time_signing_key: [11u8; 32], // deterministic test time signer
            opaque_server_setup: crate::crypto::opaque::new_setup(),
            pow_difficulty,
            ws_ping_secs: 2, // fast heartbeat for tests

            r2_bucket: String::new(),
            r2_endpoint: String::new(),
            r2_region: "auto".into(),
            r2_access_key: SecretString::from(String::new()),
            r2_secret_key: SecretString::from(String::new()),
            file_uploads_enabled: true,
            turn_secret: SecretString::from(String::new()),
            cors_origins: vec!["http://localhost:3000".to_string()],
            ws_allowed_origins: Vec::new(), // allow all in tests
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_origins;

    // PVX-09: an empty origin list must be a hard error, never allow-all.
    #[test]
    fn origins_required_non_empty() {
        assert!(parse_origins("CORS_ORIGIN", "").is_err());
        assert!(parse_origins("CORS_ORIGIN", " , ,").is_err());
        assert_eq!(
            parse_origins("CORS_ORIGIN", "https://a.example, https://b.example").unwrap(),
            vec!["https://a.example", "https://b.example"]
        );
    }
}
