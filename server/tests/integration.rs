// End-to-end server tests against a real Postgres + Redis (Docker). Covers
// health, PoW issuance, registration, PoW replay rejection, auth challenge/
// verify, generic-401 on a bad signature, and absence of PII in logs.
//
// Requires DATABASE_URL + REDIS_URL (defaults to the local Docker stack).

use std::io::Write;
use std::sync::{Arc, Mutex};

use deadpool_redis::{redis, Pool as RedisPool};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fips203::ml_kem_1024;
use fips203::traits::{KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as DsaSigner};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use privex_server::crypto::opaque::PrivexCipherSuite;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use sqlx::types::Uuid;
use sqlx::Row;

use privex_server::auth::sig::{challenge_signing_input, challenge_signing_input_v1};
use privex_server::config::Config;
use privex_server::crypto::{kt_log as ktree, pow_difficulty};
use privex_server::store::MemoryStore;
use privex_server::{app, build_state_with_store, now_unix, powcheck, rds};

fn to32(hexstr: &str) -> [u8; 32] {
    hex::decode(hexstr).unwrap().try_into().unwrap()
}

// Recompute the leaf from the bundle, verify inclusion against the signed root.
fn verify_kt_proof(user_id: &str, resp: &serde_json::Value, kt_pub: &VerifyingKey) -> bool {
    let dh = |k: &str| hex::decode(resp[k].as_str().unwrap()).unwrap();
    let bundle_hash = ktree::bundle_hash(
        &dh("ik_ed25519"),
        &dh("ik_dilithium3"),
        &dh("ik_x25519"),
        &dh("spk_x25519"),
        &dh("spk_sig_ed"),
        &dh("spk_sig_dil"),
        &dh("kyber1024_pub"),
    );
    let p = &resp["kt_proof"];
    let ts = p["timestamp"].as_i64().unwrap();
    let leaf = ktree::leaf_hash(user_id, &bundle_hash, ts);
    if hex::encode(leaf) != p["leaf"].as_str().unwrap() {
        return false;
    }
    let path: Vec<ktree::ProofNode> = p["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| ktree::ProofNode {
            left: n["left"].as_bool().unwrap(),
            hash: to32(n["hash"].as_str().unwrap()),
        })
        .collect();
    let root = to32(p["root"].as_str().unwrap());
    if !ktree::verify_inclusion(leaf, &path, root) {
        return false;
    }
    let sig64: [u8; 64] = hex::decode(p["root_sig_ed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    kt_pub.verify(&root, &Signature::from_bytes(&sig64)).is_ok()
}

// --- log capture (to assert no PII is ever logged) ---
#[derive(Clone)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);
impl Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

fn rand_hex(n: usize) -> String {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).unwrap();
    hex::encode(v)
}

struct Identity {
    user_id: String,
    signing: SigningKey,
    dsk: ml_dsa_65::PrivateKey,
    ed_pub_hex: String,
    dil_pub_hex: String,
}

fn new_identity() -> Identity {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let signing = SigningKey::from_bytes(&seed);
    let ed_pub = signing.verifying_key().to_bytes();
    let (dpk, dsk) = ml_dsa_65::try_keygen().unwrap();
    let user_id = format!("px_{}", hex::encode(&Sha256::digest(ed_pub)[..16]));
    Identity {
        user_id,
        signing,
        dsk,
        ed_pub_hex: hex::encode(ed_pub),
        dil_pub_hex: hex::encode(dpk.into_bytes()),
    }
}

fn register_body(
    id: &Identity,
    challenge_id: &str,
    nonce: u64,
    solution_hash_hex: &str,
) -> serde_json::Value {
    // Real key sizes + a real SPK signature (signing input = spk_x25519_pub).
    let mut spk = [0u8; 32];
    getrandom::getrandom(&mut spk).unwrap();
    let spk_sig_ed = id.signing.sign(&spk).to_bytes();
    let spk_sig_dil = id.dsk.try_sign(&spk, &[]).unwrap();
    let (kem_pub, _) = ml_kem_1024::KG::try_keygen().unwrap();
    let kyber_pub = kem_pub.into_bytes();

    serde_json::json!({
        "user_id": id.user_id,
        "ik_ed25519_pub": id.ed_pub_hex,
        "ik_dilithium3_pub": id.dil_pub_hex,
        "ik_x25519_pub": rand_hex(32),
        "spk_x25519_pub": hex::encode(spk),
        "spk_sig_ed": hex::encode(spk_sig_ed),
        "spk_sig_dil": hex::encode(spk_sig_dil),
        "kyber1024_pub": hex::encode(kyber_pub),
        "opks": [
            { "opk_id": 0, "opk_x25519_pub": rand_hex(32) },
            { "opk_id": 1, "opk_x25519_pub": rand_hex(32) },
        ],
        "pow": {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "solution_hash": solution_hash_hex,
        }
    })
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn register_and_auth(http: &reqwest::Client, base: &str) -> (Identity, String) {
    let pow: serde_json::Value = http
        .post(format!("{base}/auth/pow_challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_id = pow["challenge_id"].as_str().unwrap().to_string();
    let challenge_bytes = hex::decode(pow["challenge"].as_str().unwrap()).unwrap();
    let difficulty = pow["difficulty"].as_u64().unwrap() as u32;

    let id = new_identity();
    let (nonce, sol) = powcheck::pow_solve(&challenge_bytes, difficulty);
    let body = register_body(&id, &challenge_id, nonce, &hex::encode(sol));
    assert_eq!(
        http.post(format!("{base}/keys/register"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let chal: serde_json::Value = http
        .post(format!("{base}/auth/challenge"))
        .json(&serde_json::json!({ "user_id": id.user_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal_bytes = hex::decode(chal["challenge"].as_str().unwrap()).unwrap();
    let ts = now_unix();
    // Current v1 (domain-separated) signing input - what real clients send.
    let msg = challenge_signing_input_v1(&chal_bytes, &id.user_id, ts);
    let sig_ed = id.signing.sign(&msg).to_bytes();
    let sig_dil = id.dsk.try_sign(&msg, &[]).unwrap();
    let vr: serde_json::Value = http
        .post(format!("{base}/auth/verify"))
        .json(&serde_json::json!({
            "user_id": id.user_id,
            "challenge": hex::encode(&chal_bytes),
            "sig_ed": hex::encode(sig_ed),
            "sig_dil": hex::encode(sig_dil),
            "timestamp": ts,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = vr["session_token"].as_str().unwrap().to_string();
    (id, token)
}

fn random_uuid_string() -> String {
    let mut id_raw = [0u8; 16];
    getrandom::getrandom(&mut id_raw).unwrap();
    id_raw[6] = (id_raw[6] & 0x0f) | 0x40;
    id_raw[8] = (id_raw[8] & 0x3f) | 0x80;
    Uuid::from_bytes(id_raw).to_string()
}

async fn clear_pow_pressure(pool: &RedisPool) {
    let minute = pow_difficulty::unix_ts() / 60;
    let mut conn = pool.get().await.unwrap();
    let mut cmd = redis::cmd("DEL");
    cmd.arg("reg:suspicion")
        .arg("reg:difficulty_manager:last_log")
        .arg("reg:difficulty_manager:tick");
    for offset in 0..=3 {
        let m = minute.saturating_sub(offset);
        cmd.arg(format!("reg:window:{m}"))
            .arg(format!("reg:challenge_rate:{m}"));
    }
    let _: i64 = cmd.query_async(&mut conn).await.unwrap();
}

async fn set_current_registration_pressure(pool: &RedisPool, count: u32) {
    let minute = pow_difficulty::unix_ts() / 60;
    let mut conn = pool.get().await.unwrap();
    let _: () = redis::cmd("SET")
        .arg(format!("reg:window:{minute}"))
        .arg(count)
        .arg("EX")
        .arg(300)
        .query_async(&mut conn)
        .await
        .unwrap();
}

async fn redis_get_i64(pool: &RedisPool, key: &str) -> Option<i64> {
    let mut conn = pool.get().await.unwrap();
    redis::cmd("GET")
        .arg(key)
        .query_async(&mut conn)
        .await
        .unwrap()
}

async fn ws_ticket(http: &reqwest::Client, base: &str, token: &str) -> String {
    let v: serde_json::Value = http
        .post(format!("{base}/auth/ws_ticket"))
        .header("X-Privex-Auth", token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["ticket"].as_str().unwrap().to_string()
}

async fn ws_connect(
    addr: std::net::SocketAddr,
    ticket: &str,
) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("privex, {ticket}").parse().unwrap(),
    );
    tokio_tungstenite::connect_async(req).await.map(|(s, _)| s)
}

async fn devlink_connect(
    addr: std::net::SocketAddr,
    ticket: &str,
    rid: &str,
) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{addr}/v1/devlink/{rid}")
        .into_client_request()
        .unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("privex, {ticket}").parse().unwrap(),
    );
    tokio_tungstenite::connect_async(req).await.map(|(s, _)| s)
}

// Read the next Text frame, skipping protocol pings/pongs.
async fn read_text(ws: &mut Ws) -> Option<String> {
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(4), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return Some(t),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

// Read frames until a "message" arrives, replying to pings along the way.
async fn read_until_message(ws: &mut Ws) -> serde_json::Value {
    use tokio_tungstenite::tungstenite::Message;
    loop {
        let next = tokio::time::timeout(std::time::Duration::from_secs(4), ws.next())
            .await
            .expect("timed out waiting for message")
            .expect("stream ended")
            .expect("ws error");
        if let Message::Text(t) = next {
            let v: serde_json::Value = serde_json::from_str(&t).unwrap();
            match v["type"].as_str() {
                Some("message") => return v,
                Some("ping") => {
                    let _ = ws
                        .send(Message::Text(
                            serde_json::json!({ "type": "pong" }).to_string(),
                        ))
                        .await;
                }
                _ => {}
            }
        }
    }
}

// Returns true if a heartbeat ping is received within the window.
async fn expect_ping(ws: &mut Ws) -> bool {
    use tokio_tungstenite::tungstenite::Message;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
                if v["type"] == "ping" {
                    let _ = ws
                        .send(Message::Text(
                            serde_json::json!({ "type": "pong" }).to_string(),
                        ))
                        .await;
                    return true;
                }
            }
            _ => return false,
        }
    }
}

/// Build a `{ challenge_id, nonce, solution_hash }` PoW proof for the PoW-gated
/// public fetches. Stores its own low-difficulty challenge directly in Redis,
/// issued in the past so it's never flagged too-fast - fast to solve and it does
/// NOT touch `reg:challenge_rate`, so the difficulty assertions elsewhere in this
/// test stay deterministic. Still exercises the real server-side `verify_pow`.
async fn test_pow_proof(redis: &RedisPool) -> serde_json::Value {
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge).unwrap();
    let challenge_id = random_uuid_string();
    let difficulty = 8u32;
    rds::store_pow_challenge(
        redis,
        &challenge_id,
        &challenge,
        difficulty,
        pow_difficulty::unix_ts_ms().saturating_sub(10_000),
        30 * 60,
    )
    .await
    .unwrap();
    let (nonce, sol) = powcheck::pow_solve(&challenge, difficulty);
    serde_json::json!({
        "challenge_id": challenge_id,
        "nonce": nonce,
        "solution_hash": hex::encode(sol),
    })
}

/// PoW-gated key-bundle fetch (replaces the old unauthenticated GET /keys/{id}).
async fn fetch_bundle(
    redis: &RedisPool,
    http: &reqwest::Client,
    base: &str,
    user_id: &str,
) -> reqwest::Response {
    let body = serde_json::json!({ "pow": test_pow_proof(redis).await });
    http.post(format!("{base}/keys/{user_id}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn server_end_to_end() {
    // Capture all logs from our crate.
    let buf = LogBuf(Arc::new(Mutex::new(Vec::new())));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("privex_server=debug"))
        .with_writer(buf.clone())
        .with_ansi(false)
        .try_init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://privex:privex@localhost:5432/privex".into());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());

    // In-memory object store; registration difficulty itself is Redis-dynamic.
    let config = Config::for_test(database_url.clone(), redis_url, [7u8; 32], 8);
    let store = Arc::new(MemoryStore::new());
    let state = build_state_with_store(config, store).await.expect("state");
    clear_pow_pressure(&state.redis).await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&database_url)
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = app(state.clone()); // keep `state` for the cleanup_expired test
    tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();

    // 1. /health
    let r = http.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({"status":"ok"})
    );

    // 2. PoW challenge issuance
    let pow: serde_json::Value = http
        .post(format!("{base}/auth/pow_challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_id = pow["challenge_id"].as_str().unwrap().to_string();
    let challenge_bytes = hex::decode(pow["challenge"].as_str().unwrap()).unwrap();
    let difficulty = pow["difficulty"].as_u64().unwrap() as u32;
    assert_eq!(
        difficulty, 22,
        "normal conditions should return difficulty 22"
    );

    // 3. registration with a valid PoW solution
    let id = new_identity();
    let (nonce, sol) = powcheck::pow_solve(&challenge_bytes, difficulty);
    let body = register_body(&id, &challenge_id, nonce, &hex::encode(sol));
    let r = http
        .post(format!("{base}/keys/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "registration should succeed");
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["registered"],
        true
    );

    // 4. replayed PoW (same consumed challenge) is rejected
    let r = http
        .post(format!("{base}/keys/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "replayed PoW must be rejected");

    // 4b. An invalid PoW attempt consumes its challenge too. This prevents a
    // client from reusing one challenge to make the server repeatedly verify
    // guesses.
    let invalid_pow: serde_json::Value = http
        .post(format!("{base}/auth/pow_challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invalid_challenge_id = invalid_pow["challenge_id"].as_str().unwrap().to_string();
    let invalid_challenge_bytes = hex::decode(invalid_pow["challenge"].as_str().unwrap()).unwrap();
    let invalid_difficulty = invalid_pow["difficulty"].as_u64().unwrap() as u32;
    let invalid_id = new_identity();
    let invalid_body = register_body(&invalid_id, &invalid_challenge_id, 0, &"00".repeat(32));
    let r = http
        .post(format!("{base}/keys/register"))
        .json(&invalid_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "invalid PoW must be rejected");
    let (valid_nonce_after_invalid, valid_sol_after_invalid) =
        powcheck::pow_solve(&invalid_challenge_bytes, invalid_difficulty);
    let retry_after_invalid = register_body(
        &invalid_id,
        &invalid_challenge_id,
        valid_nonce_after_invalid,
        &hex::encode(valid_sol_after_invalid),
    );
    let r = http
        .post(format!("{base}/keys/register"))
        .json(&retry_after_invalid)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        400,
        "invalid PoW attempt must consume the challenge"
    );

    // 4c. Dynamic Redis pressure: 20 recent registrations raises the next
    // challenge to difficulty 25 without any IP/user/device key.
    set_current_registration_pressure(&state.redis, 20).await;
    let pressured_pow: serde_json::Value = http
        .post(format!("{base}/auth/pow_challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        pressured_pow["difficulty"].as_u64().unwrap(),
        25,
        "20 recent registrations should raise difficulty to 25"
    );
    clear_pow_pressure(&state.redis).await;

    // 4d. A valid solution that appears impossibly fast increments aggregate
    // suspicion, and decay clamps it back to zero instead of going negative.
    let mut fast_challenge = [0u8; 32];
    getrandom::getrandom(&mut fast_challenge).unwrap();
    let fast_difficulty = 22;
    let (fast_nonce, fast_sol) = powcheck::pow_solve(&fast_challenge, fast_difficulty);
    let fast_challenge_id = random_uuid_string();
    rds::store_pow_challenge(
        &state.redis,
        &fast_challenge_id,
        &fast_challenge,
        fast_difficulty,
        pow_difficulty::unix_ts_ms() + 60_000,
        30 * 60,
    )
    .await
    .unwrap();
    let fast_id = new_identity();
    let fast_body = register_body(
        &fast_id,
        &fast_challenge_id,
        fast_nonce,
        &hex::encode(fast_sol),
    );
    let r = http
        .post(format!("{base}/keys/register"))
        .json(&fast_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "fast-but-valid PoW math is accepted");
    assert_eq!(
        redis_get_i64(&state.redis, "reg:suspicion").await,
        Some(1),
        "suspicious-fast solve should increment aggregate suspicion"
    );
    assert_eq!(
        pow_difficulty::decrement_suspicion(&state.redis)
            .await
            .unwrap(),
        0,
        "suspicion decay should clamp at zero"
    );
    assert_eq!(redis_get_i64(&state.redis, "reg:suspicion").await, None);

    // 5. auth challenge + verify success
    let chal: serde_json::Value = http
        .post(format!("{base}/auth/challenge"))
        .json(&serde_json::json!({ "user_id": id.user_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal_bytes = hex::decode(chal["challenge"].as_str().unwrap()).unwrap();
    let ts = now_unix();
    // Deliberately the LEGACY (pre-domain-separation) input: the server must keep
    // accepting it while cached PWA builds age out (PVX-21 transitional fallback).
    // register_and_auth() covers the current v1 layout.
    let msg = challenge_signing_input(&chal_bytes, &id.user_id, ts);
    let sig_ed = id.signing.sign(&msg).to_bytes();
    let sig_dil = id.dsk.try_sign(&msg, &[]).unwrap();

    let verify_body = serde_json::json!({
        "user_id": id.user_id,
        "challenge": hex::encode(&chal_bytes),
        "sig_ed": hex::encode(sig_ed),
        "sig_dil": hex::encode(sig_dil),
        "timestamp": ts,
    });
    let r = http
        .post(format!("{base}/auth/verify"))
        .json(&verify_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "valid signature should authenticate");
    let token = r.json::<serde_json::Value>().await.unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!token.is_empty());

    // 6. wrong signature → generic 401
    let chal2: serde_json::Value = http
        .post(format!("{base}/auth/challenge"))
        .json(&serde_json::json!({ "user_id": id.user_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal2_bytes = hex::decode(chal2["challenge"].as_str().unwrap()).unwrap();
    let bad_body = serde_json::json!({
        "user_id": id.user_id,
        "challenge": hex::encode(&chal2_bytes),
        "sig_ed": rand_hex(64),  // garbage signature
        "sig_dil": hex::encode(id.dsk.try_sign(b"wrong", &[]).unwrap()),
        "timestamp": now_unix(),
    });
    let r = http
        .post(format!("{base}/auth/verify"))
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "bad signature must be a generic 401");

    // 6b. unknown-but-valid px_id → the SAME generic 401 (PVX-08 dummy-verify
    // path). Timing equality isn't CI-assertable; this at least exercises the
    // absent-user branch end-to-end.
    let ghost = format!("px_{}", rand_hex(16));
    let gchal: serde_json::Value = http
        .post(format!("{base}/auth/challenge"))
        .json(&serde_json::json!({ "user_id": ghost }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gchal_bytes = hex::decode(gchal["challenge"].as_str().unwrap()).unwrap();
    let gts = now_unix();
    let gmsg = challenge_signing_input_v1(&gchal_bytes, &ghost, gts);
    let r = http
        .post(format!("{base}/auth/verify"))
        .json(&serde_json::json!({
            "user_id": ghost,
            "challenge": hex::encode(&gchal_bytes),
            "sig_ed": hex::encode(id.signing.sign(&gmsg).to_bytes()),
            "sig_dil": hex::encode(id.dsk.try_sign(&gmsg, &[]).unwrap()),
            "timestamp": gts,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "unknown user must be a generic 401");

    // ===== Session 9: messages + blobs =====

    // Auth required (no X-Privex-Auth header → 401).
    assert_eq!(
        http.post(format!("{base}/messages/send"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.post(format!("{base}/messages/ack"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let dummy_id = "a".repeat(64);
    assert_eq!(
        http.post(format!("{base}/blobs/{dummy_id}"))
            .body(vec![1u8, 2, 3])
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // Send a message whose recipient is the authenticated user, so the same
    // token can ACK it (the recipient acks their own mailbox).
    let recipient = id.user_id.clone();
    let mut content = vec![0u8; 200];
    getrandom::getrandom(&mut content).unwrap();
    let send_resp: serde_json::Value = http
        .post(format!("{base}/messages/send"))
        .header("X-Privex-Auth", &token)
        .json(&serde_json::json!({
            "recipient_id": recipient,
            "content": base64::engine::general_purpose::STANDARD.encode(&content),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(send_resp["queued"], true);
    let message_id = send_resp["message_id"].as_str().unwrap().to_string();

    // DB row stores the encrypted content only - and the table has no
    // sender/read/delivery columns at all.
    let row = sqlx::query("SELECT content FROM message_queue WHERE recipient_id = $1")
        .bind(&recipient)
        .fetch_one(&pool)
        .await
        .unwrap();
    let stored_content: Vec<u8> = row.get("content");
    assert_eq!(
        stored_content, content,
        "stored content must match the sent blob"
    );
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'message_queue'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !cols.iter().any(|c| c.contains("sender")),
        "no sender column"
    );
    assert!(
        !cols
            .iter()
            .any(|c| c.contains("read") || c.contains("delivery")),
        "no read/delivery tracking column"
    );

    // ACK hard-deletes the row.
    let ack_resp: serde_json::Value = http
        .post(format!("{base}/messages/ack"))
        .header("X-Privex-Auth", &token)
        .json(&serde_json::json!({ "message_ids": [message_id] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ack_resp["deleted"], 1);
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE recipient_id = $1")
            .bind(&recipient)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "ACK must hard-delete the row");

    // Blob upload → download round trip.
    let mut blob = vec![0u8; 256];
    getrandom::getrandom(&mut blob).unwrap();
    let chunk_id = hex::encode(Sha256::digest(&blob));
    let up = http
        .post(format!("{base}/blobs/{chunk_id}"))
        .header("X-Privex-Auth", &token)
        .body(blob.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), 200, "blob upload");
    let down = http
        .get(format!("{base}/blobs/{chunk_id}"))
        .header("X-Privex-Auth", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(down.status(), 200);
    assert_eq!(
        down.bytes().await.unwrap().to_vec(),
        blob,
        "blob round trip"
    );

    // Wrong chunk_id (not the SHA-256 of the bytes) → 400.
    let wrong = http
        .post(format!("{base}/blobs/{}", "b".repeat(64)))
        .header("X-Privex-Auth", &token)
        .body(blob.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 400, "mismatched chunk_id must be rejected");

    // Missing blob → 404.
    let missing = http
        .get(format!("{base}/blobs/{}", "c".repeat(64)))
        .header("X-Privex-Auth", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    // ===== Session 10: WebSocket =====
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    let b64 = base64::engine::general_purpose::STANDARD;

    // ws_ticket requires auth.
    assert_eq!(
        http.post(format!("{base}/auth/ws_ticket"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // Bob registers + authenticates.
    let (bob, bob_token) = register_and_auth(&http, &base).await;

    // Valid ticket → WS connect succeeds.
    let ticket = ws_ticket(&http, &base, &bob_token).await;
    let mut bob_ws = ws_connect(addr, &ticket)
        .await
        .expect("ws connect with valid ticket");

    // Reusing the same (now consumed) ticket fails.
    assert!(
        ws_connect(addr, &ticket).await.is_err(),
        "reused ticket must fail"
    );

    // Query-param ticket with NO subprotocol header is rejected.
    {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let qp = ws_ticket(&http, &base, &bob_token).await;
        let req = format!("ws://{addr}/v1/ws?ticket={qp}")
            .into_client_request()
            .unwrap();
        assert!(
            tokio_tungstenite::connect_async(req).await.is_err(),
            "query-param ticket must be rejected"
        );
    }

    // Alice (id) sends to ONLINE Bob → Bob receives over WS.
    let mut online_content = vec![0u8; 128];
    getrandom::getrandom(&mut online_content).unwrap();
    let online_b64 = b64.encode(&online_content);
    let send: serde_json::Value = http
        .post(format!("{base}/messages/send"))
        .header("X-Privex-Auth", &token)
        .json(&serde_json::json!({ "recipient_id": bob.user_id, "content": online_b64 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let online_mid = send["message_id"].as_str().unwrap().to_string();

    let frame = read_until_message(&mut bob_ws).await;
    assert_eq!(frame["message_id"].as_str().unwrap(), online_mid);
    assert_eq!(frame["content"].as_str().unwrap(), online_b64);

    // Docs 9.6: every delivery carries a signed timestamp pair. Verify with the
    // for_test time signer pub ([11u8;32] seed) over be64(server_ts)||be64(queued_at)||id.
    {
        let server_ts = frame["server_ts"].as_i64().expect("server_ts present");
        let queued_at = frame["queued_at"].as_i64().expect("queued_at present");
        let now = now_unix();
        assert!((now - server_ts).abs() <= 5, "server_ts should be ~now");
        let sig64: [u8; 64] = hex::decode(frame["server_ts_sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let vk = SigningKey::from_bytes(&[11u8; 32]).verifying_key();
        let input = privex_server::crypto::time_signing::signing_input(
            server_ts, queued_at, &online_mid,
        );
        assert!(
            vk.verify(&input, &Signature::from_bytes(&sig64)).is_ok(),
            "delivery timestamp signature must verify against the pinned time pub"
        );
        // Tampered timestamp → signature must fail.
        let bad = privex_server::crypto::time_signing::signing_input(
            server_ts + 1, queued_at, &online_mid,
        );
        assert!(vk.verify(&bad, &Signature::from_bytes(&sig64)).is_err());
    }

    // Bob ACKs over WS → DB row hard-deleted.
    bob_ws
        .send(WsMessage::Text(
            serde_json::json!({ "type": "ack", "message_ids": [online_mid] }).to_string(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE recipient_id = $1")
        .bind(&bob.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "WS ack must hard-delete");

    // Bob goes offline; a new message stays queued (not delivered).
    bob_ws.send(WsMessage::Close(None)).await.ok();
    drop(bob_ws);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut offline_content = vec![0u8; 96];
    getrandom::getrandom(&mut offline_content).unwrap();
    let offline_b64 = b64.encode(&offline_content);
    http.post(format!("{base}/messages/send"))
        .header("X-Privex-Auth", &token)
        .json(&serde_json::json!({ "recipient_id": bob.user_id, "content": offline_b64 }))
        .send()
        .await
        .unwrap();
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE recipient_id = $1")
            .bind(&bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(queued, 1, "offline message must remain queued");

    // Bob reconnects → queued message delivered → ack deletes it.
    let ticket2 = ws_ticket(&http, &base, &bob_token).await;
    let mut bob_ws2 = ws_connect(addr, &ticket2).await.expect("reconnect");
    let frame2 = read_until_message(&mut bob_ws2).await;
    assert_eq!(
        frame2["content"].as_str().unwrap(),
        offline_b64,
        "queued msg on reconnect"
    );
    let mid2 = frame2["message_id"].as_str().unwrap().to_string();
    bob_ws2
        .send(WsMessage::Text(
            serde_json::json!({ "type": "ack", "message_ids": [mid2] }).to_string(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE recipient_id = $1")
            .bind(&bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after, 0);

    // Heartbeat: a server ping arrives, we pong, connection stays alive.
    assert!(
        expect_ping(&mut bob_ws2).await,
        "should receive a heartbeat ping"
    );

    // ===== Session 11: KT log + key management =====
    let kt_pub = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let count_opks = |uid: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = $1")
                .bind(uid)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    // Key fetch is PoW-gated: no proof → rejected, an unknown/invalid proof → 400,
    // only a valid solved challenge returns the bundle (closes account enumeration).
    let no_pow = http
        .post(format!("{base}/keys/{}", bob.user_id))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(
        no_pow.status().is_client_error(),
        "key fetch without a PoW proof must be rejected"
    );
    let bad_pow = http
        .post(format!("{base}/keys/{}", bob.user_id))
        .json(&serde_json::json!({ "pow": {
            "challenge_id": random_uuid_string(),
            "nonce": 0u64,
            "solution_hash": "00".repeat(32),
        } }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_pow.status(),
        400,
        "key fetch with an unknown/invalid PoW must be 400"
    );

    // Fetch Bob's bundle: full fields + one OPK + verifiable KT proof.
    let b1: serde_json::Value = fetch_bundle(&state.redis, &http, &base, &bob.user_id)
        .await
        .json()
        .await
        .unwrap();
    for k in ["ik_x25519", "spk_sig_ed", "spk_sig_dil", "kyber1024_pub"] {
        assert!(b1[k].as_str().is_some(), "bundle missing {k}");
    }
    assert!(b1["opk"].as_str().is_some(), "should serve an OPK");
    assert!(
        verify_kt_proof(&bob.user_id, &b1, &kt_pub),
        "KT proof must verify"
    );

    // Tampered bundle → proof fails.
    let mut tampered = b1.clone();
    let mut ik = hex::decode(tampered["ik_ed25519"].as_str().unwrap()).unwrap();
    ik[0] ^= 0xff;
    tampered["ik_ed25519"] = serde_json::Value::String(hex::encode(ik));
    assert!(
        !verify_kt_proof(&bob.user_id, &tampered, &kt_pub),
        "tampered bundle must fail"
    );

    // Two fetches consume two DIFFERENT OPKs (Bob registered with 2).
    let b2: serde_json::Value = fetch_bundle(&state.redis, &http, &base, &bob.user_id)
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(
        b1["opk_id"], b2["opk_id"],
        "two fetches must give different OPKs"
    );

    // Replenish, then count increases.
    let before = count_opks(bob.user_id.clone()).await;
    let new_opks: Vec<serde_json::Value> = (2..7)
        .map(|i| serde_json::json!({ "opk_id": i, "opk_x25519_pub": rand_hex(32) }))
        .collect();
    let rep: serde_json::Value = http
        .post(format!("{base}/keys/prekeys/replenish"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({ "opks": new_opks }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rep["stored"], 5);
    assert_eq!(count_opks(bob.user_id.clone()).await, before + 5);

    // Duplicate opk_id (2 already exists) + one new (99) → stored counts only 1.
    let dup: serde_json::Value = http
        .post(format!("{base}/keys/prekeys/replenish"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({ "opks": [
            { "opk_id": 2, "opk_x25519_pub": rand_hex(32) },
            { "opk_id": 99, "opk_x25519_pub": rand_hex(32) },
        ] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dup["stored"], 1, "duplicate opk_id must not be counted");

    // Concurrent fetches must not return the same OPK. Pre-solve both PoWs so the
    // two POSTs actually race (exercises the FOR UPDATE SKIP LOCKED OPK consume).
    let body_a = serde_json::json!({ "pow": test_pow_proof(&state.redis).await });
    let body_b = serde_json::json!({ "pow": test_pow_proof(&state.redis).await });
    let (ca, cb) = tokio::join!(
        http.post(format!("{base}/keys/{}", bob.user_id)).json(&body_a).send(),
        http.post(format!("{base}/keys/{}", bob.user_id)).json(&body_b).send(),
    );
    let oa: serde_json::Value = ca.unwrap().json().await.unwrap();
    let ob: serde_json::Value = cb.unwrap().json().await.unwrap();
    assert!(oa["opk_id"].as_i64().is_some() && ob["opk_id"].as_i64().is_some());
    assert_ne!(oa["opk_id"], ob["opk_id"], "concurrent fetches must differ");

    // SPK rotate with a valid hybrid signature → appends a KT entry.
    let mut new_spk = [0u8; 32];
    getrandom::getrandom(&mut new_spk).unwrap();
    let rot: serde_json::Value = http
        .post(format!("{base}/keys/spk/rotate"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({
            "spk_x25519_pub": hex::encode(new_spk),
            "spk_sig_ed": hex::encode(bob.signing.sign(&new_spk).to_bytes()),
            "spk_sig_dil": hex::encode(bob.dsk.try_sign(&new_spk, &[]).unwrap()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rot["rotated"], true);
    let kt_entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kt_log WHERE user_id = $1")
        .bind(&bob.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kt_entries, 2, "register + spk_rotate entries");

    // After rotate, the bundle still verifies (new SPK in the leaf).
    let b3: serde_json::Value = fetch_bundle(&state.redis, &http, &base, &bob.user_id)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(b3["spk_x25519"].as_str().unwrap(), hex::encode(new_spk));
    assert!(
        verify_kt_proof(&bob.user_id, &b3, &kt_pub),
        "rotated bundle proof must verify"
    );

    // SPK rotate with a bad signature → generic 400.
    let bad_rot = http
        .post(format!("{base}/keys/spk/rotate"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({
            "spk_x25519_pub": hex::encode(new_spk),
            "spk_sig_ed": rand_hex(64),
            "spk_sig_dil": hex::encode(bob.dsk.try_sign(&new_spk, &[]).unwrap()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_rot.status(), 400, "bad SPK signature must be rejected");

    // /keys/kt/root returns a real signed (non-placeholder) root.
    let kt_root: serde_json::Value = http
        .get(format!("{base}/keys/kt/root"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let root_bytes = to32(kt_root["root"].as_str().unwrap());
    assert_ne!(root_bytes, [0u8; 32], "root must not be a placeholder");
    let root_sig: [u8; 64] = hex::decode(kt_root["root_sig_ed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        kt_pub
            .verify(&root_bytes, &Signature::from_bytes(&root_sig))
            .is_ok(),
        "kt root signature must verify"
    );

    // ===== Session 12: OPAQUE recovery =====
    let password = "correct horse battery staple";

    // OPAQUE register-setup (authenticated). Replicates the WASM client via
    // opaque-ke directly (same PrivexCipherSuite) → byte-identical messages.
    let reg_start =
        ClientRegistration::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let rs: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/register/start"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({ "registration_request": hex::encode(reg_start.message.serialize()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let reg_resp = RegistrationResponse::<PrivexCipherSuite>::deserialize(
        &hex::decode(rs["registration_response"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let reg_finish = reg_start
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            reg_resp,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let rf: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/register/finish"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({
            "registration_upload": hex::encode(reg_finish.message.serialize()),
            "envelope": rand_hex(116),
            "envelope_mac": rand_hex(32),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rf["stored"], true);

    let opaque_status: serde_json::Value = http
        .get(format!("{base}/recovery/opaque/status"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        opaque_status["enabled"], true,
        "OPAQUE should be opt-in enabled after setup"
    );

    // Login with the CORRECT password → 200 + a 24h token.
    let login_start =
        ClientLogin::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let init_pow = test_pow_proof(&state.redis).await;
    let li: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/init"))
        .json(&serde_json::json!({ "user_id": bob.user_id, "credential_request": hex::encode(login_start.message.serialize()), "pow": init_pow }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_id = li["login_id"].as_str().unwrap().to_string();
    let cred_resp = CredentialResponse::<PrivexCipherSuite>::deserialize(
        &hex::decode(li["credential_response"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let login_finish = login_start
        .state
        .finish(
            password.as_bytes(),
            cred_resp,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let finalization = login_finish.message.serialize().to_vec();

    let t_ok = std::time::Instant::now();
    let lc = http
        .post(format!("{base}/recovery/opaque/complete"))
        .json(&serde_json::json!({ "login_id": login_id, "credential_finalization": hex::encode(&finalization) }))
        .send()
        .await
        .unwrap();
    let success_ms = t_ok.elapsed().as_secs_f64();
    assert_eq!(lc.status(), 200, "correct password must issue a token");
    let recovered_token = lc.json::<serde_json::Value>().await.unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();

    // The recovery token is a normal session token (works on protected routes).
    assert_eq!(
        http.post(format!("{base}/auth/ws_ticket"))
            .header("X-Privex-Auth", &recovered_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // Single-use: reusing the same login_id → 401.
    assert_eq!(
        http.post(format!("{base}/recovery/opaque/complete"))
            .json(&serde_json::json!({ "login_id": login_id, "credential_finalization": hex::encode(&finalization) }))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "OPAQUE login_id must be single-use"
    );

    // Invalid finalization → generic 401. (A genuine wrong password is detected
    // client-side and never produces a finalization; the server rejects any
    // finalization that doesn't match its login state.)
    let ls2 = ClientLogin::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let init_pow2 = test_pow_proof(&state.redis).await;
    let li2: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/init"))
        .json(&serde_json::json!({ "user_id": bob.user_id, "credential_request": hex::encode(ls2.message.serialize()), "pow": init_pow2 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_id2 = li2["login_id"].as_str().unwrap().to_string();
    let t_fail = std::time::Instant::now();
    let fail = http
        .post(format!("{base}/recovery/opaque/complete"))
        .json(&serde_json::json!({ "login_id": login_id2, "credential_finalization": hex::encode(&finalization) }))
        .send()
        .await
        .unwrap();
    let fail_ms = t_fail.elapsed().as_secs_f64();
    assert_eq!(
        fail.status(),
        401,
        "invalid finalization must be a generic 401"
    );

    // Timings roughly normalized (both run ServerLogin::finish fully).
    let ratio = success_ms.max(fail_ms) / success_ms.min(fail_ms).max(1e-6);
    assert!(
        ratio < 5.0,
        "opaque complete timing ratio too skewed: {ratio}"
    );

    // Turning OPAQUE off hard-deletes the row and invalidates already-started
    // recovery attempts before they can mint a token.
    let pending_start =
        ClientLogin::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let pending_pow = test_pow_proof(&state.redis).await;
    let pending_init: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/init"))
        .json(&serde_json::json!({ "user_id": bob.user_id, "credential_request": hex::encode(pending_start.message.serialize()), "pow": pending_pow }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        pending_init["envelope"].as_str().unwrap().len(),
        116 * 2,
        "real and dummy OPAQUE envelopes must have the same wire size"
    );
    let pending_resp = CredentialResponse::<PrivexCipherSuite>::deserialize(
        &hex::decode(pending_init["credential_response"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let pending_finish = pending_start
        .state
        .finish(
            password.as_bytes(),
            pending_resp,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let off: serde_json::Value = http
        .delete(format!("{base}/recovery/opaque"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(off["enabled"], false);
    let disabled_status: serde_json::Value = http
        .get(format!("{base}/recovery/opaque/status"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disabled_status["enabled"], false);
    assert_eq!(
        http.post(format!("{base}/recovery/opaque/complete"))
            .json(&serde_json::json!({
                "login_id": pending_init["login_id"].as_str().unwrap(),
                "credential_finalization": hex::encode(pending_finish.message.serialize()),
            }))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "pending OPAQUE login must fail after the recovery record is deleted"
    );

    let disabled_start =
        ClientLogin::<PrivexCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let disabled_pow = test_pow_proof(&state.redis).await;
    let disabled_init: serde_json::Value = http
        .post(format!("{base}/recovery/opaque/init"))
        .json(&serde_json::json!({ "user_id": bob.user_id, "credential_request": hex::encode(disabled_start.message.serialize()), "pow": disabled_pow }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disabled_init["envelope"].as_str().unwrap().len(), 116 * 2);

    // ===== Audit fixes =====

    // A2: cover traffic to a non-existent mailbox is dropped (not stored), but
    // the response is indistinguishable from a real send.
    let fake_recipient = format!("px_{}", rand_hex(16));
    let cover: serde_json::Value = http
        .post(format!("{base}/messages/send"))
        .header("X-Privex-Auth", &token)
        .json(&serde_json::json!({ "recipient_id": fake_recipient, "content": b64.encode([9u8; 64]) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cover["queued"], true, "cover send must look successful");
    let cover_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE recipient_id = $1")
            .bind(&fake_recipient)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cover_rows, 0, "cover traffic must not be stored");

    // A1: the expiry sweeper deletes expired rows.
    sqlx::query(
        "INSERT INTO message_queue (recipient_id, content, queued_at, expires_at, size_bytes) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&bob.user_id)
    .bind(vec![7u8, 7, 7])
    .bind(0i32)
    .bind(1i32) // already expired
    .bind(3i32)
    .execute(&pool)
    .await
    .unwrap();
    privex_server::cleanup_expired(&state).await.unwrap();
    let expired_left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_queue WHERE expires_at < $1")
            .bind(now_unix() as i32)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expired_left, 0, "expiry sweep must delete expired messages");

    // ===== Session 18: recovery shares + log-out-everywhere =====

    // Store 3 Shamir recovery shares (opaque encrypted blobs).
    let shares_body = serde_json::json!({
        "shares": [
            { "share_index": 1, "encrypted_share": rand_hex(80) },
            { "share_index": 2, "encrypted_share": rand_hex(80) },
            { "share_index": 3, "encrypted_share": rand_hex(80) },
        ]
    });
    let sr: serde_json::Value = http
        .post(format!("{base}/recovery/shares/store"))
        .header("X-Privex-Auth", &token)
        .json(&shares_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sr["stored"], 3, "all 3 recovery shares stored");
    let share_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_shares WHERE user_id = $1")
            .bind(&id.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        share_rows, 3,
        "recovery_shares table holds 3 encrypted blobs"
    );

    // ===== Session 19: encrypted history backup (Option A) =====

    // Auth required.
    assert_eq!(
        http.post(format!("{base}/history/blobs"))
            .json(&serde_json::json!({ "blobs": [] }))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // Bob uploads 2 encrypted history blobs (3 + 4 bytes).
    let up: serde_json::Value = http
        .post(format!("{base}/history/blobs"))
        .header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({ "blobs": [
            { "blob_id": "m1", "ciphertext": b64.encode([1u8, 2, 3]) },
            { "blob_id": "m2", "ciphertext": b64.encode([4u8, 5, 6, 7]) },
        ] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(up["stored"], 2);

    // Status reflects count + total ciphertext bytes.
    let stt: serde_json::Value = http
        .get(format!("{base}/history/status"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stt["count"], 2);
    assert_eq!(stt["bytes"], 7);

    // List returns both with ciphertext intact, no further pages.
    let lst: serde_json::Value = http
        .get(format!("{base}/history/blobs"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(lst["blobs"].as_array().unwrap().len(), 2);
    assert!(lst["next"].is_null());

    // Idempotent upsert: re-uploading m1 must not create a duplicate row.
    http.post(format!("{base}/history/blobs")).header("X-Privex-Auth", &bob_token)
        .json(&serde_json::json!({ "blobs": [{ "blob_id": "m1", "ciphertext": b64.encode([9u8, 9, 9, 9, 9]) }] }))
        .send().await.unwrap();
    let stt2: serde_json::Value = http
        .get(format!("{base}/history/status"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stt2["count"], 2, "re-upload must not duplicate");

    // Pagination with limit=1 walks the strict cursor over every blob exactly once.
    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            Some(c) => format!("{base}/history/blobs?limit=1&after={c}"),
            None => format!("{base}/history/blobs?limit=1"),
        };
        let pg: serde_json::Value = http
            .get(url)
            .header("X-Privex-Auth", &bob_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        for b in pg["blobs"].as_array().unwrap() {
            assert!(
                seen.insert(b["blob_id"].as_str().unwrap().to_string()),
                "no blob repeats across pages"
            );
        }
        match pg["next"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 2, "pagination visits every blob once");

    // Scoping: Alice (id/token) sees NONE of Bob's history.
    let alice_list: serde_json::Value = http
        .get(format!("{base}/history/blobs"))
        .header("X-Privex-Auth", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        alice_list["blobs"].as_array().unwrap().len(),
        0,
        "history is per-user scoped"
    );

    // Delete-all wipes Bob's history immediately.
    let del: serde_json::Value = http
        .delete(format!("{base}/history/blobs"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del["deleted"], 2);
    let stt3: serde_json::Value = http
        .get(format!("{base}/history/status"))
        .header("X-Privex-Auth", &bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stt3["count"], 0);

    // ===== Option B: device-link rendezvous relay =====
    {
        let rid = rand_hex(16); // 32 hex chars
        let tkt_a = ws_ticket(&http, &base, &bob_token).await;
        let tkt_b = ws_ticket(&http, &base, &bob_token).await;
        let mut a = devlink_connect(addr, &tkt_a, &rid)
            .await
            .expect("devlink A connects");
        let mut b = devlink_connect(addr, &tkt_b, &rid)
            .await
            .expect("devlink B connects");

        // The relay forwards a frame from A to B verbatim (it never reads content).
        a.send(WsMessage::Text(r#"{"t":"hello","pk":"deadbeef"}"#.into()))
            .await
            .unwrap();
        let got = read_text(&mut b)
            .await
            .expect("B receives A's relayed frame");
        assert!(
            got.contains("deadbeef"),
            "relay must forward the frame verbatim"
        );

        // …and back from B to A (A first drains its peer_joined notice).
        b.send(WsMessage::Text(r#"{"t":"enc","d":"AAAA"}"#.into()))
            .await
            .unwrap();
        let mut a_got = read_text(&mut a).await.expect("A receives a frame");
        if a_got.contains("peer_joined") {
            a_got = read_text(&mut a)
                .await
                .expect("A receives B's frame after the join notice");
        }
        assert!(a_got.contains("AAAA"), "relay must forward both directions");

        // A third peer on the same rendezvous id is rejected (room full → closed).
        let tkt_c = ws_ticket(&http, &base, &bob_token).await;
        let mut third = devlink_connect(addr, &tkt_c, &rid)
            .await
            .expect("upgrade ok");
        let closed = matches!(
            tokio::time::timeout(std::time::Duration::from_secs(3), third.next()).await,
            Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) | Ok(Some(Err(_)))
        );
        assert!(
            closed,
            "a third peer must be rejected from a full rendezvous room"
        );

        // Invalid rendezvous id → handshake rejected.
        let tkt_d = ws_ticket(&http, &base, &bob_token).await;
        assert!(
            devlink_connect(addr, &tkt_d, "not-hex").await.is_err(),
            "malformed rendezvous id must be rejected"
        );
    }

    // ===== Hardening: message-send rate limit (120 / 60s per sender) =====
    {
        let (_spammer, sp_token) = register_and_auth(&http, &base).await;
        let mut ok_count = 0;
        let mut got_429 = false;
        for _ in 0..130 {
            let r = http
                .post(format!("{base}/messages/send"))
                .header("X-Privex-Auth", &sp_token)
                .json(&serde_json::json!({ "recipient_id": bob.user_id, "content": b64.encode([1u8; 32]) }))
                .send()
                .await
                .unwrap();
            match r.status().as_u16() {
                200 => ok_count += 1,
                429 => got_429 = true,
                _ => {}
            }
        }
        assert!(
            ok_count <= 120,
            "rate limit must cap accepted sends at 120 (got {ok_count})"
        );
        assert!(
            got_429,
            "must return 429 once the message rate limit is exceeded"
        );
    }

    // Log out everywhere: the token works before, then 401s after revocation.
    assert_eq!(
        http.post(format!("{base}/auth/ws_ticket"))
            .header("X-Privex-Auth", &token)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "token valid before logout_all"
    );
    let lo = http
        .post(format!("{base}/auth/logout_all"))
        .header("X-Privex-Auth", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(lo.status(), 200);
    assert_eq!(
        http.post(format!("{base}/auth/ws_ticket"))
            .header("X-Privex-Auth", &token)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "token must be revoked after logout_all"
    );

    // 7. no PII in logs (now also covers WS identities, ticket, content)
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(password), "password leaked into logs");
    assert!(
        !logs.contains(&recovered_token),
        "recovery token leaked into logs"
    );
    assert!(!logs.contains(&id.user_id), "user_id leaked into logs");
    assert!(!logs.contains(&bob.user_id), "bob user_id leaked into logs");
    assert!(!logs.contains(&token), "session token leaked into logs");
    assert!(!logs.contains(&bob_token), "bob token leaked into logs");
    assert!(!logs.contains(&ticket), "ws ticket leaked into logs");
    assert!(
        !logs.contains(&online_b64),
        "message content leaked into logs"
    );
    assert!(!logs.contains("px_"), "a px_ id leaked into logs");
}

// PVX-06: the revocation cutoff check must fail CLOSED. With Redis unreachable,
// an otherwise-valid session token is rejected by the AuthUser extractor (500,
// treated as transient by clients) instead of silently skipping the check.
// Needs no Docker: lazy PG pool + a Redis pool pointing at a dead port.
#[tokio::test]
async fn revocation_check_fails_closed_when_redis_down() {
    use axum::extract::FromRequestParts;
    use privex_server::auth::extract::AuthUser;
    use privex_server::auth::token;
    use privex_server::state::AppState;
    use privex_server::ws;

    let key = [7u8; 32];
    let config = Config::for_test(
        "postgres://unused:unused@127.0.0.1:1/unused".into(),
        "redis://127.0.0.1:1".into(), // nothing listens here
        key,
        8,
    );
    let state = AppState {
        db: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap(),
        redis: deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap(),
        config: Arc::new(config),
        store: Arc::new(MemoryStore::new()),
        online: Arc::new(ws::state::Online::new()),
        devlink: Arc::new(ws::devlink::DevlinkRooms::new()),
        kt_cache: privex_server::kt_cache::KtCache::new(),
    };

    // Mint with the config-derived token MAC subkey (PVX-24), not the raw root.
    let tok = token::mint(
        &state.config.token_mac_key,
        "px_00000000000000000000000000000001",
        now_unix(),
    );
    let req = axum::http::Request::builder()
        .header("x-privex-auth", &tok)
        .body(())
        .unwrap();
    let (mut parts, _) = req.into_parts();

    let result = AuthUser::from_request_parts(&mut parts, &state).await;
    assert!(
        result.is_err(),
        "a valid token must be REJECTED when the revocation store is unreachable"
    );
}
