// Object storage abstraction. Production uses S3-compatible storage (MinIO
// locally, Cloudflare R2 in prod). Tests use an in-memory store so blob round
// trips are deterministic without a running MinIO.
//
// The store holds ONLY content-addressed encrypted chunks keyed by their
// SHA-256. No filename, MIME type, owner, or any plaintext metadata.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::async_trait;

use crate::config::Config;

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

// --- in-memory (tests / explicit test config) ---

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.inner.lock().unwrap().insert(key.to_string(), bytes);
        Ok(())
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }
}

// --- S3-compatible (MinIO / R2) ---

pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Store {
    pub fn from_config(config: &Config) -> Self {
        use secrecy::ExposeSecret;
        let creds = aws_sdk_s3::config::Credentials::new(
            config.r2_access_key.expose_secret(),
            config.r2_secret_key.expose_secret(),
            None,
            None,
            "privex",
        );
        let conf = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .endpoint_url(&config.r2_endpoint)
            .region(aws_sdk_s3::config::Region::new(config.r2_region.clone()))
            .credentials_provider(creds)
            .force_path_style(true) // required for MinIO
            .build();
        S3Store {
            client: aws_sdk_s3::Client::from_conf(conf),
            bucket: config.r2_bucket.clone(),
        }
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
            .send()
            .await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => {
                let data = out.body.collect().await?.into_bytes().to_vec();
                Ok(Some(data))
            }
            Err(err) => {
                let svc = err.into_service_error();
                if svc.is_no_such_key() {
                    Ok(None)
                } else {
                    Err(svc.into())
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }
}
