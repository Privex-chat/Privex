// Typed SQLx query modules. Every query is compile-time checked against the
// live schema (DATABASE_URL) or the .sqlx offline cache.
pub mod blob_index;
pub mod history;
pub mod key_directory;
pub mod kt_log;
pub mod message_queue;
pub mod opaque;
pub mod pow;
pub mod recovery_rendezvous;
pub mod recovery_shares;
pub mod register;
