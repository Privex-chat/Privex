-- Server-side encrypted chat-history backup (docs note: history sync Option A).
-- OPT-IN, off by default. Each row is an opaque AES-256-GCM blob encrypted under
-- the user's history_key = HKDF(master_seed, "privex_history_v1"); the server can
-- NEVER read it. The only metadata exposed is per-user blob count / volume - the
-- documented tradeoff of enabling backup.
--
-- LOGGED (NOT unlogged like message_queue): a backup that vanishes on a Postgres
-- crash/restart is not a backup, and the new-device restore would silently fail.
-- The blobs are ciphertext, so the WAL only ever holds unreadable bytes - the
-- no-WAL rule exists for transient queues, not for durable opt-in backup. Mirrors
-- recovery_shares (also durable encrypted blobs, FK + CASCADE).
--
-- Deletion (one user via CASCADE, or DELETE FROM ... WHERE user_id) is immediate
-- and permanent. No soft delete.
CREATE TABLE IF NOT EXISTS history_blobs (
    user_id    VARCHAR(35) NOT NULL
                   REFERENCES key_directory(user_id) ON DELETE CASCADE,
    blob_id    VARCHAR(64) NOT NULL,   -- client msg_id, or "contact:<px_id>" (idempotent re-upload)
    ciphertext BYTEA       NOT NULL,
    created_at INTEGER     NOT NULL,
    PRIMARY KEY (user_id, blob_id)
);

-- Pagination: ORDER BY (created_at, blob_id) with a strict composite cursor.
CREATE INDEX IF NOT EXISTS history_blobs_user_created ON history_blobs (user_id, created_at, blob_id);
