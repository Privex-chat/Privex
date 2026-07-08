-- Message queue (docs 8.3). Sealed Sender blobs awaiting delivery. Hard-deleted
-- on ACK; never kept after delivery. UNLOGGED: no WAL writes.
-- NEVER stored: sender_id, message_type, read_status.
CREATE UNLOGGED TABLE IF NOT EXISTS message_queue (
    message_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_id VARCHAR(35) NOT NULL CHECK (recipient_id ~ '^px_[0-9a-f]{32}$'),
    content      BYTEA       NOT NULL,  -- Sealed Sender encrypted blob
    csam_proof   BYTEA,                 -- ZK proof (image messages only)
    queued_at    INTEGER     NOT NULL,  -- unix seconds
    expires_at   INTEGER     NOT NULL,  -- queued_at + 30 days
    size_bytes   INTEGER     NOT NULL
);
CREATE INDEX idx_queue_recipient ON message_queue (recipient_id);
