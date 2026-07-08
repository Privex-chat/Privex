-- Blob store index (docs 8.3). The encrypted chunks live in the object store
-- (MinIO/R2); this is only the index. UNLOGGED: no WAL writes.
-- NEVER stored: owner, uploader, filename, mime type, content type.
CREATE UNLOGGED TABLE IF NOT EXISTS blob_index (
    chunk_id     VARCHAR(64) PRIMARY KEY,  -- SHA-256(encrypted chunk), hex
    storage_path TEXT        NOT NULL,
    size_bytes   INTEGER     NOT NULL,
    expires_at   INTEGER     NOT NULL,     -- now + 7 days, unix seconds
    downloaded   BOOLEAN     NOT NULL DEFAULT FALSE
);
