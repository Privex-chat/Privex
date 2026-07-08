-- Key Transparency log (docs 8.2/8.3). Append-only, hash-chained. UNLOGGED:
-- no WAL writes. A signed root is computed periodically and published.
CREATE UNLOGGED TABLE IF NOT EXISTS kt_log (
    seq         BIGSERIAL   PRIMARY KEY,
    user_id     VARCHAR(35) NOT NULL CHECK (user_id ~ '^px_[0-9a-f]{32}$'),
    bundle_hash VARCHAR(64) NOT NULL,  -- SHA-256(full key bundle), hex
    operation   VARCHAR(16) NOT NULL
                    CHECK (operation IN ('register', 'spk_rotate', 'opk_replenish')),
    timestamp   INTEGER     NOT NULL,  -- unix seconds
    prev_hash   VARCHAR(64)            -- hash of previous entry (chain integrity)
);
