-- MLS group state (docs 4.6/8.3). Encrypted blob the server cannot read.
-- UNLOGGED: no WAL writes.
CREATE UNLOGGED TABLE group_state (
    group_id        VARCHAR(64) PRIMARY KEY,
    epoch           INTEGER  NOT NULL DEFAULT 0,
    encrypted_state BYTEA    NOT NULL,  -- AES-256-GCM, key held by group members
    member_count    SMALLINT NOT NULL,
    updated_at      INTEGER  NOT NULL   -- unix seconds
);
