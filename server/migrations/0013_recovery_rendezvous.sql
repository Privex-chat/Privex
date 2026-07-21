-- Social-recovery share rendezvous (docs 4.2 path 3 RETRIEVAL). An ephemeral,
-- relationship-free mailbox keyed by a random 128-bit recovery_id that the
-- recovering owner generates and passes to their chosen contacts OUT OF BAND.
-- Each approving contact re-seals the owner's share to the owner's EPHEMERAL
-- recovery key and posts it here; the owner polls until >= threshold shares
-- arrive, then reconstructs the master seed.
--
-- Zero-knowledge properties:
--   * No account id and no contact id is ever stored - only a random bucket key.
--     The server cannot link a post/read to any user, so the C->O recovery
--     relationship never appears server-side (Law 3).
--   * Every blob is sealed to the owner's ephemeral key - opaque to the server.
--   * UNLOGGED + short TTL (48h): transient like message_queue; a crash-truncate
--     just aborts an in-flight recovery (re-runnable), and nothing durable leaks.
CREATE UNLOGGED TABLE IF NOT EXISTS recovery_rendezvous (
    id          BIGSERIAL PRIMARY KEY,
    recovery_id CHAR(32)  NOT NULL CHECK (recovery_id ~ '^[0-9a-f]{32}$'), -- 16 random bytes, hex
    blob        BYTEA     NOT NULL,   -- one share re-sealed to the owner's ephemeral recovery key
    created_at  INTEGER   NOT NULL,   -- unix seconds
    expires_at  INTEGER   NOT NULL    -- created_at + 48h
);
CREATE INDEX IF NOT EXISTS idx_rendezvous_recovery ON recovery_rendezvous (recovery_id);
CREATE INDEX IF NOT EXISTS idx_rendezvous_expires  ON recovery_rendezvous (expires_at);
