-- Proof-of-Work registration challenges (docs 8.5). Replaces IP-based rate
-- limiting - no IP ever needed. UNLOGGED: no WAL writes.
CREATE UNLOGGED TABLE IF NOT EXISTS pow_challenges (
    challenge_id   UUID     PRIMARY KEY DEFAULT gen_random_uuid(),
    difficulty     SMALLINT NOT NULL,   -- leading zero bits required
    challenge_data BYTEA    NOT NULL,   -- random bytes to hash
    issued_at      INTEGER  NOT NULL,
    expires_at     INTEGER  NOT NULL,   -- issued_at + 30 minutes
    used           BOOLEAN  NOT NULL DEFAULT FALSE
);
