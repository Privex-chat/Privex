-- OPAQUE records (docs 4.2/6/8.3). The server holds the OPRF record + an
-- encrypted key envelope it CANNOT decrypt without the user's password.
-- NEVER stored: password, password hash, or any function of the password.
CREATE TABLE IF NOT EXISTS opaque_records (
    user_id      VARCHAR(35) PRIMARY KEY
                     REFERENCES key_directory(user_id) ON DELETE CASCADE,
    oprf_record  BYTEA   NOT NULL,  -- OPAQUE server OPRF record (blinded)
    envelope     BYTEA   NOT NULL,  -- encrypted key material (unreadable to server)
    envelope_mac BYTEA   NOT NULL,  -- auth tag for envelope integrity
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL   -- updated on password change
);
