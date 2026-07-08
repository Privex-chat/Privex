-- Key directory (docs 8.3 / 4.1). One row per identity. Stores ONLY public
-- keys + rotation timestamps. NEVER: ip, email, phone, name, last_seen,
-- device_info, or any request metadata.
--
-- user_id is `px_` + 32 lowercase hex = 35 chars (audit fix: was CHAR(32)).
-- ik_x25519 is REQUIRED (audit fix): crypto-wasm uses a separate X25519
-- identity key for PQXDH, distinct from the Ed25519 signing IK. Without it,
-- pqxdh_initiate cannot run against a fetched bundle.
--
-- APP-LAYER REQUIREMENT (not enforced by the DB): before calling
-- pqxdh_initiate, the client MUST verify the signed prekey with
--   verify_hybrid(spk_x25519, spk_sig_ed, ik_ed25519, spk_sig_dil, ik_dilithium3)
-- The server cannot and does not verify this.

CREATE TABLE IF NOT EXISTS key_directory (
    user_id        VARCHAR(35) PRIMARY KEY
                       CHECK (user_id ~ '^px_[0-9a-f]{32}$'),
    ik_ed25519     BYTEA   NOT NULL,  -- Ed25519 identity public key (signing)
    ik_dilithium3  BYTEA   NOT NULL,  -- Dilithium3 identity public key (signing)
    ik_x25519      BYTEA   NOT NULL,  -- X25519 identity public key (PQXDH DH)
    spk_x25519     BYTEA   NOT NULL,  -- signed prekey public
    spk_sig_ed     BYTEA   NOT NULL,  -- SPK signed by ik_ed25519
    spk_sig_dil    BYTEA   NOT NULL,  -- SPK signed by ik_dilithium3
    kyber1024_pub  BYTEA   NOT NULL,  -- ML-KEM-1024 public key
    spk_created_at INTEGER NOT NULL,  -- unix seconds (SPK rotation tracking)
    created_at     INTEGER NOT NULL
);
