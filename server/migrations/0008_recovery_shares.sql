-- Shamir recovery shares (docs 4.2 path 3 / 8.3). Each share is encrypted to a
-- contact's public key. The server stores only opaque blobs and does NOT know
-- which users are whose contacts (contact px_ids are NOT stored here).
CREATE TABLE IF NOT EXISTS recovery_shares (
    user_id         VARCHAR(35) NOT NULL
                        REFERENCES key_directory(user_id) ON DELETE CASCADE,
    share_index     SMALLINT NOT NULL,
    encrypted_share BYTEA    NOT NULL,  -- XChaCha20-Poly1305(contact_IK, share)
    PRIMARY KEY (user_id, share_index)
);
