-- Relay node directory (docs 5.2/8.3). This is INFRASTRUCTURE metadata about
-- operator-run relay nodes - NOT users. The address/last_seen here describe
-- relay health, not any user; no user IP is ever stored anywhere.
CREATE TABLE relay_nodes (
    node_id      VARCHAR(32) PRIMARY KEY,
    pubkey       BYTEA       NOT NULL,
    address      TEXT        NOT NULL,  -- relay IP:Port (a relay, not a user)
    region       VARCHAR(16),
    jurisdiction VARCHAR(64),
    operator     VARCHAR(64),           -- 'Privex' | volunteer_id_hash
    is_bridge    BOOLEAN     NOT NULL DEFAULT FALSE,
    last_seen    INTEGER     NOT NULL   -- relay liveness, unix seconds
);
