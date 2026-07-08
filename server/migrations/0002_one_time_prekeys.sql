-- One-time prekeys (docs 4.1/4.3). Each is served exactly once then deleted by
-- the application. 100 uploaded at registration, replenished when low.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    user_id        VARCHAR(35) NOT NULL
                       REFERENCES key_directory(user_id) ON DELETE CASCADE,
    opk_id         INTEGER NOT NULL,
    opk_x25519_pub BYTEA   NOT NULL,
    PRIMARY KEY (user_id, opk_id)
);
