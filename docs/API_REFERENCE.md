# Privex API Reference

**Base URL**: `https://privex.chat/v1` (Accessed natively or via Nym/onion routing)

Privex's API is designed around zero-knowledge principles. The server acts as a blind relay and directory. It never sees plaintext payloads or caller identities.

## Authentication Endpoints

All authenticated requests use a 24-hour session token. The token is derived from a Zero-Knowledge Signed Challenge.

- `POST /auth/challenge`: Returns a 32-byte cryptographic challenge with a 90-second TTL.
- `POST /auth/verify`: Submits Ed25519 and CRYSTALS-Dilithium3 signatures over the challenge. Returns a 24-hour session token.
- `POST /auth/pow_challenge`: Returns a dynamic Proof-of-Work (PoW) challenge used for rate limiting public endpoints without requiring IP addresses.

## Key Management Endpoints

Key endpoints are PoW-gated to prevent enumeration attacks and preserve privacy.

- `POST /keys/register`: Registers identity keys (Ed25519, Dilithium3, X25519, Kyber). Requires PoW.
- `POST /keys/{user_id}`: Fetches public keys and an One-Time Pre-Key (OPK) for a user to initiate a chat. Requires PoW.
- `POST /keys/prekeys/replenish`: Replenishes the user's OPKs on the server.
- `POST /keys/spk/rotate`: Rotates the user's Signed Pre-Key.
- `POST /keys/kt/proof/{user_id}`: Fetches a Merkle inclusion proof for a user's keys from the Key Transparency log. Requires PoW.

## Messaging Endpoints

- `POST /messages/send`: Sends an encrypted Sealed Sender blob. The server does not know who the sender is.
- `POST /messages/ack`: Acknowledges receipt of messages, immediately deleting them from the server's unlogged queue.
- `GET /messages/poll`: Polling endpoint returning exactly a fixed number of items (real messages + dummy padding) to prevent traffic analysis.
- `POST /messages/ttl_preference`: Sets the default Time-To-Live (TTL) for queued messages (e.g., 30 or 60 days).

## Blob Store Endpoints

File attachments are chunked, encrypted locally, and assigned random chunk IDs before upload.

- `POST /blobs/{chunk_id}`: Upload an encrypted file chunk.
- `GET /blobs/{chunk_id}`: Retrieve an encrypted file chunk.
- `DELETE /blobs/{chunk_id}`: Delete a chunk.

## Account Recovery Endpoints (OPAQUE)

Privex uses the OPAQUE protocol for password-based account recovery, ensuring the server never sees the password or its hash.

- `POST /recovery/opaque/init`: Starts OPAQUE login flow. Requires PoW.
- `POST /recovery/opaque/complete`: Completes OPAQUE login, returning a session token.
- `POST /recovery/opaque/register/start`: Begins the OPAQUE registration flow.
- `POST /recovery/opaque/register/finish`: Completes OPAQUE registration.
- `GET /recovery/opaque/status`: Check recovery status.
- `DELETE /recovery/opaque`: Delete recovery data.

## WebSockets

**Endpoint**: `wss://privex.chat/v1/ws`

WebSockets are used for real-time delivery and are authenticated via the `X-Privex-Auth` header.

- **Server → Client Events**: 
  - `message` (encrypted Sealed Sender blob)
  - `prekey_low` (alert to replenish OPKs)
  - `key_change_alert` (contact's keys changed)
  - `ping`
- **Client → Server Events**: 
  - `ack` (acknowledge message receipt)
  - `pong` (keep-alive, every 30s)
