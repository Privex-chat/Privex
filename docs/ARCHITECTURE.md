# Privex Architecture

Privex is a zero-knowledge, end-to-end encrypted communication platform. The server is architecturally (not policy) blind - it cannot read messages, identify users, or trace relationships.

## Phase 1 (Web App) Tech Stack

- **Frontend:** React 18 + TypeScript 5 (strict) + Vite 5 + Tailwind 3
- **State Management:** Zustand 4
- **Local Database:** Dexie.js 3 (IndexedDB ORM) for local encrypted storage
- **Service Worker:** Workbox 7
- **Protobuf:** protobufjs 7 (for binary serialization of payloads)
- **Backend:** Rust (edition 2021) + Axum 0.7 + Tokio 1
- **Database:** PostgreSQL 16 (using SQLx 0.7 for compile-time query verification)
- **Cache / Ephemeral Storage:** Redis 7.2 (deadpool-redis, NO persistence)
- **TLS:** rustls (pure Rust - zero OpenSSL dependency)
- **Reverse Proxy:** Nginx (or Caddy 2 with access logs disabled)

## Core Design Principles

1. **Zero Knowledge by Architecture**: Privex does not rely on trust or privacy policies. It relies on cryptographic guarantees.
2. **Zero Plaintext**: No plaintext user data is ever stored on the server.
3. **Zero IP Logging**: IP addresses are never logged or stored. Not even temporarily.
4. **WASM Cryptography**: All heavy cryptography runs natively in the browser via WebAssembly or the Web Crypto API.

## Data Flow & Storage

### Server-Side
- **PostgreSQL**: Stores ONLY encrypted blobs, public keys, and cryptographic commitments.
- **Unlogged Tables**: Crucial tables like the `message_queue` and `history_blobs` are explicitly marked as `UNLOGGED` in PostgreSQL. This prevents them from being written to the Write-Ahead Log (WAL), meaning data is ephemeral and cannot be recovered from disk forensics after deletion.
- **Redis**: Configured with `save ""` and `appendonly no`. It operates purely in-memory and handles short-lived state (like WebSockets routing and Proof of Work challenges) without touching the disk.

### Client-Side
- **IndexedDB**: The primary storage for message history, session states, and keys on the device.
- **WebCrypto API**: Secures the local IndexedDB database using a non-extractable master key.

## Cryptographic Stack

- **Key Exchange & Double Ratchet:** `@signalapp/libsignal-client` (WASM build).
- **Post-Quantum Cryptography (PQC):** Kyber (ML-KEM) and Dilithium (ML-DSA) via `liboqs` encapsulated in a custom Rust-to-WASM package (`@privex/crypto-wasm`).
- **Symmetric Crypto:** AES-256-GCM, XChaCha20, HKDF, random bytes via `libsodium-wasm`.
- **Account Recovery:** OPAQUE protocol (via `opaque-ts`) combined with custom Shamir's Secret Sharing over GF(256).
- **Proof of Work:** Custom Hashcash SHA-256 to rate-limit unauthenticated endpoints without using IPs.

## Message Lifecycle (Sealed Sender)

Privex uses the **Sealed Sender** protocol to prevent the server from knowing who is talking to whom.
1. The sender encrypts the message content using the recipient's public keys (Double Ratchet + PQC).
2. The sender's identity (their ID and a certificate proving they are allowed to message the recipient) is encrypted *inside* the payload.
3. The message is padded to a fixed 1024-byte boundary to obscure message length.
4. The server routes the opaque blob to the recipient's queue without knowing the sender.
5. The recipient decrypts the outer layer, verifies the sender certificate, and then decrypts the actual message.
