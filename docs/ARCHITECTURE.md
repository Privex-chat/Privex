# Privex Architecture

Privex is a zero-knowledge, end-to-end encrypted communication platform. The server is **architecturally** (not policy) blind — it cannot read messages, identify users, or trace relationships. This document describes the complete design: what is built, what is planned, and what the known limitations are.

---

## Table of Contents

1. [Core Design Laws](#1-core-design-laws)
2. [Threat Model](#2-threat-model)
3. [Phase Status](#3-phase-status)
4. [Tech Stack](#4-tech-stack)
5. [Cryptographic Architecture](#5-cryptographic-architecture)
6. [Message Lifecycle](#6-message-lifecycle)
7. [Account Recovery](#7-account-recovery)
8. [Transport & Anonymity Layer](#8-transport--anonymity-layer)
9. [Server Architecture](#9-server-architecture)
10. [File & Media Encryption](#10-file--media-encryption)
11. [Group Messaging](#11-group-messaging)
12. [Calls — Audio & Video](#12-calls--audio--video)
13. [Delivery & Read Receipts](#13-delivery--read-receipts)
14. [Offline Message Delivery](#14-offline-message-delivery)
15. [Cross-Device Sync & History](#15-cross-device-sync--history)
16. [Rate Limiting & Anti-Abuse](#16-rate-limiting--anti-abuse)
17. [CSAM Protection](#17-csam-protection)
18. [Key Transparency Log](#18-key-transparency-log)
19. [Time Synchronization](#19-time-synchronization)
20. [Infrastructure](#20-infrastructure)
21. [Honest Limitations](#21-honest-limitations)

---

## 1. Core Design Laws

```
Law 1: The server CANNOT read content.
        Not "does not." CANNOT. Cryptographically, architecturally.

Law 2: The server CANNOT identify users.
        No names, no phone numbers, no email. Identity = public key only.
        Under no legal compulsion can Privex produce a real identity.

Law 3: The server CANNOT trace relationships.
        Sealed Sender: server sees only the recipient, never the sender.
        Social graph does not exist on the server.

Law 4: The network CANNOT confirm Privex is being used.
        ISP, DNS provider, VPS host — none of them can distinguish
        Privex traffic from other encrypted traffic. (Phase 2 target.)
```

---

## 2. Threat Model

### Adversaries and Their Capabilities

| Adversary | What They Can Do | Privex Defense | Result |
|---|---|---|---|
| ISP (Phase 1) | See connection to api.privex.io | HTTPS only | **ISP can confirm Privex is used in Phase 1. Resolved in Phase 2 via Nym.** |
| ISP (Phase 2+) | See encrypted packets to Nym gateway | Nym mixnet hides destination and content | ISP sees: "user connected to Nym." Nothing about Privex. |
| VPS Host | Physical server access, disk images | LUKS2 encrypted volumes, UNLOGGED tables, tmpfs /var/log | Host sees: encrypted storage, relay IPs, no user data |
| Compromised Server | Full DB + memory access | Pseudonymous IDs, encrypted blobs, HMAC-wrapped rate limit keys | Nothing useful. No real identities. No message content. |
| Legal Order | Court-compelled disclosure | Iceland jurisdiction. Architecture has nothing to produce. | Empty-handed even with full cooperation. |
| Man-in-the-Middle | Intercept/modify traffic | TLS 1.3 + rustls, certificate pinning, HKDF auth tags | Cannot inject or modify. |
| Global Passive Adversary | Watch both ISP connections, correlate timing | Nym Poisson delays, cover traffic, fixed polling schedule | Timing correlation computationally infeasible (Phase 2). |
| Quantum Computer (future) | Break classical DH/ECDSA | Kyber-1024 + Dilithium3 hybrid from day one | "Harvest now, decrypt later" fails. PQC on all sessions. |
| Endpoint Malware (root) | Read app memory, keystrokes | Secure Enclave / Keystore non-extractable keys | Best-effort. Kernel-level compromise is out of scope for software. |

### What the Server Has Under Court Order

```
AVAILABLE (even under subpoena with full cooperation):
  px_[32hex]    — pseudonymous user ID (not linked to any real identity)
  Public keys   — by design, these are public
  Encrypted blobs — unreadable without keys the server does not hold

NOT AVAILABLE (architecturally impossible to produce):
  Real name, phone, email, IP address
  Who any user talked to
  What any message said
  When any specific user was online
  Any message content, file content, or call recording
```

---

## 3. Phase Status

```
PHASE 1 — WEB APP (current):
  ✓ Working: 1:1 messaging, file transfers, offline delivery, PWA,
             OPAQUE recovery, multi-device linking, history transfer
  ~ Skeleton: Cover traffic (code exists, not active)
  ~ Skeleton: Nym integration (worker exists, direct WebSocket for now)
  ✗ Not built: Audio/video calls, delivery receipts, time sync,
               fixed polling, per-user rate limiting (post-registration)

PHASE 2 — METADATA PERFECTION:
  Nym mixnet transport (replacing direct WebSocket)
  Cover traffic (Poisson-distributed dummy messages)
  Censorship circumvention (obfs4, Snowflake, domain fronting, bridges)
  DNS-over-HTTPS (hardcoded, no OS DNS resolver)
  CSAM protection (PDQ + PSI + ZK proofs)
  Fixed polling + constant fetch size
  Jittered receipt sending

PHASE 3 — CALLS & MOBILE:
  Audio calls (WebRTC + SFrame)
  Android app (React Native)
  Oblivious TURN relay

PHASE 4 — DESKTOP & HARDENING:
  iOS app
  Desktop app (Tauri)
  Argon2id hybrid PoW
  Full independent security audit

PHASE 5 — DECENTRALIZATION:
  Volunteer relay node network (libp2p-based)
  Community Nym gateway nodes
  Video calls
```

---

## 4. Tech Stack

### Frontend (Web App — Primary Platform)

| Component | Technology | Purpose |
|---|---|---|
| UI Framework | React 18 + TypeScript 5 (strict) | Application UI |
| Build Tool | Vite 5 | Build, HMR, WASM support |
| Styling | Tailwind CSS 3 | Utility-first, zero runtime JS |
| State | Zustand 4 | In-memory app state (session tokens, keys never hit localStorage) |
| Local DB | Dexie.js 3 (IndexedDB) | Encrypted local message/key storage |
| Service Worker | Workbox 7 | Offline support, background sync, push handling |
| Crypto (WASM) | @privex/crypto-wasm (Rust → WASM) | All heavy cryptography |
| Signal Protocol | @signalapp/libsignal-client | PQXDH + Double Ratchet |
| Symmetric Crypto | libsodium-wasm | AES-GCM, XChaCha20, HKDF, CSPRNG |
| Recovery | opaque-ts | OPAQUE password recovery (browser) |
| Serialization | protobufjs 7 | Binary message format |
| Nym Transport | @nymproject/sdk-full-fat | Nym mixnet client (Phase 2) |

### Backend

| Component | Technology | Purpose |
|---|---|---|
| Language | Rust (edition 2021) | Memory safety, deterministic cleanup of key material |
| Web Framework | Axum 0.7 + Tokio 1 | Async HTTP + WebSocket |
| Database Driver | SQLx 0.7 | Compile-time SQL verification |
| TLS | rustls | Pure Rust TLS — zero OpenSSL |
| Redis | deadpool-redis | Sessions, rate limits, PoW challenges (RAM only) |
| Object Storage | Cloudflare R2 (Phase 1), Dataship (Phase 3+) | Encrypted blob storage |
| Reverse Proxy | Caddy 2 (`output discard`) | HTTPS termination, zero access logs |

---

## 5. Cryptographic Architecture

### Identity — Hybrid Post-Quantum

Every identity is a set of keypairs generated **on-device only**. The server never participates in key generation.

```
Classical Identity:    Ed25519  (libsodium)
PQ Identity:           CRYSTALS-Dilithium3 / ML-DSA (NIST FIPS 204, liboqs)
Key Exchange:          X25519 + CRYSTALS-Kyber-1024 / ML-KEM (NIST FIPS 203, liboqs)

Hybrid signing (all identity assertions use both):
  sig = Ed25519_sign(data, ed_priv) || Dilithium3_sign(data, dil_priv)
  verify: BOTH must be valid

Pseudonymous User ID:
  px_id = hex(SHA-256(ed25519_public_key)[0:16])
  Example: px_4a3f8c2b1d7e9f0a6b5c3d2e1f4a8b9c
  Server holds: this ID + public keys. Nothing else. Ever.
```

### PQXDH — Post-Quantum Key Exchange

Signal's PQXDH specification: X3DH (classical) + Kyber-1024 (post-quantum) hybrid.

```
DH1 = X25519(IK_A, SPK_B)
DH2 = X25519(EK_A, IK_B)
DH3 = X25519(EK_A, SPK_B)
DH4 = X25519(EK_A, OPK_B)  // if OPK available
X3DH_secret = HKDF(DH1 || DH2 || DH3 || DH4)

(Kyber_ciphertext, Kyber_secret) = Kyber1024_Encapsulate(Kyber_B_pub)

SharedSecret = HKDF(X3DH_secret || Kyber_secret, info="PQXDH_v1_final")
               ▲ Classical security  ▲ Quantum security

Security: Breaking a session requires breaking BOTH X3DH AND Kyber simultaneously.
          A quantum computer breaks X3DH but not Kyber.
```

Library: `@signalapp/libsignal-client` (canonical, audited). Not reimplemented.

### Double Ratchet

Every message gets a unique key, deleted after use. Past messages safe even if current keys leak (forward secrecy). Future messages safe even after a breach (break-in recovery).

```
Message padding: all messages padded to nearest 1024-byte boundary BEFORE encryption.
Prevents: message length leaking conversation context.
```

### Sealed Sender

Server sees only the recipient. Sender identity is encrypted **inside** the message body.

```
Outer envelope (visible to server):
  { recipient_id: "px_[bob]", content: [opaque bytes] }

Inner payload (decryptable only by Bob):
  { sender_cert: { sender_id, sender_pub_keys, valid_until, sig_ed, sig_dil },
    message: [Double Ratchet encrypted content] }

Server learns: someone sent Bob something.
Server does NOT learn: who Alice is, what it says, what type of message.
```

Anti-spoofing: both Ed25519 and Dilithium3 signatures on sender cert must be valid.

---

## 6. Message Lifecycle

```
ALICE sends "Hey Bob":

1. WASM pads plaintext to 1024-byte boundary (random padding bytes)
2. WASM encrypts with Double Ratchet → ciphertext + ratchet key advances
3. WASM wraps ciphertext in Sealed Sender → only Bob can unwrap sender identity
4. Client POST /messages/send { recipient_id: "px_[bob]", content: [sealed blob] }
   (Phase 2: this POST goes through Nym mixnet before reaching server)
5. Server stores in UNLOGGED message_queue (if Bob offline) or pushes via WebSocket
6. Bob's client receives via WebSocket
7. Bob's WASM: Sealed Sender decrypt → verify sender cert → Double Ratchet decrypt
8. Bob's client: POST /messages/ack → server hard-deletes immediately
9. Message no longer exists on server after ack

SERVER AT ALL TIMES KNOWS:
  recipient_id (needed for routing)
  Encrypted blob size (normalized by padding — always ~1024 bytes)

SERVER NEVER KNOWS:
  Sender identity
  Message content
  Message type
  Whether this is a real message or cover traffic
```

---

## 7. Account Recovery

Four independent recovery paths. All zero-knowledge from the server's perspective.

### Path 1: OPAQUE Password Recovery (Primary)

OPAQUE (IETF CFRG draft): server never learns the password or any function of it.

```
Server stores: OPRF_record + encrypted_envelope + envelope_mac
Server cannot: decrypt envelope without user's password
               run offline dictionary attack without the OPRF key

Recovery: any new device + password only → full key material restored
Library: opaque-ke (Rust server), opaque-ts (browser)
```

### Path 2: Multi-Device Linking (Easiest)

QR-code-based device pairing. Keys transferred device-to-device via ephemeral X25519 channel. Server routes encrypted blobs only. Server cannot read the transfer.

### Path 3: Emergency Recovery Contacts (Social)

Designate 2–3 trusted Privex contacts. Master key split via Shamir's Secret Sharing (2-of-3 threshold). Each share encrypted to a contact's public key. Server stores only encrypted blobs. Server cannot reconstruct the key. Recovery requires 2 contacts to actively approve in-app.

### Path 4: Seed Phrase (Power User Fallback)

24-word BIP-39 mnemonic generated at registration. Stored nowhere by Privex. Deterministically regenerates all keypairs. Optional — user chooses to write it down.

```
Recovery order (try in order):
  1. OPAQUE (password) — any device, any time
  2. Linked device — requires another device still active
  3. Emergency contacts — requires 2 of 3 contacts to approve
  4. Seed phrase — requires the 24 words written down at registration
```

---

## 8. Transport & Anonymity Layer

### Phase 1 — Direct WebSocket

All traffic goes directly to `api.privex.io` via HTTPS/WSS. ISP can see the connection to Privex. Content is encrypted. Identities are hidden. **Law 4 is not satisfied in Phase 1.**

### Phase 2 — Nym Mixnet

Nym defeats timing correlation attacks that Tor cannot. The key difference: Nym batches, shuffles, and delays packets at each mix node (Poisson delays: 50–200ms). Even a global passive adversary watching both ends of the network cannot correlate Alice's send with Bob's receive.

```
Alice's device
  → Nym entry gateway (knows Alice's IP, NOT destination)
  → Mix node 1 → Mix node 2 → Mix node 3 (Poisson delays, shuffle)
  → Privex Nym exit gateway (knows destination, NOT Alice)
  → Privex server (sees: encrypted blob from Nym exit. Not Alice. Not Alice's IP.)
```

All message traffic, file uploads, and key operations route through Nym in Phase 2. Calls use direct WebRTC (latency-sensitive — see Section 12).

### Cover Traffic

Poisson-distributed dummy messages sent from the client at all times:
- Same size as real messages (1024 bytes, padded)
- Same endpoint, same format
- Server receives them, finds no matching mailbox, silently drops them
- Observer cannot distinguish real messages from cover traffic

```
Levels (user-configurable):
  Low:    Poisson(λ=1/30s) — minimal battery drain
  Medium: Poisson(λ=1/10s) — default
  High:   Poisson(λ=1/3s)  — maximum protection
```

### Timing Analysis Mitigations (Phase 2)

```
Mitigation 1 — Fixed polling schedule:
  Client polls /messages/poll every 30 minutes regardless of push notifications.
  Observer cannot distinguish "Bob connected because a message arrived" from
  "Bob connected on schedule."

Mitigation 2 — Constant fetch size:
  Every poll returns exactly N=10 items (real messages + dummy padding).
  Observer cannot infer message volume from response size.

Mitigation 3 — Jittered receipt sending:
  Receipts are queued and sent at the next Poisson cover traffic tick.
  Not sent immediately on message receipt.
  Receipt timing decoupled from message delivery timing.

Mitigation 4 — Delivery windows (opt-in, high-threat):
  Messages held until next 6-hour UTC window (00:00, 06:00, 12:00, 18:00).
  Adversary cannot correlate send time to receive time.
  Trade-off: up to 6-hour delivery delay.
```

### Censorship Circumvention (Phase 2)

Connection cascade, tried in order:

```
1. Direct Nym WebSocket
2. Domain fronting via Cloudflare CDN
3. Hardcoded bridge nodes (10 embedded, XOR-obfuscated in binary)
4. obfs4 (random-noise obfuscation — GFW-tested)
5. Snowflake (WebRTC disguise — virtually unblockable)
6. Manual bridge entry (out-of-band distribution)
```

### DNS Protection (Phase 2)

App does not use the OS system DNS resolver. All DNS via hardcoded DNS-over-HTTPS (Cloudflare 1.1.1.1, Quad9 fallback). ISP DNS provider sees zero queries from Privex sessions.

---

## 9. Server Architecture

### What the Server Stores

```
key_directory:          px_id → public keys (pseudonymous, no real identity)
message_queue:          recipient_id → encrypted blob (UNLOGGED, deleted on ack)
blob_index:             SHA-256(enc_chunk) → storage path (UNLOGGED, deleted after download)
group_state:            group_id → encrypted MLS state (server cannot decrypt)
opaque_records:         px_id → OPRF record + encrypted envelope (server cannot decrypt)
kt_log:                 Merkle tree of all key operations (UNLOGGED, auto-repaired at startup on crash)
recovery_shares:        px_id → encrypted Shamir shares (server cannot decrypt)
history_blobs:          px_id → encrypted history blobs (UNLOGGED, OPT-IN ONLY)
linked_devices:         px_id → device public keys (UNLOGGED)
pow_challenges:         challenge_id → difficulty + expiry (UNLOGGED, 30 min TTL)
```

### What the Server Never Stores

```
Real name, email, phone number, IP address, last seen, message content,
file content, sender identity, social graph, call participants or duration,
passwords or functions of passwords, private keys
```

### Critical PostgreSQL Configuration

```sql
-- Critical tables are UNLOGGED: no Write-Ahead Log trace.
-- Forensic disk analysis of WAL cannot recover these tables.
CREATE UNLOGGED TABLE message_queue (...);
CREATE UNLOGGED TABLE blob_index (...);
CREATE UNLOGGED TABLE kt_log (...);
CREATE UNLOGGED TABLE history_blobs (...);
CREATE UNLOGGED TABLE linked_devices (...);
CREATE UNLOGGED TABLE pow_challenges (...);
```

```
postgresql.conf:
  wal_level = minimal       # Minimum WAL for crash recovery only
  archive_mode = off        # No WAL archiving
  log_statement = none      # No query logging
  log_connections = off     # No connection logging
```

### Critical Redis Configuration

```
save ""                     # No RDB snapshots — never touches disk
appendonly no               # No AOF log — in-memory only
maxmemory-policy allkeys-lru
```

### Critical Caddy Configuration

```
log {
  output discard            # Access logs never created. Not "deleted" — never created.
}
# Strips X-Real-IP and X-Forwarded-For before passing to server.
# Server never receives client IP even in headers.
```

### Session Token Security

Session tokens include `spk_version`. When a user rotates their Signed Pre-Key:
- `spk_version` increments in the database
- All existing tokens with old `spk_version` return 401 immediately
- This implements "log out everywhere" without storing a token revocation list

---

## 10. File & Media Encryption

```
SEND:
1. Client generates random 32-byte CEK (Content Encryption Key)
2. Split file into 4MB chunks
3. For each chunk:
   chunk_key = HKDF(CEK, "chunk" || i)
   nonce = CSPRNG(12 bytes)
   enc_chunk = AES-256-GCM(chunk_key, chunk_data, nonce)
   chunk_id = SHA-256(enc_chunk)  ← content-addressed, opaque to server
4. Upload enc_chunk to blob store at chunk_id
5. Build File Manifest (NOT uploaded — sent as encrypted message):
   { filename_enc, mime_type_enc, total_size, sha256_plaintext, chunks: [...], cek: WrappedCEK }
6. CEK wrapped with recipient's X25519 public key (ephemeral wrap)
7. Send manifest via Sealed Sender message to recipient

RECEIVE:
1. Receive manifest via Sealed Sender
2. Unwrap CEK with own X25519 private key
3. Download encrypted chunks by chunk_id
4. Decrypt each chunk
5. Verify: SHA-256(reassembled) == manifest.sha256_plaintext
   If mismatch: REJECT (tampering detected)

SERVER AT ALL TIMES:
  Blob store contains: chunk_id → random-looking encrypted bytes
  Server does NOT know: filename, MIME type, file size, owner, uploader, recipient
```

Media thumbnails are generated **before** encryption. Server never sees the image.

---

## 11. Group Messaging

Privex uses MLS (Messaging Layer Security, RFC 9420) for group E2EE.

```
Up to 500 members:   Full MLS (OpenMLS, RFC 9420 compliant)
                     O(log N) complexity for add/remove
                     Forward secrecy: removed members cannot read future messages

500–5000 members:    Sender Keys model
                     Less perfect forward secrecy than MLS, practical at scale

> 5000 members:      Not supported in Phase 1
```

MLS operates with **epochs**: every add/remove/update derives a new group secret. Previous epoch keys are deleted. Server stores only the encrypted MLS state — it cannot decrypt group messages.

---

## 12. Calls — Audio & Video

**Status: Phase 3 (audio), Phase 4 (video). Not implemented in Phase 1.**

### Call Signaling (Zero Metadata)

Call invites, SDP offers, and ICE candidates travel as **Sealed Sender messages** through the normal message channel (via Nym in Phase 2). Server has no call record, no participants, no duration. A call invite is indistinguishable from a regular message at the server level.

### Media Encryption — Double Layer

```
Layer 1 — DTLS-SRTP (WebRTC default transport encryption)
Layer 2 — SFrame (RFC 9605 application-layer E2EE)
          Encrypts each video/audio frame before it enters WebRTC stack.
          Even the TURN relay cannot read call content.
          SFrame keys derived from PQXDH shared secret.
```

### NAT Traversal — Oblivious TURN

```
TURN authentication: ephemeral HMAC tokens, 60-second validity
  username = unix_timestamp + ":" + CSPRNG(8 bytes)
  password = HMAC-SHA256(turn_secret, username)

TURN sees: DTLS-SRTP + SFrame encrypted streams
TURN does NOT see: caller identity, callee identity, call content
TURN logging: disabled (log-file=/dev/null in coturn config)

Default: TURN-only mode. Local IP never included in ICE candidates.
Optional: Direct P2P (user opt-in). Reveals local IP to peer only, not server.
```

### Known Call Limitation

The TURN relay sees the IP addresses of both call participants during a call. TURN authentication is not linked to user identity. TURN does not log. Call content is E2EE via SFrame. But IP-level call pairing through TURN is an acknowledged limitation. This is the same tradeoff Signal, Wire, and every other E2EE calling app makes. Content is protected. IP-level pairing through the relay is not.

---

## 13. Delivery & Read Receipts

Receipts are **Sealed Sender messages** — indistinguishable from regular messages at the network level.

```
HOW IT WORKS:
1. Alice sends a message. Inside the encrypted payload:
   { message: "...", receipt_token: CSPRNG(32 bytes), return_address: px_[alice] }

2. Bob's device receives and decrypts.
   Immediately queues a "delivered" receipt in local outbox.
   Does NOT send yet.

3. Bob opens the message (visible in viewport for >1 second):
   Queues a "read" receipt in local outbox.
   Does NOT send yet.

4. At next Poisson cover traffic interval:
   Client sends receipt as Sealed Sender message to px_[alice].
   Receipt payload: { token_id: [32 bytes], receipt_type: "delivered"|"read" }
   NO timestamp. NO message reference. NO sender info beyond Sealed Sender.

5. Alice's client receives, matches token_id to her outgoing message log,
   updates UI: ✓ (delivered) or ✓✓ (read).

KEY PROPERTIES:
  Receipts are MUTUAL: cannot receive without sending. Both parties or neither.
  No timestamps: prevents adversary inferring Bob's online schedule from receipt timing.
  Jittered sending: decouples receipt arrival from message receipt timing.
  Server learns: a Sealed Sender blob went to px_[alice]. Nothing else.
```

Settings allow disabling delivery receipts, read receipts, and adding extra receipt privacy delay (additional Poisson delay on top of cover traffic).

---

## 14. Offline Message Delivery

### Phase 1 — Server Queue

```
Bob offline → message stored in UNLOGGED message_queue
Server holds: { recipient_id, encrypted_blob, expires_at }
Server does NOT hold: sender, content, message type

Bob reconnects → server delivers via WebSocket
Bob ACKs → server hard-deletes immediately (not soft-delete, not "mark deleted")

DEFAULT TTL:  30 days (messages expire if Bob never connects)
EXTENDED TTL: 60 days (user opt-in in settings)
PER-MESSAGE:  Sender can set shorter TTL per message (1h, 6h, 24h, 7d, 30d, 60d)
              Use case: time-sensitive info that should self-destruct if undelivered
```

### Phase 2 — Nym Gateway Mailbox

In Phase 2, pending messages wait at Bob's Nym gateway — not at the Privex server. Privex server is completely out of the offline delivery path. Even server seizure during Bob's offline period reveals nothing, because the message is not there.

---

## 15. Cross-Device Sync & History

### Real-Time Cross-Device Sync (Linked Devices)

When Alice sends a message from Device A, a sync copy is encrypted and sent as a Sealed Sender message to her own `px_id`. Device B receives it via the same WebSocket delivery path. Server sees: a Sealed Sender blob going to px_[alice] — indistinguishable from an incoming message from anyone else.

### Device-to-Device History Transfer

QR-code-based. Ephemeral X25519 key exchange between devices. Full history transferred as AES-256-GCM encrypted stream. Server routes the encrypted transfer blobs — cannot read them. Both devices must be online simultaneously.

### Server-Side History Backup (Opt-In, OFF by Default)

```
history_key = HKDF(master_seed, "privex_history_backup_v1")
  Derived from OPAQUE master seed. Automatically available after recovery.

On each message (when backup enabled):
  blob = AES-256-GCM(history_key, plaintext || msg_id)
  Stored in UNLOGGED history_blobs table.

Server holds: encrypted blobs it cannot decrypt.
Server does NOT know: message content, sender, recipient, conversation.

SECURITY TRADE-OFF:
  This feature breaks forward secrecy at the server-storage layer.
  If a user's password AND the server are both compromised simultaneously,
  history blobs could be exposed to offline attack.

  DEFAULT: OFF. User must explicitly enable with clear warning.
  ON DISABLE: All history blobs are immediately hard-deleted.
  RECOMMENDED FOR: General privacy users.
  NOT RECOMMENDED FOR: Journalists, activists, high-threat users.
```

---

## 16. Rate Limiting & Anti-Abuse

### Pre-Registration: Proof-of-Work (Global)

```
No IP. No identity. No CAPTCHA. PoW only.

SHA-256 hashcash: find nonce where SHA-256(challenge || nonce) has N leading zero bits.
Challenge TTL: 30 minutes (prevents challenge stockpiling).
Difficulty: dynamic, computed globally from registration rate.

Rate → Difficulty → Approx. solve time (browser WASM):
  0–5/min     → 22 bits → ~500ms
  6–15/min    → 23 bits → ~1s
  16–40/min   → 25 bits → ~4s
  41–100/min  → 27 bits → ~16s
  101–300/min → 29 bits → ~1 minute
  300+/min    → 31 bits → ~4 minutes

Timing anomaly detection:
  Solutions arriving faster than minimum plausible browser time increment
  a global suspicion score (+1-3 bits difficulty bonus).
  Suspicion decays when registration rate normalizes.
  Protects against: GPU/ASIC attackers who are 10-100x faster than browser.

Challenge request rate tracking:
  Attacker stockpiling challenges triggers difficulty raise BEFORE solutions arrive.
  Pre-solving at difficulty 22 when difficulty rises to 27 = wasted compute.

Phase 2 (planned): Argon2id memory-hard hybrid on top of SHA-256.
  64MB RAM per solve. Eliminates GPU advantage (~100x → ~1.2x). ASIC cost prohibitive.
```

### Post-Registration: Per-User Rate Limiting

```
Every authenticated request carries a session token → server derives px_id.
Rate limited by HMAC-SHA256(server_secret, px_id + ":" + endpoint + ":" + minute_bucket).

NOT stored as raw px_id in Redis.
Server seizure reveals: HMAC values + request counts. Cannot reverse to px_ids.

Rate limits (sliding window, per user):
  POST /messages/send:     120 per 60 seconds
  GET  /keys/{user_id}:    30 per 60 seconds    (anti-enumeration)
  POST /blobs/{chunk_id}:  60 per 60 seconds
  POST /auth/verify:       5 per 60 seconds     (anti-brute-force)
  POST /keys/spk/rotate:   3 per hour

All rate limit counters: Redis with 120-second TTL.
On TTL expiry: Redis purges automatically. No historical rate limit log exists.
```

### Constant Poll Size (Phase 2)

`GET /messages/poll?count=10` always returns exactly 10 items: real messages padded with dummy items to reach 10. Observer cannot infer message volume from response size or timing.

---

## 17. CSAM Protection

**Status: Phase 2. Not implemented in Phase 1.**

Zero-knowledge CSAM detection that does not break E2EE.

```
CLIENT-SIDE (before encryption):
  1. PDQ perceptual hash of image (detects visual similarity, not just byte identity)
  2. OPRF-based Private Set Intersection against NCMEC hash database:
     - Client blinds hash: H' = r * H_to_curve(PDQ_hash)
     - Server evaluates: H'' = server_OPRF_key * H'
     - Client unblinds: result = (1/r) * H''
     - Client checks membership in precomputed set T
     - Server NEVER sees the PDQ hash or the image
  3. If match: BLOCK. Message not sent. User sees generic error.
  4. If no match: generate Groth16 ZK proof of compliance.
     Proof says: "I ran the check. Result was no match."
     Server verifies 256-byte proof in <5ms.
     Server does NOT see the image, hash, or what was checked.

USER REPORTING:
  Received CSAM goes directly from user's device to NCMEC CyberTipline API.
  Privex server is NOT in this chain. Server receives only an aggregate count.
  Satisfies 18 U.S.C. § 2258A without server-side content scanning.

TRUSTED SETUP:
  Groth16 ZK proofs require a one-time multi-party computation ceremony.
  This ceremony must be public and auditable (Powers of Tau model, 10+ participants).
  Must be completed before Phase 2 launch.
```

---

## 18. Key Transparency Log

Certificate Transparency-style Merkle tree of all key operations. Prevents silent MITM by the server.

```
Every key registration and SPK rotation is appended to an append-only KT log.
Each entry: { px_id, SHA-256(key_bundle), operation, timestamp, prev_hash }

Root hash published every 10 minutes, signed with server's Ed25519 + Dilithium3 keys.
Root also committed to a public blockchain (tamper evidence independent of Privex).

CLIENT BEHAVIOR:
  On fetching a peer's key bundle: verify Merkle inclusion proof against KT root.
  Reject the key if proof is invalid.
  Periodically: verify own key bundle in log matches local keys.
  On mismatch: ALERT (possible MITM or compromise).

WHAT THIS PREVENTS:
  If server substitutes Bob's public key when Alice requests it:
    → Substituted key must appear in KT log
    → Bob's client detects it doesn't match his actual keys
    → OR: server doesn't put it in log → Alice's client rejects (no valid proof)
    Either way: silent MITM is detectable.

KEY FINGERPRINTS:
  Every conversation shows a safety code (first 8 bytes of SHA-256 of both IK public keys).
  Users can compare codes out-of-band (in person, phone call) to verify no MITM.
```

---

## 19. Time Synchronization

Client timestamps are device-generated. A manipulated clock can cause out-of-order messages or TTL bypass.

```
SOLUTION: Cryptographic time anchor — no external NTP (would leak IP).

Server signs every WebSocket message delivery:
  server_ts:     Unix timestamp (seconds)
  server_ts_sig: Ed25519_sign(server_ts || message_id, time_signing_key)

Client verifies:
  1. Verify server_ts_sig against pinned time_signing_pub key (hardcoded in client)
  2. Check |local_clock - server_ts| <= 90 seconds
  3. If within tolerance: use local clock for display
  4. If outside tolerance: use server_ts as ordering anchor, show clock warning

Message ordering: sorted by server_anchor (tamper-resistant), not client_ts.

Time signing key rotation: annually, announced via KT log.
```

---

## 20. Infrastructure

### Phase 1 Deployment

```
Main server:    Oracle Cloud Always Free ARM (Tokyo)
                2–4 OCPU, 12–24GB RAM, 200GB storage — free forever
                Runs: Axum server + PostgreSQL + Redis in Docker Compose
                OS: Ubuntu 22.04, dm-crypt/LUKS2 encrypted volumes
                /var/log: tmpfs (logs in RAM only, purged on reboot)
                Swap: disabled (swapoff -a)

Relay node 1:   Oracle Cloud ARM (same account, same region)
                Runs: Privex onion relay node

Relay node 2:   Hetzner CX22, Singapore (~€3.79/month)
                Different jurisdiction from Oracle (Japan vs Singapore)
                Runs: Privex onion relay node

Blob storage:   Cloudflare R2 (free 10GB, zero egress fees)
                Encrypted chunks only. No filenames, no MIME types stored.

Web app:        Cloudflare Pages (free, unlimited bandwidth)
                Serves React PWA bundle + WASM modules

Database:       PostgreSQL 16 (on Oracle, UNLOGGED critical tables)
Cache:          Redis 7.2 (on Oracle, no-persist config)
Proxy:          Caddy 2 (access logs: output discard)
```

### Legal Jurisdiction

Incorporation target: **Iceland (Privex ehf.)**

- Strong privacy laws, outside Five Eyes intelligence network
- Requires Icelandic court order for any data access
- Architecture means even full cooperation with a valid order produces nothing useful
- Warrant canary signals coercion before legal gag takes effect

### Warrant Canary

Published monthly at `/canary`. GPG-signed by Privex's public key. Lists 5 specific statements about government requests. If not updated within 45 days, assume compromise.

---

## 21. Honest Limitations

```
1. ISP can identify Privex usage in Phase 1.
   Resolved in Phase 2 via Nym mixnet. Until then: use a VPN before connecting.

2. ISP can see when device is online (timing metadata).
   Nym hides destination and content. ISP still sees connection times.
   Mitigated by: fixed polling schedule, Nym loop cover traffic, jittered receipts.
   Residual: adversary watching both ISPs simultaneously can attempt correlation.
   Requires nation-state capability and active targeting of both parties.

3. Nym entry gateway sees user's IP.
   Privex-operated gateways: no-log configuration, nothing to produce.
   Residual: if Nym gateway AND Privex server both compromised simultaneously,
   correlation is theoretically possible.

4. iOS APNs knows Privex is installed on a device.
   Push payloads are 0-byte wake tokens — no content visible to Apple.
   Apple knows: device has Privex. Not who you talk to.

5. Audio/video calls: TURN relay sees IP addresses of both participants.
   TURN auth is ephemeral, not linked to user identity. TURN does not log.
   Call content is E2EE via SFrame. IP-level pairing through TURN is not hidden.
   Same tradeoff as Signal, Wire, and every E2EE calling app.

6. Server-side history backup (opt-in) breaks forward secrecy at rest.
   OFF by default. High-threat users should leave it disabled.

7. Endpoint compromise (kernel-level malware).
   SE/Keystore makes keys non-exportable. In-memory decrypted messages are readable.
   Out of scope for any software security system.

8. Phase 1 relay network is small (2–3 nodes).
   Compromising all nodes simultaneously is trivially easy.
   Onion routing provides minimal anonymity until the network grows.
   This is why Phase 1 explicitly does not claim Law 4 compliance.
```

---

## Contributing

Privex is open source. Cryptographic changes require 2 reviewer approvals minimum.

**The absolute rule: zero custom cryptographic algorithms.** Every primitive must come from a listed, audited library. Signal's libsignal for PQXDH + Double Ratchet. liboqs for Kyber + Dilithium. libsodium for symmetric. openmls for MLS. opaque-ke/-ts for OPAQUE.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](../SECURITY.md) for vulnerability reporting.
