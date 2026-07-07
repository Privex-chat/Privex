# Privex â€" Claude Code Build Guide
### How to Build It, Session by Session, Without Writing Code Yourself
*Version 1.1 â€" Updated: Phase 1 status, receipts, cross-device sync, timing mitigations, time sync*

---

## Who This Guide Is For

You don't write code. You prompt Claude Code, review what it produces, make decisions, and steer the ship. This guide is your complete operating manual for building Privex â€" from zero to a working Phase 1 web app â€" using Claude Code as your engineering team.

**What you bring:** Vision, judgment, testing, human decisions, quality control.
**What Claude Code brings:** All the actual code.

This guide covers:
1. Infrastructure setup (cheap â€" â‚¬4â€"10/month to start)
2. Your CLAUDE.md master context file (Claude Code reads this every session)
3. Phase 1 + Phase 2 metadata sessions, in order, with exact prompts
4. Human checkpoints â€" what YOU personally verify at each step
5. The hard parts â€" where to invest extra attention

---

## Part 1 â€" Infrastructure: Starting Cheap in Asia

### The Honest Reality Check

The full production spec (10 relay nodes, 5 jurisdictions, Nym gateways) costs â‚¬150+/month. You do not need that to start. You need enough to prove everything works correctly, securely, with real users. That costs â‚¬4â€"10/month.

### Your Phase 1 Stack (Asia Region)

#### Primary Server â€" Oracle Cloud Free Tier (FREE, forever)

Oracle's Always Free tier is genuinely the best free compute on the internet for a project like this.

**What you get â€" Ampere ARM (Always Free):**
- Up to 4 OCPUs + 24GB RAM total (split across up to 4 instances)
- 200GB block storage
- 10TB outbound data/month
- Available regions: Tokyo, Osaka, Seoul, Singapore, Mumbai, Sydney

**Recommended setup:**
```
Instance 1: "privex-main" â€" 2 OCPU, 12GB RAM
  Runs: Docker Compose with server + postgres + redis + minio
  OS: Ubuntu 22.04 Minimal

Instance 2: "privex-relay-1" â€" 2 OCPU, 12GB RAM  
  Runs: First onion relay node
  OS: Ubuntu 22.04 Minimal
```

> **Sign up:** cloud.oracle.com â†' Always Free Tier â†' Select Tokyo or Singapore region.
> Always Free means the card is never charged as long as you don't exceed free limits.
> You will not exceed free limits in Phase 1.

#### TURN Server â€" Metered.ca (FREE for first 50GB/month)

For call relaying. No credit card needed for the free tier.
- Sign up at metered.ca
- Create a TURN server
- Note your: `turn_server_url`, `turn_username`, `turn_password`
- You won't need this until Phase 3 (video/audio calls) â€" set it up, save the credentials, ignore it until then

#### Object Storage â€" Cloudflare R2 (FREE)

For encrypted file blobs. Better than self-hosted MinIO for Phase 1.
- 10GB free storage/month
- **Zero egress fees** (most important for a file-sharing app)
- Sign up at cloudflare.com â†' R2 â†' Create bucket named `privex-blobs`
- Note your: `account_id`, `access_key_id`, `secret_access_key`, `bucket_name`

> Alternative: Keep MinIO on Oracle if you prefer full self-hosting. The choice doesn't affect security.

#### DNS & CDN â€" Cloudflare Free (FREE)

- Buy your domain at Porkbun (~â‚¬10/year for a .io) or Namecheap
- Transfer nameservers to Cloudflare
- Cloudflare gives you: CDN, DDoS protection, free SSL, and will be your domain-fronting layer later
- Set up records:
  ```
  A    api.privex.dpdns.org     â†' [Oracle main server IP]
  A    relay1.privex.dpdns.org  â†' [Oracle relay server IP]
  CNAME privex.dpdns.org        â†' [Cloudflare Pages, for the web app]
  ```

#### Web App Hosting â€" Cloudflare Pages (FREE)

- Unlimited bandwidth, automatic HTTPS, Git-connected deploys
- Connect your GitHub repo â†' Cloudflare Pages detects Vite â†' auto-deploys on every push
- No server needed to serve the web app itself

#### Redis â€" Same Server (no cost)

Run Redis inside Docker on the Oracle main server. In Phase 1, you will not exhaust a single server's Redis capacity.

#### Second Relay Node â€" Hetzner Singapore

- Hetzner: hetzner.com â†' Cloud â†' Singapore region
- CX22: 2 vCPU, 4GB RAM, 40GB SSD â€" **â‚¬3.79/month**
- This is your second relay node in a different jurisdiction from Oracle (Japan vs Singapore)
- You need minimum 3 nodes for a 3-hop circuit. Third node: run it locally in dev, or use a free Fly.io instance

#### Summary â€" Phase 1 Monthly Cost

| Service | Cost | What It Does |
|---|---|---|
| Oracle Cloud ARM Ã- 2 | FREE | Main server + Relay node 1 |
| Hetzner CX22 Singapore | â‚¬3.79/month | Relay node 2 |
| Cloudflare R2 | FREE (10GB) | Encrypted blob storage |
| Cloudflare CDN/Pages | FREE | Web app hosting + CDN |
| Metered.ca TURN | FREE (50GB) | Call relay (Phase 3) |
| Domain | â‚¬10/year | privex.dpdns.org |
| **Total** | **~â‚¬4â€"5/month** | |

### Oracle Server Initial Setup

SSH into your Oracle server and run this bootstrap:

```bash
# Run this once on each Oracle instance
sudo apt update && sudo apt upgrade -y

# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu

# Docker Compose
sudo apt install -y docker-compose-plugin

# Rust (for building on the server if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Harden SSH
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Firewall (Oracle has its own security group too â€" configure both)
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp  # HTTPS + WSS
sudo ufw allow 8443/tcp # Relay node port
sudo ufw enable
```

> **Oracle firewall important:** Oracle has its own VCN security groups. Go to Oracle Cloud Console â†' Networking â†' Virtual Cloud Networks â†' Security Lists â†' Add rules for ports 443, 8443, 8080 or your deployment will be blocked.

---

## Part 1B â€" Current Phase 1 Status

Update this section at the start of each session to reflect actual build state.

### Working End-to-End

```
DONE:
  1:1 text messaging (real-time, Alice <-> Bob)
  Offline message delivery (server queue, delivered on reconnect)
  File transfers with client-side encrypted thumbnails
  SHA-256 integrity check on file receive
  PWA (installable, offline shell cached)
  Rust/Axum backend with UNLOGGED PostgreSQL tables
  WebCrypto non-extractable master key
  IndexedDB encrypted local storage
  Server-side history backup (opt-in, warning shown)
  Device-to-device history transfer (both devices must be online)
```

### In Progress / Broken

```
PARTIAL:
  Cover traffic â€" code skeleton, Poisson timer not firing live dummy messages
  Nym integration â€" worker exists, not connected to live Nym (direct WebSocket for now)
  Session management â€" implemented but broken (tokens not invalidated on SPK rotate)
  Cross-device real-time sync â€" sent messages from Device A do not appear on Device B
  Push notifications â€" Service Worker registered, push event handling broken
```

### Not Yet Built (Pending Sessions)

```
PENDING:
  Delivery & read receipts (Section 4.10)
  Time sync & desync attack prevention (Section 9.6)
  Fixed polling schedule (Section 5.7, Mitigation 1)
  Constant fetch size padding (Section 5.7, Mitigation 2)
  Jittered receipt sending (Section 5.7, Mitigation 3)
  Per-message TTL override (Section 4.12)
  Session management fix
  Push notification fix
```

### Remaining Sessions to Complete Phase 1

```
16B: Delivery & Read Receipts
16C: Cross-Device Real-Time Sync
16D: Time Synchronization
16E: Session Management Fix + Push Fix
16F: Timing Mitigations (polling, constant fetch, jitter)
17:  File Sharing (verify/harden only â€" already implemented)
18:  Settings, Multi-Device, Recovery (partially done â€" verify and complete)
19:  Service Worker + Push Fix (PWA done, push broken)
20:  Integration Testing + Hardening
```

---

## Part 2 â€" The CLAUDE.md File

This is the most important file in your repository. Claude Code reads `CLAUDE.md` at the start of every session. It is your way of making sure Claude Code always knows the project context, the rules, and what it's currently building.

Put this file in the root of your repository (`/CLAUDE.md`). Update the "CURRENT PHASE" section at the start of each new session.

```markdown
# CLAUDE.md â€" Privex Project Context

## What Is Privex?

Privex is a zero-knowledge, end-to-end encrypted communication platform.
The server is architecturally (not policy) blind â€" it cannot read messages,
identify users, or trace relationships. Phase 1 is a web app (PWA).

## The Absolute Laws (Never Violate These)

1. ZERO custom cryptographic algorithms. Use the listed libraries only.
2. ZERO plaintext user data stored on the server. Ever.
3. ZERO IP addresses logged or stored anywhere. Not even temporarily.
4. ZERO access logs (requests, connections, anything with user identifiers).
5. ZERO third-party analytics, tracking, or telemetry.
6. ALL crypto runs in the browser via WebAssembly or Web Crypto API.

## Cryptographic Libraries (Use These, No Others)

- Key exchange + Double Ratchet: @signalapp/libsignal-client (WASM build)
- Post-quantum (Kyber + Dilithium): liboqs via @privex/crypto-wasm (Rust â†' WASM)
- Symmetric crypto: libsodium-wasm (AES-GCM, XChaCha20, HKDF, random bytes)
- Group messaging: openmls (Rust, compiled to WASM in crypto-wasm package)
- Account recovery: opaque-ts (TypeScript, browser-compatible)
- ZK proofs: snarkjs (circom circuits, CSAM only â€" not for authentication)
- Secret sharing: custom Shamir in crypto-wasm (GF(256) implementation)
- Proof of Work: custom in crypto-wasm (hashcash SHA-256)

## Tech Stack

Frontend:       React 18 + TypeScript 5 (strict) + Vite 5 + Tailwind 3
State:          Zustand 4
Local DB:       Dexie.js 3 (IndexedDB ORM)
Service Worker: Workbox 7
Protobuf:       protobufjs 7
Backend:        Rust (edition 2021) + Axum 0.7 + Tokio 1
DB:             PostgreSQL 16 (SQLx 0.7 for compile-time query verification)
Cache:          Redis 7.2 (deadpool-redis, no persistence)
Object Store:   Cloudflare R2 (or MinIO for self-hosted)
TLS:            rustls (pure Rust â€" zero OpenSSL dependency)
Container:      Docker + Docker Compose
Reverse Proxy:  Caddy 2 (access log: disabled)

## Repository Structure

privex/
â"œâ"€â"€ apps/web/          â† Primary platform (React PWA)
â"œâ"€â"€ apps/android/      â† Phase 2 (not started)
â"œâ"€â"€ apps/ios/          â† Phase 3 (not started)
â"œâ"€â"€ packages/
â"‚   â"œâ"€â"€ crypto-wasm/   â† Rust â†' WASM crypto module
â"‚   â"œâ"€â"€ protocol/      â† Protobuf schemas
â"‚   â""â"€â"€ ui/            â† Shared UI components
â"œâ"€â"€ server/            â† Rust/Axum backend
â"œâ"€â"€ relay/             â† Onion relay node
â"œâ"€â"€ infra/             â† Docker Compose, Caddy config, Postgres config
â""â"€â"€ docs/              â† Technical documentation

## Key Technical Decisions (Don't Change These Without Discussion)

- Registration uses Proof of Work (not IP rate-limiting) â€" no IP ever stored
- Authentication uses signed Ed25519+Dilithium3 challenge â€" NOT snarkjs
- Sender identity encrypted inside message body (Sealed Sender)
- All messages padded to 1024-byte boundaries before encryption
- PostgreSQL message_queue is an UNLOGGED table (no WAL writes)
- history_blobs is UNLOGGED. History backup is opt-in, OFF by default
- Redis: save "" and appendonly no (in-memory only, no disk persistence)
- Caddy: access_log output discard (never created, not "deleted")
- Session tokens: 24-hour TTL (not 15 minutes â€" avoids timing patterns)
- Receipts: Sealed Sender messages, sent at next Poisson cover traffic interval (not immediately)
- Receipt token_id: 32-byte CSPRNG, lives only on sender and recipient devices (server never sees)
- Receipts contain NO timestamps â€" prevents timing correlation attacks
- Receipt participation is MUTUAL â€" both parties participate or neither does
- Message TTL: 30 days default, 60 days opt-in, per-message override supported
- Cross-device sync: sent messages copied as Sealed Sender to own px_id (same as any other message)
- History transfer: ephemeral X25519 + AES-256-GCM, server routes encrypted blob only
- History backup key: HKDF(master_seed, "privex_history_backup_v1")
- Time sync: server signs timestamps Ed25519, client verifies Â±90s, no external NTP (no IP leak)
- Fixed polling (Phase 2): fetch exactly N=10 items per poll cycle regardless of real message count

## Reference Document

Full technical specification: docs/PRIVEX_DOCS_V2.md
Read the relevant section of this document before implementing any feature.

## CURRENT PHASE & SESSION

Phase: 1 â€" Web App Foundation
Current session: [UPDATE THIS BEFORE EACH SESSION]
What was just completed: [UPDATE THIS]
What to build next: [UPDATE THIS]
```

---

## Part 3 â€" How to Work With Claude Code

### The Session Model

Claude Code works best in **focused sessions** with a clear, single deliverable. Each session in this guide has:
- One thing to build
- Exact context to provide
- Exact prompt to use
- Human checkpoint â€" what YOU verify before moving on

**A session typically takes 20â€"60 minutes.** Some (like WASM setup) may take longer.

### The Session Handoff Protocol

At the END of every session, tell Claude Code:

```
Before we finish this session, please:
1. Write a brief summary of what was built and what files were changed
2. List any decisions you made that I should know about
3. List any assumptions you made that I should verify
4. Write a "start of next session" note I can use in CLAUDE.md
```

Copy that output. Paste it into your CLAUDE.md under "CURRENT PHASE & SESSION" before the next session.

### When Claude Code Gets Something Wrong

This will happen. Especially with:
- WebAssembly compilation (finicky, version-sensitive)
- OPAQUE protocol integration (newer library, less training data)
- ZK circuits in circom (specialized, unusual)
- libsignal WASM bindings (Signal's APIs change between versions)

When Claude Code produces something that doesn't compile or behave correctly:

```
The [specific thing] isn't working. Here's the exact error:
[paste full error output]

Read the relevant documentation section in docs/PRIVEX_DOCS_V2.md
and try a different approach. Do not change the overall architecture.
Fix just this specific issue.
```

Never let Claude Code "refactor" a large section to fix a small bug. Keep fixes surgical.

### The No-Custom-Crypto Rule Enforcement

If you ever see Claude Code writing something like:
```rust
fn my_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // XOR-based encryption...
```

Stop it immediately:
```
Stop. Do not implement custom cryptographic functions. 
Use libsodium for this. Read the "Cryptographic Libraries" section
in CLAUDE.md and use the correct library.
```

### Reviewing Code as a Non-Coder

You don't need to understand every line. But you should scan for:

1. **Red flags in server code:**
   - Any `log::info!("user: {}", user_id)` or similar â€" IDs should never be in logs
   - Any `ip_address` field in any database insert
   - Any `.log()` call on request data
   - Any hardcoded secrets (passwords, API keys in source code)

2. **Red flags in browser code:**
   - Any `fetch()` or `axios.get()` to third-party URLs you didn't authorize
   - Any `localStorage.setItem()` for key material
   - Any unencrypted writes to IndexedDB (`db.messages.add({ content: plaintext... })`)

3. **Green flags (things that should be there):**
   - `crypto.subtle.generateKey(..., false, ...)` â€" the `false` is "non-extractable"
   - `UNLOGGED TABLE` in the database migrations
   - `save ""` and `appendonly no` in redis.conf
   - `output discard` in Caddyfile

---

## Part 4 â€" Phase 1 Session Guide

### Before Any Session: Start Claude Code

```bash
# In your project root
claude
```

Or if continuing a session:
```bash
claude --continue
```

First message in every new session (after updating CLAUDE.md):
```
Read CLAUDE.md carefully. Read docs/PRIVEX_DOCS_V2.md section [X] for this session.
When ready, confirm you understand the current phase and what we're building today.
```

---

### SESSION 1: Repository Bootstrap

**Goal:** Create the monorepo structure, tooling, and empty packages.

**Prerequisites:** Node.js 20+, Rust 1.78+, pnpm 9+ installed locally and on server.

**Prompt:**
```
Create the Privex monorepo structure as defined in CLAUDE.md and 
docs/PRIVEX_DOCS_V2.md Section 16 (Project Structure).

Use pnpm workspaces + Turborepo for the monorepo.

Create these with the correct package.json, tsconfig.json, and
placeholder index files:
- apps/web (React 18 + Vite 5 + TypeScript 5 strict + Tailwind 3)
- packages/crypto-wasm (Rust Cargo.toml with the correct dependencies)
- packages/protocol (protobufjs setup)
- packages/ui (empty shared components)
- server/ (Rust Cargo.toml with axum, tokio, sqlx, rustls, deadpool-redis)
- relay/ (Rust Cargo.toml for the onion relay node)
- infra/ (docker-compose.yml with postgres, redis, minio, caddy stubs)

Also create:
- .gitignore (comprehensive, including /target, node_modules, .env, *.key)
- .env.example (all env vars needed, with placeholder values, no real secrets)
- turbo.json (build pipeline: crypto-wasm â†' protocol â†' server, web)
- README.md (brief project description linking to docs/)

Do NOT write any application logic yet. Just the correct structure and configuration.
Verify all TypeScript configs use strict: true.
Verify all Rust Cargo.toml files pin dependency versions (no wildcards).
```

**Human Checkpoint:**
- [ ] `pnpm install` runs without errors
- [ ] `cargo build` in `server/` runs without errors (even with no logic)
- [ ] `cargo build` in `packages/crypto-wasm/` runs without errors
- [ ] File structure matches docs/PRIVEX_DOCS_V2.md Section 16
- [ ] `.env.example` has entries for: `DATABASE_URL`, `REDIS_URL`, `R2_BUCKET`, `R2_ACCESS_KEY`, `R2_SECRET_KEY`, `TURN_SECRET`, `SESSION_HMAC_KEY`
- [ ] `.gitignore` includes `.env` (verify no secrets get committed ever)

---

### SESSION 2: Protobuf Schemas

**Goal:** Define all message formats in Protocol Buffers before writing any code that uses them.

**Why first:** Protobuf is your source of truth for all data structures. Writing it before code prevents inconsistency between server and client.

**Prompt:**
```
Implement the Protobuf schemas in packages/protocol/proto/ as defined in
docs/PRIVEX_DOCS_V2.md Section 11 (API Specification) and Section 4 
(Cryptographic Architecture).

Create these .proto files:
1. envelope.proto â€" Sealed Sender wrapper (SealedEnvelope, SenderCertificate)
2. messages.proto â€" All message types (TextMessage, FileMessage, CallInvite, etc.)
3. keys.proto â€" KeyBundle, PreKeyBundle, SignedPreKey, OneTimePreKey
4. recovery.proto â€" OpaqueRecord, ShamirShare, DeviceLinkPayload  
5. groups.proto â€" MLSMessage, GroupState, MLSWelcome
6. calls.proto â€" CallInvite, CallAccept, IceCandidate, CallHangup
7. wire.proto â€" WireMessage (the top-level wrapper for everything on the wire)

Requirements:
- All binary fields use bytes type (not string)
- All timestamps use uint64 (Unix time in seconds)
- Add proto3 syntax declaration and package names
- Generate TypeScript types via protobufjs-cli (add to build pipeline)
- Generate Rust types via prost (add to server/build.rs and Cargo.toml)
- Write a README in packages/protocol/ explaining each message type

Test: Write a simple TypeScript test that encodes + decodes a TextMessage.
     Write a simple Rust test that encodes + decodes the same TextMessage.
     Both must interoperate (decode the other's output).
```

**Human Checkpoint:**
- [ ] All .proto files exist and cover the types in the technical spec
- [ ] TypeScript generation works: `pnpm --filter @privex/protocol build`
- [ ] Rust generation works: `cargo build` in server/ (prost generates from .proto)
- [ ] Interop test passes (TypeScript encodes â†' Rust decodes and vice versa)
- [ ] No `string` fields for anything that should be binary (keys, ciphertext)

---

### SESSION 3: Crypto WASM Module â€" Part 1 (Identity & Key Exchange)

**Goal:** Build the WebAssembly crypto module. This is the foundation of all security. Take this session slowly and verify carefully.

**Context:** This session will be long. The WASM compilation pipeline is the most finicky part of the entire build.

**Prompt:**
```
Implement packages/crypto-wasm/ â€" the core cryptographic WebAssembly module.

This session covers Part 1: Identity and Key Exchange.

Read docs/PRIVEX_DOCS_V2.md sections 4.1 and 4.3 carefully before starting.

Add these Rust dependencies to Cargo.toml:
  - libsodium-sys (for libsodium bindings)
  - libsignal-protocol (from Signal's GitHub: https://github.com/signalapp/libsignal)
  - liboqs (from openquantumsafe/liboqs-rust)
  - wasm-bindgen
  - js-sys
  - getrandom (with "js" feature for WASM)
  - zeroize (for memory clearing after key operations)

Implement these exported functions (accessible from TypeScript):
  
  generate_identity_keypairs() â†' IdentityKeypairs
    Returns: { ed25519_pub, ed25519_priv, dilithium3_pub, dilithium3_priv, 
               kyber1024_pub, kyber1024_priv, x25519_pub, x25519_priv }
    All using CSPRNG from libsodium.
    
  sign_hybrid(data: Uint8Array, ed_priv: Uint8Array, dil_priv: Uint8Array) â†' HybridSignature
    Returns: { sig_ed25519: Uint8Array, sig_dilithium3: Uint8Array }
    Produces both Ed25519 and Dilithium3 signatures.
    
  verify_hybrid(data, sig_ed, ed_pub, sig_dil, dil_pub) â†' boolean
    Both signatures must be valid. Returns false if either fails.
    
  pqxdh_initiate(their_bundle: KeyBundle) â†' PQXDHInit
    Implements X3DH initiator + Kyber encapsulation.
    Returns: { shared_secret, x3dh_message, kyber_ciphertext }
    
  pqxdh_respond(init: PQXDHInit, my_keys: IdentityKeypairs) â†' SharedSecret
    Implements X3DH responder + Kyber decapsulation.
    Returns: { shared_secret }

CRITICAL REQUIREMENTS:
  1. All private key bytes must be zeroed after each operation using zeroize crate
  2. The wasm_bindgen exports must have TypeScript type declarations
  3. Build must succeed with: wasm-pack build --target web --release
  4. Add a build script: packages/crypto-wasm/build.sh that runs wasm-pack
  5. The pkg/ output must be importable from the web app

Write Rust unit tests for each function.
Write a TypeScript integration test that calls the WASM from Node.js
(using @node-rs/bcrypt pattern â€" WASM loading in Node test environment).

The WASM output size should be under 5MB (run wasm-opt if needed).
```

**Human Checkpoint:**
- [ ] `wasm-pack build --target web --release` completes without errors
- [ ] WASM output is in `packages/crypto-wasm/pkg/`
- [ ] TypeScript types are in `packages/crypto-wasm/pkg/*.d.ts`
- [ ] All Rust unit tests pass: `cargo test`
- [ ] WASM size: `ls -la packages/crypto-wasm/pkg/*.wasm` â€" should be <5MB
- [ ] **Security check:** Search for any `unwrap()` in crypto code â€" unsafe in production. Should be `?` or explicit error handling.
- [ ] **Memory check:** Verify `zeroize` is called on all private key variables after use

---

### SESSION 4: Crypto WASM Module â€" Part 2 (Double Ratchet & Sealed Sender)

**Prompt:**
```
Continue implementing packages/crypto-wasm/ â€" Part 2.

Read docs/PRIVEX_DOCS_V2.md sections 4.4 and 4.5 carefully.

Note: libsignal-protocol already implements the Double Ratchet.
Use it directly â€" do NOT reimplement. Your job is to expose it
correctly via wasm-bindgen.

Implement:

  ratchet_encrypt(session_state: Uint8Array, plaintext: Uint8Array) â†' RatchetResult
    Returns: { ciphertext: Uint8Array, new_session_state: Uint8Array, 
               message_header: Uint8Array }
    IMPORTANT: Pad plaintext to nearest 1024-byte boundary BEFORE encrypting:
      padded_len = ((plaintext.len() + 1023) / 1024) * 1024
      Use random padding bytes. Include original length in first 4 bytes.
    
  ratchet_decrypt(session_state: Uint8Array, ciphertext: Uint8Array, 
                  message_header: Uint8Array) â†' DecryptResult
    Returns: { plaintext: Uint8Array, new_session_state: Uint8Array }
    IMPORTANT: Unpad after decryption (read length from first 4 bytes).
    
  sealed_sender_encrypt(
    plaintext: Uint8Array, 
    sender_ed_priv: Uint8Array,
    sender_dil_priv: Uint8Array,
    sender_id: string,
    recipient_ik_pub: Uint8Array
  ) â†' Uint8Array
    Implements Sealed Sender from docs/PRIVEX_DOCS_V2.md Section 4.5.
    The sender identity is encrypted inside the payload.
    The returned bytes contain BOTH the encrypted sender cert AND the message.
    
  sealed_sender_decrypt(
    ciphertext: Uint8Array,
    recipient_ik_priv: Uint8Array,
    known_sender_keys: SenderKeyMap  // For verification
  ) â†' SealedDecryptResult
    Returns: { plaintext, sender_id, sender_verified: boolean }

  generate_sender_cert(
    sender_id: string,
    ed_priv: Uint8Array,
    dil_priv: Uint8Array,
    valid_hours: u32  // 24 hours
  ) â†' Uint8Array
    Generates a signed SenderCertificate.

All session states must be serializable/deserializable (stored in IndexedDB).
Use serde_json or bincode for session state serialization â€" specify in code.

Write unit tests covering:
  - Encrypt â†' Decrypt round trip
  - Message ordering (out-of-order message delivery)
  - Sealed sender: verify sender identity is NOT in the outer wrapper
```

**Human Checkpoint:**
- [ ] Padding is exactly 1024-byte boundaries â€" run a test: 1-byte message â†' 1024 bytes encrypted
- [ ] Decrypt round-trip test passes
- [ ] Sealed sender outer wrapper does NOT contain sender_id in plaintext â€" verify by inspecting the bytes
- [ ] Session state serializes/deserializes correctly (simulate: encrypt, serialize state, deserialize, decrypt)

---

### SESSION 5: Crypto WASM Module â€" Part 3 (Recovery: OPAQUE + Shamir)

**Prompt:**
```
Continue implementing packages/crypto-wasm/ â€" Part 3: Account Recovery.

Read docs/PRIVEX_DOCS_V2.md Section 6 (Account Recovery System) carefully.
Read especially the OPAQUE protocol specification in Section 6.1.

Dependencies to add to Cargo.toml:
  - opaque-ke (latest stable, from crates.io)
  - vsss-rs (Shamir's Secret Sharing, Verifiable Secret Sharing)
  - bip39 (for seed phrase generation)

Implement:

  OPAQUE CLIENT SIDE:
  
  opaque_register_start(password: &str) â†' OpaqueRegistrationStart
    Returns: { message: Uint8Array, client_state: Uint8Array }
    message is sent to server. client_state is kept for opaque_register_finish.
    
  opaque_register_finish(
    client_state: Uint8Array,
    server_response: Uint8Array,
    key_material: Uint8Array  // The user's full key bundle to encrypt
  ) â†' OpaqueRegistrationFinish
    Returns: { envelope: Uint8Array, envelope_mac: Uint8Array, upload_message: Uint8Array }
    upload_message is sent to server to complete registration.
    
  opaque_login_start(password: &str, user_id: &str) â†' OpaqueLoginStart
    Returns: { message: Uint8Array, client_state: Uint8Array }
    
  opaque_login_finish(
    client_state: Uint8Array,
    server_response: Uint8Array  // Contains envelope
  ) â†' OpaqueLoginFinish
    Returns: { key_material: Uint8Array, session_key: Uint8Array, success: boolean }
    key_material is the decrypted key bundle (identity keypairs, etc.)

  SHAMIR'S SECRET SHARING:
  
  shamir_split(secret: Uint8Array, threshold: u8, total: u8) â†' Vec<Uint8Array>
    Splits secret into `total` shares, any `threshold` can reconstruct.
    Use GF(256) arithmetic (vsss-rs crate).
    
  shamir_reconstruct(shares: Vec<Uint8Array>) â†' Uint8Array
    Reconstructs secret from any threshold number of shares.
    Returns error if shares are inconsistent/corrupted.
    
  SEED PHRASE:
  
  generate_seed_phrase(entropy: Uint8Array) â†' String
    entropy should be 32 bytes (256-bit BIP-39).
    Returns 24-word BIP-39 mnemonic.
    
  seed_phrase_to_master_seed(mnemonic: &str) â†' Uint8Array
    Returns 32-byte master seed.
    Error if invalid mnemonic.
    
  derive_keypairs_from_seed(master_seed: Uint8Array) â†' IdentityKeypairs
    Deterministically derives all keypairs from master seed.
    Same seed always produces same keypairs.

IMPORTANT SECURITY NOTE for OPAQUE:
  The password MUST NEVER leave the WASM module as plaintext.
  The entire OPAQUE exchange must happen inside WASM.
  The calling TypeScript code provides a password string and gets back 
  opaque protocol messages â€" it never handles a hash or derivation of the password.

Unit tests:
  - OPAQUE full round trip: register â†' login â†' verify key material matches
  - Shamir: split 32-byte secret (3-of-5) â†' reconstruct from any 3 â†' verify
  - Seed phrase: generate â†' recover â†' same keypairs
```

**Human Checkpoint:**
- [ ] OPAQUE unit test passes: full register â†' login round trip
- [ ] Shamir test: generate 5 shares, try every combination of 3 â€" all reconstruct correctly
- [ ] Try Shamir with only 2 shares (below threshold) â€" must return error, not garbage
- [ ] Seed phrase: generate phrase, write it down, recover â†' exact same keypairs
- [ ] Search code for any variable named `password` being returned or logged â€" should not exist

---

### SESSION 6: Crypto WASM Module â€" Part 4 (Utilities: PoW, PDQ Hash, PSI Blinding)

**Prompt:**
```
Continue implementing packages/crypto-wasm/ â€" Part 4: Utilities.

Implement:

  PROOF OF WORK:
  
  pow_solve(challenge: Uint8Array, difficulty: u32) â†' PowSolution
    Solves: SHA-256(challenge || nonce) must have `difficulty` leading zero bits.
    Returns: { nonce: u64, solution_hash: Uint8Array }
    Must be cancellable (check for an abort signal periodically).
    Should report progress every 10000 attempts via a JS callback.
    Target: difficulty=22 should solve in ~500ms on modern hardware.
    
  pow_verify(challenge: Uint8Array, nonce: u64, difficulty: u32) â†' boolean
    Verifies a PoW solution without solving it.

  PDQ PERCEPTUAL HASH (for CSAM check, Phase 2):
  
  pdq_hash(image_data: Uint8Array, width: u32, height: u32) â†' Uint8Array
    Returns 32-byte PDQ hash.
    Use the pdqhash crate (Apache 2.0).
    
  PSI CLIENT BLINDING (for CSAM check, Phase 2):
  
  psi_blind_hash(hash: Uint8Array) â†' PSIBlindResult
    Returns: { blinded: Uint8Array, r: Uint8Array }
    Implements OPRF blinding: r = random scalar, blinded = r * H_to_curve(hash)
    Curve: Ristretto255 (use curve25519-dalek crate with ristretto255 feature)
    
  psi_unblind(server_response: Uint8Array, r: Uint8Array) â†' Uint8Array
    Returns: unblinded = (1/r) * server_response
    This is the OPRF output for the client's hash.
    
  psi_check_membership(unblinded: Uint8Array, precomputed_set: Uint8Array) â†' boolean
    Checks if unblinded is in a sorted byte-encoded set.
    Binary search for efficiency (set can be large).

  HKDF UTILITY:
  
  hkdf_derive(input: Uint8Array, salt: Uint8Array, info: &str, len: u32) â†' Uint8Array
    Wraps libsodium's HKDF-SHA256.

Add crates: sha2, curve25519-dalek (ristretto255 feature), pdqhash.

Also: write a bench test for pow_solve at difficulty=22.
      The bench should report average ms per solve across 10 runs.
      Fail the bench if average >1000ms (regression detection).
```

**Human Checkpoint:**
- [ ] PoW: run pow_solve with difficulty=22, measure time â€" should be 200â€"800ms
- [ ] PoW: run pow_verify on the output â€" must return true
- [ ] PoW: manually flip one bit in the nonce, run pow_verify â€" must return false
- [ ] Shamir: no need to re-test, but verify the bench file runs: `cargo bench`

---

### SESSION 7: Database Schema + Migrations

**Goal:** Set up the database with all tables as specified, with the correct no-log properties.

**Prompt:**
```
Implement the database layer in server/src/db/.

Read docs/PRIVEX_DOCS_V2.md Section 8.3 (Database Schema) completely.

Tasks:

1. Create server/migrations/ with numbered SQL migration files:
   - 001_create_key_directory.sql
   - 002_create_kt_log.sql  (UNLOGGED table)
   - 003_create_message_queue.sql  (UNLOGGED table)
   - 004_create_blob_index.sql  (UNLOGGED table)
   - 005_create_group_state.sql  (UNLOGGED table)
   - 006_create_opaque_records.sql
   - 007_create_recovery_shares.sql
   - 008_create_relay_nodes.sql
   - 009_create_pow_challenges.sql  (UNLOGGED table)
   
   CRITICAL: message_queue, blob_index, kt_log, group_state, 
             pow_challenges must be UNLOGGED tables.
             This is not optional. It prevents data from appearing in PostgreSQL WAL.

2. Create server/src/db/mod.rs with:
   - Database connection pool initialization (SQLx PgPool)
   - Connection string from env var DATABASE_URL only (never hardcoded)
   - Pool size: min=2, max=20

3. Create server/src/db/queries/ with typed SQLx query modules:
   - key_directory.rs (insert_key, get_key, update_spk, list_opk_count)
   - message_queue.rs (enqueue, dequeue_for_recipient, ack_messages)
   - blob_index.rs (store_blob, get_blob_path, mark_downloaded, cleanup_expired)
   - opaque.rs (store_opaque_record, get_opaque_record, update_opaque_record)
   - pow.rs (issue_challenge, verify_and_consume, cleanup_expired)
   - kt_log.rs (append_entry, get_root, get_inclusion_proof)

4. Create infra/postgres/postgresql.conf with:
   wal_level = minimal
   archive_mode = off
   max_wal_size = 64MB
   checkpoint_timeout = 5min
   log_statement = none
   log_connections = off
   log_disconnections = off
   log_duration = off
   
5. Update infra/docker-compose.yml to use the custom postgresql.conf.

Use SQLx with compile-time query checking (sqlx::query! macros).
Run sqlx prepare to generate the query cache.

VERIFY: After creating migrations, run them against a local test Postgres.
        SELECT table_name, relpersistence FROM pg_class WHERE relname 
        IN ('message_queue', 'blob_index', 'kt_log');
        relpersistence should be 'u' (unlogged) for these tables.
```

**Human Checkpoint:**
- [ ] Run the above SELECT query â€" message_queue, blob_index, kt_log must show `relpersistence = 'u'`
- [ ] `sqlx migrate run` works without errors
- [ ] NO column named `ip_address` anywhere in any table (`grep -r "ip_address" server/migrations/` = no results)
- [ ] NO column named `email` or `phone` anywhere
- [ ] `postgresql.conf` has `log_statement = none` and `log_connections = off`

---

### SESSION 8: Server Foundation + Authentication

**Goal:** Build the Rust server with authentication endpoints. This is the first runnable server.

**Prompt:**
```
Implement the Rust/Axum server foundation and authentication system.

Read docs/PRIVEX_DOCS_V2.md Sections 8 and 11 (Authentication Endpoints).

Build in server/src/:

1. main.rs â€" Server entry point:
   - Load config from environment variables (no config files with secrets)
   - Initialize: database pool, Redis pool, Caddy/TLS
   - Mount all routers
   - Graceful shutdown on SIGTERM

2. config.rs â€" Config struct:
   Fields: database_url, redis_url, session_hmac_key (32 bytes from env),
           r2_bucket, r2_access_key, r2_secret_key, turn_secret
   Use the `secrecy` crate to protect sensitive fields in memory.
   All loaded from environment variables. Panic on startup if any missing.

3. middleware/auth.rs â€" Session token verification middleware:
   - Parse X-Privex-Auth header
   - Verify HMAC-SHA256 signature (use ring crate, not openssl)
   - Check expiry
   - Attach verified user_id to request extensions
   - Return 401 on any failure (no distinguishing error messages)

4. middleware/rate_limit.rs â€" Per-user rate limiting:
   - Key in Redis: HMAC(server_key, user_id) â€" not raw user_id
   - Sliding window algorithm
   - Return 429 with Retry-After header
   - Rate limits from docs: /messages/send â†' 120/60s, etc.

5. routes/auth.rs â€" Authentication endpoints:
   POST /auth/challenge   (docs Section 11)
   POST /auth/verify      (docs Section 11)
   POST /auth/pow_challenge
   POST /keys/register    (calls pow verification, then registers keys + OPAQUE record)
   
   CRITICAL REQUIREMENT for all endpoints:
   - Never log request bodies
   - Never log user_id in error messages (log "auth_error" not "auth_error for px_abc123")
   - Never log IP addresses (even in debug mode)
   - Use structured logging with tracing crate â€" all spans scrubbed of PII

6. routes/keys.rs â€" Key management:
   GET  /keys/{user_id}            (fetch key bundle + KT proof)
   POST /keys/prekeys/replenish    (upload new one-time prekeys)
   POST /keys/spk/rotate           (rotate signed prekey)

7. infra/docker-compose.yml â€" Update to run:
   - server (with all env vars)
   - postgres (with postgresql.conf mount)
   - redis (with redis.conf: save "", appendonly no)
   - caddy (with access_log disabled)

LOGGING RULES (enforced in code):
  Use tracing crate. Every span field must be reviewed:
  ALLOWED: request_id (random UUID, not user-linked), duration_ms, status_code, endpoint
  FORBIDDEN: user_id, ip_address, body content, session_token, any key material

Test: Write integration tests using reqwest:
  - Register a new user (PoW challenge â†' solve â†' register)
  - Authenticate (challenge â†' sign â†' session token)
  - Try authentication with wrong signature â†' expect 401
  - Try registration with used PoW â†' expect 400
```

**Human Checkpoint:**
- [ ] `docker-compose up` starts without errors
- [ ] POST /auth/pow_challenge â†' returns challenge JSON
- [ ] Registration flow works end-to-end (test script provided by Claude Code)
- [ ] Auth flow works end-to-end
- [ ] `docker logs privex-server 2>&1 | grep -E "(user_id|ip_address|px_)"` â†' NO matches (no PII in logs)
- [ ] Redis persistence check: `docker exec privex-redis redis-cli CONFIG GET save` â†' empty string
- [ ] Redis persistence check: `docker exec privex-redis redis-cli CONFIG GET appendonly` â†' "no"

---

### SESSION 9: Message Queue + Blob Store Endpoints

**Prompt:**
```
Implement message sending, delivery, and blob storage.

Read docs/PRIVEX_DOCS_V2.md Sections 8.1, 8.3, and 11 (Messaging/Blob Endpoints).

Build:

1. routes/messages.rs:
   POST /messages/send     â€" Queue an encrypted message for a recipient
   POST /messages/ack      â€" Acknowledge receipt (triggers hard delete)
   
   CRITICAL REQUIREMENTS:
   - Store ONLY: recipient_id, content (encrypted blob), size_bytes, queued_at, expires_at
   - NEVER store sender_id â€" this is a Sealed Sender system
   - Delete messages IMMEDIATELY on /ack â€" not "soft delete", not "mark deleted"
     Use DELETE FROM message_queue WHERE message_id = $1 (hard delete)
   - No read receipts stored anywhere
   - Delivery confirmation to sender: just HTTP 200. No delivery tracking.

2. routes/blobs.rs:
   POST /blobs/{chunk_id}  â€" Upload encrypted chunk
   GET  /blobs/{chunk_id}  â€" Download encrypted chunk
   DELETE /blobs/{chunk_id} â€" Delete (called by sender after recipient downloads)
   
   Backend: Cloudflare R2 (use aws_sdk_s3 crate with R2 endpoint override)
   OR: MinIO (same S3 SDK, different endpoint)
   
   CRITICAL REQUIREMENTS:
   - chunk_id in URL is SHA-256 of the encrypted chunk (content-addressed)
   - VERIFY: SHA-256(uploaded_bytes) == chunk_id in URL â†' reject if mismatch
   - No metadata stored: no filename, no MIME type, no uploader identity
   - Mark chunk as "downloaded" in blob_index after GET
   - Schedule deletion: 24h after first download OR 7 days from upload (whichever first)
   - Run a background task (tokio::spawn) to delete expired blobs hourly

3. Background tasks:
   server/src/tasks/mod.rs
   - message_expiry.rs: Delete messages older than 30 days (shouldn't exist, but safety net)
   - blob_expiry.rs: Delete expired blobs from R2 and blob_index
   - opk_monitor.rs: Send prekey_low WebSocket notification when user has <20 OPKs
   
Run every 60 minutes via tokio::time::interval.

Integration tests:
  - Send a message â†' verify it's in message_queue
  - ACK the message â†' verify it's GONE from message_queue (SELECT returns 0 rows)
  - Upload a blob â†' verify chunk_id in response
  - Download same blob â†' verify bytes match exactly
  - Try to download a non-existent blob â†' 404
```

**Human Checkpoint:**
- [ ] After message send â†' ack: `SELECT COUNT(*) FROM message_queue WHERE message_id = '[id]'` â†' returns 0
- [ ] NO sender identity anywhere in message_queue after send
- [ ] Blob upload â†' download round trip works
- [ ] Wrong chunk_id (tampered) upload â†' 400 error
- [ ] Background tasks registered: check they appear in server startup logs

---

### SESSION 10: WebSocket Server (Real-Time Delivery)

**Prompt:**
```
Implement the WebSocket server for real-time message delivery.

Read docs/PRIVEX_DOCS_V2.md Section 11 (WebSocket Protocol).

Build server/src/ws/:

1. ws/handler.rs â€" WebSocket upgrade handler:
   Endpoint: GET /v1/ws (upgrades to WebSocket)
   Auth: X-Privex-Auth header on upgrade request (not in URL â€" URLs can be logged)
   On connect: register user_id â†' WebSocket sender in a shared state map
   On disconnect: unregister from state map

2. ws/state.rs â€" Shared WebSocket state:
   Use Arc<DashMap<String, WsSender>> where String is user_id.
   This is the "online users" map.
   NEVER persist this to database. In-memory only.

3. ws/messages.rs â€" Message types and handlers:
   SERVER â†' CLIENT messages:
     { "type": "message", "message_id": "...", "content": "...", "queued_at": N }
     { "type": "prekey_low", "remaining": N }
     { "type": "key_change_alert", "user_id": "..." }
     { "type": "ping" }
   
   CLIENT â†' SERVER messages:
     { "type": "ack", "message_ids": ["..."] }
     { "type": "pong" }

4. Integration between message send and WebSocket:
   When POST /messages/send is called:
     a. Store message in message_queue (always â€" for offline delivery)
     b. Check if recipient is in WebSocket state map
     c. If online: push message immediately via WebSocket
     d. Message stays in queue until /ack is received (or until WebSocket ack)
     e. On WebSocket ack { type: "ack" }: hard delete from message_queue
   
   If recipient is offline: message stays in queue for next connection.

5. Heartbeat:
   Server sends { "type": "ping" } every 30 seconds.
   Client must respond with { "type": "pong" } within 30 seconds.
   Disconnect if no pong received (clean up from state map).

6. Offline message delivery:
   On WebSocket connection (after auth):
     a. Fetch all queued messages for this user from message_queue
     b. Send them all immediately via WebSocket
     c. Wait for acks

Performance note: DashMap is a concurrent HashMap that avoids lock contention.
Do not use a Mutex<HashMap> â€" at scale this becomes a bottleneck.

Test: 
  Connect two WebSocket clients (Alice and Bob).
  Send a message from Alice's HTTP endpoint to Bob.
  Verify Bob's WebSocket receives it without HTTP polling.
  Disconnect Bob. Send another message. Reconnect Bob. Verify delivery.
```

**Human Checkpoint:**
- [ ] WebSocket connects successfully after auth
- [ ] Real-time delivery test works (two terminal sessions)
- [ ] Offline delivery test works
- [ ] Disconnect Bob while message in queue: `SELECT COUNT(*) FROM message_queue WHERE recipient_id = '[bob]'` â†' returns 1 (waiting)
- [ ] Bob reconnects: message delivered, then count â†' 0

---

### SESSION 11: Key Transparency Log

**Prompt:**
```
Implement the Key Transparency (KT) Log system.

Read docs/PRIVEX_DOCS_V2.md Section 8.2 (Key Directory + Transparency Log).

Build server/src/crypto/kt_log.rs:

1. KT Log structure:
   The kt_log table (already created in migrations) is an append-only Merkle tree.
   Each entry has: seq, user_id, bundle_hash, operation, timestamp, prev_hash.
   prev_hash = SHA-256 of the previous entry (chain integrity).
   
2. Merkle tree operations:
   
   append_entry(user_id, bundle_hash, operation) â†' KTEntry
     Computes prev_hash from the last entry.
     Inserts new row.
     Returns the new entry.
   
   compute_root() â†' [u8; 32]
     Build the Merkle tree from all current entries.
     Return the root hash.
     This is called every 10 minutes to publish a new root.
   
   get_inclusion_proof(user_id) â†' InclusionProof
     Returns the Merkle path from this user's entry to the current root.
     The client can verify: hash(hash(entry), sibling_path) == root
     
   verify_inclusion(entry, proof, root) â†' bool
     Verify that an entry is in the tree with the given root.

3. Root publication:
   Every 10 minutes (background task): compute_root() â†' sign with server's Ed25519 key
   â†' store signed root in Redis (key: "kt:latest_root", TTL: 24 hours)
   
   GET /keys/kt/root â†' returns { root, root_sig_ed, timestamp }
   GET /keys/kt/proof/{user_id} â†' returns InclusionProof

4. Client-side verification (in packages/crypto-wasm/):
   kt_verify_inclusion(entry: &[u8], proof: MerkleProof, root: &[u8]) â†' bool
   
5. Update GET /keys/{user_id} to include inclusion_proof in response.

6. Client requirement (document this for the web app session):
   Every time the web app fetches a peer's key bundle, it MUST call 
   kt_verify_inclusion with the returned proof. Reject the key if proof is invalid.
   This prevents Privex from performing silent MITM attacks.

Test:
  - Append 10 entries â†' compute root â†' get inclusion proof for entry 5
  - Verify inclusion proof is valid
  - Tamper with entry 5's bundle_hash â†' verify inclusion proof FAILS
  - Add new entry â†' new root â†' old proof no longer valid (expected)
```

**Human Checkpoint:**
- [ ] Tamper test: modify an entry's hash, verify inclusion proof fails
- [ ] Root signing: verify root is signed with the server's Ed25519 key (not a placeholder)
- [ ] New entry after root publication: verify old proofs become invalid (correct behavior)

---

### SESSION 12: OPAQUE Server-Side Implementation

**Prompt:**
```
Implement the OPAQUE server-side for account recovery.

Read docs/PRIVEX_DOCS_V2.md Section 6.1 (OPAQUE Protocol) carefully.

Build server/src/crypto/opaque.rs and server/src/routes/recovery.rs:

1. OPAQUE Server Operations (using opaque-ke crate):

   opaque_register_start(client_message: &[u8]) â†' OpaqueServerRegistrationResponse
     Server evaluates OPRF on client's blinded password.
     Returns server response message.
     Does NOT store anything yet.
   
   opaque_register_finish(
     client_finish_message: &[u8],
     opaque_record_to_store: &[u8],  // Server's OPRF record
     envelope: &[u8],                // Client's encrypted key envelope
     envelope_mac: &[u8]
   ) â†' Result<()>
     Stores opaque_record, envelope, envelope_mac in opaque_records table.

   opaque_login_start(user_id: &str, client_message: &[u8]) â†' OpaqueLoginStartResponse
     Fetches user's opaque_record from database.
     Server evaluates OPRF.
     Returns: { server_message, envelope, envelope_mac } to client.
   
   opaque_login_finish(user_id: &str, client_finish: &[u8]) â†' Result<SessionToken>
     Verifies the client's OPAQUE finish message.
     On success: issue a 24-hour session token.
     On failure: return generic 401 (no info about why).

2. Recovery routes (routes/recovery.rs):
   POST /recovery/opaque/init     â†' opaque_login_start
   POST /recovery/opaque/complete â†' opaque_login_finish (returns session token)
   
   POST /recovery/shares/store    â†' store encrypted Shamir shares
   GET  /recovery/shares/{user_id} â†' return user's stored encrypted shares
                                    (auth: requesting user must be the owner OR
                                     a recovery contact â€" implement contact auth)

3. Device linking routes:
   POST /recovery/link/initiate   â†' generate rendezvous_id, store ephemeral state in Redis
   POST /recovery/link/complete   â†' route encrypted key bundle to Device B via WebSocket
   
   Link session: store in Redis with TTL=5min. 
   After link complete or TTL: delete from Redis.

SECURITY: OPAQUE keys must be loaded from environment variables on server startup.
          Never hardcoded. Use the secrecy crate wrapper.

Tests:
  - Full OPAQUE register + login round trip
  - Login with wrong password â†' 401 (in constant time to prevent timing attacks)
  - Recovery shares: store 3 shares, retrieve each separately
  - Device link: initiate on Device A, complete from Device B within 5 min
  - Device link: try after 5 min TTL â†' 410 Gone
```

**Human Checkpoint:**
- [ ] OPAQUE register â†' login with correct password â†' success
- [ ] OPAQUE login with wrong password â†' 401 (verify it takes same time as correct password â€" timing side-channel prevention)
- [ ] Shamir shares: verify server cannot decrypt them (they're just bytes â€" no decryption key on server)
- [ ] Device link: rendezvous entry deleted from Redis after use

---

### SESSION 13: Web App Foundation (React + WASM + Nym)

**Goal:** The browser app. This is where users actually interact with Privex.

**Prompt:**
```
Build the React web app foundation in apps/web/.

Read docs/PRIVEX_DOCS_V2.md Section 9 (Web Application Architecture) completely.

Tasks:

1. Vite configuration (vite.config.ts):
   - TypeScript strict mode
   - WASM support: import @privex/crypto-wasm correctly (wasm-pack output)
   - Service Worker registration via Workbox
   - PWA plugin (vite-plugin-pwa) with manifest.json
   - Content Security Policy headers (Section 9.5)
   - No source maps in production build
   - Deterministic output (consistent file hashes for reproducible builds)

2. App shell (src/App.tsx):
   Routes (React Router 6):
   /           â†' ConversationList (if authenticated) or Onboarding (if not)
   /chat/:id   â†' ChatScreen
   /call/:id   â†' CallScreen
   /settings   â†' SettingsScreen
   /verify/:id â†' KeyVerificationScreen
   /onboarding â†' OnboardingScreen (registration flow)
   /recover    â†' RecoveryScreen

3. Crypto initialization (src/workers/crypto.worker.ts):
   SharedWorker that loads @privex/crypto-wasm on startup.
   All WASM calls go through this worker (keeps main thread responsive).
   Expose typed RPC interface via MessageChannel.
   
   Example call pattern:
   // In main thread:
   const keypairs = await cryptoWorker.call('generate_identity_keypairs');
   // Worker handles the WASM call, returns result

4. Nym transport (src/workers/nym.worker.ts):
   Load @nymproject/sdk-full-fat (Nym WASM client).
   Connect to Nym gateway on startup.
   Expose: sendMessage(payload, recipientNymId) and onMessage(callback).
   Handle reconnection automatically.
   
   NOTE: The Nym client will need a gateway URL.
   For Phase 1 dev: use Nym's public testnet gateways (listed in their docs).
   For production: use privex-operated Nym gateway.

5. IndexedDB schema (src/db/index.ts via Dexie):
   Tables:
   - identity: { user_id, ed25519_pub, dilithium3_pub, kyber_pub, x25519_pub }
   - sessions: { session_id, peer_id, ratchet_state (encrypted), created_at }
   - messages: { msg_id, session_id, content_enc, plaintext_preview_enc, 
                 timestamp, status, direction }
   - contacts: { px_id, display_name_enc, verified_fingerprint, added_at }
   - groups:   { group_id, name_enc, mls_state_enc, epoch, member_count }
   - blobs:    { blob_id, chunk_ids, cek_enc, filename_enc, status }
   - settings: { key, value }
   
   IMPORTANT: content_enc, plaintext_preview_enc, display_name_enc must be 
   AES-GCM encrypted using the master key from OPAQUE.
   NEVER store any plaintext in IndexedDB.
   
   Encryption wrapper: src/db/encrypted-db.ts
     EncryptedDexie class that transparently encrypts writes and decrypts reads.
     Key: non-extractable WebCrypto key stored separately from IndexedDB.

6. Web Crypto key storage (src/crypto/keystore.ts):
   masterKey = await crypto.subtle.generateKey(
     { name: 'AES-GCM', length: 256 },
     false,           // non-extractable
     ['encrypt', 'decrypt']
   );
   Store masterKey handle in IndexedDB (IDBKeyVal â€" the handle, not the bytes).
   On app reload: retrieve handle from IDBKeyVal and use directly.
   
   Rationale: The actual key bytes never exist in JavaScript memory.
   The browser's WebCrypto implementation holds the key in native memory.

7. PWA Manifest (public/manifest.json):
   Standard PWA manifest per Section 9.4.
   Include icons in /public/icons/ (placeholder SVGs for now â€" design later).

Tests: 
  - WASM loads in browser (no CSP errors)
  - Nym worker connects to testnet gateway
  - IndexedDB encryption round trip: write message â†' close app â†' reopen â†' read message
  - masterKey: verify crypto.subtle.exportKey fails (non-extractable)
```

**Human Checkpoint:**
- [ ] `pnpm --filter web dev` opens in browser without console errors
- [ ] Browser DevTools â†' Application â†' Service Workers: service worker registered
- [ ] Browser DevTools â†' Application â†' IndexedDB: tables exist, values look like encrypted bytes (not plaintext)
- [ ] `crypto.subtle.exportKey('raw', masterKey)` in browser console â†' throws DOMException (non-extractable â€" correct)
- [ ] Nym worker connects: check Network tab for WebSocket to Nym gateway
- [ ] CSP check: DevTools Console should show no CSP violations

---

### SESSION 14: Registration + Onboarding Flow

**Prompt:**
```
Build the complete user registration and onboarding flow.

Read docs/PRIVEX_DOCS_V2.md Sections 6 (Recovery) and 8.5 (PoW Registration).

Build src/screens/Onboarding/:

STEP 1 â€" Welcome screen:
  Explain Privex in plain language. No legal jargon.
  "What you're about to create: An identity that only exists on your device.
   We never know who you are. Even if we wanted to, we couldn't."
  Button: "Create My Identity"

STEP 2 â€" Key generation (animated):
  Call cryptoWorker.call('generate_identity_keypairs')
  Show animated progress: "Generating your identity keys..."
  Keys generated entirely in browser. Never sent to server.
  Display px_[id] to user: "This is your Privex ID. Share it to receive messages."

STEP 3 â€" Set recovery password:
  Input: password (with strength meter â€" use zxcvbn library)
  Require: zxcvbn score >= 3 (strong password)
  Confirm password input
  "This password lets you recover your account from any device.
   We cannot reset it. There is no 'forgot password.'"
  
  On submit: call OPAQUE registration flow:
    1. cryptoWorker.call('opaque_register_start', password) â†' oprf_request
    2. POST /recovery/opaque/init (server evaluates OPRF)
    3. cryptoWorker.call('opaque_register_finish', password, server_response, full_key_bundle)
       â†' envelope + mac
    4. Send envelope to server (POST /keys/register includes both keys and OPAQUE record)

STEP 4 â€" Registration (PoW):
  Show animated "Registering your identity..."
  Background:
    1. Fetch PoW challenge from server
    2. Solve PoW in crypto worker (won't block UI â€" it's in a worker)
    3. Show progress: "X% complete" (from worker progress callback)
    4. Submit registration (keys + OPAQUE envelope + PoW solution)
  
  On success: session token stored in memory (not localStorage).

STEP 5 â€" Recovery options setup:
  Show three cards:
  
  Card A â€" "Backup Device" (recommended):
    "Add another device now by scanning a QR code."
    If user has another device handy: start device link flow.
    If not: "Do this later" (but nag them in settings)
  
  Card B â€" "Recovery Contacts" (optional):
    "Choose 2â€"3 trusted friends on Privex to hold recovery shares."
    If they have contacts: show contact picker.
    If not: "Do this after adding contacts."
    
  Card C â€" "Write Down Seed Phrase":
    Generate 24-word phrase from master seed.
    Show words in a grid.
    "Write these down. Store them somewhere safe. 
     We will never show them again. This is your master key."
    Require user to confirm 3 random words before proceeding.
    User can skip â€" but show a warning icon in Settings.

STEP 6 â€" Done:
  "You're in. No name. No phone. No email. Just you."
  Navigate to ConversationList.

THROUGHOUT:
  Progress is saved. If user closes browser mid-onboarding:
  Resume from the last completed step (stored in IndexedDB settings table).
  
  The registration step is atomic: either the whole thing succeeds or nothing is stored.
  Do not save partial key material.
```

**Human Checkpoint:**
- [ ] Full registration works end-to-end (do it yourself in the browser)
- [ ] Check server DB: `SELECT user_id FROM key_directory` â†' shows your new px_id, nothing else
- [ ] Verify no email/phone column in the row
- [ ] OPAQUE recovery check: open a private window, go to /recover, enter password â†' should recover keys
- [ ] Seed phrase: write down 3 words, test confirmation step rejects wrong words
- [ ] Session token in memory: DevTools â†' Application â†' Local Storage â†' nothing there. DevTools â†' Application â†' IndexedDB â†' settings â†' no session token (it's in-memory via Zustand)

---

### SESSION 15: Contact Management + Key Fetching

**Prompt:**
```
Build contact management with KT log verification.

Read docs/PRIVEX_DOCS_V2.md Sections 8.2 (KT Log) and 4.1 (Identity).

Build:

1. src/screens/AddContact/ â€" Add contact by px_id:
   Input: paste or type a px_[32hex] address
   OR: QR code scanner (use html5-qrcode library)
   
   On add:
   a. Fetch key bundle from GET /keys/{user_id}
   b. VERIFY KT inclusion proof:
      const valid = await cryptoWorker.call('kt_verify_inclusion', 
                        response.bundle, response.kt_proof, response.root);
      if (!valid) throw new Error("Key verification failed â€" possible MITM attack. Contact not added.")
   c. Store contact in IndexedDB contacts table (name_enc: empty, set later)
   d. Initiate PQXDH key exchange (precompute initial message keys)

2. src/screens/KeyVerification/ â€" Safety codes:
   Show both parties' fingerprint:
   safety_code = SHA-256(alice_IK_pub || bob_IK_pub)
   Display as: 8 groups of 5 decimal digits (like Signal's Safety Numbers)
   
   UI: "Compare this code with [contact name] over a separate channel
       (in person, phone call, or another app). 
       If it matches: tap Verified."
   
   Also show as QR code for easy scanning.
   
   On verify: set contacts.verified_fingerprint in IndexedDB.
              Show a checkmark next to messages from verified contacts.

3. Key change detection:
   Every time a message is received, check sender's IK against stored IK.
   If mismatch: show alert "Warning: [contact]'s key has changed. Verify their identity."
   Do not automatically trust new keys.
   
   Same check when fetching keys before sending a message.

4. src/components/ContactList.tsx:
   List all contacts from IndexedDB.
   Show: display name (or px_id if no name), verification status (checkmark/warning).
   Tap to open chat.
   Long press: rename, remove, view safety code.

Test:
  - Add a contact by px_id
  - Fetch their keys and verify KT proof passes
  - Tamper with the proof (simulate): should be rejected
  - Set a display name: verify it's stored encrypted in IndexedDB
  - View safety code: verify both px_ids are in the computation
```

**Human Checkpoint:**
- [ ] Add a contact: check IndexedDB contacts table â€" verify display name looks like encrypted bytes
- [ ] KT verification: Claude Code should have written a test for tampered proof â†' check this test passes
- [ ] Safety code: verify it changes when you change one character in either px_id
- [ ] Key change alert: manually change a contact's stored IK in IndexedDB â†' send a message â†' should show warning

---

### SESSION 16: Message Send + Receive Flow (The Core)

**Prompt:**
```
Build the core message send and receive system.

Read docs/PRIVEX_DOCS_V2.md Sections 4.4 (Double Ratchet), 4.5 (Sealed Sender),
and Section 11 (WebSocket Protocol + Messages API).

This is the most critical session. Take it carefully.

Build:

1. src/services/messaging.ts â€" Core message service:
   
   async sendMessage(peer_id: string, plaintext: string) â†' void
     a. Load ratchet session state from IndexedDB (or create new one via PQXDH)
     b. Call cryptoWorker.call('ratchet_encrypt', session_state, plaintext_bytes)
        â†' { ciphertext, new_session_state, message_header }
     c. Save new_session_state back to IndexedDB (encrypted)
     d. Encode as protobuf: TextMessage { ... }
     e. Call cryptoWorker.call('sealed_sender_encrypt', 
           protobuf_bytes, my_ed_priv, my_dil_priv, my_id, their_ik_pub)
        â†' sealed_bytes
     f. POST /messages/send { recipient_id: peer_id, content: base64(sealed_bytes) }
     g. Store message in IndexedDB messages table:
        { direction: 'sent', status: 'delivered', content_enc: encrypt(plaintext) }
   
   async receiveMessage(ws_message: WSMessage) â†' void
     a. Decode protobuf from ws_message.content
     b. Call cryptoWorker.call('sealed_sender_decrypt', 
           content_bytes, my_ik_priv, known_sender_keys)
        â†' { plaintext, sender_id, sender_verified }
     c. If sender_verified is false: show "unverified sender" warning, still display
     d. Load ratchet session for sender_id from IndexedDB
     e. Call cryptoWorker.call('ratchet_decrypt', session_state, inner_ciphertext, header)
        â†' { plaintext, new_session_state }
     f. Save new session state to IndexedDB
     g. Store plaintext in IndexedDB encrypted messages table
     h. POST /messages/ack { message_ids: [ws_message.message_id] }
     i. Emit event to update UI

2. src/screens/Chat/ChatScreen.tsx:
   Message list (virtual scroll â€" do NOT render all messages at once)
   Input box with send button
   Message status indicators: sending â†' sent â†' delivered
   Show sender_verified status on each message
   
   Message rendering:
   - Load last 50 messages from IndexedDB on open
   - Decrypt each using the master key (IndexedDB stores encrypted plaintext_preview_enc)
   - Load older messages on scroll up (pagination from IndexedDB)

3. WebSocket listener (src/services/websocket.ts):
   Connect to wss://api.privex.dpdns.org/v1/ws with session token in header
   On message: call receiveMessage()
   On prekey_low: automatically generate + upload 50 new OPKs
   On disconnect: reconnect with exponential backoff (max 300s)
   Heartbeat: respond to { type: "ping" } with { type: "pong" }

4. PQXDH session initiation:
   If no existing session with peer:
   a. Fetch peer's key bundle (including KT proof verification)
   b. Call cryptoWorker.call('pqxdh_initiate', peer_bundle) â†' { shared_secret, initial_message }
   c. Include initial_message in first message to peer (they use it to complete X3DH)
   d. Save initial session state

5. Handling a PQXDH initial message as recipient:
   When receiving a message from a new peer (no existing session):
   a. Extract the pqxdh_init field from the message header
   b. Call cryptoWorker.call('pqxdh_respond', pqxdh_init, my_keys) â†' shared_secret
   c. Initialize new ratchet session with shared_secret
   d. Proceed with ratchet_decrypt

Test:
  - Alice registers. Bob registers (two browser tabs or two incognito windows).
  - Alice adds Bob as contact.
  - Alice sends Bob a message.
  - Bob receives it in real time.
  - Verify: neither message in server DB is decryptable (it's sealed sender encrypted)
  - Bob sends reply.
  - Both see the conversation.
  - Close both browsers. Reopen. Both see their history (from IndexedDB).
```

**Human Checkpoint:**
This is your most important checkpoint. Test it yourself.
- [ ] Alice â†' Bob message delivery in real time
- [ ] Bob â†' Alice reply works
- [ ] Server DB check: `SELECT content FROM message_queue` right after send (before ack) â†' looks like random bytes (encrypted)
- [ ] After ack: `SELECT COUNT(*) FROM message_queue` â†' 0
- [ ] History persists after browser close and reopen
- [ ] Send 5 messages quickly (ratchet advancing): verify all arrive and decrypt correctly
- [ ] Open DevTools Network tab during send: NO plaintext anywhere in any request body

---

### SESSION 16B: Delivery & Read Receipts

**Goal:** Implement the complete receipt system from docs Section 4.10. Receipts must be indistinguishable from regular messages in network traffic.

**Prompt:**
```
Implement the delivery and read receipt system.

Read docs/PRIVEX_DOCS_V2.md Section 4.10 (Delivery & Read Receipts) completely.

CRITICAL DESIGN CONSTRAINTS:
  1. Receipts are Sealed Sender messages. They travel through the EXACT same
     code path as regular messages. The server cannot distinguish them.
  2. Receipts are NOT sent immediately. They are queued and sent at the next
     Poisson cover traffic interval. Read Section 5.3 for why.
  3. Receipts contain NO timestamps. No "read at 14:32" â€" just "read".
  4. Receipt participation is MUTUAL. If Alice disables receipts, she neither
     sends nor receives them. The setting affects both directions equally.

Build:

1. packages/crypto-wasm/src/receipts.rs â€" WASM module additions:
   receipt_generate_token() â†' [u8; 32]
     Returns 32 bytes of CSPRNG. This is the token_id.
     Alice generates this when sending a message.
     Alice stores it locally mapped to the message.
     Server never sees it. Only Bob sees it (inside the decrypted message).
   
   receipt_create(token_id: &[u8], receipt_type: &str) â†' Vec<u8>
     Creates the protobuf payload for a receipt message.
     receipt_type: "delivered" | "read"
     This payload will be encrypted via the normal Sealed Sender path.

2. Update packages/protocol/proto/messages.proto:
   Add ReceiptMessage type:
   {
     token_id: bytes,        // 32 bytes matching Alice's original token
     receipt_type: string,   // "delivered" | "read"
     // NO: timestamp, message_content, conversation_id
   }

3. Update src/services/messaging.ts:
   In sendMessage(): 
     a. Call receipt_generate_token() â†' token_id
     b. Include in encrypted message payload:
        { ...message_content, receipt_token: token_id,
          return_address: my_px_id, request_delivery: true, request_read: true }
     c. Store locally: db.receipt_tokens.add({ token_id, msg_id, status: "sent" })
   
   In receiveMessage():
     a. After decryption, check if message has receipt_token field
     b. If yes: queue a delivery receipt in IndexedDB outbox:
        db.receipt_outbox.add({ token_id, type: "delivered", to: sender_id })
        DO NOT SEND YET. Cover traffic Poisson timer sends it.
     c. When message appears in viewport (IntersectionObserver):
        db.receipt_outbox.add({ token_id, type: "read", to: sender_id })
        DO NOT SEND YET.

4. Update src/services/cover-traffic.ts:
   On each Poisson tick (before or after sending dummy message):
     Check db.receipt_outbox for pending receipts.
     For each pending receipt:
       Build receipt payload via receipt_create(token_id, type)
       Encrypt and send via Sealed Sender to the return_address
       Mark receipt as sent in outbox.
   This ensures receipts fire at the cover traffic interval, not immediately.

5. Receipt receiving in receiveMessage():
   If message type is "receipt":
     a. Extract token_id from decrypted payload
     b. Look up db.receipt_tokens where token_id matches
     c. If found: update status to "delivered" or "read"
     d. Emit event â†' UI updates message status indicator

6. IndexedDB additions (src/db/index.ts):
   receipt_tokens: { token_id, msg_id, status: "sent"|"delivered"|"read", peer_id }
   receipt_outbox: { id, token_id, type, to, queued_at, sent: boolean }

7. UI (src/screens/Chat/ChatScreen.tsx):
   Sent messages show status indicator:
     Clock icon:     sending (in flight)
     Single check:   sent (server received it)
     Double check:   delivered (Bob's device received it)
     Filled check:   read (Bob opened it)
   
   Incoming messages: no status shown (receipts are outgoing only)

8. Settings (src/screens/Settings/SettingsScreen.tsx):
   Settings â†' Privacy â†' Message Status:
   [Delivery Receipts] toggle â€" default ON â€" mutual
   [Read Receipts] toggle â€" default ON â€" mutual
   [Receipt Privacy Delay] toggle â€" default OFF
     If ON: add additional Poisson(lambda=1/300s) delay on top of cover traffic timing

Test:
  - Alice sends to Bob. Before Bob opens: Alice sees double check (delivered).
  - Bob opens message. Alice sees filled check (read).
  - Alice disables receipts â†' Bob's receipts stop arriving.
    VERIFY: Bob also stops receiving receipts from Alice (mutual).
  - Inspect Network tab during receipt: receipt POST /messages/send looks identical
    to any other message send. Same size, same endpoint, same format.
  - Enable Receipt Privacy Delay. Verify receipts arrive with additional delay.
```

**Human Checkpoint:**
- [ ] Send a message, Bob receives: double check appears for Alice
- [ ] Bob opens message: filled check appears for Alice
- [ ] Receipt POST in Network tab: looks identical to a regular message send
- [ ] Disable receipts for Alice: verify Bob ALSO stops receiving receipts from Alice (mutual)
- [ ] Check: receipt messages in IndexedDB have NO timestamp fields
- [ ] Receipt outbox: verify items queued but NOT sent until cover traffic tick fires

---

### SESSION 16C: Cross-Device Real-Time Sync

**Goal:** Messages sent from Device A must automatically appear on Device B (and any other linked devices).

**Prompt:**
```
Implement cross-device real-time sync for linked devices.

Read docs/PRIVEX_DOCS_V2.md Section 4.11 (Chat History â€" Cross-Device Sync),
specifically Mode C (Real-Time Cross-Device Sync).

Problem: When Alice sends a message from her PC (Device A), it does not appear
on her phone (Device B). Both devices share the same px_[id] but outgoing
messages don't sync. Fix this.

Design:
  When Alice sends a message from Device A to Bob:
  1. Normal send flow (sealed sender â†' Bob)
  2. ADDITIONALLY: create a sync copy encrypted to Device B

Implement:

1. packages/crypto-wasm/src/device_sync.rs:
   device_sync_encrypt(
     plaintext: &[u8],
     msg_id: &[u8],
     device_sync_key: &[u8]
   ) â†' Vec<u8>
     Returns: AES-256-GCM(device_sync_key, plaintext || msg_id)
   
   device_sync_decrypt(
     ciphertext: &[u8],
     device_sync_key: &[u8]
   ) â†' (Vec<u8>, Vec<u8>)  // (plaintext, msg_id)

2. Device sync key derivation (src/crypto/keystore.ts):
   On device linking (Section 6, Recovery Path 2), both devices agree on:
   shared_device_secret: established during the device link QR flow
   (already implemented â€" extend it)
   
   For each linked device, derive:
   sync_key_for_device_B = HKDF(shared_device_secret, "sync_key_" || device_B_id || "_v1")
   
   Store in IndexedDB:
   linked_devices: { device_id, sync_key_enc, device_label, linked_at }
   sync_key_enc = AES-256-GCM(masterKey, raw_sync_key) // encrypted at rest

3. Update src/services/messaging.ts (sendMessage):
   After sending to Bob:
   For each linked device in db.linked_devices:
     a. Decrypt sync_key from IndexedDB
     b. sync_blob = device_sync_encrypt(original_plaintext, msg_id, sync_key)
     c. Wrap sync_blob as a Sealed Sender message to OWN px_id:
        { type: "device_sync", device_id: target_device_id, content: sync_blob }
     d. POST /messages/send { recipient_id: my_px_id, content: sealed(sync_payload) }
   
   Server sees: Sealed Sender message to px_[alice] â€" same as any incoming message.
   Server does not know it's a self-sync. Cannot distinguish it.

4. Update src/services/messaging.ts (receiveMessage):
   If message type is "device_sync":
     a. Check: is this addressed to MY device_id?
        If not: discard (for another linked device)
        If yes: decrypt sync_blob using this device's sync_key
     b. device_sync_decrypt(sync_blob, sync_key) â†' (plaintext, msg_id)
     c. Store in IndexedDB as a SENT message with the original msg_id
     d. Update conversation list to show the sent message
     e. ACK to server (hard delete from queue)

5. UI:
   Synced messages appear in chat with "sent" status (same as if sent from this device).
   They appear in conversation order by server_anchor timestamp.
   No visual distinction between "sent here" vs "synced from another device".
   They are the same message.

Edge cases:
  - Message sent while Device B is offline: sync message sits in queue (30-day TTL)
    Device B gets it when it next comes online (same as any offline delivery)
  - Multiple linked devices: one sync copy per device (N devices = N sync messages)
  - Self-sync with no linked devices: no sync messages sent (check linked_devices is not empty)

Test:
  - Open two browser tabs (simulating Device A and Device B)
  - Link them (or manually set shared sync keys for testing)
  - Send message from Tab A to Bob
  - Verify: message appears in Tab B's sent messages
  - Verify: server DB only shows ONE sync blob (the copy to Tab B), deleted after delivery
  - Verify: sync message in network trace is indistinguishable from normal message
```

**Human Checkpoint:**
- [ ] Send from Tab A: message appears in Tab B as sent
- [ ] Server: `SELECT COUNT(*) FROM message_queue WHERE recipient_id = [alice_px_id]` immediately after send â†' 1 (the sync copy)
- [ ] After Tab B receives and acks: count â†' 0
- [ ] Check the sync message in network tab: identical in structure to regular messages
- [ ] Send from Tab B: appears on Tab A

---

### SESSION 16D: Time Synchronization & Desync Attack Prevention

**Prompt:**
```
Implement time synchronization from docs/PRIVEX_DOCS_V2.md Section 9.6.

Problem: Message timestamps are generated client-side. A manipulated device clock
can cause messages to appear out of order or bypass TTL enforcement.
But we cannot use an external NTP server because that would leak the user's IP.

Solution: Use the server itself as a time anchor. Server signs every message
delivery with a timestamp. Client verifies the signature and uses the server
timestamp as the authoritative ordering anchor.

Build:

1. Server: add time signing key (server/src/crypto/time_signing.rs):
   On server startup: load TIME_SIGNING_KEY from environment variable
   (32-byte Ed25519 private key, separate from session HMAC key)
   
   fn sign_timestamp(ts: u64, message_id: &[u8]) â†' Vec<u8>
     Ed25519_sign(ts.to_be_bytes() || message_id, time_signing_key)
   
   TIME_SIGNING_PUBLIC_KEY: published in app binary (pinned, like a CA cert)
   Add to .env.example: TIME_SIGNING_PRIVATE_KEY=

2. Server: add to WebSocket message delivery:
   When pushing a queued message to Bob via WebSocket:
   Add to the delivery envelope (NOT inside the encrypted content):
   {
     "type": "message",
     "message_id": "[uuid]",
     "content": "[base64 sealed sender blob]",
     "server_ts": unix_timestamp_seconds,
     "server_ts_sig": "[base64 Ed25519 signature over server_ts || message_id]"
   }
   
   IMPORTANT: server_ts and server_ts_sig are OUTSIDE the encrypted content.
   They are in the delivery envelope. Server naturally has access to generate them.
   They do NOT reveal message content. They only reveal: this message was delivered
   at approximately this time â€" which is not sensitive beyond what server already knows.

3. packages/crypto-wasm/src/time_verify.rs:
   time_verify(
     server_ts: u64,
     server_ts_sig: &[u8],
     message_id: &[u8],
     time_signing_pub: &[u8],    // Pinned in binary
     tolerance_secs: u64          // 90 seconds
   ) â†' TimeVerifyResult
   
   Returns: {
     valid_signature: bool,         // Ed25519 signature check
     within_tolerance: bool,        // |local_time - server_ts| <= tolerance_secs
     use_server_ts: bool,           // true if local clock is outside tolerance
     drift_seconds: i64             // how far off local clock is (signed)
   }

4. Update src/services/messaging.ts (receiveMessage):
   On receiving WebSocket delivery:
   a. Call time_verify(server_ts, server_ts_sig, message_id, PINNED_PUB_KEY, 90)
   b. If !valid_signature: log warning "Server timestamp signature invalid" â€" 
      still process message but flag it
   c. If !within_tolerance: show UI warning "Your device clock may be incorrect"
      Use server_ts as ordering anchor for this message
   d. Store in IndexedDB:
      { ..., client_ts: Date.now(), server_anchor: server_ts, use_server_ts: bool }

5. Message ordering in ChatScreen:
   Sort messages by: server_anchor if available, fallback to client_ts
   This prevents clock-manipulated messages from appearing in wrong position

6. The PINNED_PUB_KEY:
   Hardcode in src/config/time-signing.ts:
   export const TIME_SIGNING_PUB = new Uint8Array([...]) // 32 bytes Ed25519 public key
   This is the server's time signing public key.
   Generated once: `openssl genpkey -algorithm ed25519` then extract public key bytes.
   Add private key to server .env.
   If server rotates key (annually): update app binary + announce via KT log.

Test:
  - Send a message, receive it: inspect IndexedDB message row for server_anchor field
  - Manually set device clock 5 minutes ahead: send a message â†' no warning (within 90s)
  - Manually set device clock 10 minutes behind: receive a message â†' warning shown
  - Tamper with server_ts_sig in network interceptor: should flag as invalid signature
  - Verify messages sort correctly when client_ts is wrong but server_anchor is correct
```

**Human Checkpoint:**
- [ ] Received message in IndexedDB has server_anchor field
- [ ] Clock drift test: set clock 2 minutes wrong â†' no warning. 5 minutes wrong â†' warning shown
- [ ] Server_ts_sig verify: correct signature passes, tampered signature logs warning
- [ ] Message ordering: 10 messages with scrambled client_ts still sort in correct server order

---

### SESSION 16E: Session Management Fix + Push Notification Fix

**Prompt:**
```
Fix two known broken features: session management and push notifications.

PART 1 â€" Session Management Fix

Problem: Multi-device logout and SPK rotation are implemented but broken.
When the user taps "Log out everywhere", existing session tokens on other
devices are not actually invalidated.

Root cause: Session tokens are HMAC-based, stateless. To invalidate them,
the server needs to either:
  a. Track a revocation list (Redis set of revoked JTIs)
  b. Change the signing key (invalidates ALL tokens)
  c. Tie tokens to the SPK version (rotating SPK invalidates old tokens)

Implement option C (SPK-based invalidation):

1. Add spk_version to key_directory table:
   ALTER TABLE key_directory ADD COLUMN spk_version INTEGER NOT NULL DEFAULT 0;

2. Update session token to include spk_version:
   token_payload = { user_id, issued_at, expires_at, jti, spk_version }
   
   On verify: fetch user's current spk_version from key_directory
              if token.spk_version != current_spk_version: return 401

3. On SPK rotation (POST /keys/spk/rotate):
   UPDATE key_directory SET spk_version = spk_version + 1 WHERE user_id = $1
   This instantly invalidates all tokens with the old spk_version.

4. Client: "Log out everywhere" button:
   Calls POST /keys/spk/rotate
   Clears local session token from Zustand
   Navigates to login/onboarding

5. Verify: after SPK rotation, all existing session tokens return 401.
   New login after rotation issues a token with the new spk_version.

PART 2 â€" Push Notification Fix

Problem: Service Worker is registered and PWA works, but push event handling
is broken. Messages only arrive when the app is open.

Fix the Service Worker push handler (apps/web/public/sw.js):

The push payload is a wake token (random bytes). NOT message content.
On receiving a push event:
  1. Wake up
  2. Establish WebSocket to API (re-use or create)
  3. Fetch pending messages (GET /messages/poll?count=10)
  4. For each real message: store in IndexedDB
  5. Show OS notification with GENERIC text only:
     title: "Privex"
     body: "You have a new message."
     // NO sender name, NO message preview in the OS notification
     // Content is ONLY shown inside the app, never in the system notification
  6. On notification tap: open app â†' app reads from IndexedDB

Why generic notifications: The OS notification system (and notification history)
is accessible to other apps. Never put sensitive content in the notification body.

Additionally: fix the periodic background sync for mobile:
  Register PeriodicBackgroundSync if available:
  navigator.serviceWorker.ready.then(sw => {
    sw.periodicSync.register('check-messages', { minInterval: 15 * 60 * 1000 })
  });
  This wakes the service worker every 15 minutes on mobile to check for messages.

Test:
  - Rotate SPK â†' verify old session token returns 401 â†' log in fresh â†' works
  - Close the browser tab completely â†' receive a message â†' OS notification appears
  - Tap notification â†' app opens â†' message visible
  - Notification text: must say "You have a new message" NOT the actual message content
```

**Human Checkpoint:**
- [ ] SPK rotation â†' old session token returns 401 immediately
- [ ] Log in with new session after rotation â†' works normally
- [ ] Close app â†' send message â†' OS notification appears within ~30 seconds
- [ ] Notification body: verify it says "You have a new message" â€" NOT the message content
- [ ] Tap notification â†' app opens at conversation with new message

---

### SESSION 16F: Timing Mitigations (Polling, Constant Fetch, Jitter)

**Prompt:**
```
Implement the timing analysis mitigations from Section 5.7 of PRIVEX_DOCS_V2.md.

These are Phase 1 hardening features that reduce metadata leakage from timing patterns.
Read Section 5.7 completely before starting.

Implement all three mitigations:

MITIGATION 1 â€" Fixed Polling Schedule:

Add to src/services/connection.ts:
  
  startPollingSchedule(interval_minutes: number = 30) â†' void
    Runs on app startup.
    Every `interval_minutes` (default 30):
      1. Connect to API (if not already connected)
      2. Call GET /messages/poll?count=10
      3. Process received messages normally
      4. Disconnect if not actively in use
    
    This polling runs REGARDLESS of whether push notifications arrive.
    Push notifications are still used for faster delivery when app is in foreground.
    Polling is the fallback + the privacy-hardening layer.
    
    Critical: The interval must be consistent. Do NOT jitter the polling interval itself.
    The PREDICTABILITY of the poll schedule is what makes it a mitigation.
    An adversary seeing Bob's device connect every 30 minutes cannot distinguish
    "Bob connected because a message arrived" from "Bob connected on schedule."

Server-side: GET /messages/poll?count=10 (Section 11)
  Already specced. Make sure it returns exactly count items always.
  If real messages < count: pad with dummy items to reach count.
  Dummy item format: { type: "dummy", content: random_bytes(1024) }
  
  Add to server/src/routes/messages.rs:
  GET /messages/poll handler:
    Fetch up to N real messages for this user
    If len(real_messages) < N: generate (N - len) dummy items
    Shuffle real + dummy together (so real messages aren't always first)
    Return: { messages: [...], padded_to: N }

MITIGATION 2 â€" Constant Fetch Size (already handled above via /messages/poll):
  The /messages/poll endpoint ensures constant N items returned regardless of queue size.
  Client always makes the same request, always gets the same response size.
  No observable difference between "no messages" and "10 messages waiting."

MITIGATION 3 â€" Jittered Receipt Sending (verify and harden):
  From Session 16B, receipts are queued and sent at the next Poisson tick.
  Verify this is working correctly:
  - No receipt should be sent less than 5 seconds after message receipt
  - Receipts should appear in the cover traffic Poisson stream randomly
  
  Add optional Receipt Privacy Delay (from Settings, Section 4.10):
  If enabled: add an ADDITIONAL independent Poisson(lambda=1/300s) timer per receipt.
  The receipt fires at max(cover_traffic_tick, receipt_privacy_delay_tick).
  This means receipts take on average 5 minutes extra to send.
  
  Implement in src/services/cover-traffic.ts:
  sendQueuedReceipts(privacy_delay_enabled: boolean) â†' void
    For each item in receipt_outbox:
      If privacy_delay_enabled:
        if receipt.queued_at + privacy_delay_ms > Date.now(): skip (not ready yet)
        where privacy_delay_ms = sample from Poisson(lambda=1/300s) at queue time
      Send receipt (same as regular message path)
      Mark as sent in outbox

SETTINGS UI additions (Settings â†' Privacy):
  "Polling interval" â€" 5 min / 15 min / 30 min (default) / 60 min
  Show under: "These settings reduce what can be inferred from your network traffic."
  "Receipt Privacy Delay" â€" toggle (already from Session 16B)

Test:
  - Watch Network tab for 5 minutes with polling at 5-min interval
  - Verify: regular poll requests every 5 minutes regardless of messages
  - Verify: each poll response has exactly 10 items (real + dummies)
  - Send message â†' receipt queued â†' cover traffic fires â†' receipt sent
    Verify: receipt was NOT sent immediately on receive (at least 5-second gap)
  - With privacy delay ON: receipt should arrive at Alice 3-8 minutes after Bob reads
```

**Human Checkpoint:**
- [ ] Polling fires every 30 minutes â€" verify in Network tab (idle for 30 min, then request appears)
- [ ] GET /messages/poll always returns exactly 10 items â€" inspect response when queue is empty
- [ ] Response with empty queue: 10 dummy items returned, each same size as real messages
- [ ] Response with 3 real messages: 3 real + 7 dummy = 10 total
- [ ] Receipt not sent within 5 seconds of message receive â€" check timestamps in IndexedDB outbox

---

### SESSION 17: File Sharing

**Prompt:**
```
Build file and attachment sharing.

Read docs/PRIVEX_DOCS_V2.md Section 4.7 (File & Media Encryption).

Build:

1. src/services/files.ts â€" File encryption and upload service:
   
   async uploadFile(file: File, peer_id: string) â†' void
     a. Read file as ArrayBuffer
     b. Split into 4MB chunks
     c. Generate CEK: cryptoWorker.call('generate_cek') â†' 32 random bytes
     d. For each chunk:
        chunk_key = HKDF(CEK, "chunk" || i)
        nonce = random 12 bytes
        enc_chunk = AES-256-GCM(chunk_key, chunk_data, nonce)
        chunk_id = SHA-256(enc_chunk)
        await POST /blobs/{chunk_id} with enc_chunk bytes
     e. Build manifest:
        {
          filename_enc: XChaCha20(sender_key, filename),
          total_size: N,
          sha256_plaintext: SHA-256(original_file),
          chunks: [chunk_id_0, chunk_id_1, ...],
          cek: CEK
        }
     f. Wrap CEK for recipient (X25519 ephemeral wrap per Section 4.7)
     g. Send manifest as a sealed sender message with type "file"
   
   async receiveFile(manifest: FileManifest) â†' Blob
     a. Unwrap CEK using X25519
     b. Download all chunks: GET /blobs/{chunk_id}
     c. Decrypt each chunk
     d. Reassemble: new Blob(decrypted_chunks)
     e. Verify: SHA-256(reassembled) == manifest.sha256_plaintext
        If mismatch: REJECT (tampering detected)
     f. Return Blob (user triggers download)

2. src/screens/Chat/ â€" File message rendering:
   File messages show: file icon, encrypted filename (decrypted for display), size
   Download button: triggers receiveFile â†' browser download
   Image preview: if MIME type is image/*, show inline thumbnail
     Thumbnail encrypted separately (small, fast to load)
   Video/audio: show player with download-then-play pattern

3. Progress tracking:
   Upload: progress bar showing chunks uploaded (0/N â†' N/N)
   Download: progress bar showing chunks downloaded
   Both shown inline in the message list

4. Drag and drop support in ChatScreen:
   Drop a file onto the chat â†' triggers uploadFile

Test:
  - Upload a 10MB test file
  - Receive and download it
  - Verify SHA-256 of downloaded file matches original
  - Upload an image: verify thumbnail appears inline
  - Try to download a non-existent chunk: should show error, not crash
  - Verify blob_index has entries with correct chunk_ids
```

**Human Checkpoint:**
- [ ] 10MB file upload â†' download â†' SHA-256 matches
- [ ] Blob store: verify chunk names are SHA-256 hashes (random-looking hex strings)
- [ ] Blob store: verify no filenames or MIME types stored: `SELECT * FROM blob_index` â†' no filename column
- [ ] Progress bars work without freezing the UI (uploads run in a worker/chunked async)
- [ ] After download: check blob_index shows `downloaded = true`

---

### SESSION 18: Settings, Multi-Device, and Seed Phrase Recovery

**Prompt:**
```
Build the Settings screen, multi-device linking, and recovery flows.

Build src/screens/Settings/:

1. SettingsScreen.tsx â€" Main settings:
   Sections:
   - Account: px_id (copy button), recovery status
   - Privacy: cover traffic level (low/medium/high/off), connection mode
   - Recovery: backup status, linked devices, emergency contacts
   - Security: safety codes, active sessions, app lock
   - About: version, open source link, warrant canary link

2. Recovery section â€" src/screens/Settings/Recovery/:
   
   Recovery status card:
   Shows which recovery methods are active:
   âœ" OPAQUE Password Recovery (always active after setup)
   âœ"/âœ- Additional devices linked
   âœ"/âœ- Emergency contacts configured  
   âœ"/âœ- Seed phrase written down

   Link New Device:
   - Button: "Show linking QR code"
   - Generate: rendezvous_id + link_secret â†' encode as QR code
   - Show animated countdown (5 min TTL)
   - On link completion via WebSocket: show "Device linked successfully"
   
   Emergency Contacts:
   - Contact picker (from contacts list)
   - Select 2â€"3 contacts
   - Call cryptoWorker.call('shamir_split', master_seed, 2, 3) â†' shares
   - Encrypt each share to contact's public key
   - POST /recovery/shares/store
   - Show status: "3 contacts holding your recovery shares"
   
   View Seed Phrase (one time only during setup, but recoverable here):
   - Require device authentication before showing
   - Show 24 words
   - Warning: "Anyone who sees these words has access to your account"

3. Recovery flow â€" src/screens/Recovery/:
   
   Option A: Password recovery
   - Input: px_id + password
   - Run OPAQUE login flow
   - On success: session token â†' navigate to ConversationList
   - Message history not restored (lives on devices) â€" inform user
   
   Option B: Emergency contacts
   - Input: px_id
   - Show: "Contact 2 of your 3 recovery friends. Ask them to approve in Privex."
   - Poll for recovery share messages (they arrive as special sealed messages)
   - On 2 shares received: cryptoWorker.call('shamir_reconstruct', shares) â†' master_seed
   - Regenerate keypairs from seed â†' full recovery
   
   Option C: Seed phrase
   - 24-word input grid
   - cryptoWorker.call('seed_phrase_to_master_seed', mnemonic) â†' master_seed
   - Regenerate keypairs â†' register as new device with same identity
   - Authenticate with newly derived keys

4. Active Sessions view:
   Session tokens stored in memory only â€" cannot list them.
   Instead: "You have 1 active session on this device. To log out all devices,
            rotate your signed prekey â€" this will invalidate all existing sessions."
   Button: "Log out everywhere" â†' rotates SPK â†' POST /keys/spk/rotate
           â†' all existing session tokens become invalid (they depend on the SPK)

Test full recovery:
  - Register
  - Set up OPAQUE password
  - Note your px_id
  - Clear browser storage (simulates lost device)
  - Go to /recover
  - Enter px_id + password
  - Verify you're logged in with same identity (same px_id)
```

**Human Checkpoint:**
- [ ] Full OPAQUE recovery: clear browser storage, recover with password â†' same px_id active
- [ ] Shamir setup: 3 contacts configured â†' verify 3 encrypted blobs in recovery_shares table
- [ ] Seed phrase: generate â†' write down â†' clear storage â†' recover with phrase â†' same keys
- [ ] "Log out everywhere" (SPK rotation): verify old session token returns 401 after rotation

---

### SESSION 19: Service Worker + PWA Polish

**Prompt:**
```
Implement the Service Worker, PWA installation, and offline support.

Read docs/PRIVEX_DOCS_V2.md Section 9.3 (Service Worker Architecture).

Build:

1. apps/web/public/sw.js (Service Worker â€" not in src, deployed directly):
   Using Workbox 7:
   
   Cache strategy:
   - App shell (HTML, CSS, JS, WASM): CacheFirst, version-based invalidation
   - API calls: NetworkOnly (never cache API responses)
   - Fonts/Icons: StaleWhileRevalidate
   
   Background sync:
   self.addEventListener('sync', event => {
     if (event.tag === 'sync-pending-messages') {
       event.waitUntil(syncPendingMessages());
     }
   });
   
   syncPendingMessages():
     Read pending outbox from IndexedDB
     Attempt to send each via WebSocket or REST
     On success: remove from outbox
     On failure: keep for next sync attempt
   
   Push handler:
   self.addEventListener('push', event => {
     // Push payload is a wake token (random bytes), NOT message content
     // Connect to server, fetch pending messages
     // Show notification with content from decrypted message
     event.waitUntil(handlePushWake());
   });

2. PWA installation UI:
   Show "Install App" banner when browser emits beforeinstallprompt event.
   On desktop: show prominent install button in header when available.
   On mobile: show banner at bottom of screen.
   After install: dismiss banner, set installed flag in settings.

3. Offline state handling:
   - When offline: show subtle indicator (dot in header)
   - Messages typed while offline: saved to IndexedDB outbox
   - Queue indicator: "3 messages waiting to send"
   - On reconnect: trigger background sync

4. App lock (optional, enable in settings):
   After 5 minutes of inactivity (or on app background):
   Show PIN entry screen over the app.
   masterKey stays in memory. PIN does NOT protect the key.
   This is a "deterrent lock" â€" not a cryptographic lock.
   For cryptographic app lock: require masterKey re-derivation from OPAQUE.
   (Implement basic PIN lock only. Note the limitation clearly in UI.)

5. Notification permission flow:
   Request notification permission only after user sends first message.
   Explain WHY: "To deliver messages when Privex isn't open."
   If denied: explain messages will only arrive when the app is open.
   Never request permission on app load.

Build the production bundle:
  pnpm --filter web build
  Verify output in apps/web/dist/:
  - index.html
  - sw.js
  - assets/ (hashed filenames)
  - WASM file present
  - manifest.json

Deployment: 
  Configure Cloudflare Pages to serve apps/web/dist/.
  Add required security headers via _headers file in dist/:
  Content-Security-Policy: [per Section 9.5]
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
```

**Human Checkpoint:**
- [ ] Production build completes without errors
- [ ] Lighthouse PWA audit (DevTools â†' Lighthouse): should score 90+ on PWA
- [ ] Offline: enable airplane mode â†' app still loads (cached)
- [ ] Type message while offline: appears in outbox. Re-enable network: sends automatically
- [ ] Install prompt appears on desktop (may take 2 visits)
- [ ] Check `_headers` file is in dist/ â€" Cloudflare Pages will serve these headers

---

### SESSION 20: Phase 1 Integration Testing + Hardening

**Prompt:**
```
Phase 1 is feature-complete. Now harden and test it end-to-end.

Create a comprehensive Playwright test suite and fix any issues found.

1. Core messaging tests:

   test_registration():
     - Alice registers fresh (PoW challenge â†' solve â†' register)
     - Verify px_id generated, OPAQUE envelope stored
     - Verify NO PII in any server table:
       SELECT user_id, ik_ed25519 FROM key_directory â†' only hex IDs and key bytes
       SELECT * FROM message_queue â†' empty
       Verify no columns named email, phone, ip_address exist at all

   test_offline_delivery():
     - Alice and Bob registered
     - Simulate Bob offline (close his WebSocket)
     - Alice sends "offline test"
     - Check: SELECT COUNT(*) FROM message_queue WHERE recipient_id = bob_id â†' 1
     - Bring Bob online
     - Bob receives message
     - Check: SELECT COUNT(*) FROM message_queue â†' 0 (hard deleted on ack)

   test_message_ttl():
     - Send a message with ttl_seconds = 10 (10 seconds)
     - Wait 11 seconds without Bob connecting
     - Run expiry task manually: DELETE FROM message_queue WHERE expires_at < NOW()
     - Alice should see message status as "expired"
     - SELECT COUNT(*) FROM message_queue â†' 0

   test_file_transfer():
     - Alice sends a 10MB test file to Bob
     - Bob downloads and decrypts it
     - SHA-256 of decrypted output == SHA-256 of original
     - After download: SELECT COUNT(*) FROM blob_index WHERE downloaded = true â†' 1
     - Blob scheduled for deletion

   test_receipt_system():
     - Alice sends to Bob
     - Bob receives: Alice should see double-check (delivered)
     - Bob opens message: Alice should see filled-check (read)
     - Verify receipt NOT sent immediately (queued in receipt_outbox, sent at next tick)
     - Inspect receipt message in network: identical format to regular message
     - Disable receipts for Alice â†' verify Bob stops receiving receipts too (mutual)

   test_cross_device_sync():
     - Alice logs in on Tab 1 (Device A) and Tab 2 (Device B, same identity)
     - Send a message from Tab 1 to Bob
     - Verify: message appears in Tab 2 as a sent message
     - Send a message from Tab 2 to Bob
     - Verify: message appears in Tab 1 as a sent message

   test_account_recovery():
     - Alice registers with password "correct-horse-battery-staple-42"
     - Note her px_id
     - Clear IndexedDB (simulates lost device)
     - OPAQUE recovery: enter px_id + password
     - Verify: same px_id active, contacts restored
     - Verify: history restored if server-side backup was enabled

   test_time_sync():
     - Receive a message
     - Inspect IndexedDB message row: server_anchor field present and non-zero
     - Tamper with server_ts_sig in intercepted WebSocket message
     - Verify: message is still processed but "invalid timestamp" warning flagged

2. Security hardening checks:

   a. Sealed sender leak:
      Intercept POST /messages/send in DevTools Network tab.
      Request body MUST contain: recipient_id (visible), content (random bytes).
      Request body MUST NOT contain: sender_id, message_type, plaintext.

   b. Session token invalidation:
      Rotate SPK â†' POST /keys/spk/rotate
      Try old session token â†' must return 401
      New login after rotation â†' must work

   c. PoW replay:
      Register once. Try using the same PoW solution again â†' must return 400.

   d. KT tampering:
      Add contact. Intercept /keys/{id} response. Flip one byte in kt_proof.
      Contact must NOT be added. Error shown to user.

   e. History backup toggle:
      Enable backup â†' send 3 messages â†' SELECT COUNT(*) FROM history_blobs â†' 3
      Disable backup â†' SELECT COUNT(*) FROM history_blobs WHERE user_id = X â†' 0
      (All history deleted immediately on disable)

   f. Constant poll size:
      GET /messages/poll?count=10 with empty queue â†' must return exactly 10 dummy items
      GET /messages/poll?count=10 with 3 real messages â†' must return 10 items (3 real + 7 dummy)
      Verify response size is identical in both cases.

3. Performance checks:
   - WASM load time: app interactive in <2 seconds
   - Message send latency: <500ms excluding network
   - First message (PQXDH exchange): <1 second
   - Poll response time: <100ms server-side

4. Fix all issues found during testing.

5. Create docs/KNOWN_LIMITATIONS.md with honest Phase 1 limitations:
   - Phase 1 uses direct WebSocket (ISP can see api.privex.dpdns.org) â€" resolved in Phase 2
   - Cover traffic is skeleton in Phase 1 â€" fully active in Phase 2
   - Nym integration is skeleton in Phase 1 â€" fully active in Phase 2
   - iOS push notifications limited (Service Worker background wake unreliable on iOS)
   - Audio/video calls not yet implemented (Phase 3)
   - TURN server IP exposure during calls (acknowledged, same as Signal)
   - Timing analysis: ISP can see when device is online (mitigated by polling + jitter)
```

**Human Checkpoint â€" Phase 1 Completion Gate**

Do not proceed to Phase 2 until ALL pass:

```
MESSAGING:
  [ ] 1:1 message delivery end-to-end works
  [ ] Offline delivery: Bob misses messages, reconnects, receives them
  [ ] Message expiry: TTL-expired messages hard-deleted from queue
  [ ] File transfer: 10MB file, SHA-256 verified after download
  [ ] Blob deleted after recipient downloads

RECEIPTS:
  [ ] "delivered" appears after Bob's device receives
  [ ] "read" appears after Bob opens the message
  [ ] Receipt NOT sent immediately (verify outbox queued, fires at cover tick)
  [ ] Receipt in network tab: identical format to regular message
  [ ] Mutual: disable Alice's receipts â†' Bob's receipts stop too

CROSS-DEVICE:
  [ ] Message sent from Tab A appears in Tab B as sent
  [ ] Message sent from Tab B appears in Tab A as sent
  [ ] Sync message in network: indistinguishable from regular message

SECURITY:
  [ ] Sealed sender: no sender_id in any POST /messages/send request body
  [ ] KT tampering: tampered proof rejected, contact not added
  [ ] SPK rotation: old session token returns 401 immediately
  [ ] PoW replay: used challenge returns 400
  [ ] grep -r "ip_address" server/src/ â†' 0 results
  [ ] grep -r "user_id" server/src/ | grep "log::\|tracing::" â†' 0 results
  [ ] History backup disable: all blobs hard-deleted (SELECT COUNT(*) â†' 0)

POLLING:
  [ ] GET /messages/poll with empty queue returns exactly 10 items
  [ ] GET /messages/poll with 3 real messages returns exactly 10 items
  [ ] Response body size is the same in both cases

TIME SYNC:
  [ ] Received messages have server_anchor in IndexedDB
  [ ] Tampered server_ts_sig: message still processes but warning flagged

SESSION:
  [ ] SPK rotate â†' old tokens 401 â†' new login works
  [ ] Push notification: close app â†' receive message â†' OS notification appears
  [ ] Notification body: generic text only, NOT message content

ACCOUNT RECOVERY:
  [ ] OPAQUE recovery: clear IndexedDB â†' recover with password â†' same px_id
  [ ] History backup: enable â†' send messages â†' disable â†' history blobs deleted

INFRASTRUCTURE:
  [ ] Lighthouse PWA: score 90+
  [ ] Production build deploys to Cloudflare Pages
  [ ] Server running on Oracle free tier
  [ ] Redis: `CONFIG GET save` â†' empty, `CONFIG GET appendonly` â†' no
  [ ] PostgreSQL: message_queue, blob_index, history_blobs show relpersistence = 'u'
```

**Phase 1 is complete when every box above is checked.**
Commit everything: `git add -A && git commit -m "Phase 1 complete"`
Tag the release: `git tag v0.1.0-phase1`
Push to GitHub: `git push origin main --tags`
Open source: make repo public

---

## Part 5 â€" Phase 2: Metadata Perfection (Sessions 21â€"26)

### SESSION 21: Cover Traffic System

**Prompt:**
```
Implement the cover traffic system.

Read docs/PRIVEX_DOCS_V2.md Section 5.3 (Cover Traffic).

Build src/services/cover-traffic.ts:

CoverTrafficService class:
  
  start(level: 'low' | 'medium' | 'high' | 'off') â†' void
    Starts a Poisson-distributed timer:
      low:    Î» = 1/30s  (average 1 dummy per 30 seconds)
      medium: Î» = 1/10s  (default)
      high:   Î» = 1/3s   (maximum protection)
    
    Timer: setInterval-like but with Poisson distribution:
      next_interval = -ln(Math.random()) / Î»  // Exponential distribution
    
    On each tick: sendDummyMessage()
  
  sendDummyMessage() â†' void
    recipient_id = generateRandomPxId()  // Random 32-char hex string
    content = cryptoWorker.call('random_bytes', 1024)  // 1024 bytes of random
    POST /messages/send { recipient_id, content }
    
    The server receives this, finds no mailbox for recipient_id, silently drops it.
    The REQUEST is indistinguishable from a real message.
    Cover traffic MUST go through the same code path as real messages.
    Do NOT add a special header or flag that marks it as cover traffic.
  
  stop() â†' void

Also implement: message padding check.
In sendMessage(), verify that sealed_bytes.length % 1024 === 0 before sending.
If not padded correctly (bug in WASM layer): throw an error. Do not send.

Cover traffic settings UI:
  In Settings â†' Privacy section:
  "Background traffic" with explanation:
  "Sending occasional dummy messages makes it impossible to tell when
   you're actually chatting by watching your network traffic. More = more battery."
  Radio buttons: Low / Medium (recommended) / High / Off
  Warning for Off: "With this off, someone watching your network can tell
                    when you send messages. Only disable this if you need to
                    conserve data/battery."

Battery/data impact note in UI:
  Low:    ~1-2MB/hour extra data
  Medium: ~4-6MB/hour extra data  
  High:   ~18-25MB/hour extra data

Test:
  Enable cover traffic.
  Watch Network tab in DevTools.
  Verify: a stream of POST /messages/send requests on Poisson schedule.
  Verify: these requests are indistinguishable from real messages in the request body.
  Send a real message.
  Verify: the real message is indistinguishable from cover traffic in the network trace.
```

**Human Checkpoint:**
- [ ] Enable cover traffic â†' watch Network tab â†' see periodic POST requests
- [ ] Timing: are they on a smooth random schedule (not exactly every N seconds)? Should be.
- [ ] Real message sent while cover traffic running: can you tell which one is the real message from the Network tab alone? You should NOT be able to.
- [ ] Server side: `SELECT COUNT(*) FROM message_queue` â€" cover traffic messages never arrive (dropped by server with no mailbox found). Count should stay at 0.

---

### SESSION 22: DNS-over-HTTPS + Censorship Circumvention

**Prompt:**
```
Implement censorship circumvention and DNS protection.

Read docs/PRIVEX_DOCS_V2.md Sections 5.4 and 5.5.

1. DNS-over-HTTPS (DoH):

In the web app, all fetch() calls already go to api.privex.dpdns.org.
Browser DNS resolution cannot be controlled from JavaScript (it uses OS DNS).
However, the Service Worker CAN intercept requests and override behavior.

For the web app specifically:
  - Ensure all API URLs are hardcoded (never resolved from a user-configurable DNS name)
  - In settings: add a "DNS Server" option that sets a DoH URL in IndexedDB
  - When making WebSocket/fetch requests: prefix with the DoH-resolved IP if available
  - For Nym connection: pass the gateway address as an IP, not a hostname

Document the limitation clearly:
  "Web app DNS is controlled by the browser. For maximum DNS privacy,
   use a browser with built-in DoH (Firefox with DNS over HTTPS enabled,
   or Brave). The Privex web app does not use external DNS lookups beyond
   your browser's resolver."

2. Connection mode detection + fallback cascade:

Build src/services/connection.ts â€" ConnectionManager:

  async connect() â†' void
    Try methods in order, with 5s timeout each:
    
    Method 1: Direct WebSocket to Nym gateway
      ws = new WebSocket('wss://gateway.nymtech.net:443')
      If success: use Nym transport. Done.
    
    Method 2: Domain fronting via Cloudflare
      Modify the WebSocket URL host to appear as a popular Cloudflare site
      but set Host header to privex.dpdns.org.
      (Note: only works on non-browser environments due to CORS.
       For web: this path is limited. Document this honestly.)
    
    Method 3: Try hardcoded bridge nodes (10 bridges)
      For each bridge in BRIDGE_NODES:
        Try WebSocket to bridge
        If success: route all traffic through this bridge
    
    Method 4: Snowflake
      Load Snowflake WebAssembly proxy client
      (use the snowflake.torproject.org CDN build if available)
      If success: route through Snowflake
    
    Method 5: Direct connection to API (last resort, no anonymization)
      ws = new WebSocket('wss://api.privex.dpdns.org/v1/ws')
      Show warning to user: "Connected directly. Your IP is visible to Privex server.
                             Enable a VPN or Tor for anonymization."
    
    UI: During connection attempts, show:
      "Establishing secure connection..." with animated dots
      Do not show which method is being tried (reveals nothing to an observer)
      If Snowflake: show "This may take 30 seconds..."

3. Bridge nodes configuration:
   
   Hardcode BRIDGE_NODES in src/config/bridges.ts:
   These are NOT plaintext â€" XOR obfuscate them:
   const obfuscated = [0x1a2b3c...];  // XOR with BRIDGE_KEY
   const BRIDGE_KEY = [0x7f, 0x3a, ...];  // Also in code, but makes extraction harder
   
   Add 3 placeholder bridge addresses for dev. In production, these are replaced
   with real bridge node IPs from the relay network.
   
   Add: "I can't connect" button in the connection screen that:
   - Shows a mailto link: bridges@privex.dpdns.org
   - Auto-drafts an email requesting new bridges

4. Settings â†' Connection:
   Connection mode: Nym (default) / Direct (last resort)
   Circumvention: Auto (tries all methods) / Off
   Show current connection method (after successful connect)
   Bridge configuration: text area for manual bridge entry (for users who have out-of-band bridges)

Test:
  - Block the main API domain in /etc/hosts: 127.0.0.1 api.privex.dpdns.org
  - Open Privex
  - Verify: falls through to bridge nodes (or Snowflake if configured)
  - Should eventually connect (via some fallback path)
```

**Human Checkpoint:**
- [ ] Domain blocked â†' app tries fallbacks â†' eventually connects (or shows appropriate error)
- [ ] "I can't connect" button: appears after 30s of failed connection attempts
- [ ] Bridge nodes: XOR obfuscated in source code (not plaintext IPs)
- [ ] Connection mode shown in Settings â†' Connection

---

### SESSION 23: CSAM Protection System (Phase 2 Critical)

**Prompt:**
```
Implement the CSAM protection system.

Read docs/PRIVEX_DOCS_V2.md Section 7 COMPLETELY before starting.
This section is critical. Read it multiple times.

Prerequisites: 
  The WASM module already has pdq_hash(), psi_blind_hash(), psi_unblind(), 
  and psi_check_membership() from Session 6. Build on those.

IMPORTANT SCOPE NOTE:
  The full ZK proof system (Groth16/circom) requires a public trusted setup ceremony
  that hasn't happened yet. For Phase 2 development:
  - Implement PDQ hashing and PSI protocol fully
  - Build the ZK circuit (csam_check.circom) 
  - Use a DEVELOPMENT trusted setup (not for production â€" this is just for testing)
  - Document that PRODUCTION requires a public ceremony before launch
  - This is correct engineering practice: build and test first, ceremony before launch

Build:

1. Server-side OPRF endpoint (server/src/routes/csam.rs):
   POST /csam/psi_evaluate (unauthenticated â€" called with blinded hash before message send)
   Body: { blinded_hash: "[hex]" }
   Response: { evaluated: "[hex]" }
   
   Server has: NCMEC_OPRF_KEY (a secret scalar, loaded from env var)
   Server computes: evaluated = NCMEC_OPRF_KEY * blinded_hash (Ristretto255 scalar mult)
   Server does NOT learn: the original hash (it's blinded)
   
   NCMEC hash database:
   For dev: use a test set of 10 fake PDQ hashes.
   For production: NCMEC provides their hash database to approved platforms.
     In the meantime: the server also has a pre-computed set T (all hashes in the DB
     evaluated with the OPRF key). The client checks membership in T.
   
   Server precomputes T on startup (or loads from file):
   T = { NCMEC_OPRF_KEY * H_to_curve(h) for h in ncmec_hashes }
   Return T as part of the PSI response (along with evaluated).

2. Client-side CSAM check (src/services/csam.ts):
   
   async checkImage(imageData: ImageData) â†' boolean (true = clear, false = blocked)
     a. hash = await cryptoWorker.call('pdq_hash', imageData.data, width, height)
     b. { blinded, r } = await cryptoWorker.call('psi_blind_hash', hash)
     c. { evaluated, T } = await POST /csam/psi_evaluate { blinded_hash: blinded }
     d. unblinded = await cryptoWorker.call('psi_unblind', evaluated, r)
     e. is_match = await cryptoWorker.call('psi_check_membership', unblinded, T)
     f. if is_match: return false (BLOCKED)
     g. return true (clear)
   
   checkVideo(videoFile: File) â†' async generator yielding progress:
     Extract keyframes at 5-second intervals (use canvas + HTMLVideoElement)
     For each keyframe: checkImage()
     If any keyframe is blocked: return false immediately
     Yield progress: { checked: N, total: M, blocked: false }

3. Integration with file upload (update Session 17 code):
   In uploadFile(), before encrypting:
   if (file.type.startsWith('image/') || file.type.startsWith('video/')) {
     const clear = await csam.checkImage(imageData)  // or checkVideo
     if (!clear) {
       showError("This file cannot be sent.")
       return
     }
   }
   
   DO NOT mention CSAM to user explicitly. Just "This file cannot be sent."
   (To avoid tipping off bad actors about what was detected)

4. ZK Circuit (packages/circuits/src/csam_check.circom):
   Write the circom circuit that proves:
   "I have a hash H, I computed the PSI check correctly, result = 0 (no match)"
   
   The circuit proves knowledge of:
   - PDQ hash (private input)
   - PSI blinding factor r (private input)
   
   Without revealing either to the verifier.
   
   Public inputs: image_commitment (Pedersen), result (0 or 1)
   
   For now: use a development ceremony (snarkjs groth16 setup in a single command).
   Production: requires full public ceremony.
   
   Generate: csam_check.r1cs, csam_check_final.zkey (dev), verification_key.json
   
   Add server-side Groth16 verifier (snarkjs verify or Rust port).
   For Phase 2 dev: server optionally skips ZK proof verification (dev_mode = true).
   For Phase 3+: ZK proof required for all image messages.

5. Direct-to-NCMEC reporting (src/services/reporting.ts):
   For received messages the user wants to report:
   reportToNCMEC(messageContent: Uint8Array, senderCert: Uint8Array) â†' void
   - Build a CyberTipline report structure
   - POST directly to NCMEC's API (https://api.missingkids.org/cybertipline/v1/report)
   - This goes from the user's browser directly to NCMEC
   - Privex servers are NOT in this chain
   - Report button in message right-click context menu (long press on mobile)

Test:
  - Create a test PDQ hash that you add to your fake NCMEC database
  - Create an image whose PDQ hash matches your test hash
  - Try to send that image: should be blocked with "This file cannot be sent"
  - Send a different image: should succeed
  - Generate ZK proof for the successful send: verify proof validates
```

**Human Checkpoint:**
- [ ] Blocked image test: your test hash in fake DB â†' upload blocked
- [ ] Normal image: passes and sends successfully
- [ ] PSI protocol: server never sees the actual hash â€" verify by adding logging on the server side to print what it receives: should be curve points (random-looking bytes), not recognizable hash values
- [ ] ZK proof generates and verifies (dev mode)
- [ ] Report to NCMEC: verify the HTTP request goes DIRECTLY to missingkids.org (not through your server) in Network tab

---

### SESSION 24: Message Padding Audit + Timing Hardening

**Prompt:**
```
Audit and harden timing-sensitive operations.

This session is about security engineering, not new features.

1. Message padding verification:
   Audit ALL places where messages are sent.
   Verify padding is applied BEFORE sealed sender encryption.
   Write a test: send a 1-byte message, capture the ciphertext size.
   It MUST be exactly 1024 bytes (after encryption overhead).
   
   Fix any path where padding is not applied.

2. SPK rotation jitter:
   The SPK should rotate every 30 Â± 5 days (randomized).
   Not exactly every 30 days â€" that creates a predictable timing pattern.
   
   Add to src/services/keys.ts:
   checkSPKRotation() â†' void
     If now > last_rotation + random(25 * 24h, 35 * 24h):
       generateNewSPK()
       POST /keys/spk/rotate
       Update last_rotation in IndexedDB
   
   Call checkSPKRotation() on app startup and every 24 hours.

3. OPK replenishment timing:
   OPKs run out over time. Replenishment is a detectable event.
   Add random delay before replenishment (0â€"4 hours after trigger):
   
   onPreKeyLow():
     const delay_ms = Math.random() * 4 * 60 * 60 * 1000
     setTimeout(() => replenishOPKs(), delay_ms)
   
   This prevents exact timing correlation between "Alice's OPKs were just fetched by
   someone" and "Bob just initiated a PQXDH session with Alice".

4. Authentication session renewal:
   Session tokens are 24 hours.
   Renew silently at T-2 hours (22 hours after issue).
   Add jitter: renew at T - (1.5h + random(0, 1h)).
   This prevents predictable 24-hour renewal pulses.
   
   Add to src/services/auth.ts:
   scheduleRenewal(token_expiry: number) â†' void
     jitter = Math.random() * 60 * 60 * 1000  // 0-1 hour
     renew_at = token_expiry - 2 * 60 * 60 * 1000 - jitter
     setTimeout(() => renewSession(), Math.max(0, renew_at - Date.now()))

5. Constant-time comparison for all security-critical comparisons:
   Wherever you compare MAC tags, session tokens, or challenge responses:
   Use a constant-time comparison function to prevent timing attacks.
   
   In WASM (Rust): use subtle crate's ConstantTimeEq
   In TypeScript: implement:
   function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
     if (a.length !== b.length) return false;
     let diff = 0;
     for (let i = 0; i < a.length; i++) {
       diff |= a[i] ^ b[i];
     }
     return diff === 0;
   }
   
   Audit all comparisons: replace == or === on security buffers with this function.

6. Server-side: OPAQUE wrong password response timing:
   Test: measure response time for correct vs incorrect OPAQUE password.
   They should be within 5ms of each other (constant time).
   If not: add an artificial delay to normalize the timing.

Test everything:
  - 1-byte message â†' measure ciphertext size â†' must be 1024 bytes
  - SPK rotation: set last_rotation to 35 days ago â†' rotates on next startup
  - OPK replenishment: trigger it â†' verify delay before actual request
  - Session renewal: set token to expire in 1.5h â†' verify renewal fires before expiry
```

**Human Checkpoint:**
- [ ] 1-byte message ciphertext: inspect in Network tab â†' Content-Length should be ~1024 + small overhead
- [ ] OPAQUE timing: run 10 correct + 10 incorrect login attempts, measure response times â€" should be indistinguishable
- [ ] SPK rotation jitter: verify the next_rotation timestamp is NOT exactly `now + 30 days` but `now + (25-35 days)`

---

### SESSION 25: Warrant Canary + Open Source Preparation

**Prompt:**
```
Prepare Privex for open source release and implement the warrant canary.

1. Warrant Canary (docs/WARRANT_CANARY.md and public page):
   
   Create: apps/web/public/canary/index.html (static page, served publicly)
   
   Content (update monthly via signed git commit):
   "Privex Warrant Canary â€" [MONTH YEAR]
   
   1. We have not received any national security letters.
   2. We have not received any secret court orders.
   3. We have not been required to add backdoors to our software.
   4. We have not been subject to any gag orders.
   5. We have not turned over any user data to any government.
   
   This statement is signed with our PGP key: [FINGERPRINT]
   
   Last updated: [DATE]
   
   If this page is not updated within 45 days of the above date,
   or if any of the above statements change, assume we have been compromised.
   
   [GPG SIGNATURE BLOCK]"
   
   Generate a GPG key for Privex: privex-canary@privex.dpdns.org
   Publish the public key fingerprint in README.md, on the website, and on keyservers.
   
   Add a GitHub Actions workflow that reminds you to update the canary monthly:
   - Creates an issue on the 1st of each month: "Update warrant canary"
   - If canary not updated by the 15th: creates another issue flagged urgent

2. Open Source license:
   Core cryptographic packages (crypto-wasm, circuits, protocol): MIT License
   Server code: AGPL-3.0 (requires anyone running a modified server to release changes)
   Client apps (web, android, ios, desktop): GPL-3.0
   
   Add LICENSE files to each package.
   Add SPDX headers to all source files.
   
   Create CONTRIBUTING.md with:
   - Absolute rule: No custom crypto (point to the law in CLAUDE.md)
   - How to run locally
   - Security vulnerability reporting: security@privex.dpdns.org
   - Code review requirements (crypto changes: requires 2 reviewer approvals)

3. Security policy (SECURITY.md):
   Contact: security@privex.dpdns.org (GPG key published)
   Response SLA: 48 hours acknowledgment, 7 days triage
   Scope: all repos in the Privex GitHub organization
   Out of scope: social engineering, spam, clickjacking via self-hosted installs
   Bug bounty: "Not yet, but we'll publicly acknowledge all valid reports."
   
4. Reproducible builds verification:
   apps/web:
     Add to vite.config.ts:
       build.rollupOptions.output.entryFileNames = '[name].js'  // deterministic names
       build.rollupOptions.output.chunkFileNames = '[name]-[hash].js'
     Set SOURCE_DATE_EPOCH in build script to a fixed timestamp.
     Verify: run build twice, SHA-256 of all output files should match.
   
   server/:
     Add to Cargo.toml:
       [profile.release]
       debug = false
       strip = "symbols"
     Verify: cargo build --release twice â†' same binary hash.
   
   Create: scripts/verify-build.sh
     Builds twice, compares hashes, exits 1 if any mismatch.
     Add to CI.

5. GitHub Actions CI pipeline (.github/workflows/):
   ci.yml:
     On every push:
     - cargo test (server + crypto-wasm + relay)
     - cargo clippy (Rust linting â€" zero warnings allowed)
     - pnpm typecheck (TypeScript strict mode â€" zero errors)
     - pnpm test (unit tests)
     - verify-build.sh (reproducible builds)
   
   security-audit.yml:
     Weekly:
     - cargo audit (checks for CVEs in Rust dependencies)
     - pnpm audit (checks for CVEs in npm dependencies)
     - Creates GitHub issue if any HIGH or CRITICAL CVEs found

6. README.md (final version):
   One clear sentence: "Zero-knowledge end-to-end encrypted communication."
   Architecture diagram (ASCII or SVG)
   Quick start (local dev in 3 commands)
   Link to full technical docs
   Link to warrant canary
   Link to security policy
   "Why trust us? You don't have to. Read the code."
```

**Human Checkpoint:**
- [ ] Canary page is live and signed with your GPG key
- [ ] Verify the GPG signature manually: `gpg --verify canary.txt.asc canary.txt`
- [ ] Reproducible build: run `./scripts/verify-build.sh` â†' all hashes match
- [ ] cargo audit: 0 HIGH/CRITICAL findings
- [ ] pnpm audit: 0 HIGH/CRITICAL findings
- [ ] CI pipeline: push a commit â†' all checks pass
- [ ] All files have correct SPDX license headers

---

### SESSION 26: Infrastructure as Code + Deployment

**Prompt:**
```
Create the complete deployment configuration for the Oracle + Hetzner setup.

Read the infrastructure section of the Claude Code Build Guide (Part 1) for the server specs.

1. Server setup scripts (infra/scripts/):
   
   setup-main-server.sh (Oracle ARM - main server):
     - Install Docker + Docker Compose
     - Configure firewall (ufw rules from the guide)
     - Set up automatic security updates (unattended-upgrades)
     - Configure tmpfs for /var/log (logs to RAM):
         Add to /etc/fstab: tmpfs /var/log tmpfs defaults,noatime,nosuid,size=256m 0 0
     - Disable swap: swapoff -a + remove from /etc/fstab
     - Set up LUKS encryption on data volumes
     - Clone privex repo
     - Set up .env from environment variables (never committed)
     - Start Docker Compose
   
   setup-relay.sh (Oracle ARM / Hetzner - relay nodes):
     - Minimal setup: Docker only
     - Start relay container
     - Register with main server (POST /relays/register with relay pubkey)

2. Docker Compose (infra/docker-compose.prod.yml):
   
   services:
     server:
       build: ./server
       env_file: .env
       restart: always
       depends_on: [postgres, redis]
       networks: [internal, external]
       # internal: for postgres/redis comms (not exposed)
       # external: for Caddy â†' server comms
     
     postgres:
       image: postgres:16-alpine
       volumes:
         - ./infra/postgres/postgresql.conf:/etc/postgresql/postgresql.conf
         - postgres_data:/var/lib/postgresql/data
       command: postgres -c config_file=/etc/postgresql/postgresql.conf
       networks: [internal]  # NOT exposed to external network
     
     redis:
       image: redis:7.2-alpine
       command: redis-server /etc/redis/redis.conf
       volumes:
         - ./infra/redis/redis.conf:/etc/redis/redis.conf
       networks: [internal]  # NOT exposed to external network
     
     caddy:
       image: caddy:2-alpine
       ports: ["80:80", "443:443", "443:443/udp"]  # HTTP, HTTPS, QUIC
       volumes:
         - ./infra/caddy/Caddyfile:/etc/caddy/Caddyfile
         - caddy_data:/data
       networks: [internal, external]
   
   networks:
     internal: (driver: bridge, internal: true)  # Postgres/Redis not externally reachable
     external: (driver: bridge)
   
   volumes: postgres_data, caddy_data

3. Caddyfile (infra/caddy/Caddyfile):
   
   api.privex.dpdns.org {
     log {
       output discard    # No access logs. EVER.
     }
     
     reverse_proxy server:8080 {
       header_up X-Real-IP ""          # Strip real IP before passing to server
       header_up X-Forwarded-For ""    # Strip forwarded IP
       # Server NEVER sees client IPs
     }
     
     header {
       Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
       X-Frame-Options DENY
       X-Content-Type-Options nosniff
       Referrer-Policy no-referrer
       -Server  # Remove Server header (don't reveal Caddy or version)
     }
   }

4. Relay node Docker image (relay/Dockerfile):
   FROM rust:1.78-alpine AS builder
   WORKDIR /build
   COPY . .
   RUN cargo build --release
   
   FROM alpine:3.19
   RUN adduser -D -s /bin/false relay
   COPY --from=builder /build/target/release/privex-relay /usr/local/bin/
   USER relay
   EXPOSE 8443
   CMD ["privex-relay"]

5. Health checks:
   Add GET /health endpoint to server:
   Returns: { status: "ok", timestamp: unix_ts }
   No user data. No version info. Just "ok".
   
   Caddy health check: curl -f http://server:8080/health
   
   Oracle Cloud monitoring: configure a simple TCP health check on port 443.

6. Automatic TLS certificate:
   Caddy handles this automatically via ACME/Let's Encrypt.
   Verify: on first start, certificates are issued and HTTPS works.
   Add to setup script: wait for certificate issuance before proceeding.

Test deployment:
  - Run ./infra/scripts/setup-main-server.sh on a fresh Ubuntu VM locally (Vagrant or Docker)
  - Verify: docker-compose -f infra/docker-compose.prod.yml up works
  - Verify: https://api.privex.dpdns.org/health returns {"status": "ok"}
  - Verify: postgres is NOT reachable from outside Docker network
  - Verify: redis is NOT reachable from outside Docker network
  - Verify: Caddy strips X-Real-IP and X-Forwarded-For before passing to server
```

**Human Checkpoint:**
- [ ] `docker ps` on the server shows: server, postgres, redis, caddy all running
- [ ] `curl https://api.privex.dpdns.org/health` returns `{"status": "ok"}`
- [ ] Try to connect to postgres directly from outside: `psql -h [server-ip] -p 5432` â†' connection refused (good)
- [ ] Try to connect to redis from outside: `redis-cli -h [server-ip] -p 6379 ping` â†' connection refused (good)
- [ ] Check caddy logs: `docker logs privex-caddy 2>&1` â†' should show no request logs (or "discard" sink)
- [ ] /var/log on the server is tmpfs: `df -h /var/log` â†' should show type tmpfs
- [ ] Swap is off: `swapon --show` â†' empty output

---

## Part 6 â€" Ongoing Operations

### Monthly Checklist (after launch)

```
Security:
  [ ] Run cargo audit + pnpm audit â†' 0 HIGH/CRITICAL CVEs
  [ ] Update all dependencies to latest patch versions
  [ ] Check warrant canary â†' update and re-sign
  [ ] Review GitHub security alerts

Infrastructure:
  [ ] Check Oracle free tier usage â€" verify not exceeding limits
  [ ] Check Cloudflare R2 storage â†' staying under 10GB free tier
  [ ] Verify all relay nodes online: GET /relays returns N online nodes
  [ ] Check OPAQUE record count (users registered) â€" plan scaling if growing

Code:
  [ ] Review any community contributions (if open source)
  [ ] Verify CI still passing on main branch
  [ ] Check Playwright E2E tests still passing in production
```

### How to Open Source Correctly

1. Create a GitHub organization: `github.com/privex-app`
2. Create the repo: `github.com/privex-app/privex` (the monorepo)
3. Create separate repos for documentation: `github.com/privex-app/privex-docs`
4. Add a GitHub Discussions for community questions
5. Add Issue templates: Bug Report, Feature Request, Security Concern (links to security@)
6. NEVER commit: `.env` files, private keys, TURN secrets, database URLs
7. The `.env.example` shows every variable needed â€" community can self-host from it

### When to Get a Security Audit

Before calling it "production-ready" and promoting it to journalists/activists:
- Budget: â‚¬5,000â€"15,000 for a focused audit by a reputable firm
- Firms: Cure53, Trail of Bits, NCC Group, Radically Open Security (sliding scale)
- Scope for Phase 1 audit: Cryptographic architecture + server code + WASM module
- The open source codebase lets firms audit offline, reducing cost
- Apply to: Open Technology Fund for subsidized security audits (they fund exactly this)

---

## Appendix: Quick Reference

### Starting a New Session

```
1. Update CLAUDE.md â†' "CURRENT PHASE & SESSION" section
2. Open Claude Code: claude (or claude --continue)
3. First message: "Read CLAUDE.md. Read docs/PRIVEX_DOCS_V2.md section [X].
                  Confirm you understand what we're building today."
4. Use the session prompt from this guide
5. End session: ask for handoff summary â†' paste into CLAUDE.md
```

### The No-Custom-Crypto Mantra

If Claude Code writes a function that does cryptographic operations from scratch:
```
Stop. Use [LIBRARY NAME] for this operation. 
It's listed in CLAUDE.md under "Cryptographic Libraries."
Do not implement this yourself.
```

### When Something Breaks in WASM

WASM is the most finicky part. Common fixes:
```
This WASM compilation is failing with: [error]
Try: 
  1. Pin the wasm-bindgen version in Cargo.toml to match wasm-pack's bundled version
  2. Add the getrandom crate with "js" feature explicitly
  3. Make sure wasm-opt is installed (part of binaryen): apt install binaryen
```

### Your Two Most Important Security Commands

Run these before every release:
```bash
# Check for known CVEs in all dependencies
cargo audit && pnpm audit

# Check no PII in server logs
grep -r "user_id\|ip_address\|email\|phone" server/src/ | grep "log::\|tracing::"
# This should return 0 results
```

---

## The One-Page Reference Card

Print this or keep it open while working:

```
START SESSION:
  cd ~/projects/privex && claude (or claude --continue)
  First message: "Read CLAUDE.md. Read docs/PRIVEX_DOCS_V2.md section [X]. Confirm goal."
  Also: "Check Part 1B in the build guide â€" confirm what is done vs pending."

DURING SESSION:
  Watch it work. Answer questions directly.
  Stop if it implements custom crypto: "Use [library] instead."
  Stop if it logs user data: "Remove that log line."
  Stop if a receipt is sent immediately: "Queue it. Send at next Poisson cover tick."
  Stop if a timestamp appears in a receipt payload: "Remove it. Receipts have NO timestamps."
  Stop if polling returns variable items: "Always return exactly N=10 items, pad with dummies."

END SESSION:
  "List files changed, decisions made, assumptions, 3-sentence summary, checkpoints."
  Copy output â†' update CLAUDE.md â†' update Part 1B status â†' git commit

AFTER SESSION:
  Run universal security greps (from Step 6).
  Run the functional test for whatever was built this session.
  Update Part 1B to reflect new state.

MODELS:
  Sonnet 4.6 â†' sessions 1-2, 7-15, 17-19
  Opus 4.8   â†' sessions 3-6 (WASM crypto), 16 (core messaging),
               16B (receipts), 16C (sync), 16D (time), 16E (session fix),
               16F (timing mitigations), Phase 2 ZK/CSAM/Nym work

IF SOMETHING BREAKS:
  Paste the exact error. Don't paraphrase.
  "Fix only this specific error. Don't refactor anything else."

KEY RULES NEVER TO VIOLATE:
  Receipts: queued, sent at Poisson tick, NO timestamps, MUTUAL opt-in
  History backup: UNLOGGED table, opt-in OFF by default, hard-delete on disable
  Message TTL: 30 days default, 60 days opt-in, per-message override allowed
  Poll endpoint: always return exactly N=10 items (real + dummy padding)
  Time sync: server signs ts with Ed25519, client verifies Â±90s, no external NTP

COMMIT AFTER EVERY SESSION. NO EXCEPTIONS.
git add -A && git commit -m "Session [N][letter]: what was built"
```


---

*Document: PRIVEX_BUILD_GUIDE.md*
*Version: 1.1*
*Companion to: docs/PRIVEX_DOCS_V2.md (Version 2.2)*
*License: CC BY 4.0*
