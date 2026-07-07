# Privex
### Version 2.2 | Gold Standard Privacy Architecture | Web-First

> **Privex** is a true zero-knowledge, end-to-end encrypted communication platform.
> The server is cryptographically blind - not policy-blind. Architecturally blind.
> Messages, files, calls, identities, and relationships are invisible to the platform operator,
> ISP, DNS provider, VPS host, relay operators, and every third party in between.
> Users retain full account recovery capability without ever compromising that guarantee.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Core Philosophy](#2-core-philosophy)
3. [Threat Model](#3-threat-model)
4. [Cryptographic Architecture](#4-cryptographic-architecture)
   - 4.1 Identity System (Hybrid PQC)
   - 4.2 Account Recovery ‚Ä" Zero-Knowledge, No Key Loss Ever
   - 4.3 Key Exchange ‚Ä" PQXDH (X3DH + Kyber)
   - 4.4 Double Ratchet Messaging
   - 4.5 Sealed Sender
   - 4.6 Group Messaging ‚Ä" MLS Protocol (RFC 9420)
   - 4.7 File & Media Encryption
   - 4.8 Audio & Video ‚Ä" WebRTC + SFrame
   - 4.9 Authentication ‚Ä" ZK Signed Challenge
   - 4.10 Delivery & Read Receipts
   - 4.11 Chat History ‚Ä" Cross-Device Sync
   - 4.12 Offline Message Delivery & Per-Message TTL
5. [Metadata Protection Architecture](#5-metadata-protection-architecture)
   - 5.1 Nym Mixnet ‚Ä" True Traffic Analysis Resistance
   - 5.2 Onion Routing ‚Ä" Real-Time Transport
   - 5.3 Cover Traffic
   - 5.4 Censorship Circumvention
   - 5.5 DNS & Network Protection
   - 5.6 Push Notifications Without APNs or FCM
   - 5.7 Timing Analysis Mitigations
6. [Account Recovery System](#6-account-recovery-system)
7. [CSAM Protection System](#7-csam-protection-system)
8. [Server Architecture](#8-server-architecture)
   - 8.1 Oblivious Server Model
   - 8.2 Key Directory + Transparency Log
   - 8.3 Database Schema
   - 8.4 True No-Log Infrastructure
   - 8.5 Proof-of-Work Registration
9. [Web Application Architecture](#9-web-application-architecture)
   - 9.1 Technology Foundation
   - 9.2 WebAssembly Crypto Layer
   - 9.3 Service Worker Architecture
   - 9.4 Progressive Web App (PWA)
   - 9.5 Web Security Hardening
   - 9.6 Time Synchronization & Desync Attack Prevention
10. [Mobile & Desktop Clients](#10-mobile--desktop-clients)
11. [API Specification](#11-api-specification)
12. [Network Architecture](#12-network-architecture)
13. [Tech Stack](#13-tech-stack)
14. [Security Model & Analysis](#14-security-model--analysis)
15. [Build Phases](#15-build-phases)
16. [Project Structure ‚Ä" Monorepo](#16-project-structure--monorepo)
17. [Glossary](#17-glossary)

---

## 1. Project Overview

### What Is Privex?

Privex is a multi-platform communication platform ‚Ä" web-first, then Android, iOS, and desktop ‚Ä" that provides:

- **Text messaging** ‚Ä" 1:1 and group, disappearing messages
- **File & attachment sharing** ‚Ä" any type, any size, chunked and encrypted
- **Real-time audio calling** ‚Ä" 1:1 and group
- **Real-time video calling** ‚Ä" 1:1 and group
- **Voice messages** ‚Ä" encrypted audio, delivered like files
- **Secure contact discovery** ‚Ä" find mutual contacts without exposing your contact list

Every feature operates under these absolute guarantees:

- **Zero-knowledge architecture** ‚Ä" server operator cannot read any content, identify any user, or trace any relationship
- **Sealed sender** ‚Ä" server cannot determine who sent any message
- **Metadata resistance** ‚Ä" communication patterns, frequency, and timing are cryptographically obfuscated at the network level, not just application level
- **Post-quantum cryptography** ‚Ä" secure against classical and future quantum adversaries, from day one
- **Account recovery** ‚Ä" users can recover their full account and all contacts from any new device using only their password, with no key loss ever
- **Censorship circumvention** ‚Ä" functional in China, Iran, Russia, and any country that blocks privacy tools
- **CSAM protection** ‚Ä" client-side, zero-knowledge, without breaking E2EE

### Platform Roadmap

| Phase | Platform | Timeline |
|---|---|---|
| 1 | Web App (Progressive Web App, browser-first) | Months 1‚Ä"4 |
| 2 | Android | Months 5‚Ä"7 |
| 3 | iOS | Months 7‚Ä"9 |
| 4 | Desktop (macOS, Windows, Linux via Tauri) | Months 9‚Ä"11 |
| 5 | Hardening, audit, public launch | Months 12‚Ä"15 |

### Who Is Privex For?

| User | Primary Need |
|---|---|
| Journalists & whistleblowers | Source protection, legally subpoena-proof |
| Human rights activists | Safe communication in authoritarian states |
| Lawyers & medical professionals | Client/patient privilege, regulatory compliance |
| People in censored countries | Undetectable communication when everything else is blocked |
| Privacy-conscious individuals | No surveillance, no data harvesting, no corporate overreach |
| Security researchers | Verifiable, auditable ZK architecture |
| Corporations with trade secrets | Industrial espionage protection |

### What Privex Is Not

- Not a social network. No public profiles, feeds, follower counts, or discovery algorithms.
- Not a VPN. Network-level anonymity is a property, not the product.
- Not a surveillance tool. No admin panel. No moderation dashboard. No ability to read anything.

---

## 2. Core Philosophy

### The Four Laws of Privex

```
Law 1: The server CANNOT read content.
       Not "does not." CANNOT. Cryptographically, architecturally.

Law 2: The server CANNOT identify users.
       Not "does not store names." CANNOT correlate identity to activity.
       Ever. Under any circumstance, including legal compulsion.

Law 3: The server CANNOT trace relationships.
       Not "does not log who you talk to." CANNOT determine
       who communicates with whom, when, or how often.

Law 4: The network CANNOT confirm Privex is being used.
       ISP, DNS provider, VPS host ‚Ä" none of them can
       distinguish Privex traffic from any other encrypted traffic.
```

Law 4 is what separates Privex from everything else. Most secure messengers satisfy Laws 1‚Ä"3. Law 4 ‚Ä" the "can't even tell the platform was used" requirement ‚Ä" requires a fundamentally different transport architecture.

### The Critical Distinction: Signal vs. Privex

| Property | Signal | Wire | Session | **Privex** |
|---|---|---|---|---|
| Content E2EE | ‚ú... | ‚ú... | ‚ú... | ‚ú... |
| Sealed sender | ‚ú... | ‚ùå | ‚ùå | ‚ú... |
| No phone number | ‚ùå | ‚ùå | ‚ú... | ‚ú... |
| Post-quantum (full) | Partial | ‚ùå | ‚ùå | ‚ú... (full hybrid PQC) |
| IP hidden from server | ‚ùå | ‚ùå | Partial | ‚ú... (Nym mixnet) |
| ISP can't detect usage | ‚ùå | ‚ùå | ‚ùå | ‚ú... (pluggable transports) |
| Account recovery | Device backup only | ‚ùå | ‚ùå | ‚ú... (OPAQUE, multi-device, social) |
| Metadata resistance | Partial | ‚ùå | Partial | ‚ú... (mixnet + cover traffic) |
| Works in China/Iran | Sometimes | ‚ùå | ‚ùå | ‚ú... (built-in circumvention) |
| Key directory transparency | ‚ùå | ‚ùå | ‚ùå | ‚ú... (CT log) |

---

## 3. Threat Model

This section defines exactly which adversaries Privex is designed to defeat, and which are out of scope.

### Adversaries Modeled

**Threat Level 1 ‚Ä" Passive Network Observer (ISP, DNS provider, coffee shop Wi-Fi)**
- Capability: Sees all packets leaving your device. Can read DNS queries. Knows which IPs you connect to.
- What they want: Identify that you're using Privex; read your traffic; correlate your activity.
- Privex defense:
  - DNS-over-HTTPS, hardcoded resolver ‚Ä" no DNS queries reveal Privex usage
  - All traffic routed through Nym mixnet ‚Ä" observer sees: "user connected to Nym network." Nothing else.
  - Nym traffic is indistinguishable from any other Nym usage (not from Privex specifically)
  - Cover traffic normalizes volume patterns
- **Result: ISP cannot confirm Privex is being used.**

**Threat Level 2 ‚Ä" Active Network Attacker (Man-in-the-Middle)**
- Capability: Intercept, modify, replay traffic. Inject content.
- Privex defense: TLS 1.3 + Nym mixnet layers, DTLS-SRTP + SFrame for calls, certificate pinning, HKDF-derived message keys with authentication tags (HMAC)
- **Result: MITM cannot inject or modify any content without detection.**

**Threat Level 3 ‚Ä" Compromised Privex Server (hacked, insider threat, or coerced operator)**
- Capability: Full read/write access to Privex database, logs, running code
- Privex defense:
  - Server stores only encrypted blobs and pseudonymous IDs
  - Sealed sender: server cannot identify message senders
  - No IP addresses ever stored (all traffic arrives via Nym gateways / relay nodes)
  - No social graph (server sees recipient pseudonym ID only)
  - Even with full database dump and server binary: zero usable information
- **Result: Server breach yields nothing useful about any user.**

**Threat Level 4 ‚Ä" Nation-State with Legal Authority**
- Capability: Subpoenas, gag orders, border seizure, physical server access, national security letters
- Privex defense:
  - Incorporated in Iceland (strong privacy laws, outside Five Eyes, requires Icelandic court order for any data)
  - Architecture: even with a valid court order and full cooperation, Privex legally and technically has nothing to provide
  - Warrant canary signals coercion before legal gag takes effect
  - Key material lives exclusively on user devices ‚Ä" court orders cannot reach it
- **Result: Legal compulsion cannot produce user data because no user data exists on the server.**

**Threat Level 5 ‚Ä" VPS Host (Hetzner, UpCloud, or any bare-metal provider)**
- Capability: Physical access to servers, memory dumps, filesystem access, packet capture on the NIC
- Privex defense:
  - Server never receives connections from users directly (all traffic from Nym gateways and onion relay exit nodes)
  - VPS host network monitoring sees connections from relay IPs ‚Ä" not user IPs
  - Database contains only pseudonymous IDs and encrypted blobs
  - Encrypted storage at rest (dm-crypt/LUKS on all volumes)
  - Even a full RAM dump reveals: encrypted WebSocket buffers, pseudonymous IDs, session tokens (not user identity)
- **Result: VPS host cannot identify any user, their IP, or the content of any communication.**

**Threat Level 6 ‚Ä" Future Quantum Computer**
- Capability: Break RSA, ECDH, ECDSA with Shor's algorithm; weaken symmetric ciphers via Grover's algorithm
- Privex defense:
  - All key exchanges: X25519 (classical) + CRYSTALS-Kyber-1024 (post-quantum) hybrid
  - All signatures: Ed25519 (classical) + CRYSTALS-Dilithium3 (post-quantum) hybrid
  - Symmetric: AES-256-GCM (Grover halves security to 128-bit ‚Ä" still adequate)
  - "Harvest now, decrypt later" attacks fail: PQC on every session from day one
- **Result: Even a future quantum computer cannot retroactively decrypt captured Privex traffic.**

**Threat Level 7 ‚Ä" Compromised Endpoint Device (malware with root access)**
- Capability: Read app memory, keystrokes, screen captures, access key storage
- Privex defense:
  - Web: WebCrypto non-extractable keys, memory cleared after each operation (WASM zero-fill)
  - Mobile/Desktop: Hardware-backed key storage (Secure Enclave / Android Keystore / OS Keychain)
  - Private keys non-exportable even with hardware access, on supported devices
  - Screen blur when app leaves focus (prevents shoulder surfing via app switcher)
  - Note: **Full root compromise with kernel-level malware is out of scope for any software security system.**
- **Result: Best-effort protection against endpoint compromise. Not a claim of full defense.**

### Explicit Non-Goals

- Privex does not protect against users who voluntarily share their messages with others.
- Privex does not protect against physical coercion of the user themselves.
- Privex does not protect against a malicious recipient (they have the decrypted messages).
- Privex does not make illegal activity legally safe ‚Ä" the architecture provides technical privacy, not legal immunity in the user's physical jurisdiction.

---

## 4. Cryptographic Architecture

### 4.1 Identity System ‚Ä" Hybrid Post-Quantum

Every Privex identity is a collection of cryptographic keypairs generated entirely on-device. No server involvement, no phone number, no email.

#### Identity Keypairs

```
Classical Identity Keypair:
  Algorithm:     Ed25519
  Library:       libsodium (crypto_sign_keypair)
  Usage:         Digital signatures for all identity assertions
  Private key:   On-device only, encrypted at rest

Post-Quantum Identity Keypair:
  Algorithm:     CRYSTALS-Dilithium3 (NIST FIPS 204)
  Library:       liboqs (OQS_SIG_dilithium_3_*)
  Usage:         Quantum-resistant signatures, layered with Ed25519
  Private key:   On-device only, encrypted at rest

Combined Signature (all identity assertions use both):
  sig = Ed25519_sign(data, ed_priv) || Dilithium3_sign(data, dil_priv)
  verify: BOTH signatures must be valid.
  Transition mode (Phase 1-2): EITHER valid accepted, for interop.
  Strict PQ mode (Phase 3+): BOTH required.
```

#### Pseudonymous User ID

```
Input:    Ed25519 public key (32 bytes)
Process:  SHA-256(ed25519_public_key) ‚Ü' take first 16 bytes
Format:   px_[32 hex chars]
Example:  px_4a3f8c2b1d7e9f0a6b5c3d2e1f4a8b9c

Server knowledge: This 32-char ID + public keys. Nothing else. Ever.
Real identity: Not known to, stored by, or inferrable by the server.
```

#### Key Bundle Published to Key Directory

```
Per user, server stores:
{
  user_id:          "px_[32hex]",
  ed25519_ik:       bytes,   // Classical identity key
  dilithium3_ik:    bytes,   // PQ identity key
  x25519_spk:       bytes,   // Signed prekey (X25519, rotated every 30 ¬± 5 days)
  spk_sig_ed:       bytes,   // SPK signed by Ed25519 IK
  spk_sig_dil:      bytes,   // SPK signed by Dilithium3 IK
  kyber1024_pk:     bytes,   // Post-quantum KEM public key
  x25519_opks:      [bytes], // One-time prekeys (100 initially, replenished as used)
  created_at:       int,
  spk_created_at:   int
}

NOT stored: Name, phone, email, IP address, last_seen, device info, location.
```

---

### 4.2 Account Recovery ‚Ä" Zero-Knowledge, No Key Loss Ever

**The core problem:** True E2EE requires that only the user holds decryption keys. If the user loses their device and has no backup, all key material is gone. Most secure messengers (Signal, Briar) accept this tradeoff ‚Ä" lose your device, lose your account.

**Privex's solution:** Four independent, layered recovery paths, each zero-knowledge from the server's perspective during normal operation. Server-assisted OPAQUE recovery is optional: users who want the smallest server-side footprint can leave it off, in which case no OPAQUE recovery row exists to steal or attack.

Full technical specification is in **Section 6**. The four paths in priority order:

```
Recovery Path 1: OPAQUE Password Recovery (OPT-IN)
  ‚Ä" Recover from any new device using only your password, if enabled
  ‚Ä" Server holds an encrypted "envelope" but NEVER learns the password or key material
  ‚Ä" OFF means the OPAQUE row is hard-deleted, not merely hidden behind a flag
  ‚Ä" Based on OPAQUE protocol (RFC draft) ‚Ä" provably ZK against the live server

Recovery Path 2: Multi-Device Linking (EASIEST)
  ‚Ä" Register a second device from your first device
  ‚Ä" Keys sync device-to-device over an encrypted channel, server routes only encrypted blobs
  ‚Ä" If one device is lost, the other retains full access

Recovery Path 3: Emergency Recovery Contacts (SOCIAL)
  ‚Ä" Designate 2‚Ä"3 trusted contacts. Split master key via Shamir's Secret Sharing (2-of-3 threshold)
  ‚Ä" Each share encrypted with contact's public key. Server stores only encrypted blobs.
  ‚Ä" Reconstruct with 2 of 3 contacts approving in their Privex app

Recovery Path 4: Seed Phrase (POWER USER FALLBACK)
  ‚Ä" 24-word BIP-39 mnemonic, shown once at registration
  ‚Ä" Regenerates entire keypair deterministically
  ‚Ä" Optional. User chooses to write it down. Nothing is forced.
```

---

### 4.3 Key Exchange ‚Ä" PQXDH (Post-Quantum Extended Triple Diffie-Hellman)

Privex uses Signal's PQXDH specification ‚Ä" the same protocol that Signal deployed in 2023 ‚Ä" which combines X3DH with CRYSTALS-Kyber for quantum resistance.

#### X3DH Component

```
Keys (per user):
  IK  ‚Ä" Identity Key:    Long-term Ed25519 keypair
  SPK ‚Ä" Signed Prekey:   Medium-term X25519 keypair, signed by IK, rotated ~30 days
  OPK ‚Ä" One-Time Prekey: Single-use X25519, 100 generated at registration
  EK  ‚Ä" Ephemeral Key:   Per-session X25519, generated by initiator

Alice initiates with Bob:
  Fetches Bob's bundle: { IK_B, SPK_B, SPK_sig_B, OPK_B, Kyber_B }
  Generates ephemeral: EK_A

  DH1 = X25519(IK_A_priv, SPK_B_pub)   // Alice identity + Bob signed prekey
  DH2 = X25519(EK_A_priv, IK_B_pub)    // Alice ephemeral + Bob identity
  DH3 = X25519(EK_A_priv, SPK_B_pub)   // Alice ephemeral + Bob signed prekey
  DH4 = X25519(EK_A_priv, OPK_B_pub)   // Alice ephemeral + Bob one-time prekey

  X3DH_secret = HKDF-SHA256(DH1 || DH2 || DH3 || DH4, info="PQXDH_v1")
```

#### Kyber Component (NIST FIPS 203)

```
  (Kyber_ciphertext, Kyber_secret) = Kyber1024_Encapsulate(Kyber_B_pub)
  // Alice sends Kyber_ciphertext to Bob inside the initial message header
  // Bob runs: Kyber_secret = Kyber1024_Decapsulate(Kyber_ciphertext, Kyber_B_priv)

Final shared secret (PQXDH):
  SharedSecret = HKDF-SHA256(X3DH_secret || Kyber_secret, info="PQXDH_v1_final")
                            ‚-≤ Classical security  ‚-≤ Quantum security
                            
  Security guarantee: Breaking the session requires breaking BOTH X3DH (classical DH)
                      AND Kyber (post-quantum). Compromising one leaves the other intact.
                      A quantum computer breaks X3DH but not Kyber.
                      A classical attacker breaks neither.
```

**Library:** `@signalapp/libsignal-client` (WASM build for web, native for mobile/desktop). Signal's implementation includes PQXDH. Do not reimplement.

---

### 4.4 Double Ratchet Messaging

Every individual message gets a unique key. Past keys are immediately deleted. Future keys cannot be derived from past keys ‚Ä" forward secrecy and break-in recovery in both directions.

```
Double Ratchet State (per conversation):
  RK  ‚Ä" Root Key:              32 bytes, derived from PQXDH
  CKs ‚Ä" Sending Chain Key:     Changes on every send
  CKr ‚Ä" Receiving Chain Key:   Changes on every receive
  DHs ‚Ä" Sending DH keypair:    X25519, rotated on each DH ratchet step
  DHr ‚Ä" Received DH public:    Peer's latest ratchet key

On each message sent:
  MK    = HKDF(CKs, constant="msg_key")     // Unique message key
  CKs   = HKDF(CKs, constant="chain_adv")  // Advance chain
  ctext = AES-256-GCM(MK, plaintext || padding)
  MK deleted immediately after use.

DH ratchet (every time a new DH public key is received in a message header):
  (RK, CKs) = HKDF(RK, X25519(DHs_priv, new_DHr_pub))
  DHs regenerated. Old DHs deleted.
  This step provides break-in recovery: even if current keys are compromised,
  future messages are protected by new DH material.

Message format (payload of Sealed Sender wrapper):
{
  version:      2,
  ratchet_key:  [X25519 public bytes],     // Current DH ratchet public key
  counter:      42,                         // Message index in current chain
  prev_counter: 38,                         // For out-of-order delivery
  ciphertext:   [AES-256-GCM output],
  mac:          [HMAC-SHA256 over full header + ciphertext],
  padding:      [random bytes to nearest 1024-byte boundary]
}
```

**Padding:** All messages padded to nearest 1024-byte multiple before encryption. This prevents message length from leaking conversation context (short burst = chat, long = document transfer, etc).

**Library:** `@signalapp/libsignal-client` ‚Ä" the canonical, audited implementation. Signal's library covers PQXDH + Double Ratchet as a single unit.

---

### 4.5 Sealed Sender

Standard messaging leaks the social graph to the server: `FROM: Alice, TO: Bob`. Sealed Sender moves the sender identity inside the encrypted payload. The server knows only the recipient.

```
Step 1 ‚Ä" Alice creates a sender certificate:
  SenderCert = {
    sender_id:     "px_[alice_id]",
    sender_ed_pub: IK_A_ed25519_public,
    sender_dil_pub: IK_A_dilithium3_public,
    valid_until:   now + 24h
  }
  cert_sig = Ed25519_sign(SenderCert, IK_A_ed_priv)
            || Dilithium3_sign(SenderCert, IK_A_dil_priv)

Step 2 ‚Ä" Encrypt sender certificate to Bob:
  ephemeral_key = X25519_generate()
  shared = X25519(ephemeral_key.priv, IK_B_ed_pub)  // DH with Bob's identity key
  EncCert = XChaCha20-Poly1305(HKDF(shared, "sealed_sender"), SenderCert || cert_sig)

Step 3 ‚Ä" Build the full message to server:
  {
    "recipient":  "px_[bob_id]",           // Server needs this for routing
    "type":       "sealed",
    "ephemeral":  ephemeral_key.pub,       // Bob needs this to decrypt sender cert
    "content":    EncCert || DoubleRatchet_Message,
    "csam_proof": "[ZK proof, only if contains image]"
  }

Step 4 ‚Ä" Server routes to Bob's mailbox:
  Server knows: recipient px_[bob_id], timestamp, ciphertext size.
  Server does NOT know: sender, message type, content.

Step 5 ‚Ä" Bob decrypts:
  shared = X25519(IK_B_ed_priv, ephemeral_pub)
  SenderCert = XChaCha20-Poly1305_decrypt(HKDF(shared, "sealed_sender"), EncCert)
  Verify both cert_sig_ed and cert_sig_dil against sender's public keys.
  If valid: proceed. If invalid: REJECT. (Anti-spoofing.)
```

**Anti-spoofing guarantee:** A third party cannot forge a sealed sender message from Alice because they cannot produce valid signatures from both Alice's Ed25519 and Dilithium3 identity keys.

---

### 4.6 Group Messaging ‚Ä" MLS Protocol (RFC 9420)

Pairwise Double Ratchet sessions don't scale to groups. Adding/removing members individually would require O(N) re-keying operations. MLS solves this with O(log N) complexity.

#### MLS Key Concepts

```
Ratchet Tree:
  Binary tree where each leaf = one group member.
  Each internal node's key = combined key of its two subtrees (TreeKEM).
  Group shared secret = derived from root key.
  No member can derive other members' leaf private keys.

Epoch:
  Each Add/Remove/Update operation creates a new epoch.
  New epoch = new group secret. Previous epoch keys are deleted.
  Forward secrecy: removed members cannot derive keys for future epochs.

Group operations are O(log N):
  Adding a member: update O(log N) internal tree nodes, not O(N) members.
  N = 1000 members ‚Ü' ~10 operations. Practical at scale.
```

#### Group Operations

```
CREATE GROUP (Alice):
  GroupID = CSPRNG(32 bytes)
  Alice creates her KeyPackage (MLS credential + public keys)
  Initializes ratchet tree with herself as leaf 0
  Epoch 0, GroupSecret_0

ADD MEMBER (Alice adds Bob):
  Alice fetches Bob's KeyPackage from key directory
  Sends: Add proposal (Bob's KeyPackage) + Commit
  Commit derives: GroupSecret_1 from HKDF(GroupSecret_0, commit_secret)
  Bob receives Welcome message (encrypted group state, decryptable with his KEM key)
  All existing members advance to Epoch 1 with GroupSecret_1
  Epoch 0 key deleted.

REMOVE MEMBER (Any member removes Dave):
  Propose Remove + Commit
  GroupSecret_n+1 derived, excluding Dave's contribution
  Dave's app retains Epoch n keys (can read old messages he received)
  Dave CANNOT derive GroupSecret_n+1 or any future key

SEND MESSAGE:
  ApplicationSecret = HKDF(GroupSecret_current, "application")
  ciphertext = AES-128-GCM(ApplicationSecret, plaintext || sender_id || counter)
  Sender identity authenticated by MLS tree (not via Sealed Sender for groups ‚Ä"
  MLS provides sender authentication through the tree credential)
```

#### Group Limits

- **Up to 500 members:** Full MLS, as specified.
- **500‚Ä"5000 members ("channels"):** Sender Keys model. One member generates a `SenderKey` and distributes it encrypted to each member. Messages encrypt with the SenderKey. Add/remove triggers SenderKey rotation. Less perfect forward secrecy than MLS, but practical at scale.
- **Beyond 5000:** Not supported in V1. Future architecture consideration.

**Library:** `openmls` (Rust, RFC 9420 compliant) for server-side state management. WASM build for web client via `wasm-pack`. `mls-rs` as an alternative for React Native.

---

### 4.7 File & Media Encryption

Files are encrypted client-side before a single byte leaves the device. The server is a dumb blob store that holds random-looking chunks.

```
SEND FLOW:

1. Generate random 32-byte Content Encryption Key (CEK):
   CEK = libsodium.randombytes_buf(32)

2. Split file into 4 MB chunks. Encrypt each:
   For each chunk_i:
     chunk_key_i = HKDF(CEK, info="chunk" || uint32(i))
     nonce_i     = CSPRNG(12 bytes)
     enc_chunk_i = AES-256-GCM(chunk_key_i, chunk_data_i, nonce_i)
     chunk_id_i  = SHA-256(enc_chunk_i)  // Content-addressed, random-looking

3. Upload each enc_chunk_i to blob store at chunk_id_i:
   Blob store receives: random hex ID ‚Ü' random-looking encrypted bytes
   Blob store does NOT know: file type, filename, size, owner, sender, recipient

4. Build File Manifest (NOT uploaded ‚Ä" sent inside an encrypted message):
   {
     filename_encrypted: XChaCha20(sender_key, original_filename),
     mime_type_encrypted: XChaCha20(sender_key, mime_type),
     total_size: N bytes,
     sha256_plaintext: SHA-256(original_file),  // Integrity check
     chunks: [chunk_id_0, chunk_id_1, ...],
     cek: CEK
   }

5. Wrap CEK for recipient:
   (eph_pub, eph_priv) = X25519_generate()
   wrap_key = HKDF(X25519(eph_priv, IK_B_pub), "file_cek_wrap")
   WrappedCEK = XChaCha20-Poly1305(wrap_key, CEK)

6. Send via Sealed Sender message:
   {
     type: "file",
     manifest: { ...above, cek: WrappedCEK, eph_pub: eph_pub },
     thumbnail_encrypted: [optional, AES-256-GCM encrypted thumbnail for preview]
   }

RECEIVE FLOW:
1. Receive Sealed Sender message containing manifest
2. Unwrap CEK: wrap_key = HKDF(X25519(IK_B_priv, eph_pub), "file_cek_wrap") ‚Ü' CEK
3. Download chunks by chunk_id from blob store
4. Decrypt each chunk, reassemble
5. Verify SHA-256(reassembled) == sha256_plaintext from manifest
6. If mismatch: reject (tampering detection)

CHUNK LIFECYCLE:
  - Server deletes chunk after recipient downloads it (confirmed via delivery ack)
  - OR after 7 days, whichever comes first
  - No re-download after deletion (for file permanence, recipient must save locally)
```

---

### 4.8 Audio & Video ‚Ä" WebRTC + SFrame

#### Call Signaling (Zero-Metadata)

Standard WebRTC signaling leaks call metadata (who calls whom, when, duration). Privex eliminates this by using the **existing Sealed Sender message channel** for all signaling. A call invite is just an encrypted message.

```
CALL INITIATION (Alice calls Bob):

1. Alice sends Bob a Sealed Sender message:
   {
     type:         "call_invite",
     call_id:      CSPRNG(32 bytes),
     call_type:    "audio" | "video",
     sdp_offer:    [WebRTC SDP, encrypted with Bob's IK],
     ice_candidates: [..., encrypted],
     timestamp:    unix_time
   }

2. Bob's app shows call UI.

3. Bob sends Sealed Sender reply:
   { type: "call_accept", call_id: ..., sdp_answer: [encrypted], ice: [...] }

4. ICE negotiation via Sealed Sender messages (< 500ms round trip at low latency)

5. WebRTC P2P connection OR TURN relay established.

Server sees: sealed blobs of type unknown. No call record. No duration.
             No participants. No signal that a call occurred.
```

#### Media Encryption ‚Ä" DTLS-SRTP + SFrame

```
Layer 1 ‚Ä" DTLS-SRTP (WebRTC default):
  Transport-layer encryption. Mandatory for WebRTC.
  Protects media from eavesdropping on the wire between client and TURN relay.
  Key negotiated via DTLS handshake during ICE.

Layer 2 ‚Ä" SFrame (RFC 9605):
  Application-layer, end-to-end frame encryption.
  Applied BEFORE sending to WebRTC stack.
  Even if TURN relay, CDN, or network is compromised: media is still encrypted
  with keys only the call participants hold.

SFrame key derivation:
  base_key = HKDF(PQXDH_SharedSecret, "sframe_v1_base")
  Per-sender key:
    sender_key = HKDF(base_key, "sframe_sender_" || sender_px_id)
  Per frame:
    nonce = frame_counter (8 bytes, monotonic)
    frame_ciphertext = AES-128-GCM(sender_key, frame_plaintext, nonce)

For group calls:
  Each sender has their own sender_key derived from the MLS ApplicationSecret.
  MLS provides group key management. SFrame provides per-frame encryption.
  Even the SFU relay (if used) receives only SFrame-encrypted frames.
```

#### NAT Traversal

```
STUN: ICE-standard STUN server on Privex infrastructure.
      Reveals client public IP to STUN server. Mitigated by TURN-only mode option.

TURN relay: Privex-operated. 4 regions (NA, EU, Asia, Oceania).
  Authentication: Time-limited HMAC tokens. NOT linked to user identity.
    username = unix_ts || ":" || CSPRNG(8 bytes)
    password = HMAC-SHA256(turn_secret, username)
    Valid: 60 seconds.
  TURN server sees: DTLS-SRTP encrypted streams (payload) encrypted again by SFrame.
  TURN does NOT see: caller identity, callee identity, conversation content.
  TURN logging: disabled (log-file=/dev/null in coturn config).

Privacy modes (user-selectable):
  TURN-only (default): All call media routes through TURN. Local IP never exposed.
  Direct P2P (optional): Faster, lower latency. Reveals local IP to peer only.
```

**Call Stack:** `mediasoup` (Node.js) for SFU in group calls. `pion/webrtc` (Go) for TURN. `pion/turn` for TURN server.

---

### 4.9 Authentication ‚Ä" ZK Signed Challenge

Authentication proves the user knows their private key without revealing the private key. This is a Zero-Knowledge Proof by mathematical construction ‚Ä" Schnorr identification protocol is inherently ZK.

There is no need for ZK-SNARK circuits for authentication. SNARKs are reserved for the CSAM check (Section 7), where the non-interactive, server-verifiable proof is necessary for a fundamentally different reason.

```
AUTHENTICATION FLOW:

Step 1 ‚Ä" Request challenge:
  Client ‚Ü' Server: { user_id: "px_[hex]" }
  Server ‚Ü' Client: { challenge: CSPRNG(32 bytes), expires: now + 90s }
  Server stores: (user_id, challenge, expires) in Redis. TTL 90s.

Step 2 ‚Ä" Sign challenge with BOTH identity keys (hybrid proof):
  sig_ed  = Ed25519_sign(challenge || user_id || timestamp, IK_ed_priv)
  sig_dil = Dilithium3_sign(challenge || user_id || timestamp, IK_dil_priv)

Step 3 ‚Ä" Submit proof:
  Client ‚Ü' Server: { user_id, challenge, sig_ed, sig_dil, timestamp }
  Server:
    1. Verify challenge exists in Redis, not expired
    2. Fetch user's IK_ed_pub and IK_dil_pub from key directory
    3. Verify Ed25519_verify(challenge || user_id || timestamp, sig_ed, IK_ed_pub) == true
    4. Verify Dilithium3_verify(challenge || user_id || timestamp, sig_dil, IK_dil_pub) == true
    5. Delete challenge from Redis (single-use, prevents replay)
    6. Issue session token

Step 4 ‚Ä" Session token:
  token_payload = { user_id, issued_at, expires_at: now + 24h, jti: CSPRNG(16 bytes) }
  token = HMAC-SHA256(server_session_key, canonical_json(token_payload))
  Response: { session_token: base64url(token_payload || token), expires_at }

Step 5 ‚Ä" All subsequent requests:
  Header: X-Privex-Auth: [session_token]
  Server: verify HMAC, check expiry, check jti not in revocation set
```

**Why 24-hour tokens:** 15-minute tokens create observable re-authentication bursts every 15 minutes ‚Ä" a timing signature detectable even through onion routing. 24-hour tokens with silent background renewal are indistinguishable from normal WebSocket heartbeats.

**Why NOT snarkjs for auth:** Ed25519 inside a circom/Groth16 circuit requires ~150,000+ R1CS constraints. On mobile hardware this takes 5‚Ä"30 seconds. The signed challenge above is provably equivalent zero-knowledge by Schnorr's theorem, and takes <5ms.

---

### 4.10 Delivery & Read Receipts

Receipts in Privex are not a server-side feature. They are encrypted messages that travel through the exact same path as regular messages ‚Ä" Sealed Sender, Double Ratchet, through Nym. The server cannot distinguish a receipt from any other message. To any observer, receipts are invisible in the traffic stream.

#### Design Principles

```
MUTUAL PARTICIPATION:
  Neither party can receive delivery/read confirmations without also sending them.
  If Alice disables receipts, she neither sends nor receives them.
  Asymmetric receipt state (one party seeing status, the other not) is not permitted.

NO TIMESTAMPS IN RECEIPTS:
  Receipts contain NO timestamp of when the message was delivered or read.
  Timestamps would allow an adversary to infer Bob's online/offline schedule.
  Sender sees: "delivered" or "read" ‚Ä" not when.

JITTERED SENDING:
  Receipts are NOT sent the instant a message arrives or is read.
  They are queued and sent at the next Poisson cover traffic interval.
  This decouples receipt timing from message receipt timing.
  An adversary watching traffic cannot determine when Bob came online
  from the moment Alice receives the "delivered" confirmation.
```

#### Technical Implementation

```
ALICE SENDS MESSAGE TO BOB:
  Message includes receipt_request in encrypted payload:
  {
    type: "text",
    content: "...",
    receipt_request: {
      token_id: CSPRNG(32 bytes),       // Random ID Alice generates
      return_address: "px_[alice_id]",  // Where to send receipt
      request_delivery: true,
      request_read: true
    }
  }
  token_id is inside the encrypted Double Ratchet payload.
  Server never sees it. Only Bob sees it after decryption.

BOB'S CLIENT RECEIVES MESSAGE:
  ‚Ü' Immediately queues a "delivered" receipt (does NOT send yet)
  ‚Ü' Stores: { token_id, type: "delivered" } in outbox
  ‚Ü' At next Poisson interval: sends receipt via Sealed Sender to px_[alice_id]

BOB OPENS AND VIEWS THE MESSAGE (viewport visible for >1 second):
  ‚Ü' Queues a "read" receipt (does NOT send yet)
  ‚Ü' At next Poisson interval: sends receipt via Sealed Sender to px_[alice_id]

RECEIPT MESSAGE FORMAT (Sealed Sender, encrypted):
  {
    type: "receipt",
    token_id: "[32 bytes ‚Ä" matches Alice's original token]",
    receipt_type: "delivered" | "read"
    // NO timestamp. NO message content reference. NO sender info beyond Sealed Sender.
  }

ALICE'S CLIENT RECEIVES RECEIPT:
  ‚Ü' Sealed Sender decrypts: confirms sender is Bob (anti-spoofing)
  ‚Ü' Matches token_id to Alice's local outgoing message log
  ‚Ü' Updates UI: message shows "delivered" or "read" checkmarks
  ‚Ü' Server saw: encrypted blob to px_[alice]. Nothing else.
```

#### Security Analysis

```
ATTACK: Server correlates receipt traffic
  Server sees: encrypted blob addressed to px_[alice]
  Server learns: someone sent Alice something
  Server does NOT learn: it's a receipt, which message, when Bob came online
  VERDICT: No meaningful leak. Identical to any incoming message.

ATTACK: Timing correlation between message and receipt
  Mitigation: Jittered sending (Section 5.7) decouples receipt timing.
  Residual risk: Nym cover traffic + jitter narrows the window but doesn't
  eliminate it entirely. Acknowledged as known limitation.

ATTACK: Receipt confirms Bob has his device and is alive
  Risk: For high-threat users, even "delivered" proves the device is active.
  Mitigation: "Receipt Privacy Delay" setting (see below) or disable entirely.

ATTACK: Fake receipt (impersonation)
  token_id = 32 bytes CSPRNG. Probability of guessing: 1/2^256.
  Receipt travels via Sealed Sender ‚Ä" requires valid Privex identity to send.
  Anti-spoofing: Bob's identity key signatures verified before accepting receipt.
  VERDICT: Cryptographically infeasible.
```

#### Settings

```
Settings ‚Ü' Privacy ‚Ü' Message Status

[DELIVERY RECEIPTS]  default: ON
  Your device sends delivery confirmations to senders.
  Senders' devices send delivery confirmations to you.
  Mutual: cannot receive without sending. Both or neither.

[READ RECEIPTS]  default: ON
  Sends confirmation when you view a message in the viewport.
  Triggered by: IntersectionObserver (web), viewport tracking (mobile).
  "Delivered" ‚â  "Read". Two separate signals.
  Mutual: same rule applies.

[RECEIPT PRIVACY DELAY]  default: OFF
  Adds additional random delay (Poisson average 5 minutes, max 20 min)
  on top of the standard cover traffic jitter before sending any receipt.
  Recommended for high-threat situations.
  Trade-off: sender sees delayed status updates.
  Enabling this setting is recommended for journalists and activists.
```

---

### 4.11 Chat History ‚Ä" Cross-Device Sync

Privex supports two modes for chat history when a user has multiple devices.

#### Mode A ‚Ä" Device-to-Device Transfer (DEFAULT)

```
PURPOSE: Transfer full chat history from an existing device to a new one.
REQUIRES: Both devices online simultaneously.
SERVER ROLE: Routes encrypted transfer blobs. Cannot read any content.
SECURITY: Server gains zero new information. Architecture unchanged.

FLOW:
  1. On existing Device A: Settings ‚Ü' Transfer History ‚Ü' New Device
  2. App shows QR code (contains: rendezvous_id + ephemeral transfer key)
  3. On Device B: scan QR
  4. Devices establish ephemeral encrypted channel via server (server sees blobs only):
       shared = X25519(deviceA_eph_priv, deviceB_eph_pub)
       transfer_key = HKDF(shared || rendezvous_id, "history_transfer_v1")
  5. Device A streams: AES-256-GCM(transfer_key, history_chunk)
  6. Device B decrypts and imports history
  7. Server deletes rendezvous state on completion

WHAT TRANSFERS:
  - Full message history (plaintext on Device A ‚Ü' encrypted in transit ‚Ü' plaintext on B)
  - Ratchet session states (so Device B can continue existing conversations)
  - Contacts and their keys
  - Group states

WHAT DOES NOT TRANSFER:
  - OPAQUE master key (already on Device B via recovery)
  - Session token (Device B has its own)
```

#### Mode B ‚Ä" Server-Side Encrypted History Backup (OPT-IN)

```
PURPOSE: Restore history on any new device without needing old device online.
SERVER ROLE: Stores encrypted history blobs. CANNOT decrypt them. CANNOT read them.
SECURITY TRADE-OFF: Encrypted message history persists on server until user deletes it.
                    Even though server cannot read it, history blobs now EXIST server-side.
                    Users must understand: if their password AND their device are both
                    compromised, this backup is exposed. History backup breaks
                    forward secrecy (server-side ‚Ä" Double Ratchet still protects in transit).

ARCHITECTURE:
  history_key = HKDF(master_seed, "privex_history_backup_v1")
  // Derived from OPAQUE master seed ‚Ü' automatically available on any device after recovery

  On each sent/received message (when backup is enabled):
    blob = AES-256-GCM(history_key, plaintext || msg_id || conversation_id)
    // nonce = CSPRNG(12 bytes), included in blob
    POST /history/backup { blob: base64(blob) }
    Server stores: { user_id, blob_id, encrypted_blob, stored_at }
    Server does NOT know: message content, sender, recipient, conversation

  On new device (after OPAQUE recovery):
    Derive history_key from recovered master_seed
    GET /history/fetch ‚Ü' stream of encrypted blobs
    Decrypt each: AES-256-GCM_decrypt(history_key, blob)
    Import messages to IndexedDB

DEFAULT: OFF. User must explicitly enable in Settings ‚Ü' Privacy ‚Ü' History Backup.

CLEAR WARNING IN UI:
  "Your encrypted message history will be stored on Privex servers.
   We cannot read it. But it exists there until you delete it.
   
   If someone obtains both your password AND access to your device,
   they could decrypt your stored history.
   
   This is NOT recommended if you face targeted surveillance.
   Disable at any time to immediately delete all stored history."

DELETION:
  DELETE /history ‚Ü' server hard-deletes all blobs for this user_id immediately.
  User can delete from Settings ‚Ü' Privacy ‚Ü' History Backup ‚Ü' Delete All History.
```

#### Mode C ‚Ä" Real-Time Cross-Device Sync (LINKED DEVICES)

```
PURPOSE: Messages sent from one linked device appear on all other linked devices.
REQUIRES: Devices share the same identity (linked via Section 6, Recovery Path 2).
SERVER ROLE: Routes messages to all linked devices simultaneously. Cannot read content.

HOW IT WORKS:
  When Alice sends a message from Device A:
  1. Message sent to Bob via normal flow (Sealed Sender, Nym)
  2. A copy of the plaintext is also encrypted to Alice's own Device B:
     device_sync_msg = {
       type: "device_sync",
       content: AES-256-GCM(device_B_sync_key, original_plaintext || msg_id)
     }
     Sent as a Sealed Sender message to px_[alice_id] (herself)
  3. Device B receives the sync message, decrypts, stores in its IndexedDB
  4. Device B shows the sent message in the conversation

  Device B sync key:
    device_B_sync_key = HKDF(shared_device_secret, "sync_key_deviceB_v1")
    shared_device_secret established during device linking (Section 6, Path 2)

LIMITATION: sync messages add a small amount of traffic per sent message.
            Covered by the general message traffic pattern.
            Server sees: a Sealed Sender blob going to px_[alice] = normal.

STATUS (Phase 1): IMPLEMENTED as an OPT-IN setting, default OFF.
  Because each sent message produces an additional self-addressed send, an
  actively-observing server transiently sees sender == recipient - a traffic
  pattern (never content) that can suggest multi-device use. Users opt in
  explicitly (Settings ‚Ü' Recovery ‚Ü' Cross-device sync).

  Linking: during a device-to-device transfer (Mode A), after the SAS is
  confirmed, devices that BOTH have the setting enabled exchange
  {device_id, label} over the encrypted channel and derive pairwise keys:
    key_to_device_X = HKDF(channel_secret, "privex_device_sync_v1|" + X_id)
  Keys are stored AES-GCM-encrypted at rest. Linking is pairwise: link each
  device pair that should sync.

  Wire: MessageEnvelope.device_sync { to_device, from_device, blob } where
  blob = AES-256-GCM(pairwise key, payload padded to 1024). No Double Ratchet
  (linked devices share the link key, not a ratchet). The receiver accepts a
  sync copy ONLY when the Sealed-Sender-authenticated sender is its own px_id.

  PHASE 1 DELIVERY SEMANTICS (single mailbox, single WS per account):
  - A sync copy addressed to another device is left UN-ACKED by every other
    device, so it stays queued (30-day TTL) until the target device connects.
  - "Real-time" applies to the device currently holding the account's socket;
    other devices catch up on their next (re)connect.
  - INCOMING messages still land on one device only (whichever acks first).
    Fanning out received messages needs per-device mailboxes or sender keys -
    deliberately deferred (per-device mailboxes would let the server count a
    user's devices).
```

---

### 4.12 Offline Message Delivery & Per-Message TTL

When Bob is offline, Alice's message cannot be delivered immediately. This section defines exactly what happens, what is stored, and for how long.

#### Phase 1: Server Queue Model

```
FLOW (Bob is offline):
  1. Alice's message arrives at Privex server (via Nym gateway)
  2. Server checks WebSocket state map: Bob not connected
  3. Server stores encrypted blob in message_queue (UNLOGGED table):
     { recipient_id: "px_[bob]", content: [encrypted blob], expires_at: now + TTL }
  4. Bob comes online (WebSocket connects)
  5. Server fetches all queued messages for Bob, pushes via WebSocket
  6. Bob's client ACKs receipt ‚Ü' server hard-deletes immediately

WHAT SERVER HOLDS WHILE BOB IS OFFLINE:
  recipient_id:  px_[bob]             ‚Üê pseudonymous, not a real identity
  content:       [random bytes]        ‚Üê AES-256-GCM encrypted, unreadable
  queued_at:     unix timestamp        ‚Üê reveals when Alice sent it (minor metadata)
  size_bytes:    1024                  ‚Üê fixed by padding (reveals nothing)

WHAT SERVER CANNOT DETERMINE:
  Who sent the message (Sealed Sender)
  What the message says (encrypted)
  Bob's real identity (pseudonymous px_id only)
```

#### TTL ‚Ä" Message Expiry

```
DEFAULT TTL: 30 days
  message expires_at = queued_at + (30 * 24 * 60 * 60)
  If Bob does not come online within 30 days: message hard-deleted automatically.
  Background task runs hourly: DELETE FROM message_queue WHERE expires_at < NOW()

EXTENDED TTL: 60 days (opt-in per account)
  User enables in Settings ‚Ü' Privacy ‚Ü' Message Delivery ‚Ü' Extended Queue Time
  Useful for: users who may be offline for extended periods (incarceration, remote areas)
  Risk: message blobs persist on server longer. Content is still encrypted and unreadable.

PER-MESSAGE TTL OVERRIDE:
  Sender can set a custom TTL per message (lower than their account default):
  [Message options] ‚Ü' "Delete if undelivered after..." ‚Ü' 1h / 6h / 24h / 7d / 30d / 60d
  
  Use case: a journalist sending time-sensitive meeting coordinates can set 6-hour TTL.
  If source doesn't come online in 6 hours, the message self-destructs on the server.
  
  Implementation: ttl_seconds field in message_queue row, set by sender.
  Server uses MIN(account_default_ttl, per_message_ttl) as the actual expiry.
  Server enforces this automatically. No human decision needed. No admin override possible.

EXPIRY NOTIFICATION:
  When Alice's client hasn't received an ACK within 80% of the TTL window:
  Client shows: "Message may expire soon ‚Ä" [contact] hasn't been online."
  At expiry: "Message expired ‚Ä" not delivered."
  Alice can choose to resend.
```

#### Phase 2: Nym Gateway Mailbox Model

```
In Phase 2, Privex-operated Nym gateway nodes handle offline delivery.
The Privex server is completely removed from the pending message path.

FLOW:
  1. Alice sends message via Nym (addressed to Bob's Nym address)
  2. Bob is offline ‚Ä" Bob's Nym gateway queues the Sphinx packet
  3. Packet sits at Nym gateway (NOT at Privex server)
  4. Bob comes online ‚Ä" his Nym client connects to his gateway
  5. Gateway delivers queued packet through Nym mix network to Bob
  6. Bob's client decrypts ‚Ü' ACK sent back through Nym
  7. Privex server NEVER holds the message while it is pending

PRIVEX SERVER IN PHASE 2 OFFLINE FLOW:
  The Privex server is never in the message path while Bob is offline.
  The Nym gateway acts as Bob's mailbox.
  Privex operates Nym gateways with no-log configuration (tmpfs /var/log, RAM only).
  Even the gateway cannot read the Sphinx packet contents.

ADVANTAGE:
  Server breach during Bob's offline period: nothing to find.
  The message is at a Nym gateway in encrypted Sphinx format.
  The Nym gateway log shows nothing (no-log configuration).
  Legal order to Privex: genuinely nothing to produce.
```


---

## 5. Metadata Protection Architecture

Content encryption (Section 4) prevents reading messages. This section handles the harder problem: preventing the observation that Privex is being used at all.

### 5.1 Nym Mixnet ‚Ä" True Traffic Analysis Resistance

**Why onion routing alone is not enough:** Standard onion routing (like Tor) is vulnerable to a global passive adversary who watches both the entry and exit of the network simultaneously. If an adversary sees "Alice sent N bytes at time T" and "N bytes arrived at Privex server at time T+250ms," timing correlation deanonymizes Alice without breaking any encryption.

**What Nym provides:** A **mixnet** ‚Ä" a network that batches, shuffles, and delays packets, making timing correlation computationally infeasible rather than just difficult.

```
Nym Mixnet Properties (Loopix-based design):
  - 3-layer mix topology (Entry gateway ‚Ü' Mix layer 1 ‚Ü' Mix layer 2 ‚Ü' Exit gateway)
  - Poisson-distributed delays at each mix node (average 50‚Ä"200ms per hop)
  - All packets are fixed-size Sphinx packets (indistinguishable from each other)
  - Each mix node receives ~thousands of packets/second from many users,
    shuffles order, adds Poisson delay, and forwards
  - Continuous loop cover traffic: every client sends fake Sphinx packets
    to themselves on a Poisson schedule, even when idle
  - Result: An observer watching the network globally sees a constant stream
    of indistinguishable fixed-size packets. Cannot correlate Alice's send
    with Bob's receive without observing >50% of all mix nodes simultaneously

Nym Address:
  Each client session gets an ephemeral Nym address (NymID).
  This NymID changes every session. It is not linked to px_[user_id].
  The Nym gateway knows Alice's IP, but NOT her Privex user ID or destination.
  Privex server knows: message arrived from Nym. Not Alice. Not Alice's IP.
```

#### Nym Integration Architecture

```
Alice's Privex App
        ‚"Ç
        ‚"Ç libsodium-encrypted message (Sealed Sender)
        ‚-º
Nym SDK (embedded in Privex web/mobile app)
        ‚"Ç
        ‚"Ç Wraps message in Sphinx packet addressed to Privex Nym gateway
        ‚-º
Nym Gateway (entry) ‚Ä" knows Alice's IP, does NOT know destination or content
        ‚"Ç
        ‚"Ç Sphinx packets through Nym mix network (3 hops)
        ‚"Ç Each hop adds Poisson delay, shuffles with thousands of other packets
        ‚-º
Privex Nym Gateway (exit) ‚Ä" knows message came from Nym, does NOT know Alice
        ‚"Ç
        ‚"Ç Unwrapped sealed sender blob
        ‚-º
Privex Server ‚Ä" sees: encrypted blob, recipient px_id. Nothing else.
```

#### Nym for Real-Time (Calls)

Nym's Poisson delays (50‚Ä"200ms per hop) add ~300‚Ä"600ms latency ‚Ä" acceptable for chat, not for real-time audio/video. Calls use a different transport:

```
For call signaling (SDP/ICE exchange): Nym (acceptable ‚Ä" happens once at call start)
For call media (audio/video frames):   Direct onion routing (Section 5.2)
                                       ‚Ä" lower latency, weaker anonymity
                                       ‚Ä" acknowledged in threat model

Tradeoff explicitly documented:
  Text messages: Nym mixnet ‚Ü' strong anonymity, ~300‚Ä"600ms additional latency
  File transfers: Nym mixnet ‚Ü' strong anonymity (latency acceptable for files)
  Call signaling: Nym mixnet ‚Ü' strong anonymity (one-time at call start)
  Call media: Onion routing ‚Ü' weaker anonymity, <50ms additional latency
```

**Nym SDK:** `@nymproject/sdk-full-fat` (browser WASM bundle). Nym provides a browser-compatible WebAssembly client that connects to Nym gateways via WebSocket. No installation required for web users.

### 5.2 Onion Routing ‚Ä" Real-Time Transport

For latency-sensitive operations (call media, real-time presence signals, WebSocket keep-alives), Privex maintains its own 3-hop onion routing network.

```
Circuit Structure:
         ‚"å‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ê
Alice ‚"Ä‚"Ä‚-∂‚"Ç Guard Node 1 ‚"Ç‚"Ä‚"Ä‚-∂ ‚"å‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ê‚"Ä‚"Ä‚-∂ ‚"å‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ê‚"Ä‚"Ä‚-∂ Privex Server
         ‚"Ç(knows Alice's‚"Ç    ‚"Ç  Node 2   ‚"Ç    ‚"Ç Exit Node‚"Ç
         ‚"Ç    IP only)  ‚"Ç    ‚"Ç(knows only‚"Ç    ‚"Ç(knows only‚"Ç
         ‚""‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ò    ‚"Ç hops 1+3) ‚"Ç    ‚"Ç  server) ‚"Ç
                             ‚""‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ò    ‚""‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ò

Node 1: Knows Alice's IP + Node 2 address. Does NOT know Privex server address.
Node 2: Knows Node 1 + Node 3 addresses. Does NOT know Alice or Privex server.
Node 3: Knows Node 2 address + Privex server address. Does NOT know Alice.
Privex: Knows Node 3 IP (a relay). Does NOT know Alice.

Onion encryption:
  inner = Encrypt(server_pubkey, payload)
  layer2 = Encrypt(node3_pubkey, inner || node3_addr)
  layer1 = Encrypt(node2_pubkey, layer2 || node2_addr)
  outer  = Encrypt(node1_pubkey, layer1 || node1_addr)
  Alice sends outer to Node 1.

Circuit lifetime:
  Messages: Circuit replaced by Nym for all message transport.
  Calls:    New circuit per call. Torn down on hang-up.
  Auth/API: Circuit reused for 10 minutes or 50 requests, then rotated.

Node selection criteria:
  - 3 nodes from 3 different jurisdictions (never all from same country)
  - Never 3 nodes from same operator
  - Geographic proximity for call circuits (minimize latency)
  - Weighted random otherwise
```

**Relay Node Network Phases:**
- Phase 1: 10+ Privex-operated relay nodes across Iceland, Switzerland, Singapore, Panama, and Romania (5 jurisdictions minimum from day one ‚Ä" never 3‚Ä"5 as in the prior architecture)
- Phase 2: Volunteer-operated relay nodes (reviewed, not anonymous ‚Ä" accountability without identity)
- Phase 3: Libp2p-based decentralized relay network

### 5.3 Cover Traffic

```
APP IDLE STATE (foreground, no active conversation):
  Every [Poisson(Œª=10s)] seconds, send a dummy sealed sender message:
  {
    recipient: px_[random 32-char hex],   // Fake recipient ID ‚Ä" no mailbox exists
    type: "cover",
    content: CSPRNG(1024 bytes)           // Looks identical to real encrypted message
  }
  Server receives it, finds no matching mailbox, silently drops it.
  An observer sees: constant stream of fixed-size sealed sender messages.
  Cannot distinguish real traffic from cover traffic.

APP ACTIVE STATE (typing, sending):
  Cover traffic continues at same rate.
  Real messages blend into the existing stream.

CALLS:
  During silence (no audio activity), transmit comfort noise frames encrypted
  with SFrame at the same bitrate as active audio.
  Observer cannot detect call start, end, or silence patterns.

USER CONTROL (privacy vs. battery):
  LOW:    Poisson(Œª=30s)  ‚Ä" minimal drain, moderate protection
  MEDIUM: Poisson(Œª=10s)  ‚Ä" recommended default
  HIGH:   Poisson(Œª=3s)   ‚Ä" maximum protection, higher battery/data use
  OFF:    No cover traffic ‚Ä" for users on metered data (explicit choice)
```

**Nym provides its own loop cover traffic** at the network level. Privex cover traffic is an additional, application-level layer that operates even before traffic reaches the Nym layer.

**Receipts piggyback on cover traffic:** Delivery and read receipts (Section 4.10) are not sent immediately on receipt of a message. They are queued and transmitted at the next Poisson cover traffic interval. This means receipt timing is decoupled from message delivery timing ‚Ä" an adversary cannot infer when Bob came online by watching when Alice receives a "delivered" confirmation.

### 5.4 Censorship Circumvention

Privex must be functional in China, Iran, Russia, and any country with deep packet inspection (DPI) or IP blocklists.

#### Connection Attempt Cascade

```
Attempt 1: Direct WebSocket ‚Ü' Nym network (ws://nym-gateway-entry:port)
           Detect: timeout after 5s

Attempt 2: Domain fronting via CDN
           TLS handshake says: popular-cdn.example.com (CDN domain, blocked = collateral damage)
           HTTP Host header (hidden inside TLS): nym-gateway.privex.dpdns.org
           CDN routes internally to Privex Nym gateway.
           CDN providers: 2+ independent providers (not AWS, not GCP ‚Ä" both have banned this)
           Detect: timeout after 5s

Attempt 3: Bridge nodes (unlisted Privex relay nodes)
           10 hardcoded bridges in app binary (hex-encoded, not plaintext strings)
           Bridges rotated quarterly via signed app update
           Bridge list also distributed via:
             - Email: bridges@privex.dpdns.org ‚Ü' automated encrypted response
             - Separate domain (not privex.dpdns.org): hardcoded, updated via signed config
           Detect: none of 10 bridges respond

Attempt 4: obfs4 pluggable transport
           Disguises all traffic as random bit noise
           No recognizable protocol header, no identifiable pattern
           obfs4proxy bundled as WASM module (web) or binary (native)
           Detect: timeout

Attempt 5: Snowflake
           Disguises traffic as WebRTC video calls
           Uses volunteer Snowflake proxies distributed via WebRTC
           Virtually unblockable without banning WebRTC entirely (collateral too large)
           Detect: timeout (extremely rare)

Attempt 6: Manual bridge entry
           User types a bridge address obtained from:
             trusted contact, printed QR code, in-person event, Signal message
```

#### Domain Fronting Note

Domain fronting depends on CDN provider cooperation (passive, via routing) which some CDNs have disallowed. Privex maintains relationships with 2+ CDN providers and has a fallback config update mechanism that can swap the CDN endpoint via a small, signed configuration file fetched before each connection attempt.

### 5.5 DNS & Network Protection

```
DNS Leak Prevention:
  The app does NOT use the OS system DNS resolver.
  All DNS is resolved via DNS-over-HTTPS (DoH), hardcoded in app:

  Primary DoH:  Cloudflare 1.1.1.1 (https://cloudflare-dns.com/dns-query)
  Fallback DoH: Quad9 (https://dns.quad9.net/dns-query)
  Tertiary:     DNS-over-HTTPS via the Privex bridge node network
  
  When onion routing / Nym is active:
    DNS resolves via the exit relay / Nym gateway.
    The user's system DNS resolver is completely bypassed.
    ISP DNS provider sees zero DNS queries from this session.

WebRTC IP Leak Prevention:
  ICE candidate generation defaults to TURN-only mode:
    No host candidates (no local IP in SDP)
    No server-reflexive candidates (no public IP via STUN)
    Only relay candidates (TURN server IP only)
  
  In TURN-only mode: the user's IP is never present in any SDP offer or answer.
  The TURN server sees the user's IP, but TURN server does not log it and
  TURN authentication is not linked to user identity (Section 4.8).

  Direct P2P mode: opt-in only. Reveals local IP to peer only. Not to server.
```

### 5.6 Push Notifications Without APNs or FCM

**The problem:** iOS push notifications go through Apple APNs. Android push goes through Google FCM. Both services learn: this device uses Privex, and when messages arrive. This breaks Law 4 (ISP/ecosystem can confirm Privex is used).

#### Web App Solution: Service Workers + Self-Hosted Push

```
Web Push Protocol (RFC 8030) allows encrypted push notifications over any server.
Standard Web Push goes through browser vendor servers (Chrome ‚Ü' Google, Firefox ‚Ü' Mozilla).

Privex uses the Web Push protocol but routes push through Nym:
  1. User's browser registers a push subscription.
     Instead of a Google/Mozilla push endpoint, it specifies a Privex-controlled endpoint.
  2. The Service Worker maintains a persistent WebSocket connection to Privex
     via Nym when the browser is open.
  3. When browser closes / goes background: service workers on desktop browsers
     maintain the WebSocket connection (Chrome, Firefox, Safari on desktop).
  4. On mobile web (PWA on Android/iOS): the persistent connection drops when
     backgrounded. Fallback options:
        a. PERIODIC_BACKGROUND_SYNC (Chrome Android): browser wakes service worker
           periodically to check for messages.
        b. Background Fetch API: download pending messages when browser wakes.
        c. Accept: web app on mobile has delayed notifications when backgrounded.
           This is a known PWA limitation ‚Ä" documented, not hidden.
```

#### Native Mobile App Solution

```
Android:
  High-priority FCM message (0-byte payload, encrypted notification token).
  The FCM message itself contains zero user data ‚Ä" just a wake-up signal.
  App wakes, connects via Nym, fetches pending messages.
  FCM learns: "this device should wake up." Nothing about the message, sender, or content.
  
  Better: Use Firebase-independent push via ntfy.sh or self-hosted UnifiedPush provider.
  UnifiedPush routes push through a user-chosen server.
  If user runs their own UnifiedPush server or uses a privacy-focused provider:
    Google FCM is not in the notification path at all.
  UnifiedPush is supported in Privex Android as the default (non-FCM path).
  FCM is available as an opt-in for users who prefer convenience over this specific privacy.

iOS:
  iOS is more restrictive. Push requires APNs. No alternative for background wake.
  Privex iOS approach:
    1. VoIP push (CallKit): separate APNs channel with different privacy properties.
       APNs payload: encrypted, 0-byte content. Just a wake token.
    2. BGAppRefreshTask: OS wakes app in background periodically (every 15‚Ä"30 min).
       App connects via Nym, fetches messages.
    3. Silent push (APNs content-available): 0-byte push causes background fetch.
    4. Explicitly document to iOS users: Apple knows Privex is installed and
       that their device receives periodic background pushes. Apple does NOT know
       who their contacts are, what is said, or when specific messages arrive.
  
  This is the honest limitation. iOS prevents true notification privacy at the OS level.
  Documented in threat model. Not hidden.
```

### 5.7 Timing Analysis Mitigations

> PHASE 1 STATUS: Privex Phase 1 uses a PERSISTENT WebSocket + application-level
> cover traffic (5.3), not fixed polling. In that model the constant-traffic goal
> of Mitigations 1 & 2 is met by a constant Poisson stream of fixed-size (1024-byte)
> sealed decoy sends ‚Ä" an observer sees an unchanging stream regardless of real
> activity, so connection/volume timing reveals nothing. IMPLEMENTED in Phase 1:
> cover traffic decoy sends (services/cover-traffic.ts + messaging.sendCoverMessage),
> the 1024-byte padding law, and jittered receipts with a 5 s floor (Mitigation 3).
> Mitigation 1 "fixed polling" and its GET /messages/poll endpoint are a PHASE-2 /
> Nym-gateway feature (the poll connects to the Nym gateway; Nym is Phase 2) and are
> deliberately NOT built in Phase 1 ‚Ä" they would add a second, connect/disconnect
> delivery path that duplicates and fights the persistent WS. Mitigation 4 (delivery
> windows) remains an opt-in Phase-2 high-threat mode.

Even with Nym mixnet providing strong anonymity for message content and routing, a sophisticated adversary watching Bob's specific ISP connection can still observe:
- When Bob's device connects to the Nym network
- When Bob's device disconnects
- A rough inference that Bob received something when he reconnected

This section defines the mitigations layered on top of Nym to further degrade timing correlation attacks.

#### Understanding the Residual Risk

```
WHAT AN ADVERSARY WATCHING BOB'S ISP CAN OBSERVE:
  ‚ú" Bob's device connected to Nym gateway at 09:47
  ‚ú" Bob's device was offline between 3pm and 9:47pm
  ‚ú" Bob's device generates constant encrypted traffic to Nym (when online)

WHAT THEY CANNOT OBSERVE (with Nym active):
  ‚ú- That Bob uses Privex (just: Bob uses Nym)
  ‚ú- Who Bob is talking to
  ‚ú- What any message says
  ‚ú- Whether Bob received a message at 09:47 or just reconnected normally
  ‚ú- Any information about Alice

GOAL OF TIMING MITIGATIONS:
  Further degrade the "Bob reconnected at 09:47" observation into
  "Bob reconnected sometime in a larger time window" and
  "we can't tell if he received anything or just reconnected."
```

#### Mitigation 1: Fixed Polling Schedule

```
PROBLEM: Bob's WebSocket connects reactively when a push notification arrives.
         An adversary sees: Bob connected exactly when something arrived.

SOLUTION: Bob's Nym client connects on a fixed schedule regardless of messages.

  Poll interval: every 30 minutes (default), every 10 min (high-security mode)
  On each poll cycle:
    1. Connect to Nym gateway
    2. Fetch exactly N items (see Mitigation 2)
    3. Disconnect (or stay connected for the session)

  ISP sees: Bob's device connects to Nym every 30 minutes. Always.
            Even when no messages are pending. Pattern never changes.
            When Bob is offline: device simply doesn't connect.
            When Bob comes back: connects at the next 30-minute mark.

  Result: adversary learns Bob reconnected sometime in a 30-minute window.
          Not the exact moment. Not whether messages were received.

User-controlled intervals:
  Standard mode:      Poll every 30 min, reconnect immediately on send
  High security mode: Poll every 10 min
  Maximum mode:       Poll every 5 min (significant battery drain on mobile)
  LOW power mode:     Poll every 60 min (for battery-constrained devices)
```

#### Mitigation 2: Constant Fetch Size

```
PROBLEM: When Bob connects and has 3 pending messages,
         his client fetches 3 blobs. When no messages: fetches 0.
         Observer can infer from traffic volume whether messages were pending.

SOLUTION: Always fetch exactly N items per poll cycle.

  N = 10 (default), configurable per user.
  If 3 real messages pending + 7 dummy: client fetches 10 items total.
  If 0 real messages: client fetches 10 dummy messages (indistinguishable).
  If 10+ real messages: fetches 10 items per cycle (rest next cycle).

  Dummy items: generated by Privex server on request. Random bytes. Same size.
  From observer's perspective: Bob always downloads exactly 10 fixed-size items.
  No spike. No variation. No inference about message volume.

Implementation:
  GET /messages/poll?count=10
  Server returns: up to 10 real messages + padding to exactly 10 dummy items
  Client decrypts each: real messages process normally, dummies are discarded
```

#### Mitigation 3: Jittered Receipt Sending

```
PROBLEM: Bob receives a message at 09:47:50. Alice gets a "delivered" receipt at
         09:47:52. Observer watching both ISP connections can correlate: Alice
         sent something, Bob received it 2 minutes later.

SOLUTION: Receipts are sent at the next cover traffic interval, not immediately.

  Receipt generation: immediate (client queues the receipt locally)
  Receipt transmission: at next Poisson(Œª=1/300s) cover traffic fire
  
  Average additional delay: ~5 minutes
  Range: 0 seconds to ~15 minutes (Poisson-distributed)
  
  From observer's perspective:
    Alice sent something at 07:32.
    Bob's device reconnected at 09:47.
    Alice received a "delivered" signal at 09:52.
    Gap is 5 minutes... is that Nym latency? Receipt delay? Bob reading it?
    Cannot distinguish. Correlation is broken.

Relation to cover traffic (Section 5.3):
  Receipts piggyback on the cover traffic Poisson schedule.
  When the next cover traffic tick fires, any queued receipts go out in that batch.
  Real receipts are indistinguishable from cover traffic in the network stream.
```

#### Mitigation 4: Delivery Windows (Optional, High-Threat Mode)

```
PURPOSE: For users who need the absolute maximum timing protection and can
         tolerate delivery delays of several hours.

MECHANISM:
  Pending messages are only delivered during fixed 6-hour UTC windows:
    00:00 UTC, 06:00 UTC, 12:00 UTC, 18:00 UTC

  If Bob comes online at 09:47, his pending messages are NOT delivered immediately.
  They are held at the Nym gateway (Phase 2) or server (Phase 1) until 12:00 UTC.

  Alice knows: Bob will receive this sometime in the next 6-hour window.
  Adversary watching Bob's ISP: cannot correlate Bob's reconnection to any specific
  send event. Cannot determine when Alice sent the message from when Bob received it.
  All they know: Bob was offline, came online, and eventually got a batch of messages.

APPROPRIATE FOR:
  High-risk journalists, whistleblowers, activists with known surveillance
  Secure document drops where timing is security-sensitive
  Users who have already been identified as targets

NOT APPROPRIATE FOR:
  General communication (6-hour delay is unacceptable for most use cases)
  Emergency contact

SETTING: Settings ‚Ü' Privacy ‚Ü' Delivery Timing ‚Ü' Delivery Windows (OFF by default)
         Clear explanation of trade-off shown when enabling.
```

#### Combined Defense Summary

```
After all four mitigations + Nym loop cover traffic:

An adversary watching Bob's ISP sees:
  "Bob's device sends constant encrypted traffic to Nym when online.
   Bob's device was offline for a period.
   Bob's device came back online."

That is ALL they can determine. They cannot:
  - Know Bob uses Privex (just: Bob uses Nym)
  - Know when specifically Bob received a message
  - Know if traffic spikes are real messages or cover traffic
  - Know if Bob's reconnection coincides with any specific Alice send event
  - Read any content whatsoever

This is the minimum achievable timing exposure for a software-based system
running over the public internet without controlling the physical network layer.
```


---

## 6. Account Recovery System

This is the feature that sets Privex apart from every other privacy-first messenger. You should never lose access to your account because you lost a device.

### Philosophy

True E2EE means only the user holds keys. Standard secure messengers solve this by saying "you don't lose your account, but you lose your message history" ‚Ä" which is acceptable for chats but disruptive. Privex goes further by offering recovery choices while keeping the server unable to recover keys on the user's behalf.

One optional recovery path is **OPAQUE** ‚Ä" a cryptographic protocol that lets the server store an encrypted envelope of your keys without learning your password. OPAQUE is not mandatory: turning it off deletes the server-side OPAQUE record. This matters for high-risk users because database + exported OPRF key compromise enables offline password guessing against OPAQUE-enabled accounts.

### Recovery Path 1: OPAQUE Password Recovery (OPT-IN)

**OPAQUE** (Oblivious Pseudorandom Function-based Authenticated Key Exchange) is an IETF standard (RFC draft, CFRG working group). It is specifically designed for this use case.

```
WHAT OPAQUE IS:
  A Password Authenticated Key Exchange (PAKE) protocol where:
  1. The server NEVER learns the user's password (not even a hash of it)
  2. The server stores a "record" that is not useful for offline dictionary attacks
     unless the attacker also obtains the server's private OPRF key
  3. The user derives a cryptographic export key from their password + the OPRF output
  4. That export key is used to decrypt an "envelope" containing the user's actual keys
  5. If database + OPRF key are both stolen, OPAQUE-enabled accounts become
     offline-attackable. Strong recovery passwords remain expensive to guess;
     weak passwords are at risk.

ENABLE / CHANGE PASSWORD RECOVERY (authenticated, optional):
  1. Client already has: identity keypairs, master seed S, live session token
  2. Client generates OPAQUE registration request:
     r  = CSPRNG(scalar)
     blind = r * H(password)  [blinded password, on Ristretto255 curve]
     Client sends: { blind } over an authenticated request

  3. Server responds with:
     Z = server_OPRF_key * blind  [OPRF evaluation, server never sees password]
     pk_server = server's OPAQUE public key

  4. Client computes:
     rwd = HKDF(unblind(Z, r), salt, "OPAQUE_rwd")  [randomized password]
     export_key = HKDF(rwd, "export_key")
     auth_key   = HKDF(rwd, "auth_key")
     
     envelope = AES-256-GCM(export_key, {
       master_seed: S,
       IK_ed_priv:  identity_keypair_ed.priv,
       IK_dil_priv: identity_keypair_dil.priv,
       kyber_priv:  kyber_keypair.priv,
       x25519_priv: x25519_keypair.priv
     })
     
     mac = HMAC-SHA256(auth_key, envelope)
     
     Client sends: { envelope, mac }

  5. Server upserts: { user_id, OPRF_record, envelope, mac }
     Server sees: OPRF_record (blinded), encrypted envelope.
     Server does NOT see: password, master_seed, any private key.

DISABLE PASSWORD RECOVERY:
  1. Authenticated client calls DELETE /recovery/opaque
  2. Server hard-deletes opaque_records[user_id]
  3. No disabled placeholder is kept. Row existence is the enabled state.
  4. Any OPAQUE login started before the delete is invalidated before token minting.

LOGIN / RECOVERY (any new device, only password needed):
  1. Client sends: { user_id, blind = r * H(password) }
  2. Server returns: Z = server_OPRF_key * blind, envelope, mac
  3. Client computes:
     rwd = HKDF(unblind(Z, r), salt, "OPAQUE_rwd")
     export_key = HKDF(rwd, "export_key")
     auth_key   = HKDF(rwd, "auth_key")
     
     Verify: HMAC-SHA256(auth_key, envelope) == mac  [if fails: wrong password]
     
     keys = AES-256-GCM_decrypt(export_key, envelope)  [recovers all key material]
  
  4. User has full key material on new device. Account fully restored.

SECURITY GUARANTEE:
  - OPAQUE OFF: server has no OPRF record/envelope for that user
  - Database-only theft: attacker cannot verify password guesses offline
  - Database + exported OPRF key theft: attacker can run offline password guessing
  - Live server abuse: OPRF evaluation is rate-limited by the server
  - Root/RCE on the app server can still abuse the service while live; protecting
    the OPRF key in an HSM/enclave/threshold service is required for stronger
    production seizure resistance
  - In practice: strong recovery passwords are mandatory for users who enable OPAQUE
```

**Library:** `opaque-ke` (Rust, from Meta) for server. `opaque-ts` (TypeScript) for web client. Both implement the IETF OPAQUE spec.

### Recovery Path 2: Multi-Device Linking (EASIEST)

```
LINK A NEW DEVICE from an existing device:

1. On Device A (existing): Navigate to Settings ‚Ü' Linked Devices ‚Ü' Add Device
   App generates:
     link_secret = CSPRNG(32 bytes)
     link_qr_payload = {
       link_secret: link_secret,
       rendezvous_id: CSPRNG(16 bytes)
     }
   Display as QR code. Valid for 5 minutes.

2. On Device B (new): Scan QR code.
   Derives: link_key = HKDF(link_secret, "device_link_key")
   Sends to server: { rendezvous_id, device_pub: Device_B_ephemeral_pub }

3. Device A receives (via WebSocket): Device B's ephemeral public key
   Confirms in UI: "Link this device? [Verify code: XK47]" (user confirms on both screens)
   
4. Device A encrypts full key material for Device B:
   shared = X25519(Device_A_link_priv, Device_B_ephemeral_pub)
   transfer_key = HKDF(shared || link_secret, "link_transfer")
   key_bundle = AES-256-GCM(transfer_key, {
     master_seed, IK_ed_priv, IK_dil_priv, kyber_priv, x25519_priv,
     contacts_db_encrypted, [ratchet states (optional ‚Ä" only forward from now)]
   })
   
5. Server routes key_bundle to Device B (server sees only encrypted blob)
6. Device B decrypts with transfer_key, imports keys, active on network.
7. link_secret deleted from both devices. Rendezvous record deleted from server.

RESULT: Device B has full identity. Device A and B share the same px_[id].
        Messages are routed to all linked devices simultaneously (multi-device delivery).
        If Device A is lost: Device B retains full access, history, contacts.
```

### Recovery Path 3: Emergency Recovery Contacts (SOCIAL RECOVERY)

```
User designates 1‚Ä"3 emergency contacts (must be Privex users).

SETUP:
  1. User's master_seed S split into N shares using Shamir's Secret Sharing:
     (t=2, n=3): any 2 of 3 shares reconstruct S
     
  2. For each contact C_i:
     share_i = Shamir_split(S, t=2, n=3)[i]
     enc_share_i = XChaCha20-Poly1305(
       key = X25519(user_eph_priv, IK_C_i_pub),
       plaintext = share_i
     )
     
  3. Server stores: { user_id, enc_shares: [enc_share_0, enc_share_1, enc_share_2] }
     Server sees: three encrypted blobs. Cannot decrypt. Does not know who contacts are.
     (Contacts' px_ids are NOT stored with the shares ‚Ä" user remembers who they chose)

RECOVERY:
  1. User (on new device) authenticates minimally (proves ownership of px_id via any
     valid auth: OPAQUE, or new device signing with a pre-authorized device key)
  2. User contacts 2 of 3 emergency contacts out-of-band: "I lost my device, please approve"
  3. Each approving contact: opens Privex ‚Ü' pending approval notification ‚Ü'
     taps Approve ‚Ü' their app fetches enc_share_i from server, decrypts it
     (using their private key to reverse the X25519), and sends decrypted share
     to recovering user via Sealed Sender message
  4. Recovering user receives 2 shares ‚Ü' Shamir_reconstruct(share_0, share_1) ‚Ü' S
  5. S regenerates all keypairs. Full identity restored.

SECURITY PROPERTIES:
  - Server never learns the shares (encrypted to contact keys)
  - Recovery requires physical cooperation of 2 real people
  - Contacts cannot collude to steal identity unless all 3 are malicious (2-of-3 = resistant to 1 traitor)
  - Approval is conscious: contacts must actively approve in-app, cannot be coerced silently
```

### Recovery Path 4: Seed Phrase (Fallback)

```
24-word BIP-39 mnemonic shown once during registration.
Stored nowhere by Privex.

Entropy: BIP-39 256-bit entropy ‚Ü' 24 words
Key derivation:
  seed_bytes = BIP39_to_seed(mnemonic, passphrase="PRIVEX_SEED_V1")
  master_seed = HKDF(seed_bytes, "privex_master_seed_v1")
  Ed25519 keypair = ed25519_from_seed(HKDF(master_seed, "ed25519_ik"))
  Dilithium3 keypair = dilithium3_from_seed(HKDF(master_seed, "dilithium3_ik"))
  X25519 keypair  = x25519_from_seed(HKDF(master_seed, "x25519_spk"))
  Kyber keypair   = kyber_from_seed(HKDF(master_seed, "kyber_pk"))
  
Recovery: Enter 24 words ‚Ü' regenerate all keypairs ‚Ü' same px_[id] ‚Ü' back on network.
Note: Seed phrase recovery restores identity and contacts. 
      Message history lives on devices ‚Ä" not reconstructable from seed phrase alone.
```

### Recovery Decision Flow

```
Device lost? Choose recovery path:

Has another linked device?
  YES ‚Ü' Use it. Or link new device from it.
  
OPAQUE password recovery enabled, and remember your password?
  YES ‚Ü' OPAQUE recovery. Any browser. Any device. Password only.
  
Have emergency recovery contacts set up?
  YES ‚Ü' Contact 2 of 3. Social recovery.

Have your seed phrase written down?
  YES ‚Ü' Seed phrase recovery.

NONE OF THE ABOVE:
  Account is unrecoverable. Identity must be re-created.
  This is the only scenario with total loss, and it requires
  all of the following simultaneously:
    - Lost all devices
    - Forgotten password
    - No emergency contacts configured
    - No seed phrase written down
  User was informed of all four backup options during onboarding.
```

---

## 7. CSAM Protection System

Preventing distribution of child sexual abuse material without breaking zero-knowledge architecture. The server never sees content. All protection happens client-side with cryptographic verification.

### 7.1 Architecture Overview

```
Traditional (breaks E2EE):
  Content ‚Ü' Server ‚Ü' Hash check ‚Ü' Block/Allow
  Server sees content. Breaks zero-knowledge entirely.

Privex (preserves ZK):
  Content ‚Ü' Client hash ‚Ü' PSI check ‚Ü' ZK proof ‚Ü' Server verifies proof only
  Server sees: "This message passed the CSAM check." (verified cryptographic proof)
  Server does NOT see: Content, hash, or what was checked.
```

### 7.2 Client-Side Perceptual Hashing

```
Algorithm: PDQ (Facebook/Meta, Apache 2.0 license)
Property:  Perceptual hash ‚Ä" matches images even if resized, cropped,
           compressed, watermarked, or recolored (unlike SHA-256 which changes
           completely with any modification)
Hash size: 256 bits
Collision resistance: Designed for 90%+ similarity threshold matching

Process (triggered on every outgoing image or video):
  1. Load image into memory (decrypted, pre-encryption)
  2. Compute PDQ hash(image) ‚Ü' 256-bit perceptual fingerprint
  3. Pass to PSI module (Section 7.3)
  4. Image is never sent to any server in plaintext ‚Ä" this check is local only

Video:
  Extract keyframes at 5-second intervals (not 2s ‚Ä" reduces PSI checks by 60%)
  Hash each keyframe with PDQ
  All hashes checked via PSI before the file is encrypted and uploaded

Performance on modern hardware:
  PDQ hash: ~5ms per image (WASM), ~1ms (native)
  Video keyframe extraction: ~10ms/frame
```

### 7.3 Private Set Intersection ‚Ä" OPRF-Based

```
Goal:
  Client learns: "Is my image hash in the NCMEC blocklist?" (boolean)
  Server learns: NOTHING about the image hash
  Client learns: NOTHING about other hashes in the blocklist

Protocol (Oblivious PRF, Ristretto255 curve):

Step 1 ‚Ä" Client blinds the hash:
  r  = CSPRNG(scalar on Ristretto255)
  H' = r * H_to_curve(PDQ_hash)   [hash-to-curve mapping, then scalar mult]
  Client sends H' to server.
  H' is computationally indistinguishable from a random curve point without r.

Step 2 ‚Ä" Server evaluates OPRF on blocklist and on client's blinded hash:
  Server has pre-computed: T = { server_key * H_to_curve(h) : h in NCMEC_blocklist }
  (T is computed offline and updated daily as NCMEC database updates)
  Server evaluates: H'' = server_key * H'   [server never sees the unblinded hash]
  Server returns: H'' and T

Step 3 ‚Ä" Client unblinds:
  result = (1/r) * H''  =  server_key * H_to_curve(PDQ_hash)

Step 4 ‚Ä" Client checks membership:
  Is result in T?
  YES: Hash matches a known CSAM entry ‚Ü' BLOCK, do not encrypt/send
  NO:  Image is clear ‚Ü' generate ZK proof, proceed to send

Security properties:
  Server receives H' (random-looking curve point). Cannot recover PDQ_hash without r.
  Client receives T (large set of OPRF outputs). Cannot recover any blocklist entry.
  Neither party learns the other's set.
  
Performance: <50ms per image on modern hardware, including network roundtrip.
```

### 7.4 ZK Proof of Compliance

After a PSI check returns "no match," the client generates a ZK proof so the server can verify the check happened correctly, without seeing what was checked.

```
Proving System: Groth16 (smallest proof size: 256 bytes, fastest server verification: <5ms)

TRUSTED SETUP REQUIREMENT:
  Groth16 requires a one-time "trusted setup" ceremony to generate a
  Common Reference String (CRS). If the ceremony is compromised, fake proofs
  can be generated. This ceremony MUST be public and auditable.
  
  Privex Trusted Setup Ceremony:
    Format: Powers of Tau multi-party computation ceremony
    Participants: Minimum 10, ideally 50+ independent parties
            (security researchers, EFF, journalists, public volunteers)
    Process: Each participant contributes randomness; the final CRS is secure
             as long as ANY ONE participant was honest
    Reference: Zcash's Sprout/Sapling ceremonies are the model
    Output: Publicly published CRS (pinned in app)
    Verification: Anyone can verify the ceremony transcript
    Timing: Must be completed before Phase 4 launch (group messaging phase)

ZK Circuit: csam_check.circom (Circom 2.0)

Public inputs (what the server sees):
  - image_commitment = Pedersen_Commit(PDQ_hash, randomness)
  - result = 0 (no match)

Private inputs (known only to client):
  - PDQ_hash
  - randomness (for Pedersen commitment)
  - PSI transcript (H', H'', r, T_subset)

Statement proven (without revealing private inputs):
  "I have an image whose PDQ hash I committed to in image_commitment.
   I ran the OPRF-based PSI protocol with server_OPRF_key.
   The result was 0 (no match in NCMEC blocklist).
   The PSI transcript is valid (H'' = server_key * H', result = (1/r)*H'')."

Proof size: ~256 bytes (Groth16)
Client proof generation: ~300ms (WASM, optimized circuit), ~80ms (native)
Server verification: <5ms

Message payload (to server):
  {
    sealed_content:    "[encrypted sealed sender blob]",
    csam_proof:        "[256-byte Groth16 proof]",
    image_commitment:  "[Pedersen commitment]"
  }

Server rejects any message containing an image flag without a valid csam_proof.
Server cannot see the image. Cannot see the hash. Sees only: "proof is valid."

WHAT THIS COVERS:
  Known CSAM (in NCMEC database): Blocked at send time. Cannot be transmitted.
  Unknown CSAM (newly created, not yet in DB): Not covered by this system.
  ‚Ü' Covered by user reporting (Section 7.5).
```

### 7.5 User Reporting & Legal Architecture

```
USER REPORT FLOW (for content believed to be CSAM, received by user):

1. Recipient (who has the decrypted content) taps: Report ‚Ü' CSAM

2. On the user's device:
   Build CyberTipline report:
   {
     content:       [decrypted file bytes ‚Ä" user has this legitimately as recipient],
     sender_proof:  [SenderCert extracted from the sealed message ‚Ä" cryptographic proof of sender],
     timestamp:     [message timestamp],
     report_type:   "CSAM"
   }

3. Report sent DIRECTLY from user's device to NCMEC CyberTipline API:
   POST https://api.missingkids.org/cybertipline/v1/report
   (Privex servers are NOT in this chain)

4. Privex servers receive ONLY an aggregate count: { event: "csam_report", count: 1 }
   No content. No sender identity. No recipient identity.

LEGAL FRAMEWORK:
  18 U.S.C. ¬ß 2258A (REPORT Act) requires platforms to report known CSAM.
  Privex complies via the direct user-to-NCMEC pipeline above.
  We are not required to surveil encrypted communications to comply.
  
  Defense against "Privex facilitated CSAM":
  1. Client-side PDQ+PSI blocks all known CSAM. Architecture documented, open-source, auditable.
  2. Direct-to-NCMEC user reporting satisfies 18 U.S.C. ¬ß 2258A.
  3. We applied every technically feasible measure while preserving encryption.
  4. NCMEC Technology Coalition membership (apply: missingkids.org).
  
  Jurisdiction: Iceland. Legal requests require Icelandic court order.
                Our architecture means even court-compelled disclosure reveals nothing.
```

---

## 8. Server Architecture

### 8.1 Oblivious Server Model

```
WHAT THE SERVER STORES:
  key_directory:   { px_id ‚Ü' public keys (no names, no IPs, no phone) }
  message_queue:   { recipient_px_id ‚Ü' encrypted blob } (deleted on delivery or TTL expiry)
                   Phase 1: held until Bob connects. Phase 2: Nym gateway holds instead.
  blob_index:      { sha256_of_encrypted_chunk ‚Ü' storage_path } (deleted after download)
  group_state:     { group_id ‚Ü' encrypted MLS state } (server cannot decrypt)
  relay_nodes:     { node_id ‚Ü' pubkey, address, region }
  opaque_records:  { px_id ‚Ü' OPRF_record, envelope (encrypted) } (for recovery)
  kt_log:          { sequence ‚Ü' key directory entry + hash chain } (transparency log)
  recovery_shares: { px_id ‚Ü' [encrypted Shamir shares] } (server cannot decrypt)
  history_blobs:   { user_id ‚Ü' encrypted message blobs } (OPT-IN ONLY, server cannot decrypt)
                   Only stored if user explicitly enables server-side history backup.
                   Encrypted with history_key derived from OPAQUE master seed.
                   User can delete all history blobs at any time.
                   NOT stored by default. Architecture is no-history by default.

WHAT THE SERVER NEVER STORES:
  - Any real name, email, phone number
  - Any IP address (never, not even temporarily in any buffer or log)
  - Message content (encrypted blobs only, key never held by server)
  - Sender identity (Sealed Sender ‚Ä" encrypted inside the blob)
  - Social graph (server sees only recipient px_id, never sender)
  - File content, filename, or type (content-addressed encrypted chunks)
  - Call participants, duration, or content
  - Access logs, connection logs, error logs with user identifiers
  - OPAQUE passwords or any function of them
```

### 8.2 Key Directory + Transparency Log

**The problem:** A centralized key directory can silently substitute keys, enabling a man-in-the-middle attack on new sessions. Users would have no way to detect this.

**The solution:** Certificate Transparency-style append-only log. Every key registration and SPK rotation is committed to the log. Any substitution would be publicly visible.

```
KEY TRANSPARENCY LOG (KT Log):

Structure: Append-only Merkle tree (similar to RFC 9162 Certificate Transparency)
           Each leaf = (px_id, key_bundle_hash, timestamp)
           Internal nodes = SHA-256(left_child || right_child)
           Root = published periodically (every 10 minutes)

Operations:
  REGISTER: New entry appended. Entry = { px_id, SHA-256(key_bundle), timestamp }
  SPK_ROTATE: New entry appended. Old entry remains (immutable log).
  QUERY: Client fetches inclusion proof (O(log N) size) that their entry is in the log.

What this prevents:
  If Privex substitutes Bob's public key when Alice requests it:
    1. The substituted key would need to appear in the KT log
    2. Bob's Privex client (any device) periodically checks the KT log
    3. Bob sees: a key bundle in the log that doesn't match what his device has
    4. Bob's app raises a "key change detected" alert
    5. Transparent MITM is detectable.
  
  If Privex doesn't put the substitute key in the log:
    Alice requests Bob's key.
    Alice's client checks: "Is this key bundle in the KT log?"
    If NO: Alice's client rejects the key and raises an alert.
    
  Either way: MITM is detected.

Log root distribution:
  KT log root hash published every 10 minutes, signed by Privex's signing key.
  Published at: https://kt.privex.dpdns.org/v1/root (also via Nym-based fetch)
  Signed with: Ed25519 + Dilithium3 (hybrid, same as user identity)
  
  Log root also committed to a public blockchain (Ethereum or Solana)
  for additional tamper-evidence independent of Privex infrastructure.

Client behavior:
  On fetching a peer's key bundle: verify inclusion proof against KT log root.
  Periodically: fetch own key bundle from server, verify matches local keys.
  On mismatch: ALERT (possible MITM or account compromise).

Key fingerprints:
  Every conversation shows a "safety code" = first 8 bytes of SHA-256(both parties' IK public keys)
  Users can compare codes out-of-band (QR scan, read aloud) to verify no MITM.
  Displayed prominently. Explanations in plain language.
```

### 8.3 Database Schema

```sql
-- =============================================================
-- KEY DIRECTORY
-- =============================================================
CREATE TABLE key_directory (
  user_id         CHAR(32) PRIMARY KEY,        -- px_[32hex]
  ik_ed25519      BYTEA     NOT NULL,           -- Ed25519 identity key pub
  ik_dilithium3   BYTEA     NOT NULL,           -- Dilithium3 identity key pub
  spk_x25519      BYTEA     NOT NULL,           -- Signed prekey pub
  spk_sig_ed      BYTEA     NOT NULL,           -- SPK signed by IK_ed
  spk_sig_dil     BYTEA     NOT NULL,           -- SPK signed by IK_dil
  kyber1024_pub   BYTEA     NOT NULL,           -- KEM public key
  spk_created_at  INTEGER   NOT NULL,           -- Unix timestamp (rotation tracking)
  created_at      INTEGER   NOT NULL
  -- NO: ip_address, phone, email, name, last_seen, device_info
);

CREATE TABLE one_time_prekeys (
  user_id         CHAR(32) REFERENCES key_directory(user_id) ON DELETE CASCADE,
  opk_id          INTEGER  NOT NULL,
  opk_x25519_pub  BYTEA    NOT NULL,
  PRIMARY KEY (user_id, opk_id)
);

-- =============================================================
-- KEY TRANSPARENCY LOG
-- =============================================================
CREATE UNLOGGED TABLE kt_log (  -- UNLOGGED: no WAL writes for this table
  seq             BIGSERIAL PRIMARY KEY,
  user_id         CHAR(32)  NOT NULL,
  bundle_hash     CHAR(64)  NOT NULL,   -- SHA-256 of full key bundle
  operation       VARCHAR(16) NOT NULL, -- 'register' | 'spk_rotate' | 'opk_replenish'
  timestamp       INTEGER   NOT NULL,
  prev_hash       CHAR(64)              -- Hash of previous entry (chain integrity)
);
-- Root hash computed every 10 minutes from this table and published.

-- =============================================================
-- MESSAGE QUEUE
-- Deleted immediately on delivery. Never kept after ACK.
-- =============================================================
CREATE UNLOGGED TABLE message_queue (  -- UNLOGGED: no WAL writes
  message_id      UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_id    CHAR(32)  NOT NULL,
  content         BYTEA     NOT NULL,   -- Sealed Sender encrypted blob
  csam_proof      BYTEA,                -- ZK proof (image messages only)
  queued_at       INTEGER   NOT NULL,
  expires_at      INTEGER   NOT NULL,   -- queued_at + TTL (default 30 days, max 60 days)
  size_bytes      INTEGER   NOT NULL
  -- NO: sender_id, message_type, read_status
  -- expires_at is set by server based on: MIN(account_default_ttl, per_message_ttl)
  -- account_default_ttl: 30 days (default), 60 days (user opt-in)
  -- per_message_ttl: set per-message by sender, passed in /messages/send body
);
CREATE INDEX idx_queue_recipient ON message_queue(recipient_id);
CREATE INDEX idx_queue_expires ON message_queue(expires_at);  -- For efficient expiry cleanup

-- =============================================================
-- BLOB STORE INDEX
-- Content stored in object store (MinIO). This is just the index.
-- =============================================================
CREATE UNLOGGED TABLE blob_index (
  chunk_id        CHAR(64)  PRIMARY KEY,  -- SHA-256 of encrypted chunk
  storage_path    TEXT      NOT NULL,
  size_bytes      INTEGER   NOT NULL,
  expires_at      INTEGER   NOT NULL,     -- now + 7 days
  downloaded      BOOLEAN   NOT NULL DEFAULT FALSE
  -- NO: owner, uploader, filename, mime type, content type
);

-- =============================================================
-- MLS GROUP STATE (encrypted, server cannot read)
-- =============================================================
CREATE UNLOGGED TABLE group_state (
  group_id        CHAR(64)  PRIMARY KEY,
  epoch           INTEGER   NOT NULL DEFAULT 0,
  encrypted_state BYTEA     NOT NULL,    -- AES-256-GCM, key held by group members
  member_count    SMALLINT  NOT NULL,
  updated_at      INTEGER   NOT NULL
);

-- =============================================================
-- OPAQUE RECORDS (opt-in account recovery via OPAQUE protocol)
-- Row exists = password recovery enabled. Row absent = password recovery off.
-- Server stores OPRF record + encrypted key envelope.
-- Server CANNOT decrypt envelope without user's password.
-- If DB + OPRF key are both stolen, the row is offline-password-guessable.
-- =============================================================
CREATE TABLE opaque_records (
  user_id         CHAR(32)  PRIMARY KEY REFERENCES key_directory(user_id),
  oprf_record     BYTEA     NOT NULL,   -- OPAQUE server OPRF record (blinded)
  envelope        BYTEA     NOT NULL,   -- Encrypted key material (unreadable to server)
  envelope_mac    BYTEA     NOT NULL,   -- Auth tag for envelope integrity
  created_at      INTEGER   NOT NULL,
  updated_at      INTEGER   NOT NULL    -- Updated on password change
  -- NO: password, password hash, any function of the password
);

-- =============================================================
-- SHAMIR RECOVERY SHARES (encrypted to contact public keys)
-- =============================================================
CREATE TABLE recovery_shares (
  user_id         CHAR(32)  NOT NULL REFERENCES key_directory(user_id),
  share_index     SMALLINT  NOT NULL,  -- 0, 1, or 2
  encrypted_share BYTEA     NOT NULL,  -- XChaCha20-Poly1305(contact_IK, share)
  -- Note: contact px_ids NOT stored here ‚Ä" user knows who their contacts are
  PRIMARY KEY (user_id, share_index)
);

-- =============================================================
-- RELAY NODES
-- =============================================================
CREATE TABLE relay_nodes (
  node_id         CHAR(32)  PRIMARY KEY,
  pubkey          BYTEA     NOT NULL,
  address         TEXT      NOT NULL,   -- IP:Port
  region          VARCHAR(16),
  jurisdiction    VARCHAR(64),          -- Country of operation
  operator        VARCHAR(64),          -- Privex | volunteer_id_hash
  is_bridge       BOOLEAN   NOT NULL DEFAULT FALSE,
  last_seen       INTEGER   NOT NULL
);

-- =============================================================
-- PROOF-OF-WORK REGISTRATION TOKENS
-- Active implementation is Redis-only:
--   pow:challenge:{uuid} -> { challenge, difficulty, issued_at_ms, used=false }
--   reg:challenge_rate:{minute}, reg:window:{minute}, reg:suspicion
-- No Postgres row is required for live PoW registration. This avoids WAL/disk
-- traces for short-lived registration pressure state.
-- =============================================================

-- =============================================================
-- SERVER-SIDE HISTORY BACKUP (OPT-IN ONLY)
-- Encrypted with user's history_key (derived from OPAQUE master seed).
-- Server stores random-looking blobs. Cannot decrypt. Cannot read.
-- User can delete all rows at any time. Not created by default.
-- =============================================================
CREATE UNLOGGED TABLE history_blobs (  -- UNLOGGED: no WAL trace
  blob_id         UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         CHAR(32)  NOT NULL REFERENCES key_directory(user_id) ON DELETE CASCADE,
  encrypted_blob  BYTEA     NOT NULL,   -- AES-256-GCM(history_key, plaintext || msg_id)
  stored_at       INTEGER   NOT NULL
  -- NO: message content, sender, recipient, conversation_id, message_type
  -- Server cannot determine: what was said, to whom, or when
);
CREATE INDEX idx_history_user ON history_blobs(user_id, stored_at);

-- =============================================================
-- HISTORY BACKUP SETTINGS (tracks opt-in per user)
-- =============================================================
CREATE TABLE history_backup_settings (
  user_id         CHAR(32)  PRIMARY KEY REFERENCES key_directory(user_id),
  enabled         BOOLEAN   NOT NULL DEFAULT FALSE,  -- Opt-in, default OFF
  enabled_at      INTEGER,
  ttl_days        SMALLINT  NOT NULL DEFAULT 30,     -- User's message queue TTL preference
  extended_ttl    BOOLEAN   NOT NULL DEFAULT FALSE   -- If true: ttl_days = 60
);

-- =============================================================
-- DEVICE SYNC REGISTRY (linked devices per identity)
-- =============================================================
CREATE UNLOGGED TABLE linked_devices (
  user_id         CHAR(32)  NOT NULL REFERENCES key_directory(user_id),
  device_id       CHAR(32)  NOT NULL,    -- Random device identifier
  device_pubkey   BYTEA     NOT NULL,    -- Device's ephemeral sync public key
  linked_at       INTEGER   NOT NULL,
  last_seen       INTEGER   NOT NULL,
  PRIMARY KEY (user_id, device_id)
  -- NO: device model, OS, IP, location
);
```

### 8.4 True No-Log Infrastructure

"No logs" in Privex means logs are architecturally eliminated at every layer, not just application-level.

```
APPLICATION LAYER:
  Rust/Axum:
    No access log middleware installed. Not "disabled" ‚Ä" not compiled in.
    Error logs: structured JSON, content field scrubbed of any user_id or request body.
    Pattern: if error.context contains user_data ‚Ü' log "REDACTED"
  
  WebSocket:
    Connection events: not logged. Connection count (integer) logged for monitoring only.
    Message events: not logged.

DATABASE LAYER:
  PostgreSQL:
    wal_level = minimal   // Minimum WAL for crash recovery only
    archive_mode = off    // No WAL archiving
    
    Critical tables (message_queue, blob_index, kt_log) use UNLOGGED:
      UNLOGGED tables skip WAL entirely. Rows written to these tables
      leave NO trace in WAL. On crash, these tables are truncated
      (acceptable ‚Ä" messages are re-delivered via client retry).
    
    max_wal_size = 64MB   // Small WAL, frequent checkpoints, short retention
    checkpoint_timeout = 5min

  Redis:
    save ""              // No RDB snapshots ‚Ä" never touch disk
    appendonly no        // No AOF ‚Ä" in-memory only
    maxmemory-policy allkeys-lru  // Evict old data rather than write to disk

OPERATING SYSTEM LAYER:
  Filesystem:
    /var/log mounted as tmpfs (RAM disk). Log files exist only in RAM.
    On system reboot: all logs vanish. No disk write.
    
    Server root volume: dm-crypt (LUKS2, AES-256-XTS) at rest.
    MinIO volume: dm-crypt separately keyed.
    
  Swap: swapoff -a. No swap partition. Prevents sensitive data from touching disk.
  
  /proc/net/tcp: Only accessible to root. Application runs as unprivileged user.
    Cannot read network connection tables even if app is compromised.

KUBERNETES / CONTAINER LAYER:
  Audit logging: disabled for API server. Or filtered to exclude pod/container metadata.
  Container stdout/stderr: piped to /dev/null. Not to a logging service.
  Pod security context: readOnlyRootFilesystem: true. No writes to container FS.
  Resource limits: strict CPU/memory limits prevent data exfiltration via side channel.

REVERSE PROXY (Caddy):
  Caddyfile:
    {
      log {
        output discard   // Caddy's equivalent of access_log off
      }
    }
  No access log. Not "rotated and deleted" ‚Ä" never created.

NETWORK LAYER (NIC level):
  Server network interfaces NOT configured for promiscuous mode.
  tcpdump / wireshark NOT installed on production servers.
  iptables rules: log targets NOT used. DROP rules only, never LOG.
```

### 8.5 Proof-of-Work Registration

Replaces IP-based registration rate limiting. No IP address, email, phone number, account cookie, or authentication state is needed or recorded to slow account creation.

```
PROBLEM WITH IP RATE LIMITING:
  The one IP-linked endpoint (registration) correlates a real IP
  to a new Privex identity ‚Ä" the moment of maximum exposure.

  Even with Nym routing active: the exit gateway's IP appears.
  With Nym: fine. Without Nym (direct connection during setup): real IP exposed.

PROOF-OF-WORK SOLUTION:
  Require clients to solve a hashcash-style SHA-256 puzzle before registration.
  Difficulty is dynamic and stored in Redis aggregate counters only.
  This makes bot registration computationally expensive without IP correlation.

PRIVACY INVARIANTS:
  - No IP, user_id, email, phone, device id, browser fingerprint, or cookie key.
  - PoW Redis keys are aggregate counters or random challenge IDs only.
  - Suspicion is aggregate timing pressure, not a per-user or per-device score.
  - No normal-state heartbeat logs. Only elevated aggregate pressure/suspicion
    events are logged, with no user/request/network identifiers.

REDIS KEYS:
  pow:challenge:{uuid}
    { challenge, difficulty, issued_at_ms, used=false }
    TTL: 30 minutes. Consumed with GETDEL during registration.

  reg:challenge_rate:{unix_minute}
    Aggregate challenge requests. TTL: 5 minutes.

  reg:window:{unix_minute}
    Aggregate successful PoW-gated registrations. TTL: 5 minutes.

  reg:suspicion
    Aggregate suspiciously-fast solve score. TTL: 1 hour.

DIFFICULTY CALCULATION:
  recent registrations = sum(reg:window for current minute and previous 2)
  recent challenges    = sum(reg:challenge_rate for current minute and previous 2)

  registration base:
    0..5       ‚Ü' 22
    6..15      ‚Ü' 23
    16..40     ‚Ü' 25
    41..100    ‚Ü' 27
    101..300   ‚Ü' 29
    301+       ‚Ü' 31

  challenge-request base:
    0..30      ‚Ü' 22
    31..100    ‚Ü' 23
    101..300   ‚Ü' 25
    301..1000  ‚Ü' 27
    1001..3000 ‚Ü' 29
    3001+      ‚Ü' 31

  suspicion bonus:
    0..10      ‚Ü' +0
    11..30     ‚Ü' +1
    31..60     ‚Ü' +2
    61+        ‚Ü' +3

  final difficulty = min(max(registration_base, challenge_base) + suspicion_bonus, 31)

FLOW:
  1. POST /auth/pow_challenge
     Server records reg:challenge_rate:{minute}, computes current difficulty,
     stores pow:challenge:{uuid}, and returns:
       { challenge_id, challenge: bytes(32), difficulty, expires_at }

  2. Client solves:
     nonce = 0
     loop:
       candidate = SHA-256(challenge || nonce)
       if leading_zeros(candidate) >= difficulty: break
       nonce++

  3. POST /keys/register with:
     { public_keys, pow: { challenge_id, nonce, solution_hash } }

  4. Server verifies:
     a. challenge_id exists and not expired
     b. challenge is consumed with Redis GETDEL (single-use)
     c. SHA-256(challenge || nonce) has >= challenge.difficulty leading zero bits
     d. solve_time_ms is compared to a conservative browser minimum
     e. too-fast valid math is not rejected; it increments reg:suspicion
     f. successful registration increments reg:window:{minute}
     g. proceed with registration. No IP recorded.
     h. OPAQUE password recovery is not part of registration; it is an
        authenticated opt-in setup after signup or from Settings.

  Invalid submissions consume their challenge too. This prevents one challenge
  from being reused as a server-side verification oracle or CPU/Redis work loop.

BACKGROUND DIFFICULTY MANAGER:
  Every 30 seconds:
    - one app server acquires a Redis tick lock
    - recomputes aggregate difficulty state
    - if recent registrations < 5, decrements reg:suspicion by 1
    - clamps suspicion decay at zero
    - emits no normal heartbeat log
    - logs only elevated aggregate pressure/suspicion transitions:
      severity = warn | high | critical
      event = registration_pressure or suspicious_pow_solve
      fields = difficulty, base, registration_base, challenge_base,
               suspicion_bonus, suspicion, recent_registrations,
               recent_challenges
```

#### 8.5.1 Global Launch Limitations And Required Hardening

The Redis dynamic PoW layer is a privacy-preserving pressure valve, not a complete Sybil-proof identity system. It deliberately avoids the strongest traditional anti-abuse signals because those signals identify people.

```
LIMITATIONS:
  1. SHA-256 PoW is parallelizable.
     Botnets, GPUs, and ASICs can buy more attempts. Dynamic difficulty raises
     cost globally but does not prove a human is behind the registration.

  2. Challenge flooding still creates server/Redis work.
     reg:challenge_rate raises difficulty during a spike, but each challenge
     request still costs randomness, Redis writes, and a short-lived key.

  3. No per-IP throttling means no per-network fairness.
     This is intentional for privacy. Abuse defense must be aggregate,
     cryptographic, or client-compute based.

  4. Redis is the coordination point.
     All production app servers that issue registration challenges must share
     the same Redis/Redis Cluster counters, or difficulty becomes per-node and
     attackers can spread load across nodes.

  5. Multi-region launch needs explicit coordination.
     Independent regional Redis shards reduce latency but weaken global pressure.
     Use either one globally-coordinated counter service, or combine regional
     difficulty with a privacy-preserving global aggregate.

  6. Redis restart resets pressure.
     Redis is intentionally no-persistence. A restart deletes active challenges
     and recent counters, briefly returning difficulty to baseline. This is an
     availability/privacy tradeoff; do not enable Redis disk persistence just to
     remember abuse counters.

  7. Root compromise can tamper with the control loop.
     Root on the app/Redis host can lower difficulty, delete counters, mint
     challenges, or alter code. No same-host software rate limiter fully survives
     root. Mitigate with least privilege, separate Redis host, immutable deploys,
     reproducible builds, audited releases, and eventually enclave/HSM/threshold
     protection for high-value server secrets.

  8. System clock quality matters.
     solve_time_ms uses server issue/verify timestamps. NTP drift or clock jumps
     can create false suspicion. Use disciplined time sync and alert on clock
     anomalies without logging client identity.

  9. Aggregate telemetry only.
     Operators may monitor aggregate difficulty, challenge count, registration
     count, Redis memory, and suspicion. Do not add high-cardinality labels,
     request logs, IP labels, user_id labels, or device labels.

REQUIRED BEFORE GLOBAL PUBLIC LAUNCH:
  - Run all registration nodes against one shared Redis Cluster or a consciously
    designed regional+global aggregate.
  - Set Redis maxmemory and an eviction policy suitable for short-lived challenge
    keys; alert on aggregate challenge-key cardinality and memory pressure.
  - Keep Redis persistence disabled: save "" and appendonly no.
  - Keep Caddy/server access logs disabled. DDoS tooling must not create durable
    IP logs or per-user reputation databases.
  - Add Layer 2 Argon2id hybrid PoW before serious public exposure to reduce
    GPU/ASIC advantage.
  - Treat difficulty=31 as the SHA-256 Layer 1 ceiling. If attacks continue at
    that ceiling, do not keep raising SHA-256; deploy the memory-hard layer.
  - Test fail-closed behavior: Redis unavailable should stop new registrations
    rather than silently dropping to free registration.
```

---

## 9. Web Application Architecture

The web application is the primary Privex platform. It runs entirely in the browser ‚Ä" no installation required. Crypto operations run in WebAssembly. The app is installable as a Progressive Web App (PWA).

### 9.1 Technology Foundation

```
Framework:          React 18 + TypeScript 5.x (strict mode)
Build Tool:         Vite 5.x (fast dev server, optimized production builds)
Crypto:             WebAssembly modules (libsodium-wasm, libsignal-client WASM)
State Management:   Zustand 4.x (minimal, predictable, no proxy magic)
Local Storage:      IndexedDB (via Dexie.js ORM) + Web Crypto API for key storage
Service Worker:     Workbox 7.x (offline support, background sync, push handling)
WebRTC:             Browser native (no library needed ‚Ä" fully supported in all modern browsers)
Nym Transport:      @nymproject/sdk-full-fat (WASM bundle, browser-compatible)
PWA:                Web App Manifest + Service Worker = installable without App Store
Routing:            React Router 6 (hash-based routing for static deployment compatibility)
Styling:            Tailwind CSS 3.x (utility-first, no runtime JS)
```

### 9.2 WebAssembly Crypto Layer

```
Browser crypto constraint: JavaScript has no direct access to Secure Enclave or HSM.
Solution: WebCrypto API for hardware-backed key storage + WASM for crypto operations.

KEY STORAGE MODEL (Browser):

Tier 1 ‚Ä" Non-extractable WebCrypto keys (most secure in browser context):
  const masterKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,  // extractable: false ‚Ä" key cannot be read by any JavaScript
    ["encrypt", "decrypt"]
  );
  // On Chrome/Edge: backed by OS keychain (Windows Credential Store, macOS Keychain)
  // On Firefox: backed by NSS key database
  // Cannot be exported. Cannot be read even by Privex's own JavaScript.

Tier 2 ‚Ä" IndexedDB encrypted storage:
  Double Ratchet ratchet state, MLS group state, contact list:
  Stored in IndexedDB, encrypted with Tier 1 masterKey using AES-GCM.
  Schema:
    contacts:  { px_id, display_name, verified_fingerprint, trust_level }
    sessions:  { session_id, peer_px_id, ratchet_state_enc }
    messages:  { msg_id, session_id, content_enc, timestamp, status }
    groups:    { group_id, name_enc, mls_state_enc, epoch }
    keys:      { key_id, key_type, key_bytes_enc }  // for non-WebCrypto key material

WASM CRYPTO MODULE (@privex/crypto-wasm):
  // Compiled from Rust (libsodium-sys + libsignal-protocol-rust + liboqs-sys + openmls)
  // to WASM via wasm-pack + wasm-bindgen
  
  Exports (called from TypeScript):
    generate_identity_keypairs()    ‚Ü' { ed25519_pub, dilithium3_pub, ... }
    pqxdh_initiate(their_bundle)    ‚Ü' { shared_secret, pq_ciphertext }
    pqxdh_respond(their_ek, my_keys) ‚Ü' shared_secret
    ratchet_encrypt(state, plaintext) ‚Ü' { ciphertext, new_state }
    ratchet_decrypt(state, message)   ‚Ü' { plaintext, new_state }
    mls_create_group(params)         ‚Ü' group_state
    mls_add_member(state, kp)        ‚Ü' { commit, welcome, new_state }
    mls_encrypt(state, plaintext)    ‚Ü' ciphertext
    mls_decrypt(state, ciphertext)   ‚Ü' plaintext
    pdq_hash(image_data)             ‚Ü' hash_bytes
    psi_blind(hash)                  ‚Ü' { blinded, r }
    psi_unblind(blinded_eval, r)     ‚Ü' result
    opaque_register(password, keys)  ‚Ü' { oprf_request, client_state }
    opaque_login(password, response) ‚Ü' { export_key, auth_message }
    shamir_split(secret, t, n)       ‚Ü' shares[]
    shamir_reconstruct(shares[])     ‚Ü' secret
    pow_solve(challenge, difficulty) ‚Ü' nonce
    
    // Receipt system (Section 4.10)
    receipt_generate_token() ‚Ü' Uint8Array            // 32 random bytes, stored locally by sender
    receipt_create(token_id, type) ‚Ü' Uint8Array      // Sealed sender payload for receipt message
    
    // History backup (Section 4.11, opt-in only)
    history_key_derive(master_seed) ‚Ü' Uint8Array     // HKDF(master_seed, "privex_history_backup_v1")
    history_encrypt(history_key, plaintext, msg_id) ‚Ü' Uint8Array  // AES-256-GCM blob
    history_decrypt(history_key, blob) ‚Ü' Uint8Array               // Decrypt history blob
    
    // Time verification (Section 9.6)
    time_verify(server_timestamp, server_sig, server_pub, tolerance_secs) ‚Ü' boolean
    // Returns true if server_timestamp is within tolerance_secs of local clock
    // AND server_sig is a valid Ed25519 signature over the timestamp
    
  Memory management:
    All WASM memory containing key material is explicitly zeroed after use:
    wasm_memory.fill(0, ptr, len)  // Explicit zero-fill before deallocation
    Prevents key material from lingering in JS garbage collector
```

### 9.3 Service Worker Architecture

```
Service Worker: /sw.js (registered at app root)

Responsibilities:
  1. OFFLINE SUPPORT:
     Cache app shell (HTML, CSS, JS bundles, WASM modules) on install.
     Serve from cache when network unavailable.
     Crypto operations work offline (no network needed for encryption).
     
  2. BACKGROUND SYNC:
     When network returns after offline period:
     navigator.serviceWorker.ready.then(sw => {
       sw.sync.register('sync-pending-messages');
     });
     SW processes pending outbound message queue on reconnect.
     
  3. PERSISTENT WEBSOCKET (desktop browsers):
     Service Worker maintains a WebSocket connection to Nym network
     even when the main browser tab is not focused.
     Receives incoming messages, stores in IndexedDB, shows notification.
     Main tab reads from IndexedDB on focus.
     
  4. PUSH HANDLING:
     self.addEventListener('push', async (event) => {
       // Push payload is a Privex wake token (random bytes, no user data)
       // On receive: establish WebSocket, fetch pending messages via Nym
       const messages = await fetchPendingMessages();
       // Show OS notification (content from decrypted message, never from push)
       await self.registration.showNotification(
         'New message',
         { body: '...', data: { message_id } }
       );
     });
     
  5. CRYPTO WORKER:
     Heavy WASM operations run in a SharedWorker (separate thread):
     - ZK proof generation for CSAM
     - PQXDH key exchange
     - Large file encryption
     Main thread stays responsive. User sees progress indicators.
```

### 9.4 Progressive Web App (PWA)

```
Web App Manifest (/manifest.json):
  {
    "name": "Privex",
    "short_name": "Privex",
    "description": "True zero-knowledge private communication",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0a0a0a",
    "theme_color": "#0a0a0a",
    "icons": [
      { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
      { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" },
      { "src": "/icon-maskable.png", "sizes": "512x512", "purpose": "maskable" }
    ],
    "screenshots": [],
    "categories": ["communication", "security"],
    "share_target": { ... }  // Handle OS-level share to Privex
  }

Installation flow:
  Android Chrome: Browser shows "Add to Home Screen" prompt after 2 visits.
  iOS Safari: User manually: Share ‚Ü' Add to Home Screen.
  Desktop Chrome/Edge: Install icon in address bar.
  
PWA vs native app:
  Advantages: No app store approval, no Google/Apple reviewing the binary,
              instant updates without app store submission,
              same codebase as the web app.
  Disadvantages: iOS PWA has limited background processing, no APNs alternative.
  Plan: PWA for Phase 1 (web), native apps (Phase 2-3) for full mobile capability.
```

### 9.5 Web Security Hardening

```
Content Security Policy (strict):
  Content-Security-Policy:
    default-src 'none';
    script-src 'self' 'wasm-unsafe-eval';   // Allow WASM only, no inline JS
    connect-src 'self' wss://nym-gateway-*.privex.dpdns.org;  // Only Nym WebSocket
    img-src 'self' blob: data:;
    style-src 'self';
    font-src 'self';
    worker-src 'self';
    frame-ancestors 'none';                 // Prevents clickjacking
    upgrade-insecure-requests;

HTTP Security Headers:
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=()  // Prompt only when used
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp  // Required for SharedArrayBuffer (WASM threads)

Subresource Integrity (SRI):
  All script and CSS tags include integrity="sha384-[hash]" attribute.
  Browser refuses to load if hash doesn't match.
  Protects against CDN compromise injecting malicious code.

Certificate Pinning (for WebSocket connections):
  Service Worker implements certificate pinning:
    On WebSocket connect, verify server's TLS certificate against
    pinned public key fingerprints (maintained in a signed config file).
    Reject connection if mismatch. Alerts user.
```

### 9.6 Time Synchronization & Desync Attack Prevention

#### The Problem

Message timestamps in Privex are generated client-side. This is correct for privacy ‚Ä" the server never needs to know when a message was sent. But it creates two risks:

```
RISK 1 ‚Ä" Device clock drift:
  If Bob's device clock is wrong by ¬±30 minutes, messages appear out of order
  in Alice's conversation view. Frustrating but not a security issue.

RISK 2 ‚Ä" Time desync attack:
  A malicious actor who controls a device could deliberately set the clock
  far in the future to make messages appear as if they were sent at a
  different time, confusing forensic timelines or bypassing TTL enforcement.

RISK 3 ‚Ä" Geographic metadata leakage:
  Using a third-party NTP server to sync time reveals the client's IP
  to that NTP server. Privex cannot use public NTP for privacy reasons.
  Using system time alone is unreliable.
```

#### Solution: Cryptographic Time Anchor

```
Privex uses a hybrid approach:
  1. Server provides signed timestamps on every WebSocket message and API response
  2. Client verifies the server timestamp against local clock
  3. If drift exceeds ¬±90 seconds: client shows warning, uses server time anchor
  4. No external time server contacted. No IP leakage.

SERVER-SIDE (every WebSocket message includes):
  {
    "type": "message",
    "content": "...",
    "queued_at": unix_timestamp,   // when the message ARRIVED at the server
    "server_ts": unix_timestamp,   // when THIS delivery happened (‚âà now)
    "server_ts_sig": Ed25519_sign(be64(server_ts) || be64(queued_at) || message_id,
                                  time_signing_key)
  }

  Two timestamps under one signature (implementation refinement): server_ts is
  what the client compares its clock against ‚Ä" valid even for a message that sat
  queued for days; queued_at is the ordering anchor ‚Ä" an offline backlog must
  sort by arrival, not by delivery.

  time_signing_key:   A dedicated Ed25519 keypair for timestamp signing
                      (TIME_SIGNING_KEY env; separate from KT + session keys).
                      Public key pinned in the client binary (like a CA cert).
                      Rotated annually, announced via KT log.

CLIENT-SIDE verification (wasm_verify_server_time):
  1. Receive server_ts and server_ts_sig
  2. Verify: Ed25519_verify(server_ts || message_id, server_ts_sig, pinned_pub_key) == true
     If false: reject the message (replay or forged timestamp)
  3. Check: |local_clock - server_ts| <= 90 seconds
     If within range: trust local clock for message timestamps
     If outside range: display warning "Your device clock may be incorrect"
                       Use server_ts as the authoritative timestamp for this message
                       Do NOT silently correct the clock (user may be in a restricted environment
                       where clock manipulation is a known attack vector)

MESSAGE TIMESTAMPS:
  Stored in IndexedDB as: { client_ts: local_time, server_anchor: server_ts }
  Displayed to user: client_ts (their local time, familiar)
  Used for ordering: server_anchor (prevents ordering attacks)
  Neither timestamp is sent to the server or visible to it.

WHAT THIS PREVENTS:
  - Time desync attacks: server signature required, cannot forge
  - Clock drift confusion: server anchor corrects ordering
  - NTP IP leakage: no external time server, server is the only time source

WHAT THIS DOES NOT PREVENT:
  - A compromised server lying about its own timestamp
    (Mitigation: client logs server_anchor values; sudden jumps are detectable)
  - A device with malware deliberately manipulating timestamps before WASM sees them
    (Out of scope: kernel-level compromise)

NO GEOGRAPHIC METADATA LEAKAGE:
  The server timestamp is delivered over the existing authenticated WebSocket connection.
  No additional network requests are made for time synchronization.
  No IP addresses exposed beyond what the existing connection already reveals.
```


---

## 10. Mobile & Desktop Clients

### 10.1 Android (Phase 2)

```
Framework:     React Native 0.74+ (shared components with web where possible)
Language:      TypeScript 5.x (strict)
Native Crypto: JNI bridge to Rust crypto library (same WASM code compiled to native ARM)
Notifications: UnifiedPush (default, FCM-free)
               FCM (opt-in, for users who prefer convenience)
Key Storage:   Android Keystore (hardware-backed on Android 6+)
               Keys generated in hardware, marked non-exportable
               Access requires user authentication (biometric / PIN)
Local DB:      SQLite + SQLCipher (AES-256, key from Android Keystore)
WebRTC:        react-native-webrtc

Nym integration:
  @nymproject/sdk provides React Native bindings.
  All message transport via Nym by default.

Background:
  Foreground Service for active calls.
  WorkManager for background message sync.
  UnifiedPush for wake-on-message.
```

### 10.2 iOS (Phase 3)

```
Framework:     React Native 0.74+
Notifications: VoIP push (CallKit) + Background App Refresh
               Silent push (content-available: 1) for message wake
               APNs privacy limitation: acknowledged, documented in threat model
               APNs payload: zero-byte wake token only. No content. No sender.
Key Storage:   iOS Secure Enclave (available on iPhone 5S+, all modern devices)
               Keys generated in Secure Enclave, marked permanent + non-exportable
               Access: biometric (Face ID / Touch ID) + device passcode
Local DB:      SQLite + SQLCipher (key from Secure Enclave via CommonCrypto)
WebRTC:        react-native-webrtc + CallKit for system call UI integration

Screen security:
  UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch()
  Blurs app preview in app switcher. Standard for secure messaging apps.
```

### 10.3 Desktop ‚Ä" Tauri (Phase 4)

```
Framework:     Tauri 2.x (Rust backend, React frontend)
Why Tauri:     Memory-safe Rust backend for all crypto. No Chromium bundled.
               ~8MB binary vs ~150MB for Electron. OS-level security APIs.
               Tauri IPC: typed commands only, no arbitrary JS eval.

Rust Backend (src-tauri/):
  crypto.rs:   libsodium-sys, libsignal-protocol-rust, liboqs-sys, openmls
  network.rs:  nym-sdk (Rust client), onion routing client, webrtc.rs
  storage.rs:  rusqlite + SQLCipher, keyring-rs (OS keychain)
  
Key Storage:   macOS Keychain (SecItemAdd / SecItemCopyMatching)
               Windows Credential Manager (CredWrite / CredRead)
               Linux: libsecret (GNOME Keyring) / KWallet
               via keyring-rs crate (safe, cross-platform abstraction)

No automatic updates silently modifying binaries.
Update verification: Ed25519 + Dilithium3 signed update manifest, verified before install.
```

---

## 11. API Specification

### Base URL

`https://api.privex.dpdns.org/v1` (accessed only via Nym mixnet or onion routing ‚Ä" never directly in production)

All requests authenticated via `X-Privex-Auth: [session_token]` header, except where noted.

### Authentication Endpoints

```
POST /auth/challenge
  Auth:     None
  Body:     { user_id: "px_[hex]" }
  Response: { challenge: "[32 bytes hex]", expires_at: unix_ts }
  Notes:    Challenge single-use, 90s TTL, stored in Redis.

POST /auth/verify
  Auth:     None
  Body:     { user_id, challenge, sig_ed: "[hex]", sig_dil: "[hex]", timestamp }
  Response: { session_token: "[base64url]", expires_at: unix_ts }
  Notes:    Verifies BOTH Ed25519 and Dilithium3 signatures.
            24-hour session tokens. Background renewal at T-2 hours.

POST /auth/pow_challenge
  Auth:     None
  Response: { challenge_id, challenge: "[32 bytes hex]", difficulty, expires_at }
  Notes:    Difficulty is dynamic. Challenge state is Redis-only, single-use,
            and expires after 30 minutes. Challenge requests increment only an
            aggregate Redis counter.

POST /keys/register
  Auth:     None (uses PoW instead of session)
  Body:     {
              user_id, ik_ed25519_pub, ik_dilithium3_pub, ik_x25519_pub,
              spk_x25519_pub, spk_sig_ed, spk_sig_dil, kyber1024_pub,
              opks: ["[hex]"...],
              pow: { challenge_id, nonce, solution_hash }
            }
  Response: { registered: true }
  Notes:    No IP recorded. No IP rate-limiting. Verifies and consumes a Redis
            PoW challenge before expensive key validation. Invalid attempts also
            consume the challenge. Appends entry to KT log. Initial OPK batch is
            bounded server-side.
```

### Key Management Endpoints

```
POST /keys/{user_id}
  Auth:     None ‚Ä" PoW instead. Body carries a solved single-use PoW challenge.
  Body:     { pow: { challenge_id, nonce, solution_hash } }
  Response: {
              user_id, ik_ed25519, ik_dilithium3, ik_x25519, spk_x25519,
              spk_sig_ed, spk_sig_dil, kyber1024_pub,
              opk: "[one-time prekey, server deletes after serving]",
              kt_proof: { leaf, path, root, root_sig_ed, timestamp }
            }
  Notes:    POST (not GET) so the PoW proof rides the body. The fetch is the only
            account-existence + OPK-consume signal, so it is PoW-gated: each probe
            costs a solve and a flood drives global difficulty up (no IP/identity
            rate limit, preserving zero-knowledge). The auto-add-back path makes NO
            server call ‚Ä" it learns the peer key from the sealed PqxdhInit ‚Ä" so only
            the deliberate adder pays. Returns ONE opk and immediately marks it
            deleted. KT proof lets the client verify the key is in the log.
            A 30/60s per-target cap remains as defense in depth behind the PoW.

POST /keys/prekeys/replenish
  Auth:     Session token
  Body:     { opks: ["[hex]"...] }
  Response: { stored: N }
  Notes:    Called automatically by client when OPK count falls below 20.

POST /keys/spk/rotate
  Auth:     Session token
  Body:     { spk_x25519_pub, spk_sig_ed, spk_sig_dil }
  Response: { rotated: true }
  Notes:    Client rotates SPK every 30 ¬± 5 days (randomized).
            Rotation appended to KT log.

POST /keys/kt/proof/{user_id}
  Auth:     None ‚Ä" PoW instead.
  Body:     { pow: { challenge_id, nonce, solution_hash } }
  Response: { leaf, path, root, root_sig_ed, timestamp }
  Notes:    Merkle inclusion proof for periodic key-change re-verification. POST +
            PoW-gated like the bundle fetch (it is the other per-target existence
            oracle: 404 when the user has no KT entry). 30/60s per-target cap behind
            the PoW.
```

### Messaging Endpoints

```
POST /messages/send
  Auth:     Session token
  Body:     {
              recipient_id: "px_[hex]",
              content: "[base64 encrypted sealed sender blob]",
              size_bytes: N,
              ttl_seconds: N,                      // Optional per-message TTL override
                                                   // Server uses MIN(account_ttl, this value)
              csam_proof: "[base64 ZK proof]",    // Required if content contains image
              image_commitment: "[hex]"            // Required if contains image
            }
  Response: { queued: true, message_id: "[uuid]", expires_at: unix_ts }

POST /messages/ack
  Auth:     Session token
  Body:     { message_ids: ["[uuid]"...] }
  Response: { deleted: N }
  Notes:    Server hard-deletes acknowledged messages immediately.
            No read receipts stored. No delivery log.

GET /messages/poll
  Auth:     Session token
  Query:    ?count=10
  Response: { messages: [...], padded_to: 10 }
  Notes:    Returns up to `count` real messages + dummy padding to always equal `count`.
            Used by the fixed polling schedule (Section 5.7, Mitigation 2).
            Dummy items: { type: "dummy", content: [random bytes, same size as real] }
            Client discards dummies. Observer cannot distinguish real from dummy.
            Preferred over WebSocket push for high-security polling mode users.

POST /messages/ttl_preference
  Auth:     Session token
  Body:     { default_ttl_days: 30 | 60 }
  Response: { updated: true }
  Notes:    Sets the user's account-level default TTL for queued messages.
            30 days (default), 60 days (extended, opt-in).
            Stored in history_backup_settings.ttl_days.
```

### History Backup Endpoints (Opt-In Only)

```
POST /history/backup
  Auth:     Session token
  Body:     { blob: "[base64 AES-256-GCM encrypted message blob]" }
  Response: { stored: true, blob_id: "[uuid]" }
  Notes:    Only functional if user has enabled history backup.
            Server stores opaque encrypted bytes. Cannot read content.
            Returns 403 if history backup not enabled for this account.

GET /history/fetch
  Auth:     Session token
  Query:    ?after_blob_id=[uuid]&limit=100
  Response: { blobs: ["[base64]"...], next_cursor: "[uuid]" }
  Notes:    Returns encrypted history blobs in stored_at order.
            Pagination via cursor. Client decrypts each with history_key.
            Used on new device after OPAQUE recovery to restore history.

DELETE /history
  Auth:     Session token
  Response: { deleted: N }
  Notes:    Hard-deletes ALL history blobs for this user_id immediately.
            Cannot be undone. N = number of blobs deleted.
            User confirms this action in the UI before calling.

POST /history/settings
  Auth:     Session token
  Body:     { enabled: true | false }
  Response: { updated: true }
  Notes:    Enable or disable server-side history backup.
            On disable: all history blobs are immediately hard-deleted.
            On enable: future messages are backed up. Past messages are not retroactively added.
```

### Group Endpoints

```
POST /groups/register
  Auth:     Session token
  Body:     { group_id: "[64hex]", member_count: N }
  Response: { created: true }

POST /groups/{group_id}/state
  Auth:     Session token (any group member ‚Ä" verified via ZK group membership proof)
  Body:     { epoch: N, encrypted_state: "[base64]", member_count: N }
  Response: { updated: true }

GET /groups/{group_id}/state
  Auth:     Session token
  Response: { epoch, encrypted_state, member_count, updated_at }
```

### Blob Store Endpoints

```
POST /blobs/{chunk_id}
  Auth:     Session token
  Body:     [raw bytes ‚Ä" AES-256-GCM encrypted chunk]
  Content-Type: application/octet-stream
  Response: { stored: true, expires_at: unix_ts }

GET /blobs/{chunk_id}
  Auth:     Session token
  Response: [raw bytes ‚Ä" encrypted chunk]
  Side effect: marks blob as downloaded, schedules deletion after 24h

DELETE /blobs/{chunk_id}
  Auth:     Session token
  Response: { deleted: true }
```

### Account Recovery Endpoints

```
GET /recovery/opaque/status
  Auth:     Session token
  Response: { enabled: boolean }
  Notes:    Authenticated owner-only. No public recovery-status endpoint exists.

POST /recovery/opaque/register/start
  Auth:     Session token
  Body:     { registration_request: "[hex]" }
  Response: { registration_response: "[hex]" }
  Notes:    Optional OPAQUE setup/change. Rate-limited per user.

POST /recovery/opaque/register/finish
  Auth:     Session token
  Body:     { registration_upload: "[hex]", envelope: "[hex]", envelope_mac: "[hex]" }
  Response: { stored: true }
  Notes:    Upserts the OPAQUE row. Current envelope wire size is fixed to avoid
            enabled/disabled response-size leaks during unauthenticated recovery init.

DELETE /recovery/opaque
  Auth:     Session token
  Response: { enabled: false }
  Notes:    Hard-deletes opaque_records[user_id]. OFF is absence of a row.

POST /recovery/opaque/init
  Auth:     None ‚Ä" PoW instead.
  Body:     { user_id, credential_request: "[hex]", pow: { challenge_id, nonce, solution_hash } }
  Response: { login_id, credential_response: "[hex]", envelope: "[hex]", envelope_mac: "[hex]" }
  Notes:    OPAQUE login flow step 1. PoW-gated: it is an unauthenticated, per-target
            OPRF + Redis write, so a solved challenge is required before any work.
            Missing/disabled records receive a generic dummy response with the same
            envelope/mac wire sizes. 10/60s per-target cap behind the PoW.

POST /recovery/opaque/complete
  Auth:     None
  Body:     { login_id, credential_finalization: "[hex]" }  // From OPAQUE client-side finish
  Response: { session_token: "[base64url]", expires_at }  // Full session on success
  Notes:    login_id is single-use. Completion fails if the OPAQUE row was deleted
            or replaced after init.

GET /recovery/shares/{user_id}
  Auth:     Session token (contact must be authenticated)
  Notes:    Returns encrypted Shamir shares the authenticated user is holding.
            Server doesn't know which users are contacts of whom.
  Response: { shares: [{ index: N, encrypted_share: "[base64]" }] }
  
POST /recovery/shares/store
  Auth:     Session token
  Body:     { shares: [{ index: N, encrypted_share: "[base64]" }] }
  Response: { stored: true }
```

### Rate Limiting

```
Authenticated / pseudonymous limits (NOT per IP):
  The session token is a self-issued pseudonym (HMAC, 24h TTL), NOT an IP/email/
  phone. Limiting by HMAC(token-user) buckets a pseudonym to itself ‚Ä" it builds no
  cross-user graph and stores no PII, so per-user limits here do not weaken ZK.

  POST /messages/send:        120 / 60s per user
  POST /messages/ack:         200 / 60s per user (batch capped at 500 ids)
  POST /blobs/{chunk_id}:     60 / 60s per user (upload)
  GET  /blobs/{chunk_id}:     120 / 60s per user (download)
  DELETE /blobs/{chunk_id}:   60 / 60s per user
  POST /auth/verify:          5 / 60s per user     // Anti-brute-force
  POST /auth/logout_all:      10 / 60s per user
  POST /keys/spk/rotate:      30 / 3600s per user  // KT-log bloat is a GLOBAL cost
  POST /history/blobs:        600 / 60s per user (backfill is bursty)
  GET  /history/blobs:        120 / 60s per user
  GET  /history/status:       120 / 60s per user
  DELETE /history/blobs:      10 / 600s per user
  POST /recovery/shares/store: 10 / 600s per user

PoW-gated public fetches (NO auth, NO IP ‚Ä" the proof IS the limiter):
  These are the only public, TARGET-revealing endpoints; an identity/IP limit would
  leak or fail, so each call must carry a solved single-use PoW (difficulty climbs
  globally under a flood, exactly like registration). A per-target fixed window
  stays behind the PoW as defense in depth.

  POST /keys/{user_id}:             PoW + 30/60s per target  // Anti-enumeration / OPK-drain
  POST /keys/kt/proof/{user_id}:    PoW + 30/60s per target  // Anti-enumeration
  POST /recovery/opaque/init:       PoW + 10/60s per target  // Anti-OPRF-DoS
  POST /recovery/opaque/complete:  120 / 60s global

Registration limits:
  POST /auth/pow_challenge:
    No IP cap and no raw identity key. Issues the challenges that gate BOTH
    registration and the public fetches above.
    Adds to reg:challenge_rate:{minute}; high aggregate challenge pressure
    raises the next challenge difficulty.

  POST /keys/register:
    Requires a valid single-use PoW challenge.
    Any attempt, valid or invalid, consumes the challenge.
    Successful registrations add to reg:window:{minute}; high aggregate
    registration pressure raises future difficulty.

Rate limit state: Redis (in-memory only, no disk persistence).
Per-subject key: HMAC-SHA256(server_key, user_id-or-target) ‚Ä" not raw user_id in Redis.
PoW pressure keys: aggregate counters only.
Fixed-window guard response: HTTP 429, Retry-After header.
PoW pressure response: normally still 200, but with higher returned difficulty.
```

### WebSocket Protocol

```
Endpoint: wss://api.privex.dpdns.org/v1/ws
Auth: X-Privex-Auth header on WebSocket upgrade request.
     (NOT in query string ‚Ä" query strings can appear in server logs)

Server ‚Ü' Client messages:

{ "type": "message",
  "message_id": "[uuid]",
  "content": "[base64 sealed sender blob]",
  "queued_at": unix_ts,     // arrival at the server ‚Ä" the client's ORDERING anchor
  "server_ts": unix_ts,     // time of THIS delivery ‚Ä" the client's clock-drift check
  "server_ts_sig": "[hex]"  // Ed25519(be64(server_ts) || be64(queued_at) || message_id)
                            // with the dedicated TIME_SIGNING_KEY (docs 9.6); the
                            // public half is pinned in the client build
}

{ "type": "prekey_low", "remaining": 12 }
// Triggers client to generate and upload 50 new OPKs

{ "type": "key_change_alert", "user_id": "[px_id]" }
// Key directory detected a key change for a contact. Client should verify.

{ "type": "ping" }

Client ‚Ü' Server messages:

{ "type": "ack", "message_ids": ["[uuid]"...] }
{ "type": "pong" }

Heartbeat: Client sends pong every 30s. Server disconnects after 90s without.
Reconnect: Exponential backoff, Jitter(2^n seconds), max 300s between attempts.
```

---

## 12. Network Architecture

### 12.1 Nym Mixnet Integration

```
Nym Network Components:
  Nym Gateways:   Entry/exit points for Privex users into the Nym network
  Mix Nodes:      3-layer topology. Receives, delays (Poisson), shuffles, forwards
  Validators:     Nym blockchain (Cosmos-based). Not directly involved in message routing.
  
Sphinx Packet Format (used by Nym):
  Fixed size: 2048 bytes. Every packet identical in size. No leakage from size.
  Multi-layer onion encryption. Each mix node decrypts one layer.
  
Privex Nym Integration:
  Privex operates 2+ Nym gateway nodes (alongside community gateways).
  Privex gateway NymID is published in app (verified by signature).
  
  Message flow:
    Client SDK constructs Sphinx packet:
      outer = Sphinx_encrypt(gateway_pub, mix1_pub, mix2_pub, mix3_pub, privex_gateway_pub, payload)
    Client sends to nearest Nym entry gateway via WebSocket.
    Packet traverses 3 mix nodes (Poisson delays: ~50‚Ä"200ms each hop).
    Exits at Privex's Nym gateway.
    Privex gateway strips final Sphinx layer ‚Ü' reveals sealed sender blob ‚Ü' routes to Privex server.
    
Total latency added by Nym: ~300‚Ä"800ms (message delivery).
  Acceptable for chat. Not ideal for calls (handled by onion routing instead).
```

### 12.2 Onion Relay Network

```
Node Minimum (Phase 1): 10 Privex-operated nodes, 5+ jurisdictions:
  - Reykjavik, Iceland (1¬∞ 22' North latitude from Arctic Circle ‚Ä" excellent for cooling too)
  - Geneva, Switzerland
  - Singapore
  - Panama City, Panama
  - Bucharest, Romania
  Rationale: 5 different legal jurisdictions, no MLAT agreement overlap covering all 5.
  A legal order from one jurisdiction cannot simultaneously compel all 5.

Node operator transparency:
  All node public keys published in KT-adjacent log.
  Node operators verified (not anonymous) to prevent Sybil attacks.
  Volunteer nodes (Phase 2): KYC-lite verification (public key pinned to a signed identity).

Circuit lifetime:
  Message routing: Replaced by Nym. Onion circuits reserved for calls and API calls.
  Call circuits: New circuit per call. Torn down on hangup.
  API circuits: Rotated every 10 minutes or 50 requests.

Circuit selection rules:
  1. All 3 nodes from DIFFERENT jurisdictions (legally separated)
  2. No 2 nodes from same operator
  3. For call circuits: prefer geographically close nodes (minimize latency)
  4. Weighted random (higher weight to nodes with better uptime and lower latency)
```

### 12.3 TURN/STUN

```
STUN servers: 2 per region, 4 regions (NA/EU/Asia/Oceania), 8 total.
  Function: Public IP discovery for ICE candidates.
  Logging: None. STUN is connectionless ‚Ä" no persistent state.

TURN servers: 2 per region, 4 regions.
  Software: pion/turn (Go ‚Ä" memory safe, auditable, no C dependencies)
  
  Authentication (ephemeral, no user identity):
    username = UNIX_timestamp + ":" + CSPRNG(8 bytes hex)
    password = HMAC-SHA256(turn_shared_secret, username)
    Valid: 60 seconds from timestamp.
  
  What TURN sees: DTLS-SRTP encrypted streams, further encrypted by SFrame.
    No call content. No caller identity. No callee identity.
  
  TURN configuration:
    no-log = true
    log-file = /dev/null
    stale-nonce = 60
    fingerprint
    lt-cred-mech
    no-software-attribute  // Don't reveal coturn version in STUN responses
    denied-peer-ip: 10.0.0.0-10.255.255.255  // Block RFC1918 (SSRF prevention)
    denied-peer-ip: 127.0.0.0-127.255.255.255
```

### 12.4 Bridge Distribution Network

```
When everything else is blocked (China GFW, Iranian DPI, etc.):

EMBEDDED BRIDGES:
  10 bridge addresses in app binary.
  Stored as: XOR(bridge_data, static_key) ‚Ä" not plaintext strings.
  (Prevents trivial extraction by GFW/Iran scanning app binaries)
  Rotated quarterly via signed app update (update check itself goes through Nym).

OUT-OF-BAND BRIDGE DISTRIBUTION:
  1. Email: bridges@privex.dpdns.org ‚Ü' automated response with bridge list + obfs4 certs.
     Email system uses a separate domain and separate server from main Privex.
     Bridge list is GPG-signed by Privex's public key.
     
  2. Separate domain: https://privex-bridges.net (separate registrar, separate host).
     Fetched via DoH to hide the DNS query.
     
  3. Telegram bot: @PrivexBridgesBot (ironic, but Telegram is less blocked than Privex).
  
  4. In-app: Settings ‚Ü' Bridges ‚Ü' "I can't connect" ‚Ü' app emails bridges@privex.dpdns.org.

BRIDGE PROTOCOL STACK:
  obfs4 (primary): Random-noise obfuscation. GFW-tested.
  meek-lite (secondary): Domain fronting via Fastly. Harder to detect.
  Snowflake (tertiary): WebRTC-based. Virtually unblockable.
  Custom ("Privex PT"): Mimics standard HTTPS browsing. Phase 3 development.
```

---

## 13. Tech Stack

### Frontend (Web App ‚Ä" Primary)

```
React 18.3 + TypeScript 5.x (strict: true, no implicit any, no implicit returns)
Vite 5.x                          ‚Ä" Build tool (HMR in dev, Rollup in prod)
Zustand 4.x                       ‚Ä" State management
React Router 6.x                  ‚Ä" Client-side routing
Dexie.js 3.x                      ‚Ä" IndexedDB ORM (typed, promise-based)
Tailwind CSS 3.x                  ‚Ä" Utility-first styling
Workbox 7.x                       ‚Ä" Service Worker / PWA toolkit
@nymproject/sdk-full-fat           ‚Ä" Nym mixnet client (WASM)
@signalapp/libsignal-client        ‚Ä" Signal protocol (PQXDH + Double Ratchet)
libsodium-wasm                     ‚Ä" Symmetric crypto (AES-GCM, XChaCha20, HKDF)
opaque-ts                          ‚Ä" OPAQUE account recovery (browser-compatible)
snarkjs 0.7                        ‚Ä" ZK proof generation (CSAM circuit only)
@privex/crypto-wasm               ‚Ä" Custom WASM module (MLS, PDQ, Shamir, Kyber)
protobufjs 7.x                    ‚Ä" Protocol Buffers (message serialization)
```

### Backend (Server)

```
Rust (edition 2021)               ‚Ä" Memory safety critical for crypto infrastructure
Axum 0.7                          ‚Ä" Web framework (async, Tower-based)
Tokio 1.x                         ‚Ä" Async runtime
SQLx 0.7                          ‚Ä" Async PostgreSQL driver (compile-time query checks)
Redis (deadpool-redis)            ‚Ä" Session tokens, rate limiting, challenge store
MinIO SDK                         ‚Ä" Object storage client
rustls 0.23                       ‚Ä" Pure Rust TLS. No OpenSSL dependency.
tower-http                        ‚Ä" HTTP middleware (no access logging middleware used)
prost 0.12                        ‚Ä" Protocol Buffers (Rust)
libsodium-sys                     ‚Ä" Rust bindings to libsodium
libsignal-protocol-rust           ‚Ä" Signal protocol (Rust)
liboqs 0.9                        ‚Ä" Post-quantum cryptography
openmls                           ‚Ä" MLS RFC 9420 (Rust)
opaque-ke 2.x                     ‚Ä" OPAQUE server-side
snarkjs-verifier (Rust port)      ‚Ä" Groth16 proof verification
```

### Infrastructure

```
Containers:        Docker (dev), Kubernetes (prod)
OS:                Alpine Linux 3.19 (minimal attack surface, musl libc)
Reverse Proxy:     Caddy 2.x (automatic HTTPS, access_log disabled)
Object Storage:    MinIO (self-hosted S3-compatible, Iceland + Switzerland)
Database:          PostgreSQL 16 (Iceland primary, Switzerland replica ‚Ä" async)
Cache:             Redis 7.2 (in-memory only, no persistence)
Secrets:           HashiCorp Vault (prod), SOPS (config encryption at rest)
Monitoring:        Prometheus + Grafana (no user data in any metric label)
Server hardware:   Bare metal (not shared cloud VMs) ‚Ä" Hetzner Finland or 1984 Hosting Iceland
DNS:               Split: public DNS for app (Cloudflare), internal DNS for infra (self-hosted)
TLS certs:         Let's Encrypt (via Caddy ACME) + HSTS preloading
```

### Cryptographic Libraries (Audit Status)

```
libsodium:         Audited by multiple parties (ISA, Cure53, NCC Group)
libsignal:         Audited by Cure53, ISEC, Trail of Bits
liboqs:            NIST-evaluated algorithms. Library under active security research.
OpenMLS:           RFC 9420 conformance test suite passing. Academic scrutiny.
snarkjs:           Used in production by Zcash, Hermez. circom 2.0 audited by ABDK.
opaque-ke:         Meta open-source. IETF CFRG specification.

ALL crypto: "Don't roll your own" is the law. Every primitive above is
            well-audited, widely deployed, or NIST-standardized.
            Zero custom crypto algorithms in Privex.
```

---

## 14. Security Model & Analysis

### 14.1 Full Threat Matrix

```
‚"å‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"¨‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ê
‚"Ç Adversary                          ‚"Ç Capability vs. Privex                            ‚"Ç
‚"ú‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"º‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"§
‚"Ç ISP watching user traffic          ‚"Ç BLOCKED ‚Ä" Sees Nym traffic only (not Privex)     ‚"Ç
‚"Ç DNS provider logging queries       ‚"Ç BLOCKED ‚Ä" All DNS via hardcoded DoH              ‚"Ç
‚"Ç VPS host monitoring server traffic ‚"Ç BLOCKED ‚Ä" Sees relay/Nym IPs only, not users     ‚"Ç
‚"Ç VPS host with DB access            ‚"Ç BLOCKED ‚Ä" Pseudonymous IDs + encrypted blobs     ‚"Ç
‚"Ç Privex employee with DB access     ‚"Ç BLOCKED ‚Ä" Same as VPS host                       ‚"Ç
‚"Ç Nym entry gateway operator         ‚"Ç PARTIAL ‚Ä" Knows user IP. Does not know Privex.   ‚"Ç
‚"Ç Onion relay node operator          ‚"Ç PARTIAL ‚Ä" Knows adjacent hop only                ‚"Ç
‚"Ç TURN relay operator                ‚"Ç PARTIAL ‚Ä" Knows session IP. No content/identity. ‚"Ç
‚"Ç Legal order to Privex (Iceland)    ‚"Ç BLOCKED ‚Ä" Architecture: nothing to provide       ‚"Ç
‚"Ç Legal order to VPS host            ‚"Ç BLOCKED ‚Ä" Encrypted volumes + pseudonymous data  ‚"Ç
‚"Ç Man-in-the-middle (network)        ‚"Ç BLOCKED ‚Ä" TLS + Nym + HKDF auth tags            ‚"Ç
‚"Ç Key directory substitution (MITM)  ‚"Ç BLOCKED ‚Ä" KT transparency log + client verify    ‚"Ç
‚"Ç Quantum computer (future)          ‚"Ç BLOCKED ‚Ä" CRYSTALS-Kyber + Dilithium3            ‚"Ç
‚"Ç Device with root malware           ‚"Ç PARTIAL ‚Ä" SE/Keystore protect keys; RAM readable ‚"Ç
‚"Ç Social engineering (user)          ‚"Ç OUT OF SCOPE ‚Ä" Not a technical attack            ‚"Ç
‚"Ç Global passive adversary (NSA)     ‚"Ç PARTIAL ‚Ä" Nym mixnet resists, timing still risk  ‚"Ç
‚""‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"¥‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"Ä‚"ò
```

### 14.2 Trust Hierarchy

```
TRUSTED COMPONENTS (Privex relies on these being correct):
  - libsodium, libsignal-protocol: Widely audited. Used by Signal in production.
  - CRYSTALS-Kyber, Dilithium3: NIST FIPS 203/204. Extensively cryptanalyzed.
  - User's device OS not compromised (kernel-level compromise is out of scope)
  - Nym mix nodes not >50% controlled by single adversary

NOT TRUSTED (Privex architecture protects against these):
  - Privex server operator
  - VPS host
  - ISP / DNS / network infrastructure
  - Any single onion relay node
  - TURN relay operator
  - CDN (during domain fronting)
  - Any relay node operator
  - Anyone receiving a court order directed at Privex
```

### 14.3 Honest Limitations

```
1. Nym entry gateway sees user's IP.
   Mitigation: Use Tor Browser or VPN before Nym for IP hiding from Nym gateway.
   Residual risk: If Nym gateway is compromised AND Privex server is compromised
                  simultaneously, correlation is possible (but Nym gateway doesn't
                  know the destination, and Privex server doesn't know the source).
   Additional: Privex-operated Nym gateways use no-log configuration.
               Even if compelled, there is nothing to produce.

2. ISP can observe when Bob's device is online (timing metadata).
   What ISP sees: Bob's device connects to Nym at specific times.
   What ISP cannot see: that Bob uses Privex, who he talks to, what is said.
   Mitigation: Fixed polling schedule (Section 5.7) turns precise timestamps into
               fuzzy 30-minute windows. Nym loop cover traffic normalizes volume.
               Jittered receipts decouple delivery confirmation from message receipt.
   Residual risk: An adversary simultaneously watching Alice's ISP AND Bob's ISP
                  with resources to correlate Nym-layer timing across sessions.
                  Requires nation-state capability and active targeting of both parties.
   Honest statement: Privex hides WHAT you communicate and WHO you communicate with.
                     It significantly degrades (but does not eliminate) evidence of WHEN.

3. iOS APNs knows Privex is installed on a device.
   Mitigation: 0-byte push payloads. No content visible to Apple.
   Residual risk: Apple knows the device uses Privex. Not who you talk to.

4. Phase 1 transport: ISP can see connections to api.privex.dpdns.org directly.
   This is a PHASE 1 ONLY limitation. Nym integration in Phase 2 eliminates it.
   During Phase 1, the ISP can confirm Privex is being used.
   Mitigation for Phase 1: Use a VPN or Tor before connecting.
   Phase 2 resolves this: ISP sees only Nym traffic.

5. Endpoint compromise (rooted device with kernel malware).
   Mitigation: SE/Keystore makes private keys non-exportable. Best effort.
   Residual risk: Screen content and in-memory decrypted messages are readable.
   This is out of scope for any software security system.

6. Global passive adversary with Nym mix node majority.
   Mitigation: Nym network is public, large, diverse. Achieving >50% is expensive.
   Residual risk: Nation-state adversary with sufficient resources. Theoretical.

7. KT log transparency requires users to actually check.
   Mitigation: Client checks automatically on every key fetch.
   Residual risk: Client app must not be silently modified to skip the check.
   Additional mitigation: Open-source client, reproducible builds.

8. Seed phrase recovery requires writing it down (physical security risk).
   Mitigation: OPAQUE is available as opt-in password recovery for users whose
               threat model accepts a server-side encrypted recovery record.
   Residual risk: If user writes it down insecurely, attacker who finds it
                  gains account access.

9. Server-side history backup (if opt-in enabled) breaks forward secrecy server-side.
   Mitigation: Default is OFF. User must explicitly enable with clear warning.
   Residual risk: If user's password AND server are both compromised simultaneously,
                  encrypted history blobs could be exposed to offline attack.
   Honest statement: History backup is a convenience feature with a documented tradeoff.
                     High-threat users should leave it disabled.

10. Real-time cross-device sync adds a small amount of additional traffic per sent message.
    One sync copy is sent to all linked devices for every message sent.
    Mitigation: Sync messages are indistinguishable from regular cover traffic.
    Residual risk: Higher message volume when user has multiple active devices.
                   Not a security issue. Minor metadata observation at most.

11. Audio/video calls: TURN relay sees IP addresses of both call participants.
    TURN authentication uses ephemeral tokens not linked to user identity.
    TURN server does not log. TURN does not see call content (SFrame encrypts frames).
    Residual risk: TURN relay operator knows two IPs connected for a call session.
                   They do not know who the users are or what was said.
    Honest statement: Call privacy is weaker than message privacy. This is the same
                      tradeoff as Signal, Wire, and every other E2EE calling app.
                      Content is protected. IP-level call pairing is not.
```

### 14.4 Reproducible Builds

```
All Privex client binaries are reproducibly built:
  - Given the same source code and build environment, the output binary is
    deterministic (same bytes, same checksums).
  - Anyone can verify: download the binary, build from source, compare SHA-256.
  - If they match: the distributed binary was built from the published source.
    No hidden modifications.

Implementation:
  Web app: Deterministic Vite build (fixed timestamps, sorted output).
  Android: reproducible-builds.org guidelines.
  iOS: Xcode deterministic builds (Xcode 14+).
  Desktop: cargo-build with locked Cargo.lock (same versions, same output).

Published: Binary hashes signed by Privex's signing key + committed to KT log.
```

---

## 15. Build Phases

### Phase 1 ‚Ä" Web App Foundation (Months 1‚Ä"4)

**Goal:** Secure 1:1 messaging on the web that beats Signal on every dimension.

#### Current Phase 1 Status

```
IMPLEMENTED AND WORKING:
  ‚ú" 1:1 text messaging (Alice and Bob chat in real time)
  ‚ú" File transfers with media thumbnails (images and files work end-to-end)
  ‚ú" Offline message delivery (server queues, delivers when Bob reconnects)
  ‚ú" Server-side chat history backup (opt-in, with clear warning ‚Ä" implemented)
  ‚ú" Device-to-device history transfer (implemented, requires both devices online)
  ‚ú" PWA (Progressive Web App, installable)
  ‚ú" React 18 web app foundation
  ‚ú" Rust/Axum backend with UNLOGGED PostgreSQL tables
  ‚ú" WebCrypto non-extractable master key
  ‚ú" IndexedDB encrypted storage

IN PROGRESS / PARTIAL (skeleton or cosmetic):
  ~ Cover traffic (code skeleton exists, not fully active)
  ~ Nym relay integration (code skeleton exists, not connected to live Nym network)
  ~ Session management and multi-device logout (implemented but broken)
  ~ Cross-device real-time sync (messages sent from Device A do not yet sync to Device B)
  ~ Push notifications via Service Worker (PWA done, push notifications broken)

PENDING (not yet started):
  ‚-ã Delivery & read receipts system (Section 4.10)
  ‚-ã Time synchronization & desync attack prevention (Section 9.6)
  ‚-ã Fixed polling schedule + constant fetch size (Section 5.7 Mitigations 1 & 2)
  ‚-ã Per-message TTL override
  ‚-ã Jittered receipt sending (Section 5.7 Mitigation 3)
  ‚-ã Session management fix (currently broken)
```

#### Complete Phase 1 Deliverables

```
  ‚ú" Hybrid PQC identity system (Ed25519 + Dilithium3)
  ‚ú" PQXDH key exchange (Signal PQXDH spec)
  ‚ú" Double Ratchet 1:1 messaging
  ‚ú" Sealed Sender
  ‚ú" File sharing (chunked AES-256-GCM, blob store)
  ‚ú" Media thumbnails (generated client-side before encryption)
  ‚ú" ZK authentication (signed challenge)
  ‚ú" OPAQUE account recovery (opt-in password recovery)
  ‚ú" Multi-device linking
  ‚ú" Device-to-device chat history transfer
  ‚ú" Server-side encrypted history backup (opt-in, with clear warning)
  ‚ú" Proof-of-Work registration (no IP rate-limiting)
  ‚ú" React 18 web app (PWA installable)
  ‚ú" WASM crypto layer (@privex/crypto-wasm)
  ‚ú" Rust/Axum backend
  ‚ú" PostgreSQL schema (UNLOGGED tables for message_queue, history_blobs)
  ‚ú" IndexedDB storage + WebCrypto key management
  ‚ú" Service Worker (offline support, background sync)
  ‚ú" True no-log infrastructure (WAL minimal, Redis no-persist, tmpfs logs)
  ‚ú" Delivery & read receipts (Section 4.10)
  ‚ú" Message TTL (30-day default, 60-day opt-in, per-message override)
  ‚ú" Real-time cross-device sync for linked devices (Section 4.11)
  ‚ú" Session management (multiple devices, logout everywhere)
  ‚ú" Time synchronization & desync attack prevention (Section 9.6)
  ‚-ã Cover traffic (skeleton ‚Ü' Phase 2 completes this)
  ‚-ã Nym integration (skeleton ‚Ü' Phase 2 completes this)
  ‚-ã Fixed polling schedule (‚Ü' Phase 2)
  ‚-ã Constant fetch size (‚Ü' Phase 2)

Success criteria:
  - 1:1 messages exchange end-to-end with Sealed Sender
  - Server DB inspectable ‚Ü' zero readable user data at any point
  - Offline delivery: Bob misses messages, comes back online, receives them all
  - OPAQUE recovery: lose browser data, recover on new device with password only
  - Device-to-device transfer: full history moved to new device without server involvement
  - Server-side backup: new device recovers history without old device
  - Receipt system: "delivered" and "read" confirmations arrive without revealing timing
  - Time sync: device clock verified against server, desync attacks detected
  - Session management: logout everywhere works, old tokens invalidated
  - Registration: no IP in any log at any point
```

### Phase 2 ‚Ä" Metadata Perfection + Android (Months 5‚Ä"7)

**Goal:** Perfect metadata resistance. Android app. CSAM protection live.

```
Deliverables:
  ‚ú" Cover traffic system (Poisson schedule, user-configurable)
  ‚ú" Message padding (1024-byte boundaries)
  ‚ú" Censorship circumvention (obfs4, domain fronting, bridge nodes, Snowflake)
  ‚ú" DNS-over-HTTPS (hardcoded, all platforms)
  ‚ú" KT transparency log (Merkle tree, client-side verification)
  ‚ú" PDQ perceptual hashing (WASM)
  ‚ú" PSI protocol for CSAM check
  ‚ú" Groth16 trusted setup ceremony (public, multi-party, >10 participants)
  ‚ú" ZK proof generation for image messages
  ‚ú" Direct-to-NCMEC user reporting pipeline
  ‚ú" Shamir's Secret Sharing recovery contacts
  ‚ú" Seed phrase generation and recovery
  ‚ú" Android native app (React Native + UnifiedPush)
  ‚ú" Warrant canary live at https://privex.dpdns.org/canary

Success criteria:
  - CSAM PSI blocks known test hashes
  - ZK proof verifies server-side in <5ms
  - Trusted setup ceremony transcript publicly verified
  - KT inclusion proof verified on every key fetch
  - Android app functional on Android 8+
  - Cover traffic indistinguishable from real traffic in packet capture
```

### Phase 3 ‚Ä" Group Messaging + Calls + iOS (Months 7‚Ä"9)

**Goal:** MLS group messaging. E2EE calls. iOS app.

```
Deliverables:
  ‚ú" MLS Protocol group messaging (OpenMLS, RFC 9420)
  ‚ú" Group key management (add/remove/update with epoch rotation)
  ‚ú" Group audio calls (SFrame + pion/webrtc SFU, up to 8 participants)
  ‚ú" Group video calls (SFrame, SFU-based, up to 8 participants with E2EE SFU)
  ‚ú" 1:1 audio/video calls (WebRTC + SFrame + sealed sender signaling)
  ‚ú" Oblivious TURN relay (no user identity, ephemeral HMAC tokens)
  ‚ú" TURN-only ICE mode (default, hides local IP)
  ‚ú" Voice messages (encrypted audio as file, played inline)
  ‚ú" Disappearing messages (client-enforced TTL, cryptographic deletion)
  ‚ú" iOS native app (React Native + CallKit + VoIP push)
  ‚ú" Sensor Permissions (camera/mic requested only when actually used)

Success criteria:
  - Group MLS key agreement correct (verified against RFC 9420 test vectors)
  - Call TURN captures show only SFrame-encrypted blobs
  - Server has zero record of any call
  - iOS app on iOS 16+
  - Disappearing messages fully cleared from both devices on schedule
```

### Phase 4 ‚Ä" Desktop + Advanced Features (Months 9‚Ä"11)

**Goal:** Desktop app. Advanced metadata protection. Community relay nodes.

```
Deliverables:
  ‚ú" Desktop app ‚Ä" Tauri 2 (macOS 12+, Windows 10+, Ubuntu 20.04+)
  ‚ú" OS Keychain integration (macOS Keychain, Windows Credential Manager, libsecret)
  ‚ú" Spiral PIR for message retrieval (server cannot tell which messages fetched)
  ‚ú" Community volunteer relay nodes (Phase 2 of relay network)
  ‚ú" Sender Keys model for large groups (500‚Ä"5000 members)
  ‚ú" Reproducible builds for all platforms
  ‚ú" UnifiedPush for Android (FCM-free default)
  ‚ú" Custom pluggable transport ("Privex PT" ‚Ä" HTTPS mimicry)
  ‚ú" Incorporate in Iceland (legal entity: Privex ehf.)
```

### Phase 5 ‚Ä" Hardening, Audit, Launch (Months 12‚Ä"15)

**Goal:** Production-ready. Independently audited. Public launch.

```
Deliverables:
  ‚ú" Full independent security audit (Trail of Bits or Cure53 ‚Ä" full-scope)
  ‚ú" Bug bounty program (HackerOne, public scope)
  ‚ú" Cryptographic architecture audit (separate from code audit)
  ‚ú" ZK circuit audit (the CSAM csam_check.circom)
  ‚ú" All audit findings resolved
  ‚ú" Open-source: crypto core (FOSS), server (AGPL), clients (GPL)
  ‚ú" NCMEC Technology Coalition membership active
  ‚ú" Warrant canary with GPG-signed monthly publication
  ‚ú" ICELANDIC legal entity + bank account
  ‚ú" Press outreach: EFF, The Intercept, Wired, 404 Media, Rest of World
  ‚ú" 500+ beta users from partner organizations (journalists, human rights orgs)

Launch criteria (no launch until ALL are green):
  - Security audit: no critical findings open
  - OPAQUE recovery: tested across 50+ device/browser combinations
  - Nym integration: tested in China, Iran, Russia network emulation
  - CSAM PSI: NCMEC hash database integration verified
  - KT log: Merkle inclusion proofs verified by 3 independent implementations
  - Reproducible builds: verified by 3 independent parties
```

---

## 16. Project Structure ‚Ä" Monorepo

```
privex/
‚"ú‚"Ä‚"Ä apps/
‚"Ç   ‚"ú‚"Ä‚"Ä web/                           # Primary Platform ‚Ä" React PWA
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä public/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä manifest.json
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä sw.js                  # Service Worker entry
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä main.tsx
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä App.tsx
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä screens/
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Onboarding/        # Registration, OPAQUE setup, recovery config
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Conversations/     # Message list
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Chat/              # 1:1 and group chat UI
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Call/              # Audio/video call UI
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Settings/          # Recovery, linked devices, privacy settings
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä KeyVerification/   # Safety codes, fingerprint comparison
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä components/            # Reusable UI components (custom, no third-party UI kit)
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä workers/
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä crypto.worker.ts   # SharedWorker for heavy WASM ops
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä nym.worker.ts      # Worker for Nym SDK
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä store/                 # Zustand state slices
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä identity.ts
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä messages.ts
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä groups.ts
‚"Ç   ‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä calls.ts
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä db/                    # Dexie.js IndexedDB schema and queries
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä hooks/                 # React hooks (useNym, useCrypto, useCall, etc.)
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä utils/
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä vite.config.ts
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚"ú‚"Ä‚"Ä android/                       # React Native Android (Phase 2)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä android/
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚"ú‚"Ä‚"Ä ios/                           # React Native iOS (Phase 3)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä ios/
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚""‚"Ä‚"Ä desktop/                       # Tauri (Phase 4)
‚"Ç       ‚"ú‚"Ä‚"Ä src/                       # React frontend (shared components from web)
‚"Ç       ‚"ú‚"Ä‚"Ä src-tauri/                 # Rust backend
‚"Ç       ‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç       ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä main.rs
‚"Ç       ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä commands/          # Tauri IPC typed commands
‚"Ç       ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä crypto.rs      # All crypto operations
‚"Ç       ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä messages.rs
‚"Ç       ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä calls.rs
‚"Ç       ‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä files.rs
‚"Ç       ‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä recovery.rs
‚"Ç       ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä crypto/            # Crypto implementations
‚"Ç       ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä nym/               # Nym SDK integration (Rust)
‚"Ç       ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä onion/             # Onion routing client
‚"Ç       ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä storage/           # SQLite + SQLCipher
‚"Ç       ‚"Ç   ‚""‚"Ä‚"Ä Cargo.toml
‚"Ç       ‚""‚"Ä‚"Ä package.json
‚"Ç
‚"ú‚"Ä‚"Ä packages/
‚"Ç   ‚"ú‚"Ä‚"Ä crypto-wasm/                   # @privex/crypto-wasm ‚Ä" Rust ‚Ü' WASM
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä src/                       # Rust source
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä identity.rs            # Ed25519 + Dilithium3 keypairs
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä pqxdh.rs              # X3DH + Kyber key exchange
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä ratchet.rs            # Double Ratchet
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä sealed_sender.rs      # Sealed Sender encode/decode
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä mls.rs                # MLS via openmls
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä files.rs              # File chunking + CEK
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä csam.rs               # PDQ hash + PSI
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä shamir.rs             # Shamir's Secret Sharing
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä opaque.rs             # OPAQUE client operations
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä pow.rs                # Proof of Work solver
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä pkg/                      # WASM output (built by wasm-pack)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä Cargo.toml
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚"ú‚"Ä‚"Ä circuits/                      # ZK circuits (@privex/circuits)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä csam_check.circom      # PDQ PSI ZK circuit (Circom 2.0)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä build/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä csam_check.r1cs
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä csam_check_final.zkey  # Generated from trusted setup ceremony
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä verification_key.json  # Public verification key
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä ceremony/                  # Trusted setup ceremony transcripts
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä contributions/         # Each participant's contribution
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä verify_ceremony.sh     # Script to verify ceremony integrity
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚"ú‚"Ä‚"Ä protocol/                      # Protobuf schemas (@privex/protocol)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä proto/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä envelope.proto         # Sealed Sender wrapper
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä messages.proto         # Message types
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä keys.proto             # Key bundle, prekeys
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä calls.proto            # Call signaling (SDP, ICE)
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä groups.proto           # MLS group operations
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä recovery.proto         # OPAQUE, Shamir flows
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä package.json
‚"Ç   ‚"Ç
‚"Ç   ‚""‚"Ä‚"Ä ui/                            # @privex/ui ‚Ä" Shared UI primitives
‚"Ç       ‚"ú‚"Ä‚"Ä src/                       # Custom components (no third-party UI kit)
‚"Ç       ‚""‚"Ä‚"Ä package.json
‚"Ç
‚"ú‚"Ä‚"Ä server/                            # Rust/Axum backend
‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä main.rs
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä config.rs                  # Config from environment (no plaintext secrets)
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä routes/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä auth.rs                # Challenge, verify, session
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä keys.rs                # Key directory, KT log, prekeys
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä messages.rs            # Send, ack
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä blobs.rs               # Blob upload/download/delete
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä groups.rs              # MLS group state
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä recovery.rs            # OPAQUE endpoints, Shamir shares
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä relays.rs              # Relay node directory
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä middleware/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä auth.rs                # Session token verification
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä rate_limit.rs          # Per-user-id rate limiting (Redis)
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä csam_verify.rs         # Groth16 ZK proof verification
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä crypto/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä ed25519.rs             # Signature verification
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä dilithium.rs           # PQ signature verification
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä groth16.rs             # ZK proof verifier
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä opaque.rs              # OPAQUE server operations
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä kt_log.rs              # KT Merkle tree operations
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä db/
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä schema.sql
‚"Ç   ‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä migrations/
‚"Ç   ‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä queries/               # SQLx compiled queries
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä ws/                        # WebSocket handler
‚"Ç   ‚"ú‚"Ä‚"Ä Cargo.toml
‚"Ç   ‚""‚"Ä‚"Ä Dockerfile
‚"Ç
‚"ú‚"Ä‚"Ä relay/                             # Onion relay node (Rust)
‚"Ç   ‚"ú‚"Ä‚"Ä src/
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä main.rs
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä onion.rs                   # Sphinx/onion layer decryption
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä forward.rs                 # Next-hop forwarding
‚"Ç   ‚""‚"Ä‚"Ä Cargo.toml
‚"Ç
‚"ú‚"Ä‚"Ä infra/
‚"Ç   ‚"ú‚"Ä‚"Ä docker-compose.yml             # Local dev: server + postgres + redis + minio + relay
‚"Ç   ‚"ú‚"Ä‚"Ä k8s/                           # Production Kubernetes
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä server.yaml
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä relay.yaml
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä minio.yaml
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä postgres.yaml              # UNLOGGED tables, WAL minimal config
‚"Ç   ‚"Ç   ‚"ú‚"Ä‚"Ä redis.yaml                 # No persistence, maxmemory LRU
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä caddy.yaml
‚"Ç   ‚"ú‚"Ä‚"Ä caddy/
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä Caddyfile                  # access_log: discard
‚"Ç   ‚"ú‚"Ä‚"Ä postgres/
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä postgresql.conf            # wal_level=minimal, archive_mode=off
‚"Ç   ‚"ú‚"Ä‚"Ä redis/
‚"Ç   ‚"Ç   ‚""‚"Ä‚"Ä redis.conf                 # save "", appendonly no
‚"Ç   ‚""‚"Ä‚"Ä scripts/
‚"Ç       ‚"ú‚"Ä‚"Ä gen_server_keys.sh         # Generate relay node keypairs
‚"Ç       ‚"ú‚"Ä‚"Ä build_wasm.sh              # wasm-pack build for crypto-wasm
‚"Ç       ‚"ú‚"Ä‚"Ä build_circuits.sh          # circom compile + snarkjs setup
‚"Ç       ‚""‚"Ä‚"Ä verify_ceremony.sh         # Verify trusted setup ceremony
‚"Ç
‚"ú‚"Ä‚"Ä docs/
‚"Ç   ‚"ú‚"Ä‚"Ä TECHNICAL.md                   # This document
‚"Ç   ‚"ú‚"Ä‚"Ä THREAT_MODEL.md                # Extended threat analysis
‚"Ç   ‚"ú‚"Ä‚"Ä CRYPTOGRAPHY.md                # Deep-dive crypto specifications
‚"Ç   ‚"ú‚"Ä‚"Ä CSAM_PROTECTION.md             # CSAM system detailed spec
‚"Ç   ‚"ú‚"Ä‚"Ä ACCOUNT_RECOVERY.md            # OPAQUE + Shamir detailed spec
‚"Ç   ‚"ú‚"Ä‚"Ä KT_LOG.md                      # Key Transparency log spec
‚"Ç   ‚""‚"Ä‚"Ä WARRANT_CANARY.md              # Warrant canary policy + GPG key
‚"Ç
‚"ú‚"Ä‚"Ä package.json                       # pnpm workspace root
‚"ú‚"Ä‚"Ä pnpm-workspace.yaml
‚"ú‚"Ä‚"Ä turbo.json                         # Turborepo pipeline
‚""‚"Ä‚"Ä README.md
```

---

## 17. Glossary

| Term | Definition |
|---|---|
| **AES-256-GCM** | Authenticated encryption standard. 256-bit key. GCM provides encryption + authentication in one operation. |
| **BIP-39** | Bitcoin Improvement Proposal 39. Standard for generating mnemonic seed phrases from entropy. |
| **Blob Store** | Object storage (MinIO) holding encrypted file chunks. Content-addressed by SHA-256 of encrypted chunk. |
| **CEK** | Content Encryption Key. Random 32-byte key generated per file for client-side file encryption. |
| **Circom** | Domain-specific language for writing arithmetic circuits for ZK-SNARK systems. |
| **Cover Traffic** | Fake encrypted messages sent on a randomized schedule to prevent traffic analysis. |
| **CRYSTALS-Dilithium3** | NIST FIPS 204 post-quantum digital signature algorithm. Quantum-safe alternative to Ed25519. |
| **CRYSTALS-Kyber-1024** | NIST FIPS 203 post-quantum key encapsulation mechanism. Quantum-safe key exchange. |
| **CSAM** | Child Sexual Abuse Material. |
| **DHR Ratchet** | Diffie-Hellman ratchet step in Double Ratchet. Provides break-in recovery via new key material. |
| **Dilithium3** | See CRYSTALS-Dilithium3. |
| **DoH** | DNS-over-HTTPS. Encrypts DNS queries inside HTTPS, hiding them from ISP and DNS providers. |
| **Double Ratchet** | Signal Protocol's message encryption providing forward secrecy + break-in recovery per message. |
| **DTLS-SRTP** | Transport-layer encryption for WebRTC media streams. |
| **E2EE** | End-to-End Encryption. Content encrypted from sender to recipient, decryptable only by them. |
| **Ed25519** | Edwards-curve Digital Signature Algorithm. Fast, secure classical signature algorithm. |
| **Epoch** | MLS concept. Each group modification (add/remove/update) increments the epoch and derives new keys. |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). Derives multiple keys from a single input. |
| **ICE** | Interactive Connectivity Establishment. WebRTC protocol for finding optimal network path. |
| **IK** | Identity Key. Long-term keypair that defines a user's cryptographic identity. |
| **Kyber** | See CRYSTALS-Kyber-1024. |
| **KT Log** | Key Transparency Log. Append-only Merkle tree recording all key directory operations. |
| **liboqs** | Open Quantum Safe library. Reference implementations of NIST post-quantum algorithms. |
| **libsodium** | Widely audited, high-level cryptographic library. Used for all symmetric operations. |
| **MLS** | Messaging Layer Security. IETF RFC 9420. Efficient group E2EE protocol. |
| **Mixnet** | Mix Network. Batch-and-delay network architecture providing traffic analysis resistance beyond onion routing. |
| **NCMEC** | National Center for Missing and Exploited Children. Operates CyberTipline and CSAM hash database. |
| **Nym** | Mixnet protocol and network providing traffic analysis-resistant communication transport. |
| **obfs4** | Pluggable transport that disguises network traffic as random bit noise. |
| **Onion Routing** | Multi-layer encryption routing where each node decrypts one layer, learning only adjacent hops. |
| **OPAQUE** | Oblivious Pseudorandom Function-based Authenticated Key Exchange. Server-side ZK password-based recovery protocol. |
| **OPRF** | Oblivious Pseudorandom Function. Used in PSI and OPAQUE protocols. |
| **OPK** | One-Time Prekey. Single-use X25519 key consumed during X3DH key exchange initiation. |
| **ORAM** | Oblivious RAM. Access pattern hiding for stored data. Future Privex phase. |
| **PDQ** | Perceptual hash algorithm (Meta/Facebook, Apache 2.0). Matches visually similar images. |
| **PIR** | Private Information Retrieval. Server cannot determine which messages a client fetched. |
| **PoW** | Proof of Work. Hashcash-style puzzle solving. Used for registration rate limiting without IP correlation. |
| **PQXDH** | Post-Quantum Extended Triple Diffie-Hellman. Signal's protocol combining X3DH + CRYSTALS-Kyber. |
| **PSI** | Private Set Intersection. Protocol for finding set overlap without revealing either set. |
| **PWA** | Progressive Web App. Web application installable like a native app via browser APIs. |
| **Ratchet Tree** | Binary tree structure in MLS for O(log N) group key management. |
| **Ristretto255** | Cofactor-1 prime-order elliptic curve group built on Curve25519. Used in PSI/OPAQUE OPRF. |
| **SFrame** | Scalable Frame Encryption. RFC 9605. Application-layer E2EE for WebRTC media frames. |
| **Sealed Sender** | Technique where sender identity is encrypted inside the message body. Server sees only recipient. |
| **Sender Keys** | Group messaging model for large groups (500‚Ä"5000). One sender key per member, distributed E2EE. |
| **Shamir's SSS** | Shamir's Secret Sharing. Splits a secret into N shares where any T can reconstruct it. |
| **snarkjs** | JavaScript ZK-SNARK library. Used with circom for CSAM ZK proof generation. |
| **Snowflake** | WebRTC-based pluggable transport disguising Privex traffic as WebRTC video calls. |
| **SPK** | Signed Prekey. Medium-term X25519 keypair signed by identity key. Rotated monthly. |
| **Sphinx** | Cryptographic packet format used by Nym for fixed-size, onion-encrypted routing. |
| **STUN** | Session Traversal Utilities for NAT. Helps WebRTC discover public IP for P2P connections. |
| **Tauri** | Rust-backend desktop app framework. Memory-safe, ~8MB binary vs Electron's ~150MB. |
| **TreeKEM** | Tree-based Key Encapsulation Mechanism. Efficient key distribution in MLS ratchet tree. |
| **TURN** | Traversal Using Relays around NAT. WebRTC media relay when P2P connection fails. |
| **UnifiedPush** | Push notification standard independent of Google FCM. Allows FCM-free Android notifications. |
| **X3DH** | Extended Triple Diffie-Hellman. Asynchronous key agreement for users not simultaneously online. |
| **X25519** | Elliptic curve Diffie-Hellman using Curve25519. Classical key exchange in X3DH. |
| **XChaCha20-Poly1305** | Authenticated encryption with extended 192-bit nonce. Used for Sealed Sender envelope encryption. |
| **ZK / ZKP** | Zero-Knowledge Proof. Proves a statement true without revealing why it is true. |
| **ZK-SNARK** | Succinct Non-Interactive Argument of Knowledge. Compact, fast-verifying ZK proof type. |
| **Zero-Knowledge Architecture** | System where the operator is cryptographically prevented from accessing user data ‚Ä" not merely policy-prohibited. |

---

*Document: PRIVEX_TECHNICAL_DOCS_V2.md*
*Version: 2.2 ‚Ä" Gold Standard Architecture | Offline Delivery | Receipts | Timing Mitigations | Time Sync*
*Platform Priority: Web ‚Ü' Android ‚Ü' iOS ‚Ü' Desktop*
*Maintainer: Privex Engineering*
*License: CC BY 4.0 ‚Ä" Architecture may be freely studied and implemented*
*Cryptographic implementations must use audited libraries listed in Section 13*

---

> **Final note for Claude Code:**
> Every cryptographic primitive in this document uses an existing, audited library.
> Zero custom crypto algorithms exist anywhere in Privex.
> When implementing: if a library exists for the primitive, use it.
> The security of this system depends entirely on not reinventing wheels.
> Signal's libsignal handles PQXDH + Double Ratchet.
> OpenMLS handles MLS. liboqs handles Kyber + Dilithium. libsodium handles the rest.
> Your job as implementer is to compose these correctly, not to write crypto from scratch.
