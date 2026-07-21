# Privex

![Privex](https://img.shields.io/badge/Status-Phase_1_Beta-blue) ![License](https://img.shields.io/badge/License-Custom_EULA-red)

**Privex** is a zero-knowledge, end-to-end encrypted communication platform. The server is architecturally (not policy) blind - it cannot read messages, identify users, or trace relationships. 

We are making the Phase 1 source code public for transparency and auditing. We believe that for a privacy app, open-sourcing the code is the only true way to earn user trust.

**Current Live Beta Domain:** [Privex.chat](https://privex.chat)

---

## 🔒 The Absolute Laws of Privex

1. **ZERO** custom cryptographic algorithms.
2. **ZERO** plaintext user data stored on the server. Ever.
3. **ZERO** IP addresses logged or stored anywhere. Not even temporarily.
4. **ZERO** access logs (requests, connections, anything with user identifiers).
5. **ZERO** third-party analytics, tracking, or telemetry.
6. **ALL** cryptography runs directly in your browser via WebAssembly or Web Crypto API.

## 📖 Documentation

If you want to understand how Privex achieves these guarantees, please read our documentation:

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Security & Threat Model](docs/SECURITY_DESIGN.md)
- [API Reference](docs/API_REFERENCE.md)
- [Contributing Guidelines](docs/CONTRIBUTING.md)

---

## 🚀 Current Status (Phase 1)

Privex is currently in **Phase 1 (Web App Foundation)**. We have made significant progress, but there is still a long way to go before we are ready for a global production launch.

### ✅ What is Done
- 1:1 Text messaging with Double Ratchet & Post-Quantum Cryptography (Kyber/Dilithium3).
- Offline message delivery via an UNLOGGED server queue.
- Installable PWA with a React/Vite/Tailwind frontend.
- Zero-knowledge account recovery using OPAQUE and Shamir's Secret Sharing.
- Proof-of-Work rate limiting to protect public endpoints without IP logging — Hashcash SHA-256 with a memory-hard Argon2id hybrid layer on top (blunts GPU/ASIC farms; both difficulty layers climb automatically under load).
- Client-side data secured using WebCrypto and IndexedDB.

### 🚧 What is Missing / Needs Help
We are actively building the following features to complete Phase 1:
- **Nym Integration:** Transitioning from direct WebSockets to full Nym mixnet routing. *(Client worker is a skeleton today; the full gateway wiring is the headline Phase 2 deliverable.)*
- ~~**PoW Hardening:** Argon2id, in a hybrid with SHA-256. Not instead of SHA-256, on top of it.~~
- ~~**Message TTL controls:** The server queue enforces a fixed 30-day TTL. The 60-day opt-in and per-message TTL override (docs 4.12) are not built yet.~~ *(Per-message TTL is live: senders choose "delete if undelivered after…" from 1 hour to 60 days, server-enforced with a 30-day default.)*
- ~~**Emergency Recovery Contacts:** Recover-via-contacts (Shamir) retrieval is setup only, retrieval needs a relationship-free share rendezvous the server doesn't know who your contacts are.~~ *(Retrieval is now live: a fresh device generates an ephemeral recovery key + code, contacts approve out-of-band with a SAS check, and shares are relayed through a random ephemeral rendezvous — the server never learns who your recovery contacts are.)*
- ~~**Session Management:** Fixing token invalidation on Signed Pre-Key rotation.~~
- **Push Notifications:** Service Worker push event handling needs fixing.
- ~~**Time Synchronization:** Desync attack prevention via server-signed timestamps.~~
- ~~**Cross-Device Sync:** Real-time syncing of sent messages across multiple devices.~~
- ~~**Delivery & Read Receipts:** Implementing secure receipts without timing correlations.~~
- ~~**Timing Mitigations:** Polling schedules, fetch padding, and jittered receipt sending.~~
- **File Sharing:** Disabled in Phase 1; pending client-side [CSAM protection](https://github.com/Privex-chat/Privex/blob/main/docs/ARCHITECTURE.md#17-csam-protection) perceptual hashing implementation in Phase 2.

---

## ⚖️ License & Open Source Philosophy

This repository is strictly governed by a **Custom EULA** (see the [LICENSE](LICENSE) file). 

**Why a Custom License?**
Privex will become a production-grade global entity. We have open-sourced the codebase for transparency, auditing, and to allow the community to contribute. However, **you are strictly prohibited from copying, reusing, or selling this code or its architectural design for your own products.**

We welcome contributions! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before submitting a Pull Request.

---

## 💡 About the Founder & Funding

Privex is founded and maintained by **Hemansh**. 
- 🔗 **LinkedIn:** [Hemansh](https://www.linkedin.com/in/sonixaep/)
- 🔗 **GitHub Repo:** [Privex-chat/Privex](https://github.com/Privex-chat/Privex)

### Support the Project
Currently, Privex is running on temporary infrastructure without external funding. If you believe in absolute privacy and want to support the development of Privex, please consider donating:

💖 **[Sponsor Privex on GitHub](https://github.com/sponsors/Privex-chat)**
