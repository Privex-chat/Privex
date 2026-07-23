# Contributing to Privex

Welcome. Privex is a Phase-1 beta, built and maintained by one person, and it needs more eyes far more than it needs more features. Whether you do cryptography, Rust, TypeScript, threat modeling, design, or documentation — or you just want to try to break it — there is room here.

New to the project? The [wiki](https://wiki.privex.chat) is the fastest way in (every page has a Plain and a Technical view), and [SECURITY_DESIGN.md](SECURITY_DESIGN.md) is the fastest way to start attacking it.

This repository is licensed under **AGPL-3.0-or-later** (see [`LICENSE`](../LICENSE)): you are free to use, study, modify, and self-host it. The AGPL's network clause (§13) is the condition — if you run a **modified** version as a network service, you must offer its users the corresponding source of your modified version. **By submitting a contribution, you agree it is licensed under AGPL-3.0-or-later.** The **Privex name and branding** are protected separately (see [`TRADEMARK.md`](../TRADEMARK.md)) so that "Privex" always means this one accountable project.

## The Absolute Laws

Before contributing to Privex, you must understand and adhere to the Absolute Laws. A Pull Request violating any of these will be instantly rejected:

1. **ZERO custom cryptographic algorithms.** Use the listed libraries only.
2. **ZERO plaintext user data stored on the server.** Ever.
3. **ZERO IP addresses logged or stored anywhere.** Not even temporarily.
4. **ZERO access logs.** No logs of requests, connections, or anything with user identifiers.
5. **ZERO third-party analytics, tracking, or telemetry.**
6. **ALL cryptography runs in the browser** via WebAssembly or the Web Crypto API.

## Phase 1 Status & What Needs Help

Privex is currently in Phase 1 (Web App). Here is the current status:

### Implemented
- 1:1 text messaging with Double Ratchet and full hybrid post-quantum crypto (Kyber-1024 / Dilithium3)
- Sealed sender (the server never learns who sent a message)
- Offline delivery via an `UNLOGGED` Postgres queue with per-message "delete if undelivered after…" TTLs
- Zero-knowledge account recovery — OPAQUE password, Shamir social recovery, and seed phrase (all live)
- Server-signed timestamps (desync-attack defense), delivery/read receipts with no timestamps + jittered sending, cross-device sync
- Proof-of-work registration/rate-limiting (Hashcash SHA-256 + Argon2id), no IP logged anywhere
- Rust/Axum backend, installable React/Vite PWA, WebCrypto non-extractable keys + encrypted IndexedDB, in-app safety-code verification

### Missing / Help Wanted
Where help matters most, roughly in priority order:
- **Nym mixnet integration** — the headline. Today the client uses direct WebSockets; the Nym worker is a skeleton. Wiring the full mixnet gateway path is the flagship Phase-2 deliverable. It's what makes two guarantees real rather than merely designed: **network undetectability** (an observer can't tell you use Privex) and **hiding your IP from the server in transit**. Note the second is distinct from the "ZERO access logs" rule above — the server already refuses to *log* an IP, but not logging an IP is not the same as never *seeing* it, and only the mixnet delivers the latter.
- **Push notifications** without Google/Apple push services — Service Worker push handling needs work.
- **File sharing** — disabled in Phase 1 pending the client-side, zero-knowledge CSAM safeguard (PDQ hashing + PSI + a Groth16 proof); this must ship before files are enabled.
- **Group messaging and calls** (MLS, WebRTC + SFrame) — specified and partly scaffolded, not shipped.
- **Independent review** — the most valuable contribution of all. Read the [security design](SECURITY_DESIGN.md), find the flaw, and report it (see below).

## Local Setup & Development

Privex uses a monorepo structure managed by `pnpm` and Turborepo.

### Prerequisites
- Node.js 20+
- pnpm 9+
- Rust 1.78+ & Cargo
- `wasm-pack` (for compiling `@privex/crypto-wasm`)
- Docker & Docker Compose (for PostgreSQL and Redis)

### Running Locally

1. **Install Dependencies:**
   ```bash
   pnpm install
   ```

2. **Start Infrastructure (Docker):**
   ```bash
   cd infra
   docker compose up -d postgres redis
   ```

3. **Build the Crypto WASM Module:**
   ```bash
   cd packages/crypto-wasm
   wasm-pack build --target web --release
   ```

4. **Start the Backend:**
   ```bash
   cd server
   cargo run
   ```

5. **Start the Frontend Development Server:**
   ```bash
   cd apps/web
   pnpm run dev
   ```

## Submitting a Pull Request

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'feat: add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request against the `main` branch.

All code must pass formatting (`cargo fmt`, `eslint`, `prettier`) and tests before being merged. Ensure that any Rust code includes zeroize calls for memory clearing on sensitive material.

## Found a security issue?

Please don't open a public PR or issue for it first. Report it privately via a [GitHub Security Advisory](https://github.com/Privex-chat/Privex/security/advisories) or the maintainer links in the [README](../README.md), and give a reasonable window to fix before disclosure. Details in [SECURITY_DESIGN.md](SECURITY_DESIGN.md#reporting-a-vulnerability). Serious findings will be credited.
