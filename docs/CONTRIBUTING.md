# Contributing to Privex

Welcome! Privex is currently in Phase 1 of development. We invite contributions from the open-source community to help build the most private, secure, and resilient communication platform in the world.

Please note that this repository operates under a Custom EULA (see `LICENSE`) that permits contributions via Pull Requests but explicitly denies the reuse, copying, or selling of the codebase or its architecture for other products.

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
- E2E 1:1 text messaging
- Offline message delivery queue
- PWA structure
- Rust/Axum backend with UNLOGGED PostgreSQL tables
- WebCrypto non-extractable master key & IndexedDB storage

### Missing / Help Wanted
We actively need help with the following Phase 1 deliverables:
- **Nym Integration:** The Nym SDK/mixnet is planned but not yet implemented (we currently use direct WebSockets).
- **Session Management:** Fixes needed for token invalidation during SPK rotation.
- **Push Notifications:** Service Worker is registered, but push event handling is broken.
- **Time Synchronization:** Need to implement server-signed timestamps to prevent desync attacks.
- **Cross-Device Sync:** Sent messages from Device A do not yet appear on Device B.
- **Delivery & Read Receipts:** Needs to be implemented securely without timing correlations.
- **File Sharing:** Disabled up until Phase 2 for CSAM check implementations.
- **Timing Mitigations:** Polling schedules, fetch size padding, and jittered receipt sending.

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

1. Fork the repository (for the purpose of contributing back only).
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'feat: add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request against the `main` branch.

All code must pass formatting (`cargo fmt`, `eslint`, `prettier`) and tests before being merged. Ensure that any Rust code includes zeroize calls for memory clearing on sensitive material.
