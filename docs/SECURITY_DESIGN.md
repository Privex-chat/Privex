# Privex Security & Privacy Design

Privex is engineered from the ground up to be mathematically unable to compromise its users. Its security model assumes that the server is completely untrusted and potentially compromised.

## Threat Model

Privex defends against several categories of adversaries:

- **Passive Network Observer (ISP, DNS, Wi-Fi):** Defeated by DNS over HTTPS (DoH), Nym mixnet routing, and cover traffic. They cannot confirm if a user is communicating via Privex.
- **Active Network Attacker (MITM):** Defeated by TLS 1.3, DTLS-SRTP, SFrame, and strict certificate pinning.
- **Compromised Privex Server:** The server stores only encrypted blobs and pseudonymous IDs. It has no access to IPs, social graphs, sender identities, or message content.
- **Nation-State with Legal Authority:** Technical privacy makes producing user data impossible. There is simply no plaintext data or metadata to hand over.
- **Future Quantum Computer (Q-Day):** Defeated by hybrid Post-Quantum cryptography on all key exchanges (Kyber/ML-KEM) and signatures (Dilithium3/ML-DSA).
- **Compromised Endpoint Device:** Privex provides best-effort protection (using WebCrypto non-extractable keys and secure enclaves where applicable), but root/malware access to the device is inherently out of scope.

## Privacy Guarantees

- **Zero-knowledge architecture:** The server cannot read content, identify users, or trace relationships.
- **Metadata Resistance:** Traffic analysis is mitigated using the Nym mixnet with Poisson delays, Sphinx packets, and constant loop cover traffic.
- **IP Protection:** IP addresses are never logged. Rate limiting is handled via Proof-of-Work (PoW) and pseudonymous HMAC buckets instead of IP tracking.
- **CSAM Protection (Phase 2):** Client-side perceptual hashing (PDQ) combined with OPRF-based Private Set Intersection (PSI) and ZK proofs (Groth16). The server verifies proofs without ever seeing the file content or the image hashes.

## Proof-of-Work (PoW) Rate Limiting

Because Privex refuses to log IP addresses (Absolute Law #3), it cannot use traditional IP-based rate limiting to prevent abuse. Instead, Privex uses a dynamic Hashcash SHA-256 Proof-of-Work system.

### How it Works
1. When a client wants to hit a public, target-revealing endpoint, it requests a PoW challenge (`POST /auth/pow_challenge`).
2. The client must solve `SHA-256(challenge || nonce)` to a specific difficulty (leading zero bits) natively in the browser via WebAssembly.
3. The server verifies the nonce and processes the request.
4. The difficulty scales dynamically based on aggregate network requests. A flood of requests automatically raises the difficulty for everyone, throttling attackers while keeping regular users functional.

### PoW-Gated Endpoints
PoW is specifically applied to public endpoints where a request might reveal information about a target user (e.g., existence or OPK supply):
- `POST /keys/{user_id}`
- `POST /keys/kt/proof/{user_id}`
- `POST /recovery/opaque/init`
- `POST /keys/register`

Authenticated endpoints (like sending messages) do not require PoW because they are rate-limited per-user using a pseudonymous HMAC of their session token, which preserves zero-knowledge.
