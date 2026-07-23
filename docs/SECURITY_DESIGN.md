# Privex — Security & Privacy Design

This document is the honest version of Privex's security story: what it defends against, how, what it deliberately does **not** claim, and where it stands today. It's written for the people who should be hardest on it — auditors, cryptographers, and anyone deciding whether to trust it with something that matters.

If you find something wrong here, that is the most valuable contribution you can make. See [Reporting a vulnerability](#reporting-a-vulnerability) at the end.

> **Status, up front:** Privex is a Phase-1 beta, built and maintained by one person, and it **has not been through a security audit.** The design below is what the system is engineered to do; independent verification that it *does* is exactly what this stage is asking for. Do not yet stake a life on it.

Companion reading: the [Architecture](ARCHITECTURE.md) doc for the full system, and the visual [wiki](https://wiki.privex.chat) — its **threat-model** and **seizure** pages walk through this material with diagrams, and every section has a Plain and a Technical view.

---

## 1. The core assumption

Most systems are designed to keep the operator honest. Privex is designed so the operator's honesty doesn't matter.

The working assumption behind every decision is: **the server will be compromised.** Hacked, subpoenaed, seized at the data center, or run by someone who has quietly turned. Privex is only meaningfully private if all of those change nothing — so the server is treated as an untrusted relay that is *cryptographically blind*, not policy-blind. It doesn't decline to look at your data; it is built so there is nothing to look at.

Three principles follow from that:

1. **No custom cryptography.** Privex invents zero new primitives. It composes audited, standard building blocks (Signal's `libsignal`, `libsodium`, `liboqs`, OPAQUE, Shamir's Secret Sharing). Novel crypto is how privacy tools get quietly broken; Privex's novelty is entirely in the *architecture*, never in the math.
2. **The client holds everything; the server holds nothing it can read or link to a person.** All keys are generated and stored on the device. The server sees only random-looking ciphertext addressed to pseudonymous IDs — never content, and never a real identity.
3. **Metadata is the real threat.** Encrypting content is table stakes. The hard, neglected problem — who talked to whom, when, from where, and whether they used the app at all — is where Privex spends most of its design budget.

---

## 2. Cryptographic foundations

The two layers that establish trust — **identity signatures and key agreement** — are each a **hybrid of a classical and a post-quantum primitive**, so an attacker must break *both* to win: a quantum computer breaks the classical half and gains nothing, and a classical attacker breaks neither. (Symmetric encryption doesn't need a second primitive — AES-256 and XChaCha20 keep roughly 256-bit strength against Grover — and OPAQUE and Shamir's Secret Sharing are classical.)

| Purpose | Classical | Post-quantum | Library |
|---|---|---|---|
| Identity signatures | Ed25519 | CRYSTALS-Dilithium3 (ML-DSA) | libsodium / liboqs |
| Key agreement (KEM) | X25519 | CRYSTALS-Kyber-1024 (ML-KEM) | libsignal (PQXDH) / liboqs |
| Session ratchet | Double Ratchet (X25519) | keys seeded by the PQ handshake | libsignal |
| Symmetric encryption | AES-256-GCM, XChaCha20-Poly1305 | (256-bit; Grover-resistant) | libsodium |
| Password recovery | — | OPAQUE (aPAKE) | OPAQUE-ke |
| Social recovery | Shamir's Secret Sharing (2-of-3) | — | libsodium |

Post-quantum protection is present **from the identity up**, not only at the key exchange. This is the deliberate difference from messengers that add a PQ KEM to the handshake but keep classical-only identity keys: against Privex, "harvest now, decrypt later" fails, and so does "harvest now, forge identity later."

---

## 3. Adversary model

Privex is designed against a stack of adversaries, from the coffee-shop network up to a nation-state. For each, the question is the same: *what do they actually get?*

**Passive network observer** (ISP, DNS provider, Wi-Fi operator)
Wants to know you use Privex and read/correlate your traffic. The design defends this with DNS-over-HTTPS to a pinned resolver, transport through the Nym mixnet (fixed-size Sphinx packets, Poisson mixing delays), and constant cover traffic → *once the mixnet is live, a global observer sees indistinguishable mix-network packets, not Privex traffic, and correlating your send with anyone's receive becomes computationally infeasible (reduced, not provably zero — see [§7](#7-what-privex-does-not-protect-against)).* **Today the mixnet is not yet wired in: the client connects to the server directly over TLS, so the server sees your transport (peer) IP in transit — it never logs or stores it, but it does see it — and a network observer can tell you are talking to Privex. Wiring the mixnet is the flagship Phase-2 work (see [§8](#8-current-status-and-known-limitations)).**

**Active network attacker** (man-in-the-middle)
Wants to intercept, modify, or inject. Defended by TLS 1.3, certificate pinning, HKDF-authenticated message keys (HMAC), and — for calls — DTLS-SRTP plus SFrame. Identity is confirmed out-of-band by comparing safety codes. → *Cannot inject or alter content without detection.*

**Compromised Privex server** (hacked, insider, or coerced operator)
Has full read/write access to the database and running code. It holds only pseudonymous data: recipient IDs (`px_…`), fixed-size encrypted blobs, delivery timestamps, and the public-key directory. No message content, no sender (sealed sender), no stored IP, no real identities. → *A full database dump reveals no content and nothing that ties to a human. It does expose pseudonymous metadata — which IDs are active and when, padded message sizes, public keys — which supports limited traffic analysis, but not deanonymization on its own.*

**Nation-state with legal authority** (subpoena, gag order, seizure)
Can compel the operator to hand over everything it has. The point is that "everything it has" is pseudonymous IDs, unreadable blobs, and timestamps. Key material never leaves user devices, so a valid court order reaches no message content and no user identity. → *Legal compulsion can't produce what a person said or who they are — only the pseudonymous, unlinkable metadata above. There is no plaintext and no identity to hand over.* The [wiki's seizure page](https://wiki.privex.chat) enumerates exactly what each layer yields.

**Data-center / host** (physical access, RAM dumps, NIC capture)
Sees connections arriving from mix-network gateways, not from users; storage is encrypted at rest; a RAM dump reveals encrypted buffers and session tokens, not identities. → *Cannot deanonymize a user or read a message.*

**Future quantum computer**
Breaks RSA/ECDH/ECDSA. Privex's hybrid PQC means every session and every identity also depends on Kyber and Dilithium, which it doesn't break. → *Even retroactively, captured traffic stays sealed.*

**Compromised endpoint** (malware on the user's device)
This is the honest edge. Privex uses non-extractable WebCrypto keys, memory zeroing, and hardware-backed storage where the platform allows it, plus screen-blur when the app loses focus. But **kernel-level malware with root on your own device is out of scope for any software** — if the attacker is already inside the machine reading your screen, no messenger can save you. → *Best effort, not a guarantee, and we say so.*

---

## 4. What the server can and cannot see

| The server sees | The server never sees |
|---|---|
| A pseudonymous recipient ID (`px_…`) | Your name, phone, or email |
| A fixed-size (padded) ciphertext blob | The message content |
| A delivery timestamp | Who sent it (sealed sender) |
| Your public keys (in the key directory) | Your IP address (ever, anywhere) |
| | Your social graph / contact list |
| | Whether two IDs are the same person |

There are **no access logs, no analytics, and no telemetry** anywhere in the stack. Offline messages live in an `UNLOGGED` Postgres table with a time-to-live and are hard-deleted on delivery.

---

## 5. Metadata and network protection

- **Sealed sender** moves the sender's identity inside the encrypted payload. The server learns a recipient and nothing about who's talking to them.
- **Nym mixnet transport** (Loopix-style): fixed-size Sphinx packets, per-hop Poisson delays, and continuous loop cover traffic, designed so a *global* passive adversary watching the whole network can't correlate a send with a receive. This is the property (network undetectability) that separates Privex from onion routing alone. **It is designed but not yet wired in — see [§8](#8-current-status-and-known-limitations); it's the single biggest gap between the design and today's build.**
- **No IP logged, ever.** Privex never records IP addresses anywhere; rate-limiting uses proof-of-work and pseudonymous HMAC buckets instead of IP (see §6). Preventing the server from *seeing* your IP in transit is the mixnet's job (Phase 2, §8).
- **Server-signed time.** Delivery order is anchored to a server-signed timestamp, so a malicious relay can't silently **reorder** your messages or forge their ordering without the client detecting it. (A *dropped* message surfaces as a gap in the Double Ratchet's message counters, and *replay* is blocked by its single-use message keys — those are the ratchet's job, not the timestamp's.)
- **Receipts leak nothing.** Delivery/read receipts carry no timestamp, are mutual (you can't receive them without sending them), and are jittered onto the cover-traffic schedule so they can't reveal when you came online.

---

## 6. Proof-of-work rate limiting (no IP required)

Traditional abuse prevention logs IP addresses. Privex refuses to, so it prices abuse in CPU instead of identity.

**How it works**
1. To hit a public, target-revealing endpoint, the client first requests a challenge (`POST /auth/pow_challenge`).
2. It solves a Hashcash puzzle — `SHA-256(challenge || nonce)` to a difficulty in leading zero bits — in the browser via WebAssembly. SHA-256 Hashcash is the always-on baseline; on top of it a **memory-hard Argon2id layer** (enabled by default via `POW_ARGON2_ENABLED`, with an emergency off-switch) denies GPU/ASIC farms a cheap advantage.
3. The server verifies the proof, consumes it single-use, and processes the request.
4. Difficulty scales with aggregate load: a flood raises the cost for everyone automatically, throttling attackers while ordinary use stays cheap.

**PoW-gated endpoints** (anything that could reveal a target user exists or drain their one-time prekeys):
`POST /keys/register` · `POST /keys/{user_id}` · `POST /keys/kt/proof/{user_id}` · `POST /recovery/opaque/init`

Authenticated actions (like sending a message) skip PoW; they're rate-limited per-user via a pseudonymous HMAC of the session token, which keeps the zero-knowledge property intact.

---

## 7. What Privex does *not* protect against

A security tool that won't name its limits shouldn't be trusted. Privex does **not** protect against:

- **A compromised endpoint** with root/kernel malware. If your device is owned, so are your plaintext messages.
- **Physical coercion of you.** No app defeats a wrench, or a border agent who makes you unlock the screen.
- **A malicious recipient.** Anyone you message can screenshot, save, or repeat what you send. End-to-end encryption ends at *their* end.
- **Voluntary exposure.** If you share your identity or messages, that's outside the model.
- **Legal risk in your own jurisdiction.** Privex provides *technical* privacy, not legal immunity. It can make your data impossible to produce; it can't make an activity legal where you are.
- **Traffic-analysis perfection.** Mixnet delays plus cover traffic narrow the correlation window dramatically but don't provably close it to zero. This is an acknowledged, industry-wide hard limit, not a solved problem.

---

## 8. Current status and known limitations

Being specific here is the point of open-sourcing before it's finished.

- **Not audited.** No third party has reviewed this yet. Treat every claim in this document as *designed, not verified*.
- **Nym transport is not fully wired.** Today the client reaches the server over WebSockets; the Nym worker is a skeleton. Until the mixnet path is live, the **Law 4 / network-undetectability** and **IP-hidden-from-server** properties are architectural intent, not shipped fact. This is the top Phase-2 priority.
- **Solo-maintained.** One person's blind spots are real. Independent review is the mitigation, and it's wanted.
- **File sharing is disabled** in Phase 1 pending client-side, zero-knowledge CSAM protection (PDQ perceptual hashing + OPRF-based PSI + a Groth16 proof the server can verify without seeing the file or the hash). A messenger this private has a duty not to become a safe distribution channel for abuse material; shipping that safeguard is a precondition for enabling files.
- **Groups and calls** (MLS, WebRTC + SFrame) are specified and partly scaffolded, not shipped.

---

## Reporting a vulnerability

If you find a flaw — a broken assumption, a metadata leak, a crypto misuse, anything — please report it privately first:

- Open a **GitHub Security Advisory** on [Privex-chat/Privex](https://github.com/Privex-chat/Privex/security/advisories), or
- Reach the maintainer through the links in the [README](../README.md).

Please give a reasonable window to fix before public disclosure. There's no bounty program yet (no funding yet), but serious findings will be credited, and they genuinely move this project forward more than any feature could.
