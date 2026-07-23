# Privex

![Status](https://img.shields.io/badge/status-Phase_1_beta-4f74b8) ![License](https://img.shields.io/badge/license-AGPL--3.0-2f8f57) ![PQC](https://img.shields.io/badge/crypto-post--quantum_hybrid-6b93d6) ![Audit](https://img.shields.io/badge/audit-none_yet-c9a24a)

**A messenger built on one hard promise — the server can't read your messages or tell who you are — and one hard goal it's built toward: a network that can't even prove you were there.**

- **Live beta:** [privex.chat](https://privex.chat)
- **How it works, visually:** [wiki.privex.chat](https://wiki.privex.chat) — every page in plain language *and* full technical detail, with interactive diagrams
- **The code:** this repository, open under AGPL-3.0-or-later

---

## Why this exists

Most "private" messengers protect the *message*. Privex is built to protect the fact that a conversation happened at all.

That difference is not academic. People have been found — and some have died — not because anyone broke their encryption, but because someone saw *who* they were talking to, *when*, and *from where*. A phone number tied to an account. An IP address sitting in a log. A quiet request to the company that happened to have the answer. The content stayed encrypted the whole time. It didn't matter. The metadata was enough.

If you are a journalist in a hostile country, "they can read the words" is not your worst case. "They can prove you spoke to a source, then knock on your door" is. Almost every messenger on the market answers the first threat and waves away the second, usually with some version of *"well, use a VPN."* A VPN is a company you're now also trusting, with your real IP, one subpoena away.

Privex starts from the opposite assumption. **Assume the server gets hacked. Assume the network is watched. Assume the operator is served a court order.** Design so that none of those give up anything useful, because there is nothing useful to give up. Privacy shouldn't depend on the operator's good behaviour or on a promise in a terms-of-service page. It should be a property of the math.

---

## What Privex is

A zero-knowledge, end-to-end encrypted messenger — web-first today, with Android, iOS, and desktop to follow. No phone number. No email. No name. You create an identity that exists only on your device, and the server only ever sees random-looking blobs addressed to random-looking IDs.

"Zero-knowledge" here is not a slogan. The server is **architecturally blind, not policy-blind** — it isn't that Privex *chooses* not to look, it's that the design leaves nothing to look at.

### The four laws it's built around

```text
Law 1  The server CANNOT read content.        (not "does not" — cannot)
Law 2  The server CANNOT identify users.       (no name, phone, email, or IP — ever)
Law 3  The server CANNOT trace relationships.  (it can't tell who talks to whom)
Law 4  The network CANNOT confirm Privex is even being used.
```

Laws 1–3 are the bar a serious private messenger should already clear. **Law 4 is the one almost nobody attempts** — making Privex traffic indistinguishable from ordinary encrypted traffic, so that a network observer can't even tell you opened the app. That's the design goal the whole transport layer is bending toward (see *Status* below for what's live today versus in progress).

---

## How it compares

Honest version. Every app in this table is a real, serious effort, and some of them are more battle-tested than Privex is — that matters, and it's in the table too. What Privex is trying to do is put the *whole* set of properties in one place, and take the network layer further than the rest.

| | WhatsApp | Signal | SimpleX | Session | **Privex** |
|---|:---:|:---:|:---:|:---:|:---:|
| Content end-to-end encrypted | ✓ | ✓ | ✓ | ✓ | ✓ |
| No phone number required | ✗ | ✗ | ✓ | ✓ | ✓ |
| No account identifier at all | ✗ | ✗ | ✓ | ✓ | ✓ |
| Server can't see the sender | ✗ | ✓ | ✓ | ✓ | ✓ |
| IP hidden from the server | ✗ | ✗ | via Tor | ✓ | ✓ (Nym) · *in progress* |
| Network can't tell you use it (Law 4) | ✗ | ✗ | partial | partial | ✓ *by design* · *in progress* |
| Post-quantum cryptography | ✗ | partial (key exchange) | double ratchet | ✗ | **full hybrid: identity + key exchange** |
| Zero-knowledge account recovery | weak cloud backup | device backup only | you hold the keys | seed phrase | ✓ (password / social / seed) |
| Open source | ✗ | ✓ | ✓ | ✓ | ✓ (AGPL) |
| **Audited / battle-tested** | ✓ | ✓✓ **gold standard** | some | some | **✗ — not yet** |

Read that last row first. **Signal is the gold standard for a reason** — years of audits, a protocol the entire industry copied, and a track record under real pressure. Privex has none of that yet. It is early, it is one person, and it has not been through a security audit. If you need something proven *today*, use Signal.

What Privex offers is a different *architecture* — and, on paper, a more complete one:

- **It goes after the network layer, not just the message.** Signal and WhatsApp still hand your IP and your connection timing to their servers; their answer to metadata is "trust us not to keep it." Privex is built to route through the [Nym mixnet](https://nymtech.net) so the server never sees your IP and a global observer can't correlate your traffic. Session does onion routing; SimpleX leans on Tor; Privex makes the mixnet the default transport. *(This is the headline in-progress piece — until it lands, the server still terminates your connection over TLS. See Status.)*
- **Post-quantum from the identity up.** Signal's PQXDH adds post-quantum protection to the initial key exchange; that's real and good. Privex uses a hybrid of X25519 **and** Kyber-1024 for key agreement *and* Ed25519 **and** Dilithium3 for every identity signature — so a future quantum computer breaks neither your sessions nor your identity. "Harvest now, decrypt later" fails against it from day one.
- **You can actually get your account back.** Most private messengers make you choose between security and recovery: lose your device, lose everything (Signal, Session), or manage raw keys yourself (SimpleX). Privex gives you three zero-knowledge recovery paths — an OPAQUE password envelope the server can never open, social recovery split across trusted contacts (Shamir), and a seed phrase — without the server learning anything.
- **It's meant to be usable.** The privacy community is full of tools that are excellent and unusable. Privex is trying to feel like a normal chat app your less-technical contact can install, because a privacy tool nobody can use protects nobody.

SimpleX deserves specific credit: its "no user identifiers at all" model is genuinely excellent, and if metadata is your only concern it's a superb choice. Privex's bet is that adding full-stack post-quantum crypto, mixnet transport, *and* real account recovery — in one app that a normal person can use — is worth building.

---

## Who this is for — right now

The mission is the people at the sharp end: journalists, whistleblowers, activists, anyone whose safety can depend on a conversation staying invisible. That is who Privex is *for*.

It is not yet who Privex is *ready for*. Phase 1 is unaudited, the mixnet that delivers Law 4 isn't wired in, and one person cannot see every flaw in their own design. So today, honestly, this is for **builders, auditors, and funders** — people who can read it, break it, and help pay for the infrastructure and independent review it needs before anyone should trust it with their life.

**If you are at risk today, use [Signal](https://signal.org).** It's proven, and proven is what you need. If you want to help build the thing that goes further — the thing a source could one day use without the network ever knowing they reached out — then you're in the right place. That's the entire ask: **help me earn the right to say "yes, use this."** Funding and audits are what turn this from a serious design into something a life can rest on.

---

## How it works (the short version)

- **Identity** is a set of keypairs generated on your device. Your public ID is `px_` + the first 16 bytes of `SHA-256(your signing key)`. The server stores that ID and your public keys. Nothing else.
- **Messages** use Signal's audited [PQXDH + Double Ratchet](https://signal.org/docs/) implementation (via `libsignal`), wrapped in **sealed sender** so the server sees a recipient and a blob, never a sender.
- **Abuse is priced in CPU, not identity.** Rate-limiting by IP means logging IP addresses, so Privex doesn't do it. Public endpoints instead require a **proof-of-work** puzzle — Hashcash SHA-256 with a memory-hard Argon2id layer on top — so flooding costs an attacker CPU, not you your anonymity.
- **The server is a dumb, forgetful relay.** Offline messages sit in an `UNLOGGED` Postgres table with a time-to-live and are hard-deleted on delivery. No access logs, no analytics, and **no IP is ever logged or stored**. (Hiding your IP from the server *in transit* is the mixnet's job — Phase 2; see Status.)
- **Everything sensitive happens in your browser**, in WebAssembly and the Web Crypto API. Keys are non-extractable; local data is encrypted in IndexedDB.

The full picture — storage, flows, cryptography, threat model, and what an attacker actually gets if they seize the servers — lives in the visual wiki:

**→ [wiki.privex.chat](https://wiki.privex.chat)** *(there's a Plain/Technical switch in the top bar; start in Plain, flip to Technical when you want the exact tables and algorithms.)*

---

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | The full system: crypto, transport, server, recovery, lifecycle |
| [Security & Privacy Design](docs/SECURITY_DESIGN.md) | Threat model, guarantees, what we do *not* claim, and how to attack it |
| [API Reference](docs/API_REFERENCE.md) | Server endpoints |
| [Contributing](docs/CONTRIBUTING.md) | How to help, and where help is most needed |
| [The visual wiki](https://wiki.privex.chat) | Everything above, illustrated, plain + technical |

---

## Status — where this honestly is

Privex is in **Phase 1: the web app foundation.** A lot works. A lot is deliberately not finished. Being straight about which is which is the whole point of open-sourcing early.

**Working today**
- 1:1 messaging with Double Ratchet and full hybrid post-quantum crypto (Kyber-1024 / Dilithium3)
- Sealed sender, so the server never learns who sent what
- Offline delivery via an unlogged, TTL'd server queue with per-message "delete if undelivered after…" controls
- Zero-knowledge account recovery: OPAQUE password, Shamir social recovery, and seed phrase — all live
- Server-signed timestamps that let the client detect message-reordering and desync attacks
- Proof-of-work registration and rate limiting, so no endpoint uses or logs your IP
- Delivery/read receipts with no timestamps and jittered sending, cross-device sync, an installable PWA, an in-app safety-code verification flow, and a full settings/recovery UI

**In progress / not done — this is where help matters most**
- **Nym mixnet transport (Law 4).** This is the headline. The client today talks to the server over WebSockets; the Nym worker is a skeleton. Wiring the full mixnet gateway path is the flagship Phase 2 deliverable, and it's what turns "designed to be undetectable" into "is undetectable."
- **File sharing** is disabled in Phase 1, pending client-side, zero-knowledge CSAM protection (see the architecture doc) — because a tool this private has a duty not to become a distribution channel for that.
- **Push notifications** without Google/Apple push services still need work.
- **Group messaging and calls** (MLS, WebRTC + SFrame) are specified and partially scaffolded, not shipped.

**The honest caveat:** Privex has **not been audited.** It is built and maintained by one person. Do not yet trust it with a life. Trust it enough to read it, test it, break it, and tell me what's wrong — that's exactly what this stage is for.

---

## Why I'm building it

I'm 18. I'm not in university yet. Privex is two years of me reading papers on mixnets, post-quantum crypto, and zero-knowledge systems, and then trying to actually *build* the thing those papers describe instead of just admiring it.

I kept running into the same story: someone who did everything "right," used the "secure" app, and was still found — because the app protected their words but not their pattern of life, and nobody had planned for the server or the network being the adversary. The privacy world talks a lot about encryption and surprisingly little about the harder problem: making the *existence* of a conversation invisible, and assuming your own infrastructure will be compromised.

So I'm building the app I couldn't find. One person, self-funded, on borrowed infrastructure, until this reaches the people and the funding that can take it the rest of the way — through the audits and the scrutiny it will need before anyone should stake their safety on it. That's the plan, in order: build it honestly, open it up, earn the trust the hard way.

If that resonates, the best thing you can do is look closely and be hard on it.

---

## Contributing

Privex needs more eyes far more than it needs more features. Whether you do cryptography, Rust, TypeScript, threat modeling, design, or documentation — or you just want to try to break it — there is room here, and the [Contributing guide](docs/CONTRIBUTING.md) shows where the gaps are.

Two ways to help that are worth more than they sound:
- **Audit and attack it.** Read the [Security Design](docs/SECURITY_DESIGN.md), find the hole, open an issue. Responsible disclosure details are in that doc.
- **Tell people it exists.** Reach is the bottleneck for a solo project. If the idea is worth building, it's worth boosting.

Privex is **Copyright © 2026 Hemansh**, released under **AGPL-3.0-or-later** ([LICENSE](LICENSE)): free to use, study, modify, and self-host. The AGPL's network clause (§13) is the catch — if you run a **modified** version as a network service, you must offer its users the corresponding source. The **Privex name and branding** are protected separately ([TRADEMARK.md](TRADEMARK.md)) so that "Privex" always means this specific, accountable project.

---

## Support & funding

Privex runs on temporary infrastructure with no external funding. It has been submitted for [Open Technology Fund](https://www.opentech.fund/) support, and it is looking for sponsors, contributors, and the kind of scrutiny that turns a promising design into a trustworthy one.

- 💖 [Sponsor Privex on GitHub](https://github.com/sponsors/Privex-chat)
- 🔗 Founder: [Hemansh (LinkedIn)](https://www.linkedin.com/in/sonixaep/)
- 🐙 [Privex-chat/Privex](https://github.com/Privex-chat/Privex)

If you believe communication should be something no server, no network, and no government can quietly turn against you — help me get this to the point where it's ready to prove it.
