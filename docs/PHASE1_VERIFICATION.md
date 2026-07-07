# Phase 1 Completion Gate â€" Verification Map

How each Human-Checkpoint item (build guide, Session 20) is verified in THIS codebase,
which deliberately diverges from the guide in a few places (noted inline). Status keys:

- **AUTO** â€" automated + green now (server integration test, or `infra/verify_phase1.sh`).
- **LOGIC** â€" the security-critical logic is unit/integration-tested (web `vitest`) against
  the real WASM crypto; the live-browser run is the remaining human gate.
- **DEFERRED** â€" the feature is Phase-2 / not built by design (reason inline). Cannot pass.
- **INFRA** â€" a human/infrastructure gate (Lighthouse, a real deploy). Cannot be scripted here.
- **DIVERGENCE** â€" the guide assumes something this codebase intentionally does differently.

## Run the automated gate

```bash
# 1. Server: migrations + full integration (registration, PoW replay, offline delivery,
#    ack hard-delete, sealed-sender schema, SPK rotate, rate limit, signed time).
cd server && SQLX_OFFLINE=true cargo test          # 8 lib units + server_end_to_end

# 2. Web: crypto + messaging/receipts/cross-device/time-sync/KT/recovery/app-lock logic.
pnpm --filter @privex/web test                     # 81 tests, 18 files

# 3. Infra + zero-knowledge invariants against the live stack (Docker pg 5432 + redis 6380).
bash infra/verify_phase1.sh                        # 17 checks
```

## MESSAGING

| Item | Status | Verified by |
|---|---|---|
| 1:1 delivery E2E | LOGIC | `messaging.test` (Aâ†'B first msg PQXDH + Bâ†'A reply); integration online delivery |
| Offline delivery (miss â†' reconnect â†' receive) | AUTO | integration: offline â†' queued row â†' reconnect delivery â†' ack |
| TTL-expired hard-deleted from queue | AUTO* | 30-day `expires_at` + `cleanup_expired` sweep + `message_queue::cleanup_expired`. *Per-message `ttl_seconds` override (10 s test) is **DEFERRED** â€" docs 4.12 not built; `message_queue` has a fixed `expires_at`, no `ttl_seconds` column. |
| File transfer 10 MB, SHA-256 after download | LOGIC | `files.test` (multi-chunk encrypt â†' content-addressed â†' reassemble + SHA-256 verify; tamper/mismatch reject); integration blob round-trip |
| Blob deleted after download | AUTO | `blob_index.downloaded` + `mark_downloaded_and_expire(now+24h)` + expiry sweep; harness confirms schema |

## RECEIPTS (docs 4.10)

| Item | Status | Verified by |
|---|---|---|
| "delivered" after Bob receives | LOGIC | `receipts.test` queue-on-receive â†' drain â†' `applyIncomingReceipt` sentâ†'delivered |
| "read" after Bob opens | LOGIC | `receipts.test` viewport `queueReadReceipt` â†' read; full sealed-loop test |
| NOT sent immediately (queued, fires at tick) | LOGIC | `receipts.test`: `not_before â‰¥ queued_at+5s` floor; drain before floor sends nothing |
| Network format identical to a normal message | LOGIC | rides `Content`/`sealAndSend`, same `/messages/send`; wire round-trip test |
| Mutual: disable â†' peer's stop too | LOGIC | `receipts.test`: off kills outgoing request + incoming queue + `applyIncomingReceipt` |

## CROSS-DEVICE (docs 4.11 Mode C â€" OPT-IN, sent-only)

| Item | Status | Verified by |
|---|---|---|
| Tab A â†' appears in Tab B as sent | LOGIC | `device-sync.test`: fan-out on send â†' self-copy â†' receive stores a `sent` row |
| Tab B â†' appears in Tab A | LOGIC | symmetric pairwise keys (same test) |
| Sync indistinguishable from a normal message | LOGIC | the copy is a normal Sealed Sender send to own px_id (test decodes it) |

Note: opt-in (default OFF), **sent-only**, eventually-consistent (one WS per account). INCOMING
messages still land on one device â€" documented in KNOWN_LIMITATIONS.

## SECURITY

| Item | Status | Verified by |
|---|---|---|
| No `sender_id` in POST /messages/send | AUTO | harness Â§4: `message_queue` has no sender/read/delivery column; body = `{recipient_id, content}`; `messaging.test` asserts the sealed blob doesn't contain the sender id |
| KT tampering â†' contact not added | LOGIC | `contacts.test`: tampered field / proof node / root / wrong-pin all throw, nothing stored |
| SPK rotation â†' old token 401 | DIVERGENCEâ†'AUTO | Tokens are HMAC/24h and SPK-independent **by design**; revocation is `/auth/logout_all` (cutoff), tested `token works â†' logout_all â†' 401`. 16E ALSO rotates the SPK on "log out everywhere". "SPK-rotate-alone â†' 401" is intentionally not the mechanism (would kill sessions on routine rotation). |
| PoW replay â†' 400 | AUTO | integration: replayed challenge â†' 400; invalid attempt also consumes it |
| `grep ip_address server/src` â†' 0 | AUTO | harness Â§6 |
| `grep user_id \| tracing::` â†' 0 | AUTO | harness Â§6 (the only false-positive source is the table name `kt_log`) |
| History backup disable â†' all blobs deleted | LOGIC | `history.test` + `routes/history::delete_all` (immediate `DELETE ... WHERE user_id`) |

## POLLING â€" DEFERRED (Phase 2)

`GET /messages/poll` and fixed polling are a **Phase-2 / Nym-gateway** feature (your decision
list + docs 5.7). The constant-traffic goal is met in Phase 1 by **cover-traffic decoys**
(16F, `cover-traffic.ts` + `messaging.sendCoverMessage`) + the 1024-byte padding law, not by a
poll endpoint. The three polling checklist items cannot pass and are not expected to in Phase 1.

## TIME SYNC (docs 9.6)

| Item | Status | Verified by |
|---|---|---|
| Received messages have `server_anchor` | LOGIC | `time-sync.test`: row stores + sorts by the signed anchor |
| Tampered `server_ts_sig` â†' processes + warning | LOGIC | `time-sync.test`: tampered/absent sig â†' no anchor, message NOT dropped, warning latched; integration signs + a tampered ts fails verify |

## SESSION

| Item | Status | Verified by |
|---|---|---|
| SPK rotate â†' old 401 â†' new login works | AUTO | via "log out everywhere" (see SECURITY divergence); integration + `session.test` |
| Close app â†' receive â†' OS notification | DEFERRED | Real closed-app **Web Push was not built** (16E): it needs a Google/Apple subscription + per-user server record = a deanonymization + timing-leak vector. A push/periodic-sync event WAKES an open tab; fully-closed delivery is not guaranteed (esp. iOS). |
| Notification body generic, not content | AUTO | `sw.ts`: title "Privex", body "You have a new message." â€" no sender/preview |

## ACCOUNT RECOVERY

| Item | Status | Verified by |
|---|---|---|
| OPAQUE recovery â†' same px_id | LOGIC | `recovery.test` (seed â†' same identity; OPAQUE key_material round-trip â†' same identity); integration OPAQUE login â†' working token |
| Backup: enable â†' send â†' disable â†' deleted | LOGIC | `history.test` + `routes/history` upload/delete-all |

## INFRASTRUCTURE

| Item | Status | Verified by |
|---|---|---|
| Redis `save` empty, `appendonly` no | AUTO | harness Â§5 |
| Postgres transient tables `relpersistence='u'` | AUTO | harness Â§1 (`kt_log`, `message_queue`, `blob_index`, `group_state`, `pow_challenges`) |
| `history_blobs` `relpersistence='u'` | DIVERGENCE | `history_blobs` is intentionally **LOGGED ('p')** â€" an opt-in backup that vanishes on a Postgres restart is not a backup; the blobs are ciphertext, so WAL only holds opaque bytes (migration 0012). Harness Â§2 asserts 'p'. |
| Lighthouse PWA â‰¥ 90 | INFRA | human (browser Lighthouse run) |
| Deploy to Cloudflare Pages | INFRA | human (`apps/web/dist`) |
| Server on Oracle free tier | INFRA | human |

## Playwright browser E2E â€" not shipped (honest)

A 2-browser suite driving the real app (SharedWorker crypto, WASM behind COOP/COEP,
difficulty-22 onboarding PoW, live Rust server + pg + redis) cannot be authored AND
verified green in this environment â€" shipping tests that can't be run green violates the
project's "green before done" rule. The security-critical LOGIC those tests would exercise
is already covered by the `vitest` suite above against the real WASM; the live-browser run
(the checkboxes marked LOGIC) is the documented human gate. Server-side security cases
(PoW replay, sealed-sender schema, SPK/token revocation, KT tamper, rate limit, signed time)
ARE automated in `server/tests/integration.rs` and `infra/verify_phase1.sh`.
