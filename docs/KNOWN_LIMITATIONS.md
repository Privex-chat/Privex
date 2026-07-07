# Privex â€" Known Limitations (Phase 1)

Honest, deliberate constraints of the Phase 1 web app. None of these weaken the
Absolute Laws (no plaintext, no IP, no access logs, no custom crypto); they are
trade-offs of the web platform and the zero-knowledge architecture.

## Transport / delivery

- **Phase 1 uses a direct WebSocket.** The client connects straight to the API host,
  so an on-path observer (ISP) can see *that* you connect to the Privex server and
  when. Content, sender, contacts, and message timing are still protected (TLS +
  Sealed Sender + no server logs), but the connection endpoint itself is visible.
  Nym mixnet routing (which hides even that) is **skeleton in Phase 1** â€" the client
  worker + gateway wiring land in Phase 2. This is the single biggest Phase-1 metadata
  gap and it is deliberate/known.
- **Cover traffic IS active in Phase 1** (application level): a constant Poisson stream
  of fixed-size (1024-byte) sealed decoy sends (docs 5.3/5.7, `services/cover-traffic.ts`)
  so an observer can't infer real activity from your traffic. *Nym-level* loop cover
  traffic is the Phase-2 addition. (Correction to the build-guide checklist, which
  described cover traffic as "skeleton" â€" that was true before this pass, not now.)
- **Audio/video calls are not implemented** (Phase 3). The call UI is a placeholder;
  no WebRTC/SFrame yet.
- **TURN relay IP exposure during calls** (Phase 3, when calls exist): a WebRTC TURN
  relay sees both peers' IPs, the same accepted trade-off as Signal. Not applicable
  in Phase 1 (no calls).
- **iOS background notifications.** iOS Safari has no APNs-free push for PWAs and
  heavily limits background execution. On iOS, messages arrive reliably only while
  the app/tab is open. Android/desktop get Web Push that *wakes* a tab to fetch +
  decrypt (the Service Worker itself can't decrypt â€" it holds no key/token), so the
  push notification is generic ("New message") until a tab opens.
- **Nym mixnet latency.** When routed through the Nym mixnet (default for metadata
  protection), messages incur ~300â€"800 ms of added latency by design. Direct mode
  is faster but reveals less-protected metadata to the relay.
- **Relay network is small.** The onion/relay network is a limited set of nodes
  (3-hop circuit). Anonymity-set size grows with adoption; early on it is small.

## Recovery / multi-device

- **Message history is not recoverable from identity alone.** Seed-phrase and OPAQUE
  password recovery restore your *identity and contacts* (same `px_id`), never past
  message bodies â€" they live only on devices (forward secrecy). To move history to a
  new device use either: (A) opt-in encrypted server backup, or (B) device-to-device
  transfer. Both are history-COPY, not live cross-device sync.
- **Cross-device sync is SENT-messages-only, opt-in, and eventually-consistent.**
  With the opt-in "Cross-device sync" setting on (both devices, linked during a
  transfer), messages you SEND are copied to linked devices as self-addressed
  encrypted messages. Three honest limits of the Phase 1 single-mailbox model:
  (1) the account has ONE WebSocket - the device holding it gets sync copies live,
  others on their next (re)connect; (2) a copy addressed to another device is left
  un-acked, so every other device re-receives (and re-ignores) it on each reconnect
  until the target consumes it (30-day TTL bound); (3) INCOMING messages still land
  on whichever device acks first - fanning those out needs per-device mailboxes,
  which would let the server count your devices, so it is deliberately deferred.
  The self-addressed copies are unreadable to the server but are a visible traffic
  pattern (sender == recipient) - the reason the feature is off by default.
- **Recover-via-contacts (Shamir) retrieval is setup-only.** Shares can be stored
  (sealed to contacts), but retrieval needs a relationship-free share rendezvous the
  server intentionally lacks (no social graph). Deferred rather than weaken privacy.

## Message requests (opt-in contacts)

- **The first message is decrypted before you accept.** Sealed Sender means the
  sender is unknown until the blob is decrypted, and the server queue is acked on
  receipt (no redelivery) â€" so the request's message is decrypted and stored locally
  (encrypted at rest) rather than dropped. This is the Signal "message request"
  model: *reading* the request is the informed-consent step; *replying* is blocked
  (service layer + UI) until Accept, and Decline purges the contact, session,
  messages, and any queued outbox rows. A crafted first message still exercises the
  decrypt path (protobuf/ratchet parsing) before the user decides â€" the parser
  surface is the wasm crypto module, not the UI.
- **Declined messages already backed up are not retroactively removed.** If opt-in
  history backup is enabled, a request's message may have been uploaded (encrypted)
  before the decline; it stays in the server backup until "Delete backup". Future
  backfills won't re-include it (the local rows are purged).

## App lock

- **Short numeric PIN is not offline-brute-force-proof.** The passphrase factor wraps
  the data key with Argon2id (32 MiB, t=3) â€" strong, but a *short* secret copied from
  device storage can still be ground down offline. The truly un-brute-forceable factor
  is the biometric/WebAuthn-PRF option (the secret lives in the hardware authenticator,
  OS-rate-limited). Use a real passphrase and/or enable biometrics; a minimum length is
  enforced. WebAuthn-PRF requires a platform authenticator (Touch ID / Windows Hello /
  Android biometric) on a supported browser.
- **In-app attempt backoff is advisory.** It deters on-device guessing; an attacker who
  copies IndexedDB and guesses offline is bounded only by Argon2id (above), not the
  counter.
- **Locking makes the app inert, not just hidden.** On lock the in-memory data key is
  dropped AND the live session is torn down: the WebSocket is disconnected, cover
  traffic stops, the session token + cached decrypted identity are cleared, and the
  offline outbox won't flush. So a locked device transmits nothing and holds no keys
  or session credential in memory - it isn't merely a screen over a live session.
  Inbound messages sent while locked are held server-side (30-day queue) and delivered
  when you unlock (re-auth â†' reconnect â†' decrypt + persist), never silently dropped.
  Re-lock also fires on bfcache restore and on the Page-Lifecycle freeze event so a
  backgrounded PWA/tab can't return showing decrypted content. RESIDUAL (unavoidable in
  a browser): while UNLOCKED, decrypted data is in JS memory; a full memory dump of the
  live/frozen process is out of scope (same ceiling as any client-side E2EE app).

## Server / auth model (deliberate divergences from the build guide)

- **SPK rotation does NOT revoke session tokens (and vice-versa is intentional).**
  Tokens are HMAC + 24 h TTL, independent of the signed prekey. Revocation is the
  explicit "log out everywhere" (`POST /auth/logout_all`), which sets a per-user
  cutoff that `AuthUser` enforces on every request â€" instantly killing every
  device's token. "Log out everywhere" ALSO rotates the SPK (forward secrecy: a
  future PQXDH init can't target the old prekey a seized/other device may hold),
  but *routine* replenish-driven SPK rotation stays decoupled and never logs
  anyone out. We deliberately did NOT adopt the build guide's spk_version-in-token
  scheme â€" it would log every device out on routine ~monthly rotation.
- **"Log out everywhere" â‰  local wipe; "Erase this device" is the local reset.**
  Token cutoff is server-side: it kills in-flight tokens on all devices, but a
  device that still holds the identity key re-authenticates on its next boot (the
  key is the credential â€" no password needed on the same device), and its local
  IndexedDB (messages/contacts) is untouched. So "log out everywhere" is a session
  security action (revoke leaked tokens + rotate the SPK), NOT a data wipe. The
  destructive local reset is a SEPARATE, explicit **"Erase this device"** action
  that deletes all local data + the identity + key material â†' clean onboarding.
  It is IRREVERSIBLE without recovery (seed phrase / OPAQUE password / server
  backup), so it takes a two-step confirm.
  - **Wipe is never automatic.** It runs ONLY from that button â€" never from a 401,
    a boot/restore failure, a slow load, or any transient error. The correct
    response to an auth failure is always to re-authenticate from the local
    identity (never to delete data), so latency/timing/edge-case failures can't
    nuke an account.
  - **No remote wipe of other devices.** In the zero-knowledge model a device
    can't be remotely erased (it holds its own keys and re-auths); that would need
    a server-stored wipe-command channel + new per-user metadata, deliberately not
    built. For a lost device, the real protection is App Lock (the data key is
    wrapped behind a passphrase/biometric).
- **Closed-app push wakes tabs only; no third-party push provider.** The Service
  Worker holds neither the session token nor the master key (both memory-only), so
  it cannot fetch or decrypt â€" a push/periodic-sync event only WAKES an open tab,
  which does the authenticated work. OS notifications are GENERIC ("Privex â€" You
  have a new message", no sender/preview), since the notification tray is readable
  by other apps. Real closed-app push (Web Push/VAPID) was deliberately NOT built:
  it requires a subscription endpoint at Google/Apple/Mozilla + a per-user server
  record, which would deanonymize the pseudonym and leak message-arrival timing to
  a third party. Fully-closed delivery (esp. iOS) therefore isn't guaranteed;
  foreground/backgrounded tabs deliver in real time over the WebSocket.
- **KT root is computed on-demand (O(N)).** No background root publication / cache yet;
  the public KT endpoints are rate-limited to bound the cost. Add periodic publication
  before large scale.
- **Blob deletion is capability-based.** The blob index stores no owner (privacy), so a
  `chunk_id` (SHA-256 of encrypted content, shared only inside E2E manifests) acts as the
  deletion capability. There is deliberately no owner to check against.

## Performance (targets, measured on the human checkpoint)

- WASM/app interactive < 2 s on modern hardware; message send (local crypto) well under
  500 ms; first message (PQXDH key exchange) < 1 s. Verify via Lighthouse + DevTools.
