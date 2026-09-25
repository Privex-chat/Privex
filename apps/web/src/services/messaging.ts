// Core message service (docs 4.4/4.5/11). Send: ratchet-encrypt the protobuf
// plaintext → wrap in a MessageEnvelope → Sealed Sender → POST /messages/send.
// Receive: open the sealed blob → decode envelope → (PQXDH respond on a new
// session) → ratchet-decrypt → persist + ack. All key material stays in the
// crypto worker; this module only moves opaque bytes and talks to IndexedDB/API.
import * as api from "../api/client";
import { cryptoCall } from "../workers/crypto-client";
import { useAuth } from "../store/auth";
import { loadBundle, saveBundle } from "../onboarding/store";
import {
  OPK_LOW_WATER,
  replenishOpks,
  rotateSpkIfDue,
  type PrekeyCryptoApi,
} from "./prekeys";
import type { IdentityBundle } from "../crypto/onboarding-crypto";
import { EncryptedMessages } from "../db/encrypted-db";
import { db } from "../db";
import {
  acceptContact,
  getContact,
  isBlocked,
  isKeyChanged,
  upsertInboundContact,
} from "../data/contacts";
import {
  clearPqxdhInit,
  createInboundSession,
  loadSession,
  markSessionReceived,
  saveRatchetState,
} from "../data/sessions";
import {
  decodeContent,
  decodeEnvelope,
  encodeContactAccept,
  encodeContactHello,
  encodeDeviceSyncEnvelope,
  encodeEnvelope,
  encodeFile,
  encodeReceipt,
  encodeText,
} from "./envelope";
import { emitContactsChanged, emitMessage } from "./events";
import { enqueue } from "./outbox";
import { applyIncomingReceipt, buildReceiptRequest, queueDeliveryReceipt } from "./receipts";
import {
  applySyncRecord,
  encryptSyncRecord,
  myDeviceId,
  openSyncBlob,
  syncTargets,
  type SyncRecord,
} from "./device-sync";
import { checkDeliveryTime, type VerifyEd25519 } from "./time-sync";
import { reauthenticate } from "./auth-session";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import { backupMessage } from "./history-backup";
import { b64decode, b64encode } from "./bytes";
import { encryptAndUpload, materializeIncoming, type FileMeta } from "./files";
import type {
  RatchetDecrypted,
  RatchetEncrypted,
  PqxdhInitFields,
  SealedOpened,
} from "../crypto/message-crypto";

const CERT_VALID_SECONDS = 24 * 3600;

// --- crypto API (worker-backed; injectable for tests) ---

export interface MessageCryptoApi {
  ratchetEncrypt(state: Uint8Array, plaintext: Uint8Array): Promise<RatchetEncrypted>;
  ratchetDecrypt(state: Uint8Array, ct: Uint8Array, header: Uint8Array): Promise<RatchetDecrypted>;
  ratchetInitBob(shared: Uint8Array, spkPriv: Uint8Array, spkPub: Uint8Array): Promise<Uint8Array>;
  generateSenderCert(
    senderId: string,
    edPriv: Uint8Array,
    edPub: Uint8Array,
    dilPriv: Uint8Array,
    dilPub: Uint8Array,
    x25519Pub: Uint8Array,
    now: number,
    validSeconds: number,
  ): Promise<Uint8Array>;
  sealedSenderEncrypt(message: Uint8Array, cert: Uint8Array, recipientIkPub: Uint8Array): Promise<Uint8Array>;
  sealedSenderDecrypt(blob: Uint8Array, ikPriv: Uint8Array, now: number): Promise<SealedOpened>;
  pqxdhRespond(
    init: PqxdhInitFields,
    ikPriv: Uint8Array,
    spkPriv: Uint8Array,
    opkPriv: Uint8Array,
    kyberPriv: Uint8Array,
  ): Promise<Uint8Array>;
}

export const workerMessageCrypto: MessageCryptoApi = {
  ratchetEncrypt: (s, p) => cryptoCall("ratchet_encrypt", [s, p]),
  ratchetDecrypt: (s, c, h) => cryptoCall("ratchet_decrypt", [s, c, h]),
  ratchetInitBob: (sh, sp, pub) => cryptoCall("ratchet_init_bob", [sh, sp, pub]),
  generateSenderCert: (id, ep, eP, dp, dP, xP, n, v) =>
    cryptoCall("generate_sender_cert", [id, ep, eP, dp, dP, xP, n, v]),
  sealedSenderEncrypt: (m, c, r) => cryptoCall("sealed_sender_encrypt", [m, c, r]),
  sealedSenderDecrypt: (b, k, n) => cryptoCall("sealed_sender_decrypt", [b, k, n]),
  pqxdhRespond: (i, ik, sp, op, ky) => cryptoCall("pqxdh_respond", [i, ik, sp, op, ky]),
};

const now = () => Math.floor(Date.now() / 1000);
const messages = () => new EncryptedMessages(db);

/** Status of the local notice row shown when a contact's message can't be
 *  decrypted (the row has no content). */
export const UNDECRYPTABLE = "undecryptable";

// The server keeps a queued message for at most 60 days (docs 4.12); a redelivery
// can't arrive after that, so processed ids older than this are useless.
const RECEIVED_RETENTION_SECS = 61 * 24 * 3600;

// --- identity + sender cert caches ---

let bundleCache: IdentityBundle | null = null;
async function myBundle(): Promise<IdentityBundle> {
  if (bundleCache) return bundleCache;
  const b = await loadBundle();
  if (!b) throw new Error("identity not loaded");
  bundleCache = b;
  return b;
}

let certCache: { cert: Uint8Array; expiresAt: number } | null = null;
async function myCert(crypto: MessageCryptoApi, me: IdentityBundle): Promise<Uint8Array> {
  const t = now();
  if (certCache && certCache.expiresAt - 300 > t) return certCache.cert;
  const cert = await crypto.generateSenderCert(
    me.userId,
    me.identity.ed25519_priv,
    me.identity.ed25519_pub,
    me.identity.dilithium3_priv,
    me.identity.dilithium3_pub,
    me.identity.x25519_pub,
    t,
    CERT_VALID_SECONDS,
  );
  certCache = { cert, expiresAt: t + CERT_VALID_SECONDS };
  return cert;
}

export const workerPrekeyCrypto: PrekeyCryptoApi = {
  generateOpks: (start, count) => cryptoCall("generate_opks", [start, count]),
  generateSignedSpk: (ed, dil) => cryptoCall("generate_signed_spk", [ed, dil]),
};

let upkeepRunning = false;
/** Prekey upkeep (services/prekeys.ts): rotate the signed prekey when due and top
 *  up one-time prekeys. `serverLow` = the server reported its one-time supply is
 *  low (WS prekey_low). Runs on the cached identity so the in-memory copy stays
 *  current. Best-effort: never throws; one run at a time. */
export async function prekeyUpkeep(
  serverLow = false,
  pc: PrekeyCryptoApi = workerPrekeyCrypto,
): Promise<void> {
  if (upkeepRunning) return;
  upkeepRunning = true;
  try {
    const me = await myBundle();
    const tok = token();
    await rotateSpkIfDue(me, pc, tok, now()).catch(() => {});
    await replenishOpks(me, pc, tok, serverLow).catch(() => {});
  } catch {
    // not authenticated / identity not loaded - retried on the next trigger
  } finally {
    upkeepRunning = false;
  }
}

/** Reset cached identity/cert (call on sign-out). */
export function resetMessaging(): void {
  bundleCache = null;
  certCache = null;
}

function token(): string {
  const t = useAuth.getState().sessionToken;
  if (!t) throw new Error("not authenticated");
  return t;
}

// --- send ---

/** Ratchet-encrypt an already-encoded Content, wrap + Sealed-Sender it, POST, and
 *  persist the local copy. Shared by text + file sends. Returns the server msg id.
 *  `ttlSeconds` is the per-message queue TTL (docs 4.12), defaulted HERE (the one
 *  funnel every send takes) so a parked outbox row always carries an explicit TTL
 *  and compose-time expiry applies to default sends too. */
async function sealAndSend(
  peerId: string,
  contentBytes: Uint8Array,
  store: { content: string; kind: "text" | "file"; receiptToken?: Uint8Array } | null,
  crypto: MessageCryptoApi,
  ttlSeconds: number = api.DEFAULT_TTL_SECONDS,
): Promise<string> {
  const me = await myBundle();
  const contact = await getContact(peerId);
  if (!contact || contact.ik_x25519.length === 0) {
    throw new Error("no recipient key - add this contact first");
  }
  // Enforcement (service layer, not just UI): you can only send a VISIBLE message
  // (store != null) to an ACCEPTED contact. Control messages (contact request /
  // accept, receipts, cover, device-sync — store == null) bypass this: they ARE
  // how a not-yet-accepted relationship progresses over Sealed Sender.
  if (store) {
    if (contact.status === "pending_inbound")
      throw new Error("Accept this contact's request before messaging them.");
    if (contact.status === "pending_outbound")
      throw new Error("Waiting for them to accept your request.");
    if (contact.status === "blocked")
      throw new Error("Unblock this contact to message them.");
  }
  const session = await loadSession(peerId);
  if (!session) throw new Error("no session - add this contact first");

  const ts = now();
  const enc = await crypto.ratchetEncrypt(session.ratchetState, contentBytes);
  const envelope = encodeEnvelope(enc.header, enc.ciphertext, session.pqxdhInit);
  const cert = await myCert(crypto, me);
  const sealed = await crypto.sealedSenderEncrypt(envelope, cert, contact.ik_x25519);

  // Persist the advanced ratchet BEFORE the network call - the encrypt consumed a
  // ratchet step regardless of whether the POST succeeds; `sealed` is that step's
  // only ciphertext, so an offline send is parked verbatim and re-POSTed later.
  await saveRatchetState(peerId, enc.newState);
  if (session.pqxdhInit) await clearPqxdhInit(peerId);

  const localId = globalThis.crypto.randomUUID(); // `crypto` here is the injected API
  const sealedB64 = b64encode(sealed);
  let msgId: string = localId;
  let status = "sent";
  try {
    const resp = await api.sendMessage(peerId, sealedB64, token(), ttlSeconds);
    msgId = resp.message_id;
  } catch (e) {
    // The ratchet already stepped; `sealed` is that step's only ciphertext, so a
    // recoverable failure must PARK it, never drop it (dropping = a permanent gap
    // the receiver sees as a skipped key). Transient = offline (bare error), 401
    // (stale token), 429 (rate-limit), or 5xx (server error) → outbox. This
    // matches flushOutbox, which only drops 400/404/413; other 4xx surface here.
    if (e instanceof api.ApiError && e.status !== 401 && e.status !== 429 && e.status < 500) throw e;
    status = "queued";
    await enqueue(peerId, sealedB64, store ? localId : "", ttlSeconds);
    // 401 → token went stale; re-mint so the outbox retry uses a fresh one (PVX-07).
    if (e instanceof api.ApiError && e.status === 401) void reauthenticate();
  }

  // store === null → a control message (contact hello / receipt): no visible row.
  if (store) {
    const row = {
      msg_id: msgId,
      session_id: peerId,
      content: store.content,
      timestamp: ts,
      status,
      direction: "out" as const,
      kind: store.kind,
      created_at: Date.now(),
      // Our receipt token (docs 4.10): an incoming ReceiptMessage matching it
      // upgrades this row's status to delivered/read.
      receipt_token: store.receiptToken,
    };
    await messages().add(row);
    void backupMessage(row); // best-effort history backup (no-op unless enabled)
    // Cross-device sync (docs 4.11 Mode C, OPT-IN): fan the sent message out to
    // linked devices as self-addressed Sealed Sender copies. Best-effort - a sync
    // failure must never fail or delay the user's actual send.
    void fanOutDeviceSync(me, crypto, {
      v: 1,
      msg_id: msgId,
      peer_id: peerId,
      kind: store.kind,
      content: store.content,
      ts,
      token_hex: store.receiptToken ? toHex(store.receiptToken) : undefined,
    }).catch(() => {});
    emitMessage({ peerId });
  }
  return msgId;
}

/** Send one re-encrypted copy of a just-sent message to each linked device
 *  (docs 4.11 Mode C). No-op unless the opt-in is on AND devices are linked.
 *  Each copy is AES-GCM under the pairwise sync key, padded to 1024, then Sealed
 *  Sender to OUR OWN px_id - on the wire it looks like any other message. */
async function fanOutDeviceSync(
  me: IdentityBundle,
  crypto: MessageCryptoApi,
  rec: SyncRecord,
): Promise<void> {
  const targets = await syncTargets();
  if (targets.length === 0) return;
  const myId = await myDeviceId();
  const cert = await myCert(crypto, me);
  for (const t of targets) {
    const blob = await encryptSyncRecord(rec, t.send_key);
    const env = encodeDeviceSyncEnvelope({
      toDevice: fromHex(t.device_id),
      fromDevice: fromHex(myId),
      blob,
    });
    const sealed = await crypto.sealedSenderEncrypt(env, cert, me.identity.x25519_pub);
    await api.sendMessage(me.userId, b64encode(sealed), token());
  }
}

/** Contact REQUEST: "I want to add you." On the first send it also delivers our
 *  PQXDH handshake, establishing the session. The peer sees a pending request. */
export async function sendContactHello(
  peerId: string,
  crypto: MessageCryptoApi = workerMessageCrypto,
): Promise<void> {
  await sealAndSend(peerId, encodeContactHello(now()), null, crypto);
}

/** Contact ACCEPT: sent back to a requester so their pending_outbound → accepted. */
export async function sendContactAccept(
  peerId: string,
  crypto: MessageCryptoApi = workerMessageCrypto,
): Promise<void> {
  await sealAndSend(peerId, encodeContactAccept(now()), null, crypto);
}

/** Accept an inbound request: flip it to accepted locally AND notify the requester
 *  (contact_accept) so they learn the outcome. The notify is best-effort. */
export async function acceptContactRequest(
  peerId: string,
  crypto: MessageCryptoApi = workerMessageCrypto,
): Promise<void> {
  await acceptContact(peerId); // local: pending_inbound → accepted
  await sendContactAccept(peerId, crypto).catch(() => {});
}

/** Send a queued delivery/read receipt (docs 4.10). Same path, same padding, same
 *  Sealed Sender as a text message - the server cannot tell it apart. No local row. */
export async function sendReceipt(
  to: string,
  tokenId: Uint8Array,
  type: "delivered" | "read",
  crypto: MessageCryptoApi = workerMessageCrypto,
): Promise<void> {
  await sealAndSend(to, encodeReceipt(tokenId, type), null, crypto);
}

/** Cover traffic (docs 5.3 / 5.7): a fixed-size sealed blob addressed to a random
 *  NON-EXISTENT px_id. The server finds no mailbox and silently drops it (already
 *  wired), storing nothing; a network observer sees a POST indistinguishable from a
 *  real send. Fired on the Poisson tick (cover-traffic.ts) so the transmit stream
 *  is constant regardless of real activity. Best-effort - never throws. */
export async function sendCoverMessage(crypto: MessageCryptoApi = workerMessageCrypto): Promise<void> {
  try {
    const me = await myBundle();
    const cert = await myCert(crypto, me);
    // Random recipient id + random recipient key: the blob can't be decrypted by
    // anyone (astronomically unlikely to collide with a real px_id), and the server
    // drops it before content is ever looked at.
    const fakeRid = "px_" + toHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    const fakeKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const payload = globalThis.crypto.getRandomValues(new Uint8Array(1024)); // 1024-byte law
    const sealed = await crypto.sealedSenderEncrypt(payload, cert, fakeKey);
    await api.sendMessage(fakeRid, b64encode(sealed), token());
  } catch {
    // offline / rate-limited / identity not loaded → skip this tick's cover send
  }
}

export async function sendMessage(
  peerId: string,
  plaintext: string,
  crypto: MessageCryptoApi = workerMessageCrypto,
  ttlSeconds?: number,
): Promise<void> {
  const receipt = await buildReceiptRequest(); // undefined when receipts are off (mutual)
  await sealAndSend(
    peerId,
    encodeText(plaintext, now(), receipt?.wire),
    { content: plaintext, kind: "text", receiptToken: receipt?.token },
    crypto,
    ttlSeconds,
  );
}

/** Encrypt + upload a file's chunks, then send its manifest as a file message. */
export async function sendFile(
  peerId: string,
  file: File,
  onProgress?: (done: number, total: number) => void,
  crypto: MessageCryptoApi = workerMessageCrypto,
  ttlSeconds?: number,
): Promise<void> {
  const contact = await getContact(peerId);
  if (!contact || contact.ik_x25519.length === 0) {
    throw new Error("no recipient key - add this contact first");
  }
  // Fail BEFORE the chunk upload (sealAndSend would reject anyway, but only after
  // the bytes already hit the blob store).
  if (contact.status === "pending_inbound") {
    throw new Error("Accept this contact's request before messaging them.");
  }
  const { fields, meta } = await encryptAndUpload(file, contact.ik_x25519, onProgress);
  const receipt = await buildReceiptRequest();
  await sealAndSend(
    peerId,
    encodeFile(fields, receipt?.wire),
    { content: JSON.stringify(meta), kind: "file", receiptToken: receipt?.token },
    crypto,
    ttlSeconds,
  );
}

// --- receive ---

/** Ack a delivery so the server hard-deletes it, and remember its id so a
 *  redelivered copy (the ack itself can fail on a flaky network) is simply acked
 *  again instead of re-processed - by then the ratchet has moved on, and
 *  re-processing would misreport it as undecryptable. */
async function ackDelivered(messageId: string): Promise<void> {
  await db.received.put({ message_id: messageId, at: now() });
  await api.ackMessages([messageId], token());
}

/** Drop processed-id records older than any possible redelivery. */
export async function pruneReceived(): Promise<void> {
  await db.received.where("at").below(now() - RECEIVED_RETENTION_SECS).delete();
}

/** True if the crypto engine works: seal a byte to ourselves and open it. Asked
 *  before discarding a message that failed to decrypt, so a broken worker/WASM
 *  can never be mistaken for "this message can't be decrypted" - that case
 *  throws instead, leaving the message queued for a retry. */
async function cryptoEngineHealthy(crypto: MessageCryptoApi, me: IdentityBundle): Promise<boolean> {
  try {
    const probe = await crypto.sealedSenderEncrypt(
      new Uint8Array([1]),
      await myCert(crypto, me),
      me.identity.x25519_pub,
    );
    await crypto.sealedSenderDecrypt(probe, me.identity.x25519_priv, now());
    return true;
  } catch {
    return false;
  }
}

/** Record that a message from a known, verified contact couldn't be decrypted
 *  (shown in the conversation, like Signal). Never for unverified senders (a
 *  forged certificate can't plant one), and consecutive failures collapse into
 *  one notice.
 *  Known limit: a sender certificate is a reusable credential, and anyone who
 *  has received one of Alice's messages holds a copy. They can attach it to
 *  junk sealed to us, and that junk fails here as if Alice had sent it. So a
 *  notice (never content) can be faked by a holder of the certificate. Kept by
 *  decision: a genuine lost message matters more. The real fix is a sealed
 *  sender that authenticates the sender itself (a static-key layer, as Signal
 *  does), which makes certificates useless to anyone but their owner. */
async function noteUndecryptable(peerId: string, messageId: string, anchor?: number): Promise<void> {
  const rows = await db.messages.where("session_id").equals(peerId).sortBy("created_at");
  if (rows[rows.length - 1]?.status === UNDECRYPTABLE) return;
  await messages().add({
    msg_id: messageId,
    session_id: peerId,
    content: "",
    timestamp: now(),
    server_anchor: anchor,
    created_at: Date.now(),
    status: UNDECRYPTABLE,
    direction: "in",
    kind: "text",
  });
  emitMessage({ peerId });
}

export interface WSMessage {
  message_id: string;
  content: string; // base64 sealed blob
  queued_at: number;
  // Signed delivery timestamp (docs 9.6); absent on old servers/synthetic frames.
  server_ts?: number;
  server_ts_sig?: string; // hex
}

export async function receiveMessage(
  ws: WSMessage,
  crypto: MessageCryptoApi = workerMessageCrypto,
  verifyTime?: VerifyEd25519,
): Promise<void> {
  // Already finished with this delivery (our earlier ack didn't land): ack again.
  if (await db.received.get(ws.message_id)) {
    await api.ackMessages([ws.message_id], token());
    return;
  }

  // Time anchor first (docs 9.6): verify the signed delivery timestamp against
  // the pinned key + local clock. Runs on EVERY frame (more drift samples); an
  // invalid/absent signature yields no anchor but never drops the message.
  const time = await checkDeliveryTime(ws, verifyTime);

  const me = await myBundle();
  const blob = b64decode(ws.content);
  // Check the sender's certificate for expiry as of when the message ARRIVED at
  // the server (the signed anchor), not when we read it: a message that waited
  // in the queue while we were offline was sent under a then-valid certificate,
  // and must not show as "unverified" just because we were away for a day.
  // No valid signed anchor → the local clock, as before.
  const certCheckTime = time.anchor ?? now();
  let opened: SealedOpened;
  let env: ReturnType<typeof decodeEnvelope>;
  try {
    opened = await crypto.sealedSenderDecrypt(blob, me.identity.x25519_priv, certCheckTime);
    env = decodeEnvelope(opened.plaintext);
  } catch (e) {
    // Not sealed to us, tampered, or malformed: no key we hold will ever open it.
    // Ack it so it isn't redelivered on every reconnect for its whole TTL -
    // unless the crypto engine itself is failing, in which case keep it queued.
    if (!(await cryptoEngineHealthy(crypto, me))) throw e;
    await ackDelivered(ws.message_id);
    return;
  }
  const senderId = opened.senderId;

  // Pin the cert's signing key to any identity key we already hold for this
  // sender (docs 8.2 key-change detection on receive). A mismatch means the
  // sender's key changed (or someone is impersonating them via px_id collision) -
  // never silently trust it. The px_id binding inside sealed_sender_decrypt
  // already guarantees senderId is derived from this same ed key.
  const keyChanged = await isKeyChanged(senderId, opened.senderEdPub);
  const verified = opened.senderVerified && !keyChanged;

  // Cross-device sync copy (docs 4.11 Mode C). Handled BEFORE session logic - it
  // carries no ratchet fields. Only OUR OWN other device may inject sent-history:
  // the Sealed Sender cert binds senderId to its signing key, so senderId ===
  // me.userId is only producible with our own identity key.
  if (env.deviceSync) {
    if (senderId !== me.userId || !opened.senderVerified) {
      await ackDelivered(ws.message_id); // forged/garbage - drop
      return;
    }
    if (toHex(env.deviceSync.toDevice) !== (await myDeviceId())) {
      // Addressed to a DIFFERENT linked device. The account shares one mailbox, so
      // leave it UN-ACKED: it stays queued and is delivered when that device next
      // connects. (We will see it again on our own reconnects until then.)
      return;
    }
    try {
      const rec = await openSyncBlob(toHex(env.deviceSync.fromDevice), env.deviceSync.blob);
      await applySyncRecord(rec);
    } catch {
      // Unlinked origin or undecryptable - ack anyway so it can't redeliver forever.
    }
    await ackDelivered(ws.message_id);
    return;
  }

  // Blocked sender: drop everything from them — no store, no session step, no UI.
  // Sealed Sender means we must decrypt to learn the sender first; then ack-and-drop
  // so the server deletes it (no redelivery). Messages sent while blocked are simply
  // not delivered (WhatsApp-style).
  if (await isBlocked(senderId)) {
    await ackDelivered(ws.message_id);
    return;
  }

  // A PQXDH handshake may only create or replace a session when it provably
  // comes from the certificate's identity: the cert must verify (signatures,
  // px_id binding, expiry at arrival), match any identity key we already hold,
  // AND bind the exact X25519 key this handshake uses (v2 cert). Certificates
  // are reused across recipients, so without that binding anyone who ever
  // received one could attach it to their OWN handshake and be accepted as the
  // sender - even replacing an existing contact's session. With it, a replayed
  // certificate forces the real sender's X25519 key, whose private half an
  // impersonator lacks, so the handshake can't decrypt. Unbound handshakes
  // (forged, replayed, or from an app that hasn't updated) are dropped before
  // touching any state.
  if (env.pqxdh) {
    const bound =
      verified &&
      opened.senderX25519Pub.length === 32 &&
      toHex(opened.senderX25519Pub) === toHex(env.pqxdh.alice_ik_pub);
    if (!bound) {
      await ackDelivered(ws.message_id);
      return;
    }
  }

  // Capture the sender's status BEFORE session logic (the adopt-handshake branch
  // may upsert them to pending_inbound), so contact-request glare — they requested
  // us while we already requested them — is still detectable below.
  const priorStatus = (await getContact(senderId))?.status;

  // Pick the session. Use an EXISTING session only if it's already established
  // (no pending initiator stash). When a handshake-bearing message arrives, decide
  // whether to ADOPT it (respond as bob) vs. use our own session. Glare resolution
  // for "both added each other": adopt the sender's handshake if we have no
  // established session (the common case - we only initiated, never sent), OR if
  // the sender is the canonical initiator (smaller px_id). Both sides apply the
  // same rule, so they converge on one ratchet. (In a simultaneous double-send the
  // non-canonical party's very first message may be lost; everything after converges.)
  // RESET: if the handshake doesn't decrypt on our session and that session has
  // been WORKING (it has decrypted the peer before), this isn't glare - the peer
  // started over (e.g. recovered their account on a new device) and our session
  // is dead to them. Adopt the new one; otherwise the chat stayed broken both ways
  // for every contact whose px_id sorted higher.
  const existing = await loadSession(senderId);
  const established = !!existing && !existing.pqxdhInit;
  let adoptHandshake = !!env.pqxdh && (!established || senderId < me.userId);

  let plaintextBytes: Uint8Array = new Uint8Array(0);
  if (!adoptHandshake) {
    if (!existing) {
      // A first message from an unknown peer with no handshake can NEVER be
      // decrypted (no session to open it). Leaving it un-acked made the server
      // redeliver it on every reconnect for its full 30-day TTL. Ack-and-drop
      // (mirrors the glare path below) so it can't wedge the queue (PVX-13).
      await ackDelivered(ws.message_id);
      return;
    }
    let dec: RatchetDecrypted | undefined;
    try {
      dec = await crypto.ratchetDecrypt(existing.ratchetState, env.ciphertext, env.header);
    } catch (e) {
      if (env.pqxdh && existing.receivedOk) {
        adoptHandshake = true; // reset: the peer started a new session (see above)
      } else if (env.pqxdh) {
        // Glare: the sender also initiated, but we're the canonical initiator
        // (smaller px_id), so we kept our session. Their pre-convergence message
        // can't be decrypted with it - drop it (acked, no redelivery loop). They
        // re-send once they adopt our handshake.
        await ackDelivered(ws.message_id);
        return;
      } else {
        // Can never decrypt on this session. Ack it (tell the user, if it's a
        // verified contact) - unless the crypto engine itself is failing.
        if (!(await cryptoEngineHealthy(crypto, me))) throw e;
        if (verified) await noteUndecryptable(senderId, ws.message_id, time.anchor);
        await ackDelivered(ws.message_id);
        return;
      }
    }
    if (dec) {
      await saveRatchetState(senderId, dec.newState);
      if (!existing.receivedOk) await markSessionReceived(senderId);
      plaintextBytes = dec.plaintext;
    }
  }
  if (adoptHandshake) {
    const pq = env.pqxdh!; // adoptHandshake implies a handshake is present
    // Replay guard: a handshake we already adopted (same ephemeral key) arriving
    // again - e.g. a server re-sending a captured copy under a new message id -
    // must not re-adopt: that would rewind our working session to its first
    // state (breaking the chat) and re-show its first message.
    const ek = toHex(pq.alice_ek_pub);
    if (await db.handshakes.get(ek)) {
      await ackDelivered(ws.message_id);
      return;
    }
    const opkPriv =
      pq.opk_used && pq.opk_id
        ? me.opks.find((o) => o.id === pq.opk_id)?.priv ?? new Uint8Array(0)
        : new Uint8Array(0);
    // The handshake targets our current signed prekey - or, if it was sent before
    // a rotation, one of the previous ones (the init doesn't say which): try each.
    let dec: RatchetDecrypted | undefined;
    let lastErr: unknown;
    for (const spk of [me.spk, ...(me.prevSpks ?? [])]) {
      try {
        const shared = await crypto.pqxdhRespond(
          {
            alice_ik_pub: pq.alice_ik_pub,
            alice_ek_pub: pq.alice_ek_pub,
            kyber_ciphertext: pq.kyber_ciphertext,
            opk_used: pq.opk_used,
          },
          me.identity.x25519_priv,
          spk.priv,
          opkPriv,
          me.identity.kyber1024_priv,
        );
        const bobState = await crypto.ratchetInitBob(shared, spk.priv, spk.pub);
        dec = await crypto.ratchetDecrypt(bobState, env.ciphertext, env.header);
        break;
      } catch (e) {
        lastErr = e;
      }
    }
    if (!dec) {
      // The handshake can't complete (a prekey we no longer hold, or an
      // impersonation attempt that copied someone's public key). Nothing was
      // changed; ack it, telling the user only if it's an existing contact.
      if (!(await cryptoEngineHealthy(crypto, me))) throw lastErr;
      if (priorStatus) await noteUndecryptable(senderId, ws.message_id, time.anchor);
      await ackDelivered(ws.message_id);
      return;
    }
    await createInboundSession(senderId, dec.newState);
    await db.handshakes.put({ ek, at: now() });
    // One-time prekeys are ONE-time: forget the private half now that it's used
    // (docs 4.3), and top up if that leaves us low.
    if (pq.opk_used && me.opks.some((o) => o.id === pq.opk_id)) {
      me.opks = me.opks.filter((o) => o.id !== pq.opk_id);
      await saveBundle(me);
      if (me.opks.length < OPK_LOW_WATER) void prekeyUpkeep();
    }
    // Store the reply target (Alice's X25519 IK) + the cert's authentic identity
    // key (px_id is bound to it), unless it conflicts with one we already hold.
    await upsertInboundContact(
      senderId,
      keyChanged ? new Uint8Array(0) : opened.senderEdPub,
      pq.alice_ik_pub,
    );
    emitContactsChanged(); // a new contact just appeared in our list
    plaintextBytes = dec.plaintext;
  }

  // From here the ratchet has stepped: a redelivered copy can never decrypt again,
  // so any failure below must still end in an ack.
  let content: ReturnType<typeof decodeContent>;
  try {
    content = decodeContent(plaintextBytes);
  } catch {
    await noteUndecryptable(senderId, ws.message_id, time.anchor);
    await ackDelivered(ws.message_id);
    return;
  }

  // Contact REQUEST: the sender wants to add us (they're now pending_inbound, set
  // by the session logic above). GLARE: if we had ALREADY requested them
  // (pending_outbound before this frame), we both want it → auto-accept + notify.
  if (content.contactHello) {
    if (priorStatus === "pending_outbound") {
      await acceptContactRequest(senderId, crypto); // → accepted + send contact_accept
    }
    await ackDelivered(ws.message_id);
    emitContactsChanged();
    return;
  }

  // Contact ACCEPT: a peer we requested has accepted us → pending_outbound → accepted.
  if (content.contactAccept) {
    if (priorStatus === "pending_outbound") await acceptContact(senderId);
    await ackDelivered(ws.message_id);
    emitContactsChanged();
    return;
  }

  // Delivery/read receipt (docs 4.10): upgrade OUR outgoing message's status.
  // senderId is Sealed-Sender-authenticated, so the token can only act on
  // messages we sent to exactly this peer. No chat row, no timestamps kept.
  if (content.receipt) {
    await applyIncomingReceipt(senderId, content.receipt.tokenId, content.receipt.type);
    await ackDelivered(ws.message_id);
    return;
  }

  let stored: string;
  let kind: "text" | "file";
  let sentAt: number;
  if (content.file) {
    let meta: FileMeta;
    try {
      meta = await materializeIncoming(content.file, me.identity.x25519_priv);
    } catch {
      await noteUndecryptable(senderId, ws.message_id, time.anchor);
      await ackDelivered(ws.message_id);
      return;
    }
    stored = JSON.stringify(meta);
    kind = "file";
    sentAt = content.file.sentAt;
  } else if (content.text) {
    stored = content.text.body;
    kind = "text";
    sentAt = content.text.sentAt;
  } else {
    // A content type this build doesn't know (e.g. from a newer app version):
    // nothing to show. Ack so it isn't redelivered forever.
    await ackDelivered(ws.message_id);
    return;
  }

  // Receipt request (docs 4.10): keep the sender's token so the read receipt can
  // fire when the message is actually viewed, and queue the delivery receipt NOW
  // (it still only leaves at the next Poisson cover-traffic tick, never inline).
  const rr = content.receiptRequest;
  const row = {
    msg_id: ws.message_id,
    session_id: senderId,
    // timestamp = sender-claimed time, DISPLAY only (docs 9.6); ordering uses the
    // signed server_anchor below, so a manipulated sender clock can't reorder.
    timestamp: sentAt || ws.queued_at || now(),
    server_anchor: time.anchor,
    created_at: Date.now(),
    content: stored,
    status: keyChanged ? "received-key-changed" : verified ? "received" : "received-unverified",
    direction: "in" as const,
    kind,
    receipt_token: rr?.tokenId,
    receipt_read_wanted: rr?.requestRead ?? false,
    receipt_read_done: false,
  };
  await messages().add(row);
  void backupMessage(row); // best-effort history backup (no-op unless enabled)
  if (rr?.requestDelivery) await queueDeliveryReceipt(senderId, rr.tokenId);
  await ackDelivered(ws.message_id);
  emitMessage({ peerId: senderId });
}
