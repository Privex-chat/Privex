// Delivery & read receipts (docs 4.10) - the full client path against the real
// wasm crypto + fake-indexeddb: wire round-trip, queue-on-receive (never inline),
// Poisson-tick drain, status upgrade with no downgrade, mutual off, pending-sender
// suppression, and the privacy delay.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import { pqxdhInitiate, type VerifiedBundle } from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import { decodeContent, encodeEnvelope, encodeReceipt, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import { acceptContact, addVerifiedContact, blockContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { receiveMessage, resetMessaging, type MessageCryptoApi } from "../services/messaging";
import {
  applyIncomingReceipt,
  buildReceiptRequest,
  drainReceipts,
  queueDeliveryReceipt,
  queueReadReceipt,
  setDeliveryReceipts,
  setReadReceipts,
  setReceiptPrivacyDelay,
} from "../services/receipts";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
});

beforeEach(async () => {
  resetMessaging();
  await Promise.all([
    db.contacts.clear(),
    db.sessions.clear(),
    db.messages.clear(),
    db.identity.clear(),
    db.settings.clear(),
    db.receipt_outbox.clear(),
  ]);
  // Receipts now default OFF (privacy by default). These tests exercise the ON
  // behavior, so enable them explicitly; the "mutual: disabling" test overrides.
  await setDeliveryReceipts(true);
  await setReadReceipts(true);
});

const entropy = (f: number) => new Uint8Array(32).fill(f);
const TOKEN = new Uint8Array(32).fill(0x7a);

const wasmCrypto: MessageCryptoApi = {
  ratchetEncrypt: async (s, p) => mc.ratchetEncrypt(wasm, s, p),
  ratchetDecrypt: async (s, c, h) => mc.ratchetDecrypt(wasm, s, c, h),
  ratchetInitBob: async (sh, sp, pub) => mc.ratchetInitBob(wasm, sh, sp, pub),
  generateSenderCert: async (id, ep, eP, dp, dP, n, v) =>
    mc.generateSenderCert(wasm, id, ep, eP, dp, dP, n, v),
  sealedSenderEncrypt: async (m, c, r) => mc.sealedSenderEncrypt(wasm, m, c, r),
  sealedSenderDecrypt: async (b, k, n) => mc.sealedSenderDecrypt(wasm, b, k, n),
  pqxdhRespond: async (i, ik, sp, op, ky) => mc.pqxdhRespond(wasm, i, ik, sp, op, ky),
};

function verifiedOf(b: IdentityBundle): VerifiedBundle {
  return {
    userId: b.userId,
    ik_ed25519: b.identity.ed25519_pub,
    ik_dilithium3: b.identity.dilithium3_pub,
    ik_x25519: b.identity.x25519_pub,
    spk_x25519: b.spk.pub,
    kyber1024_pub: b.identity.kyber1024_pub,
    opk: b.opks[0].pub,
    opk_id: 1,
  };
}

/** Sender's sealed first message (with PQXDH handshake) carrying `content`. */
function sealedFirst(sender: IdentityBundle, recipient: IdentityBundle, content: Uint8Array): string {
  const ts = Math.floor(Date.now() / 1000);
  const pqx = pqxdhInitiate(wasm, sender.identity.x25519_priv, {
    ik_x25519: recipient.identity.x25519_pub,
    spk_x25519: recipient.spk.pub,
    opk: recipient.opks[0].pub,
    kyber1024_pub: recipient.identity.kyber1024_pub,
  });
  const state = wasm.ratchet_init_alice(pqx.shared_secret, recipient.spk.pub);
  const enc = wasm.ratchet_encrypt(state, content);
  const envelope = encodeEnvelope(enc.message_header, enc.ciphertext, {
    alice_ik_pub: pqx.alice_ik_pub,
    alice_ek_pub: pqx.alice_ek_pub,
    kyber_ciphertext: pqx.kyber_ciphertext,
    opk_used: pqx.opk_used,
    opk_id: 1,
  });
  const cert = wasm.generate_sender_cert(
    sender.userId,
    sender.identity.ed25519_priv,
    sender.identity.ed25519_pub,
    sender.identity.dilithium3_priv,
    sender.identity.dilithium3_pub,
    BigInt(ts),
    BigInt(86_400),
  );
  return b64encode(wasm.sealed_sender_encrypt(envelope, cert, recipient.identity.x25519_pub));
}

async function setupMe(fill: number): Promise<IdentityBundle> {
  const me = genIdentityBundle(wasm, entropy(fill));
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("test-token", me.userId);
  return me;
}

/** me adds peer (accepted contact + own initiator session, like a real add). */
async function addAccepted(me: IdentityBundle, peer: IdentityBundle): Promise<void> {
  const pqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
    ik_x25519: peer.identity.x25519_pub,
    spk_x25519: peer.spk.pub,
    opk: peer.opks[0].pub,
    kyber1024_pub: peer.identity.kyber1024_pub,
  });
  const state = wasm.ratchet_init_alice(pqx.shared_secret, peer.spk.pub);
  await addVerifiedContact(verifiedOf(peer), pqx, state); // → pending_outbound
  await acceptContact(peer.userId); // mark accepted so messages can be sent
}

describe("receipt wire format", () => {
  it("round-trips the receipt request and the receipt message; absent when not attached", () => {
    const withReq = decodeContent(
      encodeText("hi", 1234, { tokenId: TOKEN, requestDelivery: true, requestRead: true }),
    );
    expect(withReq.text?.body).toBe("hi");
    expect(toHex(withReq.receiptRequest!.tokenId)).toBe(toHex(TOKEN));
    expect(withReq.receiptRequest!.requestDelivery).toBe(true);
    expect(withReq.receiptRequest!.requestRead).toBe(true);

    expect(decodeContent(encodeText("hi", 1234)).receiptRequest).toBeUndefined();

    const r = decodeContent(encodeReceipt(TOKEN, "read"));
    expect(r.receipt).toBeDefined();
    expect(toHex(r.receipt!.tokenId)).toBe(toHex(TOKEN));
    expect(r.receipt!.type).toBe("read");
    // A receipt is content-only: no timestamp field exists on the wire (docs 4.10).
  });
});

describe("receiving a message with a receipt request", () => {
  it("queues (never sends inline) a delivery receipt for an ACCEPTED sender, drained on the tick", async () => {
    const me = await setupMe(0xd1);
    const peer = genIdentityBundle(wasm, entropy(0xd2));
    await addAccepted(me, peer);

    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const content = encodeText("hello", 0, { tokenId: TOKEN, requestDelivery: true, requestRead: true });
    await receiveMessage({ message_id: "r1", content: sealedFirst(peer, me, content), queued_at: 0 }, wasmCrypto);
    ackSpy.mockRestore();

    // The row keeps the sender's token + read-wanted flag for the viewport step.
    const [msg] = await new EncryptedMessages(db).listBySession(peer.userId);
    expect(toHex(msg.receipt_token!)).toBe(toHex(TOKEN));
    expect(msg.receipt_read_wanted).toBe(true);
    expect(msg.receipt_read_done).toBe(false);

    // Queued, not sent: exactly one "delivered" row waiting for the Poisson tick.
    const queued = await db.receipt_outbox.toArray();
    expect(queued).toHaveLength(1);
    expect(queued[0].receipt_type).toBe("delivered");
    expect(queued[0].to).toBe(peer.userId);
    // docs 5.7 M3: never due less than 5 s after receipt (the floor).
    expect(queued[0].not_before).toBeGreaterThanOrEqual(queued[0].queued_at + 5000);

    // A drain BEFORE the 5 s floor sends nothing (not due yet).
    let early = 0;
    await drainReceipts(async () => {
      early += 1;
    });
    expect(early).toBe(0);
    expect(await db.receipt_outbox.count()).toBe(1);

    // Redelivery dedup: queuing the same token+type again is a no-op.
    await queueDeliveryReceipt(peer.userId, TOKEN);
    expect(await db.receipt_outbox.count()).toBe(1);

    // Simulate the floor elapsing, then drain (the cover-traffic tick): sends
    // through the injected sender, clears the queue.
    await db.receipt_outbox.toCollection().modify({ not_before: 0 });
    const sent: Array<[string, string, string]> = [];
    await drainReceipts(async (to, tok, type) => {
      sent.push([to, toHex(tok), type]);
    });
    expect(sent).toEqual([[peer.userId, toHex(TOKEN), "delivered"]]);
    expect(await db.receipt_outbox.count()).toBe(0);

    // Viewport read (>1s) → read receipt queued once; receipt_read_done dedups.
    await queueReadReceipt(msg);
    const again = (await new EncryptedMessages(db).listBySession(peer.userId))[0];
    expect(again.receipt_read_done).toBe(true);
    await queueReadReceipt(again);
    const reads = await db.receipt_outbox.toArray();
    expect(reads).toHaveLength(1);
    expect(reads[0].receipt_type).toBe("read");
  });

  it("suppresses receipts for a PENDING (unaccepted) sender - no online oracle", async () => {
    const me = await setupMe(0xd3);
    const peer = genIdentityBundle(wasm, entropy(0xd4));

    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const content = encodeText("spam?", 0, { tokenId: TOKEN, requestDelivery: true, requestRead: true });
    await receiveMessage({ message_id: "r2", content: sealedFirst(peer, me, content), queued_at: 0 }, wasmCrypto);
    ackSpy.mockRestore();

    // Auto-added as pending_inbound → NOTHING queued (accepting later must not
    // retroactively signal either - the queue stays empty until they message again).
    expect(await db.receipt_outbox.count()).toBe(0);
  });

  it("does NOT send a receipt queued before the contact was blocked", async () => {
    const me = await setupMe(0xdb);
    const peer = genIdentityBundle(wasm, entropy(0xdc));
    await addAccepted(me, peer); // accepted → receipt queues normally

    await queueDeliveryReceipt(peer.userId, TOKEN);
    await db.receipt_outbox.toCollection().modify({ not_before: 0 }); // due now
    expect(await db.receipt_outbox.count()).toBe(1);

    // Block AFTER the receipt was queued: the drain must drop it (not leak a
    // "delivered" to someone we just blocked), even though it was queued while accepted.
    await blockContact(peer.userId);
    const sent: string[] = [];
    await drainReceipts(async (to) => {
      sent.push(to);
    });
    expect(sent).toEqual([]); // nothing sent to the blocked contact
    expect(await db.receipt_outbox.count()).toBe(0); // row dropped
  });

  it("is mutual: disabling receipts stops outgoing requests AND incoming confirmations", async () => {
    await setDeliveryReceipts(false);
    await setReadReceipts(false);

    // Outgoing: no request is attached → peers get nothing to confirm to us.
    expect(await buildReceiptRequest()).toBeUndefined();

    // Incoming: a request from a peer is ignored.
    const me = await setupMe(0xd5);
    const peer = genIdentityBundle(wasm, entropy(0xd6));
    await addAccepted(me, peer);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const content = encodeText("hi", 0, { tokenId: TOKEN, requestDelivery: true, requestRead: true });
    await receiveMessage({ message_id: "r3", content: sealedFirst(peer, me, content), queued_at: 0 }, wasmCrypto);
    ackSpy.mockRestore();
    expect(await db.receipt_outbox.count()).toBe(0);

    // And incoming ReceiptMessages are ignored too (applyIncomingReceipt gate).
    expect(await applyIncomingReceipt(peer.userId, TOKEN, "delivered")).toBe(false);
  });

  it("privacy delay: queued receipts get a future not_before the drain respects", async () => {
    const me = await setupMe(0xd7);
    const peer = genIdentityBundle(wasm, entropy(0xd8));
    await addAccepted(me, peer);
    await setReceiptPrivacyDelay(true);

    await queueDeliveryReceipt(peer.userId, TOKEN);
    const [row] = await db.receipt_outbox.toArray();
    expect(row.not_before).toBeGreaterThan(Date.now());
    expect(row.not_before - row.queued_at).toBeLessThanOrEqual(20 * 60 * 1000); // 20 min cap

    // Not due yet → the tick sends nothing and keeps the row.
    const sent: string[] = [];
    await drainReceipts(async (_to, _tok, type) => {
      sent.push(type);
    });
    expect(sent).toEqual([]);
    expect(await db.receipt_outbox.count()).toBe(1);
  });
});

describe("full loop: send → peer receipt → live status update", () => {
  it("processes a real sealed receipt through receiveMessage and emits the UI event", async () => {
    const me = await setupMe(0xe1);
    const peer = genIdentityBundle(wasm, entropy(0xe2));
    await addAccepted(me, peer);

    // 1. I send a text (real sendMessage; capture the sealed blob the peer gets).
    let sealedToPeer = "";
    const sendSpy = vi.spyOn(api, "sendMessage").mockImplementation(async (_to, contentB64) => {
      sealedToPeer = contentB64;
      return { queued: true, message_id: "srv-42", expires_at: 0 };
    });
    const { sendMessage } = await import("../services/messaging");
    await sendMessage(peer.userId, "ping", wasmCrypto);
    sendSpy.mockRestore();

    const store = new EncryptedMessages(db);
    const [mine] = await store.listBySession(peer.userId);
    expect(mine.status).toBe("sent");
    expect(mine.receipt_token).toBeDefined();

    // 2. Peer side (raw wasm): open the seal, complete PQXDH as responder,
    //    decrypt, pull the receipt token out of the request.
    const opened = wasm.sealed_sender_decrypt(
      new Uint8Array(Buffer.from(sealedToPeer, "base64")),
      peer.identity.x25519_priv,
      BigInt(Math.floor(Date.now() / 1000)),
    );
    const env = (await import("../services/envelope")).decodeEnvelope(opened.plaintext);
    const shared = wasm.pqxdh_respond(
      new wasm.PqxdhInitMessage(
        env.pqxdh!.alice_ik_pub,
        env.pqxdh!.alice_ek_pub,
        env.pqxdh!.kyber_ciphertext,
        env.pqxdh!.opk_used,
      ),
      peer.identity.x25519_priv,
      peer.spk.priv,
      peer.opks[0].priv,
      peer.identity.kyber1024_priv,
    );
    let peerState = wasm.ratchet_init_bob(shared, peer.spk.priv, peer.spk.pub);
    const dec = wasm.ratchet_decrypt(peerState, env.ciphertext, env.header);
    peerState = dec.new_session_state;
    const got = decodeContent(dec.plaintext);
    expect(got.text?.body).toBe("ping");
    const token = got.receiptRequest!.tokenId;

    // 3. Peer sends a "read" receipt over its ESTABLISHED session (no pqxdh) -
    //    exactly what drainReceipts does in the live app.
    const renc = wasm.ratchet_encrypt(peerState, encodeReceipt(token, "read"));
    const receiptEnv = encodeEnvelope(renc.message_header, renc.ciphertext);
    const cert = wasm.generate_sender_cert(
      peer.userId,
      peer.identity.ed25519_priv,
      peer.identity.ed25519_pub,
      peer.identity.dilithium3_priv,
      peer.identity.dilithium3_pub,
      BigInt(Math.floor(Date.now() / 1000)),
      BigInt(86_400),
    );
    const sealedReceipt = b64encode(
      wasm.sealed_sender_encrypt(receiptEnv, cert, me.identity.x25519_pub),
    );

    // 4. I receive it live: status flips AND the message event fires (Chat reload).
    const events: string[] = [];
    const { onMessage } = await import("../services/events");
    const off = onMessage((e) => events.push(e.peerId));
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage({ message_id: "rcpt-1", content: sealedReceipt, queued_at: 0 }, wasmCrypto);
    ackSpy.mockRestore();
    off();

    expect((await store.listBySession(peer.userId))[0].status).toBe("read");
    expect(events).toContain(peer.userId);
  });
});

describe("applying incoming receipts to sent messages", () => {
  it("upgrades sent→delivered→read, never downgrades, and only for the authenticated sender", async () => {
    const peerId = "px_" + "ab".repeat(16);
    const otherId = "px_" + "cd".repeat(16);
    const store = new EncryptedMessages(db);
    await store.add({
      msg_id: "m-out",
      session_id: peerId,
      content: "yo",
      timestamp: 1,
      created_at: 1000,
      status: "sent",
      direction: "out",
      kind: "text",
      receipt_token: TOKEN,
    });

    // A receipt from the WRONG sender must not match (token is sender-scoped).
    expect(await applyIncomingReceipt(otherId, TOKEN, "delivered")).toBe(false);
    expect((await store.get("m-out"))!.status).toBe("sent");

    expect(await applyIncomingReceipt(peerId, TOKEN, "delivered")).toBe(true);
    expect((await store.get("m-out"))!.status).toBe("delivered");

    expect(await applyIncomingReceipt(peerId, TOKEN, "read")).toBe(true);
    expect((await store.get("m-out"))!.status).toBe("read");

    // Late/duplicate "delivered" after "read" → matched but NOT downgraded.
    expect(await applyIncomingReceipt(peerId, TOKEN, "delivered")).toBe(true);
    expect((await store.get("m-out"))!.status).toBe("read");
  });
});
