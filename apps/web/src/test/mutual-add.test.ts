// Regression: when both users add each other (mutual add), the receiver holds its
// OWN pending initiator session for the sender. A message arriving with a PQXDH
// handshake must be decrypted by ADOPTING the sender's handshake (responder),
// not by the receiver's own unmatched session. This is the full receiveMessage
// path against fake-indexeddb + the real wasm crypto.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it, vi } from "vitest";

// getMasterKey persists a CryptoKey via idb-keyval, which fake-indexeddb can't
// structured-clone in Node - mock it to a fixed in-memory key.
const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, type IdentityBundle } from "../crypto/onboarding-crypto";
import { pqxdhInitiate, type VerifiedBundle } from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import { encodeContactHello, encodeEnvelope, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import { onContactsChanged } from "../services/events";
import { acceptContact, addVerifiedContact, getContact, removeContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import {
  receiveMessage,
  resetMessaging,
  sendMessage,
  type MessageCryptoApi,
} from "../services/messaging";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

// A worker-free MessageCryptoApi backed directly by the wasm.
const wasmCrypto: MessageCryptoApi = {
  ratchetEncrypt: async (s, p) => mc.ratchetEncrypt(wasm, s, p),
  ratchetDecrypt: async (s, c, h) => mc.ratchetDecrypt(wasm, s, c, h),
  ratchetInitBob: async (sh, sp, pub) => mc.ratchetInitBob(wasm, sh, sp, pub),
  generateSenderCert: async (id, ep, eP, dp, dP, n, v) => mc.generateSenderCert(wasm, id, ep, eP, dp, dP, n, v),
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

/** Build sender's sealed first message to recipient (initiator, carries handshake). */
function sealedFirstMessage(sender: IdentityBundle, recipient: IdentityBundle, content: Uint8Array): string {
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

describe("mutual add", () => {
  it("decrypts an incoming message even when WE also initiated a session with the sender", async () => {
    resetMessaging();
    await db.contacts.clear();
    await db.sessions.clear();
    await db.messages.clear();
    await db.identity.clear();
    await db.settings.clear();

    const me = genIdentityBundle(wasm, entropy(0x51)); // user2 (local identity)
    const peer = genIdentityBundle(wasm, entropy(0x52)); // user1 (the sender)

    // I am user2. Persist my identity so messaging.myBundle() can load it.
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("test-token", me.userId);

    // Mutual add: I (user2) added user1 → I hold my OWN pending initiator session.
    const myPqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
      ik_x25519: peer.identity.x25519_pub,
      spk_x25519: peer.spk.pub,
      opk: peer.opks[0].pub,
      kyber1024_pub: peer.identity.kyber1024_pub,
    });
    const myState = wasm.ratchet_init_alice(myPqx.shared_secret, peer.spk.pub);
    await addVerifiedContact(verifiedOf(peer), myPqx, myState);

    // user1 sends me their first message (with a handshake).
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      { message_id: "m1", content: sealedFirstMessage(peer, me, encodeText("hi from user1", 0)), queued_at: 0 },
      wasmCrypto,
    );

    // It must be decrypted + stored under the sender's conversation, and acked.
    const msgs = await new EncryptedMessages(db).listBySession(peer.userId);
    expect(msgs).toHaveLength(1);
    expect(msgs[0].content).toBe("hi from user1");
    expect(msgs[0].direction).toBe("in");
    expect(ackSpy).toHaveBeenCalledWith(["m1"], "test-token");
    ackSpy.mockRestore();
  });

  it("auto-adds the sender from a contact hello, with no chat message", async () => {
    resetMessaging();
    await db.contacts.clear();
    await db.sessions.clear();
    await db.messages.clear();
    await db.identity.clear();

    const me = genIdentityBundle(wasm, entropy(0x61));
    const peer = genIdentityBundle(wasm, entropy(0x62));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("test-token", me.userId);

    // One-directional: peer added me; I have no session for them yet.
    let changed = 0;
    const off = onContactsChanged(() => (changed += 1));
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    await receiveMessage(
      { message_id: "h1", content: sealedFirstMessage(peer, me, encodeContactHello(0)), queued_at: 0 },
      wasmCrypto,
    );
    off();

    // The sender is now in my contacts, the list was notified, and there is NO
    // visible chat message - just a silent auto-add.
    expect((await getContact(peer.userId))?.px_id).toBe(peer.userId);
    expect(await new EncryptedMessages(db).listBySession(peer.userId)).toHaveLength(0);
    expect(changed).toBeGreaterThan(0);
    expect(ackSpy).toHaveBeenCalledWith(["h1"], "test-token");
    ackSpy.mockRestore();
  });

  it("blocks replying to a pending request until accepted (opt-in enforcement)", async () => {
    resetMessaging();
    await db.contacts.clear();
    await db.sessions.clear();
    await db.messages.clear();
    await db.identity.clear();

    const me = genIdentityBundle(wasm, entropy(0x81));
    const peer = genIdentityBundle(wasm, entropy(0x82));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("test-token", me.userId);

    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      { message_id: "p1", content: sealedFirstMessage(peer, me, encodeText("hi, add me?", 0)), queued_at: 0 },
      wasmCrypto,
    );
    expect((await getContact(peer.userId))?.status).toBe("pending_inbound");

    // Reply while pending → refused at the SERVICE layer (not just hidden UI).
    await expect(sendMessage(peer.userId, "sure", wasmCrypto)).rejects.toThrow(/[Aa]ccept/);
    expect(await new EncryptedMessages(db).listBySession(peer.userId)).toHaveLength(1); // only theirs

    // Accept → the reply goes through.
    await acceptContact(peer.userId);
    const sendSpy = vi
      .spyOn(api, "sendMessage")
      .mockResolvedValue({ queued: true, message_id: "srv-1" });
    await sendMessage(peer.userId, "sure", wasmCrypto);
    expect(sendSpy).toHaveBeenCalledOnce();
    expect(await new EncryptedMessages(db).listBySession(peer.userId)).toHaveLength(2);
    sendSpy.mockRestore();
    ackSpy.mockRestore();
  });

  it("declining a request purges its messages, session, and contact", async () => {
    resetMessaging();
    await db.contacts.clear();
    await db.sessions.clear();
    await db.messages.clear();
    await db.identity.clear();

    const me = genIdentityBundle(wasm, entropy(0x91));
    const peer = genIdentityBundle(wasm, entropy(0x92));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("test-token", me.userId);

    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      { message_id: "d1", content: sealedFirstMessage(peer, me, encodeText("spam", 0)), queued_at: 0 },
      wasmCrypto,
    );
    expect(await new EncryptedMessages(db).listBySession(peer.userId)).toHaveLength(1);

    // Decline = removeContact → nothing readable is left behind.
    await removeContact(peer.userId);
    expect(await getContact(peer.userId)).toBeUndefined();
    expect(await db.sessions.get(peer.userId)).toBeUndefined();
    expect(await new EncryptedMessages(db).listBySession(peer.userId)).toHaveLength(0);
    ackSpy.mockRestore();
  });
});
