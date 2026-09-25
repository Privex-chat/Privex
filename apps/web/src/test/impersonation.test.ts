// Regression: a sender certificate is reused for 24 h across every recipient, so
// anyone who received one could attach it to their OWN PQXDH handshake. Before
// the fix that was accepted as a genuine, verified message from the certificate's
// owner - and for an existing contact it replaced the session and the stored
// X25519 key. The v2 certificate binds the owner's X25519 identity key, and a
// handshake is only honoured when it uses exactly that key (so an impersonator,
// lacking the private half, can't decrypt). Full receiveMessage path against
// fake-indexeddb + the real wasm crypto.
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
import { pqxdhInitiate } from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import { encodeEnvelope, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import { acceptContact, getContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import {
  receiveMessage,
  resetMessaging,
  UNDECRYPTABLE,
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
const nowS = () => Math.floor(Date.now() / 1000);
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

// A worker-free MessageCryptoApi backed directly by the wasm.
const wasmCrypto: MessageCryptoApi = {
  ratchetEncrypt: async (s, p) => mc.ratchetEncrypt(wasm, s, p),
  ratchetDecrypt: async (s, c, h) => mc.ratchetDecrypt(wasm, s, c, h),
  ratchetInitBob: async (sh, sp, pub) => mc.ratchetInitBob(wasm, sh, sp, pub),
  generateSenderCert: async (id, ep, eP, dp, dP, xP, n, v) =>
    mc.generateSenderCert(wasm, id, ep, eP, dp, dP, xP, n, v),
  sealedSenderEncrypt: async (m, c, r) => mc.sealedSenderEncrypt(wasm, m, c, r),
  sealedSenderDecrypt: async (b, k, n) => mc.sealedSenderDecrypt(wasm, b, k, n),
  pqxdhRespond: async (i, ik, sp, op, ky) => mc.pqxdhRespond(wasm, i, ik, sp, op, ky),
};

/** `owner`'s (v2) sender certificate - what every recipient of their messages holds. */
function certOf(owner: IdentityBundle, nowUnix = nowS(), validSeconds = 86_400): Uint8Array {
  return wasm.generate_sender_cert(
    owner.userId,
    owner.identity.ed25519_priv,
    owner.identity.ed25519_pub,
    owner.identity.dilithium3_priv,
    owner.identity.dilithium3_pub,
    owner.identity.x25519_pub,
    BigInt(nowUnix),
    BigInt(validSeconds),
  );
}

/** A handshake-bearing first message from `initiator` (whose X25519 identity key
 *  runs the PQXDH) to `recipient`, wrapped in `cert`. Genuine sends use the
 *  initiator's own cert; the attacks below pair one identity's cert with
 *  another's handshake. `claimIk` overrides the initiator key WRITTEN into the
 *  envelope (an attacker copying the victim's public key). */
function sealedHandshake(
  initiator: IdentityBundle,
  recipient: IdentityBundle,
  cert: Uint8Array,
  content: Uint8Array,
  claimIk?: Uint8Array,
): { b64: string; state: Uint8Array } {
  const pqx = pqxdhInitiate(wasm, initiator.identity.x25519_priv, {
    ik_x25519: recipient.identity.x25519_pub,
    spk_x25519: recipient.spk.pub,
    opk: recipient.opks[0].pub,
    kyber1024_pub: recipient.identity.kyber1024_pub,
  });
  const enc = wasm.ratchet_encrypt(wasm.ratchet_init_alice(pqx.shared_secret, recipient.spk.pub), content);
  const envelope = encodeEnvelope(enc.message_header, enc.ciphertext, {
    alice_ik_pub: claimIk ?? pqx.alice_ik_pub,
    alice_ek_pub: pqx.alice_ek_pub,
    kyber_ciphertext: pqx.kyber_ciphertext,
    opk_used: pqx.opk_used,
    opk_id: 1,
  });
  return {
    b64: b64encode(wasm.sealed_sender_encrypt(envelope, cert, recipient.identity.x25519_pub)),
    state: enc.new_session_state,
  };
}

/** A follow-up (non-handshake) ratchet message on an established session. */
function sealedFollowUp(
  state: Uint8Array,
  recipient: IdentityBundle,
  cert: Uint8Array,
  content: Uint8Array,
): string {
  const enc = wasm.ratchet_encrypt(state, content);
  const envelope = encodeEnvelope(enc.message_header, enc.ciphertext);
  return b64encode(wasm.sealed_sender_encrypt(envelope, cert, recipient.identity.x25519_pub));
}

async function freshMe(me: IdentityBundle): Promise<void> {
  resetMessaging();
  await db.contacts.clear();
  await db.sessions.clear();
  await db.messages.clear();
  await db.identity.clear();
  await db.settings.clear();
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("test-token", me.userId);
}

/** Two identities where `first` has the SMALLER px_id. That is the case the old
 *  glare rule adopted a new handshake over an established session, so the
 *  hijack tests below would have succeeded before the fix. */
function orderedPair(a: number, b: number): [IdentityBundle, IdentityBundle] {
  const x = genIdentityBundle(wasm, entropy(a));
  const y = genIdentityBundle(wasm, entropy(b));
  return x.userId < y.userId ? [x, y] : [y, x];
}

const messagesOf = (pxId: string) => new EncryptedMessages(db).listBySession(pxId);

describe("sender-certificate replay (impersonation)", () => {
  it("a replayed certificate cannot open a conversation in the owner's name", async () => {
    const alice = genIdentityBundle(wasm, entropy(0xc1));
    const mallory = genIdentityBundle(wasm, entropy(0xc2));
    const carol = genIdentityBundle(wasm, entropy(0xc3));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Mallory holds a copy of Alice's certificate (any message Alice ever sent
    // her carries one) and staples it to her OWN handshake.
    const attack = sealedHandshake(mallory, carol, certOf(alice), encodeText("hi, it's Alice", 0));
    await receiveMessage({ message_id: "x1", content: attack.b64, queued_at: 0 }, wasmCrypto);

    expect(await getContact(alice.userId)).toBeUndefined();
    expect(await db.sessions.get(alice.userId)).toBeUndefined();
    expect(await messagesOf(alice.userId)).toHaveLength(0);
    expect(ackSpy).toHaveBeenCalledWith(["x1"], "test-token"); // dropped, not left queued
    ackSpy.mockRestore();
  });

  it("copying the owner's public X25519 key into the handshake doesn't help: it can't decrypt", async () => {
    const alice = genIdentityBundle(wasm, entropy(0xc4));
    const mallory = genIdentityBundle(wasm, entropy(0xc5));
    const carol = genIdentityBundle(wasm, entropy(0xc6));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Passes the binding check (the envelope names Alice's real X25519 key), but
    // Mallory ran the key agreement with her own private key.
    const attack = sealedHandshake(
      mallory,
      carol,
      certOf(alice),
      encodeText("hi, it's Alice", 0),
      alice.identity.x25519_pub,
    );
    await receiveMessage({ message_id: "x2", content: attack.b64, queued_at: 0 }, wasmCrypto);

    expect(await getContact(alice.userId)).toBeUndefined();
    expect(await db.sessions.get(alice.userId)).toBeUndefined();
    expect(await messagesOf(alice.userId)).toHaveLength(0); // stranger: no notice either
    expect(ackSpy).toHaveBeenCalledWith(["x2"], "test-token"); // discarded, not redelivered
    ackSpy.mockRestore();
  });

  it("a replayed certificate cannot hijack an existing, accepted contact", async () => {
    const [alice, carol] = orderedPair(0xd1, 0xd3);
    const mallory = genIdentityBundle(wasm, entropy(0xd2));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Genuine: Alice opens a conversation; Carol accepts.
    const aliceCert = certOf(alice);
    const genuine = sealedHandshake(alice, carol, aliceCert, encodeText("hello Carol", 0));
    await receiveMessage({ message_id: "g1", content: genuine.b64, queued_at: 0 }, wasmCrypto);
    await acceptContact(alice.userId);
    const before = {
      session: hex((await db.sessions.get(alice.userId))!.ratchet_state_enc),
      contact: await getContact(alice.userId),
    };
    expect(before.contact?.status).toBe("accepted");
    expect(hex(before.contact!.ik_x25519)).toBe(hex(alice.identity.x25519_pub));

    // Attack with both variants: Mallory's own key, and Alice's copied key.
    const own = sealedHandshake(mallory, carol, aliceCert, encodeText("new number, meet me", 0));
    await receiveMessage({ message_id: "x3", content: own.b64, queued_at: 0 }, wasmCrypto);
    const copied = sealedHandshake(
      mallory,
      carol,
      aliceCert,
      encodeText("new number, meet me", 0),
      alice.identity.x25519_pub,
    );
    await receiveMessage({ message_id: "x4", content: copied.b64, queued_at: 0 }, wasmCrypto);

    // Session, stored key, status: all untouched. No attacker content is stored;
    // the failed copy leaves only a "couldn't be decrypted" notice.
    const after = await getContact(alice.userId);
    expect(hex((await db.sessions.get(alice.userId))!.ratchet_state_enc)).toBe(before.session);
    expect(hex(after!.ik_x25519)).toBe(hex(alice.identity.x25519_pub));
    expect(after!.status).toBe("accepted");
    const msgs = await messagesOf(alice.userId);
    expect(msgs.filter((m) => m.status !== UNDECRYPTABLE).map((m) => m.content)).toEqual(["hello Carol"]);
    expect(msgs.some((m) => m.content.includes("meet me"))).toBe(false);

    // And Alice's real follow-up still decrypts on the untouched session.
    const follow = sealedFollowUp(genuine.state, carol, aliceCert, encodeText("still me", 0));
    await receiveMessage({ message_id: "g2", content: follow, queued_at: 0 }, wasmCrypto);
    expect((await messagesOf(alice.userId)).map((m) => m.content)).toContain("still me");
    ackSpy.mockRestore();
  });

  it("a forged certificate claiming someone else's px_id changes nothing", async () => {
    const [alice, carol] = orderedPair(0xe1, 0xe3);
    const mallory = genIdentityBundle(wasm, entropy(0xe2));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Mallory signs a cert with HER keys but Alice's px_id (fails the px_id binding).
    const forged = wasm.generate_sender_cert(
      alice.userId,
      mallory.identity.ed25519_priv,
      mallory.identity.ed25519_pub,
      mallory.identity.dilithium3_priv,
      mallory.identity.dilithium3_pub,
      mallory.identity.x25519_pub,
      BigInt(nowS()),
      BigInt(86_400),
    );
    const attack = sealedHandshake(mallory, carol, forged, encodeText("hi, it's Alice", 0));
    await receiveMessage({ message_id: "x5", content: attack.b64, queued_at: 0 }, wasmCrypto);

    expect(await getContact(alice.userId)).toBeUndefined();
    expect(await db.sessions.get(alice.userId)).toBeUndefined();
    expect(await messagesOf(alice.userId)).toHaveLength(0);
    expect(ackSpy).toHaveBeenCalledWith(["x5"], "test-token");
    ackSpy.mockRestore();
  });

  it("a sender still on a legacy (v1) certificate: handshakes refused, existing sessions keep working", async () => {
    const alice = genIdentityBundle(wasm, entropy(0xf1));
    const carol = genIdentityBundle(wasm, entropy(0xf3));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Establish the session with a normal (v2) handshake first.
    const aliceCert = certOf(alice);
    const genuine = sealedHandshake(alice, carol, aliceCert, encodeText("hello", 0));
    await receiveMessage({ message_id: "l1", content: genuine.b64, queued_at: 0 }, wasmCrypto);

    // Now treat Alice's certs as legacy v1 (no X25519 binding): what a recipient
    // sees from a sender whose app hasn't reloaded yet.
    const legacy: MessageCryptoApi = {
      ...wasmCrypto,
      sealedSenderDecrypt: async (b, k, n) => ({
        ...mc.sealedSenderDecrypt(wasm, b, k, n),
        senderX25519Pub: new Uint8Array(0),
      }),
    };
    // A follow-up on the existing session: authenticated by the session, kept.
    const follow = sealedFollowUp(genuine.state, carol, aliceCert, encodeText("follow-up", 0));
    await receiveMessage({ message_id: "l2", content: follow, queued_at: 0 }, legacy);
    expect((await messagesOf(alice.userId)).map((m) => m.content)).toContain("follow-up");

    // A NEW handshake under a legacy cert can't be bound → dropped.
    const dave = genIdentityBundle(wasm, entropy(0xf4));
    const fresh = sealedHandshake(dave, carol, certOf(dave), encodeText("hi from dave", 0));
    await receiveMessage({ message_id: "l3", content: fresh.b64, queued_at: 0 }, legacy);
    expect(await getContact(dave.userId)).toBeUndefined();
    expect(ackSpy).toHaveBeenCalledWith(["l3"], "test-token");
    ackSpy.mockRestore();
  });
});

describe("certificate expiry is judged at arrival (N4)", () => {
  it("a first message that waited 3 days in the queue is still accepted as verified", async () => {
    const alice = genIdentityBundle(wasm, entropy(0xa5));
    const carol = genIdentityBundle(wasm, entropy(0xa6));
    await freshMe(carol);
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Alice sent it 3 days ago under a 24 h cert; it reached the server a minute
    // later (queued_at, server-signed) while Carol was offline.
    const sentAt = nowS() - 3 * 86_400;
    const msg = sealedHandshake(alice, carol, certOf(alice, sentAt, 86_400), encodeText("see you", sentAt));
    const signedAnchor = async () => true; // stands in for a valid server signature
    await receiveMessage(
      {
        message_id: "late1",
        content: msg.b64,
        queued_at: sentAt + 60,
        server_ts: nowS(),
        server_ts_sig: "00",
      },
      wasmCrypto,
      signedAnchor,
    );

    expect((await getContact(alice.userId))?.status).toBe("pending_inbound");
    const msgs = await messagesOf(alice.userId);
    expect(msgs).toHaveLength(1);
    expect(msgs[0].status).toBe("received"); // verified, not "received-unverified"
    ackSpy.mockRestore();
  });
});
