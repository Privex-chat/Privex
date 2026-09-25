// N2: a message this device can never decrypt used to be left un-acked, so the
// server redelivered it on every reconnect for its whole TTL (up to 60 days) -
// and anyone could plant such messages. Now: anything that can never be opened is
// acked; a verified contact's undecryptable message leaves one "couldn't be
// decrypted" notice; a redelivered copy of an already-processed message is just
// re-acked; and a failing crypto ENGINE never causes a message to be discarded.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { proto } from "@privex/protocol";
import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, type IdentityBundle } from "../crypto/onboarding-crypto";
import { pqxdhInitiate } from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import { encodeEnvelope, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import { acceptContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import {
  pruneReceived,
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

function certOf(owner: IdentityBundle): Uint8Array {
  return wasm.generate_sender_cert(
    owner.userId,
    owner.identity.ed25519_priv,
    owner.identity.ed25519_pub,
    owner.identity.dilithium3_priv,
    owner.identity.dilithium3_pub,
    owner.identity.x25519_pub,
    BigInt(nowS()),
    BigInt(86_400),
  );
}

/** First message (handshake) from `from` to `to`; returns the wire blob + the
 *  sender's ratchet state for follow-ups. */
function first(from: IdentityBundle, to: IdentityBundle, content: Uint8Array) {
  const pqx = pqxdhInitiate(wasm, from.identity.x25519_priv, {
    ik_x25519: to.identity.x25519_pub,
    spk_x25519: to.spk.pub,
    opk: to.opks[0].pub,
    kyber1024_pub: to.identity.kyber1024_pub,
  });
  const enc = wasm.ratchet_encrypt(wasm.ratchet_init_alice(pqx.shared_secret, to.spk.pub), content);
  const env = encodeEnvelope(enc.message_header, enc.ciphertext, {
    alice_ik_pub: pqx.alice_ik_pub,
    alice_ek_pub: pqx.alice_ek_pub,
    kyber_ciphertext: pqx.kyber_ciphertext,
    opk_used: pqx.opk_used,
    opk_id: 1,
  });
  return {
    b64: b64encode(wasm.sealed_sender_encrypt(env, certOf(from), to.identity.x25519_pub)),
    state: enc.new_session_state,
  };
}

function followUp(state: Uint8Array, cert: Uint8Array, to: IdentityBundle, content: Uint8Array) {
  const enc = wasm.ratchet_encrypt(state, content);
  const env = encodeEnvelope(enc.message_header, enc.ciphertext);
  return {
    b64: b64encode(wasm.sealed_sender_encrypt(env, cert, to.identity.x25519_pub)),
    state: enc.new_session_state,
  };
}

async function freshMe(me: IdentityBundle) {
  resetMessaging();
  for (const t of [db.contacts, db.sessions, db.messages, db.identity, db.settings, db.received]) await t.clear();
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("tok", me.userId);
}

const frame = (id: string, b64: string) => ({ message_id: id, content: b64, queued_at: 0 });
const rowsOf = (pxId: string) => new EncryptedMessages(db).listBySession(pxId);

/** Carol with an accepted contact Alice and an established session. */
async function carolWithAlice(fa: number, fc: number) {
  const alice = genIdentityBundle(wasm, entropy(fa));
  const carol = genIdentityBundle(wasm, entropy(fc));
  await freshMe(carol);
  const hello = first(alice, carol, encodeText("hello", 0));
  const setupAck = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
  await receiveMessage(frame("h0", hello.b64), wasmCrypto);
  setupAck.mockRestore();
  await acceptContact(alice.userId);
  return { alice, carol, aliceState: hello.state, aliceCert: certOf(alice) };
}

describe("messages that can never be decrypted (N2)", () => {
  it("acks a blob that isn't sealed to us, and garbage, without storing anything", async () => {
    const me = genIdentityBundle(wasm, entropy(0x21));
    const other = genIdentityBundle(wasm, entropy(0x22));
    await freshMe(me);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    const notForMe = first(me, other, encodeText("for someone else", 0)).b64;
    await receiveMessage(frame("n1", notForMe), wasmCrypto);
    await receiveMessage(frame("n2", b64encode(crypto.getRandomValues(new Uint8Array(300)))), wasmCrypto);

    expect(ack).toHaveBeenCalledWith(["n1"], "tok");
    expect(ack).toHaveBeenCalledWith(["n2"], "tok");
    expect(await db.messages.count()).toBe(0);
    expect(await db.received.get("n1")).toBeDefined();
    ack.mockRestore();
  });

  it("a verified contact's undecryptable message leaves ONE notice until something decrypts", async () => {
    const { alice, carol, aliceState, aliceCert } = await carolWithAlice(0x31, 0x33);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    // A message from a ratchet Carol doesn't share (e.g. Alice's session to Dave).
    const dave = genIdentityBundle(wasm, entropy(0x34));
    const stray = first(alice, dave, encodeText("x", 0)).state;

    await receiveMessage(frame("u1", followUp(stray, aliceCert, carol, encodeText("?", 0)).b64), wasmCrypto);
    await receiveMessage(frame("u2", followUp(stray, aliceCert, carol, encodeText("?", 0)).b64), wasmCrypto);
    let rows = await rowsOf(alice.userId);
    expect(rows.filter((r) => r.status === UNDECRYPTABLE)).toHaveLength(1); // collapsed
    expect(ack).toHaveBeenCalledWith(["u1"], "tok");
    expect(ack).toHaveBeenCalledWith(["u2"], "tok");

    // A real message decrypts on the untouched session; a later failure notes again.
    await receiveMessage(frame("r1", followUp(aliceState, aliceCert, carol, encodeText("real", 0)).b64), wasmCrypto);
    await receiveMessage(frame("u3", followUp(stray, aliceCert, carol, encodeText("?", 0)).b64), wasmCrypto);
    rows = await rowsOf(alice.userId);
    expect(rows.map((r) => (r.status === UNDECRYPTABLE ? "!" : r.content))).toEqual(["hello", "!", "real", "!"]);
    ack.mockRestore();
  });

  it("a forged certificate can't plant a notice in someone else's conversation", async () => {
    const { alice, carol, aliceState } = await carolWithAlice(0x41, 0x43);
    const mallory = genIdentityBundle(wasm, entropy(0x42));
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
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
    const junk = followUp(first(mallory, carol, encodeText("x", 0)).state, forged, carol, encodeText("?", 0));
    await receiveMessage(frame("f1", junk.b64), wasmCrypto);

    expect(ack).toHaveBeenCalledWith(["f1"], "tok");
    expect((await rowsOf(alice.userId)).map((r) => r.content)).toEqual(["hello"]); // no notice
    void aliceState;
    ack.mockRestore();
  });

  it("a redelivered copy after a failed ack is re-acked, not re-processed", async () => {
    const { alice, carol, aliceState, aliceCert } = await carolWithAlice(0x51, 0x53);
    const msg = followUp(aliceState, aliceCert, carol, encodeText("once", 0));

    // The ack is lost on the network: the message is stored, the error surfaces.
    const lost = vi.spyOn(api, "ackMessages").mockRejectedValue(new Error("offline"));
    await expect(receiveMessage(frame("d1", msg.b64), wasmCrypto)).rejects.toThrow("offline");
    lost.mockRestore();

    // The server redelivers it: just ack again - no notice, no duplicate.
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(frame("d1", msg.b64), wasmCrypto);
    expect(ack).toHaveBeenCalledWith(["d1"], "tok");
    expect((await rowsOf(alice.userId)).map((r) => r.content)).toEqual(["hello", "once"]);
    ack.mockRestore();
  });

  it("never discards a message when the crypto engine itself is failing", async () => {
    const { carol, aliceState, aliceCert } = await carolWithAlice(0x61, 0x63);
    const msg = followUp(aliceState, aliceCert, carol, encodeText("keep me", 0));
    const broken: MessageCryptoApi = {
      ...wasmCrypto,
      sealedSenderDecrypt: async () => {
        throw new Error("worker unavailable");
      },
      sealedSenderEncrypt: async () => {
        throw new Error("worker unavailable");
      },
    };
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await expect(receiveMessage(frame("e1", msg.b64), broken)).rejects.toThrow("worker unavailable");
    expect(ack).not.toHaveBeenCalled(); // stays queued for a retry
    expect(await db.received.get("e1")).toBeUndefined();
    ack.mockRestore();
  });

  it("acks a content type this build doesn't know (newer app) without storing it", async () => {
    const { alice, carol, aliceState, aliceCert } = await carolWithAlice(0x71, 0x73);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const empty = proto.privex.Content.encode({}).finish();
    await receiveMessage(frame("k1", followUp(aliceState, aliceCert, carol, empty).b64), wasmCrypto);
    expect(ack).toHaveBeenCalledWith(["k1"], "tok");
    expect((await rowsOf(alice.userId)).map((r) => r.content)).toEqual(["hello"]);
    ack.mockRestore();
  });

  it("prunes processed ids only once no redelivery can come", async () => {
    await db.received.clear();
    await db.received.bulkPut([
      { message_id: "old", at: nowS() - 62 * 86_400 },
      { message_id: "recent", at: nowS() - 59 * 86_400 },
    ]);
    await pruneReceived();
    expect(await db.received.get("old")).toBeUndefined();
    expect(await db.received.get("recent")).toBeDefined();
  });
});
