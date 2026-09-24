// N3: when a contact recovered their account (new device, fresh session) and
// messaged us again, their new handshake was only adopted if their px_id sorted
// LOWER than ours (the glare tie-break). Otherwise we kept our now-dead session,
// dropped their handshake as "glare", and the chat stayed broken both ways.
// A handshake that doesn't decrypt on a session that has been WORKING means the
// peer started over, so it's adopted; genuine glare (both sides' fresh
// initiator sessions) still resolves exactly as before.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it, vi } from "vitest";

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
import { encodeEnvelope, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import { acceptContact, addVerifiedContact } from "../data/contacts";
import { clearPqxdhInit } from "../data/sessions";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { receiveMessage, resetMessaging, type MessageCryptoApi } from "../services/messaging";

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

/** A NEW session's first message from `from` to `to`, using `to`'s one-time
 *  prekey #opk (a recovered device starts a brand-new session). */
function handshake(from: IdentityBundle, to: IdentityBundle, opk: number, content: Uint8Array) {
  const pqx = pqxdhInitiate(wasm, from.identity.x25519_priv, {
    ik_x25519: to.identity.x25519_pub,
    spk_x25519: to.spk.pub,
    opk: to.opks[opk].pub,
    kyber1024_pub: to.identity.kyber1024_pub,
  });
  const enc = wasm.ratchet_encrypt(wasm.ratchet_init_alice(pqx.shared_secret, to.spk.pub), content);
  const env = encodeEnvelope(enc.message_header, enc.ciphertext, {
    alice_ik_pub: pqx.alice_ik_pub,
    alice_ek_pub: pqx.alice_ek_pub,
    kyber_ciphertext: pqx.kyber_ciphertext,
    opk_used: pqx.opk_used,
    opk_id: to.opks[opk].id,
  });
  return {
    b64: b64encode(wasm.sealed_sender_encrypt(env, certOf(from), to.identity.x25519_pub)),
    state: enc.new_session_state,
  };
}

function followUp(state: Uint8Array, from: IdentityBundle, to: IdentityBundle, content: Uint8Array): string {
  const enc = wasm.ratchet_encrypt(state, content);
  const env = encodeEnvelope(enc.message_header, enc.ciphertext);
  return b64encode(wasm.sealed_sender_encrypt(env, certOf(from), to.identity.x25519_pub));
}

/** [smaller px_id, larger px_id]. */
function orderedPair(a: number, b: number): [IdentityBundle, IdentityBundle] {
  const x = genIdentityBundle(wasm, entropy(a));
  const y = genIdentityBundle(wasm, entropy(b));
  return x.userId < y.userId ? [x, y] : [y, x];
}

async function freshMe(me: IdentityBundle) {
  resetMessaging();
  for (const t of [db.contacts, db.sessions, db.messages, db.identity, db.settings, db.received]) await t.clear();
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("tok", me.userId);
}

const frame = (id: string, b64: string) => ({ message_id: id, content: b64, queued_at: 0 });
const contents = async (pxId: string) =>
  (await new EncryptedMessages(db).listBySession(pxId)).map((m) => m.content);

describe("a contact who started over (N3)", () => {
  it("adopts a recovered contact's new session even when their px_id sorts higher", async () => {
    const [carol, alice] = orderedPair(0x11, 0x12); // alice > carol: the case that broke
    await freshMe(carol);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // A working conversation.
    const s1 = handshake(alice, carol, 0, encodeText("hi", 0));
    await receiveMessage(frame("a1", s1.b64), wasmCrypto);
    await acceptContact(alice.userId);

    // Alice recovers her account on a new device and messages Carol again.
    const s2 = handshake(alice, carol, 1, encodeText("I'm back", 0));
    await receiveMessage(frame("a2", s2.b64), wasmCrypto);
    expect(await contents(alice.userId)).toEqual(["hi", "I'm back"]);

    // ...and the conversation continues on her NEW session.
    await receiveMessage(frame("a3", followUp(s2.state, alice, carol, encodeText("new phone", 0))), wasmCrypto);
    expect(await contents(alice.userId)).toEqual(["hi", "I'm back", "new phone"]);
    ack.mockRestore();
  });

  it("treats sessions stored before this change as working conversations", async () => {
    const [carol, alice] = orderedPair(0x21, 0x22);
    await freshMe(carol);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(frame("b1", handshake(alice, carol, 0, encodeText("hi", 0)).b64), wasmCrypto);
    await acceptContact(alice.userId);
    // Simulate a row written by an older build (no received_ok field).
    const row = (await db.sessions.get(alice.userId))!;
    delete row.received_ok;
    await db.sessions.put(row);

    await receiveMessage(frame("b2", handshake(alice, carol, 1, encodeText("I'm back", 0)).b64), wasmCrypto);
    expect(await contents(alice.userId)).toEqual(["hi", "I'm back"]);
    ack.mockRestore();
  });

  it("genuine glare is unchanged: our fresh initiator session wins as the canonical side", async () => {
    const [carol, alice] = orderedPair(0x31, 0x32); // carol canonical (smaller)
    await freshMe(carol);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    // Carol added Alice (her own initiator session) and already sent the hello.
    const pqx = pqxdhInitiate(wasm, carol.identity.x25519_priv, {
      ik_x25519: alice.identity.x25519_pub,
      spk_x25519: alice.spk.pub,
      opk: alice.opks[0].pub,
      kyber1024_pub: alice.identity.kyber1024_pub,
    });
    const verified: VerifiedBundle = {
      userId: alice.userId,
      ik_ed25519: alice.identity.ed25519_pub,
      ik_dilithium3: alice.identity.dilithium3_pub,
      ik_x25519: alice.identity.x25519_pub,
      spk_x25519: alice.spk.pub,
      kyber1024_pub: alice.identity.kyber1024_pub,
      opk: alice.opks[0].pub,
      opk_id: 1,
    };
    await addVerifiedContact(verified, pqx, wasm.ratchet_init_alice(pqx.shared_secret, alice.spk.pub));
    await clearPqxdhInit(alice.userId);
    const before = hex((await db.sessions.get(alice.userId))!.ratchet_state_enc);

    // Simultaneously, Alice added Carol: her handshake arrives. Carol keeps hers.
    await receiveMessage(frame("c1", handshake(alice, carol, 0, encodeText("hi", 0)).b64), wasmCrypto);
    expect(hex((await db.sessions.get(alice.userId))!.ratchet_state_enc)).toBe(before);
    expect(await contents(alice.userId)).toEqual([]);
    expect(ack).toHaveBeenCalledWith(["c1"], "tok");
    ack.mockRestore();
  });
});
