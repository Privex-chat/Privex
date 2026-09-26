// Account recovery / history restore end to end. After a restore the contacts
// come back but their session keys don't, and:
//  1. sending to a restored contact failed with "no session - add this contact
//     first" - now the send starts a fresh session (the message carries the
//     handshake);
//  2. re-adding a contact who already has us left us waiting forever for an
//     accept they would never send - now they confirm right back, and a real
//     message from them counts as the accept too.
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

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
import {
  decodeContent,
  decodeEnvelope,
  encodeContactHello,
  encodeEnvelope,
  encodeText,
} from "../services/envelope";
import { b64decode, b64encode } from "../services/bytes";
import { acceptContact, addVerifiedContact, getContact, restoreContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import * as handshake from "../contacts/handshake";
import {
  receiveMessage,
  resetMessaging,
  sendContactHello,
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

afterEach(() => vi.restoreAllMocks());

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

function verifiedOf(b: IdentityBundle, opk = 0): VerifiedBundle {
  return {
    userId: b.userId,
    ik_ed25519: b.identity.ed25519_pub,
    ik_dilithium3: b.identity.dilithium3_pub,
    ik_x25519: b.identity.x25519_pub,
    spk_x25519: b.spk.pub,
    kyber1024_pub: b.identity.kyber1024_pub,
    opk: b.opks[opk].pub,
    opk_id: b.opks[opk].id,
  };
}

/** What handshake.startSession does, minus the PoW-gated bundle fetch + KT check:
 *  PQXDH against `peer`'s published prekeys, stored as our session with them. */
async function localStartSession(me: IdentityBundle, peer: IdentityBundle, opk: number) {
  const pqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
    ik_x25519: peer.identity.x25519_pub,
    spk_x25519: peer.spk.pub,
    opk: peer.opks[opk].pub,
    kyber1024_pub: peer.identity.kyber1024_pub,
  });
  await addVerifiedContact(verifiedOf(peer, opk), pqx, wasm.ratchet_init_alice(pqx.shared_secret, peer.spk.pub));
}

/** The peer's side of a message we sent: open it, complete PQXDH if it carries a
 *  handshake, decrypt. Returns the content and the peer's ratchet state. */
function peerOpens(peer: IdentityBundle, sealedB64: string, opkIdx: number, state?: Uint8Array) {
  const opened = mc.sealedSenderDecrypt(wasm, b64decode(sealedB64), peer.identity.x25519_priv, nowS());
  const env = decodeEnvelope(opened.plaintext);
  let s = state;
  if (env.pqxdh) {
    const shared = mc.pqxdhRespond(wasm, env.pqxdh, peer.identity.x25519_priv, peer.spk.priv,
      peer.opks[opkIdx].priv, peer.identity.kyber1024_priv);
    s = mc.ratchetInitBob(wasm, shared, peer.spk.priv, peer.spk.pub);
  }
  const dec = mc.ratchetDecrypt(wasm, s!, env.ciphertext, env.header);
  return { handshake: !!env.pqxdh, content: decodeContent(dec.plaintext), state: dec.newState };
}

/** A NEW session's first message from `from` to `to` (a recovered device). */
function handshakeMsg(from: IdentityBundle, to: IdentityBundle, opk: number, content: Uint8Array) {
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

function sealedReply(from: IdentityBundle, to: IdentityBundle, state: Uint8Array, content: Uint8Array) {
  const enc = wasm.ratchet_encrypt(state, content);
  const env = encodeEnvelope(enc.message_header, enc.ciphertext);
  return b64encode(wasm.sealed_sender_encrypt(env, certOf(from), to.identity.x25519_pub));
}

async function freshMe(me: IdentityBundle) {
  resetMessaging();
  for (const t of [db.contacts, db.sessions, db.messages, db.identity, db.settings, db.received, db.handshakes])
    await t.clear();
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("tok", me.userId);
}

const frame = (id: string, b64: string) => ({ message_id: id, content: b64, queued_at: 0 });
const contents = async (pxId: string) =>
  (await new EncryptedMessages(db).listBySession(pxId)).map((m) => m.content);

describe("after an account recovery / history restore", () => {
  it("sending to a restored contact starts a fresh session instead of failing", async () => {
    const alice = genIdentityBundle(wasm, entropy(0x61));
    const bob = genIdentityBundle(wasm, entropy(0x62));
    await freshMe(alice);
    // Restored from a backup: an accepted contact, but no session.
    await restoreContact(bob.userId, bob.identity.ed25519_pub, bob.identity.x25519_pub, "accepted");
    const start = vi
      .spyOn(handshake, "startSession")
      .mockImplementation(async () => (await localStartSession(alice, bob, 0), verifiedOf(bob, 0)));
    const sent = vi.spyOn(api, "sendMessage").mockResolvedValue({ queued: true, message_id: "m1", expires_at: 0 });

    await sendMessage(bob.userId, "hi after restore", wasmCrypto);

    expect(start).toHaveBeenCalledOnce();
    const got = peerOpens(bob, sent.mock.calls[0][1], 0);
    expect(got.handshake).toBe(true); // the message carries the new handshake...
    expect(got.content.text?.body).toBe("hi after restore"); // ...and opens on it
    expect((await getContact(bob.userId))?.status).toBe("accepted"); // not downgraded
  });

  it("a contact who already has us confirms a re-request right back", async () => {
    const carol = genIdentityBundle(wasm, entropy(0x63));
    const alice = genIdentityBundle(wasm, entropy(0x64));
    await freshMe(carol);
    vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const sent = vi.spyOn(api, "sendMessage").mockResolvedValue({ queued: true, message_id: "x", expires_at: 0 });

    // A working conversation.
    await receiveMessage(frame("c1", handshakeMsg(alice, carol, 0, encodeText("hi", 0)).b64), wasmCrypto);
    await acceptContact(alice.userId);

    // Alice recovered her account and re-added Carol: a new handshake + request.
    const again = handshakeMsg(alice, carol, 1, encodeContactHello(0));
    await receiveMessage(frame("c2", again.b64), wasmCrypto);

    // Carol answered with contact_accept, on Alice's NEW session.
    expect(sent).toHaveBeenCalledOnce();
    expect(sent.mock.calls[0][0]).toBe(alice.userId);
    const opened = mc.sealedSenderDecrypt(wasm, b64decode(sent.mock.calls[0][1]), alice.identity.x25519_priv, nowS());
    const env = decodeEnvelope(opened.plaintext);
    const dec = mc.ratchetDecrypt(wasm, again.state, env.ciphertext, env.header);
    expect(decodeContent(dec.plaintext).contactAccept).toBe(true);
    expect((await getContact(alice.userId))?.status).toBe("accepted");
  });

  it("a real message from someone we're waiting on counts as their accept", async () => {
    const alice = genIdentityBundle(wasm, entropy(0x65));
    const bob = genIdentityBundle(wasm, entropy(0x66));
    await freshMe(alice);
    vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    const sent = vi.spyOn(api, "sendMessage").mockResolvedValue({ queued: true, message_id: "h", expires_at: 0 });

    // Alice re-added Bob (pending_outbound); her request carries the handshake.
    await localStartSession(alice, bob, 0);
    await sendContactHello(bob.userId, wasmCrypto);
    expect((await getContact(bob.userId))?.status).toBe("pending_outbound");

    // Bob's (older) app never sends contact_accept - it just replies.
    const bobSide = peerOpens(bob, sent.mock.calls[0][1], 0);
    await receiveMessage(frame("b1", sealedReply(bob, alice, bobSide.state, encodeText("hey", 0))), wasmCrypto);

    expect((await getContact(bob.userId))?.status).toBe("accepted");
    expect(await contents(bob.userId)).toEqual(["hey"]);
  });
});
