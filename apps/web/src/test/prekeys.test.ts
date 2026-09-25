// #6: prekey upkeep. Used one-time prekeys' private halves were never deleted,
// the one-time supply was never topped up (after 50 fetches every new session
// fell back to the weaker no-OPK handshake), and the signed prekey never rotated
// on schedule (docs: every 30 ± 5 days).
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import * as oc from "../crypto/onboarding-crypto";
import { genIdentityBundle, type IdentityBundle } from "../crypto/onboarding-crypto";
import { pqxdhInitiate } from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import { encodeEnvelope, encodeText } from "../services/envelope";
import { b64encode } from "../services/bytes";
import * as store from "../onboarding/store";
import { loadBundle, persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import {
  prekeyUpkeep,
  receiveMessage,
  resetMessaging,
  type MessageCryptoApi,
} from "../services/messaging";
import {
  OPK_BATCH,
  SPK_RETAIN_SECS,
  replenishOpks,
  rotateSpkIfDue,
  type PrekeyCryptoApi,
} from "../services/prekeys";

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
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const DAY = 86_400;

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

const prekeyCrypto: PrekeyCryptoApi = {
  generateOpks: async (start, count) => oc.generateOpks(wasm, start, count),
  generateSignedSpk: async (ed, dil) => oc.generateSignedSpk(wasm, ed, dil),
};

/** Alice's first message to `to`, against the prekeys `to` published (spk + opk #opk). */
function handshake(from: IdentityBundle, to: IdentityBundle, spkPub: Uint8Array, opk: number): string {
  const pqx = pqxdhInitiate(wasm, from.identity.x25519_priv, {
    ik_x25519: to.identity.x25519_pub,
    spk_x25519: spkPub,
    opk: to.opks[opk].pub,
    kyber1024_pub: to.identity.kyber1024_pub,
  });
  const enc = wasm.ratchet_encrypt(wasm.ratchet_init_alice(pqx.shared_secret, spkPub), encodeText("hi", 0));
  const env = encodeEnvelope(enc.message_header, enc.ciphertext, {
    alice_ik_pub: pqx.alice_ik_pub,
    alice_ek_pub: pqx.alice_ek_pub,
    kyber_ciphertext: pqx.kyber_ciphertext,
    opk_used: pqx.opk_used,
    opk_id: to.opks[opk].id,
  });
  const cert = wasm.generate_sender_cert(
    from.userId,
    from.identity.ed25519_priv,
    from.identity.ed25519_pub,
    from.identity.dilithium3_priv,
    from.identity.dilithium3_pub,
    from.identity.x25519_pub,
    BigInt(nowS()),
    BigInt(86_400),
  );
  return b64encode(wasm.sealed_sender_encrypt(env, cert, to.identity.x25519_pub));
}

async function freshMe(me: IdentityBundle) {
  resetMessaging();
  for (const t of [db.contacts, db.sessions, db.messages, db.identity, db.settings, db.received, db.handshakes])
    await t.clear();
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("tok", me.userId);
}

describe("one-time prekeys", () => {
  it("forgets a one-time prekey's private half once a handshake used it", async () => {
    const alice = genIdentityBundle(wasm, entropy(0x41));
    const carol = genIdentityBundle(wasm, entropy(0x43));
    await freshMe(carol);
    vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });

    await receiveMessage(
      { message_id: "o1", content: handshake(alice, carol, carol.spk.pub, 0), queued_at: 0 },
      wasmCrypto,
    );
    expect(await new EncryptedMessages(db).listBySession(alice.userId)).toHaveLength(1);
    const stored = (await loadBundle())!;
    expect(stored.opks.some((o) => o.id === carol.opks[0].id)).toBe(false);
    expect(stored.opks).toHaveLength(carol.opks.length - 1);
  });

  it("tops up when low: new ids, private halves saved BEFORE the public halves go out", async () => {
    const me = genIdentityBundle(wasm, entropy(0x44));
    await freshMe(me);
    me.opks = me.opks.slice(0, 10); // local supply is low
    const maxId = Math.max(...me.opks.map((o) => o.id));
    const upload = vi.spyOn(api, "replenishPrekeys").mockImplementation(async (opks) => {
      const saved = (await loadBundle())!;
      for (const o of opks) expect(saved.opks.some((s) => s.id === o.opk_id)).toBe(true);
      return { stored: opks.length };
    });

    expect(await replenishOpks(me, prekeyCrypto, "tok", false)).toBe(true);
    expect(upload).toHaveBeenCalledOnce();
    const ids = upload.mock.calls[0][0].map((o) => o.opk_id);
    expect(ids).toEqual(Array.from({ length: OPK_BATCH }, (_, i) => maxId + 1 + i));
    expect(me.opks).toHaveLength(10 + OPK_BATCH);
  });

  it("a full local supply isn't topped up unless the server says it's low; unused keys are kept", async () => {
    const me = genIdentityBundle(wasm, entropy(0x45));
    await freshMe(me);
    const start = me.opks.length;
    const upload = vi.spyOn(api, "replenishPrekeys").mockResolvedValue({ stored: OPK_BATCH });
    expect(await replenishOpks(me, prekeyCrypto, "tok", false)).toBe(false);
    expect(upload).not.toHaveBeenCalled();

    // A drain (fetches that never became messages) keeps the server low. Every
    // private half is kept until a handshake uses it - no cap that could strand a
    // first message still queued for us.
    for (let i = 0; i < 5; i++) await replenishOpks(me, prekeyCrypto, "tok", true);
    expect(upload).toHaveBeenCalledTimes(5);
    expect(me.opks).toHaveLength(start + 5 * OPK_BATCH);
    expect(me.opks[0].id).toBe(1);
  });

  it("a batch whose upload failed is re-sent as-is, not replaced", async () => {
    const me = genIdentityBundle(wasm, entropy(0x46));
    await freshMe(me);
    me.opks = me.opks.slice(0, 10);
    const gen = vi.spyOn(prekeyCrypto, "generateOpks");
    const upload = vi.spyOn(api, "replenishPrekeys").mockRejectedValueOnce(new Error("offline"));
    await expect(replenishOpks(me, prekeyCrypto, "tok", false)).rejects.toThrow("offline");
    const batch = (await loadBundle())!.opkPending!;
    expect(batch).toHaveLength(OPK_BATCH); // survives a reload

    upload.mockResolvedValue({ stored: OPK_BATCH });
    expect(await replenishOpks(me, prekeyCrypto, "tok", false)).toBe(true);
    expect(upload.mock.calls.at(-1)![0].map((o) => o.opk_id)).toEqual(batch); // the same keys
    expect(gen).toHaveBeenCalledOnce(); // nothing new generated
    expect((await loadBundle())!.opkPending).toBeUndefined();
  });

  it("a server-low signal during a running upkeep pass is not lost", async () => {
    const me = genIdentityBundle(wasm, entropy(0x47));
    await freshMe(me); // full local supply: only a server-low pass tops up
    vi.spyOn(api, "spkRotate").mockResolvedValue({ rotated: true });
    const upload = vi.spyOn(api, "replenishPrekeys").mockResolvedValue({ stored: OPK_BATCH });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow: PrekeyCryptoApi = {
      ...prekeyCrypto,
      generateSignedSpk: async (ed, dil) => {
        await gate; // the first pass is busy rotating...
        return prekeyCrypto.generateSignedSpk(ed, dil);
      },
    };
    const first = prekeyUpkeep(false, slow);
    await prekeyUpkeep(true, slow); // ...when the server says it's low
    release();
    await first;
    expect(upload).toHaveBeenCalledOnce();
  });

  it("a failed save while forgetting a used one-time key doesn't fail the delivery", async () => {
    const alice = genIdentityBundle(wasm, entropy(0x48));
    const carol = genIdentityBundle(wasm, entropy(0x49));
    await freshMe(carol);
    const ack = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    vi.spyOn(store, "saveBundle").mockRejectedValue(new Error("disk full"));
    await receiveMessage(
      { message_id: "o2", content: handshake(alice, carol, carol.spk.pub, 0), queued_at: 0 },
      wasmCrypto,
    );
    expect(await new EncryptedMessages(db).listBySession(alice.userId)).toHaveLength(1);
    expect(ack).toHaveBeenCalledWith(["o2"], "tok");
  });
});

describe("signed prekey rotation", () => {
  it("rotates when due, keeps retired keys for the max message TTL, and schedules 30 ± 5 days out", async () => {
    const me = genIdentityBundle(wasm, entropy(0x51));
    await freshMe(me);
    const first = hex(me.spk.pub);
    const publish = vi.spyOn(api, "spkRotate").mockImplementation(async (body) => {
      // The new private half is stored before the server learns the public half.
      expect(hex((await loadBundle())!.spk.pub)).toBe(body.spk_x25519_pub);
      return { rotated: true };
    });

    const t0 = nowS();
    expect(await rotateSpkIfDue(me, prekeyCrypto, "tok", t0)).toBe(true); // age unknown → rotate
    expect(hex(me.spk.pub)).not.toBe(first);
    expect(me.prevSpks!.map((k) => hex(k.pub))).toEqual([first]);
    expect(me.spkPending).toBe(false);
    expect(me.spkRotateAfter! - t0).toBeGreaterThanOrEqual(25 * DAY);
    expect(me.spkRotateAfter! - t0).toBeLessThan(35 * DAY);

    // Not due yet → nothing happens.
    expect(await rotateSpkIfDue(me, prekeyCrypto, "tok", t0 + DAY)).toBe(false);
    // Two more rotations in quick succession (as "log out everywhere" can cause):
    // every retired key is still inside its window, so all are kept.
    me.spkRotateAfter = undefined;
    await rotateSpkIfDue(me, prekeyCrypto, "tok", t0 + 10);
    me.spkRotateAfter = undefined;
    await rotateSpkIfDue(me, prekeyCrypto, "tok", t0 + 20);
    expect(me.prevSpks).toHaveLength(3);
    expect(me.prevSpks!.map((k) => hex(k.pub))).toContain(first);
    expect(publish).toHaveBeenCalledTimes(3);

    // Once a key's window has passed, it's forgotten (checked on every upkeep).
    me.spkRotateAfter = t0 + 400 * DAY;
    expect(await rotateSpkIfDue(me, prekeyCrypto, "tok", t0 + SPK_RETAIN_SECS + 15)).toBe(false);
    expect(me.prevSpks).toHaveLength(1); // only the key retired at t0 + 20 remains
    expect((await loadBundle())!.prevSpks).toHaveLength(1);
  });

  it("never publishes a signed prekey whose private half wasn't saved", async () => {
    const me = genIdentityBundle(wasm, entropy(0x55));
    await freshMe(me);
    const before = hex(me.spk.pub);
    const publish = vi.spyOn(api, "spkRotate").mockResolvedValue({ rotated: true });
    vi.spyOn(store, "saveBundle").mockRejectedValueOnce(new Error("disk full"));
    await expect(rotateSpkIfDue(me, prekeyCrypto, "tok", nowS())).rejects.toThrow("disk full");
    expect(publish).not.toHaveBeenCalled();
    expect(hex(me.spk.pub)).toBe(before); // the cached identity didn't move ahead
    expect(me.spkPending).toBeFalsy();

    // The next pass rotates afresh; what it publishes is what's stored.
    expect(await rotateSpkIfDue(me, prekeyCrypto, "tok", nowS())).toBe(true);
    expect(publish.mock.calls[0][0].spk_x25519_pub).toBe(hex((await loadBundle())!.spk.pub));
  });

  it("retries publishing a rotation the server never confirmed", async () => {
    const me = genIdentityBundle(wasm, entropy(0x52));
    await freshMe(me);
    vi.spyOn(api, "spkRotate").mockRejectedValueOnce(new Error("offline"));
    await expect(rotateSpkIfDue(me, prekeyCrypto, "tok", nowS())).rejects.toThrow("offline");
    expect((await loadBundle())!.spkPending).toBe(true); // survives a reload

    const retry = vi.spyOn(api, "spkRotate").mockResolvedValue({ rotated: true });
    expect(await rotateSpkIfDue(me, prekeyCrypto, "tok", nowS())).toBe(true);
    expect(retry.mock.calls.at(-1)![0].spk_x25519_pub).toBe(hex(me.spk.pub)); // same key, republished
    expect(me.spkPending).toBe(false);
  });

  it("a handshake sent before a rotation still opens (previous signed prekey)", async () => {
    const alice = genIdentityBundle(wasm, entropy(0x53));
    const carol = genIdentityBundle(wasm, entropy(0x54));
    await freshMe(carol);
    vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    vi.spyOn(api, "spkRotate").mockResolvedValue({ rotated: true });
    vi.spyOn(api, "replenishPrekeys").mockResolvedValue({ stored: 0 });

    // Alice fetched Carol's bundle (old SPK) and sends later...
    const inFlight = handshake(alice, carol, carol.spk.pub, 0);
    // ...after Carol's app rotated its signed prekey.
    await prekeyUpkeep(false, prekeyCrypto);
    expect(hex((await loadBundle())!.spk.pub)).not.toBe(hex(carol.spk.pub));

    await receiveMessage({ message_id: "r1", content: inFlight, queued_at: 0 }, wasmCrypto);
    expect(
      (await new EncryptedMessages(db).listBySession(alice.userId)).map((m) => m.content),
    ).toEqual(["hi"]);
  });
});
