// Cross-device sync (docs 4.11 Mode C): pairwise key derivation, the padded
// AES-GCM sync codec, opt-in fan-out on send, and the full receiveMessage path
// for an incoming sync copy (self-authenticated, device-addressed, un-acked
// pass-through for other devices).
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
import { decodeEnvelope, encodeDeviceSyncEnvelope } from "../services/envelope";
import { b64decode, b64encode } from "../services/bytes";
import { acceptContact, addVerifiedContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { receiveMessage, resetMessaging, sendMessage, type MessageCryptoApi } from "../services/messaging";
import {
  decryptSyncRecord,
  deriveSyncKey,
  deviceSyncEnabled,
  encryptSyncRecord,
  myDeviceId,
  setDeviceSyncEnabled,
  storeLinkedDevice,
  syncTargets,
  type SyncRecord,
} from "../services/device-sync";

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
    db.linked_devices.clear(),
  ]);
});

const entropy = (f: number) => new Uint8Array(32).fill(f);
const CHANNEL_SECRET = new Uint8Array(32).fill(0x42);
const OTHER_DEVICE = "ab".repeat(16);

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

async function setupMe(fill: number): Promise<IdentityBundle> {
  const me = genIdentityBundle(wasm, entropy(fill));
  await persistGeneratedIdentity(me);
  useAuth.getState().setSession("test-token", me.userId);
  return me;
}

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

/** Seal a sync copy the way another linked device of MY OWN identity would. */
async function sealedSyncCopy(
  me: IdentityBundle,
  rec: SyncRecord,
  toDevice: string,
  fromDevice: string,
  sendKey: Uint8Array,
  senderIdentity: IdentityBundle = me,
): Promise<string> {
  const blob = await encryptSyncRecord(rec, sendKey);
  const env = encodeDeviceSyncEnvelope({
    toDevice: Uint8Array.from(Buffer.from(toDevice, "hex")),
    fromDevice: Uint8Array.from(Buffer.from(fromDevice, "hex")),
    blob,
  });
  const cert = wasm.generate_sender_cert(
    senderIdentity.userId,
    senderIdentity.identity.ed25519_priv,
    senderIdentity.identity.ed25519_pub,
    senderIdentity.identity.dilithium3_priv,
    senderIdentity.identity.dilithium3_pub,
    BigInt(Math.floor(Date.now() / 1000)),
    BigInt(86_400),
  );
  return b64encode(wasm.sealed_sender_encrypt(env, cert, me.identity.x25519_pub));
}

describe("sync codec + key derivation", () => {
  it("round-trips a record; blobs are padded to a constant size regardless of length", async () => {
    const key = await deriveSyncKey(CHANNEL_SECRET, OTHER_DEVICE);
    const a = await encryptSyncRecord(
      { v: 1, msg_id: "m1", peer_id: "px_x", kind: "text", content: "hi", ts: 5 },
      key,
    );
    const b = await encryptSyncRecord(
      { v: 1, msg_id: "m2", peer_id: "px_x", kind: "text", content: "a much longer message body ".repeat(8), ts: 6 },
      key,
    );
    expect(a.length).toBe(b.length); // 1024-boundary padding law
    const back = await decryptSyncRecord(a, key);
    expect(back).toEqual({ v: 1, msg_id: "m1", peer_id: "px_x", kind: "text", content: "hi", ts: 5 });
    // Wrong key must not decrypt (AES-GCM auth).
    const wrong = await deriveSyncKey(CHANNEL_SECRET, "cd".repeat(16));
    await expect(decryptSyncRecord(a, wrong)).rejects.toThrow();
  });

  it("pairwise symmetry: my send-key to device X equals X's recv-key from me", async () => {
    // A stores B: send = HKDF(cs, B_id), recv = HKDF(cs, A_id).
    // B stores A: send = HKDF(cs, A_id), recv = HKDF(cs, B_id). Mirror by construction.
    const aId = "11".repeat(16);
    const bId = "22".repeat(16);
    const aSend = await deriveSyncKey(CHANNEL_SECRET, bId);
    const bRecv = await deriveSyncKey(CHANNEL_SECRET, bId);
    expect(toHex(aSend)).toBe(toHex(bRecv));
    expect(toHex(await deriveSyncKey(CHANNEL_SECRET, aId))).not.toBe(toHex(aSend));
  });

  it("stores link keys encrypted at rest and opt-in gates the targets", async () => {
    await storeLinkedDevice(CHANNEL_SECRET, OTHER_DEVICE, "Phone");
    const row = await db.linked_devices.get(OTHER_DEVICE);
    const expected = await deriveSyncKey(CHANNEL_SECRET, OTHER_DEVICE);
    // At rest: AES-GCM ciphertext, not the raw key bytes.
    expect(toHex(row!.send_key_enc)).not.toContain(toHex(expected));

    expect(await deviceSyncEnabled()).toBe(false); // DEFAULT OFF (opt-in)
    expect(await syncTargets()).toEqual([]); // off → no fan-out even when linked
    await setDeviceSyncEnabled(true);
    const targets = await syncTargets();
    expect(targets).toHaveLength(1);
    expect(toHex(targets[0].send_key)).toBe(toHex(expected)); // decrypts to the derived key
  });
});

describe("fan-out on send (opt-in)", () => {
  it("sends one indistinguishable self-copy per linked device; none when disabled", async () => {
    const me = await setupMe(0xf1);
    const peer = genIdentityBundle(wasm, entropy(0xf2));
    await addAccepted(me, peer);
    await storeLinkedDevice(CHANNEL_SECRET, OTHER_DEVICE, "Phone");

    // Disabled (default): exactly one send - to the peer.
    let calls: Array<{ to: string; content: string }> = [];
    const spy = vi.spyOn(api, "sendMessage").mockImplementation(async (to, content) => {
      calls.push({ to, content });
      return { queued: true, message_id: `srv-${calls.length}`, expires_at: 0 };
    });
    await sendMessage(peer.userId, "no sync", wasmCrypto);
    await new Promise((r) => setTimeout(r, 50)); // fan-out is fire-and-forget
    expect(calls.map((c) => c.to)).toEqual([peer.userId]);

    // Enabled: peer send + one self-addressed sync copy.
    calls = [];
    await setDeviceSyncEnabled(true);
    await sendMessage(peer.userId, "with sync", wasmCrypto);
    await vi.waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0].to).toBe(peer.userId);
    expect(calls[1].to).toBe(me.userId); // self-addressed

    // The self-copy is a normal Sealed Sender blob the "other device" (same
    // identity) can open, addressed to it, decryptable with the pairwise key.
    const opened = wasm.sealed_sender_decrypt(
      b64decode(calls[1].content),
      me.identity.x25519_priv,
      BigInt(Math.floor(Date.now() / 1000)),
    );
    expect(opened.sender_id).toBe(me.userId);
    const env = decodeEnvelope(opened.plaintext);
    expect(env.deviceSync).toBeDefined();
    expect(toHex(env.deviceSync!.toDevice)).toBe(OTHER_DEVICE);
    const rec = await decryptSyncRecord(
      env.deviceSync!.blob,
      await deriveSyncKey(CHANNEL_SECRET, OTHER_DEVICE),
    );
    expect(rec.peer_id).toBe(peer.userId);
    expect(rec.content).toBe("with sync");
    expect(rec.msg_id).toBe("srv-1"); // the server id of the real send
    spy.mockRestore();
  });
});

describe("receiving a sync copy", () => {
  it("stores it as a sent message (acked), ignores copies for other devices (un-acked)", async () => {
    const me = await setupMe(0xf3);
    const myId = await myDeviceId();
    // Link the origin device; my recv-key from it = HKDF(cs, MY device id).
    await storeLinkedDevice(CHANNEL_SECRET, OTHER_DEVICE, "PC");
    const sendKeyToMe = await deriveSyncKey(CHANNEL_SECRET, myId);

    const rec: SyncRecord = {
      v: 1,
      msg_id: "sync-1",
      peer_id: "px_" + "ef".repeat(16),
      kind: "text",
      content: "sent elsewhere",
      ts: 1234,
    };

    // Addressed to ME → stored as my own sent message + acked.
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      {
        message_id: "q1",
        content: await sealedSyncCopy(me, rec, myId, OTHER_DEVICE, sendKeyToMe),
        queued_at: 0,
      },
      wasmCrypto,
    );
    const msgs = await new EncryptedMessages(db).listBySession(rec.peer_id);
    expect(msgs).toHaveLength(1);
    expect(msgs[0].direction).toBe("out");
    expect(msgs[0].status).toBe("sent");
    expect(msgs[0].content).toBe("sent elsewhere");
    expect(ackSpy).toHaveBeenCalledWith(["q1"], "test-token");

    // Addressed to a DIFFERENT device → untouched AND left un-acked (stays queued
    // for that device; the shared mailbox has no per-device fan-out).
    ackSpy.mockClear();
    await receiveMessage(
      {
        message_id: "q2",
        content: await sealedSyncCopy(
          me,
          { ...rec, msg_id: "sync-2" },
          "99".repeat(16),
          OTHER_DEVICE,
          await deriveSyncKey(CHANNEL_SECRET, "99".repeat(16)),
        ),
        queued_at: 0,
      },
      wasmCrypto,
    );
    expect(ackSpy).not.toHaveBeenCalled();
    expect(await new EncryptedMessages(db).listBySession(rec.peer_id)).toHaveLength(1);
    ackSpy.mockRestore();
  });

  it("rejects a forged sync copy from a different identity (acked + dropped)", async () => {
    const me = await setupMe(0xf4);
    const attacker = genIdentityBundle(wasm, entropy(0xf5));
    const myId = await myDeviceId();
    await storeLinkedDevice(CHANNEL_SECRET, OTHER_DEVICE, "PC");

    const rec: SyncRecord = {
      v: 1,
      msg_id: "evil-1",
      peer_id: "px_" + "aa".repeat(16),
      kind: "text",
      content: "injected fake sent history",
      ts: 1,
    };
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      {
        message_id: "q3",
        content: await sealedSyncCopy(
          me,
          rec,
          myId,
          OTHER_DEVICE,
          await deriveSyncKey(CHANNEL_SECRET, myId),
          attacker, // signed by someone else's identity → senderId ≠ me
        ),
        queued_at: 0,
      },
      wasmCrypto,
    );
    expect(await new EncryptedMessages(db).listBySession(rec.peer_id)).toHaveLength(0);
    expect(ackSpy).toHaveBeenCalled(); // garbage is drained, not redelivered forever
    ackSpy.mockRestore();
  });
});
