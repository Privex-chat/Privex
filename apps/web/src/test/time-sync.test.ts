// Time synchronization (docs 9.6): signed-timestamp verification against the
// pinned key, drift detection, anchor storage on the receive path, and anchored
// ordering that defeats a sender's manipulated clock.
//
// The test signer: wasm sign_hybrid's sig_ed25519 is a plain Ed25519 signature
// over the input bytes - the same shape kt_verify_root_sig (our verifier) checks.
// The pinned pub is env-driven (VITE_TIME_SIGNING_PUB), so tests inject `verify`
// with the test signer's pub instead of relying on the build pin.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

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
import { addVerifiedContact } from "../data/contacts";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { receiveMessage, resetMessaging, type MessageCryptoApi } from "../services/messaging";
import {
  checkDeliveryTime,
  clockStatus,
  timeSigningInput,
  type VerifyEd25519,
} from "../services/time-sync";

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
  ]);
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

// Test time signer: an identity whose ed25519 key stands in for TIME_SIGNING_KEY.
let signer: IdentityBundle;
const signTs = (serverTs: number, queuedAt: number, msgId: string): string => {
  const sig = wasm.sign_hybrid(
    timeSigningInput(serverTs, queuedAt, msgId),
    signer.identity.ed25519_priv,
    signer.identity.dilithium3_priv,
  );
  return Array.from(sig.sig_ed25519, (b) => b.toString(16).padStart(2, "0")).join("");
};
// Verifier pinned to the TEST signer's pub (production pins via config/env).
const testVerify: VerifyEd25519 = async (msg, sig) =>
  wasm.kt_verify_root_sig(msg, sig, signer.identity.ed25519_pub);

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

/** Peer's sealed first message carrying `sentAt` as the claimed timestamp. */
function sealedText(sender: IdentityBundle, recipient: IdentityBundle, body: string, sentAt: number): string {
  const pqx = pqxdhInitiate(wasm, sender.identity.x25519_priv, {
    ik_x25519: recipient.identity.x25519_pub,
    spk_x25519: recipient.spk.pub,
    opk: recipient.opks[0].pub,
    kyber1024_pub: recipient.identity.kyber1024_pub,
  });
  const state = wasm.ratchet_init_alice(pqx.shared_secret, recipient.spk.pub);
  const enc = wasm.ratchet_encrypt(state, encodeText(body, sentAt));
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
    BigInt(Math.floor(Date.now() / 1000)),
    BigInt(86_400),
  );
  return b64encode(wasm.sealed_sender_encrypt(envelope, cert, recipient.identity.x25519_pub));
}

describe("signed delivery timestamps", () => {
  beforeAll(() => {
    signer = genIdentityBundle(wasm, entropy(0x99));
  });

  it("accepts a valid signature (anchor = queued_at) and measures drift", async () => {
    const r = await checkDeliveryTime(
      { message_id: "m1", queued_at: 1_000_000, server_ts: 1_000_500, server_ts_sig: signTs(1_000_500, 1_000_000, "m1") },
      testVerify,
      () => 1_000_530, // local clock 30s ahead of server → within 90s
    );
    expect(r.validSignature).toBe(true);
    expect(r.anchor).toBe(1_000_000);
    expect(r.driftSeconds).toBe(30);
    expect(r.withinTolerance).toBe(true);
  });

  it("flags out-of-tolerance drift (uses server anchor, warns, never drops)", async () => {
    const r = await checkDeliveryTime(
      { message_id: "m2", queued_at: 2_000_000, server_ts: 2_000_000, server_ts_sig: signTs(2_000_000, 2_000_000, "m2") },
      testVerify,
      () => 2_000_000 + 600, // clock 10 min ahead
    );
    expect(r.validSignature).toBe(true);
    expect(r.withinTolerance).toBe(false);
    expect(r.driftSeconds).toBe(600);
    expect(r.anchor).toBe(2_000_000);
    expect(clockStatus().warning).toBe(true); // UI warning latched

    // A later in-tolerance sample clears the warning.
    await checkDeliveryTime(
      { message_id: "m3", queued_at: 2_000_700, server_ts: 2_000_700, server_ts_sig: signTs(2_000_700, 2_000_700, "m3") },
      testVerify,
      () => 2_000_710,
    );
    expect(clockStatus().warning).toBe(false);
  });

  it("rejects a tampered signature/timestamp: no anchor, no drift signal", async () => {
    const sig = signTs(3_000_000, 3_000_000, "m4");
    // Server (or a relay) lies about the timestamp after signing.
    const r = await checkDeliveryTime(
      { message_id: "m4", queued_at: 3_000_000, server_ts: 3_009_999, server_ts_sig: sig },
      testVerify,
      () => 3_000_010,
    );
    expect(r.validSignature).toBe(false);
    expect(r.anchor).toBeUndefined();

    // Absent fields (old server / synthetic frame) → same safe fallback.
    const none = await checkDeliveryTime({ message_id: "m5", queued_at: 1 }, testVerify);
    expect(none.validSignature).toBe(false);
    expect(none.anchor).toBeUndefined();
  });

  it("stores the anchor on received rows and orders by it (defeats clock manipulation)", async () => {
    const me = genIdentityBundle(wasm, entropy(0xa7));
    const peer = genIdentityBundle(wasm, entropy(0xa8));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("test-token", me.userId);
    const pqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
      ik_x25519: peer.identity.x25519_pub,
      spk_x25519: peer.spk.pub,
      opk: peer.opks[0].pub,
      kyber1024_pub: peer.identity.kyber1024_pub,
    });
    await addVerifiedContact(verifiedOf(peer), pqx, wasm.ratchet_init_alice(pqx.shared_secret, peer.spk.pub));

    // The peer CLAIMS a far-future sent time (desync attack, docs 9.6 RISK 2),
    // but the server observed it arriving at queued_at = 5_000_000.
    const farFuture = 9_999_999_999;
    const ackSpy = vi.spyOn(api, "ackMessages").mockResolvedValue({ deleted: 1 });
    await receiveMessage(
      {
        message_id: "attack-1",
        content: sealedText(peer, me, "claims the future", farFuture),
        queued_at: 5_000_000,
        server_ts: 5_000_400,
        server_ts_sig: signTs(5_000_400, 5_000_000, "attack-1"),
      },
      wasmCrypto,
      testVerify,
    );
    ackSpy.mockRestore();

    // Row keeps the claimed time for DISPLAY but the signed anchor for ORDER.
    const store = new EncryptedMessages(db);
    const [got] = await store.listBySession(peer.userId);
    expect(got.timestamp).toBe(farFuture);
    expect(got.server_anchor).toBe(5_000_000);

    // A LATER local message must sort AFTER the attack message because its
    // created_at (Date.now()) is strictly later than the attack message's
    // created_at (also Date.now(), set when receiveMessage processed it).
    const later = Date.now();
    await store.add({
      msg_id: "later-local",
      session_id: peer.userId,
      content: "sent after",
      timestamp: 6_000_000,
      created_at: later,
      status: "sent",
      direction: "out",
      kind: "text",
    });
    const ordered = await store.listBySession(peer.userId);
    expect(ordered.map((m) => m.msg_id)).toEqual(["attack-1", "later-local"]);
  });
});
