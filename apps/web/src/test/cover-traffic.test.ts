// Cover traffic (docs 5.3 / 5.7): the Poisson tick drains due receipts and emits a
// fixed-size dummy send (skipped when the user turns cover traffic off), and the
// dummy send is a normal-looking sealed POST to a random non-existent px_id.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle } from "../crypto/onboarding-crypto";
import * as mc from "../crypto/message-crypto";
import { persistGeneratedIdentity } from "../onboarding/store";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { resetMessaging, sendCoverMessage, type MessageCryptoApi } from "../services/messaging";
import { runCoverCycle } from "../services/cover-traffic";

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
  await Promise.all([db.identity.clear(), db.settings.clear(), db.receipt_outbox.clear()]);
  useAuth.setState({ sessionToken: null, userId: null, authenticated: false });
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

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

const dueReceipt = (token: string, type: "delivered" | "read") =>
  db.receipt_outbox.add({
    to: "px_" + "aa".repeat(16),
    token_hex: token,
    receipt_type: type,
    queued_at: 0,
    not_before: 0, // already due
  });

describe("cover-traffic Poisson cycle", () => {
  it("drains due receipts AND emits a cover send when cover traffic is on", async () => {
    await dueReceipt("bb".repeat(32), "delivered");
    const drained: string[] = [];
    let cover = 0;
    await runCoverCycle(
      async (to) => {
        drained.push(to);
      },
      async () => {
        cover += 1;
      },
      "medium",
    );
    expect(drained).toHaveLength(1); // receipt sent on the tick
    expect(cover).toBe(1); // one dummy cover send per tick
    expect(await db.receipt_outbox.count()).toBe(0);
  });

  it('still drains receipts but emits NO cover send when level is "off"', async () => {
    await dueReceipt("cc".repeat(32), "read");
    const drained: string[] = [];
    let cover = 0;
    await runCoverCycle(
      async (to) => {
        drained.push(to);
      },
      async () => {
        cover += 1;
      },
      "off",
    );
    expect(drained).toHaveLength(1); // receipts must not break when cover is off
    expect(cover).toBe(0); // but no dummy traffic
  });
});

describe("dummy cover send (docs 5.3)", () => {
  it("posts a fixed-size sealed blob to a random non-existent px_id; swallows errors", async () => {
    const me = genIdentityBundle(wasm, entropy(0x77));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("tok", me.userId);

    const calls: Array<{ to: string; content: string }> = [];
    const spy = vi.spyOn(api, "sendMessage").mockImplementation(async (to, content) => {
      calls.push({ to, content });
      return { queued: true, message_id: "x" };
    });
    await sendCoverMessage(wasmCrypto);
    spy.mockRestore();

    expect(calls).toHaveLength(1);
    expect(calls[0].to).toMatch(/^px_[0-9a-f]{32}$/); // valid, random recipient id
    expect(calls[0].to).not.toBe(me.userId); // not self
    expect(calls[0].content.length).toBeGreaterThan(1000); // ~1024-byte sealed blob (base64)

    // Rate-limited / offline → never throws to the tick loop.
    const spy2 = vi.spyOn(api, "sendMessage").mockRejectedValue(new api.ApiError(429));
    await expect(sendCoverMessage(wasmCrypto)).resolves.toBeUndefined();
    spy2.mockRestore();
  });
});
