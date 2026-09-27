// Regression (N1): account recovery must REPLACE the server's one-time-prekey
// inventory, not add to it. The recovered device reuses prekey ids 1..N, so a
// plain add (server ON CONFLICT DO NOTHING) kept serving the OLD prekeys, whose
// private halves died with the lost device - and every peer who fetched one sent
// a first message the recovered account could never decrypt.
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));
// The only worker call on this path is the auth-challenge signature; run it on
// the wasm directly (no SharedWorker in Node).
vi.mock("../workers/crypto-client", async () => {
  const { wasm } = await import("../crypto/wasm");
  const oc = await import("../crypto/onboarding-crypto");
  return {
    cryptoCall: async (method: string, a: unknown[]) => {
      if (method !== "sign_challenge") throw new Error(`unexpected crypto call ${method}`);
      return oc.signHybrid(
        wasm,
        oc.challengeSigningInput(a[0] as Uint8Array, a[1] as string, a[2] as number),
        a[3] as Uint8Array,
        a[4] as Uint8Array,
      );
    },
  };
});

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, recoverBundleFromSeed } from "../crypto/onboarding-crypto";
import { recoverWithSeed, type RecoveryCryptoApi } from "../services/recovery";
import { loadProgress } from "../onboarding/store";
import * as api from "../api/client";
import { db } from "../db";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
});

afterEach(() => vi.restoreAllMocks());

describe("seed recovery re-provisions prekeys", () => {
  it("replaces the server's whole one-time-prekey inventory", async () => {
    await db.identity.clear();
    const original = genIdentityBundle(wasm, new Uint8Array(32).fill(0x3c));
    const seedCrypto = {
      seedToMasterSeed: async () => original.masterSeed,
      recoverBundleFromSeed: async (s: Uint8Array) => recoverBundleFromSeed(wasm, s),
    } as unknown as RecoveryCryptoApi;

    vi.spyOn(api, "authChallenge").mockResolvedValue({ challenge: "00".repeat(32), expires_at: 0 });
    vi.spyOn(api, "authVerify").mockResolvedValue({ session_token: "tok", expires_at: 0 });
    vi.spyOn(api, "spkRotate").mockResolvedValue({ rotated: true });
    const replenish = vi.spyOn(api, "replenishPrekeys").mockResolvedValue({ stored: 0 });

    expect(await recoverWithSeed(original.mnemonic, seedCrypto)).toBe(original.userId);

    expect(replenish).toHaveBeenCalledOnce();
    const [opks, token, replace] = replenish.mock.calls[0];
    expect(token).toBe("tok");
    expect(replace).toBe(true); // REPLACE, not add
    expect(opks.length).toBeGreaterThan(0);
  });
});

// A phrase that passes its checksum but belongs to no account (one mistyped word
// that's another valid word) must leave nothing behind: a saved identity with
// onboarding progress would be registered as a brand-new account by onboarding.
describe("seed recovery for a phrase with no account", () => {
  it("saves no identity and no progress, and publishes nothing", async () => {
    await db.identity.clear();
    await db.settings.clear();
    const stranger = genIdentityBundle(wasm, new Uint8Array(32).fill(0x3d)); // never registered
    const seedCrypto = {
      seedToMasterSeed: async () => stranger.masterSeed,
      recoverBundleFromSeed: async (s: Uint8Array) => recoverBundleFromSeed(wasm, s),
    } as unknown as RecoveryCryptoApi;

    vi.spyOn(api, "authChallenge").mockResolvedValue({ challenge: "00".repeat(32), expires_at: 0 });
    vi.spyOn(api, "authVerify").mockRejectedValue(new api.ApiError(401)); // unknown account
    const rotate = vi.spyOn(api, "spkRotate");
    const replenish = vi.spyOn(api, "replenishPrekeys");

    await expect(recoverWithSeed(stranger.mnemonic, seedCrypto)).rejects.toMatchObject({ status: 401 });
    expect(await db.identity.count()).toBe(0);
    expect((await loadProgress()).step).toBe("welcome");
    expect(rotate).not.toHaveBeenCalled();
    expect(replenish).not.toHaveBeenCalled();
  });
});
