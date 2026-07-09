import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import {
  buildKeyMaterial,
  challengeSigningInput,
  genIdentityBundle,
  OPK_COUNT,
  recoverIdentityFromKeyMaterial,
  signHybrid,
  toHex,
} from "../crypto/onboarding-crypto";
import { checkConfirm, pickConfirmIndices } from "../onboarding/seed-confirm";
import {
  clearOnboarding,
  finalizeIdentity,
  loadBundle,
  loadProgress,
  persistGeneratedIdentity,
} from "../onboarding/store";
import { db } from "../db";

beforeAll(async () => {
  const wasmUrl = new URL(
    "../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm",
    import.meta.url,
  );
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});

const entropy = (fill: number) => new Uint8Array(32).fill(fill);
const testKey = () =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

describe("identity generation", () => {
  it("is deterministic and the seed phrase recovers the same identity", () => {
    const b = genIdentityBundle(wasm, entropy(0x11));
    expect(b.userId).toMatch(/^px_[0-9a-f]{32}$/);
    expect(b.mnemonic.trim().split(/\s+/)).toHaveLength(24);
    expect(b.opks).toHaveLength(OPK_COUNT);
    expect(b.opks[0].pub).toHaveLength(32);

    // Same entropy → same identity.
    const again = genIdentityBundle(wasm, entropy(0x11));
    expect(again.userId).toBe(b.userId);
    expect(toHex(again.identity.ed25519_pub)).toBe(toHex(b.identity.ed25519_pub));

    // The mnemonic re-derives the exact identity keys (real recovery).
    const seed = wasm.seed_phrase_to_master_seed(b.mnemonic);
    const rederived = wasm.derive_keypairs_from_seed(seed);
    expect(toHex(rederived.ed25519_pub)).toBe(toHex(b.identity.ed25519_pub));
    expect(toHex(rederived.kyber1024_pub)).toBe(toHex(b.identity.kyber1024_pub));
  });

  it("hybrid-signs the SPK so the server's registration check passes", () => {
    const b = genIdentityBundle(wasm, entropy(0x22));
    expect(
      wasm.verify_hybrid(
        b.spk.pub,
        b.spkSig.ed,
        b.identity.ed25519_pub,
        b.spkSig.dil,
        b.identity.dilithium3_pub,
      ),
    ).toBe(true);
  });

  it("produces an auth-challenge signature the server would accept", () => {
    const b = genIdentityBundle(wasm, entropy(0x33));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const ts = 1_900_000_000;
    const input = challengeSigningInput(challenge, b.userId, ts);
    // Domain separation (PVX-21): the input must start with the v1 context tag,
    // byte-matching server/src/auth/sig.rs::challenge_signing_input_v1.
    const ctx = new TextEncoder().encode("privex-auth-v1");
    expect(Array.from(input.subarray(0, ctx.length))).toEqual(Array.from(ctx));
    expect(input.length).toBe(ctx.length + 32 + b.userId.length + 8);
    const sig = signHybrid(wasm, input, b.identity.ed25519_priv, b.identity.dilithium3_priv);
    expect(
      wasm.verify_hybrid(input, sig.ed, b.identity.ed25519_pub, sig.dil, b.identity.dilithium3_pub),
    ).toBe(true);
  });
});

describe("OPAQUE recovery payload", () => {
  it("round-trips the master seed back to the same identity", () => {
    const b = genIdentityBundle(wasm, entropy(0x44));
    const km = buildKeyMaterial(b.masterSeed);
    const recovered = recoverIdentityFromKeyMaterial(wasm, km);
    expect(toHex(recovered.ed25519_pub)).toBe(toHex(b.identity.ed25519_pub));
    expect(toHex(recovered.x25519_pub)).toBe(toHex(b.identity.x25519_pub));
  });
});

describe("seed-phrase confirmation", () => {
  it("accepts correct words and rejects wrong ones", () => {
    const b = genIdentityBundle(wasm, entropy(0x55));
    const words = b.mnemonic.trim().split(/\s+/);
    // Deterministic indices via a fixed RNG sequence.
    const seq = [0.05, 0.5, 0.9];
    let i = 0;
    const idx = pickConfirmIndices(24, 3, () => seq[i++]);
    expect(idx).toHaveLength(3);

    const right = idx.map((p) => words[p - 1]);
    expect(checkConfirm(b.mnemonic, idx, right)).toBe(true);
    expect(checkConfirm(b.mnemonic, idx, ["wrong", "wrong", "wrong"])).toBe(false);
    expect(checkConfirm(b.mnemonic, idx, ["", "", ""])).toBe(false);
  });
});

describe("encrypted identity persistence", () => {
  it("round-trips the private bundle and stores no plaintext key material", async () => {
    await clearOnboarding();
    const key = await testKey();
    const b = genIdentityBundle(wasm, entropy(0x66));

    await persistGeneratedIdentity(b, key);
    const loaded = await loadBundle(key);
    expect(loaded?.userId).toBe(b.userId);
    expect(toHex(loaded!.identity.ed25519_priv)).toBe(toHex(b.identity.ed25519_priv));
    expect(loaded!.mnemonic).toBe(b.mnemonic); // present pre-finalize for the seed screen

    // The raw IndexedDB row must NOT contain the private key bytes in the clear.
    const row = await db.identity.get(b.userId);
    expect(row?.priv_bundle_enc).toBeInstanceOf(Uint8Array);
    const stored = toHex(row!.priv_bundle_enc!);
    expect(stored).not.toContain(toHex(b.identity.ed25519_priv));
    expect(stored).not.toContain(toHex(b.identity.x25519_priv));
    // The mnemonic words must not be stored in the clear either.
    expect(toHex(row!.priv_bundle_enc!)).not.toContain(
      toHex(new TextEncoder().encode(b.mnemonic)),
    );

    // Finalize keeps the mnemonic (encrypted at rest, for Settings → View Seed
    // Phrase - it can't be re-derived from the seed) and marks onboarding done.
    await finalizeIdentity(b, key);
    expect((await loadBundle(key))!.mnemonic).toBe(b.mnemonic);
    expect((await loadProgress()).step).toBe("done");
  });
});
