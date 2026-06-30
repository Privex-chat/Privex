import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import {
  bincodeLoginServerResponse,
  buildKeyMaterial,
  genIdentityBundle,
  masterSeedFromKeyMaterial,
  recoverBundleFromSeed,
  toHex,
} from "../crypto/onboarding-crypto";

beforeAll(async () => {
  const wasmUrl = new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url);
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});

const entropy = (fill: number) => new Uint8Array(32).fill(fill);

describe("seed recovery", () => {
  it("re-derives the SAME identity (px_id + keys) from the master seed", () => {
    const original = genIdentityBundle(wasm, entropy(0x71));
    const recovered = recoverBundleFromSeed(wasm, original.masterSeed);

    expect(recovered.userId).toBe(original.userId); // same px_id
    expect(toHex(recovered.identity.ed25519_pub)).toBe(toHex(original.identity.ed25519_pub));
    expect(toHex(recovered.identity.x25519_pub)).toBe(toHex(original.identity.x25519_pub));
    expect(toHex(recovered.identity.kyber1024_pub)).toBe(toHex(original.identity.kyber1024_pub));
    // Prekeys are freshly generated (ephemeral) → different from the originals.
    expect(toHex(recovered.spk.pub)).not.toBe(toHex(original.spk.pub));
    expect(recovered.opks).toHaveLength(original.opks.length);
    expect(recovered.mnemonic).toBe(""); // not recoverable from the seed
  });

  it("re-derives the same identity from the 24-word mnemonic", () => {
    const b = genIdentityBundle(wasm, entropy(0x72));
    const seed = wasm.seed_phrase_to_master_seed(b.mnemonic);
    const recovered = recoverBundleFromSeed(wasm, seed);
    expect(recovered.userId).toBe(b.userId);
  });
});

describe("OPAQUE key material", () => {
  it("round-trips the master seed through the envelope payload", () => {
    const b = genIdentityBundle(wasm, entropy(0x73));
    const km = buildKeyMaterial(b.masterSeed);
    expect(toHex(masterSeedFromKeyMaterial(km))).toBe(toHex(b.masterSeed));
  });
});

describe("bincode LoginServerResponse", () => {
  it("encodes three Vec<u8> as u64-LE-length-prefixed segments", () => {
    const cr = new Uint8Array([1, 2, 3]);
    const env = new Uint8Array([4, 5]);
    const mac = new Uint8Array(32).fill(9);
    const out = bincodeLoginServerResponse(cr, env, mac);

    // Parse it back the way bincode (Rust) would: u64 LE length, then bytes, ×3.
    const dv = new DataView(out.buffer);
    let o = 0;
    const read = () => {
      const len = Number(dv.getBigUint64(o, true));
      o += 8;
      const bytes = out.subarray(o, o + len);
      o += len;
      return bytes;
    };
    expect(toHex(read())).toBe(toHex(cr));
    expect(toHex(read())).toBe(toHex(env));
    expect(toHex(read())).toBe(toHex(mac));
    expect(o).toBe(out.length); // no trailing bytes
  });
});
