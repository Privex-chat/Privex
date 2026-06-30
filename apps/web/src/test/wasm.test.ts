import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";

describe("crypto-wasm", () => {
  it("loads and generates identity keypairs", async () => {
    const wasmUrl = new URL(
      "../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm",
      import.meta.url,
    );
    await initCrypto({ module_or_path: readFileSync(wasmUrl) });

    const keys = wasm.generate_identity_keypairs();
    expect(keys.ed25519_pub.length).toBe(32);
    expect(keys.x25519_pub.length).toBe(32);
  });
});
