// Loads the @privex/crypto-wasm module once. In the browser the .wasm is fetched
// relative to the module (call initCrypto() with no args). In Node tests, pass
// the wasm bytes via { module_or_path }.
import initWasm, * as wasm from "@privex/crypto-wasm";

let ready: Promise<void> | null = null;

export function initCrypto(input?: Parameters<typeof initWasm>[0]): Promise<void> {
  if (!ready) {
    ready = initWasm(input).then(() => undefined);
  }
  return ready;
}

export { wasm };
