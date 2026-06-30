// Pure wrappers for the device-link wasm primitives (history sync Option B). Run
// inside the crypto worker (production) or directly against an initialised wasm in
// Node tests. The ephemeral keypair + X25519/HKDF channel-key derivation are wasm
// (browser-compat); the per-frame AEAD runs in the browser via Web Crypto.
import type { WasmModule } from "./onboarding-crypto";

export interface EphKeypair {
  pub: Uint8Array;
  priv: Uint8Array;
}

/** A fresh ephemeral X25519 keypair for one transfer (reuses the prekey keygen). */
export function devlinkKeypair(w: WasmModule): EphKeypair {
  const k = w.generate_x25519_prekey();
  return { pub: k.public_key, priv: k.private_key };
}

/** HKDF(X25519(myPriv, theirPub)) → 32-byte shared channel key. */
export function devlinkChannelKey(w: WasmModule, myPriv: Uint8Array, theirPub: Uint8Array): Uint8Array {
  return w.devlink_channel_key(myPriv, theirPub);
}
