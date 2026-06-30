// Pure wrappers for the wasm file-CEK functions (docs 4.7). Run inside the crypto
// worker (production) and directly against an initialised wasm in Node tests. The
// bulk chunk crypto (AES-256-GCM + HKDF + SHA-256) lives in services/files.ts via
// the Web Crypto API - only the CEK + X25519/XChaCha20 wrap is wasm here.
import type { WasmModule } from "./onboarding-crypto";

export function generateCek(w: WasmModule): Uint8Array {
  return w.generate_cek();
}

export interface WrappedCek {
  wrapped: Uint8Array;
  ephPub: Uint8Array;
}

export function wrapCek(w: WasmModule, cek: Uint8Array, recipientIkX25519Pub: Uint8Array): WrappedCek {
  const r = w.wrap_cek(cek, recipientIkX25519Pub);
  return { wrapped: r.wrapped, ephPub: r.eph_pub };
}

export function unwrapCek(
  w: WasmModule,
  wrapped: Uint8Array,
  ephPub: Uint8Array,
  myIkX25519Priv: Uint8Array,
): Uint8Array {
  return w.unwrap_cek(wrapped, ephPub, myIkX25519Priv);
}
