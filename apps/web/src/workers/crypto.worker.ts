/// <reference lib="webworker" />
// Crypto SharedWorker (docs 9.3). Loads @privex/crypto-wasm once and runs all
// heavy crypto off the main thread. Tabs connect via a MessagePort and call by
// method name.
//
// High-level handlers convert wasm-bindgen structs (NOT structured-cloneable)
// into plain data before posting. Methods not listed fall through to a generic
// passthrough, which is only safe for wasm fns that return cloneable primitives
// (strings, booleans, Uint8Arrays) - never struct returns.
import { initCrypto, wasm } from "../crypto/wasm";
import * as oc from "../crypto/onboarding-crypto";
import * as cc from "../crypto/contact-crypto";
import * as mc from "../crypto/message-crypto";
import * as fc from "../crypto/file-crypto";
import * as dl from "../crypto/devlink-crypto";
import type { KeyBundleResp } from "../api/client";

const ready = initCrypto();

type Emit = (progress: number) => void;

const handlers: Record<string, (args: unknown[], emit: Emit) => unknown> = {
  gen_identity: (a) => oc.genIdentityBundle(wasm, a[0] as Uint8Array),
  recover_bundle: (a) => oc.recoverBundleFromSeed(wasm, a[0] as Uint8Array),
  opaque_login_start: (a) => oc.opaqueLoginStart(wasm, a[0] as string),
  opaque_login_finish: (a) =>
    oc.opaqueLoginFinish(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as string),
  opaque_reg_start: (a) => oc.opaqueRegStart(wasm, a[0] as string),
  opaque_reg_finish: (a) =>
    oc.opaqueRegFinish(
      wasm,
      a[0] as Uint8Array,
      a[1] as Uint8Array,
      a[2] as Uint8Array,
      a[3] as string,
    ),
  sign_challenge: (a) =>
    oc.signHybrid(
      wasm,
      oc.challengeSigningInput(a[0] as Uint8Array, a[1] as string, a[2] as number),
      a[3] as Uint8Array,
      a[4] as Uint8Array,
    ),
  // Fresh signed prekey for rotation (16E "log out everywhere"). Struct → plain.
  generate_signed_spk: (a) => oc.generateSignedSpk(wasm, a[0] as Uint8Array, a[1] as Uint8Array),
  // Synchronous solve blocks this worker (~500ms at difficulty 22, plus the
  // Argon2id evals on hybrid challenges); progress posts live to the tab.
  solve_pow: (a, emit) =>
    oc.solvePow(
      wasm,
      a[0] as Uint8Array,
      a[1] as number,
      emit,
      a[2] as oc.PowArgonParams | undefined,
    ),
  // Contact / messaging crypto. These wasm fns return structs (PqxdhInitResult)
  // that aren't structured-cloneable, so the pure helpers convert to plain data.
  // verify_bundle throws on any KT/SPK failure → surfaced as a rejected call.
  verify_bundle: (a) => cc.verifyBundle(wasm, a[0] as string, a[1] as KeyBundleResp),
  pqxdh_initiate: (a) =>
    cc.pqxdhInitiate(wasm, a[0] as Uint8Array, a[1] as cc.PqxdhBundleInput),
  // Double Ratchet + Sealed Sender (S16). Struct returns/args → plain data; u64
  // clock args are passed as plain numbers and converted to BigInt in the wrapper.
  ratchet_encrypt: (a) => mc.ratchetEncrypt(wasm, a[0] as Uint8Array, a[1] as Uint8Array),
  ratchet_decrypt: (a) =>
    mc.ratchetDecrypt(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as Uint8Array),
  ratchet_init_bob: (a) =>
    mc.ratchetInitBob(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as Uint8Array),
  generate_sender_cert: (a) =>
    mc.generateSenderCert(
      wasm,
      a[0] as string,
      a[1] as Uint8Array,
      a[2] as Uint8Array,
      a[3] as Uint8Array,
      a[4] as Uint8Array,
      a[5] as number,
      a[6] as number,
    ),
  sealed_sender_encrypt: (a) =>
    mc.sealedSenderEncrypt(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as Uint8Array),
  sealed_sender_decrypt: (a) =>
    mc.sealedSenderDecrypt(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as number),
  pqxdh_respond: (a) =>
    mc.pqxdhRespond(
      wasm,
      a[0] as mc.PqxdhInitFields,
      a[1] as Uint8Array,
      a[2] as Uint8Array,
      a[3] as Uint8Array,
      a[4] as Uint8Array,
    ),
  // File CEK (docs 4.7). wrap_cek returns a struct → plain-data wrapper.
  generate_cek: () => fc.generateCek(wasm),
  wrap_cek: (a) => fc.wrapCek(wasm, a[0] as Uint8Array, a[1] as Uint8Array),
  unwrap_cek: (a) => fc.unwrapCek(wasm, a[0] as Uint8Array, a[1] as Uint8Array, a[2] as Uint8Array),
  // Device-link transfer (Option B). keypair returns a struct → plain-data wrapper.
  devlink_keypair: () => dl.devlinkKeypair(wasm),
  devlink_channel_key: (a) => dl.devlinkChannelKey(wasm, a[0] as Uint8Array, a[1] as Uint8Array),
};

async function handle(method: string, args: unknown[], emit: Emit): Promise<unknown> {
  await ready;
  const h = handlers[method];
  if (h) return h(args, emit);
  const fn = (wasm as Record<string, unknown>)[method];
  if (typeof fn !== "function") throw new Error(`unknown crypto method: ${method}`);
  return (fn as (...a: unknown[]) => unknown)(...args);
}

const scope = self as unknown as SharedWorkerGlobalScope;
scope.onconnect = (event: MessageEvent) => {
  const port = event.ports[0];
  port.onmessage = async (ev: MessageEvent) => {
    const { id, method, args } = ev.data as { id: number; method: string; args?: unknown[] };
    const emit: Emit = (progress) => port.postMessage({ id, progress });
    try {
      const result = await handle(method, args ?? [], emit);
      port.postMessage({ id, ok: true, result });
    } catch (err) {
      port.postMessage({ id, ok: false, error: String(err) });
    }
  };
  port.start();
};
