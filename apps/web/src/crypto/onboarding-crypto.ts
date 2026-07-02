// Pure crypto helpers for registration + recovery. Each takes the wasm module so
// it is callable both inside the crypto worker (production) and directly against
// an initialised wasm in Node tests - no SharedWorker required to exercise the
// security-critical paths. All wasm structs are converted to plain, structured-
// cloneable data here so results can cross postMessage.
import type * as Wasm from "@privex/crypto-wasm";

export type WasmModule = typeof Wasm;

// Initial one-time-prekey batch. docs 8: the server asks clients to replenish in
// batches of ~50; we seed the account with one batch at registration.
export const OPK_COUNT = 50;

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface IdentityKeys {
  ed25519_pub: Uint8Array;
  ed25519_priv: Uint8Array;
  dilithium3_pub: Uint8Array;
  dilithium3_priv: Uint8Array;
  kyber1024_pub: Uint8Array;
  kyber1024_priv: Uint8Array;
  x25519_pub: Uint8Array;
  x25519_priv: Uint8Array;
}

export interface PreKey {
  id: number;
  pub: Uint8Array;
  priv: Uint8Array;
}

/** Everything generated locally for a new identity. Private fields never leave
 *  the device unencrypted; the browser encrypts them at rest (keystore.ts). */
export interface IdentityBundle {
  userId: string;
  mnemonic: string;
  masterSeed: Uint8Array;
  identity: IdentityKeys;
  spk: { pub: Uint8Array; priv: Uint8Array };
  spkSig: { ed: Uint8Array; dil: Uint8Array };
  opks: PreKey[];
}

function plainIdentity(k: Wasm.IdentityKeypairs): IdentityKeys {
  return {
    ed25519_pub: k.ed25519_pub,
    ed25519_priv: k.ed25519_priv,
    dilithium3_pub: k.dilithium3_pub,
    dilithium3_priv: k.dilithium3_priv,
    kyber1024_pub: k.kyber1024_pub,
    kyber1024_priv: k.kyber1024_priv,
    x25519_pub: k.x25519_pub,
    x25519_priv: k.x25519_priv,
  };
}

/** docs 4.2 / 6: 256-bit entropy → 24-word mnemonic → master seed → the full
 *  identity (deterministic, so the seed phrase truly recovers it), plus a fresh
 *  signed prekey (hybrid-signed) and a batch of one-time prekeys. */
export function genIdentityBundle(w: WasmModule, entropy: Uint8Array): IdentityBundle {
  const mnemonic = w.generate_seed_phrase(entropy);
  const masterSeed = w.seed_phrase_to_master_seed(mnemonic);
  const id = plainIdentity(w.derive_keypairs_from_seed(masterSeed));
  const userId = w.user_id_from_ed25519(id.ed25519_pub);

  const spk = w.generate_x25519_prekey();
  const sig = w.sign_hybrid(spk.public_key, id.ed25519_priv, id.dilithium3_priv);

  const opks: PreKey[] = [];
  for (let i = 0; i < OPK_COUNT; i++) {
    const kp = w.generate_x25519_prekey();
    opks.push({ id: i + 1, pub: kp.public_key, priv: kp.private_key });
  }

  return {
    userId,
    mnemonic,
    masterSeed,
    identity: id,
    spk: { pub: spk.public_key, priv: spk.private_key },
    spkSig: { ed: sig.sig_ed25519, dil: sig.sig_dilithium3 },
    opks,
  };
}

/** Rebuild a full identity bundle from a recovered master seed (docs 4.2). The
 *  seed re-derives the SAME identity keys (→ same px_id); the signed prekey + OPKs
 *  are freshly generated (prekeys are ephemeral) and must be re-uploaded so the
 *  recovered device can receive messages. The mnemonic is not recoverable from the
 *  seed, so it's left empty. */
export function recoverBundleFromSeed(w: WasmModule, masterSeed: Uint8Array): IdentityBundle {
  const id = plainIdentity(w.derive_keypairs_from_seed(masterSeed));
  const userId = w.user_id_from_ed25519(id.ed25519_pub);

  const spk = w.generate_x25519_prekey();
  const sig = w.sign_hybrid(spk.public_key, id.ed25519_priv, id.dilithium3_priv);

  const opks: PreKey[] = [];
  for (let i = 0; i < OPK_COUNT; i++) {
    const kp = w.generate_x25519_prekey();
    opks.push({ id: i + 1, pub: kp.public_key, priv: kp.private_key });
  }

  return {
    userId,
    mnemonic: "",
    masterSeed,
    identity: id,
    spk: { pub: spk.public_key, priv: spk.private_key },
    spkSig: { ed: sig.sig_ed25519, dil: sig.sig_dilithium3 },
    opks,
  };
}

/** The master seed wrapped inside the OPAQUE envelope (inverse of buildKeyMaterial). */
export function masterSeedFromKeyMaterial(keyMaterial: Uint8Array): Uint8Array {
  const parsed = JSON.parse(new TextDecoder().decode(keyMaterial)) as { v: number; master_seed: string };
  return fromHex(parsed.master_seed);
}

// --- OPAQUE recovery setup ---

/** The secret payload the OPAQUE envelope wraps. The master seed alone re-derives
 *  every identity key (docs 4.2), so wrapping it is sufficient for full recovery.
 *  Versioned for forward compatibility. */
export function buildKeyMaterial(masterSeed: Uint8Array): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ v: 1, master_seed: toHex(masterSeed) }));
}

/** Inverse of buildKeyMaterial → the recovered identity (used by the recovery
 *  flow and by tests proving registration stores recoverable material). */
export function recoverIdentityFromKeyMaterial(w: WasmModule, keyMaterial: Uint8Array): IdentityKeys {
  const parsed = JSON.parse(new TextDecoder().decode(keyMaterial)) as { v: number; master_seed: string };
  return plainIdentity(w.derive_keypairs_from_seed(fromHex(parsed.master_seed)));
}

export interface OpaqueStart {
  message: Uint8Array;
  clientState: Uint8Array;
}

export function opaqueRegStart(w: WasmModule, password: string): OpaqueStart {
  const r = w.opaque_register_start(password);
  return { message: r.message, clientState: r.client_state };
}

export interface OpaqueFinish {
  uploadMessage: Uint8Array;
  envelope: Uint8Array;
  envelopeMac: Uint8Array;
}

export function opaqueRegFinish(
  w: WasmModule,
  clientState: Uint8Array,
  serverResponse: Uint8Array,
  keyMaterial: Uint8Array,
  password: string,
): OpaqueFinish {
  const r = w.opaque_register_finish(clientState, serverResponse, keyMaterial, password);
  return { uploadMessage: r.upload_message, envelope: r.envelope, envelopeMac: r.envelope_mac };
}

// --- OPAQUE recovery login ---

export function opaqueLoginStart(w: WasmModule, password: string): OpaqueStart {
  const r = w.opaque_login_start(password, "");
  return { message: r.message, clientState: r.client_state };
}

export interface OpaqueLoginResult {
  keyMaterial: Uint8Array; // the recovered envelope payload (→ master seed)
  finalization: Uint8Array; // OPAQUE KE3 → POST /recovery/opaque/complete
}

/** `serverResponse` is the bincode LoginServerResponse (see bincodeLoginServerResponse).
 *  A wrong password makes OPAQUE finish throw. */
export function opaqueLoginFinish(
  w: WasmModule,
  clientState: Uint8Array,
  serverResponse: Uint8Array,
  password: string,
): OpaqueLoginResult {
  const r = w.opaque_login_finish(clientState, serverResponse, password);
  return { keyMaterial: r.key_material, finalization: r.finalization };
}

/** The server returns the OPAQUE login response as three hex fields, but
 *  opaque_login_finish expects a bincode `LoginServerResponse { credential_response,
 *  envelope, envelope_mac }` - each Vec<u8> = u64 LE length + bytes. */
export function bincodeLoginServerResponse(
  credentialResponse: Uint8Array,
  envelope: Uint8Array,
  envelopeMac: Uint8Array,
): Uint8Array {
  const parts = [credentialResponse, envelope, envelopeMac];
  const total = parts.reduce((n, p) => n + 8 + p.length, 0);
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let o = 0;
  for (const p of parts) {
    dv.setBigUint64(o, BigInt(p.length), true); // bincode: little-endian u64 length
    o += 8;
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// --- PoW ---

export interface PowResult {
  nonce: number;
  solutionHash: Uint8Array;
}

/** Solve a PoW challenge. `onProgress` receives the attempt count. nonce is
 *  returned as a JS number: difficulty-22 nonces are far below 2^53, so JSON is
 *  safe. ponytail: holds while difficulty stays sane (<~45 bits). */
export function solvePow(
  w: WasmModule,
  challenge: Uint8Array,
  difficulty: number,
  onProgress?: (attempts: number) => void,
): PowResult {
  const cb = onProgress ? (n: number) => onProgress(n) : undefined;
  const sol = w.pow_solve(challenge, difficulty, cb, undefined);
  return { nonce: Number(sol.nonce), solutionHash: sol.solution_hash };
}

// --- auth challenge signing (docs 4.9) ---

/** Canonical signing input: challenge || user_id(utf8) || timestamp(BE u64).
 *  Must byte-match server/src/auth/sig.rs::challenge_signing_input. */
export function challengeSigningInput(challenge: Uint8Array, userId: string, timestamp: number): Uint8Array {
  const idBytes = new TextEncoder().encode(userId);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(timestamp), false); // big-endian
  const out = new Uint8Array(challenge.length + idBytes.length + 8);
  out.set(challenge, 0);
  out.set(idBytes, challenge.length);
  out.set(ts, challenge.length + idBytes.length);
  return out;
}

export interface HybridSig {
  ed: Uint8Array;
  dil: Uint8Array;
}

export function signHybrid(w: WasmModule, data: Uint8Array, edPriv: Uint8Array, dilPriv: Uint8Array): HybridSig {
  const s = w.sign_hybrid(data, edPriv, dilPriv);
  return { ed: s.sig_ed25519, dil: s.sig_dilithium3 };
}

// --- signed prekey rotation (docs 4.9 / 16E) ---

export interface SignedSpk {
  pub: Uint8Array;
  priv: Uint8Array;
  sigEd: Uint8Array;
  sigDil: Uint8Array;
}

/** Generate a fresh X25519 signed prekey and hybrid-sign its public key with the
 *  identity keys (same construction genIdentityBundle uses). Returned as plain,
 *  structured-cloneable data so it can cross the crypto worker. */
export function generateSignedSpk(w: WasmModule, edPriv: Uint8Array, dilPriv: Uint8Array): SignedSpk {
  const spk = w.generate_x25519_prekey();
  const sig = w.sign_hybrid(spk.public_key, edPriv, dilPriv);
  return { pub: spk.public_key, priv: spk.private_key, sigEd: sig.sig_ed25519, sigDil: sig.sig_dilithium3 };
}
