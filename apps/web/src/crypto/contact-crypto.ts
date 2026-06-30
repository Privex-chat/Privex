// Pure contact crypto: KT-proof verification, PQXDH initiation, safety codes.
// Each wasm-using helper takes the module so it runs inside the crypto worker
// (production) and directly against an initialised wasm in Node tests - no
// SharedWorker needed to exercise the security-critical verification path. All
// results are plain, structured-cloneable data so they can cross postMessage.
import type { KeyBundleResp } from "../api/client";
import { fromHex, type WasmModule } from "./onboarding-crypto";

/** `px_` + 32 lowercase hex chars. Mirrors server routes::valid_user_id. */
export function isValidPxId(s: string): boolean {
  return /^px_[0-9a-f]{32}$/.test(s);
}

/** A peer key bundle that PASSED full verification - decoded to raw bytes. */
export interface VerifiedBundle {
  userId: string;
  ik_ed25519: Uint8Array;
  ik_dilithium3: Uint8Array;
  ik_x25519: Uint8Array;
  spk_x25519: Uint8Array;
  kyber1024_pub: Uint8Array;
  opk: Uint8Array | null; // null when the server's OPK supply was drained
  opk_id: number | null;
}

/**
 * Verify a fetched key bundle end-to-end (docs 8.2). Throws on ANY failure - the
 * caller must NOT add the contact. The checks, in order:
 *   1. Root signature: the KT root is signed by the PINNED KT key (kt_verify_root_sig).
 *      Without this, inclusion only proves membership in a root the server made up.
 *   2. Inclusion: the leaf RECOMPUTED from the returned key fields is in that root.
 *      We deliberately ignore the server-supplied `kt_proof.leaf` and recompute it
 *      from the actual bundle - otherwise a server could prove a real leaf while
 *      handing us attacker-controlled keys.
 *   3. SPK signature: the signed prekey is hybrid-signed by the bundle's identity
 *      keys (verify_hybrid over spk_x25519).
 */
export function verifyBundle(
  w: WasmModule,
  pinnedKtPubHex: string,
  resp: KeyBundleResp,
): VerifiedBundle {
  const root = fromHex(resp.kt_proof.root);
  const rootSig = fromHex(resp.kt_proof.root_sig_ed);
  const pinned = fromHex(pinnedKtPubHex);
  if (!w.kt_verify_root_sig(root, rootSig, pinned)) {
    throw new Error("Key verification failed - KT root is not signed by the pinned key.");
  }

  const ik_ed25519 = fromHex(resp.ik_ed25519);
  const ik_dilithium3 = fromHex(resp.ik_dilithium3);
  const ik_x25519 = fromHex(resp.ik_x25519);
  const spk_x25519 = fromHex(resp.spk_x25519);
  const spk_sig_ed = fromHex(resp.spk_sig_ed);
  const spk_sig_dil = fromHex(resp.spk_sig_dil);
  const kyber1024_pub = fromHex(resp.kyber1024_pub);

  // Recompute the leaf from what we actually received and prove THAT is included.
  const bundleHash = w.kt_bundle_hash(
    ik_ed25519,
    ik_dilithium3,
    ik_x25519,
    spk_x25519,
    spk_sig_ed,
    spk_sig_dil,
    kyber1024_pub,
  );
  const leaf = w.kt_leaf_hash(resp.user_id, bundleHash, BigInt(resp.kt_proof.timestamp));
  const proofFlat = flattenPath(resp.kt_proof.path);
  if (!w.kt_verify_inclusion(leaf, proofFlat, root)) {
    throw new Error("Key verification failed - possible MITM attack. Contact not added.");
  }

  // The signed prekey must be signed by the identity keys in the same bundle.
  if (!w.verify_hybrid(spk_x25519, spk_sig_ed, ik_ed25519, spk_sig_dil, ik_dilithium3)) {
    throw new Error("Key verification failed - signed prekey signature invalid.");
  }

  return {
    userId: resp.user_id,
    ik_ed25519,
    ik_dilithium3,
    ik_x25519,
    spk_x25519,
    kyber1024_pub,
    opk: resp.opk ? fromHex(resp.opk) : null,
    opk_id: resp.opk_id,
  };
}

/** Pack the proof path into the 33-byte-per-node layout kt_verify_inclusion
 *  wants: byte 0 = side (1 = sibling on the left), bytes 1..33 = sibling hash. */
export function flattenPath(path: { left: boolean; hash: string }[]): Uint8Array {
  const out = new Uint8Array(path.length * 33);
  path.forEach((node, i) => {
    out[i * 33] = node.left ? 1 : 0;
    out.set(fromHex(node.hash), i * 33 + 1);
  });
  return out;
}

// --- PQXDH session initiation (docs 4.3) ---

/** The decoded peer prekey fields PQXDH needs (a structured-cloneable shape so
 *  it can cross postMessage into the worker). */
export interface PqxdhBundleInput {
  ik_x25519: Uint8Array;
  spk_x25519: Uint8Array;
  opk: Uint8Array | null;
  kyber1024_pub: Uint8Array;
}

export interface PqxdhInit {
  shared_secret: Uint8Array;
  alice_ik_pub: Uint8Array;
  alice_ek_pub: Uint8Array;
  kyber_ciphertext: Uint8Array;
  opk_used: boolean;
}

/** Alice initiates PQXDH against a VERIFIED peer bundle. An absent OPK (drained
 *  supply) yields the 3-DH path; pqxdh_initiate handles that branch. */
export function pqxdhInitiate(
  w: WasmModule,
  myIkX25519Priv: Uint8Array,
  b: PqxdhBundleInput,
): PqxdhInit {
  const bundle = new w.PreKeyBundle(
    b.ik_x25519,
    b.spk_x25519,
    b.opk ?? new Uint8Array(0),
    b.kyber1024_pub,
  );
  const r = w.pqxdh_initiate(myIkX25519Priv, bundle);
  return {
    shared_secret: r.shared_secret,
    alice_ik_pub: r.alice_ik_pub,
    alice_ek_pub: r.alice_ek_pub,
    kyber_ciphertext: r.kyber_ciphertext,
    opk_used: r.opk_used,
  };
}

// --- Safety codes (docs 4.1 / Signal-style Safety Numbers) ---

/**
 * safety_code = SHA-256(min(a,b) || max(a,b)) over the two Ed25519 identity public
 * keys, rendered as 8 groups of 5 decimal digits. Sorting the inputs makes both
 * parties compute the SAME code regardless of who is "alice".
 *
 * Each group is 5 hash bytes read big-endian as a uint40 mod 100000. 8 groups need
 * 40 bytes, but SHA-256 yields only 32 - so the material is deterministically
 * extended with SHA-256(digest). Both sides MUST use this exact rule or codes
 * won't match (and a future native client must replicate it).
 */
export async function safetyCode(myIkEd: Uint8Array, theirIkEd: Uint8Array): Promise<string> {
  const [lo, hi] = compareBytes(myIkEd, theirIkEd) <= 0 ? [myIkEd, theirIkEd] : [theirIkEd, myIkEd];
  const concat = new Uint8Array(lo.length + hi.length);
  concat.set(lo, 0);
  concat.set(hi, lo.length);

  const d0 = new Uint8Array(await crypto.subtle.digest("SHA-256", concat as BufferSource));
  const d1 = new Uint8Array(await crypto.subtle.digest("SHA-256", d0 as BufferSource));
  const material = new Uint8Array(40); // 8 groups × 5 bytes
  material.set(d0, 0);
  material.set(d1.subarray(0, 8), 32);

  const groups: string[] = [];
  for (let g = 0; g < 8; g++) {
    const o = g * 5;
    // uint40 (≤ 2^40, safely below 2^53) - multiply, don't shift (<< is 32-bit).
    const n =
      material[o] * 2 ** 32 +
      material[o + 1] * 2 ** 24 +
      material[o + 2] * 2 ** 16 +
      material[o + 3] * 2 ** 8 +
      material[o + 4];
    groups.push((n % 100000).toString().padStart(5, "0"));
  }
  return groups.join(" ");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
