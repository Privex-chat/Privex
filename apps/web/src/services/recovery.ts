// Account recovery (docs 4.2 / 6.1). Two working paths:
//   A - OPAQUE password: lost device, only the password. The OPAQUE login both
//       authenticates AND returns the encrypted envelope wrapping the master seed.
//   C - seed phrase: 24 words → master seed → same identity, then a signed-challenge
//       auth.
// Both re-derive the SAME identity keys (same px_id) from the master seed, then
// re-provision fresh prekeys (SPK + OPKs are ephemeral) so the recovered device can
// receive messages again. Message history is NOT restored - it lives only on devices.
import * as api from "../api/client";
import { cryptoCall } from "../workers/crypto-client";
import { useAuth } from "../store/auth";
import { db } from "../db";
import { isValidPxId } from "../crypto/contact-crypto";
import { workerFileCrypto, type FileCryptoApi } from "./files";
import { solveServerPow } from "./pow";
import type { PlainContact } from "../db/encrypted-db";
import { authenticateBundle } from "./auth-session";
import { finalizeIdentity, loadBundle, persistGeneratedIdentity } from "../onboarding/store";
import {
  bincodeLoginServerResponse,
  buildKeyMaterial,
  fromHex,
  masterSeedFromKeyMaterial,
  toHex,
  type IdentityBundle,
  type OpaqueFinish,
  type OpaqueLoginResult,
  type OpaqueStart,
} from "../crypto/onboarding-crypto";

export interface RecoveryCryptoApi {
  opaqueRegStart(password: string): Promise<OpaqueStart>;
  opaqueRegFinish(
    clientState: Uint8Array,
    serverResponse: Uint8Array,
    keyMaterial: Uint8Array,
    password: string,
  ): Promise<OpaqueFinish>;
  opaqueLoginStart(password: string): Promise<OpaqueStart>;
  opaqueLoginFinish(
    clientState: Uint8Array,
    serverResponse: Uint8Array,
    password: string,
  ): Promise<OpaqueLoginResult>;
  recoverBundleFromSeed(masterSeed: Uint8Array): Promise<IdentityBundle>;
  seedToMasterSeed(mnemonic: string): Promise<Uint8Array>;
  solvePow: import("./pow").SolvePow;
}

export const workerRecoveryCrypto: RecoveryCryptoApi = {
  opaqueRegStart: (pw) => cryptoCall("opaque_reg_start", [pw]),
  opaqueRegFinish: (cs, sr, km, pw) => cryptoCall("opaque_reg_finish", [cs, sr, km, pw]),
  opaqueLoginStart: (pw) => cryptoCall("opaque_login_start", [pw]),
  opaqueLoginFinish: (cs, sr, pw) => cryptoCall("opaque_login_finish", [cs, sr, pw]),
  recoverBundleFromSeed: (seed) => cryptoCall("recover_bundle", [seed]),
  seedToMasterSeed: (m) => cryptoCall("seed_phrase_to_master_seed", [m]),
  solvePow: (c, d, a) => cryptoCall("solve_pow", [c, d, a]),
};

/** Upload the recovered device's fresh signed prekey + one-time prekeys so peers
 *  can establish sessions with it again (the old ones are gone with the lost device). */
async function provisionPrekeys(bundle: IdentityBundle, token: string): Promise<void> {
  await api.spkRotate(
    {
      spk_x25519_pub: toHex(bundle.spk.pub),
      spk_sig_ed: toHex(bundle.spkSig.ed),
      spk_sig_dil: toHex(bundle.spkSig.dil),
    },
    token,
  );
  await api.replenishPrekeys(
    bundle.opks.map((o) => ({ opk_id: o.id, opk_x25519_pub: toHex(o.pub) })),
    token,
  );
}

/** Shared tail: persist the recovered identity, obtain a token (OPAQUE provides
 *  one; seed recovery signs a challenge), re-provision prekeys, enter the app. */
async function completeRecovery(bundle: IdentityBundle, tokenOpt?: string): Promise<void> {
  await persistGeneratedIdentity(bundle);
  const token = tokenOpt ?? (await authenticateBundle(bundle));
  useAuth.getState().setSession(token, bundle.userId);
  await provisionPrekeys(bundle, token);
  await finalizeIdentity(bundle);
  useAuth.getState().setAuthenticated(bundle.userId);
}

/** Option A - OPAQUE password recovery. Throws on a bad px_id or wrong password. */
export async function recoverWithPassword(
  pxId: string,
  password: string,
  crypto: RecoveryCryptoApi = workerRecoveryCrypto,
): Promise<string> {
  if (!isValidPxId(pxId)) throw new Error("That doesn't look like a Privex ID.");

  const start = await crypto.opaqueLoginStart(password);
  // PoW-gate the unauthenticated OPAQUE init (same gate as the key directory).
  const pow = await solveServerPow(crypto.solvePow);
  const init = await api.opaqueLoginInit(pxId, toHex(start.message), pow);
  const lsr = bincodeLoginServerResponse(
    fromHex(init.credential_response),
    fromHex(init.envelope),
    fromHex(init.envelope_mac),
  );
  let fin: OpaqueLoginResult;
  try {
    fin = await crypto.opaqueLoginFinish(start.clientState, lsr, password);
  } catch {
    throw new Error("Wrong password, or no account with that ID.");
  }
  const complete = await api.opaqueLoginComplete(init.login_id, toHex(fin.finalization));
  const bundle = await crypto.recoverBundleFromSeed(masterSeedFromKeyMaterial(fin.keyMaterial));
  await completeRecovery(bundle, complete.session_token);
  return bundle.userId;
}

async function requireRecoverySession(): Promise<{ bundle: IdentityBundle; token: string }> {
  const bundle = await loadBundle();
  if (!bundle) throw new Error("Your identity isn't loaded on this device.");

  let token = useAuth.getState().sessionToken;
  if (!token) {
    token = await authenticateBundle(bundle);
    useAuth.getState().setSession(token, bundle.userId);
  }
  return { bundle, token };
}

export async function opaqueRecoveryStatus(): Promise<boolean> {
  const token = useAuth.getState().sessionToken;
  if (!token) throw new Error("not authenticated");
  return (await api.opaqueStatus(token)).enabled;
}

export async function enableOpaqueRecovery(
  password: string,
  crypto: RecoveryCryptoApi = workerRecoveryCrypto,
): Promise<void> {
  const { bundle, token } = await requireRecoverySession();
  const start = await crypto.opaqueRegStart(password);
  const res1 = await api.opaqueRegisterStart(toHex(start.message), token);
  const fin = await crypto.opaqueRegFinish(
    start.clientState,
    fromHex(res1.registration_response),
    buildKeyMaterial(bundle.masterSeed),
    password,
  );
  await api.opaqueRegisterFinish(
    {
      registration_upload: toHex(fin.uploadMessage),
      envelope: toHex(fin.envelope),
      envelope_mac: toHex(fin.envelopeMac),
    },
    token,
  );
}

export async function disableOpaqueRecovery(): Promise<void> {
  const { token } = await requireRecoverySession();
  await api.opaqueDisable(token);
}

/** Option C - seed-phrase recovery. Throws on an invalid mnemonic. */
export async function recoverWithSeed(
  mnemonic: string,
  crypto: RecoveryCryptoApi = workerRecoveryCrypto,
): Promise<string> {
  const masterSeed = await crypto.seedToMasterSeed(mnemonic.trim().replace(/\s+/g, " "));
  const bundle = await crypto.recoverBundleFromSeed(masterSeed);
  await completeRecovery(bundle);
  return bundle.userId;
}

// --- Emergency contacts (Shamir social recovery - SETUP only) ---
// Splits the master seed into N shares (threshold 2), seals each to a contact's
// X25519 identity key, and stores the opaque blobs server-side. RETRIEVAL
// ("recover via contacts") needs a relationship-free share rendezvous and stays
// deferred (the server has no social graph by design).
export const RECOVERY_CONTACTS_KEY = "recovery_contacts";

export async function setupEmergencyContacts(
  contacts: PlainContact[],
  fileCrypto: FileCryptoApi = workerFileCrypto,
): Promise<number> {
  if (contacts.length < 2 || contacts.length > 3) {
    throw new Error("Choose 2 or 3 recovery contacts.");
  }
  if (contacts.some((c) => c.ik_x25519.length === 0)) {
    throw new Error("A selected contact is missing a key - message them first.");
  }
  const bundle = await loadBundle();
  if (!bundle) throw new Error("Your identity isn't loaded.");
  // You can't be your own recovery contact: sealing a share to yourself defeats
  // the whole point (a lost device loses that share too) and weakens the threshold.
  if (contacts.some((c) => c.px_id === bundle.userId)) {
    throw new Error("You can't choose yourself as a recovery contact.");
  }
  const token = useAuth.getState().sessionToken;
  if (!token) throw new Error("not authenticated");

  // threshold 2 → any 2 of the chosen contacts can reconstruct the seed.
  const shares = await cryptoCall<Uint8Array[]>("shamir_split", [bundle.masterSeed, 2, contacts.length]);

  const wire: { share_index: number; encrypted_share: string }[] = [];
  for (let i = 0; i < contacts.length; i++) {
    const w = await fileCrypto.wrapCek(shares[i], contacts[i].ik_x25519);
    const blob = new Uint8Array(w.ephPub.length + w.wrapped.length); // ephPub || wrapped
    blob.set(w.ephPub, 0);
    blob.set(w.wrapped, w.ephPub.length);
    wire.push({ share_index: i + 1, encrypted_share: toHex(blob) });
  }

  const res = await api.storeShares(wire, token);
  await db.settings.put({ key: RECOVERY_CONTACTS_KEY, value: contacts.map((c) => c.px_id) });
  return res.stored;
}

// --- Emergency contacts (Shamir social recovery - RETRIEVAL) ---
// The relationship-free rendezvous (docs 4.2 path 3). The recovering owner has NO
// keys yet: they generate an EPHEMERAL recovery keypair (RK), pass a recovery code
// (recovery_id + RK public) to their chosen contacts OUT OF BAND, and poll a random
// server bucket. Each contact fetches the owner's encrypted shares (PoW-gated,
// unauthenticated - the server can't attribute the fetch to them), decrypts the one
// sealed to their own key, re-seals it to RK, and posts it. The owner collects >=2
// and reconstructs the master seed. The server never learns any C->O relationship.

const RK_PUB_LEN = 32;
const RECOVERY_ID_LEN = 16;

export interface ContactRecoveryCryptoApi {
  ephKeypair(): Promise<{ pub: Uint8Array; priv: Uint8Array }>;
  wrapCek(cek: Uint8Array, recipientPub: Uint8Array): Promise<{ wrapped: Uint8Array; ephPub: Uint8Array }>;
  unwrapCek(wrapped: Uint8Array, ephPub: Uint8Array, myPriv: Uint8Array): Promise<Uint8Array>;
  shamirReconstruct(shares: Uint8Array[]): Promise<Uint8Array>;
  recoverBundleFromSeed(masterSeed: Uint8Array): Promise<IdentityBundle>;
  solvePow: import("./pow").SolvePow;
}

export const workerContactRecoveryCrypto: ContactRecoveryCryptoApi = {
  ephKeypair: () => cryptoCall("devlink_keypair"), // returns plain { pub, priv }
  wrapCek: (c, r) => cryptoCall("wrap_cek", [c, r]),
  unwrapCek: (w, e, p) => cryptoCall("unwrap_cek", [w, e, p]),
  shamirReconstruct: (shares) => cryptoCall("shamir_reconstruct", [shares]),
  recoverBundleFromSeed: (seed) => cryptoCall("recover_bundle", [seed]),
  solvePow: (c, d, a) => cryptoCall("solve_pow", [c, d, a]),
};

export interface RecoverySession {
  recoveryId: string; // hex (16 bytes) - the ephemeral bucket key
  rk: { pub: Uint8Array; priv: Uint8Array }; // owner's ephemeral recovery keypair
  code: string; // hex(recovery_id || rk_pub) - hand this to contacts out of band
  sas: string; // 6-digit verbal check binding the code (defeats a swapped RK)
}

async function sas6(buf: Uint8Array): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(buf).buffer));
  const n = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
  return String(n % 1_000_000).padStart(6, "0");
}

/** Parse + validate a recovery code into its recovery_id (hex) and RK public key. */
export function parseRecoveryCode(code: string): { recoveryId: string; rkPub: Uint8Array } {
  const bytes = fromHex(code.trim());
  if (bytes.length !== RECOVERY_ID_LEN + RK_PUB_LEN) {
    throw new Error("That recovery code isn't valid.");
  }
  return { recoveryId: toHex(bytes.slice(0, RECOVERY_ID_LEN)), rkPub: bytes.slice(RECOVERY_ID_LEN) };
}

/** The SAS a contact shows to verbally confirm the code with the recovering owner. */
export async function recoveryCodeSas(code: string): Promise<string> {
  return sas6(fromHex(code.trim()));
}

/** Owner (fresh device) starts a recovery: fresh RK + random recovery_id → a code
 *  + SAS to read to each contact out of band. */
export async function startContactRecovery(
  crypto: ContactRecoveryCryptoApi = workerContactRecoveryCrypto,
): Promise<RecoverySession> {
  const rk = await crypto.ephKeypair();
  const rid = globalThis.crypto.getRandomValues(new Uint8Array(RECOVERY_ID_LEN));
  const codeBytes = new Uint8Array(RECOVERY_ID_LEN + RK_PUB_LEN);
  codeBytes.set(rid, 0);
  codeBytes.set(rk.pub, RECOVERY_ID_LEN);
  return {
    recoveryId: toHex(rid),
    rk,
    code: toHex(codeBytes),
    sas: await sas6(codeBytes),
  };
}

/** Try to reconstruct the seed from any pair of collected shares (threshold 2).
 *  A wrong pair fails the Shamir SHA tag and throws → we skip it (self-validating,
 *  design decision #1). Returns the seed, or null if no pair reconstructs yet. */
async function tryReconstruct(
  shares: Uint8Array[],
  crypto: ContactRecoveryCryptoApi,
): Promise<Uint8Array | null> {
  for (let i = 0; i < shares.length; i++) {
    for (let j = i + 1; j < shares.length; j++) {
      try {
        return await crypto.shamirReconstruct([shares[i], shares[j]]);
      } catch {
        // wrong / mismatched pair - try the next combination
      }
    }
  }
  return null;
}

/** Unseal an `ephPub || wrapped` blob (the wire format for both stored shares and
 *  rendezvous posts) with an X25519 private key; null if it isn't sealed to us. */
async function unsealBlob(
  hex: string,
  myPriv: Uint8Array,
  crypto: ContactRecoveryCryptoApi,
): Promise<Uint8Array | null> {
  const blob = fromHex(hex);
  if (blob.length <= RK_PUB_LEN) return null;
  try {
    return await crypto.unwrapCek(blob.slice(RK_PUB_LEN), blob.slice(0, RK_PUB_LEN), myPriv);
  } catch {
    return null; // not for us / garbage
  }
}

/** Unseal all posted blobs with RK, dedupe into `collected`, and reconstruct the
 *  master seed once >=2 distinct shares are present. Pure crypto, no app-state side
 *  effects (the caller finalizes). Returns the seed, or null to keep polling. */
export async function unsealAndReconstruct(
  rkPriv: Uint8Array,
  blobs: string[],
  collected: Map<string, Uint8Array>,
  crypto: ContactRecoveryCryptoApi = workerContactRecoveryCrypto,
): Promise<Uint8Array | null> {
  for (const hex of blobs) {
    const share = await unsealBlob(hex, rkPriv, crypto);
    if (share) collected.set(toHex(share), share);
  }
  return tryReconstruct([...collected.values()], crypto);
}

/** One poll pass: pull the bucket, decrypt any new shares, and reconstruct if >=2
 *  distinct shares now open. Returns the recovered userId (or null to keep polling)
 *  plus `posted` = how many blobs the bucket held this pass. `posted > 0` while
 *  `collected` stays 0 means blobs arrived but none decrypted with our RK - i.e.
 *  the code the contacts used is from a different recovery session (diagnostic). */
export async function pollContactRecovery(
  session: RecoverySession,
  collected: Map<string, Uint8Array>,
  crypto: ContactRecoveryCryptoApi = workerContactRecoveryCrypto,
): Promise<{ userId: string | null; posted: number }> {
  const { blobs } = await api.rendezvousPoll(session.recoveryId);
  const seed = await unsealAndReconstruct(session.rk.priv, blobs, collected, crypto);
  if (!seed) return { userId: null, posted: blobs.length };
  const bundle = await crypto.recoverBundleFromSeed(seed);
  await completeRecovery(bundle); // persists identity, auths, re-provisions prekeys
  return { userId: bundle.userId, posted: blobs.length };
}

/** Contact side: verify who is recovering out of band FIRST (SAS), then approve.
 *  Fetches the owner's encrypted shares, decrypts the one sealed to us, re-seals it
 *  to the owner's ephemeral RK, and posts it to the rendezvous. */
export async function approveRecovery(
  code: string,
  ownerPxId: string,
  crypto: ContactRecoveryCryptoApi = workerContactRecoveryCrypto,
): Promise<void> {
  if (!isValidPxId(ownerPxId)) throw new Error("That doesn't look like a Privex ID.");
  const { recoveryId, rkPub } = parseRecoveryCode(code);
  const me = await loadBundle();
  if (!me) throw new Error("Your identity isn't loaded on this device.");

  // Fetch the owner's encrypted shares (PoW-gated, unauthenticated).
  const pow1 = await solveServerPow(crypto.solvePow);
  const resp = await api.sharesGet(ownerPxId, pow1);

  // Exactly one blob is sealed to us; the rest (or all, for a non-contact / dummy
  // response) fail the AEAD and are skipped.
  let myShare: Uint8Array | null = null;
  for (const s of resp.shares) {
    myShare = await unsealBlob(s.encrypted_share, me.identity.x25519_priv, crypto);
    if (myShare) break;
  }
  if (!myShare) {
    throw new Error("You don't hold a recovery share for this contact.");
  }

  // Re-seal our share to the owner's ephemeral RK and post it.
  const w = await crypto.wrapCek(myShare, rkPub);
  const outBlob = new Uint8Array(w.ephPub.length + w.wrapped.length);
  outBlob.set(w.ephPub, 0);
  outBlob.set(w.wrapped, w.ephPub.length);
  const pow2 = await solveServerPow(crypto.solvePow);
  await api.rendezvousPost(recoveryId, toHex(outBlob), pow2);
}
