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
