// Resumable onboarding state. The generated identity (incl. private keys) is
// persisted AES-GCM-encrypted under the WebCrypto master key so a closed browser
// resumes with the SAME keys (stable px_id). Plaintext key material never lands
// in IndexedDB. A coarse progress marker lives in the (non-sensitive) settings
// table; the seed mnemonic is stripped from storage once onboarding completes.
import { db } from "../db";
import { getMasterKey } from "../crypto/keystore";
import { encryptString, decryptString } from "../db/encrypted-db";
import { fromHex, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";

export type OnbStep = "welcome" | "keys" | "registered" | "done";
const PROGRESS_KEY = "onboarding";

export interface Progress {
  step: OnbStep;
  userId?: string;
}

export async function loadProgress(): Promise<Progress> {
  const row = await db.settings.get(PROGRESS_KEY);
  return (row?.value as Progress | undefined) ?? { step: "welcome" };
}

export async function saveProgress(step: OnbStep, userId?: string): Promise<void> {
  await db.settings.put({ key: PROGRESS_KEY, value: { step, userId } });
}

// --- serialize the bundle to a hex JSON blob for encryption ---

function serialize(b: IdentityBundle, includeMnemonic: boolean): string {
  const id = b.identity;
  return JSON.stringify({
    userId: b.userId,
    mnemonic: includeMnemonic ? b.mnemonic : "",
    masterSeed: toHex(b.masterSeed),
    identity: {
      ed25519_pub: toHex(id.ed25519_pub),
      ed25519_priv: toHex(id.ed25519_priv),
      dilithium3_pub: toHex(id.dilithium3_pub),
      dilithium3_priv: toHex(id.dilithium3_priv),
      kyber1024_pub: toHex(id.kyber1024_pub),
      kyber1024_priv: toHex(id.kyber1024_priv),
      x25519_pub: toHex(id.x25519_pub),
      x25519_priv: toHex(id.x25519_priv),
    },
    spk: { pub: toHex(b.spk.pub), priv: toHex(b.spk.priv) },
    spkSig: { ed: toHex(b.spkSig.ed), dil: toHex(b.spkSig.dil) },
    opks: b.opks.map((o) => ({ id: o.id, pub: toHex(o.pub), priv: toHex(o.priv) })),
  });
}

interface SerKeys {
  ed25519_pub: string;
  ed25519_priv: string;
  dilithium3_pub: string;
  dilithium3_priv: string;
  kyber1024_pub: string;
  kyber1024_priv: string;
  x25519_pub: string;
  x25519_priv: string;
}
interface SerBundle {
  userId: string;
  mnemonic: string;
  masterSeed: string;
  identity: SerKeys;
  spk: { pub: string; priv: string };
  spkSig: { ed: string; dil: string };
  opks: { id: number; pub: string; priv: string }[];
}

function deserialize(json: string): IdentityBundle {
  const s = JSON.parse(json) as SerBundle;
  const id = s.identity;
  return {
    userId: s.userId,
    mnemonic: s.mnemonic,
    masterSeed: fromHex(s.masterSeed),
    identity: {
      ed25519_pub: fromHex(id.ed25519_pub),
      ed25519_priv: fromHex(id.ed25519_priv),
      dilithium3_pub: fromHex(id.dilithium3_pub),
      dilithium3_priv: fromHex(id.dilithium3_priv),
      kyber1024_pub: fromHex(id.kyber1024_pub),
      kyber1024_priv: fromHex(id.kyber1024_priv),
      x25519_pub: fromHex(id.x25519_pub),
      x25519_priv: fromHex(id.x25519_priv),
    },
    spk: { pub: fromHex(s.spk.pub), priv: fromHex(s.spk.priv) },
    spkSig: { ed: fromHex(s.spkSig.ed), dil: fromHex(s.spkSig.dil) },
    opks: s.opks.map((o) => ({ id: o.id, pub: fromHex(o.pub), priv: fromHex(o.priv) })),
  };
}

// The master key is normally the non-extractable WebCrypto key from the keystore.
// Tests pass one explicitly (Node can't structured-clone a CryptoKey through
// idb-keyval into fake-indexeddb the way browsers do).
async function masterKey(override?: CryptoKey): Promise<CryptoKey> {
  return override ?? getMasterKey();
}

async function writeBundle(b: IdentityBundle, includeMnemonic: boolean, key: CryptoKey): Promise<void> {
  const id = b.identity;
  await db.identity.put({
    user_id: b.userId,
    ed25519_pub: id.ed25519_pub,
    dilithium3_pub: id.dilithium3_pub,
    kyber_pub: id.kyber1024_pub,
    x25519_pub: id.x25519_pub,
    priv_bundle_enc: await encryptString(key, serialize(b, includeMnemonic)),
  });
}

/** Persist the freshly generated identity (with the mnemonic, for the seed-phrase
 *  screen) and record progress. */
export async function persistGeneratedIdentity(b: IdentityBundle, key?: CryptoKey): Promise<void> {
  await writeBundle(b, true, await masterKey(key));
  await saveProgress("keys", b.userId);
}

export async function loadBundle(key?: CryptoKey): Promise<IdentityBundle | undefined> {
  const progress = await loadProgress();
  if (!progress.userId) return undefined;
  const row = await db.identity.get(progress.userId);
  if (!row?.priv_bundle_enc) return undefined;
  return deserialize(await decryptString(await masterKey(key), row.priv_bundle_enc));
}

/** Mark onboarding done. The mnemonic is retained (encrypted at rest under the
 *  master key) so Settings → View Seed Phrase can show it later - it is NOT
 *  recoverable from the master seed, so storing it is the only way to view it
 *  again. Recovered devices have an empty mnemonic (it can't be re-derived). */
export async function finalizeIdentity(b: IdentityBundle, key?: CryptoKey): Promise<void> {
  await writeBundle(b, true, await masterKey(key));
  await saveProgress("done", b.userId);
}

/** Wipe onboarding state (e.g. user restarts an incomplete onboarding). */
export async function clearOnboarding(): Promise<void> {
  const progress = await loadProgress();
  if (progress.userId) await db.identity.delete(progress.userId);
  await db.settings.delete(PROGRESS_KEY);
}
