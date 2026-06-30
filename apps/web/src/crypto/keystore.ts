// Master key storage (docs 9.2 Tier 1) + cryptographic app-lock gating.
//
// DEFAULT (no app lock): a NON-EXTRACTABLE AES-GCM key in IndexedDB encrypts
// everything; its bytes never exist in JS, and it's auto-available on boot.
//
// APP LOCK ON: the data key lives in MEMORY ONLY while unlocked. At rest it exists
// solely as wrap blobs - under an Argon2id passphrase key and/or a WebAuthn-PRF
// (biometric) key - with NO auto-available handle. So a page reload, a URL change,
// or a copied IndexedDB cannot reach it without the unlock secret. getMasterKey()
// throws "locked" until unlocked; the app shows the unlock screen first.
import { get, set, del } from "idb-keyval";

const MASTER_KEY_ID = "privex-master-key"; // no-lock: non-extractable handle
const LOCK_ID = "privex-lock"; // lock metadata (wrap blobs + KDF params)

export interface PassphraseFactor {
  salt: string; // hex (Argon2id salt)
  m_cost: number; // KiB
  t_cost: number; // iterations
  wrapped: string; // hex iv||ct of the data key under the Argon2id KEK
}
export interface WebauthnFactor {
  cred_id: string; // hex WebAuthn credential id
  prf_salt: string; // hex PRF eval input
  wrapped: string; // hex iv||ct of the data key under the PRF-derived KEK
}
export interface LockMeta {
  v: 1;
  passphrase?: PassphraseFactor;
  webauthn?: WebauthnFactor;
}

// In-memory data key (lock mode). NEVER persisted unwrapped; gone on reload.
let memKey: CryptoKey | null = null;
let memKeyBytes: Uint8Array | null = null;

const raw = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

function importDataKey(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw(bytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function isUnlocked(): boolean {
  return memKey !== null;
}

export async function getLockMeta(): Promise<LockMeta | null> {
  return (await get<LockMeta>(LOCK_ID)) ?? null;
}

export async function isLockEnabled(): Promise<boolean> {
  return (await get<LockMeta>(LOCK_ID)) !== undefined;
}

/** The master key for all at-rest crypto. Throws "locked" when app lock is on and
 *  the app hasn't been unlocked this session - the caller MUST gate on the unlock
 *  screen before reaching any code that needs the key. */
export async function getMasterKey(): Promise<CryptoKey> {
  if (memKey) return memKey;
  if (await get<LockMeta>(LOCK_ID)) throw new Error("locked");
  const existing = await get<CryptoKey>(MASTER_KEY_ID);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await set(MASTER_KEY_ID, key);
  return key;
}

export async function hasMasterKey(): Promise<boolean> {
  if (memKey) return true;
  if (await get<LockMeta>(LOCK_ID)) return true;
  return (await get<CryptoKey>(MASTER_KEY_ID)) !== undefined;
}

/** Wipe ALL key material (logout): no-lock handle, lock meta, in-memory key. */
export async function clearMasterKey(): Promise<void> {
  memKey = null;
  memKeyBytes = null;
  await del(MASTER_KEY_ID);
  await del(LOCK_ID);
}

// --- app-lock plumbing (used by services/applock.ts) ---

/** Load the unlocked data key into memory (after unwrap or re-key migration). */
export async function setUnlockedKey(bytes: Uint8Array): Promise<void> {
  memKeyBytes = bytes;
  memKey = await importDataKey(bytes);
}

/** Raw data-key bytes - only while unlocked - for (re-)wrapping factors. */
export function unlockedKeyBytes(): Uint8Array | null {
  return memKeyBytes;
}

/** Forget the in-memory key (lock now). A reload clears it too. */
export function lockNow(): void {
  memKey = null;
  memKeyBytes = null;
}

export async function setLockMeta(meta: LockMeta): Promise<void> {
  await set(LOCK_ID, meta);
}
export async function clearLockMeta(): Promise<void> {
  await del(LOCK_ID);
}

/** Drop the auto-available handle when switching INTO lock mode. */
export async function clearNoLockHandle(): Promise<void> {
  await del(MASTER_KEY_ID);
}

/** Re-create a no-lock non-extractable handle from the (in-memory) data key bytes
 *  when DISABLING lock - no data re-encryption needed since the key is unchanged. */
export async function setNoLockHandle(bytes: Uint8Array): Promise<void> {
  await set(MASTER_KEY_ID, await importDataKey(bytes));
}
