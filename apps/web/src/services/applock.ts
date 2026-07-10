// App lock (cryptographic, not a deterrent). The device's data key is wrapped by
// the unlock secret(s) and held in memory only while unlocked, so a reload, a URL
// change, or a copied IndexedDB is useless without the secret:
//   - Passphrase factor: Argon2id(passphrase) → AES-GCM-wrap the data key.
//   - Biometric factor (optional): WebAuthn PRF → HKDF → AES-GCM-wrap the data key.
// Enabling re-keys all local data onto a fresh in-memory key (current chats kept).
// Locking just forgets the in-memory key; the unlock screen is the only way back in.
import { db } from "../db";
import * as ks from "../crypto/keystore";
import { aesDecrypt, aesEncrypt, rekeyAllEncryptedFields } from "../db/encrypted-db";
import { cryptoCall } from "../workers/crypto-client";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import * as webauthn from "../crypto/webauthn-prf";

// Argon2id cost for the passphrase factor (stored per-wrap so it's tunable later).
const ARGON_M = 32768; // 32 MiB
const ARGON_T = 3;
// 8-char floor: the wrap blob is offline-guessable straight from IndexedDB, so
// the only real barrier is Argon2id + passphrase entropy - 6 chars was too weak
// against a local at-rest attacker (PVX-22).
export const MIN_PASSPHRASE = 8;
export const DEFAULT_IDLE_MS = 5 * 60 * 1000;
const IDLE_KEY = "app_lock_idle_ms";
const FAIL_KEY = "app_lock_fail";

// KDF is injectable (default: the wasm worker) so tests run without a SharedWorker.
export interface AppLockKdf {
  argon2id(password: Uint8Array, salt: Uint8Array, m: number, t: number): Promise<Uint8Array>;
}
export const workerKdf: AppLockKdf = {
  argon2id: (p, s, m, t) => cryptoCall("applock_derive_key", [p, s, m, t]),
};

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const aesKey = (bytes: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", bytes as unknown as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);

export const isLockEnabled = ks.isLockEnabled;
export const isUnlocked = ks.isUnlocked;

/** Forget the in-memory key now (idle / manual lock). A reload does the same. */
export function lock(): void {
  ks.lockNow();
}

export interface LockStatus {
  enabled: boolean;
  passphrase: boolean;
  biometric: boolean;
  biometricAvailable: boolean;
}
export async function lockStatus(): Promise<LockStatus> {
  const meta = await ks.getLockMeta();
  return {
    enabled: !!meta,
    passphrase: !!meta?.passphrase,
    biometric: !!meta?.webauthn,
    biometricAvailable: webauthn.webauthnSupported(),
  };
}

// --- passphrase factor ---

async function wrapPassphrase(dataKey: Uint8Array, passphrase: string, kdf: AppLockKdf): Promise<ks.PassphraseFactor> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await aesKey(await kdf.argon2id(enc(passphrase), salt, ARGON_M, ARGON_T));
  return {
    salt: toHex(salt),
    m_cost: ARGON_M,
    t_cost: ARGON_T,
    wrapped: toHex(await aesEncrypt(kek, dataKey)),
  };
}

/** Turn on app lock with a passphrase. Re-keys all local data onto a fresh key that
 *  only the passphrase (and any biometric added later) can unwrap.
 *  ponytail: re-key isn't transactional - do it while idle, not mid-conversation. */
export async function enableWithPassphrase(passphrase: string, kdf: AppLockKdf = workerKdf): Promise<void> {
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Use at least ${MIN_PASSPHRASE} characters.`);
  const oldKey = await ks.getMasterKey();
  const newBytes = crypto.getRandomValues(new Uint8Array(32));
  await rekeyAllEncryptedFields(db, oldKey, await aesKey(newBytes));
  await ks.setUnlockedKey(newBytes);
  await ks.setLockMeta({ v: 1, passphrase: await wrapPassphrase(newBytes, passphrase, kdf) });
  await ks.clearNoLockHandle();
  await clearFailures();
}

export async function unlockWithPassphrase(passphrase: string, kdf: AppLockKdf = workerKdf): Promise<void> {
  const meta = await ks.getLockMeta();
  if (!meta?.passphrase) throw new Error("No passphrase is set.");
  await throttle();
  const f = meta.passphrase;
  const kek = await aesKey(await kdf.argon2id(enc(passphrase), fromHex(f.salt), f.m_cost, f.t_cost));
  let dataKey: Uint8Array;
  try {
    dataKey = await aesDecrypt(kek, fromHex(f.wrapped));
  } catch {
    await recordFailure();
    throw new Error("Wrong passphrase.");
  }
  await clearFailures();
  await ks.setUnlockedKey(dataKey);
}

export async function changePassphrase(newPassphrase: string, kdf: AppLockKdf = workerKdf): Promise<void> {
  const bytes = ks.unlockedKeyBytes();
  if (!bytes) throw new Error("Unlock first.");
  if (newPassphrase.length < MIN_PASSPHRASE) throw new Error(`Use at least ${MIN_PASSPHRASE} characters.`);
  const meta = (await ks.getLockMeta()) ?? { v: 1 as const };
  meta.passphrase = await wrapPassphrase(bytes, newPassphrase, kdf);
  await ks.setLockMeta(meta);
}

// --- biometric (WebAuthn PRF) factor ---

async function prfKEK(prfOutput: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", prfOutput as unknown as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0) as unknown as BufferSource,
      info: enc("privex_applock_prf_v1") as unknown as BufferSource,
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Add a biometric factor (requires the lock to be set up + unlocked). */
export async function addBiometric(userId: string): Promise<void> {
  const bytes = ks.unlockedKeyBytes();
  if (!bytes) throw new Error("Unlock first.");
  const { credId, prfSalt, prfOutput } = await webauthn.enrollWebauthn(userId);
  const kek = await prfKEK(prfOutput);
  const meta = (await ks.getLockMeta()) ?? { v: 1 as const };
  meta.webauthn = {
    cred_id: toHex(credId),
    prf_salt: toHex(prfSalt),
    wrapped: toHex(await aesEncrypt(kek, bytes)),
  };
  await ks.setLockMeta(meta);
}

export async function unlockWithBiometric(): Promise<void> {
  const meta = await ks.getLockMeta();
  if (!meta?.webauthn) throw new Error("No biometric is set.");
  const w = meta.webauthn;
  const kek = await prfKEK(await webauthn.derivePrf(fromHex(w.cred_id), fromHex(w.prf_salt)));
  const dataKey = await aesDecrypt(kek, fromHex(w.wrapped)); // throws if the secret is wrong
  await ks.setUnlockedKey(dataKey);
}

export async function removeBiometric(): Promise<void> {
  const meta = await ks.getLockMeta();
  if (!meta) return;
  delete meta.webauthn;
  await ks.setLockMeta(meta);
}

// --- disable ---

export async function disableLock(): Promise<void> {
  const bytes = ks.unlockedKeyBytes();
  if (!bytes) throw new Error("Unlock first.");
  await ks.setNoLockHandle(bytes); // auto-available again; data key unchanged → no re-encrypt
  await ks.clearLockMeta();
  await clearFailures();
}

// --- idle policy ---

export async function getIdleMs(): Promise<number> {
  return ((await db.settings.get(IDLE_KEY))?.value as number | undefined) ?? DEFAULT_IDLE_MS;
}
export async function setIdleMs(ms: number): Promise<void> {
  await db.settings.put({ key: IDLE_KEY, value: ms });
}

// --- failure backoff (deters on-device guessing; offline brute-force is bounded by
//     Argon2id + the biometric factor, neither of which this counter can enforce). ---

interface FailState {
  count: number;
  until: number;
}
async function failState(): Promise<FailState> {
  return ((await db.settings.get(FAIL_KEY))?.value as FailState | undefined) ?? { count: 0, until: 0 };
}
async function throttle(): Promise<void> {
  const wait = (await failState()).until - Date.now();
  if (wait > 0) throw new Error(`Too many attempts - wait ${Math.ceil(wait / 1000)}s.`);
}
async function recordFailure(): Promise<void> {
  const count = (await failState()).count + 1;
  const delay = count >= 5 ? Math.min(5 * 60_000, 2 ** (count - 5) * 1000) : 0;
  await db.settings.put({ key: FAIL_KEY, value: { count, until: Date.now() + delay } });
}
async function clearFailures(): Promise<void> {
  await db.settings.delete(FAIL_KEY);
}
