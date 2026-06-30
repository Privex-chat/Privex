// History-backup crypto (history sync Option A). The history key is derived from
// the same master_seed the user already holds (recovered automatically via
// seed/OPAQUE), so a new device can decrypt the backup with no extra secret:
//   history_key = HKDF-SHA256(master_seed, salt="", info="privex_history_v1")
// All of this is WebCrypto (Law 6 permits browser crypto) - no server ever sees it.
import { encryptString, decryptString } from "../db/encrypted-db";

const src = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

/** Derive the non-extractable AES-256-GCM history key from the master seed. */
export async function deriveHistoryKey(masterSeed: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", src(masterSeed), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: src(new Uint8Array(0)),
      info: src(new TextEncoder().encode("privex_history_v1")),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypt one history record → iv||ciphertext bytes (caller base64s for the wire). */
export function encryptRecord(key: CryptoKey, record: unknown): Promise<Uint8Array> {
  return encryptString(key, JSON.stringify(record));
}

export async function decryptRecord<T>(key: CryptoKey, blob: Uint8Array): Promise<T> {
  return JSON.parse(await decryptString(key, blob)) as T;
}
