// Double Ratchet session persistence. The ratchet state (bincode bytes from wasm)
// and the PQXDH initial-message stash are stored AES-GCM-encrypted at rest. The
// stash is present only until the session's first outbound message is sent.
import { db } from "../db";
import { getMasterKey } from "../crypto/keystore";
import { decryptString, encryptString } from "../db/encrypted-db";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import type { PqxdhInitWire } from "../services/envelope";

async function masterKey(override?: CryptoKey): Promise<CryptoKey> {
  return override ?? getMasterKey();
}

export interface LoadedSession {
  ratchetState: Uint8Array;
  pqxdhInit?: PqxdhInitWire; // present until the first outbound message is sent
}

export async function loadSession(peerId: string, key?: CryptoKey): Promise<LoadedSession | undefined> {
  const row = await db.sessions.get(peerId);
  if (!row) return undefined;
  const k = await masterKey(key);
  const ratchetState = fromHex(await decryptString(k, row.ratchet_state_enc));
  if (!row.pqxdh_init_enc) return { ratchetState };

  const s = JSON.parse(await decryptString(k, row.pqxdh_init_enc)) as {
    alice_ik_pub: string;
    alice_ek_pub: string;
    kyber_ciphertext: string;
    opk_used: boolean;
    opk_id: number | null;
  };
  return {
    ratchetState,
    pqxdhInit: {
      alice_ik_pub: fromHex(s.alice_ik_pub),
      alice_ek_pub: fromHex(s.alice_ek_pub),
      kyber_ciphertext: fromHex(s.kyber_ciphertext),
      opk_used: s.opk_used,
      opk_id: s.opk_id ?? 0,
    },
  };
}

export async function hasSession(peerId: string): Promise<boolean> {
  return (await db.sessions.get(peerId)) !== undefined;
}

export async function saveRatchetState(peerId: string, state: Uint8Array, key?: CryptoKey): Promise<void> {
  await db.sessions.update(peerId, {
    ratchet_state_enc: await encryptString(await masterKey(key), toHex(state)),
  });
}

/** Drop the PQXDH stash once the first message carrying it has been sent. */
export async function clearPqxdhInit(peerId: string): Promise<void> {
  await db.sessions.update(peerId, { pqxdh_init_enc: undefined });
}

/** Create a fresh inbound session (responder side) - no PQXDH stash to send. */
export async function createInboundSession(peerId: string, state: Uint8Array, key?: CryptoKey): Promise<void> {
  await db.sessions.put({
    session_id: peerId,
    peer_id: peerId,
    ratchet_state_enc: await encryptString(await masterKey(key), toHex(state)),
    created_at: Math.floor(Date.now() / 1000),
  });
}
