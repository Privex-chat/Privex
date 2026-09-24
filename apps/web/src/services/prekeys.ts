// Prekey upkeep (docs 4.1 / 4.3 / 11): the forward-secrecy maintenance a PQXDH
// responder owes its peers.
//  - One-time prekeys are ONE-time: a used one's private half is deleted right
//    after the handshake that consumed it (messaging.ts).
//  - The server's one-time supply is topped up in batches when it runs low.
//  - The signed prekey rotates every 30 ± 5 days. The two previous private halves
//    are kept, so a handshake already in flight against an older one (queued for
//    up to the 60-day max TTL) still opens.
// Order is always: persist the new PRIVATE keys locally, then publish - the
// server must never hand out a public key whose private half we don't hold.
//
// These functions mutate the identity object they're given (the one messaging.ts
// caches) and persist it, so the in-memory copy never goes stale.
import * as api from "../api/client";
import { saveBundle } from "../onboarding/store";
import { toHex, type IdentityBundle, type PreKey, type SignedSpk } from "../crypto/onboarding-crypto";

/** Below this many one-time prekeys, top up (the server's own nudge threshold, docs 11). */
export const OPK_LOW_WATER = 20;
export const OPK_BATCH = 50;
/** Cap on locally held one-time private keys (see replenishOpks). */
export const OPK_MAX_LOCAL = 200;
export const PREV_SPKS_KEPT = 2;
const DAY = 86_400;

export interface PrekeyCryptoApi {
  generateOpks(startId: number, count: number): Promise<PreKey[]>;
  generateSignedSpk(edPriv: Uint8Array, dilPriv: Uint8Array): Promise<SignedSpk>;
}

/** When the next rotation is due: 30 ± 5 days from `now`, uniformly, so a user's
 *  rotations don't form a fixed, fingerprintable cadence. */
export function nextSpkRotation(now: number): number {
  const u = crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32; // [0, 1)
  return now + Math.floor((25 + 10 * u) * DAY);
}

/** Top up one-time prekeys when the local supply is low - or, with `serverLow`,
 *  when the server says ITS supply is low (bundle fetches that never led to a
 *  message drain it without us seeing). Returns true if a batch was published. */
export async function replenishOpks(
  me: IdentityBundle,
  pc: PrekeyCryptoApi,
  token: string,
  serverLow: boolean,
): Promise<boolean> {
  if (!serverLow && me.opks.length >= OPK_LOW_WATER) return false;
  const nextId = me.opks.reduce((m, o) => Math.max(m, o.id), 0) + 1;
  const fresh = await pc.generateOpks(nextId, OPK_BATCH);
  // Keep the newest OPK_MAX_LOCAL. The server hands out the LOWEST ids first, so
  // anything older than that was served long ago; holding those private halves
  // forever (e.g. under a bundle-fetch drain) would only grow storage.
  me.opks = [...me.opks, ...fresh].slice(-OPK_MAX_LOCAL);
  await saveBundle(me);
  await api.replenishPrekeys(
    fresh.map((o) => ({ opk_id: o.id, opk_x25519_pub: toHex(o.pub) })),
    token,
  );
  return true;
}

async function publishSpk(me: IdentityBundle, token: string): Promise<void> {
  await api.spkRotate(
    {
      spk_x25519_pub: toHex(me.spk.pub),
      spk_sig_ed: toHex(me.spkSig.ed),
      spk_sig_dil: toHex(me.spkSig.dil),
    },
    token,
  );
  me.spkPending = false;
  await saveBundle(me);
}

/** Rotate the signed prekey when due (or if its age is unknown - bundles from
 *  before this existed). A rotation whose publish failed is retried first.
 *  Returns true if anything was published. */
export async function rotateSpkIfDue(
  me: IdentityBundle,
  pc: PrekeyCryptoApi,
  token: string,
  now: number,
): Promise<boolean> {
  if (me.spkPending) {
    await publishSpk(me, token);
    return true;
  }
  if (me.spkRotateAfter !== undefined && now < me.spkRotateAfter) return false;

  const spk = await pc.generateSignedSpk(me.identity.ed25519_priv, me.identity.dilithium3_priv);
  me.prevSpks = [me.spk, ...(me.prevSpks ?? [])].slice(0, PREV_SPKS_KEPT);
  me.spk = { pub: spk.pub, priv: spk.priv };
  me.spkSig = { ed: spk.sigEd, dil: spk.sigDil };
  me.spkRotateAfter = nextSpkRotation(now);
  me.spkPending = true; // cleared once the server has the new public key
  await saveBundle(me);
  await publishSpk(me, token);
  return true;
}
