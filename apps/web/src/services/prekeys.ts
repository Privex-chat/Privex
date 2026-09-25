// Prekey upkeep (docs 4.1 / 4.3 / 11): the forward-secrecy maintenance a PQXDH
// responder owes its peers.
//  - One-time prekeys are ONE-time: a used one's private half is deleted right
//    after the handshake that consumed it (messaging.ts). Unused ones are kept
//    until used - dropping one early could strand a first message still queued
//    for us. Storage grows only if someone pays proof-of-work to drain our supply
//    (~3 KB per batch of 50).
//  - The server's one-time supply is topped up in batches when it runs low.
//  - The signed prekey rotates every 30 ± 5 days. Each retired private half is
//    kept for the 60-day max message TTL (+ a day), so a handshake queued against
//    it still opens - however many rotations (incl. "log out everywhere") happen
//    meanwhile.
// Order is always: persist the new PRIVATE keys durably, then publish - the
// server must never hand out a public key whose private half we don't hold.
//
// These functions update the identity object they're given (the one messaging.ts
// caches) - but only AFTER the change is saved (see commit), so a failed save can
// never leave the cached copy ahead of what's stored.
import * as api from "../api/client";
import { saveBundle } from "../onboarding/store";
import { toHex, type IdentityBundle, type PreKey, type SignedSpk } from "../crypto/onboarding-crypto";

/** Below this many one-time prekeys, top up (the server's own nudge threshold, docs 11). */
export const OPK_LOW_WATER = 20;
export const OPK_BATCH = 50;
const DAY = 86_400;
/** How long a retired signed prekey's private half is kept: the server's 60-day
 *  max message TTL, plus a day. */
export const SPK_RETAIN_SECS = 61 * DAY;

type RetiredSpk = NonNullable<IdentityBundle["prevSpks"]>[number];

export interface PrekeyCryptoApi {
  generateOpks(startId: number, count: number): Promise<PreKey[]>;
  generateSignedSpk(edPriv: Uint8Array, dilPriv: Uint8Array): Promise<SignedSpk>;
}

/** Save `changes` durably, THEN apply them to the cached identity. */
async function commit(me: IdentityBundle, changes: Partial<IdentityBundle>): Promise<void> {
  await saveBundle({ ...me, ...changes });
  Object.assign(me, changes);
}

/** When the next rotation is due: 30 ± 5 days from `now`, uniformly, so a user's
 *  rotations don't form a fixed, fingerprintable cadence. */
export function nextSpkRotation(now: number): number {
  const u = crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32; // [0, 1)
  return now + Math.floor((25 + 10 * u) * DAY);
}

/** The retired signed prekeys still inside their retention window. One saved by
 *  an older build (no retirement time) starts its window now. */
export function retainSpks(list: RetiredSpk[], now: number): RetiredSpk[] {
  return list
    .map((k) => ({ ...k, retiredAt: k.retiredAt ?? now }))
    .filter((k) => now - k.retiredAt < SPK_RETAIN_SECS);
}

async function publishOpks(me: IdentityBundle, batch: PreKey[], token: string): Promise<void> {
  if (batch.length) {
    await api.replenishPrekeys(
      batch.map((o) => ({ opk_id: o.id, opk_x25519_pub: toHex(o.pub) })),
      token,
    );
  }
  await commit(me, { opkPending: undefined });
}

/** Top up one-time prekeys when the local supply is low - or, with `serverLow`,
 *  when the server says ITS supply is low (bundle fetches that never led to a
 *  message drain it without us seeing). A batch saved earlier whose upload failed
 *  is re-sent first (same keys - their private halves are already stored).
 *  Returns true if a batch was published. */
export async function replenishOpks(
  me: IdentityBundle,
  pc: PrekeyCryptoApi,
  token: string,
  serverLow: boolean,
): Promise<boolean> {
  if (me.opkPending?.length) {
    const pending = new Set(me.opkPending);
    await publishOpks(me, me.opks.filter((o) => pending.has(o.id)), token);
    return true;
  }
  if (!serverLow && me.opks.length >= OPK_LOW_WATER) return false;
  const nextId = me.opks.reduce((m, o) => Math.max(m, o.id), 0) + 1;
  const fresh = await pc.generateOpks(nextId, OPK_BATCH);
  await commit(me, { opks: [...me.opks, ...fresh], opkPending: fresh.map((o) => o.id) });
  await publishOpks(me, fresh, token);
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
  await commit(me, { spkPending: false });
}

/** Rotate the signed prekey when due (or if its age is unknown - bundles from
 *  before this existed). A rotation whose publish failed is retried first, and
 *  retired keys past their window are forgotten. Returns true if anything was
 *  published. */
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
  if (me.spkRotateAfter !== undefined && now < me.spkRotateAfter) {
    const prev = me.prevSpks ?? [];
    const kept = retainSpks(prev, now);
    if (kept.length !== prev.length || prev.some((k) => k.retiredAt === undefined)) {
      await commit(me, { prevSpks: kept });
    }
    return false;
  }

  const spk = await pc.generateSignedSpk(me.identity.ed25519_priv, me.identity.dilithium3_priv);
  await commit(me, {
    prevSpks: retainSpks([{ ...me.spk, retiredAt: now }, ...(me.prevSpks ?? [])], now),
    spk: { pub: spk.pub, priv: spk.priv },
    spkSig: { ed: spk.sigEd, dil: spk.sigDil },
    spkRotateAfter: nextSpkRotation(now),
    spkPending: true, // cleared once the server has the new public key
  });
  await publishSpk(me, token);
  return true;
}
