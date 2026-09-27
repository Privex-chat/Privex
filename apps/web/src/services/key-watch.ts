// "Your account was set up on another device" (docs 8.2 self-check, without any
// new request). Sign-in and WS-ticket replies carry the account's current signed
// prekey. Every recovery publishes a new one, and this device saves each of its
// own before publishing it - so a key this device never made, signed by this
// account's identity, means another device holding the account's keys published
// it. It all happens here: nothing is sent, and the server never learns whether
// an alert was raised or what the user answered.
//
// A lying server can hide a real change (by serving our own key back) but can't
// fake one: the key must carry this identity's hybrid signature, and a replay of
// an old key of ours is caught by KNOWN - every key this device has held, plus
// any the user said were theirs. Public keys only, kept on this device.
import { db } from "../db";
import type { AccountSpk } from "../api/client";
import { loadBundle } from "../onboarding/store";
import { fromHex, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import { cryptoCall } from "../workers/crypto-client";
import { emitKeyAlertChanged } from "./events";

const KNOWN = "known_spks"; // hex signed-prekey pubs: ours, or ones the user said were theirs
const ALERT = "key_alert"; // the unanswered foreign key (hex)

export interface KeyWatchDeps {
  loadBundle(): Promise<IdentityBundle | undefined>;
  verifyHybrid(
    data: Uint8Array,
    sigEd: Uint8Array,
    edPub: Uint8Array,
    sigDil: Uint8Array,
    dilPub: Uint8Array,
  ): Promise<boolean>;
}

const workerDeps: KeyWatchDeps = {
  loadBundle: () => loadBundle(),
  verifyHybrid: (...a) => cryptoCall<boolean>("verify_hybrid", a),
};

async function knownKeys(): Promise<Set<string>> {
  return new Set((await db.settings.get(KNOWN))?.value as string[] | undefined);
}

/** Check a reply's account key. Best effort: never throws, and does nothing on a
 *  reply from a server that predates the field. Call it only after this device
 *  has published its keys (not mid-recovery: the server still has the old ones). */
export async function checkAccountKeys(
  reply: AccountSpk | undefined,
  deps: KeyWatchDeps = workerDeps,
): Promise<void> {
  if (!reply) return;
  try {
    // Loaded AFTER the reply: our keys are saved before they're published, so this
    // copy is never older than what the server could have from us.
    const me = await deps.loadBundle();
    if (!me) return;
    const known = await knownKeys();
    const mine = [me.spk, ...(me.prevSpks ?? [])].map((k) => toHex(k.pub));
    if (mine.some((k) => !known.has(k))) {
      mine.forEach((k) => known.add(k));
      await db.settings.put({ key: KNOWN, value: [...known] });
    }

    const spk = reply.spk_x25519.toLowerCase();
    if (known.has(spk)) return;
    const signedByUs = await deps.verifyHybrid(
      fromHex(spk),
      fromHex(reply.spk_sig_ed),
      me.identity.ed25519_pub,
      fromHex(reply.spk_sig_dil),
      me.identity.dilithium3_pub,
    );
    // Not signed by this account: a broken or lying server, not another device
    // with our keys - nothing to warn about.
    if (!signedByUs) return;
    if ((await db.settings.get(ALERT))?.value === spk) return;
    await db.settings.put({ key: ALERT, value: spk });
    emitKeyAlertChanged();
  } catch {
    // Malformed reply / storage hiccup: the next reply checks again.
  }
}

export async function hasKeyAlert(): Promise<boolean> {
  return typeof (await db.settings.get(ALERT))?.value === "string";
}

/** "That was me" (or read and dismissed): remember that key as the user's and
 *  clear the alert. A different new key alerts again. */
export async function dismissKeyAlert(): Promise<void> {
  const spk = (await db.settings.get(ALERT))?.value;
  if (typeof spk === "string") {
    const known = await knownKeys();
    known.add(spk);
    await db.settings.put({ key: KNOWN, value: [...known] });
  }
  await db.settings.delete(ALERT);
  emitKeyAlertChanged();
}
