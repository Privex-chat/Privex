// On-device session actions (docs 4.9): lock the app, erase this device.
//
// There is deliberately no "log out everywhere". Each device holds the account's
// keys and signs itself in with them - there's no password - so no server action
// could remove a device that holds them without the server keeping a list of your
// devices, which Privex doesn't. A server-side token cutoff only looked like it did
// (every device signed straight back in), stored when you pressed it, and left
// connected devices untouched. See docs/private/KNOWN_LIMITATIONS.md.
import { db } from "../db";
import { useAuth } from "../store/auth";
import { lockNow, wipeKeystore } from "../crypto/keystore";
import { disconnectWebSocket } from "./websocket";
import { stopCoverTraffic } from "./cover-traffic";
import { resetMessaging } from "./messaging";

/**
 * Lock the app: drop the in-memory data key AND fully tear down the live session,
 * so a locked device is INERT - no WebSocket, no cover traffic, no session token,
 * and no decrypted identity keys in memory. Fixes the leak where the socket + token
 * stayed live behind the lock screen (inbound messages then hit getMasterKey()→
 * "locked" and were silently dropped).
 *
 * Non-destructive: nothing on disk is deleted. Unlocking re-derives the key from the
 * passphrase/biometric, and the app re-authenticates + reconnects (App.onUnlocked),
 * at which point the server delivers everything that queued while locked.
 *
 * signOut() drops (token, authenticated); the App WS effect (keyed on those) also
 * tears down the socket + cover traffic, but we do it directly here too so the
 * teardown is immediate and deterministic, not deferred to the next React commit.
 */
export function lockApp(): void {
  lockNow(); // in-memory data key gone → getMasterKey() throws "locked"
  stopCoverTraffic(); // stop the Poisson decoy/receipt ticks
  disconnectWebSocket(); // no inbound (no silent-drop), no acks, no flush-on-open
  resetMessaging(); // drop the cached decrypted identity bundle + sender cert
  useAuth.getState().signOut(); // drop the session token + authenticated flag
}

/**
 * "Erase this device": a full LOCAL reset - delete every message, contact,
 * session, AND the identity key material, then sign out to a clean onboarding.
 *
 * IRREVERSIBLE: without a recovery phrase / OPAQUE password / server backup, the
 * account is gone. This is DESTRUCTIVE by design.
 *
 * SAFETY CONTRACT (do not violate): this runs ONLY from the explicit, confirmed
 * Settings action. It is NEVER wired to a 401, a boot/restore failure, a slow
 * load, or any transient/network condition - the correct response to those is to
 * RE-AUTHENTICATE from the local identity (auth-session.ts), never to delete data.
 * So a latency spike or an ambiguous auth error can never nuke local data.
 *
 * Does NOT contact the server (nothing to tell it - the data was only ever local).
 * The caller reloads afterwards so all in-memory module caches are dropped too.
 */
export async function eraseThisDevice(): Promise<void> {
  // 1. Stop anything that could re-write IndexedDB mid-wipe.
  stopCoverTraffic();
  disconnectWebSocket();
  resetMessaging(); // drop cached identity/sender-cert

  // 2. Delete every local store: all Dexie tables (db.tables auto-covers future
  //    ones) + the entire idb-keyval keystore (data-key handle + app-lock meta).
  await Promise.all(db.tables.map((t) => t.clear()));
  await wipeKeystore();

  // 3. Drop in-memory auth. The caller reloads → boot finds no identity → onboarding.
  useAuth.getState().signOut();
}
