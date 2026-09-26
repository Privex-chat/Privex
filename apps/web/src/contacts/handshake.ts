// Start a fresh session with a peer: fetch their key bundle (PoW-gated), verify it
// end-to-end against the pinned KT key, run PQXDH, and store the session with the
// handshake stashed for the first outbound message. Shared by adding a contact and
// by sending to a contact we have no session with (after an account recovery or a
// history restore, the old session keys are gone). The crypto surface is
// injectable so the flow is testable in Node against the wasm directly.
import * as api from "../api/client";
import { KT_SIGNING_PUB_HEX } from "../config";
import type { PqxdhBundleInput, PqxdhInit, VerifiedBundle } from "../crypto/contact-crypto";
import { cryptoCall } from "../workers/crypto-client";
import { addVerifiedContact, isKeyChanged } from "../data/contacts";
import { loadBundle } from "../onboarding/store";
import { solveServerPow } from "../services/pow";

export interface ContactCryptoApi {
  solvePow: import("../services/pow").SolvePow;
  verifyBundle(pinnedKtPubHex: string, resp: api.KeyBundleResp): Promise<VerifiedBundle>;
  pqxdhInitiate(myIkX25519Priv: Uint8Array, b: PqxdhBundleInput): Promise<PqxdhInit>;
  ratchetInitAlice(sharedSecret: Uint8Array, bobRatchetPub: Uint8Array): Promise<Uint8Array>;
}

/** Production crypto: routes to the SharedWorker. ratchet_init_alice returns
 *  plain bytes (bincode session state) → the existing passthrough handles it. */
export const workerContactCrypto: ContactCryptoApi = {
  solvePow: (c, d, a) => cryptoCall("solve_pow", [c, d, a]),
  verifyBundle: (pin, resp) => cryptoCall("verify_bundle", [pin, resp]),
  pqxdhInitiate: (priv, b) => cryptoCall("pqxdh_initiate", [priv, b]),
  ratchetInitAlice: (ss, pub) => cryptoCall("ratchet_init_alice", [ss, pub]),
};

/**
 * Establish (or replace) our session with `pxId`. Throws on a fetch failure, a
 * KT/SPK verification failure (possible MITM - nothing is stored), or a changed
 * identity key for a contact we already hold (never silently trust a new key).
 * A new contact row is created as pending_outbound; an existing accepted or
 * blocked contact keeps its status.
 */
export async function startSession(
  pxId: string,
  crypto: ContactCryptoApi = workerContactCrypto,
): Promise<VerifiedBundle> {
  const me = await loadBundle();
  if (!me) throw new Error("Your identity isn't loaded. Finish onboarding first.");

  // Solve a PoW to fetch the bundle. This is the cost that closes account
  // enumeration / OPK drain - the server consumes the proof single-use and the
  // global difficulty climbs under a flood. No IP/identity is involved.
  const pow = await solveServerPow(crypto.solvePow);
  const resp = await api.fetchKeyBundle(pxId, pow);
  const verified = await crypto.verifyBundle(KT_SIGNING_PUB_HEX, resp);

  // If we already know this contact, refuse to overwrite a changed identity key
  // without an explicit re-verification (docs 8.2 - do not auto-trust new keys).
  if (await isKeyChanged(pxId, verified.ik_ed25519)) {
    throw new Error(`${pxId}'s key has changed. Verify their identity before re-adding.`);
  }

  const pqx = await crypto.pqxdhInitiate(me.identity.x25519_priv, {
    ik_x25519: verified.ik_x25519,
    spk_x25519: verified.spk_x25519,
    opk: verified.opk,
    kyber1024_pub: verified.kyber1024_pub,
  });
  // Bootstrap the Double Ratchet: Bob's ratchet key is his signed prekey (docs 4.4).
  const ratchetState = await crypto.ratchetInitAlice(pqx.shared_secret, verified.spk_x25519);
  await addVerifiedContact(verified, pqx, ratchetState);
  return verified;
}
