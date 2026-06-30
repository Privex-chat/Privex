// Add-contact pipeline: fetch a peer's key bundle, verify it end-to-end against
// the pinned KT key, initiate PQXDH, and persist the contact + session. The
// crypto surface is injectable (ContactCryptoApi) so the whole flow is testable
// in Node against the wasm directly with a mocked fetch - no SharedWorker.
import * as api from "../api/client";
import { KT_SIGNING_PUB_HEX } from "../config";
import {
  isValidPxId,
  type PqxdhBundleInput,
  type PqxdhInit,
  type VerifiedBundle,
} from "../crypto/contact-crypto";
import type { PowResult } from "../crypto/onboarding-crypto";
import { cryptoCall } from "../workers/crypto-client";
import { addVerifiedContact, isKeyChanged } from "../data/contacts";
import { loadBundle } from "../onboarding/store";
import { sendContactHello } from "../services/messaging";
import { solveServerPow } from "../services/pow";

export interface ContactCryptoApi {
  solvePow(challenge: Uint8Array, difficulty: number): Promise<PowResult>;
  verifyBundle(pinnedKtPubHex: string, resp: api.KeyBundleResp): Promise<VerifiedBundle>;
  pqxdhInitiate(myIkX25519Priv: Uint8Array, b: PqxdhBundleInput): Promise<PqxdhInit>;
  ratchetInitAlice(sharedSecret: Uint8Array, bobRatchetPub: Uint8Array): Promise<Uint8Array>;
}

/** Production crypto: routes to the SharedWorker. ratchet_init_alice returns
 *  plain bytes (bincode session state) → the existing passthrough handles it. */
export const workerContactCrypto: ContactCryptoApi = {
  solvePow: (c, d) => cryptoCall("solve_pow", [c, d]),
  verifyBundle: (pin, resp) => cryptoCall("verify_bundle", [pin, resp]),
  pqxdhInitiate: (priv, b) => cryptoCall("pqxdh_initiate", [priv, b]),
  ratchetInitAlice: (ss, pub) => cryptoCall("ratchet_init_alice", [ss, pub]),
};

export interface AddedContact {
  userId: string;
  ik_ed25519: Uint8Array;
}

/**
 * Add a contact by px_id. Throws on a malformed id, a fetch failure, KT/SPK
 * verification failure (possible MITM - nothing is stored), or a detected key
 * change for an existing contact (the caller must re-verify, not silently trust).
 */
export async function addContact(
  pxId: string,
  crypto: ContactCryptoApi = workerContactCrypto,
): Promise<AddedContact> {
  if (!isValidPxId(pxId)) throw new Error("That doesn't look like a Privex ID.");

  // Load our identity before spending a PoW solve, so a missing identity fails fast.
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

  // Announce ourselves so the peer auto-adds us back (rides Sealed Sender - no
  // server-side social graph). Best-effort: if it fails, they'll still see us on
  // our first real message.
  await sendContactHello(pxId).catch(() => {});

  return { userId: verified.userId, ik_ed25519: verified.ik_ed25519 };
}
