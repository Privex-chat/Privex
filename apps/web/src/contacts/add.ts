// Add-contact pipeline: fetch a peer's key bundle, verify it end-to-end against
// the pinned KT key, initiate PQXDH, and persist the contact + session (the
// handshake itself lives in ./handshake, shared with the send path). The crypto
// surface is injectable (ContactCryptoApi) so the whole flow is testable in Node
// against the wasm directly with a mocked fetch - no SharedWorker.
import { isValidPxId } from "../crypto/contact-crypto";
import { getContact } from "../data/contacts";
import { loadSession } from "../data/sessions";
import { loadBundle } from "../onboarding/store";
import { acceptContactRequest, sendContactHello } from "../services/messaging";
import { startSession, workerContactCrypto, type ContactCryptoApi } from "./handshake";

export { workerContactCrypto, type ContactCryptoApi };

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
  if (pxId === me.userId) throw new Error("You can't add yourself as a contact.");

  // Short-circuit on the existing relationship (no fetch/PoW needed):
  //  - they already requested US → "adding" them accepts it (we already hold their
  //    key + session from their request), and notifies them.
  //  - already accepted / already requested → no-op.
  //  - blocked → refuse (unblock first).
  //  - accepted but NO session (restored from a backup, or re-added after an
  //    account recovery) → fall through: a fresh handshake is the only way to
  //    talk to them again. They already have us, so they confirm right back.
  const existing = await getContact(pxId);
  if (existing?.status === "pending_inbound") {
    await acceptContactRequest(pxId);
    return { userId: pxId, ik_ed25519: existing.ik_ed25519 };
  }
  if (existing?.status === "pending_outbound") {
    return { userId: pxId, ik_ed25519: existing.ik_ed25519 };
  }
  if (existing?.status === "accepted" && (await loadSession(pxId))) {
    return { userId: pxId, ik_ed25519: existing.ik_ed25519 };
  }
  if (existing?.status === "blocked") {
    throw new Error("You've blocked this contact. Unblock them first.");
  }

  const verified = await startSession(pxId, crypto);

  // Announce ourselves so the peer auto-adds us back (rides Sealed Sender - no
  // server-side social graph). Best-effort: if it fails, they'll still see us on
  // our first real message.
  await sendContactHello(pxId).catch(() => {});

  return { userId: verified.userId, ik_ed25519: verified.ik_ed25519 };
}
