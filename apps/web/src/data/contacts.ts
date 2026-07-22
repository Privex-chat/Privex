// Contact + session persistence. Display names are AES-GCM-encrypted via
// EncryptedContacts (db/encrypted-db.ts). The peer's Ed25519 identity key is kept
// in the clear for safety-code rendering and key-change detection - it carries no
// more than the px_id primary key already does.
//
// The master key is normally the keystore's non-extractable key; tests pass one
// explicitly (Node can't structured-clone a CryptoKey into fake-indexeddb).
import { db } from "../db";
import { getMasterKey } from "../crypto/keystore";
import { EncryptedContacts, encryptString, type PlainContact } from "../db/encrypted-db";
import { toHex } from "../crypto/onboarding-crypto";
import { emitContactsChanged } from "../services/events";
import type { PqxdhInit, VerifiedBundle } from "../crypto/contact-crypto";

export type { PlainContact };

async function masterKey(override?: CryptoKey): Promise<CryptoKey> {
  return override ?? getMasterKey();
}

function contactsStore(key?: CryptoKey): EncryptedContacts {
  return new EncryptedContacts(db, masterKey(key));
}

/** The PQXDH initial-message fields (encrypted with the session) that the first
 *  outbound message must carry so Bob can complete the handshake in S16. */
interface PqxdhInitStash {
  v: 1;
  alice_ik_pub: string; // hex
  alice_ek_pub: string;
  kyber_ciphertext: string;
  opk_id: number | null;
  opk_used: boolean;
}

function buildInitStash(bundle: VerifiedBundle, pqx: PqxdhInit): PqxdhInitStash {
  return {
    v: 1,
    alice_ik_pub: toHex(pqx.alice_ik_pub),
    alice_ek_pub: toHex(pqx.alice_ek_pub),
    kyber_ciphertext: toHex(pqx.kyber_ciphertext),
    opk_id: bundle.opk_id,
    opk_used: pqx.opk_used,
  };
}

/**
 * Store a freshly verified contact plus its bootstrapped session: the Double
 * Ratchet state (from ratchet_init_alice) encrypted at rest, and the PQXDH
 * initial-message fields stashed for the S16 first send.
 */
export async function addVerifiedContact(
  bundle: VerifiedBundle,
  pqx: PqxdhInit,
  ratchetState: Uint8Array,
  key?: CryptoKey,
): Promise<void> {
  const k = await masterKey(key);
  // A deliberate add → pending_outbound (Discord-style): we've sent a request and
  // await their accept. `add` keeps a prior "accepted"/"blocked" sticky, so this
  // never downgrades an existing contact. Glare (they already requested us) is
  // resolved to accepted by the caller before this runs.
  await contactsStore(k).add(bundle.userId, bundle.ik_ed25519, bundle.ik_x25519, "pending_outbound");
  await db.sessions.put({
    session_id: bundle.userId,
    peer_id: bundle.userId,
    ratchet_state_enc: await encryptString(k, toHex(ratchetState)),
    pqxdh_init_enc: await encryptString(k, JSON.stringify(buildInitStash(bundle, pqx))),
    created_at: Math.floor(Date.now() / 1000),
  });
  // Notify listeners AFTER both writes so a mounted Requests/contacts view reloads
  // to show the new pending_outbound ("Sent") entry.
  emitContactsChanged();
}

/** Auto-add a sender we received a first message from but haven't KT-verified
 *  (no existing contact). ik_ed25519 comes from the sealed cert (px_id is bound to
 *  it, so it's authentic but NOT safety-code-verified); ik_x25519 (= the PQXDH
 *  alice_ik_pub) is stored so replies can be sealed. Pass an empty ikEd to leave
 *  a previously-stored identity key untouched (e.g. on a detected key change). */
export async function upsertInboundContact(
  senderId: string,
  ikEd25519: Uint8Array,
  ikX25519: Uint8Array,
  key?: CryptoKey,
): Promise<void> {
  // Unsolicited inbound → a friend request (pending_inbound) the user must accept,
  // not an auto-trusted contact. If we already accepted them, add() keeps accepted.
  await contactsStore(key).add(senderId, ikEd25519, ikX25519, "pending_inbound");
}

/** Accept a pending inbound friend request (opt-in): flip it to a real contact.
 *  The caller also sends a contact_accept so the requester learns the outcome. */
export async function acceptContact(pxId: string, key?: CryptoKey): Promise<void> {
  await contactsStore(key).setStatus(pxId, "accepted");
  emitContactsChanged(); // refresh the requests tab + the home chat list
}

/** Block a contact or requester: their future messages AND requests are dropped
 *  (a tombstone `add` won't override). Works on any state; keeps the row + history
 *  so an accepted contact can be restored on unblock (WhatsApp-style). */
export async function blockContact(pxId: string, key?: CryptoKey): Promise<void> {
  await contactsStore(key).setStatus(pxId, "blocked");
  emitContactsChanged();
}

/** Unblock: restore to a normal (accepted) contact, keeping any chat history. */
export async function unblockContact(pxId: string, key?: CryptoKey): Promise<void> {
  await contactsStore(key).setStatus(pxId, "accepted");
  emitContactsChanged();
}

/** True if this sender is blocked (their inbound messages/requests must be dropped). */
export async function isBlocked(pxId: string, key?: CryptoKey): Promise<boolean> {
  return (await contactsStore(key).get(pxId))?.status === "blocked";
}

export const getContact = (pxId: string, key?: CryptoKey) => contactsStore(key).get(pxId);
export const listContacts = (key?: CryptoKey) => contactsStore(key).list();
export const setDisplayName = (pxId: string, name: string, key?: CryptoKey) =>
  contactsStore(key).setName(pxId, name);

// verified_fingerprint is not sensitive (a public code) → a direct, key-less update.
export async function setVerified(pxId: string, safetyCode: string): Promise<void> {
  await db.contacts.update(pxId, { verified_fingerprint: safetyCode });
}

/** Remove a contact (also the DECLINE action for a pending request). Purges the
 *  whole local conversation - contact, session, stored messages, queued outbox
 *  rows - so declining leaves no orphaned readable rows behind (a bare
 *  contact/session delete used to leave messages reachable via #/chat/<id>). */
export async function removeContact(pxId: string): Promise<void> {
  await db.contacts.delete(pxId);
  await db.sessions.delete(pxId);
  await db.messages.where("session_id").equals(pxId).delete();
  // peer_id isn't indexed on outbox → filter scan (the outbox is tiny).
  await db.outbox.filter((r) => r.peer_id === pxId).delete();
  emitContactsChanged();
}

/**
 * True if a freshly fetched bundle's identity key differs from the one we stored
 * for this contact (docs 8.2 key-change detection). Reused on every key fetch
 * (before sending / re-fetch); S16 calls it again on the message-receive path.
 * The caller must NOT silently trust the new key - warn and require re-verification.
 */
export async function isKeyChanged(pxId: string, fetchedIkEd: Uint8Array): Promise<boolean> {
  const row = await db.contacts.get(pxId);
  if (!row?.ik_ed25519_pub) return false; // unknown contact / no stored key → nothing to compare
  return toHex(row.ik_ed25519_pub) !== toHex(fetchedIkEd);
}
