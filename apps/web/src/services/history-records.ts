// Canonical history record shape + local DB <-> record mapping. Shared by the
// server backup (Option A) and the device-to-device transfer (Option B) so both
// encode/import history identically. A record is the plaintext unit that each path
// then encrypts (under the history_key for A, the channel_key for B).
import { db } from "../db";
import { getMasterKey } from "../crypto/keystore";
import { decryptString, EncryptedMessages } from "../db/encrypted-db";
import { setDisplayName, setVerified, upsertInboundContact } from "../data/contacts";
import { fromHex, toHex } from "../crypto/onboarding-crypto";

export interface MsgRecord {
  v: 1;
  type: "message";
  msg_id: string;
  peer_id: string;
  direction: "in" | "out";
  kind: "text" | "file";
  content: string;
  timestamp: number;
  status: string;
}
export interface ContactRecord {
  v: 1;
  type: "contact";
  px_id: string;
  name: string;
  ik_ed25519: string; // hex ("" if unknown)
  ik_x25519: string; // hex ("" if unknown)
  verified?: string; // safety code, if verified
}
export type HistoryRecord = MsgRecord | ContactRecord;

/** Stable id for a record (idempotent upload / dedup). */
export function recordId(rec: HistoryRecord): string {
  return rec.type === "contact" ? `contact:${rec.px_id}` : rec.msg_id;
}

/** Build a contact sidecar record (so names/verification survive the move). */
export async function contactRecordFor(pxId: string): Promise<ContactRecord | null> {
  const c = await db.contacts.get(pxId);
  if (!c) return null;
  const mk = await getMasterKey();
  return {
    v: 1,
    type: "contact",
    px_id: c.px_id,
    name: c.display_name_enc ? await decryptString(mk, c.display_name_enc) : "",
    ik_ed25519: c.ik_ed25519_pub ? toHex(c.ik_ed25519_pub) : "",
    ik_x25519: c.ik_x25519_pub ? toHex(c.ik_x25519_pub) : "",
    verified: c.verified_fingerprint,
  };
}

/** Every local message + contact as records (for full backfill / transfer). */
export async function collectLocalRecords(): Promise<HistoryRecord[]> {
  const mk = await getMasterKey();
  const out: HistoryRecord[] = [];
  for (const r of await db.messages.toArray()) {
    out.push({
      v: 1,
      type: "message",
      msg_id: r.msg_id,
      peer_id: r.session_id,
      direction: r.direction,
      kind: r.kind ?? "text",
      content: await decryptString(mk, r.content_enc),
      timestamp: r.timestamp,
      status: r.status,
    });
  }
  for (const c of await db.contacts.toArray()) {
    const rec = await contactRecordFor(c.px_id);
    if (rec) out.push(rec);
  }
  return out;
}

/** Import one record into the local DB. Idempotent (overwrite by id). */
export async function importRecord(rec: HistoryRecord): Promise<void> {
  if (rec.type === "contact") {
    await upsertInboundContact(
      rec.px_id,
      rec.ik_ed25519 ? fromHex(rec.ik_ed25519) : new Uint8Array(0),
      rec.ik_x25519 ? fromHex(rec.ik_x25519) : new Uint8Array(0),
    );
    if (rec.name) await setDisplayName(rec.px_id, rec.name);
    if (rec.verified) await setVerified(rec.px_id, rec.verified);
  } else {
    await new EncryptedMessages(db).add({
      msg_id: rec.msg_id,
      session_id: rec.peer_id,
      content: rec.content,
      timestamp: rec.timestamp,
      status: rec.status,
      direction: rec.direction,
      kind: rec.kind,
    });
  }
}
