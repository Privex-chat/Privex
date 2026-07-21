// Transparent AES-GCM encryption for IndexedDB. Writes encrypt with the master
// key; reads decrypt. Plaintext content is never persisted - only `*_enc` bytes.
import { getMasterKey } from "../crypto/keystore";
import type {
  BlobRow,
  ContactRow,
  ContactStatus,
  GroupRow,
  MessageRow,
  PrivexDB,
  SessionRow,
} from "./index";

const IV_LEN = 12;

// TS 5.7 made TypedArrays generic over their backing buffer; WebCrypto wants
// `BufferSource` (ArrayBuffer-backed). Our arrays always are, so assert it.
const src = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

export async function aesEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: src(iv) }, key, src(plaintext)),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

export async function aesDecrypt(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  const iv = blob.subarray(0, IV_LEN);
  const ct = blob.subarray(IV_LEN);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: src(iv) }, key, src(ct)),
  );
}

export async function encryptString(key: CryptoKey, value: string): Promise<Uint8Array> {
  return aesEncrypt(key, new TextEncoder().encode(value));
}

export async function decryptString(key: CryptoKey, blob: Uint8Array): Promise<string> {
  return new TextDecoder().decode(await aesDecrypt(key, blob));
}

/** Re-encrypt every at-rest ciphertext field from oldKey to newKey (app-lock
 *  enable/disable re-key). The data key changes; plaintext is preserved. */
export async function rekeyAllEncryptedFields(
  db: PrivexDB,
  oldKey: CryptoKey,
  newKey: CryptoKey,
): Promise<void> {
  const recrypt = async (blob: Uint8Array) => aesEncrypt(newKey, await aesDecrypt(oldKey, blob));

  for (const r of await db.identity.toArray()) {
    if (r.priv_bundle_enc) {
      await db.identity.update(r.user_id, { priv_bundle_enc: await recrypt(r.priv_bundle_enc) });
    }
  }
  for (const r of await db.messages.toArray()) {
    const patch: Partial<MessageRow> = { content_enc: await recrypt(r.content_enc) };
    if (r.preview_enc) patch.preview_enc = await recrypt(r.preview_enc);
    await db.messages.update(r.msg_id, patch);
  }
  for (const r of await db.contacts.toArray()) {
    if (r.display_name_enc) {
      await db.contacts.update(r.px_id, { display_name_enc: await recrypt(r.display_name_enc) });
    }
  }
  for (const r of await db.sessions.toArray()) {
    const patch: Partial<SessionRow> = { ratchet_state_enc: await recrypt(r.ratchet_state_enc) };
    if (r.pqxdh_init_enc) patch.pqxdh_init_enc = await recrypt(r.pqxdh_init_enc);
    await db.sessions.update(r.session_id, patch);
  }
  for (const r of await db.blobs.toArray()) {
    const patch: Partial<BlobRow> = { cek_enc: await recrypt(r.cek_enc) };
    if (r.filename_enc) patch.filename_enc = await recrypt(r.filename_enc);
    await db.blobs.update(r.blob_id, patch);
  }
  for (const r of await db.groups.toArray()) {
    const patch: Partial<GroupRow> = {};
    if (r.name_enc) patch.name_enc = await recrypt(r.name_enc);
    if (r.mls_state_enc) patch.mls_state_enc = await recrypt(r.mls_state_enc);
    if (Object.keys(patch).length) await db.groups.update(r.group_id, patch);
  }
}

export interface PlainMessage {
  msg_id: string;
  session_id: string;
  content: string; // text body, or JSON FileMeta when kind === "file"
  timestamp: number;
  status: string;
  direction: "in" | "out";
  kind: "text" | "file";
  // Receipt fields (docs 4.10) — see MessageRow for semantics.
  receipt_token?: Uint8Array;
  receipt_read_wanted?: boolean;
  receipt_read_done?: boolean;
  // Signed server time anchor (docs 9.6): ORDERING key; `timestamp` is display.
  server_anchor?: number;
  // Monotonic creation timestamp (ms). Primary ordering key — same-second
  // messages always appear in arrival/send order regardless of clock drift.
  created_at: number;
}

/** Message store that transparently encrypts content on write / decrypts on read. */
export class EncryptedMessages {
  constructor(
    private db: PrivexDB,
    private keyPromise: Promise<CryptoKey> = getMasterKey(),
  ) {}

  async add(message: PlainMessage): Promise<void> {
    const key = await this.keyPromise;
    const { content, ...rest } = message;
    const row: MessageRow = { ...rest, created_at: message.created_at, content_enc: await encryptString(key, content) };
    await this.db.messages.put(row);
  }

  private async rowToPlain(row: MessageRow, key: CryptoKey): Promise<PlainMessage> {
    return {
      msg_id: row.msg_id,
      session_id: row.session_id,
      timestamp: row.timestamp,
      status: row.status,
      direction: row.direction,
      kind: row.kind ?? "text",
      receipt_token: row.receipt_token,
      receipt_read_wanted: row.receipt_read_wanted,
      receipt_read_done: row.receipt_read_done,
      server_anchor: row.server_anchor,
      created_at: row.created_at ?? 0,
      content: await decryptString(key, row.content_enc),
    };
  }

  async get(msgId: string): Promise<PlainMessage | undefined> {
    const key = await this.keyPromise;
    const row = await this.db.messages.get(msgId);
    if (!row) return undefined;
    return this.rowToPlain(row, key);
  }

  /** Most-recent `limit` messages for a conversation, oldest-first for display.
   *  Primary sort = created_at (ms precision, local monotonic clock) so same-second
   *  messages always appear in arrival/send order even when the receiver's clock
   *  drifts relative to the server anchor. Secondary = server_anchor (docs 9.6)
   *  or local timestamp; tertiary = UUIDv4 for determinism. */
  async listBySession(sessionId: string, limit = 50): Promise<PlainMessage[]> {
    const key = await this.keyPromise;
    const rows = await this.db.messages.where("session_id").equals(sessionId).toArray();
    const orderCreated = (r: MessageRow) => r.created_at ?? 0;
    const orderKey = (r: MessageRow) => r.server_anchor ?? r.timestamp;
    rows.sort((a, b) => orderCreated(a) - orderCreated(b) || orderKey(a) - orderKey(b) || a.msg_id.localeCompare(b.msg_id));
    const recent = rows.slice(-limit);
    return Promise.all(recent.map((row) => this.rowToPlain(row, key)));
  }
}

export interface PlainContact {
  px_id: string;
  name: string; // "" if unset
  verified: boolean;
  status: ContactStatus; // "accepted" | "pending_inbound" (legacy rows → "accepted")
  ik_ed25519: Uint8Array; // peer Ed25519 identity pub (empty if legacy/unset)
  ik_x25519: Uint8Array; // peer X25519 identity pub (Sealed Sender target)
  added_at: number; // unix timestamp
}

/** Contact store that transparently encrypts the display name (the only
 *  sensitive contact field) with the master key. Extends the encrypted-at-rest
 *  pattern past messages, mirroring EncryptedMessages. */
export class EncryptedContacts {
  constructor(
    private db: PrivexDB,
    private keyPromise: Promise<CryptoKey> = getMasterKey(),
  ) {}

  /** Insert/replace the contact's public record. Preserves an existing name +
   *  verification status if present (re-adds after a verified key-match). An
   *  empty ikEd (inbound sender we haven't KT-verified yet) is allowed.
   *
   *  `status` is the intent of THIS call. Two statuses are STICKY and never
   *  downgraded by a re-add / inbound: "blocked" (a blocked sender re-requesting
   *  must not unblock themselves) and "accepted" (an inbound request can't
   *  downgrade a contact you already accepted). Glare (a request from someone you
   *  already requested) is resolved to "accepted" by the caller, not here. */
  async add(
    pxId: string,
    ikEd: Uint8Array,
    ikX: Uint8Array,
    status: ContactStatus = "accepted",
  ): Promise<void> {
    const existing = await this.db.contacts.get(pxId);
    const sticky = existing?.status === "blocked" || existing?.status === "accepted";
    const row: ContactRow = {
      px_id: pxId,
      ik_ed25519_pub: ikEd.length > 0 ? ikEd : existing?.ik_ed25519_pub,
      ik_x25519_pub: ikX.length > 0 ? ikX : existing?.ik_x25519_pub,
      display_name_enc: existing?.display_name_enc,
      verified_fingerprint: existing?.verified_fingerprint,
      status: sticky ? existing!.status : status,
      added_at: existing?.added_at ?? Math.floor(Date.now() / 1000),
    };
    await this.db.contacts.put(row);
  }

  /** Promote a pending request to an accepted contact. */
  async setStatus(pxId: string, status: ContactStatus): Promise<void> {
    await this.db.contacts.update(pxId, { status });
  }

  async setName(pxId: string, name: string): Promise<void> {
    const enc = await encryptString(await this.keyPromise, name);
    await this.db.contacts.update(pxId, { display_name_enc: enc });
  }

  async setVerified(pxId: string, safetyCode: string): Promise<void> {
    await this.db.contacts.update(pxId, { verified_fingerprint: safetyCode });
  }

  async remove(pxId: string): Promise<void> {
    await this.db.contacts.delete(pxId);
  }

  private async toPlain(row: ContactRow, key: CryptoKey): Promise<PlainContact> {
    return {
      px_id: row.px_id,
      name: row.display_name_enc ? await decryptString(key, row.display_name_enc) : "",
      verified: !!row.verified_fingerprint,
      status: row.status ?? "accepted", // legacy rows predate opt-in
      ik_ed25519: row.ik_ed25519_pub ?? new Uint8Array(0),
      ik_x25519: row.ik_x25519_pub ?? new Uint8Array(0),
      added_at: row.added_at,
    };
  }

  async get(pxId: string): Promise<PlainContact | undefined> {
    const row = await this.db.contacts.get(pxId);
    if (!row) return undefined;
    return this.toPlain(row, await this.keyPromise);
  }

  async list(): Promise<PlainContact[]> {
    const rows = await this.db.contacts.toArray();
    const key = await this.keyPromise;
    return Promise.all(rows.map((r) => this.toPlain(r, key)));
  }
}
