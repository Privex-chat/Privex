// Local database schema (Dexie / IndexedDB). Every sensitive field is stored
// ENCRYPTED (suffix `_enc`) with the WebCrypto master key - see encrypted-db.ts.
// No plaintext message content, contact names, or key material ever lands here.
import Dexie, { type Table } from "dexie";

export interface IdentityRow {
  user_id: string;
  ed25519_pub: Uint8Array;
  dilithium3_pub: Uint8Array;
  kyber_pub: Uint8Array;
  x25519_pub: Uint8Array;
  // Private key material (identity privs + SPK + OPKs + master seed), serialized
  // and AES-GCM-encrypted with the WebCrypto master key. Plaintext private keys
  // never touch IndexedDB. Not an index, so no schema version bump is needed.
  priv_bundle_enc?: Uint8Array;
}

export interface SessionRow {
  session_id: string;
  peer_id: string;
  ratchet_state_enc: Uint8Array; // Double Ratchet state (encrypted)
  // PQXDH initial-message fields (encrypted JSON) the FIRST outbound message must
  // carry so Bob can complete the handshake. Consumed + cleared in S16.
  pqxdh_init_enc?: Uint8Array;
  created_at: number;
}

export interface MessageRow {
  msg_id: string;
  session_id: string;
  content_enc: Uint8Array;
  preview_enc?: Uint8Array;
  timestamp: number;
  status: string;
  direction: "in" | "out";
  // "text" (default) or "file". For files, the decrypted content is a JSON
  // FileMeta (download manifest + display fields). Not sensitive → no _enc.
  kind?: "text" | "file";
  // Receipts (docs 4.10). A 32-byte random token that lives ONLY on the two
  // devices (the server never sees it). Outgoing rows: OUR token — an incoming
  // ReceiptMessage matching it flips status sent→delivered→read. Incoming rows:
  // the SENDER's token, kept so the read receipt can be queued when the message
  // is actually viewed. Random + local-only → no _enc needed; not indexed → no
  // schema version bump for these fields.
  receipt_token?: Uint8Array;
  receipt_read_wanted?: boolean; // incoming: sender asked for a read receipt
  receipt_read_done?: boolean; // incoming: read receipt already queued (dedup)
  // Signed server time anchor (docs 9.6): the server-observed arrival time,
  // verified against the pinned TIME_SIGNING pub. Used for ORDERING (a sender's
  // manipulated clock can't reorder a conversation); `timestamp` stays the
  // sender-claimed display time. Absent on outgoing rows / unsigned deliveries.
  // Not indexed → no schema version bump.
  server_anchor?: number;
  // Monotonic creation timestamp (Date.now(), millisecond precision). Primary
  // ordering key — same-second messages appear in actual send order, not random
  // UUID order. Optional for backward compatibility with older stored rows.
  created_at?: number;
}

export interface ContactRow {
  px_id: string;
  // Peer Ed25519 identity public key (PUBLIC → no _enc). px_id already pins the
  // social graph locally, and px_id = SHA-256(ik_ed25519)[..16] is derived from
  // it. Needed for safety codes + key-change detection. Not an index → no schema
  // version bump.
  ik_ed25519_pub?: Uint8Array;
  // Peer X25519 identity public key - the Sealed Sender recipient key for
  // outbound messages. From the verified bundle (added contacts) or the PQXDH
  // init field alice_ik_pub (inbound senders we haven't added yet). PUBLIC.
  ik_x25519_pub?: Uint8Array;
  display_name_enc?: Uint8Array;
  // Set to the agreed safety code once the user confirms it out-of-band.
  verified_fingerprint?: string;
  // Friend-request state. "accepted" = a contact the user chose (or a request they
  // accepted); "pending_inbound" = an unsolicited inbound hello/message awaiting the
  // user's accept/decline. Absent on rows created before opt-in → treated as
  // "accepted" (they predate the feature). Not an index → no schema version bump.
  status?: ContactStatus;
  added_at: number;
}

export type ContactStatus = "accepted" | "pending_inbound";

export interface GroupRow {
  group_id: string;
  name_enc?: Uint8Array;
  mls_state_enc?: Uint8Array;
  epoch: number;
  member_count: number;
}

export interface BlobRow {
  blob_id: string;
  chunk_ids: string[];
  cek_enc: Uint8Array;
  filename_enc?: Uint8Array;
  status: string;
}

export interface SettingRow {
  key: string;
  value: unknown; // non-sensitive app settings only
}

// Outbound messages that couldn't be POSTed (offline / network blip). The blob is
// ALREADY ratchet-encrypted + Sealed-Sender-sealed - the ratchet advanced once at
// compose time, so a retry just re-POSTs the same opaque bytes (no re-encrypt, no
// master key needed). local_msg_id links back to the visible message row (or "" for
// silent control messages like ContactHello).
export interface OutboxRow {
  id?: number;
  peer_id: string;
  sealed_b64: string;
  local_msg_id: string;
  created_at: number;
  attempts: number;
  // Per-message TTL (docs 4.12) the sender chose, in seconds; absent = server
  // default. Counts from created_at: an expired row is dropped, never sent late.
  ttl_seconds?: number;
}

// A linked device for cross-device sync (docs 4.11 Mode C). Established over the
// SAS-confirmed device-transfer channel; the pairwise sync keys are HKDF'd from
// that channel's secret and stored AES-GCM-encrypted with the master key.
// send_key encrypts sync copies TO this device; recv_key decrypts copies FROM it.
export interface LinkedDeviceRow {
  device_id: string; // peer device id, 16-byte hex
  label: string; // peer's self-chosen display label (not sensitive)
  send_key_enc: Uint8Array;
  recv_key_enc: Uint8Array;
  linked_at: number;
}

// Queued delivery/read receipts (docs 4.10). NOT sent immediately — drained at the
// next Poisson cover-traffic tick (services/cover-traffic.ts) so receipt timing is
// decoupled from receive/read timing. Persisted so a closed tab still confirms on
// the next session. token_hex is random and local-only (never a server-visible id).
export interface ReceiptOutboxRow {
  id?: number;
  to: string; // peer px_id (the original sender)
  token_hex: string;
  receipt_type: "delivered" | "read";
  queued_at: number;
  not_before: number; // 0, or a future time when Receipt Privacy Delay is on
}

export class PrivexDB extends Dexie {
  identity!: Table<IdentityRow, string>;
  sessions!: Table<SessionRow, string>;
  messages!: Table<MessageRow, string>;
  contacts!: Table<ContactRow, string>;
  groups!: Table<GroupRow, string>;
  blobs!: Table<BlobRow, string>;
  settings!: Table<SettingRow, string>;
  outbox!: Table<OutboxRow, number>;
  receipt_outbox!: Table<ReceiptOutboxRow, number>;
  linked_devices!: Table<LinkedDeviceRow, string>;

  constructor(name = "privex") {
    super(name);
    this.version(1).stores({
      identity: "user_id",
      sessions: "session_id, peer_id",
      messages: "msg_id, session_id, timestamp",
      contacts: "px_id",
      groups: "group_id",
      blobs: "blob_id",
      settings: "key",
    });
    // v2: offline outbox for background-sync resend.
    this.version(2).stores({
      outbox: "++id, created_at",
    });
    // v3: queued delivery/read receipts (drained on Poisson cover-traffic ticks).
    this.version(3).stores({
      receipt_outbox: "++id, not_before",
    });
    // v4: linked devices for cross-device sync (docs 4.11 Mode C).
    this.version(4).stores({
      linked_devices: "device_id",
    });
  }
}

export const db = new PrivexDB();
