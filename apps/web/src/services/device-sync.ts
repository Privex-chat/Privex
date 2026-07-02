// Cross-device real-time sync (docs 4.11 Mode C). OPT-IN, default OFF.
//
// A message SENT from this device is re-encrypted per linked device (AES-256-GCM
// under a pairwise sync key, padded to the 1024 law) and Sealed-Sender-addressed
// to our OWN px_id. The server routes it like any message - it cannot read it and
// stores nothing extra - but an actively-observing server transiently sees
// sender==recipient on the send, which is why this is opt-in (traffic fingerprint).
//
// Keys: during a device-to-device transfer (devicelink.ts), after the SAS is
// confirmed, both devices exchange {device_id, label} over the encrypted channel
// and derive pairwise keys from the channel secret:
//   key_to_device_X = HKDF(channel_secret, "privex_device_sync_v1|" + X_device_id)
// Each side stores: send_key (= key to THEM) + recv_key (= key to ME), both
// AES-GCM-encrypted at rest with the master key. Server never sees any of it.
//
// DEVIATION (documented, mirrors receipts): no wasm device_sync.rs - AES-256-GCM
// + HKDF ride Web Crypto (Law 6; same primitives as file-chunk crypto), and the
// envelope protobuf lives in @privex/protocol like every other wire type.
import { db } from "../db";
import { getMasterKey } from "../crypto/keystore";
import { aesDecrypt, aesEncrypt, EncryptedMessages } from "../db/encrypted-db";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import { emitMessage } from "./events";

const ENABLED_KEY = "device_sync_enabled";
const DEVICE_ID_KEY = "device_id";
const HKDF_INFO = "privex_device_sync_v1|";
const PAD_BOUNDARY = 1024; // law: pad before encryption

const src = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

// --- opt-in setting (default OFF - self-sends are a traffic fingerprint) ---

export async function deviceSyncEnabled(): Promise<boolean> {
  return (await db.settings.get(ENABLED_KEY))?.value === true;
}
export const setDeviceSyncEnabled = (on: boolean) =>
  db.settings.put({ key: ENABLED_KEY, value: on });

// --- this device's identity (random, local-only; the server never sees it) ---

export async function myDeviceId(): Promise<string> {
  const existing = (await db.settings.get(DEVICE_ID_KEY))?.value as string | undefined;
  if (existing) return existing;
  const id = toHex(crypto.getRandomValues(new Uint8Array(16)));
  await db.settings.put({ key: DEVICE_ID_KEY, value: id });
  return id;
}

// --- pairwise key derivation (from the SAS-confirmed devlink channel secret) ---

/** HKDF-SHA256(channel_secret, info = "privex_device_sync_v1|" + target device id)
 *  → the 32-byte key used for sync copies SENT TO that device. */
export async function deriveSyncKey(channelSecret: Uint8Array, targetDeviceId: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", src(channelSecret), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: src(new TextEncoder().encode(HKDF_INFO + targetDeviceId)),
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

/** Persist a linked device (called from the devlink flow on BOTH sides after the
 *  SAS confirm + link-frame exchange). Keys are encrypted at rest. */
export async function storeLinkedDevice(
  channelSecret: Uint8Array,
  peerDeviceId: string,
  peerLabel: string,
): Promise<void> {
  const mk = await getMasterKey();
  const sendKey = await deriveSyncKey(channelSecret, peerDeviceId);
  const recvKey = await deriveSyncKey(channelSecret, await myDeviceId());
  await db.linked_devices.put({
    device_id: peerDeviceId,
    label: peerLabel.slice(0, 64),
    send_key_enc: await aesEncrypt(mk, sendKey),
    recv_key_enc: await aesEncrypt(mk, recvKey),
    linked_at: Math.floor(Date.now() / 1000),
  });
}

export interface LinkedDeviceInfo {
  device_id: string;
  label: string;
  linked_at: number;
}

export async function listLinkedDevices(): Promise<LinkedDeviceInfo[]> {
  const rows = await db.linked_devices.toArray();
  return rows.map((r) => ({ device_id: r.device_id, label: r.label, linked_at: r.linked_at }));
}

export const removeLinkedDevice = (deviceId: string) => db.linked_devices.delete(deviceId);

// --- sync payload codec (JSON → 1024-padded → AES-256-GCM) ---

/** Everything the other device needs to reconstruct the sent message: the
 *  conversation (peer_id), the row identity (msg_id, dedup via primary key), and
 *  the receipt token so EITHER device can apply an incoming receipt. */
export interface SyncRecord {
  v: 1;
  msg_id: string;
  peer_id: string;
  kind: "text" | "file";
  content: string; // text body / FileMeta JSON - same as the local row
  ts: number;
  token_hex?: string; // receipt token (docs 4.10), if the message carries one
}

function pad(data: Uint8Array): Uint8Array {
  const need = 4 + data.length;
  const size = Math.max(PAD_BOUNDARY, Math.ceil(need / PAD_BOUNDARY) * PAD_BOUNDARY);
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, data.length, true);
  out.set(data, 4);
  return out;
}

function unpad(padded: Uint8Array): Uint8Array {
  const len = new DataView(padded.buffer, padded.byteOffset).getUint32(0, true);
  if (4 + len > padded.length) throw new Error("bad sync padding");
  return padded.subarray(4, 4 + len);
}

async function importAes(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", src(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptSyncRecord(rec: SyncRecord, rawKey: Uint8Array): Promise<Uint8Array> {
  const key = await importAes(rawKey);
  return aesEncrypt(key, pad(new TextEncoder().encode(JSON.stringify(rec))));
}

export async function decryptSyncRecord(blob: Uint8Array, rawKey: Uint8Array): Promise<SyncRecord> {
  const key = await importAes(rawKey);
  const rec = JSON.parse(new TextDecoder().decode(unpad(await aesDecrypt(key, blob)))) as SyncRecord;
  if (rec.v !== 1 || !rec.msg_id || !rec.peer_id) throw new Error("bad sync record");
  return rec;
}

// --- send side: targets for the fan-out ---

export interface SyncTarget {
  device_id: string;
  send_key: Uint8Array;
}

/** Linked devices to fan a sent message out to. Empty when the opt-in is off or
 *  nothing is linked (the common case - zero overhead). */
export async function syncTargets(): Promise<SyncTarget[]> {
  if (!(await deviceSyncEnabled())) return [];
  const rows = await db.linked_devices.toArray();
  if (rows.length === 0) return [];
  const mk = await getMasterKey();
  return Promise.all(
    rows.map(async (r) => ({ device_id: r.device_id, send_key: await aesDecrypt(mk, r.send_key_enc) })),
  );
}

// --- receive side ---

/** Decrypt a sync copy from a linked device (throws if the origin is unknown or
 *  the blob doesn't authenticate under the pairwise key). */
export async function openSyncBlob(fromDeviceId: string, blob: Uint8Array): Promise<SyncRecord> {
  const row = await db.linked_devices.get(fromDeviceId);
  if (!row) throw new Error("sync from unlinked device");
  const mk = await getMasterKey();
  const recvKey = await aesDecrypt(mk, row.recv_key_enc);
  return decryptSyncRecord(blob, recvKey);
}

/** Store a synced sent message exactly as if it had been sent from this device.
 *  Idempotent: msg_id is the primary key, so a redelivered copy just overwrites. */
export async function applySyncRecord(rec: SyncRecord): Promise<void> {
  await new EncryptedMessages(db).add({
    msg_id: rec.msg_id,
    session_id: rec.peer_id,
    content: rec.content,
    timestamp: rec.ts,
    status: "sent",
    direction: "out",
    kind: rec.kind,
    receipt_token: rec.token_hex ? fromHex(rec.token_hex) : undefined,
  });
  emitMessage({ peerId: rec.peer_id });
}
