// Server-side encrypted history backup (history sync Option A). OPT-IN, off by
// default. Each message (and a contact sidecar) is re-encrypted under the
// history_key = HKDF(master_seed, ...) and uploaded as an opaque blob the server
// can't read. A new device that recovered the same identity derives the same key
// and restores. NEITHER plaintext nor the key ever leaves the device.
//
// Tradeoff (shown in the UI): while enabled, the server holds your encrypted
// history; a server+device compromise exposes it (breaks forward secrecy for
// backed-up messages). That's why it's off by default. Record shape + local DB
// mapping live in ./history-records (shared with the device-to-device transfer).
import * as api from "../api/client";
import { db } from "../db";
import { useAuth } from "../store/auth";
import { loadBundle } from "../onboarding/store";
import { deriveHistoryKey, encryptRecord, decryptRecord } from "../crypto/history-crypto";
import {
  collectLocalRecords,
  contactRecordFor,
  importRecord,
  recordId,
  type HistoryRecord,
  type MsgRecord,
} from "./history-records";
import { b64decode, b64encode } from "./bytes";

const FLAG = "history_backup";
// Flush a batch at whichever comes first: MAX_COUNT items (server caps at 500) or
// ~MAX_BODY bytes (server body limit is 2 MiB) - byte-aware so a few big file
// manifests can't push a batch over the limit and wedge the backfill.
const MAX_COUNT = 200;
const MAX_BODY = 1_500_000;

interface Blob {
  blob_id: string;
  ciphertext: string;
}

export async function isBackupEnabled(): Promise<boolean> {
  return (await db.settings.get(FLAG))?.value === true;
}

function token(): string {
  const t = useAuth.getState().sessionToken;
  if (!t) throw new Error("not authenticated");
  return t;
}

let keyCache: CryptoKey | null = null;
async function historyKey(): Promise<CryptoKey> {
  if (keyCache) return keyCache;
  const b = await loadBundle();
  if (!b) throw new Error("identity not loaded");
  keyCache = await deriveHistoryKey(b.masterSeed);
  return keyCache;
}

// Per-session set so a peer's contact sidecar is only re-sent once per app run.
const backedContacts = new Set<string>();

/** Reset cached state (sign-out / tests). */
export function resetHistoryBackup(): void {
  keyCache = null;
  backedContacts.clear();
}

async function toBlob(key: CryptoKey, rec: HistoryRecord): Promise<Blob> {
  return { blob_id: recordId(rec), ciphertext: b64encode(await encryptRecord(key, rec)) };
}

async function uploadBatched(blobs: Blob[], onProgress?: (done: number, total: number) => void): Promise<void> {
  const tok = token();
  let batch: Blob[] = [];
  let bytes = 0;
  let done = 0;
  const flush = async () => {
    if (!batch.length) return;
    await api.uploadHistory(batch, tok);
    done += batch.length;
    onProgress?.(done, blobs.length);
    batch = [];
    bytes = 0;
  };
  for (const b of blobs) {
    const sz = b.blob_id.length + b.ciphertext.length;
    if (batch.length && (batch.length >= MAX_COUNT || bytes + sz > MAX_BODY)) await flush();
    batch.push(b);
    bytes += sz;
  }
  await flush();
}

/** Re-upload the FULL local history (messages + contacts). Idempotent. */
export async function backfillAll(onProgress?: (done: number, total: number) => void): Promise<void> {
  const key = await historyKey();
  const blobs: Blob[] = [];
  for (const rec of await collectLocalRecords()) blobs.push(await toBlob(key, rec));
  await uploadBatched(blobs, onProgress);
}

/** Best-effort live backup of one newly-persisted message (+ its contact once).
 *  A failure here is healed by the next backfill - never throws to the caller. */
export async function backupMessage(m: {
  msg_id: string;
  session_id: string;
  content: string;
  timestamp: number;
  status: string;
  direction: "in" | "out";
  kind: "text" | "file";
}): Promise<void> {
  try {
    if (!(await isBackupEnabled())) return;
    const key = await historyKey();
    const rec: MsgRecord = {
      v: 1,
      type: "message",
      msg_id: m.msg_id,
      peer_id: m.session_id,
      direction: m.direction,
      kind: m.kind,
      content: m.content,
      timestamp: m.timestamp,
      status: m.status,
    };
    const blobs: Blob[] = [await toBlob(key, rec)];
    if (!backedContacts.has(m.session_id)) {
      const c = await contactRecordFor(m.session_id);
      if (c) {
        blobs.push(await toBlob(key, c));
        backedContacts.add(m.session_id);
      }
    }
    await api.uploadHistory(blobs, token());
  } catch {
    // best-effort; the next backfillAll() re-uploads anything that didn't land.
  }
}

export async function enableBackup(onProgress?: (done: number, total: number) => void): Promise<void> {
  await db.settings.put({ key: FLAG, value: true });
  await backfillAll(onProgress);
}

export async function disableBackup(): Promise<void> {
  await db.settings.delete(FLAG);
  backedContacts.clear();
  await api.deleteHistory(token());
}

export function backupStatus(): Promise<{ count: number; bytes: number }> {
  return api.historyStatus(token());
}

/** Download + decrypt all backed-up history into this device. Idempotent. */
export async function restoreHistory(onProgress?: (done: number) => void): Promise<number> {
  const key = await historyKey();
  const tok = token();
  let after: string | undefined;
  let done = 0;
  for (;;) {
    const page = await api.listHistory(tok, after);
    for (const w of page.blobs) {
      await importRecord(await decryptRecord<HistoryRecord>(key, b64decode(w.ciphertext)));
      done++;
      onProgress?.(done);
    }
    if (!page.next) break;
    after = page.next;
  }
  return done;
}
