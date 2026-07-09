// Offline outbox (docs 9.3 background sync). When a send can't reach the network
// the already-sealed blob is parked here and re-POSTed on reconnect. Crypto already
// ran at compose time, so flushing needs only the session token - no master key.
// That's why the Service Worker's `sync` event can't flush directly (it has neither
// key nor token): it just wakes open tabs, which call flushOutbox().
import * as api from "../api/client";
import { db } from "../db";
import { useAuth } from "../store/auth";
import { reauthenticate } from "./auth-session";
import { emitMessage, emitOutboxChanged } from "./events";

type SendFn = (peerId: string, contentB64: string, token: string) => Promise<{ message_id: string }>;

const SYNC_TAG = "sync-pending-messages";
// HTTP statuses a retry can never fix → drop the blob instead of wedging the queue.
const PERMANENT = new Set([400, 404, 413]);

/** Park a sealed blob for later delivery and ask the SW to wake us on reconnect. */
export async function enqueue(peerId: string, sealedB64: string, localMsgId: string): Promise<void> {
  await db.outbox.add({
    peer_id: peerId,
    sealed_b64: sealedB64,
    local_msg_id: localMsgId,
    created_at: Date.now(),
    attempts: 0,
  });
  emitOutboxChanged();
  void requestBackgroundSync();
}

export function outboxCount(): Promise<number> {
  return db.outbox.count();
}

let flushing = false;

/** Re-POST queued blobs oldest-first. Stops at the first network failure so the
 *  remaining ones (and ratchet/server ordering) stay intact for the next attempt. */
export async function flushOutbox(
  send: SendFn = api.sendMessage,
  token: string | null = useAuth.getState().sessionToken,
): Promise<void> {
  if (!token || flushing) return;
  flushing = true;
  try {
    const rows = await db.outbox.orderBy("created_at").toArray();
    for (const row of rows) {
      try {
        await send(row.peer_id, row.sealed_b64, token);
      } catch (e) {
        // Permanent client error (malformed / gone / too large) → this blob can
        // never succeed, so drop it (mark the row failed) and keep draining the rest.
        if (e instanceof api.ApiError && PERMANENT.has(e.status)) {
          await db.outbox.delete(row.id!);
          if (row.local_msg_id) await db.messages.update(row.local_msg_id, { status: "failed" });
          continue;
        }
        // Transient (offline, 401 stale token, 429 rate-limit, 5xx) → keep it and
        // stop; the next flush retries the whole queue (with a fresh token).
        await db.outbox.update(row.id!, { attempts: row.attempts + 1 });
        // 401 → the token expired; re-mint and re-flush once so the queue drains
        // without waiting for the next reconnect (PVX-07). reauthenticate dedupes.
        if (e instanceof api.ApiError && e.status === 401) {
          void reauthenticate().then((ok) => {
            if (ok) void flushOutbox();
          });
        }
        break;
      }
      await db.outbox.delete(row.id!);
      if (row.local_msg_id) {
        // status is a plain (non-encrypted) column → update in place.
        await db.messages.update(row.local_msg_id, { status: "sent" });
        emitMessage({ peerId: row.peer_id });
      }
    }
  } finally {
    flushing = false;
    emitOutboxChanged();
  }
}

async function requestBackgroundSync(): Promise<void> {
  try {
    const reg = await navigator.serviceWorker?.ready;
    // SyncManager isn't in the TS DOM lib and is absent on iOS Safari - best effort.
    await (reg as unknown as { sync?: { register(tag: string): Promise<void> } })?.sync?.register(SYNC_TAG);
  } catch {
    // No background sync available → the `online` event + WS reconnect still flush.
  }
}
