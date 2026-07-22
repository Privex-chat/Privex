// Delivery & read receipts (docs 4.10). Receipts are ordinary Sealed Sender
// messages - the server cannot distinguish them from chat. Three invariants:
//   MUTUAL: one setting per receipt type governs BOTH directions. Disabling means
//     we neither attach receipt requests to outgoing messages (so peers have
//     nothing to confirm to us) nor answer incoming requests.
//   NO TIMESTAMPS: a receipt carries only { token, "delivered"|"read" }.
//   JITTERED: receipts are queued in IndexedDB and sent at the next Poisson
//     cover-traffic tick (services/cover-traffic.ts), never immediately - so an
//     observer can't infer when the recipient came online from receipt timing.
//
// DEVIATION (documented): the docs sketch a wasm receipt_generate_token(); the
// token is plain CSPRNG so we use Web Crypto getRandomValues (Law 6 sanctioned,
// same source as file IVs), and the payload protobuf lives in @privex/protocol
// like every other Content variant - receipts must ride the identical envelope.
import { db } from "../db";
import { getContact } from "../data/contacts";
import { toHex, fromHex } from "../crypto/onboarding-crypto";
import { emitMessage } from "./events";
import type { ReceiptRequestWire } from "./envelope";
import type { PlainMessage } from "../db/encrypted-db";

// --- settings (db.settings; defaults: receipts ON, privacy delay OFF) ---

const DELIVERY_KEY = "receipts_delivery";
const READ_KEY = "receipts_read";
const DELAY_KEY = "receipts_privacy_delay";

const flag = async (key: string, dflt: boolean): Promise<boolean> => {
  const v = (await db.settings.get(key))?.value;
  return v === undefined ? dflt : v === true;
};

export const deliveryReceiptsEnabled = () => flag(DELIVERY_KEY, true);
export const readReceiptsEnabled = () => flag(READ_KEY, true);
export const receiptPrivacyDelayEnabled = () => flag(DELAY_KEY, false);

export const setDeliveryReceipts = (on: boolean) => db.settings.put({ key: DELIVERY_KEY, value: on });
export const setReadReceipts = (on: boolean) => db.settings.put({ key: READ_KEY, value: on });
export const setReceiptPrivacyDelay = (on: boolean) => db.settings.put({ key: DELAY_KEY, value: on });

// --- Poisson / exponential jitter ---

/** One inter-arrival sample of a Poisson process with the given mean (ms). */
export function expSample(meanMs: number, random: () => number = Math.random): number {
  return -meanMs * Math.log(1 - random());
}

const PRIVACY_DELAY_MEAN_MS = 5 * 60 * 1000; // docs 4.10: Poisson avg 5 min ...
const PRIVACY_DELAY_MAX_MS = 20 * 60 * 1000; // ... capped at 20 min
// docs 5.7 M3: a receipt must NEVER go out less than 5 s after the message arrives
// (a tick can otherwise fire almost immediately), so receipt timing can't be
// tied back to receive/read timing. Applied as a floor on every receipt.
const MIN_RECEIPT_DELAY_MS = 5_000;

// --- sender side: attach a receipt request to outgoing messages ---

/** Build the receipt request for an outgoing message, or undefined when both
 *  receipt types are off (mutual: no request → the peer can't confirm to us). */
export async function buildReceiptRequest(): Promise<
  { wire: ReceiptRequestWire; token: Uint8Array } | undefined
> {
  const [delivery, read] = await Promise.all([deliveryReceiptsEnabled(), readReceiptsEnabled()]);
  if (!delivery && !read) return undefined;
  const token = crypto.getRandomValues(new Uint8Array(32));
  return { wire: { tokenId: token, requestDelivery: delivery, requestRead: read }, token };
}

// --- recipient side: queue receipts (NEVER send inline) ---

async function queueReceipt(
  to: string,
  tokenId: Uint8Array,
  type: "delivered" | "read",
): Promise<void> {
  // Mutual gate + never confirm to a sender we haven't accepted: a delivery
  // receipt to a pending/unknown requester would be a live-account/online oracle
  // (the exact charting vector the PoW gate closed), and receipts-after-decline
  // would leak the decline. Accepted contacts only.
  const contact = await getContact(to);
  if (!contact || contact.status !== "accepted") return;

  const tokenHex = toHex(tokenId);
  // Dedup (server redelivery / re-render): one row per (token, type).
  const dup = await db.receipt_outbox
    .filter((r) => r.token_hex === tokenHex && r.receipt_type === type)
    .first();
  if (dup) return;

  const now = Date.now();
  const extra = (await receiptPrivacyDelayEnabled())
    ? Math.min(expSample(PRIVACY_DELAY_MEAN_MS), PRIVACY_DELAY_MAX_MS)
    : 0;
  // Always at least the 5 s floor; the privacy delay (avg 5 min) layers on top.
  await db.receipt_outbox.add({
    to,
    token_hex: tokenHex,
    receipt_type: type,
    queued_at: now,
    not_before: now + Math.max(MIN_RECEIPT_DELAY_MS, extra),
  });
}

/** Queue a "delivered" receipt for a just-received message (if the sender asked
 *  and our mutual setting is on). Called from receiveMessage. */
export async function queueDeliveryReceipt(senderId: string, tokenId: Uint8Array): Promise<void> {
  if (!(await deliveryReceiptsEnabled())) return;
  await queueReceipt(senderId, tokenId, "delivered");
}

/** Queue a "read" receipt once the message has actually been viewed (viewport,
 *  >1 s - Chat.tsx IntersectionObserver). Marks the row so it fires only once. */
export async function queueReadReceipt(msg: PlainMessage): Promise<void> {
  if (msg.direction !== "in" || !msg.receipt_read_wanted || msg.receipt_read_done) return;
  if (!msg.receipt_token || msg.receipt_token.length === 0) return;
  if (!(await readReceiptsEnabled())) return;
  await db.messages.update(msg.msg_id, { receipt_read_done: true });
  await queueReceipt(msg.session_id, msg.receipt_token, "read");
}

// --- drain (called on each Poisson cover-traffic tick) ---

export type SendReceipt = (to: string, tokenId: Uint8Array, type: "delivered" | "read") => Promise<void>;

let draining = false;

/** Send every due queued receipt through the normal Sealed Sender path. Rows are
 *  kept on a rate-limit (429) response and retried next tick; any other failure
 *  (contact removed, session gone) drops the row - receipts are best-effort. */
export async function drainReceipts(send: SendReceipt): Promise<void> {
  if (draining) return; // reentrancy guard (ticks + manual flushes can overlap)
  draining = true;
  try {
    const now = Date.now();
    const due = (await db.receipt_outbox.toArray()).filter((r) => r.not_before <= now);
    for (const r of due) {
      // Enforce the queueReceipt "accepted only" invariant at SEND time too: a
      // contact BLOCKED (or removed) AFTER a receipt was queued must not receive
      // it. Closes the block race where a "delivered"/"read" would otherwise leak
      // to someone you just blocked, in the seconds/minutes before this tick. Uses
      // the CURRENT status, so a quick block→unblock still delivers correctly.
      const contact = await getContact(r.to);
      if (!contact || contact.status !== "accepted") {
        await db.receipt_outbox.delete(r.id!);
        continue;
      }
      try {
        await send(r.to, fromHex(r.token_hex), r.receipt_type);
        await db.receipt_outbox.delete(r.id!);
      } catch (e) {
        const status = (e as { status?: number }).status;
        if (status === 429 || (status !== undefined && status >= 500)) break; // retry next tick
        await db.receipt_outbox.delete(r.id!); // permanent - drop
      }
    }
  } finally {
    draining = false;
  }
}

// --- sender side: apply an incoming receipt to our outgoing message ---

const STATUS_RANK: Record<string, number> = { sent: 0, queued: 0, delivered: 1, read: 2 };

/** Match an incoming ReceiptMessage (authenticated sender = senderId) to our
 *  outgoing message by token and upgrade its status. Never downgrades (a late
 *  "delivered" after "read" is ignored). Mutual: ignored entirely when the
 *  corresponding receipt type is disabled on this side. */
export async function applyIncomingReceipt(
  senderId: string,
  tokenId: Uint8Array,
  type: "delivered" | "read",
): Promise<boolean> {
  const enabled = type === "read" ? await readReceiptsEnabled() : await deliveryReceiptsEnabled();
  if (!enabled) return false;

  const tokenHex = toHex(tokenId);
  // Sender-scoped scan (session_id is indexed): the token must belong to a message
  // WE sent to exactly this authenticated sender - a receipt from anyone else with
  // a stolen/guessed token (2^-256) cannot touch other conversations.
  const rows = await db.messages.where("session_id").equals(senderId).toArray();
  const match = rows.find(
    (r) => r.direction === "out" && r.receipt_token && toHex(r.receipt_token) === tokenHex,
  );
  if (!match) return false;

  const current = STATUS_RANK[match.status] ?? 0;
  const next = STATUS_RANK[type];
  if (next <= current) return true; // stale/duplicate - matched, but no downgrade
  await db.messages.update(match.msg_id, { status: type });
  emitMessage({ peerId: senderId });
  return true;
}
