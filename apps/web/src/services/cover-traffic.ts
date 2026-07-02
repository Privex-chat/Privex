// Poisson cover-traffic scheduler (docs 5.3). Each tick is one inter-arrival of a
// Poisson process; the mean follows the user's cover-traffic level (Settings).
// Queued delivery/read receipts (docs 4.10) piggyback on these ticks - that is
// what decouples receipt timing from receive/read timing.
//
// SCOPE (this session): the scheduler + receipt drain. The dummy cover SENDS
// themselves (random recipient + CSPRNG payload, docs 5.3 - the server-side drop
// path already exists) land with 16F Timing Mitigations; until then a tick that
// has no queued receipts sends nothing.
// NOTE: level "off" disables future dummy traffic, NOT the receipt drain - queued
// receipts must still flush (at the default MEDIUM cadence) or receipts would
// silently break for users who turn cover traffic off.
import { db } from "../db";
import { drainReceipts, expSample, type SendReceipt } from "./receipts";
import { sendReceipt } from "./messaging";

const COVER_KEY = "cover_traffic"; // shared with Settings.tsx

// docs 5.3: LOW λ=30s, MEDIUM λ=10s (default), HIGH λ=3s.
const MEAN_MS: Record<string, number> = {
  low: 30_000,
  medium: 10_000,
  high: 3_000,
  off: 10_000, // receipts still drain at the default cadence (see NOTE above)
};

let timer: ReturnType<typeof setTimeout> | null = null;
let running = false;

async function meanMs(): Promise<number> {
  const level = ((await db.settings.get(COVER_KEY))?.value as string | undefined) ?? "medium";
  return MEAN_MS[level] ?? MEAN_MS.medium;
}

async function tick(send: SendReceipt): Promise<void> {
  if (!running) return;
  try {
    await drainReceipts(send);
    // ponytail: 16F adds the dummy cover send here (level-gated, off → none).
  } catch {
    // best-effort; next tick retries
  }
  if (!running) return;
  timer = setTimeout(() => void tick(send), expSample(await meanMs()));
}

/** Start the Poisson tick loop (call when authenticated; idempotent). The level
 *  is re-read every tick, so Settings changes apply without a restart. */
export async function startCoverTraffic(send: SendReceipt = sendReceipt): Promise<void> {
  if (running) return;
  running = true;
  timer = setTimeout(() => void tick(send), expSample(await meanMs()));
}

export function stopCoverTraffic(): void {
  running = false;
  if (timer) clearTimeout(timer);
  timer = null;
}
