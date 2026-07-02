// Poisson cover-traffic scheduler (docs 5.3 / 5.7). Each tick is one inter-arrival
// of a Poisson process; the mean follows the user's cover-traffic level (Settings).
// On each tick we (a) drain any queued delivery/read receipts and (b) emit ONE
// fixed-size dummy send - so the transmit stream is a constant Poisson process an
// observer can't correlate to real activity (docs 5.7 Mitigations 1+2, achieved
// here via constant cover traffic rather than fixed polling, which is the Phase-2
// Nym-gateway approach). Receipts riding this same stream is docs 5.7 M3.
//
// Level "off": no dummy sends (explicit user choice, e.g. metered data), but queued
// receipts still drain at the default cadence - receipts must not silently break.
import { db } from "../db";
import { drainReceipts, expSample, type SendReceipt } from "./receipts";
import { sendCoverMessage, sendReceipt } from "./messaging";

const COVER_KEY = "cover_traffic"; // shared with Settings.tsx

// docs 5.3: LOW λ=30s, MEDIUM λ=10s (default), HIGH λ=3s.
const MEAN_MS: Record<string, number> = {
  low: 30_000,
  medium: 10_000,
  high: 3_000,
  off: 10_000, // receipts still drain at the default cadence (see header)
};

export type SendCover = () => Promise<void>;

let timer: ReturnType<typeof setTimeout> | null = null;
let running = false;

async function coverLevel(): Promise<string> {
  return ((await db.settings.get(COVER_KEY))?.value as string | undefined) ?? "medium";
}

/** One tick's work: drain due receipts, then emit a dummy cover send unless cover
 *  traffic is off. Exported for tests (no scheduling side effects). */
export async function runCoverCycle(send: SendReceipt, cover: SendCover, level: string): Promise<void> {
  await drainReceipts(send);
  if (level !== "off") await cover();
}

async function tick(send: SendReceipt, cover: SendCover): Promise<void> {
  if (!running) return;
  const level = await coverLevel();
  try {
    await runCoverCycle(send, cover, level);
  } catch {
    // best-effort; next tick retries
  }
  if (!running) return;
  timer = setTimeout(() => void tick(send, cover), expSample(MEAN_MS[level] ?? MEAN_MS.medium));
}

/** Start the Poisson tick loop (call when authenticated; idempotent). The level is
 *  re-read every tick, so Settings changes apply without a restart. */
export async function startCoverTraffic(
  send: SendReceipt = sendReceipt,
  cover: SendCover = sendCoverMessage,
): Promise<void> {
  if (running) return;
  running = true;
  timer = setTimeout(() => void tick(send, cover), expSample(MEAN_MS[await coverLevel()] ?? MEAN_MS.medium));
}

export function stopCoverTraffic(): void {
  running = false;
  if (timer) clearTimeout(timer);
  timer = null;
}
