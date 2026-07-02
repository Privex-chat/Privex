// Time synchronization & desync-attack prevention (docs 9.6). The server is the
// ONLY time source - an external NTP query would leak the user's IP. Every WS
// delivery carries { server_ts, queued_at, server_ts_sig }: an Ed25519 signature
// (dedicated key, public half PINNED in the build) over
//   be64(server_ts) || be64(queued_at) || message_id     (byte-mirror of
//   server/src/crypto/time_signing.rs::signing_input)
//
// server_ts  = time of THIS delivery  → drift check (valid even for old backlog).
// queued_at  = arrival at the server  → the ordering anchor stored on the row
//              (a sender's manipulated clock can no longer reorder conversations
//              or dodge TTLs; the sender-claimed time is display-only).
//
// Out-of-tolerance drift shows a warning and anchors ordering to server time; the
// local clock is NEVER silently corrected (docs 9.6 - clock manipulation is a
// known attack vector in restricted environments).
//
// DEVIATION (documented): no new wasm time_verify.rs - kt_verify_root_sig IS a
// generic Ed25519 verify over raw bytes (no hashing/domain separation), so the
// same wasm export verifies these signatures; tolerance math is trivial TS.
import { TIME_SIGNING_PUB_HEX } from "../config";
import { fromHex } from "../crypto/onboarding-crypto";
import { cryptoCall } from "../workers/crypto-client";

export const DRIFT_TOLERANCE_SECS = 90;

export type VerifyEd25519 = (msg: Uint8Array, sig: Uint8Array, pub: Uint8Array) => Promise<boolean>;

const workerVerify: VerifyEd25519 = (m, s, p) => cryptoCall("kt_verify_root_sig", [m, s, p]);

/** Byte-mirror of the server's signing input. */
export function timeSigningInput(serverTs: number, queuedAt: number, messageId: string): Uint8Array {
  const id = new TextEncoder().encode(messageId);
  const out = new Uint8Array(16 + id.length);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, BigInt(serverTs), false); // big-endian, mirrors to_be_bytes
  dv.setBigUint64(8, BigInt(queuedAt), false);
  out.set(id, 16);
  return out;
}

export interface DeliveryTimeFields {
  message_id: string;
  queued_at: number;
  server_ts?: number;
  server_ts_sig?: string; // hex
}

export interface TimeVerifyResult {
  validSignature: boolean;
  withinTolerance: boolean;
  driftSeconds: number; // local - server (signed); 0 when unverifiable
  /** The ordering anchor to store: queued_at, only when the signature checks out. */
  anchor?: number;
}

/** Verify a delivery's signed timestamps against the pinned key and the local
 *  clock. Never throws; an invalid/absent signature just yields no anchor (the
 *  message itself is still end-to-end authenticated by Sealed Sender). */
export async function checkDeliveryTime(
  frame: DeliveryTimeFields,
  verify: VerifyEd25519 = workerVerify,
  localNowSecs: () => number = () => Math.floor(Date.now() / 1000),
): Promise<TimeVerifyResult> {
  if (frame.server_ts === undefined || !frame.server_ts_sig) {
    // Old server / synthetic test frame: no anchor, no drift signal.
    return { validSignature: false, withinTolerance: true, driftSeconds: 0 };
  }
  let valid = false;
  try {
    valid = await verify(
      timeSigningInput(frame.server_ts, frame.queued_at, frame.message_id),
      fromHex(frame.server_ts_sig),
      fromHex(TIME_SIGNING_PUB_HEX),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    // Forged/tampered timestamp (docs 9.6): flag it, fall back to claimed order.
    console.warn("[privex] server timestamp signature invalid");
    return { validSignature: false, withinTolerance: true, driftSeconds: 0 };
  }
  const drift = localNowSecs() - frame.server_ts;
  const within = Math.abs(drift) <= DRIFT_TOLERANCE_SECS;
  setDrift(drift, within);
  return {
    validSignature: true,
    withinTolerance: within,
    driftSeconds: drift,
    anchor: frame.queued_at,
  };
}

// --- drift state for the UI (docs 9.6: warn, never auto-correct) ---

let clockDrift = 0;
let clockWarning = false;
const driftListeners = new Set<() => void>();

function setDrift(drift: number, within: boolean): void {
  const changed = clockWarning !== !within;
  clockDrift = drift;
  clockWarning = !within;
  if (changed) for (const fn of driftListeners) fn();
}

export function clockStatus(): { warning: boolean; driftSeconds: number } {
  return { warning: clockWarning, driftSeconds: clockDrift };
}

export function onClockStatusChanged(fn: () => void): () => void {
  driftListeners.add(fn);
  return () => driftListeners.delete(fn);
}
