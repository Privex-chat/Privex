// WebSocket client (docs 11). Auth is a single-use ticket carried in the
// subprotocol (browsers can't set headers on a socket): connect with
// ["privex", <ticket>]. Inbound messages flow to receiveMessage; server pings are
// answered with pong; drops reconnect with exponential backoff (cap 300s).
import * as api from "../api/client";
import { receiveMessage } from "./messaging";
import { flushOutbox } from "./outbox";

const MAX_BACKOFF = 300_000;
// A live socket should hear SOMETHING (server ping, if nothing else) at least
// every WS_PING_SECS (30s default) - see server/src/ws/handler.rs. 3x that is
// generous slack, so this only fires on a genuinely stuck connection.
const STALE_MS = 90_000;

let ws: WebSocket | null = null;
let token: string | null = null;
let stopped = false;
let retry = 0;
let lastFrameAt = 0;
// Sequential frame queue (see sock.onmessage) - one receiveMessage at a time.
let frameChain: Promise<void> = Promise.resolve();
// Bumped on every connect/disconnect so a superseded attempt (e.g. StrictMode's
// mount→unmount→mount) can't open or reconnect a stale second socket.
let gen = 0;

// --- connection status (local to this tab - the server allows one socket per
// account, so this is never meaningful to broadcast cross-tab like events.ts). ---
export type WsStatus = "connected" | "disconnected";
let status: WsStatus = "disconnected";
const statusListeners = new Set<(s: WsStatus) => void>();
function setStatus(s: WsStatus): void {
  if (status === s) return;
  status = s;
  for (const fn of statusListeners) fn(s);
}
export function getWsStatus(): WsStatus {
  return status;
}
export function onWsStatusChanged(fn: (s: WsStatus) => void): () => void {
  statusListeners.add(fn);
  return () => statusListeners.delete(fn);
}

function wsUrl(): string {
  // If the app talks to an absolute backend (VITE_API_BASE), derive ws/wss from
  // it (http→ws, https→wss). Otherwise same-origin (dev proxy / Caddy in prod).
  const base = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";
  if (/^https?:\/\//.test(base)) {
    return base.replace(/^http/, "ws").replace(/\/+$/, "") + "/v1/ws";
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/v1/ws`;
}

export async function connectWebSocket(sessionToken: string): Promise<void> {
  token = sessionToken;
  stopped = false;
  await open(++gen);
}

export function disconnectWebSocket(): void {
  stopped = true;
  token = null;
  gen++;
  const sock = ws;
  ws = null;
  sock?.close();
  setStatus("disconnected");
}

async function open(myGen: number): Promise<void> {
  if (stopped || !token || myGen !== gen) return;
  let ticket: string;
  try {
    ticket = (await api.wsTicket(token)).ticket;
  } catch {
    return scheduleReconnect(myGen);
  }
  if (stopped || myGen !== gen) return; // superseded while fetching the ticket
  const sock = new WebSocket(wsUrl(), ["privex", ticket]);
  ws = sock;
  sock.onopen = () => {
    retry = 0;
    lastFrameAt = Date.now();
    setStatus("connected");
    // Connectivity is back → deliver anything queued while offline.
    void flushOutbox();
  };
  // Process frames SEQUENTIALLY. Concurrent receiveMessage calls race the shared
  // Double Ratchet state (both load the same session, last save wins) and the
  // receipt status upgrade (a late "delivered" could clobber "read"). Receipts
  // made this real: a Poisson drain sends delivered+read back-to-back, so two
  // frames routinely arrive within milliseconds.
  sock.onmessage = (ev) => {
    lastFrameAt = Date.now();
    frameChain = frameChain.then(() => handleFrame(String(ev.data))).catch(() => {});
  };
  sock.onerror = () => sock.close();
  sock.onclose = () => {
    if (ws === sock) {
      ws = null;
      setStatus("disconnected");
      scheduleReconnect(myGen);
    }
  };
}

// A backgrounded/suspended tab can miss its own `onclose` entirely (the OS may
// freeze JS execution rather than deliver the event), leaving `ws` pointing at
// a socket that will never fire onclose or reconnect on its own - see the
// Brave-PWA incident this fixes. On regaining visibility, check freshness
// directly instead of trusting onclose: reuse the SAME reconnect path (gen
// guard, ticket fetch, existing backoff/jitter for any FUTURE retry), just
// triggered immediately rather than waiting on a signal that may never come.
// This is a local, user-driven check (the user physically returned to their
// device) - it adds no new network-observable timing signal (docs §5.7).
function checkStaleness(): void {
  if (typeof document === "undefined" || document.visibilityState !== "visible") return;
  if (stopped || !token) return;
  // CONNECTING/CLOSING are mid-handshake, not stuck - leave them to resolve on
  // their own (a fresh connect attempt, or the onclose→reconnect path).
  const stale =
    !ws ||
    ws.readyState === WebSocket.CLOSED ||
    (ws.readyState === WebSocket.OPEN && Date.now() - lastFrameAt > STALE_MS);
  if (!stale) return;
  const sock = ws;
  ws = null;
  sock?.close();
  setStatus("disconnected");
  void open(++gen);
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", checkStaleness);
}

function scheduleReconnect(myGen: number): void {
  if (stopped || myGen !== gen) return;
  const delay = Math.min(MAX_BACKOFF, 1000 * 2 ** retry) + Math.random() * 1000;
  retry++;
  setTimeout(() => void open(myGen), delay);
}

function send(obj: unknown): void {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

interface ServerFrame {
  type: string;
  message_id?: string;
  content?: string;
  queued_at?: number;
  // Signed delivery timestamp (docs 9.6) - verified in receiveMessage against
  // the pinned TIME_SIGNING_PUB.
  server_ts?: number;
  server_ts_sig?: string;
}

async function handleFrame(data: string): Promise<void> {
  let frame: ServerFrame;
  try {
    frame = JSON.parse(data) as ServerFrame;
  } catch {
    return;
  }
  switch (frame.type) {
    case "message":
      if (frame.message_id && frame.content !== undefined) {
        try {
          await receiveMessage({
            message_id: frame.message_id,
            content: frame.content,
            queued_at: frame.queued_at ?? 0,
            server_ts: frame.server_ts,
            server_ts_sig: frame.server_ts_sig,
          });
        } catch {
          // Never log message contents. Undecryptable frames are left un-acked so
          // the server may redeliver after the session is established.
        }
      }
      break;
    case "ping":
      send({ type: "pong" });
      break;
    // ponytail: prekey_low replenish needs new OPK privs persisted into the
    // identity bundle (so future inbound sessions can use them). The 50 OPKs from
    // onboarding cover the checkpoint; on drain the server falls back to no-OPK
    // 3-DH (already supported). Wire full replenish when sustained load needs it.
    case "prekey_low":
      break;
    // key_change_alert is advisory; clients detect changes by re-verifying KT on
    // fetch (isKeyChanged). No server-trusted action taken here.
    case "key_change_alert":
      break;
  }
}
