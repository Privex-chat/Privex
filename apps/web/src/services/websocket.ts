// WebSocket client (docs 11). Auth is a single-use ticket carried in the
// subprotocol (browsers can't set headers on a socket): connect with
// ["privex", <ticket>]. Inbound messages flow to receiveMessage; server pings are
// answered with pong; drops reconnect with exponential backoff (cap 300s).
import * as api from "../api/client";
import { receiveMessage } from "./messaging";
import { flushOutbox } from "./outbox";

const MAX_BACKOFF = 300_000;

let ws: WebSocket | null = null;
let token: string | null = null;
let stopped = false;
let retry = 0;
// Bumped on every connect/disconnect so a superseded attempt (e.g. StrictMode's
// mount→unmount→mount) can't open or reconnect a stale second socket.
let gen = 0;

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
    // Connectivity is back → deliver anything queued while offline.
    void flushOutbox();
  };
  sock.onmessage = (ev) => void handleFrame(String(ev.data));
  sock.onerror = () => sock.close();
  sock.onclose = () => {
    if (ws === sock) {
      ws = null;
      scheduleReconnect(myGen);
    }
  };
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
