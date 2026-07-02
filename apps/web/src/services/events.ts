// Tiny in-process pub/sub so screens refresh when a message is sent/received.
// ponytail: a module-level Set, not a state library - the data lives in IndexedDB;
// this only nudges the UI to re-read it.
//
// CROSS-TAB: the server allows ONE WebSocket per account (a new connection
// replaces the old), so with several Privex tabs open only one of them receives
// pushes. That tab writes IndexedDB - shared by all tabs - but an in-process bus
// alone would leave every OTHER tab's UI stale until remount (e.g. a receipt
// flipping ✓✓ only after reopening the chat). Every emit therefore also fans out
// over a BroadcastChannel; remote posts re-emit to the local listeners only
// (BroadcastChannel never echoes to the posting tab, so there's no double-fire).
export interface MessageEvent {
  peerId: string;
}

type WireEvent =
  | { kind: "message"; peerId: string }
  | { kind: "contacts" }
  | { kind: "outbox" };

const listeners = new Set<(e: MessageEvent) => void>();
const contactListeners = new Set<() => void>();
const outboxListeners = new Set<() => void>();

const channel: BroadcastChannel | null =
  typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("privex-ui-events") : null;

if (channel) {
  channel.onmessage = (ev: globalThis.MessageEvent) => {
    const w = ev.data as WireEvent;
    if (w.kind === "message") for (const fn of listeners) fn({ peerId: w.peerId });
    else if (w.kind === "contacts") for (const fn of contactListeners) fn();
    else if (w.kind === "outbox") for (const fn of outboxListeners) fn();
  };
}

const broadcast = (w: WireEvent) => {
  try {
    channel?.postMessage(w);
  } catch {
    // closed channel / clone error - cross-tab refresh is best-effort
  }
};

export function onMessage(fn: (e: MessageEvent) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emitMessage(e: MessageEvent): void {
  for (const fn of listeners) fn(e);
  broadcast({ kind: "message", peerId: e.peerId });
}

// Contact-list changes (a new inbound contact auto-added on receive).
export function onContactsChanged(fn: () => void): () => void {
  contactListeners.add(fn);
  return () => contactListeners.delete(fn);
}

export function emitContactsChanged(): void {
  for (const fn of contactListeners) fn();
  broadcast({ kind: "contacts" });
}

// Outbox changes (a message was queued while offline, or the queue drained).
export function onOutboxChanged(fn: () => void): () => void {
  outboxListeners.add(fn);
  return () => outboxListeners.delete(fn);
}

export function emitOutboxChanged(): void {
  for (const fn of outboxListeners) fn();
  broadcast({ kind: "outbox" });
}
