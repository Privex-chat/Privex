// Tiny in-process pub/sub so screens refresh when a message is sent/received.
// ponytail: a module-level Set, not a state library - the data lives in IndexedDB;
// this only nudges the UI to re-read it.
export interface MessageEvent {
  peerId: string;
}

const listeners = new Set<(e: MessageEvent) => void>();

export function onMessage(fn: (e: MessageEvent) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emitMessage(e: MessageEvent): void {
  for (const fn of listeners) fn(e);
}

// Contact-list changes (a new inbound contact auto-added on receive).
const contactListeners = new Set<() => void>();

export function onContactsChanged(fn: () => void): () => void {
  contactListeners.add(fn);
  return () => contactListeners.delete(fn);
}

export function emitContactsChanged(): void {
  for (const fn of contactListeners) fn();
}

// Outbox changes (a message was queued while offline, or the queue drained).
const outboxListeners = new Set<() => void>();

export function onOutboxChanged(fn: () => void): () => void {
  outboxListeners.add(fn);
  return () => outboxListeners.delete(fn);
}

export function emitOutboxChanged(): void {
  for (const fn of outboxListeners) fn();
}
