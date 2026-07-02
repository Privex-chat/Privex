/// <reference lib="webworker" />
// Service Worker (docs 9.3), built with the Workbox injectManifest strategy: the
// precache manifest is stamped into self.__WB_MANIFEST at build time; everything
// else here is hand-written.
//
// HARD LIMIT (zero-knowledge): the SW has NEITHER the master key NOR the session
// token - both live in the main thread's memory only (never in the SW, never on
// disk). So the SW CANNOT decrypt, send, or authenticate. Background sync + push
// therefore only WAKE an open tab, which does the real work (flushOutbox /
// receiveMessage over the authenticated WebSocket). Push shows a generic
// notification; decrypted content never travels through the SW.
import {
  precacheAndRoute,
  cleanupOutdatedCaches,
  type PrecacheEntry,
} from "workbox-precaching";

const sw = self as unknown as ServiceWorkerGlobalScope;

// App shell + WASM, CacheFirst with build revisions → full offline support. With
// hash routing the only document URL is "/", which the precache serves from cache.
// API requests are NOT precached → they go to the network (effectively NetworkOnly)
// and simply fail while offline, which is correct: no stale plaintext is ever cached.
precacheAndRoute(
  (self as unknown as { __WB_MANIFEST: (string | PrecacheEntry)[] }).__WB_MANIFEST,
);
cleanupOutdatedCaches();

sw.addEventListener("install", () => void sw.skipWaiting());
sw.addEventListener("activate", (e) => e.waitUntil(sw.clients.claim()));

// autoUpdate: the page posts SKIP_WAITING to activate a freshly built SW at once.
sw.addEventListener("message", (e) => {
  if ((e as ExtendableMessageEvent).data?.type === "SKIP_WAITING") void sw.skipWaiting();
});

/** Tell every open tab to drain the outbox (the SW can't - no key/token). */
async function wakeTabs(): Promise<void> {
  const tabs = await sw.clients.matchAll({ includeUncontrolled: true, type: "window" });
  for (const tab of tabs) tab.postMessage({ type: "flush-outbox" });
}

// Background Sync + Push aren't in the TS DOM lib - minimal local shapes + a cast.
interface TaggedEvent extends ExtendableEvent {
  readonly tag: string;
}
sw.addEventListener("sync", ((e: TaggedEvent) => {
  if (e.tag === "sync-pending-messages") e.waitUntil(wakeTabs());
}) as EventListener);

// Periodic background sync (16E): on mobile/installed PWAs the SW is woken every
// ~15 min to nudge open/backgrounded tabs to sync over the authed WS. The SW holds
// no key/token, so it can only WAKE tabs - it never fetches or decrypts itself.
sw.addEventListener("periodicsync", ((e: TaggedEvent) => {
  if (e.tag === "check-messages") e.waitUntil(wakeTabs());
}) as EventListener);

// Push payload is a wake token (random bytes), never message content. The OS
// notification is GENERIC by design: the notification tray (and its history) is
// readable by other apps, so sender/preview NEVER appear here - content is shown
// only inside the app after a tab syncs.
sw.addEventListener("push", ((e: ExtendableEvent) => {
  e.waitUntil(
    (async () => {
      await wakeTabs();
      await sw.registration.showNotification("Privex", {
        body: "You have a new message.",
        tag: "privex-message",
        icon: "/icons/maskable192.webp",
      });
    })(),
  );
}) as EventListener);

interface NotificationClickEvent extends ExtendableEvent {
  readonly notification: { close(): void };
}
sw.addEventListener("notificationclick", ((e: NotificationClickEvent) => {
  e.notification.close();
  e.waitUntil(
    (async () => {
      const tabs = await sw.clients.matchAll({ includeUncontrolled: true, type: "window" });
      if (tabs.length > 0) return (tabs[0] as WindowClient).focus();
      await sw.clients.openWindow("/");
    })(),
  );
}) as EventListener);
