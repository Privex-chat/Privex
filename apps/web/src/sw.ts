/// <reference lib="webworker" />
// Service Worker (docs 9.3), built with the Workbox injectManifest strategy: the
// precache manifest is stamped into self.__WB_MANIFEST at build time; everything
// else here is hand-written.
//
// HARD LIMIT (zero-knowledge): the SW has NEITHER the master key NOR the session
// token - both live in the main thread's memory only (never in the SW, never on
// disk). So the SW CANNOT decrypt, send, or authenticate. Its only jobs are the
// offline app-shell/WASM precache and waking an open tab to flush the outbox on
// reconnect (Background Sync). It shows no notifications and holds no push
// subscription: closed-app push would route through Google/Apple/Mozilla push
// infrastructure (deanonymizing the pseudonym + leaking arrival timing), so it is
// deliberately absent. Messages deliver in real time over the WebSocket while a
// tab is open.
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

// Background Sync isn't in the TS DOM lib - minimal local shape + a cast. On
// reconnect the SW wakes any open tab to flush the offline outbox over the authed
// WebSocket (the SW itself can't - no key/token). Not a notification.
interface TaggedEvent extends ExtendableEvent {
  readonly tag: string;
}
sw.addEventListener("sync", ((e: TaggedEvent) => {
  if (e.tag === "sync-pending-messages") e.waitUntil(wakeTabs());
}) as EventListener);
