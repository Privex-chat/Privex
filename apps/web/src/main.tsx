import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { registerSW } from "virtual:pwa-register";
import App from "./App";
import { warmCrypto } from "./workers/crypto-client";
import "./index.css";

// Service worker: offline app shell + WASM caching (docs 9.3).
registerSW({ immediate: true });

// Best-effort periodic wake-up (16E). Installed PWAs with the permission get their
// SW woken ~every 15 min to nudge tabs to sync. No-op elsewhere (desktop/Firefox/
// iOS): push + the foreground WebSocket still deliver. The SW holds no key/token,
// so this only wakes tabs - it can't fetch or decrypt.
async function registerPeriodicSync(): Promise<void> {
  try {
    if (!("serviceWorker" in navigator) || !("permissions" in navigator)) return;
    const reg = await navigator.serviceWorker.ready;
    const psync = (reg as unknown as {
      periodicSync?: { register(tag: string, opts: { minInterval: number }): Promise<void> };
    }).periodicSync;
    if (!psync) return;
    const status = await navigator.permissions.query({
      name: "periodic-background-sync" as PermissionName,
    });
    if (status.state === "granted") {
      await psync.register("check-messages", { minInterval: 15 * 60 * 1000 });
    }
  } catch {
    // Unsupported / not installed → silently skip.
  }
}
void registerPeriodicSync();

// Load the crypto WASM module (in its worker) ahead of first use.
warmCrypto();

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
