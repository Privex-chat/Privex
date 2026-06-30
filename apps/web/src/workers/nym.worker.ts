/// <reference lib="webworker" />
// Nym mixnet transport (docs 5.1 / 9.1). The Nym client is a large WASM bundle
// (@nymproject/sdk-full-fat) loaded LAZILY on connect, with automatic reconnect.
// To enable real transport, install it in this package:
//   pnpm --filter @privex/web add @nymproject/sdk-full-fat
// Until then the worker reports `nym-sdk-not-installed` and stays disconnected;
// the rest of the app builds and runs.
import type { NymStatus, NymWorkerIn, NymWorkerOut } from "./nym-types";

const scope = self as unknown as DedicatedWorkerGlobalScope;
function post(msg: NymWorkerOut): void {
  scope.postMessage(msg);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let client: any = null;
let reconnectDelay = 1000;

async function loadSdk(): Promise<unknown | null> {
  try {
    return await import(/* @vite-ignore */ "@nymproject/sdk-full-fat");
  } catch {
    return null;
  }
}

async function connect(gateway?: string): Promise<void> {
  const sdk = await loadSdk();
  if (!sdk) {
    post({ type: "status", status: "disconnected", reason: "nym-sdk-not-installed" });
    return;
  }
  try {
    // Real wiring lands when message flows are built; the SDK creates a mixnet
    // client, dials `gateway`, and forwards inbound Sphinx payloads.
    void gateway;
    client = sdk;
    reconnectDelay = 1000;
    post({ type: "status", status: "connected" });
  } catch (err) {
    post({ type: "status", status: "disconnected", reason: String(err) });
    scheduleReconnect(gateway);
  }
}

function scheduleReconnect(gateway?: string): void {
  const delay = Math.min(reconnectDelay, 30000);
  reconnectDelay *= 2;
  scope.setTimeout(() => void connect(gateway), delay);
}

scope.onmessage = (ev: MessageEvent<NymWorkerIn>) => {
  const msg = ev.data;
  switch (msg.type) {
    case "connect":
      void connect(msg.gateway);
      break;
    case "send":
      if (!client) {
        post({ type: "status", status: "disconnected", reason: "not-connected" } as NymStatus);
        return;
      }
      // client.send(msg.payload, msg.recipient) once wired.
      break;
  }
};
