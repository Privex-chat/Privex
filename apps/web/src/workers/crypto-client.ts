// Main-thread RPC client for the crypto SharedWorker. Lazily spawns the worker
// and resolves each call by id over the MessagePort. Intermediate `{ id, progress }`
// messages (e.g. PoW solve) invoke the call's onProgress without resolving it.
let port: MessagePort | null = null;
let nextId = 1;

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
  onProgress?: (attempts: number) => void;
}
const pending = new Map<number, Pending>();

function ensurePort(): MessagePort {
  if (port) return port;
  const worker = new SharedWorker(new URL("./crypto.worker.ts", import.meta.url), {
    type: "module",
    name: "privex-crypto",
  });
  port = worker.port;
  port.onmessage = (ev: MessageEvent) => {
    const d = ev.data as {
      id: number;
      ok?: boolean;
      result?: unknown;
      error?: string;
      progress?: number;
    };
    const p = pending.get(d.id);
    if (!p) return;
    if (typeof d.progress === "number") {
      p.onProgress?.(d.progress);
      return;
    }
    pending.delete(d.id);
    if (d.ok) p.resolve(d.result);
    else p.reject(new Error(d.error));
  };
  port.start();
  return port;
}

export function cryptoCall<T = unknown>(
  method: string,
  args: unknown[] = [],
  onProgress?: (attempts: number) => void,
): Promise<T> {
  const p = ensurePort();
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject, onProgress });
    p.postMessage({ id, method, args });
  });
}

/** Spawn the crypto worker early so the WASM module is loaded + cached ahead of
 *  the first real crypto call (and so it is precached for offline use). */
export function warmCrypto(): void {
  // Worker not available during SSR/tests - guard for that.
  if (typeof SharedWorker !== "undefined") ensurePort();
}
