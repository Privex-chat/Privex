// Device-to-device history transfer (history sync Option B). Two devices of the
// same account meet at a rendezvous_id (carried in a QR) and stream history over an
// END-TO-END ENCRYPTED channel the server only relays. The server sees ciphertext,
// like a file transfer; it stores nothing.
//
// Channel: each device makes an ephemeral X25519 keypair, exchanges public keys
// (exporter's via the QR, importer's via the relay's `hello`), and derives a shared
// channel key (wasm). Frames are AES-256-GCM under it (Web Crypto). A Short
// Authentication String (SAS = digest of both ephemeral pubs) is shown on BOTH
// screens; the user confirms they match before any data flows - this defeats a
// man-in-the-middle at the (untrusted) relay. If keys disagree, the SAS differs AND
// the encrypted frames won't open, so the transfer aborts.
//
// Scope: copies PAST history (messages + contacts) for viewing on the new device -
// it is NOT live multi-device sync. Ratchet/session state is deliberately NOT moved
// (two devices must not share one ratchet).
import * as api from "../api/client";
import { cryptoCall } from "../workers/crypto-client";
import { useAuth } from "../store/auth";
import { aesDecrypt, aesEncrypt } from "../db/encrypted-db";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import { b64decode, b64encode } from "./bytes";
import { collectLocalRecords, importRecord, type HistoryRecord } from "./history-records";

// --- crypto API (worker-backed; injectable for tests) ---

export interface DevlinkCryptoApi {
  keypair(): Promise<{ pub: Uint8Array; priv: Uint8Array }>;
  channelKey(myPriv: Uint8Array, theirPub: Uint8Array): Promise<Uint8Array>;
}

export const workerDevlinkCrypto: DevlinkCryptoApi = {
  keypair: () => cryptoCall("devlink_keypair"),
  channelKey: (p, t) => cryptoCall("devlink_channel_key", [p, t]),
};

// --- transport (a relay socket; a fake pipe in tests) ---

export interface Transport {
  send(frame: string): void;
  onFrame(cb: (frame: string) => void): void;
  onClose(cb: () => void): void;
  close(): void;
}

// --- channel crypto ---

const src = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

async function importChannelKey(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", src(bytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(key: CryptoKey, obj: unknown): Promise<string> {
  return b64encode(await aesEncrypt(key, new TextEncoder().encode(JSON.stringify(obj))));
}
async function open<T>(key: CryptoKey, d: string): Promise<T> {
  return JSON.parse(new TextDecoder().decode(await aesDecrypt(key, b64decode(d)))) as T;
}

/** 6-digit Short Authentication String over both ephemeral pubs (order-independent). */
export async function computeSAS(pubA: Uint8Array, pubB: Uint8Array): Promise<string> {
  const [x, y] = toHex(pubA) <= toHex(pubB) ? [pubA, pubB] : [pubB, pubA];
  const buf = new Uint8Array(x.length + y.length);
  buf.set(x, 0);
  buf.set(y, x.length);
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", src(buf)));
  const n = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
  return String(n % 1_000_000).padStart(6, "0");
}

function frame(t: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ t, ...extra });
}
function parse(s: string): Record<string, unknown> | null {
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return null;
  }
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
}
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export interface QrPayload {
  v: 1;
  rid: string;
  pk: string; // hex exporter ephemeral pub
}

// Compact, paste-friendly transfer token: "<rid>.<pk>" (both hex). Far shorter than
// JSON → a less dense QR that scans more reliably; also easy to copy/paste on a PC
// without a webcam. JSON is still accepted on parse for robustness.
export function encodeTransferToken(qr: QrPayload): string {
  return `${qr.rid}.${qr.pk}`;
}
export function parseTransferToken(s: string): QrPayload | null {
  const t = s.trim();
  const m = t.match(/^([0-9a-f]{32})\.([0-9a-f]{64})$/i);
  if (m) return { v: 1, rid: m[1].toLowerCase(), pk: m[2].toLowerCase() };
  try {
    const p = JSON.parse(t) as QrPayload;
    if (p.v === 1 && /^[0-9a-f]{32}$/.test(p.rid) && /^[0-9a-f]{64}$/.test(p.pk)) return p;
  } catch {
    /* not JSON */
  }
  return null;
}

export interface TransferCallbacks {
  onQr?: (qr: QrPayload) => void;
  onSas?: (sas: string) => void;
  onStatus?: (status: string) => void;
  onProgress?: (done: number, total: number) => void;
  onError?: (msg: string) => void;
}

export interface TransferHandle {
  confirm: () => void;
  cancel: () => void;
  done: Promise<number>; // # records transferred
}

/** Exporter (the existing device): shows the QR, waits for the peer, streams local
 *  history once both sides confirm the SAS. */
export function runExport(t: Transport, rid: string, cb: TransferCallbacks, dc: DevlinkCryptoApi = workerDevlinkCrypto): TransferHandle {
  const done = deferred<number>();
  let key: CryptoKey | null = null;
  let confirmed = false;
  let sentReady = false;
  let peerReady = false;
  let streaming = false;
  let finished = false;

  const fail = (msg: string) => {
    if (finished) return;
    finished = true;
    cb.onError?.(msg);
    t.close();
    done.reject(new Error(msg));
  };

  const trySendReady = async () => {
    if (!key || !confirmed || sentReady) return;
    sentReady = true;
    t.send(frame("enc", { d: await seal(key, { t: "ready" }) }));
    void maybeStream();
  };

  const maybeStream = async () => {
    if (streaming || !key || !sentReady || !peerReady) return;
    streaming = true;
    cb.onStatus?.("transferring");
    try {
      const recs = await collectLocalRecords();
      t.send(frame("enc", { d: await seal(key, { t: "manifest", count: recs.length }) }));
      let sent = 0;
      for (const rec of recs) {
        if (finished) return;
        t.send(frame("enc", { d: await seal(key, { t: "chunk", seq: sent, rec }) }));
        sent += 1;
        cb.onProgress?.(sent, recs.length);
      }
      t.send(frame("enc", { d: await seal(key, { t: "done" }) }));
      finished = true;
      cb.onStatus?.("done");
      done.resolve(sent);
      setTimeout(() => t.close(), 500); // let the last frame flush
    } catch {
      fail("transfer failed");
    }
  };

  void (async () => {
    const eph = await dc.keypair();
    cb.onQr?.({ v: 1, rid, pk: toHex(eph.pub) });
    cb.onStatus?.("waiting");
    t.onClose(() => fail("disconnected"));

    const handleFrame = async (f: string) => {
      const m = parse(f);
      if (!m) return;
      if (m.t === "hello" && typeof m.pk === "string") {
        try {
          const theirPub = fromHex(m.pk);
          key = await importChannelKey(await dc.channelKey(eph.priv, theirPub));
          cb.onSas?.(await computeSAS(eph.pub, theirPub));
          cb.onStatus?.("confirm");
          await trySendReady();
        } catch {
          fail("handshake failed");
        }
      } else if (m.t === "enc" && typeof m.d === "string" && key) {
        let inner: { t?: string };
        try {
          inner = await open(key, m.d);
        } catch {
          return fail("secure channel failed (codes did not match)");
        }
        if (inner.t === "ready") {
          peerReady = true;
          await maybeStream();
        }
      } else if (m.t === "peer_left") {
        fail("the other device disconnected");
      }
    };
    // Serialize frame handling so async crypto can't reorder frames.
    let chain: Promise<void> = Promise.resolve();
    t.onFrame((f) => {
      chain = chain.then(() => handleFrame(f)).catch(() => {});
    });
  })().catch(() => fail("export failed"));

  return {
    confirm: () => {
      confirmed = true;
      void trySendReady();
    },
    cancel: () => {
      if (!finished) {
        finished = true;
        t.close();
        done.reject(new Error("cancelled"));
      }
    },
    done: done.promise,
  };
}

/** Importer (the new device): scans the QR, joins the relay, imports streamed
 *  history once both sides confirm the SAS. */
export function runImport(t: Transport, qr: QrPayload, cb: TransferCallbacks, dc: DevlinkCryptoApi = workerDevlinkCrypto): TransferHandle {
  const done = deferred<number>();
  let key: CryptoKey | null = null;
  let total = 0;
  let imported = 0;
  let finished = false;
  let confirmed = false;
  let sentReady = false;

  const fail = (msg: string) => {
    if (finished) return;
    finished = true;
    cb.onError?.(msg);
    t.close();
    done.reject(new Error(msg));
  };

  // Send our "ready" only once the channel key exists AND the user confirmed the SAS
  // (handles confirm arriving before the key is derived).
  const trySendReady = async () => {
    if (!key || !confirmed || sentReady || finished) return;
    sentReady = true;
    t.send(frame("enc", { d: await seal(key, { t: "ready" }) }));
  };

  void (async () => {
    const eph = await dc.keypair();
    const theirPub = fromHex(qr.pk);
    key = await importChannelKey(await dc.channelKey(eph.priv, theirPub));
    cb.onSas?.(await computeSAS(theirPub, eph.pub));
    cb.onStatus?.("confirm");
    t.onClose(() => fail("disconnected"));

    const handleFrame = async (f: string) => {
      const m = parse(f);
      if (!m || !key) return;
      if (m.t === "enc" && typeof m.d === "string") {
        let inner: { t?: string; count?: number; rec?: HistoryRecord };
        try {
          inner = await open(key, m.d);
        } catch {
          return fail("secure channel failed (codes did not match)");
        }
        if (inner.t === "manifest") {
          total = inner.count ?? 0;
          cb.onStatus?.("transferring");
          cb.onProgress?.(0, total);
        } else if (inner.t === "chunk" && inner.rec) {
          await importRecord(inner.rec);
          imported += 1;
          cb.onProgress?.(imported, total);
        } else if (inner.t === "done") {
          finished = true;
          cb.onStatus?.("done");
          done.resolve(imported);
          t.close();
        }
      } else if (m.t === "peer_left") {
        fail("the other device disconnected");
      }
    };
    // Serialize frame handling so streamed chunks import strictly in order.
    let chain: Promise<void> = Promise.resolve();
    t.onFrame((f) => {
      chain = chain.then(() => handleFrame(f)).catch(() => {});
    });

    // Announce ourselves so the exporter can derive the channel key.
    t.send(frame("hello", { pk: toHex(eph.pub) }));
    await trySendReady(); // in case the user confirmed before the key was ready
  })().catch(() => fail("import failed"));

  return {
    confirm: () => {
      confirmed = true;
      void trySendReady();
    },
    cancel: () => {
      if (!finished) {
        finished = true;
        t.close();
        done.reject(new Error("cancelled"));
      }
    },
    done: done.promise,
  };
}

// --- WebSocket transport (production) ---

function devlinkUrl(rid: string): string {
  const base = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";
  if (/^https?:\/\//.test(base)) {
    return base.replace(/^http/, "ws").replace(/\/+$/, "") + `/v1/devlink/${rid}`;
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/v1/devlink/${rid}`;
}

async function openTransport(rid: string): Promise<Transport> {
  const token = useAuth.getState().sessionToken;
  if (!token) throw new Error("not authenticated");
  const ticket = (await api.wsTicket(token)).ticket;
  const ws = new WebSocket(devlinkUrl(rid), ["privex", ticket]);
  ws.onerror = () => {};
  // Buffer frames sent before the socket opens (the importer's `hello` is sent
  // immediately on connect) so the handshake can't be dropped mid-open.
  let queue: string[] = [];
  ws.addEventListener("open", () => {
    for (const f of queue) ws.send(f);
    queue = [];
  });
  return {
    send: (f) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(f);
      else if (ws.readyState === WebSocket.CONNECTING) queue.push(f);
    },
    onFrame: (cb) => {
      ws.onmessage = (ev) => cb(String(ev.data));
    },
    onClose: (cb) => {
      ws.addEventListener("close", () => cb());
    },
    close: () => ws.close(),
  };
}

function randomRid(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Public: start exporting from this device. Returns once the relay is open; drives
 *  the QR/SAS/progress via callbacks. */
export async function startExport(cb: TransferCallbacks): Promise<TransferHandle> {
  const rid = randomRid();
  const t = await openTransport(rid);
  return runExport(t, rid, cb);
}

/** Public: start importing on the new device from a scanned QR payload. */
export async function startImport(qr: QrPayload, cb: TransferCallbacks): Promise<TransferHandle> {
  const t = await openTransport(qr.rid);
  return runImport(t, qr, cb);
}
