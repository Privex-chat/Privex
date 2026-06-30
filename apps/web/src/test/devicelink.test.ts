// Device-to-device transfer (Option B): full export→import over two cross-wired
// fake transports with the real wasm channel crypto. Records module is mocked so
// the test isolates the protocol + encryption (not the local DB).
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const { hoist } = vi.hoisted(() => ({
  hoist: { source: [] as unknown[], recorded: [] as unknown[] },
}));
vi.mock("../services/history-records", () => ({
  collectLocalRecords: async () => hoist.source,
  importRecord: async (r: unknown) => {
    hoist.recorded.push(r);
  },
}));

import { initCrypto, wasm } from "../crypto/wasm";
import {
  encodeTransferToken,
  parseTransferToken,
  runExport,
  runImport,
  type DevlinkCryptoApi,
  type QrPayload,
  type Transport,
} from "../services/devicelink";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
});

const wasmCrypto: DevlinkCryptoApi = {
  keypair: async () => {
    const k = wasm.generate_x25519_prekey();
    return { pub: k.public_key, priv: k.private_key };
  },
  channelKey: async (p, t) => wasm.devlink_channel_key(p, t),
};

// Two transports cross-wired through an async pipe (a stand-in for the relay).
function relay(): { a: Transport; b: Transport } {
  let aFrame: ((f: string) => void) | null = null;
  let bFrame: ((f: string) => void) | null = null;
  const aClose: (() => void)[] = [];
  const bClose: (() => void)[] = [];
  let closed = false;
  const dispatch = (cb: ((f: string) => void) | null, f: string) => {
    if (cb) setTimeout(() => cb(f), 0);
  };
  const closeAll = () => {
    if (closed) return;
    closed = true;
    setTimeout(() => {
      aClose.forEach((c) => c());
      bClose.forEach((c) => c());
    }, 0);
  };
  return {
    a: {
      send: (f) => dispatch(bFrame, f),
      onFrame: (cb) => (aFrame = cb),
      onClose: (cb) => aClose.push(cb),
      close: closeAll,
    },
    b: {
      send: (f) => dispatch(aFrame, f),
      onFrame: (cb) => (bFrame = cb),
      onClose: (cb) => bClose.push(cb),
      close: closeAll,
    },
  };
}

afterEach(() => {
  hoist.source = [];
  hoist.recorded.length = 0;
});

describe("transfer token", () => {
  const qr: QrPayload = { v: 1, rid: "a".repeat(32), pk: "b".repeat(64) };
  it("round-trips the compact token and accepts JSON; rejects junk", () => {
    const tok = encodeTransferToken(qr);
    expect(tok).toBe(`${"a".repeat(32)}.${"b".repeat(64)}`);
    expect(parseTransferToken(`  ${tok}  `)).toEqual(qr); // trims
    expect(parseTransferToken(JSON.stringify(qr))).toEqual(qr); // JSON still accepted
    expect(parseTransferToken("not a code")).toBeNull();
    expect(parseTransferToken(`${"a".repeat(32)}.${"b".repeat(10)}`)).toBeNull(); // wrong length
  });
});

describe("device-to-device transfer (Option B)", () => {
  it("streams history records over the encrypted channel and SAS matches", async () => {
    hoist.source = [
      { v: 1, type: "message", msg_id: "a", peer_id: "px_x", direction: "out", kind: "text", content: "hello", timestamp: 1, status: "sent" },
      { v: 1, type: "message", msg_id: "b", peer_id: "px_x", direction: "in", kind: "text", content: "world", timestamp: 2, status: "received" },
      { v: 1, type: "contact", px_id: "px_x", name: "Alice", ik_ed25519: "", ik_x25519: "", verified: "123 456" },
    ];
    const { a, b } = relay();

    let sasA = "";
    let sasB = "";
    let qrResolve!: (q: QrPayload) => void;
    const qrP = new Promise<QrPayload>((r) => (qrResolve = r));

    const ex = runExport(a, "rid", { onQr: (q) => qrResolve(q), onSas: (s) => (sasA = s) }, wasmCrypto);
    const qr = await qrP;
    const im = runImport(b, qr, { onSas: (s) => (sasB = s) }, wasmCrypto);

    // Simulate both users confirming the matching SAS.
    ex.confirm();
    im.confirm();

    const [sent, got] = await Promise.all([ex.done, im.done]);
    expect(sent).toBe(3);
    expect(got).toBe(3);
    expect(hoist.recorded).toEqual(hoist.source); // exact records, in order
    expect(sasA).toBe(sasB);
    expect(sasA).toMatch(/^\d{6}$/);
  });

  it("aborts when a MITM swaps the exporter key (SAS differs, channel won't open)", async () => {
    hoist.source = [
      { v: 1, type: "message", msg_id: "a", peer_id: "px_x", direction: "out", kind: "text", content: "secret", timestamp: 1, status: "sent" },
    ];
    const { a, b } = relay();

    let sasA = "";
    let sasB = "";
    let qrResolve!: (q: QrPayload) => void;
    const qrP = new Promise<QrPayload>((r) => (qrResolve = r));

    const ex = runExport(a, "rid", { onQr: (q) => qrResolve(q), onSas: (s) => (sasA = s) }, wasmCrypto);
    const realQr = await qrP;
    // Tamper the exporter pubkey the importer sees (relay MITM).
    const tampered: QrPayload = { ...realQr, pk: (realQr.pk[0] === "0" ? "1" : "0") + realQr.pk.slice(1) };
    const im = runImport(b, tampered, { onSas: (s) => (sasB = s) }, wasmCrypto);

    ex.done.catch(() => {}); // both sides fail; swallow to avoid an unhandled rejection
    ex.confirm();
    im.confirm();

    await expect(im.done).rejects.toThrow();
    expect(hoist.recorded).toHaveLength(0); // nothing imported
    expect(sasA).not.toBe(sasB); // the human check would have caught it too
  });
});
