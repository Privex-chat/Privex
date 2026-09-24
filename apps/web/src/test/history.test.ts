// History backup (Option A): backfill → restore round-trip on a "new device", and
// the live hook is a no-op while backup is disabled. Uses a fake in-memory server
// (api spies) + the real history_key crypto over fake-indexeddb.
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle } from "../crypto/onboarding-crypto";
import { persistGeneratedIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { getContact, setDisplayName, setVerified, upsertInboundContact } from "../data/contacts";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import {
  backfillAll,
  backupMessage,
  enableBackup,
  isBackupEnabled,
  migrateBackupIds,
  resetHistoryBackup,
  restoreHistory,
} from "../services/history-backup";
import { deriveHistoryIdKey, historyBlobId } from "../crypto/history-crypto";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

// Fake server: blob_id -> { ciphertext, created_at }.
let server: Map<string, { ciphertext: string; created_at: number }>;
let ctr: number;

beforeEach(async () => {
  await db.messages.clear();
  await db.contacts.clear();
  await db.identity.clear();
  await db.settings.clear();
  resetHistoryBackup();
  server = new Map();
  ctr = 0;
  vi.spyOn(api, "uploadHistory").mockImplementation(async (blobs) => {
    for (const b of blobs) server.set(b.blob_id, { ciphertext: b.ciphertext, created_at: ctr++ });
    return { stored: blobs.length };
  });
  vi.spyOn(api, "listHistory").mockImplementation(async () => ({
    blobs: [...server.entries()]
      .sort((a, b) => a[1].created_at - b[1].created_at)
      .map(([blob_id, v]) => ({ blob_id, ciphertext: v.ciphertext, created_at: v.created_at })),
    next: null,
  }));
  vi.spyOn(api, "historyStatus").mockImplementation(async () => ({ count: server.size, bytes: 0 }));
  vi.spyOn(api, "deleteHistory").mockImplementation(async () => {
    const n = server.size;
    server.clear();
    return { deleted: n };
  });
});

afterEach(() => vi.restoreAllMocks());

describe("history backup (Option A)", () => {
  it("backfills then restores messages + contacts on a fresh device", async () => {
    const me = genIdentityBundle(wasm, entropy(0x71));
    const peer = genIdentityBundle(wasm, entropy(0x72));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("tok", me.userId);

    // Seed a contact (name + verified) and two messages.
    await upsertInboundContact(peer.userId, peer.identity.ed25519_pub, peer.identity.x25519_pub);
    await setDisplayName(peer.userId, "Alice");
    await setVerified(peer.userId, "12345 67890");
    const msgs = new EncryptedMessages(db);
    await msgs.add({ msg_id: "a", session_id: peer.userId, content: "hello", timestamp: 1, created_at: 1000, status: "sent", direction: "out", kind: "text" });
    await msgs.add({ msg_id: "b", session_id: peer.userId, content: "world", timestamp: 2, created_at: 1001, status: "received", direction: "in", kind: "text" });

    await enableBackup();
    expect(server.size).toBe(3); // 2 messages + 1 contact sidecar

    // Simulate a fresh device: wipe local messages + contacts (identity stays).
    await db.messages.clear();
    await db.contacts.clear();

    const restored = await restoreHistory();
    expect(restored).toBe(3);

    const got = await new EncryptedMessages(db).listBySession(peer.userId);
    expect(got.map((m) => m.content)).toEqual(["hello", "world"]);
    expect(got.map((m) => m.direction)).toEqual(["out", "in"]);

    const c = await getContact(peer.userId);
    expect(c?.name).toBe("Alice");
    expect(c?.verified).toBe(true);
  });

  it("names blobs with opaque ids: no contact px_id or message id reaches the server", async () => {
    const me = genIdentityBundle(wasm, entropy(0x74));
    const peer = genIdentityBundle(wasm, entropy(0x75));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("tok", me.userId);
    await upsertInboundContact(peer.userId, peer.identity.ed25519_pub, peer.identity.x25519_pub);
    await new EncryptedMessages(db).add({ msg_id: "msg-1", session_id: peer.userId, content: "hi", timestamp: 1, created_at: 1, status: "sent", direction: "out", kind: "text" });

    await enableBackup();
    const ids = [...server.keys()];
    expect(ids).toHaveLength(2);
    for (const id of ids) {
      expect(id).toMatch(/^[0-9a-f]{64}$/);
      expect(id).not.toContain(peer.userId.slice(3)); // no readable contact id
    }
    expect(ids).not.toContain("msg-1");

    // Stable ids: a second backfill overwrites instead of duplicating.
    await backfillAll();
    expect(server.size).toBe(2);
  });

  it("opaque ids depend on the user's seed (another user can't compute them)", async () => {
    const a = await deriveHistoryIdKey(entropy(0x01));
    const b = await deriveHistoryIdKey(entropy(0x02));
    const rec = "contact:px_00000000000000000000000000000001";
    expect(await historyBlobId(a, rec)).toBe(await historyBlobId(a, rec));
    expect(await historyBlobId(a, rec)).not.toBe(await historyBlobId(b, rec));
  });

  it("re-uploads an existing backup under opaque ids once per device", async () => {
    const me = genIdentityBundle(wasm, entropy(0x76));
    const peer = genIdentityBundle(wasm, entropy(0x77));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("tok", me.userId);
    await upsertInboundContact(peer.userId, peer.identity.ed25519_pub, peer.identity.x25519_pub);
    // Backup was enabled by an older build (flag set, ids not yet migrated).
    await db.settings.put({ key: "history_backup", value: true });

    await migrateBackupIds();
    expect(api.uploadHistory).toHaveBeenCalledTimes(1);
    expect([...server.keys()].every((id) => /^[0-9a-f]{64}$/.test(id))).toBe(true);
    expect(server.size).toBe(1); // the contact sidecar is back, under an opaque id

    await migrateBackupIds(); // already done → no-op
    expect(api.uploadHistory).toHaveBeenCalledTimes(1);
  });

  it("the live hook does nothing while backup is disabled", async () => {
    const me = genIdentityBundle(wasm, entropy(0x73));
    await persistGeneratedIdentity(me);
    useAuth.getState().setSession("tok", me.userId);

    expect(await isBackupEnabled()).toBe(false);
    await backupMessage({ msg_id: "x", session_id: "px_peer", content: "hi", timestamp: 1, status: "sent", direction: "out", kind: "text" });
    expect(api.uploadHistory).not.toHaveBeenCalled();
    expect(server.size).toBe(0);
  });
});
