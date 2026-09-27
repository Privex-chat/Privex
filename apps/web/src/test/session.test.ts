// On-device session actions: locking tears the live session down; erasing wipes
// everything local without contacting the server.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef, wipeSpy, lockNowSpy } = vi.hoisted(() => ({
  keyRef: { key: null as CryptoKey | null },
  wipeSpy: { called: 0 },
  lockNowSpy: { called: 0 },
}));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
  wipeKeystore: async () => {
    wipeSpy.called += 1;
  },
  lockNow: () => {
    lockNowSpy.called += 1;
  },
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle } from "../crypto/onboarding-crypto";
import { persistGeneratedIdentity, finalizeIdentity } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import { eraseThisDevice, lockApp } from "../services/session";
import * as ws from "../services/websocket";
import * as cover from "../services/cover-traffic";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
});

beforeEach(async () => {
  await Promise.all([
    db.identity.clear(),
    db.settings.clear(),
    db.messages.clear(),
    db.contacts.clear(),
    db.sessions.clear(),
  ]);
  wipeSpy.called = 0;
  lockNowSpy.called = 0;
  useAuth.setState({ sessionToken: null, userId: null, authenticated: false });
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

describe("app lock teardown", () => {
  it("lockApp drops the key AND the live session (WS, cover traffic, token)", () => {
    useAuth.getState().setSession("live-token", "px_" + "aa".repeat(16));
    useAuth.getState().setAuthenticated("px_" + "aa".repeat(16));
    expect(useAuth.getState().authenticated).toBe(true);

    const disc = vi.spyOn(ws, "disconnectWebSocket").mockImplementation(() => {});
    const stopCover = vi.spyOn(cover, "stopCoverTraffic").mockImplementation(() => {});

    lockApp();

    expect(lockNowSpy.called).toBe(1); // in-memory data key dropped
    expect(disc).toHaveBeenCalled(); // WebSocket torn down
    expect(stopCover).toHaveBeenCalled(); // cover traffic stopped
    // Session dropped → the App WS effect can't reconnect while locked, and outbox
    // flush (gated on `authenticated`) stays inert.
    expect(useAuth.getState().authenticated).toBe(false);
    expect(useAuth.getState().sessionToken).toBe(null);

    disc.mockRestore();
    stopCover.mockRestore();
  });
});

describe("erase this device (16E follow-up)", () => {
  it("wipes ALL local data + keystore, signs out, and never touches the network", async () => {
    const me = genIdentityBundle(wasm, entropy(0x41));
    await persistGeneratedIdentity(me);
    await finalizeIdentity(me);
    useAuth.getState().setSession("tok", me.userId);

    // Seed data across several stores.
    await new EncryptedMessages(db).add({
      msg_id: "m1",
      session_id: "px_" + "aa".repeat(16),
      content: "secret",
      timestamp: 1,
      created_at: 1000,
      status: "sent",
      direction: "out",
      kind: "text",
    });
    await db.contacts.put({ px_id: "px_" + "aa".repeat(16), added_at: 1 });
    await db.settings.put({ key: "some-flag", value: true });
    expect(await db.identity.count()).toBe(1);
    expect(await db.messages.count()).toBe(1);

    // Any network call during erase would be a bug (nothing to tell the server).
    const anyFetch = vi.spyOn(globalThis, "fetch");

    await eraseThisDevice();

    // Every local store is empty.
    for (const t of db.tables) {
      expect(await t.count()).toBe(0);
    }
    // Keystore wiped + auth dropped.
    expect(wipeSpy.called).toBe(1);
    expect(useAuth.getState().authenticated).toBe(false);
    expect(useAuth.getState().sessionToken).toBe(null);
    // No server contact.
    expect(anyFetch).not.toHaveBeenCalled();
    anyFetch.mockRestore();
  });
});
