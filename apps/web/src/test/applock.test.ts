// Cryptographic app lock: enabling re-keys local data behind the passphrase, the
// in-memory key is forgotten on lock, and only the correct passphrase unwraps it.
// idb-keyval is mocked to an in-memory map (Node can't structured-clone a CryptoKey
// into fake-indexeddb); the Argon2id KDF runs in real wasm with tiny cost for speed.
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { store } = vi.hoisted(() => ({ store: new Map<string, unknown>() }));
vi.mock("idb-keyval", () => ({
  get: async (k: string) => store.get(k),
  set: async (k: string, v: unknown) => void store.set(k, v),
  del: async (k: string) => void store.delete(k),
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { db } from "../db";
import { EncryptedMessages } from "../db/encrypted-db";
import { getMasterKey, isUnlocked } from "../crypto/keystore";
import {
  disableLock,
  enableWithPassphrase,
  lock,
  lockStatus,
  unlockWithPassphrase,
  type AppLockKdf,
} from "../services/applock";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
});

// Tiny Argon2 cost keeps the test fast; correctness of the wrap/unwrap is what we
// test here (the real cost is exercised by the crypto-wasm cargo test).
const fastKdf: AppLockKdf = {
  argon2id: async (p, s) => wasm.applock_derive_key(p, s, 64, 1),
};

const PASS = "correct horse battery";

beforeEach(async () => {
  store.clear();
  await db.messages.clear();
  lock(); // clear any in-memory key between tests
});
afterEach(() => lock());

async function addMessage(id: string, body: string) {
  await new EncryptedMessages(db).add({
    msg_id: id,
    session_id: "px_x",
    content: body,
    timestamp: 1,
    status: "sent",
    direction: "out",
    kind: "text",
  });
}
const readMessage = (id: string) => new EncryptedMessages(db).get(id).then((m) => m?.content);

describe("cryptographic app lock", () => {
  it("re-keys data on enable, gates the key on lock, and unlocks with the passphrase", async () => {
    await addMessage("a", "hello"); // encrypted under the no-lock key
    expect((await lockStatus()).enabled).toBe(false);

    await enableWithPassphrase(PASS, fastKdf);
    const st = await lockStatus();
    expect(st.enabled).toBe(true);
    expect(st.passphrase).toBe(true);
    expect(isUnlocked()).toBe(true);
    expect(await readMessage("a")).toBe("hello"); // re-key preserved the data

    // Lock → the key is gone; nothing can read at-rest data.
    lock();
    expect(isUnlocked()).toBe(false);
    await expect(getMasterKey()).rejects.toThrow(/locked/);

    // Wrong passphrase fails; correct one restores access.
    await expect(unlockWithPassphrase("nope nope nope", fastKdf)).rejects.toThrow(/[Ww]rong/);
    await unlockWithPassphrase(PASS, fastKdf);
    expect(isUnlocked()).toBe(true);
    expect(await readMessage("a")).toBe("hello");
  });

  it("disabling restores an auto-available key without re-encrypting", async () => {
    await addMessage("b", "world");
    await enableWithPassphrase(PASS, fastKdf);
    await disableLock();
    expect((await lockStatus()).enabled).toBe(false);
    // No lock + still unlocked in-memory → readable, and a reload (no meta) would
    // auto-open via the restored handle.
    expect(await readMessage("b")).toBe("world");
  });
});
