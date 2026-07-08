import { describe, expect, it } from "vitest";
import { PrivexDB } from "../db/index";
import { EncryptedMessages } from "../db/encrypted-db";

function testKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

describe("encrypted IndexedDB", () => {
  it("round-trips a message across close/reopen and stores no plaintext", async () => {
    const key = await testKey();
    const secret = "the eagle lands at midnight";
    const dbName = `privex-test-${Math.random().toString(36).slice(2)}`;

    // write (content is encrypted before it ever reaches IndexedDB)
    const db1 = new PrivexDB(dbName);
    await new EncryptedMessages(db1, Promise.resolve(key)).add({
      msg_id: "m1",
      session_id: "s1",
      content: secret,
      timestamp: 1,
      created_at: 1000,
      status: "sent",
      direction: "out",
      kind: "text",
    });

    // the raw stored row holds ciphertext only - no plaintext, no `content` field
    const raw = await db1.messages.get("m1");
    expect(raw?.content_enc).toBeInstanceOf(Uint8Array);
    expect((raw as unknown as { content?: string }).content).toBeUndefined();
    expect(JSON.stringify(raw)).not.toContain(secret);
    db1.close();

    // reopen the same DB → decrypt back to the original plaintext
    const db2 = new PrivexDB(dbName);
    const msg = await new EncryptedMessages(db2, Promise.resolve(key)).get("m1");
    expect(msg?.content).toBe(secret);
    db2.close();
  });
});
