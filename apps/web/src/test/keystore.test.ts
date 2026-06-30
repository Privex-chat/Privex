import { describe, expect, it } from "vitest";

describe("master key", () => {
  it("is AES-GCM and non-extractable - exportKey must fail", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
  });
});
