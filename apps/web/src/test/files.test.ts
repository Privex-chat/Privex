import { describe, expect, it } from "vitest";
import { CHUNK_SIZE, encryptFile, reassembleAndVerify } from "../services/files";
import { decodeContent, encodeFile, type FileFields } from "../services/envelope";
import { toHex } from "../crypto/onboarding-crypto";
import { src } from "../services/bytes";

const cek = () => crypto.getRandomValues(new Uint8Array(32));

describe("file chunk crypto (docs 4.7)", () => {
  it("encrypts → uploads (content-addressed) → reassembles + verifies a multi-chunk file", async () => {
    const key = cek();
    // ~2 chunks so chunk indexing (HKDF "chunk"||i) is exercised.
    const original = new Uint8Array(CHUNK_SIZE + 4096);
    for (let i = 0; i < original.length; i++) original[i] = (i * 31) & 0xff;

    const { chunks, sha256 } = await encryptFile(original, key);
    expect(chunks.length).toBe(2);
    // chunk_id is the SHA-256 of the encrypted blob (server enforces this).
    for (const c of chunks) {
      const id = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", src(c.blob))));
      expect(c.chunkId).toBe(id);
      expect(c.chunkId).toMatch(/^[0-9a-f]{64}$/);
    }

    const back = await reassembleAndVerify(chunks.map((c) => c.blob), key, sha256);
    expect(toHex(back)).toBe(toHex(original));
  });

  it("handles a single small chunk", async () => {
    const key = cek();
    const original = new TextEncoder().encode("a tiny secret file");
    const { chunks, sha256 } = await encryptFile(original, key);
    expect(chunks.length).toBe(1);
    const back = await reassembleAndVerify([chunks[0].blob], key, sha256);
    expect(new TextDecoder().decode(back)).toBe("a tiny secret file");
  });

  it("rejects a tampered chunk (integrity/AEAD failure)", async () => {
    const key = cek();
    const original = new Uint8Array(2048).fill(7);
    const { chunks, sha256 } = await encryptFile(original, key);
    const tampered = new Uint8Array(chunks[0].blob);
    tampered[tampered.length - 1] ^= 0xff; // flip a ciphertext byte
    await expect(reassembleAndVerify([tampered], key, sha256)).rejects.toThrow();
  });

  it("rejects when the plaintext hash doesn't match the manifest", async () => {
    const key = cek();
    const { chunks } = await encryptFile(new Uint8Array(100).fill(3), key);
    // A wrong (but well-formed) expected hash → integrity check fails.
    await expect(reassembleAndVerify(chunks.map((c) => c.blob), key, "00".repeat(32))).rejects.toThrow(
      /integrity/i,
    );
  });
});

describe("file manifest protobuf", () => {
  it("round-trips a FileMessage through Content", () => {
    const fields: FileFields = {
      filenameEnc: new Uint8Array([1, 2, 3]),
      mimeEnc: new Uint8Array([4, 5]),
      totalSize: 123456,
      sha256: new Uint8Array(32).fill(9),
      chunkIds: ["aa".repeat(32), "bb".repeat(32)],
      wrappedCek: new Uint8Array(40).fill(1),
      ephPub: new Uint8Array(32).fill(2),
      thumbnailEnc: new Uint8Array([7, 7, 7]),
      sentAt: 1_900_000_000,
    };
    const decoded = decodeContent(encodeFile(fields));
    expect(decoded.text).toBeUndefined();
    const f = decoded.file!;
    expect(f.totalSize).toBe(123456);
    expect(f.chunkIds).toEqual(fields.chunkIds);
    expect(toHex(f.sha256)).toBe(toHex(fields.sha256));
    expect(toHex(f.wrappedCek)).toBe(toHex(fields.wrappedCek));
    expect(toHex(f.ephPub)).toBe(toHex(fields.ephPub));
    expect(f.thumbnailEnc && toHex(f.thumbnailEnc)).toBe(toHex(fields.thumbnailEnc!));
    expect(f.sentAt).toBe(1_900_000_000);
  });

  it("omits the thumbnail when absent", () => {
    const fields: FileFields = {
      filenameEnc: new Uint8Array([1]),
      mimeEnc: new Uint8Array([2]),
      totalSize: 10,
      sha256: new Uint8Array(32),
      chunkIds: ["cc".repeat(32)],
      wrappedCek: new Uint8Array(40),
      ephPub: new Uint8Array(32),
      sentAt: 100,
    };
    expect(decodeContent(encodeFile(fields)).file?.thumbnailEnc).toBeUndefined();
  });
});
