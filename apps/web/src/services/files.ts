// File encryption + upload/download (docs 4.7). Bulk chunk crypto is Web Crypto
// (AES-256-GCM + HKDF + SHA-256) - fast, native, no megabytes through the worker.
// The CEK is wrapped for the recipient in wasm (X25519 + XChaCha20). The manifest
// (FileMessage) rides the normal Sealed Sender channel; only random-looking
// encrypted chunks ever hit the blob store.
import * as api from "../api/client";
import { cryptoCall } from "../workers/crypto-client";
import { useAuth } from "../store/auth";
import { fromHex, toHex } from "../crypto/onboarding-crypto";
import type { WrappedCek } from "../crypto/file-crypto";
import type { FileFields } from "./envelope";
import { b64encode, src } from "./bytes";

export const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB (docs 4.7)
const IV_LEN = 12;

// What we persist locally (encrypted at rest) per file message: enough to render
// + re-download. `cek` is the raw key (the recipient unwraps it once on receive).
export interface FileMeta {
  name: string;
  mime: string;
  size: number;
  sha256: string; // hex of the plaintext file
  chunks: string[]; // chunk_ids, in order
  cek: string; // hex
  thumb?: string; // data URL, image previews only
}

// --- crypto API (worker-backed; injectable for tests) ---

export interface FileCryptoApi {
  generateCek(): Promise<Uint8Array>;
  wrapCek(cek: Uint8Array, recipientIkPub: Uint8Array): Promise<WrappedCek>;
  unwrapCek(wrapped: Uint8Array, ephPub: Uint8Array, myIkPriv: Uint8Array): Promise<Uint8Array>;
}

export const workerFileCrypto: FileCryptoApi = {
  generateCek: () => cryptoCall("generate_cek", []),
  wrapCek: (cek, r) => cryptoCall("wrap_cek", [cek, r]),
  unwrapCek: (w, e, p) => cryptoCall("unwrap_cek", [w, e, p]),
};

function token(): string {
  const t = useAuth.getState().sessionToken;
  if (!t) throw new Error("not authenticated");
  return t;
}

// --- Web Crypto key derivation ---

async function chunkKey(cek: Uint8Array, i: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", src(cek), "HKDF", false, ["deriveKey"]);
  const info = new Uint8Array(9); // "chunk" (5) || uint32 big-endian (4)
  info.set(new TextEncoder().encode("chunk"), 0);
  new DataView(info.buffer).setUint32(5, i, false);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function metaKey(cek: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", src(cek), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("file_meta") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function gcmEncrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: src(iv) }, key, src(data)));
  const out = new Uint8Array(IV_LEN + ct.length);
  out.set(iv, 0);
  out.set(ct, IV_LEN);
  return out;
}

async function gcmDecrypt(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  const iv = blob.subarray(0, IV_LEN);
  const ct = blob.subarray(IV_LEN);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: src(iv) }, key, src(ct)));
}

async function sha256hex(data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", src(data))));
}

async function encMeta(cek: Uint8Array, text: string): Promise<Uint8Array> {
  return gcmEncrypt(await metaKey(cek), new TextEncoder().encode(text));
}
async function decMeta(cek: Uint8Array, bytes: Uint8Array): Promise<string> {
  return new TextDecoder().decode(await gcmDecrypt(await metaKey(cek), bytes));
}

// --- testable cores (no network) ---

export interface EncryptedChunk {
  chunkId: string; // hex SHA-256 of the uploaded blob
  blob: Uint8Array; // iv || AES-256-GCM(chunk)
}

/** Split + encrypt a file (docs 4.7 step 2). chunk_i key = HKDF(CEK,"chunk"||i). */
export async function encryptFile(
  buf: Uint8Array,
  cek: Uint8Array,
): Promise<{ chunks: EncryptedChunk[]; sha256: string }> {
  const sha256 = await sha256hex(buf);
  const chunks: EncryptedChunk[] = [];
  const n = Math.max(1, Math.ceil(buf.length / CHUNK_SIZE));
  for (let i = 0; i < n; i++) {
    const part = buf.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    const blob = await gcmEncrypt(await chunkKey(cek, i), part);
    chunks.push({ chunkId: await sha256hex(blob), blob });
  }
  return { chunks, sha256 };
}

/** Decrypt ordered chunk blobs, reassemble, verify the plaintext SHA-256 (docs
 *  4.7 receive steps 4-5). Throws on a hash mismatch (tampering). */
export async function reassembleAndVerify(
  blobs: Uint8Array[],
  cek: Uint8Array,
  sha256Hex: string,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let i = 0; i < blobs.length; i++) {
    const pt = await gcmDecrypt(await chunkKey(cek, i), blobs[i]);
    parts.push(pt);
    total += pt.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  if ((await sha256hex(out)) !== sha256Hex) {
    throw new Error("File integrity check failed - the download was tampered with.");
  }
  return out;
}

// --- thumbnails (browser only) ---

async function makeThumbnail(file: File): Promise<Uint8Array | undefined> {
  if (!file.type.startsWith("image/") || typeof createImageBitmap === "undefined") return undefined;
  try {
    const bmp = await createImageBitmap(file);
    const scale = Math.min(1, 320 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    canvas.getContext("2d")?.drawImage(bmp, 0, 0, w, h);
    const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/jpeg", 0.7));
    if (!blob) return undefined;
    return new Uint8Array(await blob.arrayBuffer());
  } catch {
    return undefined; // preview is best-effort; never block the upload
  }
}

const dataUrl = (bytes: Uint8Array, mime: string) => `data:${mime};base64,${b64encode(bytes)}`;

// --- orchestrators (network) ---

/** Encrypt + upload all chunks, build the FileMessage wire fields + the local
 *  FileMeta. Does NOT send the manifest - messaging.sendFile does that. */
export async function encryptAndUpload(
  file: File,
  recipientIkX25519: Uint8Array,
  onProgress?: (done: number, total: number) => void,
  fileCrypto: FileCryptoApi = workerFileCrypto,
): Promise<{ fields: FileFields; meta: FileMeta }> {
  const buf = new Uint8Array(await file.arrayBuffer());
  const cek = await fileCrypto.generateCek();
  const { chunks, sha256 } = await encryptFile(buf, cek);

  const tok = token();
  for (let i = 0; i < chunks.length; i++) {
    await api.putBlob(chunks[i].chunkId, chunks[i].blob, tok);
    onProgress?.(i + 1, chunks.length);
  }

  const mime = file.type || "application/octet-stream";
  const thumbBytes = await makeThumbnail(file);
  const wrapped = await fileCrypto.wrapCek(cek, recipientIkX25519);

  const fields: FileFields = {
    filenameEnc: await encMeta(cek, file.name),
    mimeEnc: await encMeta(cek, mime),
    totalSize: buf.length,
    sha256: fromHex(sha256),
    chunkIds: chunks.map((c) => c.chunkId),
    wrappedCek: wrapped.wrapped,
    ephPub: wrapped.ephPub,
    thumbnailEnc: thumbBytes ? await gcmEncrypt(await metaKey(cek), thumbBytes) : undefined,
    sentAt: Math.floor(Date.now() / 1000),
  };
  const meta: FileMeta = {
    name: file.name,
    mime,
    size: buf.length,
    sha256,
    chunks: fields.chunkIds,
    cek: toHex(cek),
    thumb: thumbBytes ? dataUrl(thumbBytes, "image/jpeg") : undefined,
  };
  return { fields, meta };
}

/** Receiver side: unwrap the CEK, decrypt the display metadata + thumbnail, and
 *  produce the local FileMeta (download happens later on demand). */
export async function materializeIncoming(
  f: FileFields,
  myIkX25519Priv: Uint8Array,
  fileCrypto: FileCryptoApi = workerFileCrypto,
): Promise<FileMeta> {
  const cek = await fileCrypto.unwrapCek(f.wrappedCek, f.ephPub, myIkX25519Priv);
  const mime = await decMeta(cek, f.mimeEnc);
  let thumb: string | undefined;
  if (f.thumbnailEnc) {
    const bytes = await gcmDecrypt(await metaKey(cek), f.thumbnailEnc);
    thumb = dataUrl(bytes, "image/jpeg");
  }
  return {
    name: await decMeta(cek, f.filenameEnc),
    mime,
    size: f.totalSize,
    sha256: toHex(f.sha256),
    chunks: f.chunkIds,
    cek: toHex(cek),
    thumb,
  };
}

/** Download all chunks, decrypt, verify integrity, return a Blob for the browser
 *  to save (docs 4.7 receive). */
export async function downloadAndDecrypt(
  meta: FileMeta,
  onProgress?: (done: number, total: number) => void,
): Promise<Blob> {
  const tok = token();
  const blobs: Uint8Array[] = [];
  for (let i = 0; i < meta.chunks.length; i++) {
    blobs.push(await api.getBlob(meta.chunks[i], tok));
    onProgress?.(i + 1, meta.chunks.length);
  }
  const bytes = await reassembleAndVerify(blobs, fromHex(meta.cek), meta.sha256);
  return new Blob([src(bytes)], { type: meta.mime });
}
