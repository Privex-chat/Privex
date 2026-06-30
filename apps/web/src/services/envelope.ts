// Protobuf encode/decode for the message wire format (docs 4.4/4.5). Two layers:
//   - Content{ text: TextMessage } - the plaintext the Double Ratchet encrypts.
//   - MessageEnvelope{ ratchet_header, ratchet_ciphertext, pqxdh? } - the payload
//     Sealed Sender wraps. The ratchet header is opaque (wasm-internal bincode).
import { proto } from "@privex/protocol";

const toNum = (v: number | { toNumber(): number } | null | undefined): number =>
  v == null ? 0 : typeof v === "number" ? v : v.toNumber();

const u8 = (v: Uint8Array | null | undefined): Uint8Array => v ?? new Uint8Array(0);

// --- plaintext (Content / TextMessage) ---

export function encodeText(body: string, sentAt: number): Uint8Array {
  return proto.privex.Content.encode({ text: { body, sentAt } }).finish();
}

/** Silent contact announcement (auto-add). No visible message body. */
export function encodeContactHello(sentAt: number): Uint8Array {
  return proto.privex.Content.encode({ contactHello: { sentAt } }).finish();
}

export interface DecodedText {
  body: string;
  sentAt: number;
}

export function decodeText(bytes: Uint8Array): DecodedText {
  const t = proto.privex.Content.decode(bytes).text;
  if (!t) throw new Error("message is not a text message");
  return { body: t.body ?? "", sentAt: toNum(t.sentAt) };
}

// --- file content (Content / FileMessage, docs 4.7) ---

export interface FileFields {
  filenameEnc: Uint8Array;
  mimeEnc: Uint8Array;
  totalSize: number;
  sha256: Uint8Array;
  chunkIds: string[];
  wrappedCek: Uint8Array;
  ephPub: Uint8Array;
  thumbnailEnc?: Uint8Array; // empty if none
  sentAt: number;
}

export function encodeFile(f: FileFields): Uint8Array {
  return proto.privex.Content.encode({
    file: {
      filenameEncrypted: f.filenameEnc,
      mimeTypeEncrypted: f.mimeEnc,
      totalSize: f.totalSize,
      sha256Plaintext: f.sha256,
      chunkIds: f.chunkIds,
      wrappedCek: f.wrappedCek,
      cekEphPub: f.ephPub,
      thumbnailEncrypted: f.thumbnailEnc ?? new Uint8Array(0),
      sentAt: f.sentAt,
    },
  }).finish();
}

/** Decode a plaintext Content into exactly one variant we handle. */
export function decodeContent(
  bytes: Uint8Array,
): { text?: DecodedText; file?: FileFields; contactHello?: boolean } {
  const c = proto.privex.Content.decode(bytes);
  if (c.contactHello) return { contactHello: true };
  if (c.text) return { text: { body: c.text.body ?? "", sentAt: toNum(c.text.sentAt) } };
  if (c.file) {
    const f = c.file;
    return {
      file: {
        filenameEnc: u8(f.filenameEncrypted),
        mimeEnc: u8(f.mimeTypeEncrypted),
        totalSize: toNum(f.totalSize),
        sha256: u8(f.sha256Plaintext),
        chunkIds: f.chunkIds ?? [],
        wrappedCek: u8(f.wrappedCek),
        ephPub: u8(f.cekEphPub),
        thumbnailEnc: f.thumbnailEncrypted && f.thumbnailEncrypted.length > 0 ? u8(f.thumbnailEncrypted) : undefined,
        sentAt: toNum(f.sentAt),
      },
    };
  }
  return {};
}

// --- transport envelope (MessageEnvelope) ---

export interface PqxdhInitWire {
  alice_ik_pub: Uint8Array;
  alice_ek_pub: Uint8Array;
  kyber_ciphertext: Uint8Array;
  opk_used: boolean;
  opk_id: number;
}

export function encodeEnvelope(
  header: Uint8Array,
  ciphertext: Uint8Array,
  pqxdh?: PqxdhInitWire,
): Uint8Array {
  return proto.privex.MessageEnvelope.encode({
    ratchetHeader: header,
    ratchetCiphertext: ciphertext,
    pqxdh: pqxdh
      ? {
          aliceIkPub: pqxdh.alice_ik_pub,
          aliceEkPub: pqxdh.alice_ek_pub,
          kyberCiphertext: pqxdh.kyber_ciphertext,
          opkUsed: pqxdh.opk_used,
          opkId: pqxdh.opk_id,
        }
      : null,
  }).finish();
}

export interface DecodedEnvelope {
  header: Uint8Array;
  ciphertext: Uint8Array;
  pqxdh?: PqxdhInitWire;
}

export function decodeEnvelope(bytes: Uint8Array): DecodedEnvelope {
  const e = proto.privex.MessageEnvelope.decode(bytes);
  const out: DecodedEnvelope = { header: u8(e.ratchetHeader), ciphertext: u8(e.ratchetCiphertext) };
  if (e.pqxdh) {
    out.pqxdh = {
      alice_ik_pub: u8(e.pqxdh.aliceIkPub),
      alice_ek_pub: u8(e.pqxdh.aliceEkPub),
      kyber_ciphertext: u8(e.pqxdh.kyberCiphertext),
      opk_used: !!e.pqxdh.opkUsed,
      opk_id: e.pqxdh.opkId ?? 0,
    };
  }
  return out;
}
