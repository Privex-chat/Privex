// The single gate between arbitrary, attacker-controlled QR/image content and the
// add-contact pipeline. A scanned QR (camera OR a gallery image) can decode to
// ANYTHING - a URL, HTML, a huge blob, a look-alike id. parseScannedPxId returns
// a value ONLY when the payload is exactly a Privex ID; everything else is null.
//
// The returned string must be treated as the only trusted output: it flows into
// React state and addContact() (which validates again). The raw decoded text must
// never reach innerHTML, an href, a URL param, or eval.
import { isValidPxId } from "../crypto/contact-crypto";

// "px_" + 32 hex = 35 chars. Our own QR (MyQr) encodes exactly this raw string.
const PX_ID_LEN = 35;

/** Validate a decoded QR payload as a Privex ID. Trims surrounding whitespace,
 *  caps length before the regex (so a pathological multi-MB decode can't do work),
 *  and returns the normalized px_id or null. */
export function parseScannedPxId(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (s.length !== PX_ID_LEN) return null;
  return isValidPxId(s) ? s : null;
}
