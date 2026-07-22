import { describe, expect, it } from "vitest";
import { parseScannedPxId } from "../services/qr";

const VALID = "px_" + "a".repeat(32);

describe("parseScannedPxId (scan injection boundary)", () => {
  it("accepts an exact px_id", () => {
    expect(parseScannedPxId(VALID)).toBe(VALID);
  });

  it("trims surrounding whitespace/newlines a QR may carry", () => {
    expect(parseScannedPxId(`  ${VALID}\n`)).toBe(VALID);
  });

  it("rejects the wrong shape", () => {
    expect(parseScannedPxId("px_short")).toBeNull();
    expect(parseScannedPxId("px_" + "a".repeat(31))).toBeNull(); // too short
    expect(parseScannedPxId("px_" + "a".repeat(33))).toBeNull(); // too long
    expect(parseScannedPxId("px_" + "A".repeat(32))).toBeNull(); // uppercase hex
    expect(parseScannedPxId("px_" + "g".repeat(32))).toBeNull(); // non-hex
  });

  it("rejects wrapped / injection-shaped payloads", () => {
    expect(parseScannedPxId(`https://privex.chat/add?id=${VALID}`)).toBeNull();
    expect(parseScannedPxId(`<img src=x onerror=alert(1)>`)).toBeNull();
    expect(parseScannedPxId(`javascript:alert(1)`)).toBeNull();
    expect(parseScannedPxId(`data:text/html,${VALID}`)).toBeNull();
    expect(parseScannedPxId(`${VALID} ${VALID}`)).toBeNull();
  });

  it("rejects non-strings and pathological length without scanning it", () => {
    expect(parseScannedPxId(null)).toBeNull();
    expect(parseScannedPxId(undefined)).toBeNull();
    expect(parseScannedPxId(12345 as unknown)).toBeNull();
    expect(parseScannedPxId("x".repeat(5_000_000))).toBeNull();
  });
});
