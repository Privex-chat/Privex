// Announcement banner shape validation (PVX-26): a malformed JSON file must be
// rejected (returns null) rather than throwing at banner render.
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchAnnouncement } from "../services/announcement";

function mockFetch(body: unknown, ok = true): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok, json: async () => body })) as unknown as typeof fetch,
  );
}

describe("announcement validation", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("accepts a well-formed announcement", async () => {
    mockFetch({ version: 3, message: "Scheduled maintenance", severity: "warning", dismissible: true });
    expect(await fetchAnnouncement()).toEqual({
      version: 3,
      message: "Scheduled maintenance",
      severity: "warning",
      dismissible: true,
    });
  });

  it("rejects a non-string message (would throw at render)", async () => {
    mockFetch({ version: 1, message: { nested: "oops" }, severity: "info", dismissible: false });
    expect(await fetchAnnouncement()).toBeNull();
  });

  it("rejects an unknown severity", async () => {
    mockFetch({ version: 1, message: "hi", severity: "critical", dismissible: false });
    expect(await fetchAnnouncement()).toBeNull();
  });

  it("rejects a missing/!boolean dismissible and a non-number version", async () => {
    mockFetch({ version: "1", message: "hi", severity: "info", dismissible: true });
    expect(await fetchAnnouncement()).toBeNull();
    mockFetch({ version: 1, message: "hi", severity: "info" });
    expect(await fetchAnnouncement()).toBeNull();
  });

  it("rejects an over-long message", async () => {
    mockFetch({ version: 1, message: "x".repeat(501), severity: "info", dismissible: false });
    expect(await fetchAnnouncement()).toBeNull();
  });

  it("returns null on a non-OK response", async () => {
    mockFetch({}, false);
    expect(await fetchAnnouncement()).toBeNull();
  });
});
