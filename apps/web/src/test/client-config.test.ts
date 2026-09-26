// Uploads default OFF on the client too when the server config can't be read,
// matching the server's FILE_UPLOADS_ENABLED default.
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

const load = async () => (await import("../services/client-config")).getClientConfig();

describe("client config", () => {
  it("falls back to uploads OFF when the request fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect((await load()).file_uploads_enabled).toBe(false);
  });

  it("falls back to uploads OFF on a non-OK response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 503 })));
    expect((await load()).file_uploads_enabled).toBe(false);
  });

  it("uses the server's answer when there is one", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ file_uploads_enabled: true })));
    expect((await load()).file_uploads_enabled).toBe(true);
  });
});
