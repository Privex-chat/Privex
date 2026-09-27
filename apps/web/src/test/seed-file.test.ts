import { afterEach, describe, expect, it, vi } from "vitest";
import { parseSeedText, saveSeedFile, SEED_FILE_NAME, seedFileText } from "../services/seed-file";

const words = (
  "abandon ability able about above absent absorb abstract absurd abuse access accident " +
  "account accuse achieve acid acoustic acquire across act action actor actress actual"
).split(" ");

describe("recovery phrase file", () => {
  it("reads back its own file", () => {
    expect(parseSeedText(seedFileText(words))).toEqual(words);
  });

  it("reads a plain phrase in any case, spacing or punctuation", () => {
    expect(parseSeedText(`  ${words.join(",  ").toUpperCase()}\r\n`)).toEqual(words);
  });

  it("reads a numbered list by number, even run together and out of order", () => {
    // Copying the on-screen grid gives "1abandon2ability…".
    expect(parseSeedText(words.map((w, i) => `${i + 1}${w}`).reverse().join(""))).toEqual(words);
  });

  it("treats a stray digit in a plain phrase as noise", () => {
    expect(parseSeedText(words.join(" ").replace(" able ", " 3able "))).toEqual(words);
  });

  it("refuses two different words under one number", () => {
    expect(parseSeedText(`${seedFileText(words)}\n2. zoo`)).toEqual([]);
  });
});

describe("saving the file", () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubDownload() {
    const a = { href: "", download: "", click: vi.fn() };
    vi.stubGlobal("document", { createElement: () => a });
    return a;
  }

  it("writes where the user picked, without downloading", async () => {
    const written: string[] = [];
    vi.stubGlobal("showSaveFilePicker", async () => ({
      createWritable: async () => ({
        write: async (b: Blob) => void written.push(await b.text()),
        close: async () => {},
      }),
    }));
    const a = stubDownload();
    expect(await saveSeedFile(words)).toBe("saved");
    expect(written).toEqual([seedFileText(words)]);
    expect(a.click).not.toHaveBeenCalled();
  });

  it("does nothing when the user cancels the picker", async () => {
    vi.stubGlobal("showSaveFilePicker", async () => {
      throw new DOMException("cancelled", "AbortError");
    });
    const a = stubDownload();
    expect(await saveSeedFile(words)).toBe("cancelled");
    expect(a.click).not.toHaveBeenCalled();
  });

  it("downloads when there's no picker, or the picker refuses", async () => {
    const a = stubDownload();
    expect(await saveSeedFile(words)).toBe("downloaded");
    expect(a.download).toBe(SEED_FILE_NAME);
    vi.stubGlobal("showSaveFilePicker", async () => {
      throw new DOMException("no user gesture", "SecurityError");
    });
    expect(await saveSeedFile(words)).toBe("downloaded");
    expect(a.click).toHaveBeenCalledTimes(2);
  });

  it("fails loudly when writing to the picked place fails - no quiet download", async () => {
    vi.stubGlobal("showSaveFilePicker", async () => ({
      createWritable: async () => {
        throw new Error("disk full");
      },
    }));
    const a = stubDownload();
    await expect(saveSeedFile(words)).rejects.toThrow("disk full");
    expect(a.click).not.toHaveBeenCalled();
  });
});
