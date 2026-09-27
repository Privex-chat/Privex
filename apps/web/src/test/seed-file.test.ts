import { describe, expect, it } from "vitest";
import { parseSeedText, seedFileText } from "../services/seed-file";

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
