import { describe, expect, it } from "vitest";
import { identiconCells, identiconHue } from "../components/Avatar";

describe("identicon", () => {
  const seed = "px_4a3f8c2b1d7e9f0a6b5c3d2e1f4a8b9c";

  it("is deterministic per seed", () => {
    expect(identiconCells(seed)).toEqual(identiconCells(seed));
    expect(identiconHue(seed)).toBe(identiconHue(seed));
  });

  it("differs across seeds", () => {
    expect(identiconCells(seed)).not.toEqual(identiconCells(seed + "x"));
  });

  it("is left-right symmetric (5x5)", () => {
    const c = identiconCells(seed);
    expect(c).toHaveLength(25);
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        expect(c[y * 5 + x]).toBe(c[y * 5 + (4 - x)]);
      }
    }
  });

  it("hue stays in range", () => {
    for (const s of ["", "a", seed, "px_" + "f".repeat(32)]) {
      const hue = identiconHue(s);
      expect(hue).toBeGreaterThanOrEqual(0);
      expect(hue).toBeLessThan(360);
    }
  });
});
