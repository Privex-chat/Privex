// Deterministic identicon avatar from a seed (a contact's px_id). A 5x5,
// left-right-symmetric grid with a hue derived from the seed, so every identity
// gets a stable, distinct tile with zero server involvement and no dependency.
// Theme-independent: the tint is the derived color's own alpha, which reads on
// both dark and light backgrounds.
//
// ponytail: FNV-1a + an LCG bit stream is plenty for a visual identicon. Not a
// hash anyone relies on for security - it's decoration keyed to the px_id.

type Props = {
  /** Stable seed - use the contact's px_id so the tile never changes. */
  seed: string;
  /** Rendered size in px (square). */
  size?: number;
  className?: string;
  /** Accessible label; defaults to the seed. */
  title?: string;
};

function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Hue (0-359) derived from the seed. Exported for the identicon and its test. */
export function identiconHue(seed: string): number {
  return fnv1a(seed || "privex") % 360;
}

/** 25 booleans (row-major 5x5), left-right symmetric, deterministic per seed.
 *  Pure so it can be unit-tested without rendering. */
export function identiconCells(seed: string): boolean[] {
  let r = fnv1a(seed || "privex") || 1;
  const bit = () => {
    r = (Math.imul(r, 1664525) + 1013904223) >>> 0;
    return (r >>> 17) & 1; // a high-ish bit; LCG low bits are poor
  };
  const cells: boolean[] = [];
  for (let y = 0; y < 5; y++) {
    const left = [bit(), bit(), bit()];
    for (let x = 0; x < 5; x++) cells.push(!!left[x < 3 ? x : 4 - x]);
  }
  return cells;
}

export default function Avatar({ seed, size = 40, className = "", title }: Props) {
  const hue = identiconHue(seed);
  const color = `hsl(${hue} 62% 55%)`;
  const tint = `hsl(${hue} 62% 55% / 0.16)`;
  const cells = identiconCells(seed);

  return (
    <svg
      role="img"
      aria-label={title ?? seed}
      viewBox="0 0 5 5"
      width={size}
      height={size}
      className={"shrink-0 rounded-xl " + className}
      style={{ background: tint }}
    >
      {cells.map((on, i) =>
        on ? (
          <rect key={i} x={i % 5} y={Math.floor(i / 5)} width={1.02} height={1.02} fill={color} />
        ) : null,
      )}
    </svg>
  );
}
