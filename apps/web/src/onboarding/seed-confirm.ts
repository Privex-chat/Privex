// Seed-phrase confirmation quiz (onboarding step 5, Card C). Pure + testable.

/** Pick `count` distinct 1-based word positions to quiz from the mnemonic. */
export function pickConfirmIndices(wordCount: number, count = 3, rng: () => number = Math.random): number[] {
  const idxs = new Set<number>();
  while (idxs.size < count && idxs.size < wordCount) idxs.add(Math.floor(rng() * wordCount) + 1);
  return [...idxs].sort((a, b) => a - b);
}

/** True iff every quizzed position matches the user's answer (case-insensitive,
 *  trimmed). Empty answers fail. */
export function checkConfirm(mnemonic: string, indices: number[], answers: string[]): boolean {
  const words = mnemonic.trim().split(/\s+/);
  return indices.every((pos, i) => {
    const expected = words[pos - 1];
    const given = (answers[i] ?? "").trim().toLowerCase();
    return given.length > 0 && expected === given;
  });
}
