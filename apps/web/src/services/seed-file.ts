// The recovery phrase as a text file (docs 6, path 4). Made and read on this
// device only - no network, nothing kept. The file holds the words and how to
// keep them safe: no Privex ID, no date, nothing it doesn't need.

export const SEED_FILE_NAME = "privex-recovery-phrase.txt";

/** Keep digits out of the prose: parseSeedText reads "number word" pairs. */
export function seedFileText(words: string[]): string {
  return [
    "PRIVEX RECOVERY PHRASE",
    "",
    "Anyone who has these words can take over your Privex account.",
    "Safest: print this or copy it onto paper, keep that somewhere safe, and delete this file.",
    "Never keep it in cloud-synced folders, email, chats or screenshots.",
    "Privex will never ask you for these words.",
    "",
    ...words.map((w, i) => `${i + 1}. ${w}`),
    "",
    "To recover: open Privex, choose Recover your account, then Seed phrase,",
    "and open this file or paste the words.",
    "",
  ].join("\n");
}

export function downloadSeedFile(words: string[]): void {
  const url = URL.createObjectURL(new Blob([seedFileText(words)], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = SEED_FILE_NAME;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000); // some browsers read it after click()
}

/** The words in pasted or uploaded text. A numbered list ("1. word", "1word", in any
 *  order) is read by number; anything else is every word in order. Case,
 *  punctuation and surrounding text don't matter. Two different words under one
 *  number give [] - there's no telling which is right. */
export function parseSeedText(text: string): string[] {
  const tokens = text.normalize("NFKD").toLowerCase().match(/\d+|[a-z]+/g) ?? [];
  const isWord = (t: string) => /^[a-z]/.test(t);
  const numbered: string[] = [];
  for (let i = 0; i + 1 < tokens.length; i++) {
    const n = Number(tokens[i]);
    const w = tokens[i + 1];
    if (isWord(tokens[i]) || !isWord(w) || n < 1 || n > 24) continue;
    if (numbered[n - 1] !== undefined && numbered[n - 1] !== w) return [];
    numbered[n - 1] = w;
  }
  const byNumber = numbered.filter(Boolean);
  // A few stray digits in a plain phrase ("3able") don't make it a numbered list.
  return byNumber.length >= 12 ? byNumber : tokens.filter(isWord);
}
