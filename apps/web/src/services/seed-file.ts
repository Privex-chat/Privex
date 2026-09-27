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

// File System Access API (desktop Chrome/Edge); not in TypeScript's DOM types yet.
type SaveFilePicker = (opts: {
  suggestedName: string;
  types: { description: string; accept: Record<string, string[]> }[];
}) => Promise<FileSystemFileHandle>;

/** Save the file. Where the browser can ask where (desktop Chrome/Edge), the user
 *  picks the place - a USB stick, say - so it doesn't just land in Downloads.
 *  Elsewhere it's a normal download. Call from a click (the picker needs one). */
export async function saveSeedFile(words: string[]): Promise<"saved" | "downloaded" | "cancelled"> {
  const blob = new Blob([seedFileText(words)], { type: "text/plain;charset=utf-8" });
  const pick = (globalThis as { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;
  if (pick) {
    let handle: FileSystemFileHandle | undefined;
    try {
      handle = await pick({
        suggestedName: SEED_FILE_NAME,
        types: [{ description: "Text file", accept: { "text/plain": [".txt"] } }],
      });
    } catch (e) {
      if ((e as { name?: string }).name === "AbortError") return "cancelled";
      // The picker refused (e.g. the click's activation ran out): plain download below.
    }
    if (handle) {
      // A failed write throws to the caller - never quietly download instead of
      // saving where the user chose.
      const out = await handle.createWritable();
      await out.write(blob);
      await out.close();
      return "saved";
    }
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = SEED_FILE_NAME;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000); // some browsers read it after click()
  return "downloaded";
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
