// "Print" / "Save as text file" for the recovery phrase (onboarding + Settings).
// Paper is the safe copy, so Print leads; the file is behind a warning, because
// file-stealing malware hunts for exactly this kind of file. Printing shows only
// the .seed-print sheet below (index.css hides the app), so a printout or "Save as
// PDF" holds the words and nothing else.
import { useState } from "react";
import { createPortal } from "react-dom";
import { saveSeedFile } from "../services/seed-file";

export default function SeedSave({ words }: { words: string[] }) {
  const [asking, setAsking] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  // The warning's own button is the click that opens the save dialog (it needs a
  // fresh click, which a confirm() popup in between wouldn't give it).
  async function save() {
    setAsking(false);
    setResult(null);
    try {
      const r = await saveSeedFile(words);
      if (r === "saved") setResult("Saved.");
      if (r === "downloaded") {
        setResult(
          "It's in your Downloads folder. Move it somewhere offline, like a USB stick, then delete it from Downloads.",
        );
      }
    } catch (e) {
      setResult(e instanceof Error ? `Couldn't save the file: ${e.message}` : "Couldn't save the file.");
    }
  }

  const secondary = "rounded-lg bg-raised px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-border-strong";
  return (
    <>
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => window.print()}
          className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
        >
          Print / save as PDF
        </button>
        <button type="button" onClick={() => setAsking(true)} disabled={asking} className={secondary + " disabled:opacity-40"}>
          Save as text file
        </button>
      </div>
      {asking ? (
        <div className="mt-2 rounded-lg border border-warning p-3 text-xs">
          <p className="text-warning">
            Malware that steals files looks for exactly this kind of file. Anyone who gets it can take
            over your account, and there&rsquo;s no way to lock them out again.
          </p>
          <p className="mt-1 text-text-secondary">
            Save it straight to a USB stick or an encrypted drive — not Downloads, the Desktop or a
            cloud-synced folder — and never email or message it.
          </p>
          <div className="mt-2 flex gap-2">
            <button type="button" onClick={() => void save()} className={secondary}>
              Save the file
            </button>
            <button type="button" onClick={() => setAsking(false)} className="px-2 text-text-muted hover:text-text-secondary">
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <p className="mt-2 text-xs text-text-muted">
          Best: print it and keep the paper somewhere safe. A file or PDF opens your account just like
          the words do.
        </p>
      )}
      {result && <p className="mt-1 text-xs text-text-secondary">{result}</p>}
      {createPortal(
        <div className="seed-print">
          <h1>Privex recovery phrase</h1>
          <p>
            Anyone who has these words can take over your Privex account. Keep this paper somewhere
            safe. Privex will never ask you for these words.
          </p>
          <ol>
            {words.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ol>
        </div>,
        document.body,
      )}
    </>
  );
}
