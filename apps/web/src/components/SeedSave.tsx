// "Save as text file" / "Print" for the recovery phrase (onboarding + Settings).
// Printing shows only the .seed-print sheet below (index.css hides the app), so a
// printout or "Save as PDF" holds the words and nothing else.
import { createPortal } from "react-dom";
import { downloadSeedFile } from "../services/seed-file";

export default function SeedSave({ words }: { words: string[] }) {
  const btn = "rounded-lg bg-raised px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-border-strong";
  return (
    <>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" onClick={() => downloadSeedFile(words)} className={btn}>
          Save as text file
        </button>
        <button type="button" onClick={() => window.print()} className={btn}>
          Print / save as PDF
        </button>
      </div>
      <p className="mt-2 text-xs text-text-muted">
        A file or PDF of these words opens your account just like the words do. Keep it out of
        cloud-synced folders, email and chats. Paper kept somewhere safe is best.
      </p>
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
