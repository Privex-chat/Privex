// PWA install banner. The browser fires `beforeinstallprompt` (Chrome/Edge, often
// after ~2 visits); we suppress the mini-infobar and show our own bottom banner so
// the user installs on our terms. Dismissal + install are remembered in settings.
import { useEffect, useState } from "react";
import { db } from "../db";
import { XIcon } from "./icons";

interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>;
  readonly userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

const DISMISS_KEY = "install_dismissed";

export default function InstallPrompt() {
  const [evt, setEvt] = useState<BeforeInstallPromptEvent | null>(null);
  const [dismissed, setDismissed] = useState(true);

  useEffect(() => {
    void db.settings.get(DISMISS_KEY).then((r) => setDismissed(!!r?.value));
    const onPrompt = (e: Event) => {
      e.preventDefault();
      setEvt(e as BeforeInstallPromptEvent);
    };
    const onInstalled = () => {
      setEvt(null);
      void db.settings.put({ key: DISMISS_KEY, value: true });
    };
    window.addEventListener("beforeinstallprompt", onPrompt);
    window.addEventListener("appinstalled", onInstalled);
    return () => {
      window.removeEventListener("beforeinstallprompt", onPrompt);
      window.removeEventListener("appinstalled", onInstalled);
    };
  }, []);

  if (!evt || dismissed) return null;

  async function install() {
    if (!evt) return;
    await evt.prompt();
    await evt.userChoice;
    setEvt(null);
  }
  function dismiss() {
    setDismissed(true);
    void db.settings.put({ key: DISMISS_KEY, value: true });
  }

  return (
    <div className="fixed inset-x-0 bottom-0 z-40 flex justify-center p-3 md:p-4">
      <div className="flex w-full max-w-md items-center gap-3 rounded-xl border border-divider bg-elevated px-4 py-3 shadow-lg backdrop-blur">
        <div className="flex-1">
          <p className="text-sm font-medium text-text-primary">Install Privex</p>
          <p className="text-xs text-text-muted">Add it to your device for offline access and a faster launch.</p>
        </div>
        <button
          onClick={() => void install()}
          className="rounded-lg bg-accent hover:bg-accent-hover px-3 py-1.5 text-sm font-medium"
        >
          Install
        </button>
        <button onClick={dismiss} aria-label="Dismiss" className="flex items-center text-text-muted hover:text-text-secondary">
          <XIcon className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
