// Home-screen warning raised by services/key-watch.ts: another device published
// keys for this account. Shown on this device only, until answered; nothing about
// it (or the answer) is ever sent anywhere.
import { useEffect, useState } from "react";
import { dismissKeyAlert, hasKeyAlert } from "../services/key-watch";
import { onKeyAlertChanged } from "../services/events";
import { useAuth } from "../store/auth";
import { WarningTriangleIcon } from "./icons";

export default function KeyAlert() {
  const userId = useAuth((s) => s.userId);
  const [shown, setShown] = useState(false);
  const [notMe, setNotMe] = useState(false);

  useEffect(() => {
    if (!userId) {
      setShown(false);
      return;
    }
    const refresh = () => void hasKeyAlert(userId).then(setShown);
    refresh();
    return onKeyAlertChanged(refresh);
  }, [userId]);

  if (!shown || !userId) return null;

  const btn = "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors";
  return (
    <div role="alert" className="mb-4 rounded-xl border border-danger bg-danger-subtle p-3 text-sm">
      <p className="flex items-center gap-1.5 font-medium text-danger">
        <WarningTriangleIcon className="h-4 w-4 shrink-0" />
        Your account was set up on another device
      </p>
      <p className="mt-1 text-xs text-text-secondary">
        Another device published new keys for your account. That happens when someone restores it
        with your recovery phrase or password.
      </p>
      {!notMe ? (
        <>
          <p className="mt-1 text-xs text-text-secondary">
            If it was you — setting up a new phone or browser, or your other device updating its
            keys — tap &ldquo;That was me&rdquo;.
          </p>
          <div className="mt-2 flex gap-2">
            <button onClick={() => void dismissKeyAlert(userId)} className={`${btn} bg-raised text-text-secondary hover:bg-border-strong`}>
              That was me
            </button>
            <button onClick={() => setNotMe(true)} className={`${btn} border border-danger text-danger hover:bg-danger-subtle`}>
              It wasn&rsquo;t me
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="mt-2 text-xs text-text-secondary">
            Then someone has your recovery phrase or password. They hold your account&rsquo;s keys:
            they can receive messages sent to you and message people as you, and that can&rsquo;t be
            undone for this account.
          </p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-text-secondary">
            <li>Warn your contacts in person or by call — not in Privex.</li>
            <li>When you&rsquo;re ready, move to a new account and share its ID with them the same way.</li>
            <li>If chat backup is on, turn it off in Settings → Recovery. That deletes it from our servers.</li>
          </ul>
          <button onClick={() => void dismissKeyAlert(userId)} className={`${btn} mt-2 bg-raised text-text-secondary hover:bg-border-strong`}>
            Hide this warning
          </button>
        </>
      )}
    </div>
  );
}
