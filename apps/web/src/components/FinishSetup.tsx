// Home-screen "finish securing your account" checklist. Appears while a new user
// still has account recovery or app lock unset (things they may have skipped in
// onboarding), and disappears once both are done or the card is dismissed. The
// dismissal is remembered so it doesn't nag.
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { db } from "../db";
import { opaqueRecoveryStatus, RECOVERY_CONTACTS_KEY } from "../services/recovery";
import { lockStatus } from "../services/applock";
import { onContactsChanged } from "../services/events";
import { CheckIcon, XIcon } from "./icons";

const DISMISS_KEY = "finish_setup_dismissed";
/** Set true when the user confirms their seed phrase during onboarding. */
export const SEED_SAVED_KEY = "recovery_seed_saved";

export default function FinishSetup() {
  const nav = useNavigate();
  const [recovery, setRecovery] = useState<boolean | null>(null);
  const [lock, setLock] = useState<boolean | null>(null);
  const [dismissed, setDismissed] = useState<boolean | null>(null);

  const refresh = useCallback(() => {
    void (async () => {
      const [opaque, contactsRow, seedRow, lk, dis] = await Promise.all([
        opaqueRecoveryStatus().catch(() => false),
        db.settings.get(RECOVERY_CONTACTS_KEY),
        db.settings.get(SEED_SAVED_KEY),
        lockStatus(),
        db.settings.get(DISMISS_KEY),
      ]);
      setRecovery(opaque === true || !!contactsRow || seedRow?.value === true);
      setLock(!!lk?.enabled);
      setDismissed(dis?.value === true);
    })();
  }, []);
  useEffect(() => {
    refresh();
    return onContactsChanged(refresh); // emergency-contact setup emits this
  }, [refresh]);

  if (recovery === null || lock === null || dismissed === null) return null;
  if (dismissed || (recovery && lock)) return null;

  const dismiss = async () => {
    await db.settings.put({ key: DISMISS_KEY, value: true });
    setDismissed(true);
  };

  const Item = ({ done, label, onClick }: { done: boolean; label: string; onClick: () => void }) => (
    <button
      onClick={onClick}
      disabled={done}
      className="flex w-full items-center gap-2.5 rounded-lg px-2 py-2 text-left text-sm transition-colors disabled:cursor-default enabled:hover:bg-raised"
    >
      <span
        className={
          "flex h-5 w-5 shrink-0 items-center justify-center rounded-full " +
          (done ? "bg-success-bg text-white" : "border border-border-strong")
        }
      >
        {done ? <CheckIcon className="h-3.5 w-3.5" /> : null}
      </span>
      <span className={done ? "text-text-muted line-through" : "text-text-secondary"}>{label}</span>
      {!done && <span className="ml-auto text-xs text-accent-text">Set up</span>}
    </button>
  );

  return (
    <div className="mb-4 rounded-xl border border-divider bg-elevated p-3">
      <div className="flex items-center justify-between px-1">
        <span className="text-sm font-medium">Finish securing your account</span>
        <button
          onClick={() => void dismiss()}
          aria-label="Dismiss"
          className="flex h-7 w-7 items-center justify-center rounded-full text-text-muted transition-colors hover:bg-raised hover:text-text-secondary"
        >
          <XIcon className="h-4 w-4" />
        </button>
      </div>
      <div className="mt-1 space-y-0.5">
        <Item done={recovery} label="Set up a way to recover your account" onClick={() => nav("/settings/recovery")} />
        <Item done={lock} label="Lock this app with a passphrase" onClick={() => nav("/settings/account")} />
      </div>
    </div>
  );
}
