// Re-lock policy for the cryptographic app lock. Mounted only while the app is
// unlocked AND the lock is enabled. Locks after idle (foreground inactivity) or
// after a long absence (returning to a tab that was hidden past the idle window) -
// but NOT on a quick tab switch. Locking forgets the in-memory key; a reload locks
// inherently. Renders nothing.
import { useCallback, useEffect, useRef } from "react";
import { getIdleMs, isLockEnabled, lock, DEFAULT_IDLE_MS } from "../services/applock";

export default function AppLockGuard({ onLock }: { onLock: () => void }) {
  const last = useRef(Date.now());
  const idle = useRef(DEFAULT_IDLE_MS);

  // Self-gates on the lock being enabled, so it's a no-op for users without a lock
  // and arms automatically when the lock is enabled mid-session (no reload needed).
  const doLock = useCallback(async () => {
    if (!(await isLockEnabled())) return;
    lock();
    onLock();
  }, [onLock]);

  useEffect(() => {
    void getIdleMs().then((ms) => (idle.current = ms));
    const bump = () => (last.current = Date.now());
    const events = ["mousemove", "keydown", "pointerdown", "touchstart"] as const;
    for (const e of events) window.addEventListener(e, bump, { passive: true });

    // On returning to the tab, lock only if it was idle/hidden past the window
    // (activity doesn't fire while hidden, so `last` reflects the absence).
    const onVisible = () => {
      if (document.visibilityState === "visible" && Date.now() - last.current >= idle.current) void doLock();
    };
    document.addEventListener("visibilitychange", onVisible);

    const iv = setInterval(() => {
      if (Date.now() - last.current >= idle.current) void doLock();
    }, 20_000);

    return () => {
      for (const e of events) window.removeEventListener(e, bump);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(iv);
    };
  }, [doLock]);

  return null;
}
