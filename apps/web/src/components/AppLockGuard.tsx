// Re-lock policy for the cryptographic app lock. Mounted only while the app is
// unlocked AND rendered (boot === "ready"). Triggers a FULL lock (drop the data key
// + tear down the live session - see services/session.lockApp) on:
//   - foreground idle past the window,
//   - returning to a tab that was hidden past the window (not a quick switch),
//   - the page being frozen / restored from bfcache (a backgrounded PWA/tab must
//     not come back showing decrypted content or holding a live socket).
// A reload locks inherently (the key isn't on disk). Renders nothing.
import { useCallback, useEffect, useRef } from "react";
import { getIdleMs, isLockEnabled, DEFAULT_IDLE_MS } from "../services/applock";
import { lockApp } from "../services/session";

export default function AppLockGuard({ onLock }: { onLock: () => void }) {
  const last = useRef(Date.now());
  const idle = useRef(DEFAULT_IDLE_MS);

  // Self-gates on the lock being enabled, so it's a no-op for users without a lock
  // and arms automatically when the lock is enabled mid-session (no reload needed).
  const doLock = useCallback(async () => {
    if (!(await isLockEnabled())) return;
    onLock(); // boot="locked" → UnlockScreen (set before the auth teardown)
    lockApp(); // drop key + disconnect WS + stop cover traffic + drop session token
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

    // Restored from the back/forward cache: the JS heap (incl. any decrypted UI
    // state) is preserved, so re-lock immediately rather than show stale content.
    const onPageShow = (e: Event) => {
      if ((e as PageTransitionEvent).persisted) void doLock();
    };
    window.addEventListener("pageshow", onPageShow);

    // Page Lifecycle: the browser froze this tab (deep background) → lock so the
    // frozen heap holds no data key. On resume/restore the checks above re-gate.
    const onFreeze = () => void doLock();
    document.addEventListener("freeze", onFreeze);

    const iv = setInterval(() => {
      if (Date.now() - last.current >= idle.current) void doLock();
    }, 20_000);

    return () => {
      for (const e of events) window.removeEventListener(e, bump);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("pageshow", onPageShow);
      document.removeEventListener("freeze", onFreeze);
      clearInterval(iv);
    };
  }, [doLock]);

  return null;
}
