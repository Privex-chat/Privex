// Full-screen unlock gate (cryptographic app lock). Shown BEFORE the app restores
// when the lock is on and this session hasn't unlocked yet - so a reload or URL
// change can't bypass it. Unlocks via biometric (WebAuthn) or the Argon2id
// passphrase; both unwrap the in-memory data key.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { lockStatus, unlockWithBiometric, unlockWithPassphrase } from "../services/applock";

export default function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState<"bio" | "pass" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [biometric, setBiometric] = useState(false);
  const autoTried = useRef(false);
  const passRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void lockStatus().then((s) => {
      const available = s.biometric && s.biometricAvailable;
      setBiometric(available);
      if (available && !autoTried.current) {
        // Auto-prompt biometrics once; a failure/cancel just falls through to the
        // passphrase form below (always usable). Focus is left alone so the native
        // biometric sheet - not the soft keyboard - is what comes up.
        autoTried.current = true;
        void unlockBio(true);
      } else if (!available) {
        passRef.current?.focus();
      }
    });
  }, []);

  async function unlockPass(e: FormEvent) {
    e.preventDefault();
    setBusy("pass");
    setError(null);
    try {
      await unlockWithPassphrase(pass);
      setPass("");
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't unlock.");
      setBusy(null);
    }
  }

  async function unlockBio(auto = false) {
    setBusy("bio");
    setError(null);
    try {
      await unlockWithBiometric();
      onUnlocked();
    } catch (err) {
      // Stay quiet on the automatic attempt - a browser that blocks WebAuthn
      // without a tap would otherwise flash an error before the user acted.
      if (!auto) setError(err instanceof Error ? err.message : "Biometric unlock failed.");
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-surface text-text-primary flex items-center justify-center p-6">
      <form onSubmit={(e) => void unlockPass(e)} className="w-full max-w-xs text-center">
        <h1 className="text-lg font-semibold">Privex is locked</h1>
        <p className="mt-1 text-xs text-text-muted">Unlock to access your messages on this device.</p>

        {biometric && (
          <button
            type="button"
            onClick={() => void unlockBio()}
            disabled={!!busy}
            className="mt-5 w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-2.5 font-medium"
          >
            {busy === "bio" ? "Waiting for biometrics…" : "Unlock with biometrics"}
          </button>
        )}

        <input
          ref={passRef}
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          placeholder="Passphrase"
          minLength={6}
          className="mt-4 w-full rounded-lg border border-border-strong bg-input px-3 py-2 text-center outline-none focus:border-border-focus"
        />
        {error && <p className="mt-2 text-xs text-danger">{error}</p>}
        <button
          type="submit"
          disabled={!!busy || pass.length === 0}
          className="mt-4 w-full rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 py-2.5 font-medium"
        >
          {busy === "pass" ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </main>
  );
}
