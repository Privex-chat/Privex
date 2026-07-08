// Full-screen unlock gate (cryptographic app lock). Shown BEFORE the app restores
// when the lock is on and this session hasn't unlocked yet - so a reload or URL
// change can't bypass it. Unlocks via biometric (WebAuthn) or the Argon2id
// passphrase; both unwrap the in-memory data key.
import { useEffect, useState, type FormEvent } from "react";
import { lockStatus, unlockWithBiometric, unlockWithPassphrase } from "../services/applock";

export default function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [biometric, setBiometric] = useState(false);

  useEffect(() => {
    void lockStatus().then((s) => setBiometric(s.biometric && s.biometricAvailable));
  }, []);

  async function unlockPass(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlockWithPassphrase(pass);
      setPass("");
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't unlock.");
      setBusy(false);
    }
  }

  async function unlockBio() {
    setBusy(true);
    setError(null);
    try {
      await unlockWithBiometric();
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Biometric unlock failed.");
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 flex items-center justify-center p-6">
      <form onSubmit={(e) => void unlockPass(e)} className="w-full max-w-xs text-center">
        <h1 className="text-lg font-semibold">Privex is locked</h1>
        <p className="mt-1 text-xs text-neutral-500">Unlock to access your messages on this device.</p>

        {biometric && (
          <button
            type="button"
            onClick={() => void unlockBio()}
            disabled={busy}
            className="mt-5 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 py-2.5 font-medium"
          >
            Unlock with biometrics
          </button>
        )}

        <input
          autoFocus
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          placeholder="Passphrase"
          minLength={6}
          className="mt-4 w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-center outline-none focus:border-indigo-500"
        />
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        <button
          type="submit"
          disabled={busy || pass.length === 0}
          className="mt-4 w-full rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 py-2.5 font-medium"
        >
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </main>
  );
}
