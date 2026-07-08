// Account recovery (docs 4.2). Restore an identity on a fresh device:
//   A - password (OPAQUE), B - emergency contacts (deferred), C - seed phrase.
// Message history is NOT restored (it lives only on devices).
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { recoverWithPassword, recoverWithSeed } from "../services/recovery";

type Tab = "password" | "seed" | "contacts";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen bg-surface text-text-primary flex items-center justify-center p-6">
      <div className="w-full max-w-md">{children}</div>
    </main>
  );
}

export default function Recovery() {
  const nav = useNavigate();
  const [tab, setTab] = useState<Tab>("password");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(fn: () => Promise<string>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      nav("/", { replace: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Recovery failed.");
      setBusy(false);
    }
  }

  return (
    <Shell>
      <button onClick={() => nav("/onboarding")} className="text-sm text-text-muted hover:text-text-secondary">← Back</button>
      <h1 className="mt-3 text-2xl font-semibold">Recover your account</h1>
      <p className="mt-2 text-text-secondary text-sm">
        Your identity is restored from your master key. Message history stays on your devices and
        won&rsquo;t be recovered.
      </p>

      <div className="mt-6 flex gap-2 text-sm">
        {(["password", "seed", "contacts"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => {
              setTab(t);
              setError(null);
            }}
            className={
              "rounded-lg px-3 py-1.5 " +
              (tab === t ? "bg-accent" : "bg-elevated border border-divider hover:bg-raised")
            }
          >
            {t === "password" ? "Password" : t === "seed" ? "Seed phrase" : "Contacts"}
          </button>
        ))}
      </div>

      <div className="mt-5">
        {tab === "password" && <PasswordRecovery busy={busy} onRun={run} />}
        {tab === "seed" && <SeedRecovery busy={busy} onRun={run} />}
        {tab === "contacts" && <ContactsRecovery />}
      </div>

      {error && <p className="mt-4 text-sm text-danger">{error}</p>}
    </Shell>
  );
}

function PasswordRecovery({ busy, onRun }: { busy: boolean; onRun: (fn: () => Promise<string>) => void }) {
  const [pxId, setPxId] = useState("");
  const [password, setPassword] = useState("");
  return (
    <div className="space-y-3">
      <input
        value={pxId}
        onChange={(e) => setPxId(e.target.value)}
        placeholder="px_…"
        maxLength={35}
        spellCheck={false}
        autoCapitalize="none"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 font-mono text-sm outline-none focus:border-border-focus"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Recovery password"
        minLength={8}
        autoComplete="current-password"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 outline-none focus:border-border-focus"
      />
      <button
        disabled={busy || !pxId.trim() || !password}
        onClick={() => onRun(() => recoverWithPassword(pxId.trim(), password))}
        className="w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-3 font-medium"
      >
        {busy ? "Recovering…" : "Recover with password"}
      </button>
    </div>
  );
}

function SeedRecovery({ busy, onRun }: { busy: boolean; onRun: (fn: () => Promise<string>) => void }) {
  const [phrase, setPhrase] = useState("");
  const wordCount = phrase.trim() ? phrase.trim().split(/\s+/).length : 0;
  return (
    <div className="space-y-3">
      <textarea
        value={phrase}
        onChange={(e) => setPhrase(e.target.value)}
        placeholder="Enter your 24-word seed phrase, separated by spaces"
        rows={4}
        maxLength={528}
        spellCheck={false}
        autoCapitalize="none"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 text-sm outline-none focus:border-border-focus"
      />
      <p className="text-xs text-text-muted">{wordCount}/24 words</p>
      <button
        disabled={busy || wordCount !== 24}
        onClick={() => onRun(() => recoverWithSeed(phrase))}
        className="w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-3 font-medium"
      >
        {busy ? "Recovering…" : "Recover with seed phrase"}
      </button>
    </div>
  );
}

function ContactsRecovery() {
  return (
    <div className="rounded-xl border border-divider p-4 text-sm text-text-secondary">
      <p className="font-medium text-text">Recovery via emergency contacts</p>
      <p className="mt-2">
        Ask 2 of your recovery friends to approve your recovery in Privex. This flow needs the
        relationship-free share rendezvous, which is coming in a later release. For now, recover with
        your password or seed phrase.
      </p>
    </div>
  );
}
