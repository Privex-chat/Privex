// Account recovery (docs 4.2). Restore an identity on a fresh device:
//   A - password (OPAQUE), B - emergency contacts (deferred), C - seed phrase.
// Message history is NOT restored (it lives only on devices).
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  pollContactRecovery,
  recoverWithPassword,
  recoverWithSeed,
  startContactRecovery,
  type RecoverySession,
} from "../services/recovery";
import { useCopyToClipboard } from "../hooks/useCopyToClipboard";

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
  const nav = useNavigate();
  const [session, setSession] = useState<RecoverySession | null>(null);
  const [received, setReceived] = useState(0);
  const [posted, setPosted] = useState(0); // blobs the bucket held on the last poll
  const [pollError, setPollError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, copy] = useCopyToClipboard();

  async function start() {
    setStarting(true);
    setError(null);
    try {
      setSession(await startContactRecovery());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start recovery.");
    } finally {
      setStarting(false);
    }
  }

  // Poll the rendezvous until >= 2 contacts have posted their shares and the seed
  // reconstructs; pollContactRecovery finalizes (persists identity + re-auths).
  useEffect(() => {
    if (!session) return;
    const collected = new Map<string, Uint8Array>();
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      if (stopped) return;
      try {
        const { userId, posted } = await pollContactRecovery(session, collected);
        if (stopped) return; // effect was cleaned up mid-poll — no state/nav/reschedule
        setReceived(collected.size);
        setPosted(posted);
        setPollError(null);
        if (userId) {
          stopped = true;
          nav("/", { replace: true });
          return;
        }
      } catch (e) {
        // Surface a persistent failure instead of hiding it (a silent catch here
        // is why a stuck recovery looked like "nothing happening").
        if (!stopped) setPollError(e instanceof Error ? e.message : "Couldn't reach the server.");
      }
      if (!stopped) timer = setTimeout(() => void tick(), 3000);
    };
    timer = setTimeout(() => void tick(), 500);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [session, nav]);

  if (!session) {
    return (
      <div className="rounded-xl border border-divider p-4 text-sm">
        <p className="font-medium text-text-primary">Recover with your emergency contacts</p>
        <p className="mt-2 text-text-secondary">
          If you set up 2–3 recovery contacts, they can restore your account together — no password
          or seed phrase needed. You&rsquo;ll get a one-time recovery code to give them.
        </p>
        <button
          onClick={() => void start()}
          disabled={starting}
          className="mt-3 rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 px-4 py-2 text-sm"
        >
          {starting ? "Starting…" : "Start recovery"}
        </button>
        {error && <p className="mt-2 text-danger">{error}</p>}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-divider p-4 text-sm space-y-3">
      <p className="font-medium text-text-primary">Send this code to your recovery contacts</p>
      <div className="rounded-lg bg-input border border-border-strong p-2 font-mono text-xs break-all">
        {session.code}
      </div>
      <button
        onClick={() => copy(session.code)}
        className="rounded-lg bg-raised hover:bg-border-strong px-3 py-1.5 text-xs"
      >
        {copied ? "Copied ✓" : "Copy code"}
      </button>
      <p className="text-text-secondary">
        Give this code to at least <strong>2</strong> of your recovery contacts{" "}
        <strong>out of band</strong> (phone / in person). Then read them this confirmation code so
        they know the request is really from you:
      </p>
      <p className="text-center text-2xl font-mono tracking-[0.3em] text-accent-subtle">
        {session.sas}
      </p>
      <p className="text-text-muted text-xs">
        Waiting for approvals… {received} of 2 shares received. Keep this page open.
      </p>
      {/* Diagnostic: blobs arrived but none decrypted → the contacts used a code
          from a DIFFERENT recovery session. Tell the user to restart + re-share. */}
      {posted > received && (
        <p className="text-warning text-xs">
          Received {posted} approval{posted === 1 ? "" : "s"} that don&rsquo;t match this code.
          Your contacts likely used an older recovery code — press Back, start again, and re-share
          the new code + confirmation number.
        </p>
      )}
      {pollError && <p className="text-danger text-xs">Connection issue: {pollError}</p>}
      {error && <p className="text-danger">{error}</p>}
    </div>
  );
}
