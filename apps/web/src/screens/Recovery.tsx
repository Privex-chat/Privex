// Account recovery (docs 4.2 / 6). Restore an identity on a fresh device with a
// password (OPAQUE), the seed phrase, or emergency contacts. Message history comes
// back only from an encrypted history backup, offered once the account is back.
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  pollContactRecovery,
  recoverWithPassword,
  recoverWithSeed,
  startContactRecovery,
  type RecoverySession,
} from "../services/recovery";
import { backupStatus, restoreHistory } from "../services/history-backup";
import { parseSeedText } from "../services/seed-file";
import { ArrowLeftIcon } from "../components/icons";
import { useCopyToClipboard } from "../hooks/useCopyToClipboard";
import * as api from "../api/client";

type Tab = "password" | "seed" | "contacts";

const STATUS_TIMEOUT_MS = 10_000;

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
  const [offerRestore, setOfferRestore] = useState(false);

  const enter = () => nav("/", { replace: true });

  // Back in: offer the encrypted history backup if there is one. (Settings →
  // Recovery makes this same status call every time it opens.)
  async function recovered() {
    let count = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      // Bounded: the account is already back, so a stalled request mustn't hold
      // this screen on "Recovering…".
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("backup status timed out")), STATUS_TIMEOUT_MS);
      });
      count = (await Promise.race([backupStatus(), timeout])).count;
    } catch {
      // No status, nothing to offer - restore stays available in Settings.
    } finally {
      clearTimeout(timer);
    }
    if (count > 0) setOfferRestore(true);
    else enter();
  }

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Recovery failed.");
      setBusy(false);
      return;
    }
    await recovered();
  }

  if (offerRestore) {
    return (
      <Shell>
        <RestoreBackup onDone={enter} />
      </Shell>
    );
  }

  return (
    <Shell>
      <button onClick={() => nav("/onboarding")} className="inline-flex items-center gap-1 text-sm text-text-muted hover:text-text-secondary"><ArrowLeftIcon className="h-4 w-4" /> Back</button>
      <h1 className="mt-3 text-2xl font-semibold">Recover your account</h1>
      <p className="mt-2 text-text-secondary text-sm">
        This brings back your Privex ID and keys. Your chats come back only if you turned on
        encrypted chat backup.
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
        {tab === "seed" && <SeedRecovery busy={busy} onRun={run} onEdit={() => setError(null)} />}
        {tab === "contacts" && <ContactsRecovery onRecovered={() => void recovered()} />}
      </div>

      {error && <p className="mt-4 text-sm text-danger">{error}</p>}
    </Shell>
  );
}

type RunFn = (fn: () => Promise<unknown>) => void;

function PasswordRecovery({ busy, onRun }: { busy: boolean; onRun: RunFn }) {
  const [pxId, setPxId] = useState("");
  const [password, setPassword] = useState("");
  const id = pxId.trim().toLowerCase();
  const ready = !busy && !!id && !!password;
  // A real form with username + current-password, so a password manager can fill
  // (and save) the ID and password together.
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready) onRun(() => recoverWithPassword(id, password));
      }}
    >
      <input
        name="username"
        value={pxId}
        onChange={(e) => setPxId(e.target.value)}
        placeholder="px_…"
        aria-label="Privex ID"
        maxLength={40}
        spellCheck={false}
        autoCapitalize="none"
        autoComplete="username"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 font-mono text-sm outline-none focus:border-border-focus"
      />
      <input
        type="password"
        name="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Recovery password"
        aria-label="Recovery password"
        minLength={8}
        autoComplete="current-password"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 outline-none focus:border-border-focus"
      />
      <button
        type="submit"
        disabled={!ready}
        className="w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-3 font-medium"
      >
        {busy ? "Recovering…" : "Recover with password"}
      </button>
    </form>
  );
}

/** bip39's errors count words from 0 and read like a stack trace, and a refused
 *  sign-in only says "api 401". */
function friendlySeedError(e: unknown): Error {
  // Either a valid phrase that no account uses (e.g. one mistyped word that's
  // another real word and still passes the checksum), or a device clock off by
  // over 5 minutes. The server answers every failed sign-in the same way - it
  // never says whether an account exists - so name both, assert neither.
  if (e instanceof api.ApiError && e.status === 401) {
    return new Error(
      "Couldn't sign in with these words. Either they don't match a Privex account - check each one against your saved copy - or this device's clock is more than 5 minutes off.",
    );
  }
  const msg = e instanceof Error ? e.message : String(e);
  const unknown = /unknown word \(word (\d+)\)/.exec(msg);
  if (unknown) {
    return new Error(`Word ${Number(unknown[1]) + 1} isn't a recovery-phrase word. Check its spelling.`);
  }
  if (msg.includes("invalid checksum")) {
    return new Error("These words aren't a valid recovery phrase. One may be misspelled or out of order.");
  }
  return e instanceof Error ? e : new Error(msg);
}

// A saved phrase file is under 1 KB; anything this big isn't one.
const MAX_SEED_FILE = 16 * 1024;

function SeedRecovery({ busy, onRun, onEdit }: { busy: boolean; onRun: RunFn; onEdit: () => void }) {
  const [phrase, setPhraseState] = useState("");
  const setPhrase = (v: string) => {
    setPhraseState(v);
    onEdit(); // the last attempt's error no longer applies
  };
  const [fileError, setFileError] = useState<string | null>(null);
  // Pasting the saved file, the numbered list or the bare words all work.
  const words = parseSeedText(phrase);

  // Read on this device as plain text - never uploaded, never kept. Only the
  // words parsed out of it are used.
  async function openFile(file: File | undefined) {
    setFileError(null);
    if (!file) return;
    if (file.size > MAX_SEED_FILE) {
      setFileError("That file is too big to be a saved recovery phrase.");
      return;
    }
    const found = parseSeedText(await file.text());
    if (found.length !== 24) {
      setFileError("Couldn't find 24 words in that file. You can paste or type them instead.");
      return;
    }
    setPhrase(found.join(" "));
  }

  return (
    <div className="space-y-3">
      <textarea
        value={phrase}
        onChange={(e) => setPhrase(e.target.value)}
        placeholder="Paste or type your 24 words"
        aria-label="Seed phrase"
        rows={4}
        maxLength={4096}
        spellCheck={false}
        autoCapitalize="none"
        autoComplete="off"
        className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 text-sm outline-none focus:border-border-focus"
      />
      <div className="flex items-center justify-between text-xs">
        <span className="text-text-muted">{words.length}/24 words</span>
        <label className="cursor-pointer text-accent-text hover:underline focus-within:underline">
          Open saved file
          <input
            type="file"
            accept=".txt,text/plain"
            className="sr-only"
            onChange={(e) => {
              void openFile(e.target.files?.[0]);
              e.target.value = ""; // so picking the same file again still fires
            }}
          />
        </label>
      </div>
      {fileError && <p className="text-xs text-danger">{fileError}</p>}
      <button
        disabled={busy || words.length !== 24}
        onClick={() =>
          onRun(() =>
            recoverWithSeed(words.join(" ")).catch((e: unknown) => {
              throw friendlySeedError(e);
            }),
          )
        }
        className="w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-3 font-medium"
      >
        {busy ? "Recovering…" : "Recover with seed phrase"}
      </button>
    </div>
  );
}

function RestoreBackup({ onDone }: { onDone: () => void }) {
  const [restored, setRestored] = useState<number | null>(null); // null = not started
  const [error, setError] = useState<string | null>(null);

  async function restore() {
    setError(null);
    setRestored(0);
    try {
      await restoreHistory(setRestored);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Restore failed.");
      setRestored(null);
    }
  }

  return (
    <>
      <h1 className="text-2xl font-semibold">You&rsquo;re back in</h1>
      <p className="mt-2 text-sm text-text-secondary">
        Your encrypted chat backup is still on our servers. Restore it to this device now, or later
        from Settings → Recovery.
      </p>
      <p className="mt-2 text-xs text-text-muted">
        Backing up stays off on this device until you turn it on there.
      </p>
      <button
        onClick={() => void restore()}
        disabled={restored !== null}
        className="mt-6 w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 py-3 font-medium"
      >
        {restored === null ? "Restore chats" : `Restoring… ${restored}`}
      </button>
      <button
        onClick={onDone}
        disabled={restored !== null}
        className="mt-2 w-full rounded-lg border border-border-strong py-3 text-sm text-text-secondary hover:bg-elevated disabled:opacity-40"
      >
        Not now
      </button>
      {error && <p className="mt-4 text-sm text-danger">{error}</p>}
    </>
  );
}

function ContactsRecovery({ onRecovered }: { onRecovered: () => void }) {
  // Via a ref: the poll below must not restart (and drop collected shares) when
  // the parent re-renders with a new callback.
  const onRecoveredRef = useRef(onRecovered);
  onRecoveredRef.current = onRecovered;
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
          onRecoveredRef.current();
          return;
        }
      } catch (e) {
        // Surface a persistent failure instead of hiding it (a silent catch here
        // is why a stuck recovery looked like "nothing happening"). pollContactRecovery
        // also decrypts, reconstructs, and finalizes, so DON'T call every failure a
        // connection issue: only classify network/API errors as that.
        if (!stopped) {
          const network = e instanceof api.ApiError || e instanceof TypeError;
          setPollError(
            network
              ? "Can't reach the server — still trying."
              : `Recovery hit a problem — still trying.${e instanceof Error ? ` (${e.message})` : ""}`,
          );
        }
      }
      if (!stopped) timer = setTimeout(() => void tick(), 3000);
    };
    timer = setTimeout(() => void tick(), 500);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [session]);

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
        {copied ? "Copied" : "Copy code"}
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
          Some approvals don&rsquo;t match this code. Your contacts likely used an older recovery
          code — press Back, start again, and re-share the new code + confirmation number.
        </p>
      )}
      {pollError && <p className="text-danger text-xs">{pollError}</p>}
      {error && <p className="text-danger">{error}</p>}
    </div>
  );
}
