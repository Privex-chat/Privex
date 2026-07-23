// Registration + onboarding (docs 6 / 8.5). Five visible steps with a progress
// bar; progress is persisted so a closed browser resumes where it left off. All
// key material is generated in the browser (crypto worker) and never sent to the
// server in the clear.
//
// Flow: welcome → keys (forge + identicon reveal) → register (PoW) → secure
// (recovery) → safety orientation → enter. finishOnboarding() strips the mnemonic
// and signs in, so it runs at the end of the recovery step; the safety step is a
// post-signin orientation shown once (progress is already "done" on reload).
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { completeRegistration, finishOnboarding, generateIdentity } from "../onboarding/flow";
import { loadBundle, loadProgress } from "../onboarding/store";
import { checkConfirm, pickConfirmIndices } from "../onboarding/seed-confirm";
import { enableOpaqueRecovery, opaqueRecoveryStatus } from "../services/recovery";
import { db } from "../db";
import Avatar from "../components/Avatar";
import { useCopyToClipboard } from "../hooks/useCopyToClipboard";
import { ArrowLeftIcon, CheckIcon, KeyIcon, LockIcon, ShieldCheckIcon, WarningTriangleIcon } from "../components/icons";

type UiStep = "loading" | "welcome" | "keys" | "register" | "password" | "recovery" | "safety";

const TOTAL_STEPS = 5;

function Stepper({ current }: { current: number }) {
  return (
    <div className="flex shrink-0 justify-center gap-1.5 px-6 pt-6" aria-hidden="true">
      {Array.from({ length: TOTAL_STEPS }, (_, i) => (
        <span
          key={i}
          className={"h-1 w-8 rounded-full transition-colors " + (i < current ? "bg-accent" : "bg-border")}
        />
      ))}
    </div>
  );
}

function Shell({ step, children }: { step?: number; children: ReactNode }) {
  return (
    <main className="flex min-h-[100dvh] flex-col bg-surface text-text-primary">
      {step ? <Stepper current={step} /> : null}
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex min-h-full w-full max-w-md items-center justify-center p-6">
          <div className="w-full">{children}</div>
        </div>
      </div>
    </main>
  );
}

/* ── Illustrations (geometric, theme-aware) ── */

function ShieldIllustration() {
  return (
    <svg viewBox="0 0 96 96" className="mx-auto h-24 w-24" fill="none" aria-hidden="true">
      <circle cx="48" cy="48" r="44" className="stroke-border" strokeWidth="1.5" />
      <circle cx="48" cy="48" r="32" className="stroke-divider" strokeWidth="1.5" />
      <path
        d="M48 26l16 7v11c0 10-7 15-16 19-9-4-16-9-16-19V33z"
        className="fill-accent-bg stroke-accent-subtle"
        strokeWidth="2"
      />
      <path
        d="M41 48l5 5 9-10"
        className="stroke-accent-subtle"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** The "forging" moment: a slow dashed ring that resolves into the identicon. */
function ForgeIllustration() {
  return (
    <div className="relative mx-auto flex h-24 w-24 items-center justify-center">
      <svg
        viewBox="0 0 96 96"
        className="absolute inset-0 h-full w-full motion-safe:animate-spin [animation-duration:6s]"
        fill="none"
        aria-hidden="true"
      >
        <circle cx="48" cy="48" r="44" className="stroke-accent-subtle" strokeWidth="1.5" strokeDasharray="6 9" opacity="0.55" />
      </svg>
      <div className="h-10 w-10 rounded-xl bg-accent-bg motion-safe:animate-pulse" />
    </div>
  );
}

function RingedAvatar({ seed }: { seed: string }) {
  return (
    <div className="relative mx-auto flex h-24 w-24 items-center justify-center">
      <svg viewBox="0 0 96 96" className="absolute inset-0 h-full w-full" fill="none" aria-hidden="true">
        <circle cx="48" cy="48" r="44" className="stroke-border" strokeWidth="1.5" strokeDasharray="4 7" />
      </svg>
      <Avatar seed={seed} size={64} title="Your identicon" />
    </div>
  );
}

export default function Onboarding() {
  const nav = useNavigate();
  const [step, setStep] = useState<UiStep>("loading");
  const [userId, setUserId] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let off = false;
    void (async () => {
      const p = await loadProgress();
      if (off) return;
      if (p.userId) setUserId(p.userId);
      if (p.step === "done") nav("/", { replace: true });
      else if (p.step === "registered") setStep("recovery");
      else if (p.step === "keys") setStep("register");
      else setStep("welcome");
    })();
    return () => {
      off = true;
    };
  }, [nav]);

  if (step === "loading") return <Shell>{null}</Shell>;
  if (step === "welcome") return <Welcome onStart={() => setStep("keys")} />;
  if (step === "keys")
    return (
      <KeyGen
        onDone={(id) => {
          setUserId(id);
          setStep("register");
        }}
        onError={setError}
        error={error}
      />
    );
  if (step === "register")
    return (
      <Registering
        onDone={() => setStep("recovery")}
        onError={setError}
        error={error}
        onBack={() => {
          setError(null);
          setStep("keys");
        }}
      />
    );
  if (step === "password")
    return (
      <PasswordStep
        error={error}
        onBack={() => {
          setError(null);
          setStep("recovery");
        }}
        onSubmit={async (pw) => {
          setError(null);
          try {
            await enableOpaqueRecovery(pw);
            setStep("recovery");
          } catch {
            setError("Could not enable password recovery. Please try again.");
          }
        }}
      />
    );
  if (step === "safety") return <SafetyStep onEnter={() => nav("/", { replace: true })} />;
  return (
    <RecoveryStep
      userId={userId}
      onPasswordRecovery={() => {
        setError(null);
        setStep("password");
      }}
      onDone={() => setStep("safety")}
      onError={setError}
      error={error}
    />
  );
}

// --- STEP 1: Welcome ---
function Welcome({ onStart }: { onStart: () => void }) {
  return (
    <Shell step={1}>
      <div className="text-center">
        <ShieldIllustration />
        <h1 className="mt-6 text-2xl font-semibold">Welcome to Privex</h1>
        <p className="mx-auto mt-3 max-w-xs text-sm leading-relaxed text-text-secondary">
          You&rsquo;re about to create an identity that lives only on this device. We never learn who
          you are — even if we wanted to, we couldn&rsquo;t.
        </p>
        <p className="mt-3 text-sm text-text-muted">No phone number. No email. No name.</p>
      </div>
      <button
        onClick={onStart}
        className="mt-8 w-full rounded-lg bg-accent py-3 font-medium text-white transition-colors hover:bg-accent-hover"
      >
        Create my identity
      </button>
      <Link
        to="/recover"
        className="mt-4 block text-center text-sm text-text-secondary transition-colors hover:text-text-primary"
      >
        Recover an existing account
      </Link>
    </Shell>
  );
}

// --- STEP 2: keys (forge + identicon reveal) ---
function KeyGen({
  onDone,
  onError,
  error,
}: {
  onDone: (userId: string) => void;
  onError: (e: string) => void;
  error: string | null;
}) {
  const [userId, setUserId] = useState("");
  const [copied, copy] = useCopyToClipboard();
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void (async () => {
      try {
        const existing = await loadBundle();
        setUserId(existing?.userId ?? (await generateIdentity()));
      } catch {
        onError("Key generation failed. Please reload and try again.");
      }
    })();
  }, [onError]);

  return (
    <Shell step={2}>
      {!userId ? (
        <div className="text-center">
          <ForgeIllustration />
          <h1 className="mt-6 text-xl font-semibold">Forging your keys</h1>
          <p className="mx-auto mt-3 max-w-xs text-sm leading-relaxed text-text-secondary">
            Post-quantum signing and messaging keys (Ed25519 + Dilithium3, X25519 + Kyber-1024),
            generated entirely in your browser and never sent to us.
          </p>
          {error && <p className="mt-4 text-sm text-danger">{error}</p>}
        </div>
      ) : (
        <div className="text-center">
          <RingedAvatar seed={userId} />
          <h1 className="mt-6 text-2xl font-semibold">This is you</h1>
          <p className="mt-2 text-sm text-text-secondary">
            Your device just generated these keys. Nobody assigned this to you.
          </p>
          <button
            type="button"
            onClick={() => copy(userId)}
            title="Click to copy"
            className="mx-auto mt-5 block w-full break-all rounded-lg border border-divider bg-elevated p-3 text-center font-mono text-xs text-accent-subtle transition-colors hover:text-accent-hover"
          >
            {userId}
          </button>
          <p className="mt-2 text-xs text-text-muted">{copied ? "Copied" : "Tap to copy — share it so people can reach you."}</p>
          <button
            onClick={() => onDone(userId)}
            className="mt-8 w-full rounded-lg bg-accent py-3 font-medium text-white transition-colors hover:bg-accent-hover"
          >
            Continue
          </button>
        </div>
      )}
    </Shell>
  );
}

// --- STEP 3: register (PoW) ---
function Registering({
  onDone,
  onError,
  error,
  onBack,
}: {
  onDone: () => void;
  onError: (e: string) => void;
  error: string | null;
  onBack: () => void;
}) {
  const [percent, setPercent] = useState(0);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void (async () => {
      try {
        await completeRegistration(setPercent);
        onDone();
      } catch {
        onError("Registration failed. Check your connection and try again.");
      }
    })();
  }, [onDone, onError]);

  if (error) {
    return (
      <Shell step={3}>
        <div className="text-center">
          <span className="inline-flex text-danger">
            <WarningTriangleIcon className="h-10 w-10" />
          </span>
          <h1 className="mt-4 text-xl font-semibold">Registration failed</h1>
          <p className="mt-3 text-sm text-danger">{error}</p>
        </div>
        <button
          onClick={onBack}
          className="mt-8 w-full rounded-lg bg-accent py-3 font-medium text-white transition-colors hover:bg-accent-hover"
        >
          Try again
        </button>
      </Shell>
    );
  }

  return (
    <Shell step={3}>
      <div className="text-center">
        <ForgeIllustration />
        <h1 className="mt-6 text-xl font-semibold">Setting you up</h1>
        <p className="mx-auto mt-3 max-w-xs text-sm leading-relaxed text-text-secondary">
          Solving a proof-of-work puzzle so registration never needs your IP address.
        </p>
      </div>
      <div className="mt-6 h-1.5 w-full overflow-hidden rounded bg-input">
        <div className="h-full bg-accent transition-all" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-1 text-center text-xs text-text-muted">{percent}% complete</p>
    </Shell>
  );
}

// --- STEP 4 (sub): password recovery ---
function PasswordStep({
  onSubmit,
  onBack,
  error,
}: {
  onSubmit: (pw: string) => Promise<void>;
  onBack: () => void;
  error: string | null;
}) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  // zxcvbn is ~400 kB - load it on demand here, not in the app's main bundle.
  const [scorer, setScorer] = useState<((pw: string) => number) | null>(null);
  useEffect(() => {
    void import("zxcvbn").then((m) => setScorer(() => (p: string) => m.default(p).score));
  }, []);
  const score = scorer && pw ? scorer(pw) : 0;
  const strongEnough = scorer !== null && score >= 3;
  const matches = pw.length > 0 && pw === confirm;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const colors = ["bg-password-weak", "bg-password-fair", "bg-password-good", "bg-password-strong", "bg-password-vstrong"];

  async function submit() {
    setBusy(true);
    try {
      await onSubmit(pw);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell step={4}>
      <button onClick={onBack} disabled={busy} className="inline-flex items-center gap-1 text-sm text-text-muted transition-colors hover:text-text-secondary disabled:opacity-40">
        <ArrowLeftIcon className="h-4 w-4" /> Back
      </button>
      <h1 className="mt-3 text-xl font-semibold">Password recovery</h1>
      <p className="mt-2 text-sm text-text-secondary">
        Recover your account on a new device with just a password. We store a scrambled record only
        your password can unlock — we can&rsquo;t read it.
      </p>

      <label className="mt-6 block text-sm text-text-secondary">Password</label>
      <input
        type="password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
        minLength={8}
        autoComplete="new-password"
        className="mt-1 w-full rounded-lg border border-border-strong bg-input px-3 py-2 outline-none focus:border-border-focus"
      />
      {pw && scorer && (
        <div className="mt-2">
          <div className="h-1.5 w-full overflow-hidden rounded bg-input">
            <div className={`h-full ${colors[score]}`} style={{ width: `${(score + 1) * 20}%` }} />
          </div>
          <p className="mt-1 text-xs text-text-secondary">
            {labels[score]}
            {!strongEnough && " - needs to be Strong or better"}
          </p>
        </div>
      )}

      <label className="mt-4 block text-sm text-text-secondary">Confirm password</label>
      <input
        type="password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="new-password"
        className="mt-1 w-full rounded-lg border border-border-strong bg-input px-3 py-2 outline-none focus:border-border-focus"
      />
      {confirm && !matches && <p className="mt-1 text-xs text-danger">Passwords don&rsquo;t match.</p>}

      <button
        disabled={busy || !strongEnough || !matches}
        onClick={() => void submit()}
        className="mt-8 w-full rounded-lg bg-accent py-3 font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
      >
        {busy ? "Enabling…" : "Enable password recovery"}
      </button>
      {error && <p className="mt-3 text-sm text-danger">{error}</p>}
    </Shell>
  );
}

// --- STEP 4: secure your account (recovery) ---
function RecoveryStep({
  userId,
  onPasswordRecovery,
  onDone,
  onError,
  error,
}: {
  userId: string;
  onPasswordRecovery: () => void;
  onDone: () => void;
  onError: (e: string) => void;
  error: string | null;
}) {
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [hasPassword, setHasPassword] = useState(false);
  const [mode, setMode] = useState<"choose" | "seed">("choose");
  const [revealed, setRevealed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [seedDone, setSeedDone] = useState(false);
  const [indices, setIndices] = useState<number[]>([]);
  const [answers, setAnswers] = useState<string[]>(["", "", ""]);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [finishing, setFinishing] = useState(false);

  useEffect(() => {
    void loadBundle().then((b) => setMnemonic(b?.mnemonic ?? ""));
    void opaqueRecoveryStatus().then(setHasPassword).catch(() => setHasPassword(false));
  }, []);

  async function finish() {
    setFinishing(true);
    try {
      await finishOnboarding();
      onDone();
    } catch {
      onError("Could not complete sign-in. Please try again.");
      setFinishing(false);
    }
  }

  function startConfirm() {
    setIndices(pickConfirmIndices(24));
    setAnswers(["", "", ""]);
    setConfirmError(null);
    setConfirming(true);
  }

  function submitConfirm() {
    if (mnemonic && checkConfirm(mnemonic, indices, answers)) {
      setSeedDone(true);
      void db.settings.put({ key: "recovery_seed_saved", value: true }); // FinishSetup home checklist
      void finish();
    } else {
      setConfirmError("Those words don't match. Check your written copy.");
    }
  }

  const words = mnemonic ? mnemonic.trim().split(/\s+/) : [];
  const hasAnyRecovery = hasPassword || seedDone;

  // Seed sub-view: reveal → confirm.
  if (mode === "seed") {
    return (
      <Shell step={4}>
        <button
          onClick={() => { setMode("choose"); setRevealed(false); setConfirming(false); }}
          className="inline-flex items-center gap-1 text-sm text-text-muted transition-colors hover:text-text-secondary"
        >
          <ArrowLeftIcon className="h-4 w-4" /> Back
        </button>
        <h1 className="mt-3 text-xl font-semibold">Your seed phrase</h1>
        {!revealed ? (
          <>
            <p className="mt-2 text-sm text-text-secondary">
              24 words that <em>are</em> your account. Write them down and keep them offline — we
              will never show them again, and never ask for them.
            </p>
            <button
              onClick={() => setRevealed(true)}
              className="mt-6 w-full rounded-lg bg-raised py-3 text-sm font-medium transition-colors hover:bg-border-strong"
            >
              Reveal seed phrase
            </button>
          </>
        ) : !confirming ? (
          <>
            <div className="mt-4 grid grid-cols-3 gap-2">
              {words.map((w, i) => (
                <div key={i} className="rounded bg-elevated px-2 py-1 font-mono text-xs">
                  <span className="mr-1 text-text-subtle">{i + 1}</span>
                  {w}
                </div>
              ))}
            </div>
            <p className="mt-3 text-xs text-warning">Store these somewhere safe before continuing.</p>
            <button
              onClick={startConfirm}
              className="mt-4 w-full rounded-lg bg-accent py-3 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
            >
              I&rsquo;ve written them down
            </button>
          </>
        ) : (
          <>
            <p className="mt-3 text-sm text-text-secondary">Confirm a few words to make sure you have them:</p>
            <div className="mt-3 space-y-2">
              {indices.map((pos, i) => (
                <div key={pos} className="flex items-center gap-2">
                  <span className="w-16 text-sm text-text-muted">Word #{pos}</span>
                  <input
                    value={answers[i]}
                    onChange={(e) => setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))}
                    maxLength={8}
                    spellCheck={false}
                    autoCapitalize="none"
                    className="flex-1 rounded border border-border-strong bg-input px-2 py-1 text-sm outline-none focus:border-border-focus"
                  />
                </div>
              ))}
            </div>
            {confirmError && <p className="mt-2 text-xs text-danger">{confirmError}</p>}
            <button
              onClick={submitConfirm}
              disabled={finishing}
              className="mt-4 w-full rounded-lg bg-accent py-3 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-40"
            >
              {finishing ? "Finishing…" : "Confirm & finish"}
            </button>
          </>
        )}
        {error && <p className="mt-3 text-sm text-danger">{error}</p>}
      </Shell>
    );
  }

  // Choose view.
  const Option = ({
    icon,
    title,
    desc,
    onClick,
    done,
    tag,
    disabled,
  }: {
    icon: ReactNode;
    title: string;
    desc: string;
    onClick?: () => void;
    done?: boolean;
    tag?: string;
    disabled?: boolean;
  }) => (
    <button
      onClick={onClick}
      disabled={disabled}
      className={
        "flex w-full items-center gap-3 rounded-xl border p-3 text-left transition-colors " +
        (done
          ? "border-success bg-elevated"
          : disabled
            ? "cursor-default border-divider opacity-70"
            : "border-divider hover:border-border-strong hover:bg-elevated")
      }
    >
      <span className={"inline-flex shrink-0 " + (done ? "text-success" : "text-accent-text")}>
        {done ? <CheckIcon className="h-5 w-5" /> : icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="text-sm font-medium">{title}</span>
          {tag && (
            <span className="rounded-full bg-accent-bg px-2 py-0.5 text-[10px] font-medium text-accent-text">{tag}</span>
          )}
        </span>
        <span className="mt-0.5 block text-xs text-text-muted">{done ? "Set up" : desc}</span>
      </span>
    </button>
  );

  return (
    <Shell step={4}>
      <div className="text-center">
        <span className="inline-flex text-accent-text">
          <KeyIcon className="h-10 w-10" />
        </span>
        <h1 className="mt-4 text-2xl font-semibold">How do you get back in?</h1>
        <p className="mx-auto mt-2 max-w-xs text-sm text-text-secondary">
          If you lose this device, one of these is how you recover your account. Set up at least one.
        </p>
      </div>

      <div className="mt-6 space-y-2.5">
        <Option
          icon={<LockIcon className="h-5 w-5" />}
          title="Password"
          desc="Recover with a password only you know."
          tag="Recommended"
          done={hasPassword}
          onClick={hasPassword ? undefined : onPasswordRecovery}
        />
        <Option
          icon={<KeyIcon className="h-5 w-5" />}
          title="Seed phrase"
          desc="24 words you keep offline."
          done={seedDone}
          onClick={() => setMode("seed")}
        />
        <Option
          icon={<ShieldCheckIcon className="h-5 w-5" />}
          title="Emergency contacts"
          desc="Split a recovery key across trusted friends — set up in Settings once you have contacts."
          disabled
        />
      </div>

      {!hasAnyRecovery && (
        <p className="mt-4 inline-flex items-start gap-1.5 text-xs text-warning">
          <WarningTriangleIcon className="mt-px h-3.5 w-3.5 shrink-0" />
          Without a recovery method, a lost device means a lost account.
        </p>
      )}
      {error && <p className="mt-3 text-sm text-danger">{error}</p>}

      <button
        onClick={() => void finish()}
        disabled={finishing}
        className={
          "mt-6 w-full rounded-lg py-3 text-sm font-medium transition-colors disabled:opacity-40 " +
          (hasAnyRecovery
            ? "bg-accent text-white hover:bg-accent-hover"
            : "border border-border-strong text-text-secondary hover:bg-elevated")
        }
      >
        {finishing ? "Finishing…" : hasAnyRecovery ? "Continue" : "Skip for now"}
      </button>
      {/* userId shown small for reassurance/copy parity with the reveal step */}
      {userId && <p className="mt-4 text-center font-mono text-[11px] text-text-subtle break-all">{userId}</p>}
    </Shell>
  );
}

// --- STEP 5: safety orientation (post-signin, shown once) ---
function SafetyStep({ onEnter }: { onEnter: () => void }) {
  const Card = ({
    icon,
    title,
    children,
  }: {
    icon: ReactNode;
    title: string;
    children: ReactNode;
  }) => (
    <div className="flex gap-3 rounded-xl border border-divider p-4">
      <span className="inline-flex shrink-0 text-accent-text">{icon}</span>
      <div>
        <div className="text-sm font-medium">{title}</div>
        <p className="mt-0.5 text-xs leading-relaxed text-text-muted">{children}</p>
      </div>
    </div>
  );

  return (
    <Shell step={5}>
      <div className="text-center">
        <span className="inline-flex text-success">
          <ShieldCheckIcon className="h-12 w-12" />
        </span>
        <h1 className="mt-4 text-2xl font-semibold">You&rsquo;re in</h1>
        <p className="mt-2 text-sm text-text-secondary">A few things Privex already does for you — and one worth turning on.</p>
      </div>

      <div className="mt-6 space-y-3">
        <Card icon={<ShieldCheckIcon className="h-5 w-5" />} title="Privacy is already on">
          Read and delivery receipts are off by default, your IP is never logged, and steady cover
          traffic hides when you&rsquo;re active. You didn&rsquo;t have to configure any of it.
        </Card>
        <Card icon={<LockIcon className="h-5 w-5" />} title="Lock this app">
          Add a passphrase or fingerprint so your messages can&rsquo;t be read from this device if it&rsquo;s
          lost or shared. Turn it on in <span className="text-accent-text">Settings → Account</span>.
        </Card>
        <Card icon={<KeyIcon className="h-5 w-5" />} title="Recovery &amp; backups live here">
          Change how you recover your account — and optionally back up your chat history — anytime in
          <span className="text-accent-text"> Settings → Recovery</span>.
        </Card>
      </div>

      <button
        onClick={onEnter}
        className="mt-8 w-full rounded-lg bg-accent py-3 font-medium text-white transition-colors hover:bg-accent-hover"
      >
        Enter Privex
      </button>
    </Shell>
  );
}
