// Registration + onboarding (docs 6 / 8.5). Six steps; progress is persisted so a
// closed browser resumes where it left off. All key material is generated in the
// browser (crypto worker) and never sent to the server in the clear.
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { completeRegistration, finishOnboarding, generateIdentity } from "../onboarding/flow";
import { loadBundle, loadProgress } from "../onboarding/store";
import { checkConfirm, pickConfirmIndices } from "../onboarding/seed-confirm";
import { enableOpaqueRecovery } from "../services/recovery";

type UiStep = "loading" | "welcome" | "keys" | "register" | "password" | "recovery";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 flex items-center justify-center p-6">
      <div className="w-full max-w-md">{children}</div>
    </main>
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
        userId={userId}
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
  return (
    <RecoveryStep
      onPasswordRecovery={() => {
        setError(null);
        setStep("password");
      }}
      onDone={() => nav("/", { replace: true })}
      onError={setError}
      error={error}
    />
  );
}

// --- STEP 1 ---
function Welcome({ onStart }: { onStart: () => void }) {
  return (
    <Shell>
      <h1 className="text-2xl font-semibold">Welcome to Privex</h1>
      <p className="mt-4 text-neutral-300 leading-relaxed">
        What you&rsquo;re about to create: an identity that only exists on your device.
        We never know who you are. Even if we wanted to, we couldn&rsquo;t.
      </p>
      <p className="mt-3 text-neutral-500 text-sm">No phone number. No email. No name.</p>
      <button
        onClick={onStart}
        className="mt-8 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium"
      >
        Create My Identity
      </button>
      <Link
        to="/recover"
        className="mt-4 block text-center text-sm text-neutral-400 hover:text-neutral-200"
      >
        Recover an existing account
      </Link>
    </Shell>
  );
}

// --- STEP 2 ---
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
    <Shell>
      {!userId ? (
        <>
          <div className="flex items-center gap-3">
            <Spinner />
            <h1 className="text-xl font-semibold">Generating your identity keys&hellip;</h1>
          </div>
          <p className="mt-4 text-neutral-400 text-sm">
            Ed25519 + Dilithium3 signing keys, X25519 + Kyber1024 for messaging. Entirely in your
            browser. Never sent to the server.
          </p>
          {error && <p className="mt-4 text-red-400 text-sm">{error}</p>}
        </>
      ) : (
        <>
          <h1 className="text-xl font-semibold">This is your Privex ID</h1>
          <p className="mt-4 break-all font-mono text-indigo-300 bg-neutral-900 rounded-lg p-3">
            {userId}
          </p>
          <p className="mt-3 text-neutral-400 text-sm">Share it with people to receive messages.</p>
          <button
            onClick={() => onDone(userId)}
            className="mt-8 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium"
          >
            Continue
          </button>
        </>
      )}
    </Shell>
  );
}

// --- STEP 3 ---
function PasswordStep({
  userId,
  onSubmit,
  onBack,
  error,
}: {
  userId: string;
  onSubmit: (pw: string) => Promise<void>;
  onBack: () => void;
  error: string | null;
}) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  // zxcvbn is ~400 kB - load it on demand here, not in the app's main bundle
  // (already-onboarded users never reach this step).
  const [scorer, setScorer] = useState<((pw: string) => number) | null>(null);
  useEffect(() => {
    void import("zxcvbn").then((m) => setScorer(() => (p: string) => m.default(p).score));
  }, []);
  const score = scorer && pw ? scorer(pw) : 0;
  const strongEnough = scorer !== null && score >= 3;
  const matches = pw.length > 0 && pw === confirm;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const colors = ["bg-red-600", "bg-orange-600", "bg-yellow-600", "bg-lime-600", "bg-green-600"];

  async function submit() {
    setBusy(true);
    try {
      await onSubmit(pw);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell>
      <h1 className="text-xl font-semibold">Enable password recovery</h1>
      <p className="mt-3 text-neutral-400 text-sm">
        This creates an encrypted server recovery record. Leave it off for maximum privacy.
      </p>
      {userId && <p className="mt-3 font-mono text-xs text-neutral-600 break-all">{userId}</p>}

      <label className="block mt-6 text-sm text-neutral-300">Password</label>
      <input
        type="password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
        autoComplete="new-password"
        minLength={8}
        className="mt-1 w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 outline-none focus:border-indigo-500"
      />
      {pw && scorer && (
        <div className="mt-2">
          <div className="h-1.5 w-full rounded bg-neutral-800 overflow-hidden">
            <div className={`h-full ${colors[score]}`} style={{ width: `${(score + 1) * 20}%` }} />
          </div>
          <p className="mt-1 text-xs text-neutral-400">
            {labels[score]}
            {!strongEnough && " - needs to be Strong or better"}
          </p>
        </div>
      )}

      <label className="block mt-4 text-sm text-neutral-300">Confirm password</label>
      <input
        type="password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="new-password"
        className="mt-1 w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 outline-none focus:border-indigo-500"
      />
      {confirm && !matches && <p className="mt-1 text-xs text-red-400">Passwords don&rsquo;t match.</p>}

      <button
        disabled={busy || !strongEnough || !matches}
        onClick={() => void submit()}
        className="mt-8 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 font-medium"
      >
        {busy ? "Enabling..." : "Enable password recovery"}
      </button>
      {error && <p className="mt-3 text-red-400 text-sm">{error}</p>}
      <button
        onClick={onBack}
        disabled={busy}
        className="mt-3 w-full rounded-lg border border-neutral-700 hover:bg-neutral-900 disabled:opacity-40 py-3 text-sm text-neutral-300"
      >
        Back
      </button>
    </Shell>
  );
}

// --- STEP 4 ---
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
      <Shell>
        <h1 className="text-xl font-semibold">Registration failed</h1>
        <p className="mt-3 text-red-400 text-sm">{error}</p>
        <button
          onClick={onBack}
          className="mt-8 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium"
        >
          Try again
        </button>
      </Shell>
    );
  }

  return (
    <Shell>
      <div className="flex items-center gap-3">
        <Spinner />
        <h1 className="text-xl font-semibold">Registering your identity&hellip;</h1>
      </div>
      <p className="mt-4 text-neutral-400 text-sm">
        Solving a proof-of-work puzzle so we never need your IP address.
      </p>
      <div className="mt-4 h-1.5 w-full rounded bg-neutral-800 overflow-hidden">
        <div className="h-full bg-indigo-500 transition-all" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-1 text-xs text-neutral-500">{percent}% complete</p>
    </Shell>
  );
}

// --- STEP 5 + 6 ---
function RecoveryStep({
  onPasswordRecovery,
  onDone,
  onError,
  error,
}: {
  onPasswordRecovery: () => void;
  onDone: () => void;
  onError: (e: string) => void;
  error: string | null;
}) {
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [indices, setIndices] = useState<number[]>([]);
  const [answers, setAnswers] = useState<string[]>(["", "", ""]);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [finishing, setFinishing] = useState(false);

  useEffect(() => {
    void (async () => {
      const b = await loadBundle();
      setMnemonic(b?.mnemonic ?? "");
    })();
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
    if (mnemonic && checkConfirm(mnemonic, indices, answers)) void finish();
    else setConfirmError("Those words don't match. Check your written copy.");
  }

  const words = mnemonic ? mnemonic.trim().split(/\s+/) : [];

  return (
    <Shell>
      <h1 className="text-2xl font-semibold">You&rsquo;re in.</h1>
      <p className="mt-2 text-neutral-400 text-sm">No name. No phone. No email. Just you.</p>
      <p className="mt-6 text-neutral-300 text-sm">Set up account recovery (you can do this later):</p>

      <div className="mt-4 rounded-xl border border-neutral-800 p-4">
        <p className="font-medium">Password recovery</p>
        <p className="mt-1 text-neutral-400 text-sm">
          Optional. Creates an encrypted server recovery record protected by your password.
        </p>
        <button
          onClick={onPasswordRecovery}
          className="mt-3 rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-sm"
        >
          Set up password recovery
        </button>
      </div>

      {/* Card A - multi-device linking (deferred to Phase 2: needs WebSocket fan-out) */}
      <div className="mt-4 rounded-xl border border-neutral-800 p-4 opacity-60">
        <p className="font-medium">Link another device</p>
        <p className="mt-1 text-neutral-400 text-sm">
          Transfer your account to another phone or computer. Available in a future update.
        </p>
      </div>

      {/* Card B - emergency contacts (needs contacts first; set up in Settings > Recovery) */}
      <div className="mt-3 rounded-xl border border-neutral-800 p-4 opacity-60">
        <p className="font-medium">Emergency contacts</p>
        <p className="mt-1 text-neutral-400 text-sm">
          Split your recovery key across trusted friends. Add contacts first, then set this up in Settings.
        </p>
      </div>

      {/* Card C - seed phrase (real) */}
      <div className="mt-3 rounded-xl border border-neutral-800 p-4">
        <p className="font-medium">Write down your seed phrase</p>
        {!revealed ? (
          <>
            <p className="mt-1 text-neutral-400 text-sm">
              24 words that are your master key. We will never show them again.
            </p>
            <button
              onClick={() => setRevealed(true)}
              className="mt-3 rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-sm"
            >
              Reveal seed phrase
            </button>
          </>
        ) : !confirming ? (
          <>
            <div className="mt-3 grid grid-cols-3 gap-2">
              {words.map((w, i) => (
                <div key={i} className="rounded bg-neutral-900 px-2 py-1 text-sm font-mono">
                  <span className="text-neutral-600 mr-1">{i + 1}</span>
                  {w}
                </div>
              ))}
            </div>
            <p className="mt-3 text-neutral-400 text-sm">
              Store these somewhere safe. This is your master key.
            </p>
            <button
              onClick={startConfirm}
              className="mt-3 rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-sm"
            >
              I&rsquo;ve written them down
            </button>
          </>
        ) : (
          <>
            <p className="mt-3 text-neutral-300 text-sm">Confirm these words to continue:</p>
            <div className="mt-2 space-y-2">
              {indices.map((pos, i) => (
                <div key={pos} className="flex items-center gap-2">
                  <span className="w-16 text-neutral-500 text-sm">Word #{pos}</span>
                  <input
                    value={answers[i]}
                    onChange={(e) =>
                      setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))
                    }
                    maxLength={8}
                    spellCheck={false}
                    autoCapitalize="none"
                    className="flex-1 rounded bg-neutral-900 border border-neutral-700 px-2 py-1 text-sm outline-none focus:border-indigo-500"
                  />
                </div>
              ))}
            </div>
            {confirmError && <p className="mt-2 text-xs text-red-400">{confirmError}</p>}
            <button
              onClick={submitConfirm}
              disabled={finishing}
              className="mt-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-4 py-2 text-sm"
            >
              Confirm &amp; finish
            </button>
          </>
        )}
      </div>

      {error && <p className="mt-4 text-red-400 text-sm">{error}</p>}

      <button
        onClick={() => void finish()}
        disabled={finishing}
        className="mt-6 w-full rounded-lg border border-neutral-700 hover:bg-neutral-900 disabled:opacity-40 py-3 text-sm text-neutral-300"
      >
        Skip for now - enter Privex
      </button>
    </Shell>
  );
}

function Spinner() {
  return (
    <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-neutral-600 border-t-indigo-400" />
  );
}
