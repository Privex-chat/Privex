// Settings: account+security, privacy, recovery, guide, about (docs 9). Tabbed layout
// so users aren't buried in one long scroll. Most state is local (IndexedDB settings
// table) or derived from the stored identity.
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useAuth } from "../store/auth";
import { db } from "../db";
import { loadBundle } from "../onboarding/store";
import { listContacts } from "../data/contacts";
import type { PlainContact } from "../db/encrypted-db";
import {
  disableOpaqueRecovery,
  enableOpaqueRecovery,
  opaqueRecoveryStatus,
  setupEmergencyContacts,
  RECOVERY_CONTACTS_KEY,
} from "../services/recovery";
import {
  addBiometric,
  disableLock,
  enableWithPassphrase,
  lock,
  lockStatus,
  MIN_PASSPHRASE,
  removeBiometric,
  type LockStatus,
} from "../services/applock";
import {
  backfillAll,
  backupStatus,
  disableBackup,
  enableBackup,
  isBackupEnabled,
  restoreHistory,
} from "../services/history-backup";
import {
  deliveryReceiptsEnabled,
  readReceiptsEnabled,
  receiptPrivacyDelayEnabled,
  setDeliveryReceipts,
  setReadReceipts,
  setReceiptPrivacyDelay,
} from "../services/receipts";
import {
  deviceSyncEnabled,
  listLinkedDevices,
  removeLinkedDevice,
  setDeviceSyncEnabled,
  type LinkedDeviceInfo,
} from "../services/device-sync";
import { eraseThisDevice as eraseThisDeviceSvc, logoutEverywhere as logoutEverywhereSvc } from "../services/session";
import ThemeToggle from "../components/ThemeToggle";
import { useScreenRecord } from "../store/screenRecord";
import {
  isNotificationEnabled,
  setNotificationEnabled,
  requestPermissionAndSubscribe,
} from "../services/notifications";

const HISTORY_WARNING =
  "Store encrypted chat history on Privex servers so you can restore it on a new device " +
  "without your old device online. Your messages are encrypted with a key only you hold - " +
  "Privex cannot read them.\n\n" +
  "Trade-off: your encrypted history stays on our servers while this is on (turning it off " +
  "deletes it immediately). A backup means your past messages could be exposed if someone " +
  "gains access to your password or device - the encryption is real, but the data then exists " +
  "in more places. Not recommended if your threat model includes targeted surveillance.\n\n" +
  "Turn on history backup?";

const APP_VERSION = "0.1.0 (Phase 1)";
const COVER_KEY = "cover_traffic";

type SettingsTab = "account" | "privacy" | "recovery" | "guide" | "about";

const TABS: { key: SettingsTab; label: string }[] = [
  { key: "account", label: "Account" },
  { key: "privacy", label: "Privacy" },
  { key: "recovery", label: "Recovery" },
  { key: "guide", label: "Guide" },
  { key: "about", label: "About" },
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-6">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-text-muted">{title}</h2>
      <div className="mt-2 rounded-xl border border-divider divide-y divide-divider">{children}</div>
    </section>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return <div className="px-4 py-3">{children}</div>;
}

const VALID_TABS: SettingsTab[] = ["account", "privacy", "recovery", "guide", "about"];

export default function Settings() {
  const nav = useNavigate();
  const { tab: rawTab } = useParams();
  const tab: SettingsTab =
    rawTab && VALID_TABS.includes(rawTab as SettingsTab) ? (rawTab as SettingsTab) : "account";
  const pxId = useAuth((s) => s.userId) ?? "";

  // Redirect invalid tab to account
  useEffect(() => {
    if (rawTab && tab !== rawTab) nav(`/settings/${tab}`, { replace: true });
  }, [rawTab, tab, nav]);

  const [cover, setCover] = useState<string>("medium");
  const [hasContacts, setHasContacts] = useState(false);
  const [hasSeed, setHasSeed] = useState(false);
  const [opaqueEnabled, setOpaqueEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    void db.settings.get(COVER_KEY).then((r) => r && setCover(r.value as string));
    void db.settings.get(RECOVERY_CONTACTS_KEY).then((r) => setHasContacts(!!r));
    void loadBundle().then((b) => setHasSeed(!!b?.mnemonic));
    void opaqueRecoveryStatus().then(setOpaqueEnabled).catch(() => setOpaqueEnabled(null));
  }, []);

  function setCoverLevel(v: string) {
    setCover(v);
    void db.settings.put({ key: COVER_KEY, value: v });
  }

  return (
    <main className="min-h-screen bg-surface text-text-primary">
      <div className="mx-auto w-full max-w-2xl px-4 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => nav("/")}
              className="flex h-9 w-9 items-center justify-center rounded-full text-lg text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
              title="Back"
            >
              ←
            </button>
            <h1 className="text-2xl font-semibold">Settings</h1>
          </div>
        </div>

        {/* Tab bar */}
        <nav className="mt-5 flex gap-1 border-b border-divider text-sm">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => nav(`/settings/${t.key}`)}
              className={
                "-mb-px border-b-2 px-4 py-2.5 transition-colors " +
                (tab === t.key
                  ? "border-border-focus text-text-primary"
                  : "border-transparent text-text-secondary hover:text-text")
              }
            >
              {t.label}
            </button>
          ))}
        </nav>

        {/* Tab content */}
        <div className="mt-6">
          {tab === "account" && <AccountSecurityTab pxId={pxId} />}
          {tab === "privacy" && <PrivacyTab cover={cover} setCoverLevel={setCoverLevel} />}
          {tab === "recovery" && (
            <RecoveryTab
              opaqueEnabled={opaqueEnabled}
              setOpaqueEnabled={setOpaqueEnabled}
              hasSeed={hasSeed}
              hasContacts={hasContacts}
              setHasContacts={setHasContacts}
            />
          )}
          {tab === "guide" && <GuideTab />}
          {tab === "about" && <AboutTab />}
        </div>
      </div>
    </main>
  );
}

/* ───────── Tab: Account + Security ───────── */
function AccountSecurityTab({ pxId }: { pxId: string }) {
  return (
    <>
      <Section title="Account">
        <Row>
          <div className="text-sm text-text-secondary">Your Privex ID</div>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 break-all font-mono text-xs text-accent-subtle">{pxId}</code>
            <button
              onClick={() => void navigator.clipboard?.writeText(pxId)}
              className="rounded bg-raised hover:bg-border-strong px-2 py-1 text-xs"
            >
              Copy
            </button>
          </div>
        </Row>
      <Row>
          <ThemeToggle />
        </Row>
      </Section>

      <Section title="Security">
        <Row>
          <Link to="/" className="text-sm text-accent-text hover:underline">
            Verify contacts &amp; safety codes
          </Link>
          <p className="text-xs text-text-muted">Compare codes in a chat&rsquo;s ⚠ badge.</p>
        </Row>
        <Row>
          <AppLockToggle />
        </Row>
        <Row>
          <ActiveSessions />
        </Row>
        <Row>
          <EraseDevice />
        </Row>
      </Section>
    </>
  );
}

/* ───────── Tab: Privacy ───────── */
function PrivacyTab({
  cover,
  setCoverLevel,
}: {
  cover: string;
  setCoverLevel: (v: string) => void;
}) {
  const screenRecord = useScreenRecord((s) => s.enabled);
  const setScreenRecord = useScreenRecord((s) => s.setEnabled);
  const init = useScreenRecord((s) => s.init);
  const [notifOn, setNotifOn] = useState(true);

  useEffect(() => {
    void init();
  }, [init]);

  useEffect(() => {
    void isNotificationEnabled().then(setNotifOn);
  }, []);

  async function toggleNotification() {
    if (notifOn) {
      setNotifOn(false);
      await setNotificationEnabled(false);
    } else {
      const ok = await requestPermissionAndSubscribe();
      if (ok) setNotifOn(true);
    }
  }

  return (
    <Section title="Privacy">
      <Row>
        <label className="text-sm text-text-secondary">Cover traffic</label>
        <p className="text-xs text-text-muted">
          Sends steady fixed-size decoy messages so an observer can&rsquo;t tell from your
          traffic when you&rsquo;re really active. Higher = more protection,
          more battery/data. Off = no decoys (for metered data).
        </p>
        <select
          value={cover}
          onChange={(e) => setCoverLevel(e.target.value)}
          className="mt-2 w-full rounded-lg bg-input border border-border-strong px-3 py-2 text-sm outline-none focus:border-border-focus"
        >
          <option value="off">Off</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>
      </Row>
      <Row>
        <div className="flex items-center justify-between">
          <span className="text-sm text-text-secondary">Connection mode</span>
          <span className="text-sm text-text-muted">Direct</span>
        </div>
      </Row>
      <Row>
        <MessageStatusSettings />
      </Row>
      <Row>
        <label className="flex items-start justify-between gap-3 cursor-pointer">
          <span>
            <span className="block text-sm text-text-secondary">Push notifications</span>
            <span className="block text-xs text-text-muted">
              Receive alerts when messages arrive. When off, messages arrive only while
              Privex is open. No message content is ever shown in notifications — only
              &ldquo;You have a new message.&rdquo;
            </span>
          </span>
          <input
            type="checkbox"
            checked={notifOn}
            onChange={() => void toggleNotification()}
            className="mt-1 h-4 w-4 accent-accent-hover"
          />
        </label>
      </Row>
      <Row>
        <HistoryBackup />
      </Row>
      <Row>
        <label className="flex items-start justify-between gap-3 cursor-pointer">
          <span>
            <span className="block text-sm text-text-secondary">Screen recording protection</span>
            <span className="block text-xs text-text-muted">
              Blurs content when you switch away from Privex and overlays a discreet watermark
              to deter screen recording. This is a visual deterrent — it cannot prevent
              recording via external cameras or kernel-level capture.
            </span>
          </span>
          <input
            type="checkbox"
            checked={screenRecord}
            onChange={() => void setScreenRecord(!screenRecord)}
            className="mt-1 h-4 w-4 accent-accent-hover"
          />
        </label>
      </Row>
    </Section>
  );
}

/* ───────── Tab: Recovery ───────── */
function RecoveryTab({
  opaqueEnabled,
  setOpaqueEnabled,
  hasSeed,
  hasContacts,
  setHasContacts,
}: {
  opaqueEnabled: boolean | null;
  setOpaqueEnabled: (v: boolean) => void;
  hasSeed: boolean;
  hasContacts: boolean;
  setHasContacts: (v: boolean) => void;
}) {
  return (
    <Section title="Recovery">
      <Row>
        <RecoveryStatus
          opaqueEnabled={opaqueEnabled === true}
          hasSeed={hasSeed}
          hasContacts={hasContacts}
        />
      </Row>
      <Row>
        <OpaqueRecoveryToggle enabled={opaqueEnabled} onChanged={setOpaqueEnabled} />
      </Row>
      <Row>
        <SeedPhraseView />
      </Row>
      <Row>
        <EmergencyContacts onConfigured={() => setHasContacts(true)} />
      </Row>
      <Row>
        <Link to="/device-transfer" className="text-sm text-accent-text hover:underline">
          Transfer history to another device
        </Link>
        <p className="text-xs text-text-muted">
          Send your chat history directly to a new device (or receive it here). End-to-end
          encrypted, both devices online — nothing is stored on the server.
        </p>
      </Row>
      <Row>
        <DeviceSyncSettings />
      </Row>
    </Section>
  );
}

/* ───────── Tab: Guide ───────── */
function GuideTab() {
  return (
    <div className="space-y-6 text-sm text-text-secondary leading-relaxed">
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wide text-text-muted">Getting started</h2>
        <div className="mt-2 rounded-xl border border-divider divide-y divide-divider">
          <div className="px-4 py-3 space-y-2">
            <p>
              Privex is a zero-knowledge, end-to-end encrypted messenger. Your identity lives
              only on your device — the server cannot read messages, identify users, or trace
              relationships.
            </p>
          </div>
          <div className="px-4 py-3">
<h3 className="font-medium text-text">Adding contacts</h3>
            <ol className="mt-2 list-inside list-decimal space-y-1 text-text-secondary">
             <li>Share your Privex ID (px_…) with someone you want to chat with.</li>
             <li>Tap <span className="text-accent-text">+ Add contact</span> on the home screen and paste their Privex ID.</li>
              <li>Privex fetches their keys, verifies them against the key transparency log, and sets up an encrypted session.</li>
              <li>Compare safety codes over a separate channel (in person, phone call, another app).</li>
              <li>If the codes match, tap <strong>Mark Verified</strong> — you&rsquo;re ready to chat.</li>
            </ol>
          </div>
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">Sending messages &amp; files</h3>
            <p className="mt-1 text-text-secondary">
              Type in the composer at the bottom of a conversation and press Enter or tap Send.
              Use the paperclip icon to attach files (up to 100 MB). Drag-and-drop is also supported.
            </p>
          </div>
        </div>
      </section>

      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wide text-text-muted">Privacy &amp; settings guide</h2>
        <div className="mt-2 rounded-xl border border-divider divide-y divide-divider">
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">Cover traffic</h3>
            <p className="mt-1 text-text-secondary">
              Sends decoy messages at random intervals so an observer can&rsquo;t tell when you&rsquo;re
              actually active. <strong>Off</strong> = no decoys (saves battery/data). <strong>Low–High</strong> = increasing
              protection at the cost of more traffic. Recommended: <strong>Low</strong> or <strong>Medium</strong> for most users.
            </p>
          </div>
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">Delivery &amp; read receipts</h3>
            <p className="mt-1 text-text-secondary">
              Receipts are mutual — turning them off means you neither send nor receive them.
              Each receipt is end-to-end encrypted and carries no timestamp. The privacy delay
              adds a random jitter (avg 5 min) before your receipts send, useful for high-threat
              scenarios.
            </p>
          </div>
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">History backup</h3>
            <p className="mt-1 text-text-secondary">
              Off by default. When on, your encrypted message history is stored on Privex servers.
              Only you can decrypt it. The trade-off: your data exists in more places. Not
              recommended if your threat model includes targeted surveillance.
            </p>
          </div>
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">App lock</h3>
            <p className="mt-1 text-text-secondary">
              Encrypts this device&rsquo;s data behind a passphrase or biometrics. Required after
              reload or 5 min idle. This is a deterrent lock — a short passphrase is not
              offline-brute-force-proof. Recommended for anyone who shares their device.
            </p>
          </div>
          <div className="px-4 py-3">
            <h3 className="font-medium text-text">Recovery options</h3>
            <p className="mt-1 text-text-secondary">
              <strong>Password recovery (OPAQUE):</strong> Creates an encrypted server record. Off by default —
              the record becomes part of your server-side footprint. <br />
              <strong>Seed phrase:</strong> 24 words that are your master key. Store them offline.
              Privex never asks for them. <br />
              <strong>Emergency contacts:</strong> Split your recovery key across 2–3 trusted friends.
              Each share is useless alone; all shares together can restore your account.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

/* ───────── Tab: About ───────── */
function AboutTab() {
  return (
    <Section title="About">
      <Row>
        <div className="flex items-center justify-between text-sm">
          <span className="text-text-secondary">Version</span>
          <span className="text-text-secondary">{APP_VERSION}</span>
        </div>
      </Row>
      <Row>
        <div className="flex items-center justify-between text-sm">
          <span className="text-text-secondary">Source code</span>
          <span className="text-text-muted">github.com/Privex-chat/Privex</span>
        </div>
      </Row>
      <Row>
        <div className="flex items-center justify-between text-sm">
          <span className="text-text-secondary">Warrant canary</span>
          <span className="text-text-muted">privex.dpdns.org/canary</span>
        </div>
      </Row>
    </Section>
  );
}

function RecoveryStatus({
  opaqueEnabled,
  hasSeed,
  hasContacts,
}: {
  opaqueEnabled: boolean;
  hasSeed: boolean;
  hasContacts: boolean;
}) {
  const Item = ({ ok, label }: { ok: boolean; label: string }) => (
    <div className="flex items-center gap-2 text-sm">
      <span className={ok ? "text-success" : "text-text-subtle"}>{ok ? "✓" : "✗"}</span>
      <span className={ok ? "text-text" : "text-text-muted"}>{label}</span>
    </div>
  );
  return (
    <div className="space-y-1">
      <div className="text-sm text-text-secondary mb-1">Recovery methods</div>
      <Item ok={opaqueEnabled} label="Password recovery (OPAQUE)" />
      <Item ok={hasSeed} label="Seed phrase saved" />
      <Item ok={hasContacts} label="Emergency contacts" />
      <Item ok={false} label="Additional devices" />
    </div>
  );
}

function OpaqueRecoveryToggle({
  enabled,
  onChanged,
}: {
  enabled: boolean | null;
  onChanged: (enabled: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [scorer, setScorer] = useState<((pw: string) => number) | null>(null);

  useEffect(() => {
    if (open && !scorer) {
      void import("zxcvbn").then((m) => setScorer(() => (p: string) => m.default(p).score));
    }
  }, [open, scorer]);

  const score = scorer && pw ? scorer(pw) : 0;
  const strongEnough = scorer !== null && score >= 3;
  const matches = pw.length > 0 && pw === confirm;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const colors = ["bg-password-weak", "bg-password-fair", "bg-password-good", "bg-password-strong", "bg-password-vstrong"];

  async function enable() {
    setBusy("Enabling...");
    setError(null);
    setMsg(null);
    try {
      await enableOpaqueRecovery(pw);
      setPw("");
      setConfirm("");
      setOpen(false);
      onChanged(true);
      setMsg("Password recovery is on.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not enable password recovery.");
    } finally {
      setBusy(null);
    }
  }

  async function disable() {
    if (!window.confirm("Turn off password recovery and delete the server recovery record?")) return;
    setBusy("Deleting...");
    setError(null);
    setMsg(null);
    try {
      await disableOpaqueRecovery();
      onChanged(false);
      setOpen(false);
      setMsg("Password recovery is off.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not turn off password recovery.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-sm text-text-secondary">Password recovery</span>
        {enabled ? (
          <button
            onClick={() => void disable()}
            disabled={!!busy}
            className="rounded bg-danger-bg hover:bg-danger-hover disabled:opacity-40 px-2 py-1 text-xs"
          >
            {busy ?? "Turn off"}
          </button>
        ) : (
          <button
            onClick={() => setOpen((v) => !v)}
            disabled={!!busy || enabled === null}
            className="rounded bg-raised hover:bg-border-strong disabled:opacity-40 px-2 py-1 text-xs"
          >
            {open ? "Cancel" : "Turn on"}
          </button>
        )}
      </div>
      <p className="text-xs text-text-muted">
        Off means no OPAQUE recovery record exists on the server. On means password recovery is
        available, but the encrypted record becomes part of your server-side footprint.
      </p>
      {msg && <p className="mt-1 text-xs text-success">{msg}</p>}
      {open && !enabled && (
        <div className="mt-3 space-y-2">
          <input
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="new-password"
            placeholder="Recovery password"
            minLength={8}
            className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 text-sm outline-none focus:border-border-focus"
          />
          {pw && scorer && (
            <div>
              <div className="h-1.5 w-full rounded bg-input overflow-hidden">
                <div className={`h-full ${colors[score]}`} style={{ width: `${(score + 1) * 20}%` }} />
              </div>
<p className="mt-1 text-xs text-text-secondary">
                {labels[score]}
                {!strongEnough && " - needs to be Strong or better"}
              </p>
            </div>
          )}
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            placeholder="Confirm password"
            minLength={8}
            className="w-full rounded-lg bg-input border border-border-strong px-3 py-2 text-sm outline-none focus:border-border-focus"
          />
          {confirm && !matches && <p className="text-xs text-danger">Passwords don&rsquo;t match.</p>}
          <button
            onClick={() => void enable()}
            disabled={!!busy || !strongEnough || !matches}
            className="rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
          >
            {busy ?? "Enable"}
          </button>
        </div>
      )}
      {error && <p className="mt-1 text-xs text-danger">{error}</p>}
    </div>
  );
}

function SeedPhraseView() {
  const [words, setWords] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reveal() {
    if (!window.confirm("Anyone who sees these 24 words gains full access to your account. Show them?")) return;
    const b = await loadBundle();
    if (!b?.mnemonic) {
      setError("No seed phrase on this device (it isn't recoverable after a recovery).");
      return;
    }
    setWords(b.mnemonic.trim().split(/\s+/));
  }

  return (
    <div>
      <div className="text-sm text-text-secondary">Recovery seed phrase</div>
      {!words ? (
        <>
          {error && <p className="mt-1 text-xs text-danger">{error}</p>}
          <button onClick={() => void reveal()} className="mt-2 rounded-lg bg-raised hover:bg-border-strong px-3 py-1.5 text-sm">
            View seed phrase
          </button>
        </>
      ) : (
        <>
          <div className="mt-2 grid grid-cols-3 gap-2">
            {words.map((w, i) => (
              <div key={i} className="rounded bg-elevated px-2 py-1 text-xs font-mono">
                <span className="text-text-subtle mr-1">{i + 1}</span>
                {w}
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-warning">Store these offline. We will never ask for them.</p>
          <button onClick={() => setWords(null)} className="mt-2 text-xs text-text-muted hover:text-text-secondary">Hide</button>
        </>
      )}
    </div>
  );
}

function EmergencyContacts({ onConfigured }: { onConfigured: () => void }) {
  const [contacts, setContacts] = useState<PlainContact[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) void listContacts().then((c) => setContacts(c.filter((x) => x.ik_x25519.length > 0)));
  }, [open]);

  function toggle(id: string) {
    setPicked((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else if (next.size < 3) next.add(id);
      return next;
    });
  }

  async function setup() {
    setBusy(true);
    setError(null);
    try {
      const chosen = contacts.filter((c) => picked.has(c.px_id));
      const n = await setupEmergencyContacts(chosen);
      setMsg(`${n} contacts now hold your recovery shares.`);
      onConfigured();
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not set up recovery contacts.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="text-sm text-text-secondary">Emergency contacts</div>
      <p className="text-xs text-text-muted">Split your recovery key across 2–3 trusted friends.</p>
      {msg && <p className="mt-1 text-xs text-success">{msg}</p>}
      {!open ? (
        <button onClick={() => setOpen(true)} className="mt-2 rounded-lg bg-raised hover:bg-border-strong px-3 py-1.5 text-sm">
          Choose contacts
        </button>
      ) : (
        <div className="mt-2">
          {contacts.length === 0 ? (
            <p className="text-xs text-text-muted">No eligible contacts yet.</p>
          ) : (
            <ul className="space-y-1 max-h-40 overflow-y-auto">
              {contacts.map((c) => (
                <li key={c.px_id}>
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={picked.has(c.px_id)} onChange={() => toggle(c.px_id)} />
                    <span className="truncate">{c.name || c.px_id}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          {error && <p className="mt-1 text-xs text-danger">{error}</p>}
          <div className="mt-2 flex gap-2">
            <button
              disabled={busy || picked.size < 2}
              onClick={() => void setup()}
              className="rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 px-3 py-1.5 text-sm"
            >
              {busy ? "Storing…" : `Protect with ${picked.size} contacts`}
            </button>
            <button onClick={() => setOpen(false)} className="rounded-lg border border-border-strong px-3 py-1.5 text-sm">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

/** Cross-device sync (docs 4.11 Mode C). OPT-IN, default OFF: each sent message
 *  also produces a self-addressed encrypted copy per linked device - the server
 *  can't read it, but the extra self-traffic is an observable pattern, so the
 *  user must choose it. Linking happens during a device transfer when BOTH
 *  devices have this on. */
function DeviceSyncSettings() {
  const [enabled, setEnabled] = useState(false);
  const [devices, setDevices] = useState<LinkedDeviceInfo[]>([]);

  const reload = () => void listLinkedDevices().then(setDevices);
  useEffect(() => {
    void deviceSyncEnabled().then(setEnabled);
    reload();
  }, []);

  async function toggle(on: boolean) {
    setEnabled(on);
    await setDeviceSyncEnabled(on);
  }

  async function unlink(id: string) {
    if (!window.confirm("Unlink this device? It will stop receiving your sent messages.")) return;
    await removeLinkedDevice(id);
    reload();
  }

  return (
    <div>
      <label className="flex items-start justify-between gap-3 cursor-pointer">
        <span>
          <span className="block text-sm text-text-secondary">Cross-device sync</span>
          <span className="block text-xs text-text-muted">
            Messages you send also appear on your linked devices, as end-to-end encrypted
            copies routed through your own mailbox. Off by default: the extra self-addressed
            traffic is visible to the server as a pattern (not content).
          </span>
        </span>
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => void toggle(e.target.checked)}
          className="mt-1 h-4 w-4 accent-accent-hover"
        />
      </label>
      {enabled && (
        <div className="mt-2">
          <div className="text-xs text-text-secondary">
            Linked devices {devices.length === 0 && "- none yet"}
          </div>
          {devices.length === 0 ? (
            <p className="text-xs text-text-muted">
              Run &ldquo;Transfer history&rdquo; with this setting ON on both devices to link them.
            </p>
          ) : (
            <ul className="mt-1 space-y-1">
              {devices.map((d) => (
                <li key={d.device_id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-text-secondary">
                    {d.label}
                    <span className="ml-2 font-mono text-text-subtle">{d.device_id.slice(0, 8)}…</span>
                  </span>
                  <button
                    onClick={() => void unlink(d.device_id)}
                    className="rounded px-2 py-0.5 text-danger hover:bg-raised"
                  >
                    Unlink
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/** Message Status (docs 4.10). Both receipt toggles are MUTUAL: turning one off
 *  means you neither send that receipt type nor receive it (your outgoing messages
 *  stop carrying a receipt request, so peers have nothing to confirm). */
function MessageStatusSettings() {
  const [delivery, setDelivery] = useState(true);
  const [read, setRead] = useState(true);
  const [delay, setDelay] = useState(false);

  useEffect(() => {
    void deliveryReceiptsEnabled().then(setDelivery);
    void readReceiptsEnabled().then(setRead);
    void receiptPrivacyDelayEnabled().then(setDelay);
  }, []);

  const Toggle = ({
    label,
    hint,
    value,
    onChange,
  }: {
    label: string;
    hint: string;
    value: boolean;
    onChange: (v: boolean) => void;
  }) => (
    <label className="flex items-start justify-between gap-3 py-1.5 cursor-pointer">
      <span>
        <span className="block text-sm text-text-secondary">{label}</span>
        <span className="block text-xs text-text-muted">{hint}</span>
      </span>
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 accent-accent-hover"
      />
    </label>
  );

  return (
    <div>
      <div className="text-sm text-text-secondary">Message status</div>
      <p className="text-xs text-text-muted">
        Receipts are end-to-end encrypted, carry no timestamps, and are mutual - each
        toggle applies to both sending and receiving.
      </p>
      <div className="mt-2">
        <Toggle
          label="Delivery receipts"
          hint="Show ✓✓ when your message reaches the recipient's device."
          value={delivery}
          onChange={(v) => {
            setDelivery(v);
            void setDeliveryReceipts(v);
          }}
        />
        <Toggle
          label="Read receipts"
          hint="Show when your message has been viewed. Delivered ≠ read."
          value={read}
          onChange={(v) => {
            setRead(v);
            void setReadReceipts(v);
          }}
        />
        <Toggle
          label="Receipt privacy delay"
          hint="Extra random delay (avg 5 min) before your receipts send. For high-threat use."
          value={delay}
          onChange={(v) => {
            setDelay(v);
            void setReceiptPrivacyDelay(v);
          }}
        />
      </div>
    </div>
  );
}

function HistoryBackup() {
  const [enabled, setEnabled] = useState(false);
  const [status, setStatus] = useState<{ count: number; bytes: number } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    void isBackupEnabled().then(setEnabled);
    void backupStatus().then(setStatus).catch(() => setStatus(null));
  };
  useEffect(refresh, []);

  async function toggle() {
    setError(null);
    try {
      if (enabled) {
        if (!window.confirm("Turn off backup and delete all history stored on the server? This is immediate and permanent.")) return;
        setBusy("Deleting…");
        await disableBackup();
      } else {
        if (!window.confirm(HISTORY_WARNING)) return;
        setBusy("Backing up…");
        await enableBackup();
      }
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed.");
    } finally {
      setBusy(null);
    }
  }

  async function run(label: string, fn: () => Promise<unknown>, reload = false) {
    setError(null);
    setBusy(label);
    try {
      await fn();
      if (reload) location.reload();
      else refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-sm text-text-secondary">Chat history backup</span>
        <button
          onClick={() => void toggle()}
          disabled={!!busy}
          className={
            "rounded px-2 py-1 text-xs disabled:opacity-40 " +
            (enabled ? "bg-danger-bg hover:bg-danger-hover" : "bg-raised hover:bg-border-strong")
          }
        >
          {busy ?? (enabled ? "Turn off" : "Turn on")}
        </button>
      </div>
      <p className="text-xs text-text-muted">
        Off by default. Encrypted with a key only you hold - the server can&rsquo;t read it. While on, your
        encrypted history lives on our servers; a backup means it exists in more places. Not for
        targeted-surveillance threat models.
      </p>
      {status && status.count > 0 && (
        <p className="mt-1 text-xs text-text-secondary">
          {status.count} messages backed up ({Math.max(1, Math.round(status.bytes / 1024))} KB).
        </p>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        {enabled && (
          <button onClick={() => void run("Backing up…", () => backfillAll())} disabled={!!busy} className="rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 px-3 py-1.5 text-sm">
            Back up now
          </button>
        )}
        {status && status.count > 0 && (
          <button onClick={() => void run("Restoring…", () => restoreHistory(), true)} disabled={!!busy} className="rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 px-3 py-1.5 text-sm">
            Restore to this device
          </button>
        )}
      </div>
      {error && <p className="mt-1 text-xs text-danger">{error}</p>}
    </div>
  );
}

function AppLockToggle() {
  const pxId = useAuth((s) => s.userId) ?? "";
  const [st, setSt] = useState<LockStatus | null>(null);
  const [pass, setPass] = useState("");
  const [setting, setSetting] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = () => void lockStatus().then(setSt);
  useEffect(refresh, []);

  async function run(label: string, fn: () => Promise<unknown>, after?: () => void) {
    setBusy(label);
    setError(null);
    setMsg(null);
    try {
      await fn();
      after?.();
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed.");
    } finally {
      setBusy(null);
    }
  }

  if (!st) return null;

  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-sm text-text-secondary">App lock</span>
        {st.enabled ? (
          <button
            onClick={() => void run("Turning off…", () => disableLock())}
            disabled={!!busy}
            className="rounded bg-raised hover:bg-border-strong disabled:opacity-40 px-2 py-1 text-xs"
          >
            {busy ?? "Turn off"}
          </button>
        ) : (
          <button
            onClick={() => setSetting((s) => !s)}
            disabled={!!busy}
            className="rounded bg-raised hover:bg-border-strong disabled:opacity-40 px-2 py-1 text-xs"
          >
            {setting ? "Cancel" : "Set up"}
          </button>
        )}
      </div>
      <p className="text-xs text-text-muted">
        Encrypts this device&rsquo;s data behind a passphrase{st.biometricAvailable ? " or biometrics" : ""}. Required
        after a reload or 5&nbsp;min idle - your messages can&rsquo;t be read without it, even from device storage.
      </p>
      {msg && <p className="mt-1 text-xs text-success">{msg}</p>}

      {!st.enabled && setting && (
        <div className="mt-2 flex gap-2">
          <input
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            placeholder={`Passphrase (min ${MIN_PASSPHRASE})`}
            className="flex-1 rounded-lg border border-border-strong bg-input px-3 py-1.5 text-sm outline-none focus:border-border-focus"
          />
          <button
            disabled={!!busy || pass.length < MIN_PASSPHRASE}
            onClick={() =>
              void run("Encrypting…", () => enableWithPassphrase(pass), () => {
                setPass("");
                setSetting(false);
                setMsg("App lock on. Your data is encrypted behind your passphrase.");
              })
            }
            className="rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
          >
            {busy ?? "Enable"}
          </button>
        </div>
      )}

      {st.enabled && (
        <div className="mt-2 flex flex-wrap gap-2">
          {st.biometricAvailable && !st.biometric && (
            <button
              disabled={!!busy}
              onClick={() => void run("Setting up…", () => addBiometric(pxId), () => setMsg("Biometric unlock added."))}
              className="rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 px-3 py-1.5 text-sm"
            >
              Add biometrics
            </button>
          )}
          {st.biometric && (
            <button
              disabled={!!busy}
              onClick={() => void run("Removing…", () => removeBiometric())}
              className="rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 px-3 py-1.5 text-sm"
            >
              Remove biometrics
            </button>
          )}
          <button
            disabled={!!busy}
            onClick={() => {
              lock();
              location.reload();
            }}
            className="rounded-lg bg-raised hover:bg-border-strong disabled:opacity-40 px-3 py-1.5 text-sm"
          >
            Lock now
          </button>
        </div>
      )}
      {error && <p className="mt-1 text-xs text-danger">{error}</p>}
    </div>
  );
}

/** Erase this device (16E follow-up): a full LOCAL reset. Irreversible without
 *  recovery, so it takes an explicit typed confirmation. Runs ONLY from this
 *  button - never from an auth error / slow load (those re-authenticate instead). */
function EraseDevice() {
  const [busy, setBusy] = useState(false);

  async function erase() {
    const ok = window.confirm(
      "Erase this device?\n\n" +
        "This permanently deletes ALL local data on THIS device — messages, contacts, " +
        "and your identity key — and returns to the welcome screen.\n\n" +
        "This is IRREVERSIBLE. You can only get your account back if you have your " +
        "recovery phrase, your recovery password, or an enabled server backup. " +
        "Other devices are NOT affected.\n\n" +
        "Continue?",
    );
    if (!ok) return;
    // Second gate for an irreversible action.
    if (window.prompt('Type ERASE to confirm.') !== "ERASE") return;
    setBusy(true);
    try {
      await eraseThisDeviceSvc();
      location.reload(); // boot into a clean onboarding (no identity left)
    } catch {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="text-sm text-danger">Erase this device</div>
      <p className="text-xs text-text-muted">
        Permanently delete all data and your identity on this device, returning to a clean
        slate. Irreversible without your recovery phrase, password, or backup. Other devices
        are untouched.
      </p>
      <button
        onClick={() => void erase()}
        disabled={busy}
        className="mt-2 rounded-lg border border-danger hover:bg-danger-subtle text-danger disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
      >
        {busy ? "Erasing…" : "Erase this device"}
      </button>
    </div>
  );
}

function ActiveSessions() {
  const token = useAuth((s) => s.sessionToken);
  const [busy, setBusy] = useState(false);

  async function logoutEverywhere() {
    if (!token) return;
    if (
      !window.confirm(
        "Log out of ALL devices? Every session token is revoked and your signed prekey is " +
          "rotated (forward secrecy). You'll sign back in on this device.",
      )
    )
      return;
    setBusy(true);
    try {
      await logoutEverywhereSvc(); // rotate SPK + revoke all tokens
      // Drop the (now-revoked) token; reload re-authenticates this device from the
      // stored keys with a fresh post-cutoff token.
      location.reload();
    } catch {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="text-sm text-text-secondary">Active sessions</div>
      <p className="text-xs text-text-muted">
        Tokens live in memory only and can&rsquo;t be listed. &ldquo;Log out everywhere&rdquo;
        revokes every device&rsquo;s token and rotates your signed prekey. It does NOT erase
        this device&rsquo;s data &mdash; use &ldquo;Erase this device&rdquo; below for that.
      </p>
      <button
        onClick={() => void logoutEverywhere()}
        disabled={busy}
        className="mt-2 rounded-lg bg-danger-bg hover:bg-danger-hover disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
      >
        {busy ? "Logging out…" : "Log out everywhere"}
      </button>
    </div>
  );
}
