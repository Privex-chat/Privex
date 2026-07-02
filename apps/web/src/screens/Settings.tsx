// Settings: account, privacy, recovery, security, about (docs 9). Most state is
// local (IndexedDB settings table) or derived from the stored identity. Recovery
// management (seed phrase, emergency contacts) and "log out everywhere" live here.
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-6">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">{title}</h2>
      <div className="mt-2 rounded-xl border border-neutral-800 divide-y divide-neutral-800">{children}</div>
    </section>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return <div className="px-4 py-3">{children}</div>;
}

export default function Settings() {
  const nav = useNavigate();
  const pxId = useAuth((s) => s.userId) ?? "";
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
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 p-6">
      <div className="mx-auto w-full max-w-md">
        <button onClick={() => nav("/")} className="text-sm text-neutral-500 hover:text-neutral-300">← Back</button>
        <h1 className="mt-3 text-2xl font-semibold">Settings</h1>

        <Section title="Account">
          <Row>
            <div className="text-sm text-neutral-400">Your Privex ID</div>
            <div className="mt-1 flex items-center gap-2">
              <code className="flex-1 break-all font-mono text-xs text-indigo-300">{pxId}</code>
              <button
                onClick={() => void navigator.clipboard?.writeText(pxId)}
                className="rounded bg-neutral-800 hover:bg-neutral-700 px-2 py-1 text-xs"
              >
                Copy
              </button>
            </div>
          </Row>
        </Section>

        <Section title="Privacy">
          <Row>
            <label className="text-sm text-neutral-300">Cover traffic</label>
            <p className="text-xs text-neutral-500">Decoy messages that hide when you&rsquo;re really active.</p>
            <select
              value={cover}
              onChange={(e) => setCoverLevel(e.target.value)}
              className="mt-2 w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-indigo-500"
            >
              <option value="off">Off</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </Row>
          <Row>
            <div className="flex items-center justify-between">
              <span className="text-sm text-neutral-300">Connection mode</span>
              <span className="text-sm text-neutral-500">Direct (onion routing soon)</span>
            </div>
          </Row>
          <Row>
            <MessageStatusSettings />
          </Row>
          <Row>
            <HistoryBackup />
          </Row>
        </Section>

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
            <Link to="/device-transfer" className="text-sm text-indigo-300 hover:underline">
              Transfer history to another device
            </Link>
            <p className="text-xs text-neutral-500">
              Send your chat history directly to a new device (or receive it here). End-to-end
              encrypted, both devices online - nothing is stored on the server.
            </p>
          </Row>
          <Row>
            <DeviceSyncSettings />
          </Row>
        </Section>

        <Section title="Security">
          <Row>
            <Link to="/" className="text-sm text-indigo-300 hover:underline">
              Verify contacts &amp; safety codes
            </Link>
            <p className="text-xs text-neutral-500">Compare codes in a chat&rsquo;s ⚠ badge.</p>
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

        <Section title="About">
          <Row>
            <div className="flex items-center justify-between text-sm">
              <span className="text-neutral-400">Version</span>
              <span className="text-neutral-300">{APP_VERSION}</span>
            </div>
          </Row>
          <Row>
            <div className="flex items-center justify-between text-sm">
              <span className="text-neutral-400">Source code</span>
              <span className="text-neutral-500">github.com/Privex-chat/Privex</span>
            </div>
          </Row>
          <Row>
            <div className="flex items-center justify-between text-sm">
              <span className="text-neutral-400">Warrant canary</span>
              <span className="text-neutral-500">privex.dpdns.org/canary</span>
            </div>
          </Row>
        </Section>
      </div>
    </main>
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
      <span className={ok ? "text-green-400" : "text-neutral-600"}>{ok ? "✓" : "✗"}</span>
      <span className={ok ? "text-neutral-200" : "text-neutral-500"}>{label}</span>
    </div>
  );
  return (
    <div className="space-y-1">
      <div className="text-sm text-neutral-400 mb-1">Recovery methods</div>
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
  const colors = ["bg-red-600", "bg-orange-600", "bg-yellow-600", "bg-lime-600", "bg-green-600"];

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
        <span className="text-sm text-neutral-300">Password recovery</span>
        {enabled ? (
          <button
            onClick={() => void disable()}
            disabled={!!busy}
            className="rounded bg-red-600/80 hover:bg-red-600 disabled:opacity-40 px-2 py-1 text-xs"
          >
            {busy ?? "Turn off"}
          </button>
        ) : (
          <button
            onClick={() => setOpen((v) => !v)}
            disabled={!!busy || enabled === null}
            className="rounded bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-2 py-1 text-xs"
          >
            {open ? "Cancel" : "Turn on"}
          </button>
        )}
      </div>
      <p className="text-xs text-neutral-500">
        Off means no OPAQUE recovery record exists on the server. On means password recovery is
        available, but the encrypted record becomes part of your server-side footprint.
      </p>
      {msg && <p className="mt-1 text-xs text-green-400">{msg}</p>}
      {open && !enabled && (
        <div className="mt-3 space-y-2">
          <input
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="new-password"
            placeholder="Recovery password"
            className="w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          {pw && scorer && (
            <div>
              <div className="h-1.5 w-full rounded bg-neutral-800 overflow-hidden">
                <div className={`h-full ${colors[score]}`} style={{ width: `${(score + 1) * 20}%` }} />
              </div>
              <p className="mt-1 text-xs text-neutral-400">
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
            className="w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          />
          {confirm && !matches && <p className="text-xs text-red-400">Passwords don&rsquo;t match.</p>}
          <button
            onClick={() => void enable()}
            disabled={!!busy || !strongEnough || !matches}
            className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
          >
            {busy ?? "Enable"}
          </button>
        </div>
      )}
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
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
      <div className="text-sm text-neutral-300">Recovery seed phrase</div>
      {!words ? (
        <>
          {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
          <button onClick={() => void reveal()} className="mt-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 text-sm">
            View seed phrase
          </button>
        </>
      ) : (
        <>
          <div className="mt-2 grid grid-cols-3 gap-2">
            {words.map((w, i) => (
              <div key={i} className="rounded bg-neutral-900 px-2 py-1 text-xs font-mono">
                <span className="text-neutral-600 mr-1">{i + 1}</span>
                {w}
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-yellow-500">Store these offline. We will never ask for them.</p>
          <button onClick={() => setWords(null)} className="mt-2 text-xs text-neutral-500 hover:text-neutral-300">Hide</button>
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
      <div className="text-sm text-neutral-300">Emergency contacts</div>
      <p className="text-xs text-neutral-500">Split your recovery key across 2–3 trusted friends.</p>
      {msg && <p className="mt-1 text-xs text-green-400">{msg}</p>}
      {!open ? (
        <button onClick={() => setOpen(true)} className="mt-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 text-sm">
          Choose contacts
        </button>
      ) : (
        <div className="mt-2">
          {contacts.length === 0 ? (
            <p className="text-xs text-neutral-500">No eligible contacts yet.</p>
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
          {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
          <div className="mt-2 flex gap-2">
            <button
              disabled={busy || picked.size < 2}
              onClick={() => void setup()}
              className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-3 py-1.5 text-sm"
            >
              {busy ? "Storing…" : `Protect with ${picked.size} contacts`}
            </button>
            <button onClick={() => setOpen(false)} className="rounded-lg border border-neutral-700 px-3 py-1.5 text-sm">Cancel</button>
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
          <span className="block text-sm text-neutral-300">Cross-device sync</span>
          <span className="block text-xs text-neutral-500">
            Messages you send also appear on your linked devices, as end-to-end encrypted
            copies routed through your own mailbox. Off by default: the extra self-addressed
            traffic is visible to the server as a pattern (not content).
          </span>
        </span>
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => void toggle(e.target.checked)}
          className="mt-1 h-4 w-4 accent-indigo-500"
        />
      </label>
      {enabled && (
        <div className="mt-2">
          <div className="text-xs text-neutral-400">
            Linked devices {devices.length === 0 && "- none yet"}
          </div>
          {devices.length === 0 ? (
            <p className="text-xs text-neutral-500">
              Run &ldquo;Transfer history&rdquo; with this setting ON on both devices to link them.
            </p>
          ) : (
            <ul className="mt-1 space-y-1">
              {devices.map((d) => (
                <li key={d.device_id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-neutral-300">
                    {d.label}
                    <span className="ml-2 font-mono text-neutral-600">{d.device_id.slice(0, 8)}…</span>
                  </span>
                  <button
                    onClick={() => void unlink(d.device_id)}
                    className="rounded px-2 py-0.5 text-red-400 hover:bg-neutral-800"
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
        <span className="block text-sm text-neutral-300">{label}</span>
        <span className="block text-xs text-neutral-500">{hint}</span>
      </span>
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 accent-indigo-500"
      />
    </label>
  );

  return (
    <div>
      <div className="text-sm text-neutral-300">Message status</div>
      <p className="text-xs text-neutral-500">
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
        <span className="text-sm text-neutral-300">Chat history backup</span>
        <button
          onClick={() => void toggle()}
          disabled={!!busy}
          className={
            "rounded px-2 py-1 text-xs disabled:opacity-40 " +
            (enabled ? "bg-red-600/80 hover:bg-red-600" : "bg-neutral-800 hover:bg-neutral-700")
          }
        >
          {busy ?? (enabled ? "Turn off" : "Turn on")}
        </button>
      </div>
      <p className="text-xs text-neutral-500">
        Off by default. Encrypted with a key only you hold - the server can&rsquo;t read it. While on, your
        encrypted history lives on our servers; a backup means it exists in more places. Not for
        targeted-surveillance threat models.
      </p>
      {status && status.count > 0 && (
        <p className="mt-1 text-xs text-neutral-400">
          {status.count} messages backed up ({Math.max(1, Math.round(status.bytes / 1024))} KB).
        </p>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        {enabled && (
          <button onClick={() => void run("Backing up…", () => backfillAll())} disabled={!!busy} className="rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-3 py-1.5 text-sm">
            Back up now
          </button>
        )}
        {status && status.count > 0 && (
          <button onClick={() => void run("Restoring…", () => restoreHistory(), true)} disabled={!!busy} className="rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-3 py-1.5 text-sm">
            Restore to this device
          </button>
        )}
      </div>
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
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
        <span className="text-sm text-neutral-300">App lock</span>
        {st.enabled ? (
          <button
            onClick={() => void run("Turning off…", () => disableLock())}
            disabled={!!busy}
            className="rounded bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-2 py-1 text-xs"
          >
            {busy ?? "Turn off"}
          </button>
        ) : (
          <button
            onClick={() => setSetting((s) => !s)}
            disabled={!!busy}
            className="rounded bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-2 py-1 text-xs"
          >
            {setting ? "Cancel" : "Set up"}
          </button>
        )}
      </div>
      <p className="text-xs text-neutral-500">
        Encrypts this device&rsquo;s data behind a passphrase{st.biometricAvailable ? " or biometrics" : ""}. Required
        after a reload or 5&nbsp;min idle - your messages can&rsquo;t be read without it, even from device storage.
      </p>
      {msg && <p className="mt-1 text-xs text-green-400">{msg}</p>}

      {!st.enabled && setting && (
        <div className="mt-2 flex gap-2">
          <input
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            placeholder={`Passphrase (min ${MIN_PASSPHRASE})`}
            className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-1.5 text-sm outline-none focus:border-indigo-500"
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
            className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
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
              className="rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-3 py-1.5 text-sm"
            >
              Add biometrics
            </button>
          )}
          {st.biometric && (
            <button
              disabled={!!busy}
              onClick={() => void run("Removing…", () => removeBiometric())}
              className="rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-3 py-1.5 text-sm"
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
            className="rounded-lg bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 px-3 py-1.5 text-sm"
          >
            Lock now
          </button>
        </div>
      )}
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
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
      <div className="text-sm text-red-300">Erase this device</div>
      <p className="text-xs text-neutral-500">
        Permanently delete all data and your identity on this device, returning to a clean
        slate. Irreversible without your recovery phrase, password, or backup. Other devices
        are untouched.
      </p>
      <button
        onClick={() => void erase()}
        disabled={busy}
        className="mt-2 rounded-lg border border-red-600/60 text-red-300 hover:bg-red-600/10 disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
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
      <div className="text-sm text-neutral-300">Active sessions</div>
      <p className="text-xs text-neutral-500">
        Tokens live in memory only and can&rsquo;t be listed. &ldquo;Log out everywhere&rdquo;
        revokes every device&rsquo;s token and rotates your signed prekey. It does NOT erase
        this device&rsquo;s data &mdash; use &ldquo;Erase this device&rdquo; below for that.
      </p>
      <button
        onClick={() => void logoutEverywhere()}
        disabled={busy}
        className="mt-2 rounded-lg bg-red-600/80 hover:bg-red-600 disabled:opacity-40 px-3 py-1.5 text-sm font-medium"
      >
        {busy ? "Logging out…" : "Log out everywhere"}
      </button>
    </div>
  );
}
