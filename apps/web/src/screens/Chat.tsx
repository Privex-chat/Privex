// Conversation view. Loads the last 50 messages from IndexedDB (decrypted in
// memory only), live-updates on the message event bus, sends text + files, and
// renders file messages (icon, name, size, image thumbnail, download). Drag a
// file onto the window - or use the paperclip - to send it.
// ponytail: renders the bounded last-50 in a scroll container; true windowed
// virtualization can wait until conversations are huge.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { EncryptedMessages, type PlainContact, type PlainMessage } from "../db/encrypted-db";
import { db } from "../db";
import { blockContact, getContact, removeContact, unblockContact } from "../data/contacts";
import { acceptContactRequest } from "../services/messaging";
import { onContactsChanged, onMessage } from "../services/events";
import { sendMessage, sendFile } from "../services/messaging";
import { queueReadReceipt } from "../services/receipts";
import { downloadAndDecrypt, type FileMeta } from "../services/files";
import { getClientConfig } from "../services/client-config";
import { buildChatTimeline } from "../services/chat-timeline";
import {
  AlertCircleIcon,
  ArrowLeftIcon,
  AttachIcon,
  CheckIcon,
  ClockIcon,
  DotsVerticalIcon,
  DoubleCheckIcon,
  DownloadIcon,
  FileIcon,
  ShieldCheckIcon,
  WarningTriangleIcon,
} from "../components/icons";
import ConnectionStatus from "../components/ConnectionStatus";
import Avatar from "../components/Avatar";
import { ConfirmDialog } from "../components/Modal";

/** Outgoing status ticks (docs 4.10): clock in flight, single check at server,
 *  double check delivered, accent double check read. Incoming messages show
 *  nothing - receipts are outgoing-only. */
function StatusTicks({ status }: { status: string }) {
  const wrap = (title: string, node: JSX.Element, cls = "") => (
    <span title={title} className={"inline-flex " + cls}>
      {node}
    </span>
  );
  if (status === "queued") return wrap("Waiting for connection", <ClockIcon className="h-3.5 w-3.5" />);
  if (status === "delivered") return wrap("Delivered", <DoubleCheckIcon className="h-3.5 w-3.5" />);
  if (status === "read") return wrap("Read", <DoubleCheckIcon className="h-3.5 w-3.5" />, "text-accent-subtle");
  if (status === "failed") return wrap("Failed", <AlertCircleIcon className="h-3.5 w-3.5" />, "text-danger");
  return wrap("Sent", <CheckIcon className="h-3.5 w-3.5" />);
}

function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function parseFileMeta(content: string): FileMeta | null {
  try {
    return JSON.parse(content) as FileMeta;
  } catch {
    return null;
  }
}

// Per-message queue TTL (docs 4.12): "delete if undelivered after…". The server
// enforces [1 h, 60 d]; 30 d is its default. Resets to default per conversation
// visit - the safe direction for a forgotten setting.
const DEFAULT_TTL = 30 * 24 * 3600;
const TTL_OPTIONS: { label: string; short: string; value: number }[] = [
  { label: "1 hour", short: "1h", value: 3600 },
  { label: "6 hours", short: "6h", value: 6 * 3600 },
  { label: "24 hours", short: "24h", value: 24 * 3600 },
  { label: "7 days", short: "7d", value: 7 * 24 * 3600 },
  { label: "30 days (default)", short: "30d", value: DEFAULT_TTL },
  { label: "60 days", short: "60d", value: 60 * 24 * 3600 },
];

export default function Chat() {
  const { id: peerId } = useParams();
  const nav = useNavigate();
  const [contact, setContact] = useState<PlainContact | undefined>();
  const [msgs, setMsgs] = useState<PlainMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [upload, setUpload] = useState<{ done: number; total: number } | null>(null);
  const [downloads, setDownloads] = useState<Record<string, { done: number; total: number }>>({});
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileUploadsEnabled, setFileUploadsEnabled] = useState(true);
  const [ttl, setTtl] = useState(DEFAULT_TTL);
  const [ttlOpen, setTtlOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const ttlRef = useRef<HTMLDivElement>(null);

  // Close either popover (header ⋮ overflow, composer TTL) on an outside tap or
  // Escape (mouseleave alone leaves them stuck open on touch devices - this is a PWA).
  useEffect(() => {
    if (!menuOpen && !ttlOpen) return;
    const onDown = (e: MouseEvent | TouchEvent) => {
      const t = e.target as Node;
      if (menuRef.current && !menuRef.current.contains(t)) setMenuOpen(false);
      if (ttlRef.current && !ttlRef.current.contains(t)) setTtlOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMenuOpen(false);
        setTtlOpen(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("touchstart", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("touchstart", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen, ttlOpen]);

  useEffect(() => {
    void getClientConfig().then((c) => setFileUploadsEnabled(c.file_uploads_enabled));
  }, []);

  useEffect(() => {
    if (!peerId) return;
    // Per-conversation UI state resets on every peer switch, not just on mount
    // (React Router reuses this component across /chat/:id navigations): the TTL
    // picker and the (peer-specific) overflow menu must not carry over.
    setTtl(DEFAULT_TTL);
    setMenuOpen(false);
    setTtlOpen(false);
    const store = new EncryptedMessages(db);
    const reload = () => void store.listBySession(peerId).then(setMsgs);
    const loadContact = () => void getContact(peerId).then(setContact);
    loadContact();
    reload();
    const offMsg = onMessage((e) => {
      if (e.peerId === peerId) reload();
    });
    // Status flips (accept here or from the Requests tab) re-gate the composer.
    const offContacts = onContactsChanged(loadContact);
    return () => {
      offMsg();
      offContacts();
    };
  }, [peerId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs]);

  // Read receipts (docs 4.10): a message counts as "read" only after its bubble
  // has been in the viewport for >1 s. Queues the receipt (sent at the next
  // Poisson tick, never inline); queueReadReceipt is a no-op when read receipts
  // are off (mutual) or already fired for this message.
  const readObserver = useRef<IntersectionObserver | null>(null);
  const readTimers = useRef(new Map<Element, ReturnType<typeof setTimeout>>());
  const msgByEl = useRef(new Map<Element, PlainMessage>());
  useEffect(() => {
    const timers = readTimers.current;
    const byEl = msgByEl.current;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const en of entries) {
          const m = byEl.get(en.target);
          if (!m) continue;
          if (en.isIntersecting) {
            if (!timers.has(en.target)) {
              timers.set(
                en.target,
                setTimeout(() => {
                  timers.delete(en.target);
                  obs.unobserve(en.target);
                  byEl.delete(en.target);
                  void queueReadReceipt(m);
                }, 1000),
              );
            }
          } else {
            const t = timers.get(en.target);
            if (t) {
              clearTimeout(t);
              timers.delete(en.target);
            }
          }
        }
      },
      { threshold: 0.5 },
    );
    readObserver.current = obs;
    return () => {
      obs.disconnect();
      for (const t of timers.values()) clearTimeout(t);
      timers.clear();
      byEl.clear();
    };
  }, [peerId]);

  const observeForRead = useCallback((el: HTMLDivElement | null, m: PlainMessage) => {
    if (!el || m.direction !== "in" || !m.receipt_read_wanted || m.receipt_read_done) return;
    msgByEl.current.set(el, m);
    readObserver.current?.observe(el);
  }, []);

  async function send() {
    if (!peerId || !draft.trim()) return;
    const text = draft.trim();
    setDraft("");
    setSending(true);
    setError(null);
    try {
      await sendMessage(peerId, text, undefined, ttl);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to send.");
      setDraft(text);
    } finally {
      setSending(false);
    }
  }

  const MAX_FILE_BYTES = 100 * 1024 * 1024;

  // Composer gating by relationship state.
  const pending = contact?.status === "pending_inbound"; // they requested me
  const pendingOut = contact?.status === "pending_outbound"; // I requested, waiting
  const blocked = contact?.status === "blocked";
  const canMessage = !pending && !pendingOut && !blocked; // accepted (or legacy)

  async function upload_(file: File) {
    if (file.size > MAX_FILE_BYTES || file.size === 0) {
      setError("File too large or empty (max 100 MB).");
      return;
    }
    if (!peerId || !canMessage) return;
    setError(null);
    setUpload({ done: 0, total: 1 });
    try {
      await sendFile(peerId, file, (done, total) => setUpload({ done, total }), undefined, ttl);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed.");
    } finally {
      setUpload(null);
    }
  }

  async function download(m: PlainMessage, meta: FileMeta) {
    setError(null);
    setDownloads((d) => ({ ...d, [m.msg_id]: { done: 0, total: meta.chunks.length } }));
    try {
      const blob = await downloadAndDecrypt(meta, (done, total) =>
        setDownloads((d) => ({ ...d, [m.msg_id]: { done, total } })),
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = meta.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Download failed.");
    } finally {
      setDownloads((d) => {
        const { [m.msg_id]: _gone, ...rest } = d;
        return rest;
      });
    }
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    if (!canMessage || !fileUploadsEnabled) return;
    const file = e.dataTransfer.files?.[0];
    if (file && file.size > 0) void upload_(file);
  }

  async function acceptRequest() {
    if (!peerId) return;
    await acceptContactRequest(peerId); // accept + notify them (contact_accept)
  }

  async function declineRequest() {
    if (!peerId) return;
    // Purges contact + session + these messages + outbox rows (data/contacts).
    await removeContact(peerId);
    nav("/", { replace: true });
  }

  async function block() {
    if (!peerId) return;
    try {
      await blockContact(peerId); // their future messages/requests are dropped
    } catch (e) {
      // Surface a failed block: a privacy control must never look successful when
      // the write didn't land (a false sense of "blocked").
      setError(e instanceof Error ? e.message : "Couldn't block this contact.");
    }
  }

  async function unblock() {
    if (!peerId) return;
    try {
      await unblockContact(peerId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't unblock this contact.");
    }
  }

  async function doDeleteChat() {
    if (!peerId) return;
    setConfirmDelete(false);
    try {
      await removeContact(peerId);
      nav("/", { replace: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't delete this chat.");
    }
  }

  // Memoized so it only recomputes when messages change, not on every keystroke
  // in the composer (which re-renders Chat via the draft state).
  const timeline = useMemo(() => buildChatTimeline(msgs), [msgs]);

  const title = contact?.name || peerId || "";

  return (
    <main
      className="h-[100dvh] bg-surface text-text-primary flex flex-col"
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      {/* Sticky header — always visible while scrolling messages */}
      <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-divider bg-header px-4 py-3 backdrop-blur-sm">
        <button
          onClick={() => nav("/")}
          className="flex h-9 w-9 items-center justify-center rounded-full text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
          title="Back to conversations"
          aria-label="Back to conversations"
        >
          <ArrowLeftIcon className="h-5 w-5" />
        </button>
        {/* Contact avatar — deterministic identicon from the px_id. */}
        <Avatar seed={peerId ?? ""} size={36} title={contact?.name || peerId} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-semibold">{title}</span>
            {contact?.verified ? (
              <span title="Verified" className="inline-flex text-success">
                <ShieldCheckIcon className="h-4 w-4" />
              </span>
            ) : (
              <button
                onClick={() => peerId && nav(`/verify/${peerId}`)}
                title="Not verified — compare safety code"
                aria-label="Verify safety code"
                className="inline-flex text-warning"
              >
                <WarningTriangleIcon className="h-4 w-4" />
              </button>
            )}
          </div>
          <div className="truncate font-mono text-[11px] text-text-muted">{peerId}</div>
        </div>
        <div className="shrink-0 flex items-center gap-1">
          <ConnectionStatus />
          {/* Overflow menu: Block / Unblock / Delete chat (WhatsApp-style). Only
              meaningful for an existing relationship, not a bare pending request. */}
          {contact && !pending && (
            <div className="relative" ref={menuRef}>
              <button
                onClick={() => setMenuOpen((v) => !v)}
                title="More"
                aria-label="More options"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                className="flex h-9 w-9 items-center justify-center rounded-full text-text-secondary hover:bg-raised hover:text-text-primary"
              >
                <DotsVerticalIcon className="h-5 w-5" />
              </button>
              {menuOpen && (
                <div
                  role="menu"
                  className="absolute right-0 top-10 z-20 w-40 overflow-hidden rounded-lg border border-divider bg-elevated text-sm shadow-lg"
                >
                  {blocked ? (
                    <button role="menuitem" onClick={() => { setMenuOpen(false); void unblock(); }} className="block w-full px-3 py-2 text-left hover:bg-raised">
                      Unblock
                    </button>
                  ) : (
                    <button role="menuitem" onClick={() => { setMenuOpen(false); void block(); }} className="block w-full px-3 py-2 text-left hover:bg-raised">
                      Block
                    </button>
                  )}
                  <button role="menuitem" onClick={() => { setMenuOpen(false); setConfirmDelete(true); }} className="block w-full px-3 py-2 text-left text-danger hover:bg-raised">
                    Delete chat
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-3 relative">
        {dragging && (
          <div className="absolute inset-2 z-10 rounded-xl border-2 border-dashed border-border-focus bg-accent-bg flex items-center justify-center text-accent-subtle text-sm pointer-events-none">
            Drop to send
          </div>
        )}
        {msgs.length === 0 && <p className="text-text-subtle text-sm">No messages yet.</p>}
        {timeline.map((row) => {
          if (row.kind === "day") {
            return (
              <div key={row.key} className="my-4 flex justify-center">
                <span className="rounded-full bg-elevated px-3 py-1 text-[11px] text-text-muted">{row.label}</span>
              </div>
            );
          }
          const m = row.m;
          const out = m.direction === "out";
          const meta = m.kind === "file" ? parseFileMeta(m.content) : null;
          const dl = downloads[m.msg_id];
          // Tuck the grouped corner so a run of same-side bubbles reads as one cluster.
          const tuck = out
            ? (row.firstOfGroup ? "" : " rounded-tr-md") + (row.lastOfGroup ? "" : " rounded-br-md")
            : (row.firstOfGroup ? "" : " rounded-tl-md") + (row.lastOfGroup ? "" : " rounded-bl-md");
          const warned = m.status === "received-unverified" || m.status === "received-key-changed";
          return (
            <div
              key={m.msg_id}
              ref={(el) => observeForRead(el, m)}
              className={(row.firstOfGroup ? "mt-3" : "mt-0.5") + (out ? " flex justify-end" : " flex justify-start")}
            >
              <div
                className={
                  "max-w-[75%] rounded-2xl px-3 py-2 text-sm " +
                  (out ? "bg-bubble-out text-bubble-out-text" : "bg-raised") +
                  tuck
                }
              >
                {meta ? (
                  <div className="space-y-2">
                    {meta.thumb && (
                      <img src={meta.thumb} alt={meta.name} className="max-h-48 rounded-lg" />
                    )}
                    <div className="flex items-center gap-2">
                      <FileIcon className="w-6 h-6 shrink-0 text-text-secondary" />
                      <div className="min-w-0">
                        <div className="truncate">{meta.name}</div>
                        <div className="text-[11px] text-text-muted">{formatSize(meta.size)}</div>
                      </div>
                      <button
                        onClick={() => void download(m, meta)}
                        disabled={!!dl}
                        title="Download"
                        className="ml-1 rounded-full p-1.5 hover:bg-white/10 disabled:opacity-50"
                      >
                        <DownloadIcon className="w-5 h-5" />
                      </button>
                    </div>
                    {dl && (
                      <div className="h-1 w-full rounded bg-progress-track-file overflow-hidden">
                        <div className="h-full bg-progress-fill-file" style={{ width: `${(dl.done / Math.max(1, dl.total)) * 100}%` }} />
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap break-words">{m.content}</p>
                )}
                {(row.lastOfGroup || warned) && (
                  <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-text-muted">
                    {row.lastOfGroup && (
                      <span>{new Date(m.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                    )}
                    {row.lastOfGroup && out && <StatusTicks status={m.status} />}
                    {m.status === "received-unverified" && (
                      <span title="Sender not verified" className="inline-flex items-center gap-1">
                        <WarningTriangleIcon className="h-3 w-3" /> unverified
                      </span>
                    )}
                    {m.status === "received-key-changed" && (
                      <span className="inline-flex items-center gap-1 text-danger" title="This contact's key changed - re-verify">
                        <WarningTriangleIcon className="h-3 w-3" /> key changed
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {upload && (
        <div className="px-4 pb-1">
          <div className="text-[11px] text-text-secondary mb-1">Encrypting & uploading… {upload.done}/{upload.total}</div>
          <div className="h-1 w-full rounded bg-raised overflow-hidden">
            <div className="h-full bg-accent-hover" style={{ width: `${(upload.done / Math.max(1, upload.total)) * 100}%` }} />
          </div>
        </div>
      )}
      {error && <p className="px-4 text-sm text-danger">{error}</p>}

      {blocked ? (
        /* Blocked: WhatsApp-style — no composer, offer Unblock / Delete chat. */
        <footer className="border-t border-divider p-4 space-y-3">
          <p className="text-sm text-text-secondary">
            You blocked this contact. Their messages are hidden and won&rsquo;t be delivered.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => void unblock()}
              className="flex-1 rounded-lg bg-accent hover:bg-accent-hover py-2 text-sm font-medium"
            >
              Unblock
            </button>
            <button
              onClick={() => setConfirmDelete(true)}
              className="flex-1 rounded-lg border border-border-strong hover:bg-raised py-2 text-sm text-danger"
            >
              Delete chat
            </button>
          </div>
        </footer>
      ) : pendingOut ? (
        /* We requested them; can't message until they accept. */
        <footer className="border-t border-divider p-4">
          <p className="text-sm text-text-secondary">
            Request sent — you can message once{" "}
            <span className="font-mono">{contact?.name || peerId}</span> accepts.
          </p>
        </footer>
      ) : pending ? (
        /* Incoming request: no composer until accepted. Accepting notifies them;
           declining deletes it locally and sends no signal (silent). */
        <footer className="border-t border-divider p-4 space-y-3">
          <p className="text-sm text-text-secondary">
            <span className="font-mono text-text-secondary">{peerId}</span> wants to connect.
            Accepting lets you reply; declining deletes this request (they can ask again).
            Blocking drops this and any future requests and messages. They are not notified either way.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => void acceptRequest()}
              className="flex-1 rounded-lg bg-accent hover:bg-accent-hover py-2 text-sm font-medium"
            >
              Accept
            </button>
            <button
              onClick={() => void declineRequest()}
              className="flex-1 rounded-lg border border-border-strong hover:bg-raised py-2 text-sm"
            >
              Decline
            </button>
            <button
              onClick={() => void block()}
              className="flex-1 rounded-lg border border-border-strong hover:bg-raised py-2 text-sm text-danger"
            >
              Block
            </button>
          </div>
        </footer>
      ) : (
      <footer className="flex items-center gap-2 border-t border-divider p-3">
        {fileUploadsEnabled && (
          <>
            <input
              ref={fileInput}
              type="file"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void upload_(f);
                e.target.value = "";
              }}
            />
            <button
              onClick={() => fileInput.current?.click()}
              disabled={!!upload}
              title="Attach a file"
              className="rounded-full p-2 text-text-secondary hover:bg-raised disabled:opacity-40"
            >
              <AttachIcon className="w-6 h-6" />
            </button>
          </>
        )}
        {/* Per-message TTL (docs 4.12): delete from the server queue if undelivered
            after this long. Applies to messages sent from here on. Icon-button +
            popover instead of an inline <select> so the composer fits narrow screens. */}
        <div className="relative shrink-0" ref={ttlRef}>
          <button
            type="button"
            onClick={() => setTtlOpen((v) => !v)}
            title="Delete if undelivered after…"
            aria-label="Delete if undelivered after"
            aria-haspopup="menu"
            aria-expanded={ttlOpen}
            className={
              "relative flex h-9 items-center gap-1 rounded-full border border-border-strong px-2.5 text-xs transition-colors hover:bg-raised " +
              (ttl === DEFAULT_TTL ? "text-text-secondary" : "text-accent-subtle border-border-focus")
            }
          >
            <ClockIcon className="h-4 w-4" />
            {ttl !== DEFAULT_TTL && (
              <span className="font-medium">{TTL_OPTIONS.find((o) => o.value === ttl)?.short}</span>
            )}
          </button>
          {ttlOpen && (
            <div className="absolute bottom-full left-0 z-20 mb-2 w-48 overflow-hidden rounded-xl border border-divider bg-elevated text-sm shadow-lg">
              <p className="px-3 pb-1 pt-2 text-[11px] text-text-muted">Delete if undelivered after</p>
              <div role="menu">
                {TTL_OPTIONS.map((o) => (
                  <button
                    key={o.value}
                    role="menuitemradio"
                    aria-checked={ttl === o.value}
                    onClick={() => {
                      setTtl(o.value);
                      setTtlOpen(false);
                    }}
                    className={
                      "flex w-full items-center justify-between px-3 py-2 text-left hover:bg-raised " +
                      (ttl === o.value ? "text-accent-subtle" : "text-text-secondary")
                    }
                  >
                    <span>{o.label}</span>
                    {ttl === o.value && <CheckIcon className="h-4 w-4" />}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send();
            }
          }}
          placeholder="Message"
          maxLength={4096}
          className="flex-1 rounded-full bg-input border border-border-strong px-4 py-2 outline-none focus:border-border-focus"
        />
        <button
          disabled={sending || draft.trim().length === 0}
          onClick={() => void send()}
          className="rounded-full bg-accent hover:bg-accent-hover disabled:opacity-40 px-4 py-2 text-sm font-medium"
        >
          Send
        </button>
      </footer>
      )}
      <ConfirmDialog
        open={confirmDelete}
        title="Delete chat"
        message={`Delete your chat with ${contact?.name || peerId}? This removes it and its messages from this device.`}
        confirmLabel="Delete"
        danger
        onConfirm={() => void doDeleteChat()}
        onCancel={() => setConfirmDelete(false)}
      />
    </main>
  );
}
