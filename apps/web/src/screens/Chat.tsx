// Conversation view. Loads the last 50 messages from IndexedDB (decrypted in
// memory only), live-updates on the message event bus, sends text + files, and
// renders file messages (icon, name, size, image thumbnail, download). Drag a
// file onto the window - or use the paperclip - to send it.
// ponytail: renders the bounded last-50 in a scroll container; true windowed
// virtualization can wait until conversations are huge.
import { useCallback, useEffect, useRef, useState } from "react";
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
import { AttachIcon, DownloadIcon, FileIcon } from "../components/icons";
import ConnectionStatus from "../components/ConnectionStatus";

/** Outgoing status ticks (docs 4.10): ◷ in flight, ✓ at server, ✓✓ delivered,
 *  ✓✓ (highlighted) read. Incoming messages show nothing - receipts are outgoing-only. */
function StatusTicks({ status }: { status: string }) {
  if (status === "queued") return <span title="Waiting for connection">◷</span>;
  if (status === "delivered") return <span title="Delivered">✓✓</span>;
  if (status === "read") return <span className="text-accent-subtle" title="Read">✓✓</span>;
  if (status === "failed") return <span className="text-danger" title="Failed">!</span>;
  return <span title="Sent">✓</span>; // "sent"
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
const TTL_OPTIONS: { label: string; value: number }[] = [
  { label: "1 hour", value: 3600 },
  { label: "6 hours", value: 6 * 3600 },
  { label: "24 hours", value: 24 * 3600 },
  { label: "7 days", value: 7 * 24 * 3600 },
  { label: "30 days (default)", value: DEFAULT_TTL },
  { label: "60 days", value: 60 * 24 * 3600 },
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
  const [menuOpen, setMenuOpen] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void getClientConfig().then((c) => setFileUploadsEnabled(c.file_uploads_enabled));
  }, []);

  useEffect(() => {
    if (!peerId) return;
    // TTL is per-conversation: reset on every peer switch, not just on mount
    // (React Router reuses this component across /chat/:id navigations).
    setTtl(DEFAULT_TTL);
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
    await blockContact(peerId); // their future messages/requests are dropped
  }

  async function unblock() {
    if (!peerId) return;
    await unblockContact(peerId);
  }

  async function deleteChat() {
    if (!peerId) return;
    if (!window.confirm(`Delete chat with ${contact?.name || peerId}? This can't be undone.`)) return;
    await removeContact(peerId);
    nav("/", { replace: true });
  }

  const title = contact?.name || peerId || "";

  return (
    <main
      className="min-h-screen bg-surface text-text-primary flex flex-col"
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
          className="flex h-9 w-9 items-center justify-center rounded-full text-lg text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
          title="Back to conversations"
          aria-label="Back to conversations"
        >
          ←
        </button>
        {/* Contact avatar — initials fallback */}
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-bg text-sm font-semibold text-accent-text">
          {(contact?.name || peerId || "?").charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-semibold">{title}</span>
            {contact?.verified ? (
              <span title="Verified" className="text-success text-sm">✓</span>
            ) : (
              <button onClick={() => peerId && nav(`/verify/${peerId}`)} title="Not verified — compare safety code" aria-label="Verify safety code" className="text-warning text-sm">⚠</button>
            )}
          </div>
          <div className="truncate font-mono text-[11px] text-text-muted">{peerId}</div>
        </div>
        <div className="shrink-0 flex items-center gap-1">
          <ConnectionStatus />
          {/* Overflow menu: Block / Unblock / Delete chat (WhatsApp-style). Only
              meaningful for an existing relationship, not a bare pending request. */}
          {contact && !pending && (
            <div className="relative">
              <button
                onClick={() => setMenuOpen((v) => !v)}
                title="More"
                aria-label="More options"
                className="flex h-9 w-9 items-center justify-center rounded-full text-text-secondary hover:bg-raised hover:text-text-primary"
              >
                ⋮
              </button>
              {menuOpen && (
                <div
                  className="absolute right-0 top-10 z-20 w-40 overflow-hidden rounded-lg border border-divider bg-elevated text-sm shadow-lg"
                  onMouseLeave={() => setMenuOpen(false)}
                >
                  {blocked ? (
                    <button onClick={() => { setMenuOpen(false); void unblock(); }} className="block w-full px-3 py-2 text-left hover:bg-raised">
                      Unblock
                    </button>
                  ) : (
                    <button onClick={() => { setMenuOpen(false); void block(); }} className="block w-full px-3 py-2 text-left hover:bg-raised">
                      Block
                    </button>
                  )}
                  <button onClick={() => { setMenuOpen(false); void deleteChat(); }} className="block w-full px-3 py-2 text-left text-danger hover:bg-raised">
                    Delete chat
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2 relative">
        {dragging && (
          <div className="absolute inset-2 z-10 rounded-xl border-2 border-dashed border-border-focus bg-accent-bg flex items-center justify-center text-accent-subtle text-sm pointer-events-none">
            Drop to send
          </div>
        )}
        {msgs.length === 0 && <p className="text-text-subtle text-sm">No messages yet.</p>}
        {msgs.map((m) => {
          const out = m.direction === "out";
          const meta = m.kind === "file" ? parseFileMeta(m.content) : null;
          const dl = downloads[m.msg_id];
          return (
            <div
              key={m.msg_id}
              ref={(el) => observeForRead(el, m)}
              className={out ? "flex justify-end" : "flex justify-start"}
            >
              <div className={"max-w-[75%] rounded-2xl px-3 py-2 text-sm " + (out ? "bg-accent" : "bg-raised")}>
                {meta ? (
                  <div className="space-y-2">
                    {meta.thumb && (
                      <img src={meta.thumb} alt={meta.name} className="max-h-48 rounded-lg" />
                    )}
                    <div className="flex items-center gap-2">
                      <FileIcon className="w-6 h-6 shrink-0 text-text" />
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
                <div className="mt-1 flex items-center gap-1 text-[10px] text-text-muted">
                  <span>{new Date(m.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                  {out && <StatusTicks status={m.status} />}
                  {m.status === "received-unverified" && <span title="Sender not verified">· ⚠ unverified</span>}
                  {m.status === "received-key-changed" && (
                    <span className="text-danger" title="This contact's key changed - re-verify">· ⚠ key changed</span>
                  )}
                </div>
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
              onClick={() => void deleteChat()}
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
            Accepting lets you reply; declining deletes this request and its messages.
            They are not notified either way.
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
              className="flex-1 rounded-lg border border-border-strong hover:bg-raised py-2 text-sm text-danger"
            >
              Decline &amp; delete
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
        {/* Per-message TTL (docs 4.12): delete from the server queue if
            undelivered after this long. Applies to messages sent from here on. */}
        <select
          value={ttl}
          onChange={(e) => setTtl(Number(e.target.value))}
          title="Delete if undelivered after…"
          aria-label="Delete if undelivered after"
          className={
            "shrink-0 rounded-full border border-border-strong bg-input px-2 py-2 text-xs outline-none focus:border-border-focus " +
            (ttl === DEFAULT_TTL ? "text-text-muted" : "text-accent-subtle")
          }
        >
          {TTL_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              ⏱ {o.label}
            </option>
          ))}
        </select>
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
    </main>
  );
}
