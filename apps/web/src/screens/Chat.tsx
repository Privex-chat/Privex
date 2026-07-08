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
import { acceptContact, getContact, removeContact } from "../data/contacts";
import { onContactsChanged, onMessage } from "../services/events";
import { sendMessage, sendFile } from "../services/messaging";
import { queueReadReceipt } from "../services/receipts";
import { downloadAndDecrypt, type FileMeta } from "../services/files";
import { AttachIcon, DownloadIcon, FileIcon } from "../components/icons";
import ConnectionStatus from "../components/ConnectionStatus";

/** Outgoing status ticks (docs 4.10): ◷ in flight, ✓ at server, ✓✓ delivered,
 *  ✓✓ (highlighted) read. Incoming messages show nothing - receipts are outgoing-only. */
function StatusTicks({ status }: { status: string }) {
  if (status === "queued") return <span title="Waiting for connection">◷</span>;
  if (status === "delivered") return <span title="Delivered">✓✓</span>;
  if (status === "read") return <span className="text-sky-300" title="Read">✓✓</span>;
  if (status === "failed") return <span className="text-red-300" title="Failed">!</span>;
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
  const bottomRef = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!peerId) return;
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
      await sendMessage(peerId, text);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to send.");
      setDraft(text);
    } finally {
      setSending(false);
    }
  }

  // Message request (opt-in): reading is informed consent, replying is gated.
  const pending = contact?.status === "pending_inbound";

  const MAX_FILE_BYTES = 100 * 1024 * 1024; // 100 MB

  async function upload_(file: File) {
    if (!peerId || pending) return;
    if (file.size > MAX_FILE_BYTES) {
      setError(`File too large (max 100 MB).`);
      return;
    }
    setError(null);
    setUpload({ done: 0, total: 1 });
    try {
      await sendFile(peerId, file, (done, total) => setUpload({ done, total }));
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
    if (pending) return;
    const file = e.dataTransfer.files?.[0];
    if (file && file.size > 0) void upload_(file);
  }

  async function acceptRequest() {
    if (!peerId) return;
    await acceptContact(peerId); // emits contactsChanged → contact reloads
  }

  async function declineRequest() {
    if (!peerId) return;
    // Purges contact + session + these messages + outbox rows (data/contacts).
    await removeContact(peerId);
    nav("/", { replace: true });
  }

  const title = contact?.name || peerId || "";

  return (
    <main
      className="min-h-screen bg-[#0a0a0a] text-neutral-100 flex flex-col"
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      {/* Sticky header — always visible while scrolling messages */}
      <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-neutral-800 bg-[#0a0a0a]/95 px-4 py-3 backdrop-blur-sm">
        <button
          onClick={() => nav("/")}
          className="flex h-9 w-9 items-center justify-center rounded-full text-lg text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-100"
          title="Back to conversations"
          aria-label="Back to conversations"
        >
          ←
        </button>
        {/* Contact avatar — initials fallback */}
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-indigo-600/20 text-sm font-semibold text-indigo-400">
          {(contact?.name || peerId || "?").charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-semibold">{title}</span>
            {contact?.verified ? (
              <span title="Verified" className="text-green-400 text-sm">✓</span>
            ) : (
              <button onClick={() => peerId && nav(`/verify/${peerId}`)} title="Not verified — compare safety code" aria-label="Verify safety code" className="text-yellow-500 text-sm">⚠</button>
            )}
          </div>
          <div className="truncate font-mono text-[11px] text-neutral-500">{peerId}</div>
        </div>
        <div className="shrink-0">
          <ConnectionStatus />
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2 relative">
        {dragging && (
          <div className="absolute inset-2 z-10 rounded-xl border-2 border-dashed border-indigo-500 bg-indigo-500/10 flex items-center justify-center text-indigo-300 text-sm pointer-events-none">
            Drop to send
          </div>
        )}
        {msgs.length === 0 && <p className="text-neutral-600 text-sm">No messages yet.</p>}
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
              <div className={"max-w-[75%] rounded-2xl px-3 py-2 text-sm " + (out ? "bg-indigo-600" : "bg-neutral-800")}>
                {meta ? (
                  <div className="space-y-2">
                    {meta.thumb && (
                      <img src={meta.thumb} alt={meta.name} className="max-h-48 rounded-lg" />
                    )}
                    <div className="flex items-center gap-2">
                      <FileIcon className="w-6 h-6 shrink-0 text-neutral-200" />
                      <div className="min-w-0">
                        <div className="truncate">{meta.name}</div>
                        <div className="text-[11px] text-neutral-300/70">{formatSize(meta.size)}</div>
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
                      <div className="h-1 w-full rounded bg-black/30 overflow-hidden">
                        <div className="h-full bg-white/70" style={{ width: `${(dl.done / Math.max(1, dl.total)) * 100}%` }} />
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap break-words">{m.content}</p>
                )}
                <div className="mt-1 flex items-center gap-1 text-[10px] text-neutral-300/70">
                  <span>{new Date(m.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                  {out && <StatusTicks status={m.status} />}
                  {m.status === "received-unverified" && <span title="Sender not verified">· ⚠ unverified</span>}
                  {m.status === "received-key-changed" && (
                    <span className="text-red-300" title="This contact's key changed - re-verify">· ⚠ key changed</span>
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
          <div className="text-[11px] text-neutral-400 mb-1">Encrypting & uploading… {upload.done}/{upload.total}</div>
          <div className="h-1 w-full rounded bg-neutral-800 overflow-hidden">
            <div className="h-full bg-indigo-500" style={{ width: `${(upload.done / Math.max(1, upload.total)) * 100}%` }} />
          </div>
        </div>
      )}
      {error && <p className="px-4 text-sm text-red-400">{error}</p>}

      {pending ? (
        /* Message request: no composer until accepted. Declining deletes the
           request AND its messages; the sender is never notified either way. */
        <footer className="border-t border-neutral-800 p-4 space-y-3">
          <p className="text-sm text-neutral-400">
            <span className="font-mono text-neutral-300">{peerId}</span> wants to connect.
            Accepting lets you reply; declining deletes this request and its messages.
            They are not notified either way.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => void acceptRequest()}
              className="flex-1 rounded-lg bg-indigo-600 hover:bg-indigo-500 py-2 text-sm font-medium"
            >
              Accept
            </button>
            <button
              onClick={() => void declineRequest()}
              className="flex-1 rounded-lg border border-neutral-700 hover:bg-neutral-800 py-2 text-sm text-red-400"
            >
              Decline &amp; delete
            </button>
          </div>
        </footer>
      ) : (
      <footer className="flex items-center gap-2 border-t border-neutral-800 p-3">
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
          className="rounded-full p-2 text-neutral-400 hover:bg-neutral-800 disabled:opacity-40"
        >
          <AttachIcon className="w-6 h-6" />
        </button>
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
          className="flex-1 rounded-full bg-neutral-900 border border-neutral-700 px-4 py-2 outline-none focus:border-indigo-500"
        />
        <button
          disabled={sending || draft.trim().length === 0}
          onClick={() => void send()}
          className="rounded-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-4 py-2 text-sm font-medium"
        >
          Send
        </button>
      </footer>
      )}
    </main>
  );
}
