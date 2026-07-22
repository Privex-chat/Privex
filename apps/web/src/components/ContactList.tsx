// Contact list (accepted contacts only). Loads from IndexedDB (names decrypted in
// memory only), shows verification status, taps through to the chat, and offers
// rename / remove / view-safety-code from a per-row overflow menu.
//
// Opt-in friend requests (pending_inbound) are NOT shown here - they live on a
// separate "Requests" tab inside Contacts, so the home list stays clean as
// requests pile up.
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listContacts, removeContact, setDisplayName, type PlainContact } from "../data/contacts";
import { onContactsChanged, onMessage } from "../services/events";
import { db } from "../db";
import EmptyChats from "./EmptyChats";
import Avatar from "./Avatar";
import { ConfirmDialog, Modal } from "./Modal";
import { DotsVerticalIcon, ShieldCheckIcon, WarningTriangleIcon } from "./icons";

/** Load the latest message timestamp per session from IndexedDB. Uses the signed
 *  server_anchor when available (docs 9.6), falling back to the local timestamp.
 *  Accepts the contact px_ids so it can query by the indexed session_id field
 *  rather than scanning every row. */
async function latestPerSession(sessionIds: string[]): Promise<Map<string, number>> {
  const map = new Map<string, number>();
  if (sessionIds.length === 0) return map;
  const msgs = await db.messages.where("session_id").anyOf(sessionIds).toArray();
  for (const m of msgs) {
    const key = m.server_anchor ?? m.timestamp;
    const prev = map.get(m.session_id);
    if (!prev || key > prev) map.set(m.session_id, key);
  }
  return map;
}

export default function ContactList() {
  const nav = useNavigate();
  const [contacts, setContacts] = useState<PlainContact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [menuFor, setMenuFor] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<PlainContact | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [removing, setRemoving] = useState<PlainContact | null>(null);

  const reload = useCallback(() => {
    void (async () => {
      try {
        const all = await listContacts();
        // Home list = ACCEPTED contacts only (legacy rows default to accepted).
        // pending_inbound → Requests tab, pending_outbound → Requests "Sent",
        // blocked → Blocked tab. So the DM list stays clean.
        const accepted = (c: PlainContact) => c.status === "accepted";
        const contactIds = all.filter(accepted).map((c) => c.px_id);
        const [latest] = await Promise.all([latestPerSession(contactIds)]);
        const sorted = all
          .filter(accepted)
          .sort((a, b) => {
            const aKey = latest.get(a.px_id) ?? a.added_at;
            const bKey = latest.get(b.px_id) ?? b.added_at;
            return bKey - aKey;
          });
        setContacts(sorted);
        setError(null);
      } catch (e) {
        console.error("[privex] failed to load contacts:", e);
        setError("Couldn't load your contacts.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);
  const msgTimer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    reload();
    const unsub1 = onContactsChanged(reload);
    // Bump on every new message (docs 4.4/4.10): the conversation moves to the
    // top when the latest message timestamp changes, matching WhatsApp/Signal.
    // Debounced (300ms) so rapid bursts coalesce into a single reload.
    const unsub2 = onMessage(() => {
      clearTimeout(msgTimer.current);
      msgTimer.current = setTimeout(reload, 300);
    });
    return () => {
      unsub1();
      unsub2();
      clearTimeout(msgTimer.current);
    };
  }, [reload]);

  // Close the row overflow menu on any outside tap or Escape.
  useEffect(() => {
    if (menuFor === null) return;
    const onDown = (e: MouseEvent | TouchEvent) => {
      if (!(e.target as Element).closest("[data-row-menu]")) setMenuFor(null);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenuFor(null);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("touchstart", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("touchstart", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuFor]);

  async function saveRename() {
    if (!renaming) return;
    const trimmed = renameValue.trim().slice(0, 64);
    const target = renaming;
    setRenaming(null);
    if (!trimmed) return;
    await setDisplayName(target.px_id, trimmed);
    reload();
  }

  async function confirmRemove() {
    if (!removing) return;
    const target = removing;
    setRemoving(null);
    await removeContact(target.px_id);
    reload();
  }

  if (contacts.length === 0) {
    if (error) return <p className="p-4 text-sm text-danger">{error}</p>;
    if (loading) return null;
    return <EmptyChats />;
  }

  return (
    <>
      <ul className="divide-y divide-divider">
        {contacts.map((c) => (
          <li key={c.px_id} className="flex items-center gap-3 py-2.5">
            <button onClick={() => nav(`/chat/${c.px_id}`)} className="flex min-w-0 flex-1 items-center gap-3 text-left">
              <Avatar seed={c.px_id} size={40} title={c.name || c.px_id} />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate font-medium">{c.name || c.px_id}</span>
                  {c.verified ? (
                    <ShieldCheckIcon className="h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <WarningTriangleIcon className="h-4 w-4 shrink-0 text-warning" />
                  )}
                </span>
                {c.name && <span className="block truncate font-mono text-xs text-text-subtle">{c.px_id}</span>}
              </span>
            </button>

            <div className="relative shrink-0" data-row-menu>
              <button
                onClick={() => setMenuFor((v) => (v === c.px_id ? null : c.px_id))}
                aria-label="Contact options"
                aria-haspopup="menu"
                aria-expanded={menuFor === c.px_id}
                className="flex h-9 w-9 items-center justify-center rounded-full text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
              >
                <DotsVerticalIcon className="h-5 w-5" />
              </button>
              {menuFor === c.px_id && (
                <div
                  role="menu"
                  className="absolute right-0 top-10 z-20 w-36 overflow-hidden rounded-lg border border-divider bg-elevated text-sm shadow-lg"
                >
                  <button
                    role="menuitem"
                    onClick={() => { setMenuFor(null); nav(`/verify/${c.px_id}`); }}
                    className="block w-full px-3 py-2 text-left text-text-secondary hover:bg-raised"
                  >
                    Safety code
                  </button>
                  <button
                    role="menuitem"
                    onClick={() => { setMenuFor(null); setRenameValue(c.name ?? ""); setRenaming(c); }}
                    className="block w-full px-3 py-2 text-left text-text-secondary hover:bg-raised"
                  >
                    Rename
                  </button>
                  <button
                    role="menuitem"
                    onClick={() => { setMenuFor(null); setRemoving(c); }}
                    className="block w-full px-3 py-2 text-left text-danger hover:bg-raised"
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>

      <Modal open={renaming !== null} onClose={() => setRenaming(null)} title="Display name">
        <input
          autoFocus
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void saveRename()}
          maxLength={64}
          placeholder="Name (only you see this)"
          className="w-full rounded-lg border border-border-strong bg-input px-3 py-2 text-sm outline-none focus:border-border-focus"
        />
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={() => setRenaming(null)} className="rounded-lg border border-border-strong px-4 py-2 text-sm text-text-secondary hover:bg-raised">
            Cancel
          </button>
          <button onClick={() => void saveRename()} className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-hover">
            Save
          </button>
        </div>
      </Modal>

      <ConfirmDialog
        open={removing !== null}
        title="Remove contact"
        message={`Remove ${removing?.name || removing?.px_id}? This deletes the chat and its messages on this device.`}
        confirmLabel="Remove"
        danger
        onConfirm={() => void confirmRemove()}
        onCancel={() => setRemoving(null)}
      />
    </>
  );
}
