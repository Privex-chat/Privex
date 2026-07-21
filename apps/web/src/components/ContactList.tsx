// Contact list (accepted contacts only). Loads from IndexedDB (names decrypted in
// memory only), shows verification status, taps through to the chat, and offers
// rename / remove / view-safety-code actions.
//
// Opt-in friend requests (pending_inbound) are NOT shown here - they live on a
// separate "Requests" tab inside /add-contact, so the home list stays clean as
// requests pile up.
//
// ponytail: rename uses window.prompt and remove uses window.confirm - no modal
// component yet. Swap for a real dialog when the design system lands.
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listContacts, removeContact, setDisplayName, type PlainContact } from "../data/contacts";
import { onContactsChanged, onMessage } from "../services/events";
import { db } from "../db";

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

  const reload = useCallback(() => {
    void (async () => {
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

  async function rename(c: PlainContact) {
    const name = window.prompt("Display name (max 64 chars)", c.name);
    if (name === null) return;
    const trimmed = name.trim().slice(0, 64);
    if (!trimmed) return;
    await setDisplayName(c.px_id, trimmed);
    reload();
  }

  async function remove(c: PlainContact) {
    if (!window.confirm(`Remove ${c.name || c.px_id}?`)) return;
    await removeContact(c.px_id);
    reload();
  }

  if (contacts.length === 0) {
    return <p className="text-text-muted">No contacts yet. Add someone by their Privex ID.</p>;
  }

  return (
    <ul className="divide-y divide-divider">
      {contacts.map((c) => (
        <li key={c.px_id} className="flex items-center gap-3 py-3">
          <button
            onClick={() => nav(`/chat/${c.px_id}`)}
            className="flex-1 text-left min-w-0"
          >
            <div className="flex items-center gap-2">
              <span className="truncate font-medium">{c.name || c.px_id}</span>
              {c.verified ? (
                <span title="Verified" className="text-success text-sm">
                  ✓
                </span>
              ) : (
                <span title="Not verified" className="text-warning text-sm">
                  ⚠
                </span>
              )}
            </div>
            {c.name && <div className="truncate font-mono text-xs text-text-subtle">{c.px_id}</div>}
          </button>
          <button
            onClick={() => nav(`/verify/${c.px_id}`)}
            className="rounded px-2 py-1 text-xs text-text-secondary hover:bg-raised"
          >
            Code
          </button>
          <button
            onClick={() => void rename(c)}
            className="rounded px-2 py-1 text-xs text-text-secondary hover:bg-raised"
          >
            Rename
          </button>
          <button
            onClick={() => void remove(c)}
            className="rounded px-2 py-1 text-xs text-danger hover:bg-raised"
          >
            Remove
          </button>
        </li>
      ))}
    </ul>
  );
}
