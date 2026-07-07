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
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listContacts, removeContact, setDisplayName, type PlainContact } from "../data/contacts";
import { onContactsChanged } from "../services/events";

export default function ContactList() {
  const nav = useNavigate();
  const [contacts, setContacts] = useState<PlainContact[]>([]);

  const reload = useCallback(() => {
    void listContacts().then((all) => setContacts(all.filter((c) => c.status !== "pending_inbound")));
  }, []);
  useEffect(() => {
    reload();
    return onContactsChanged(reload); // refresh when a contact is accepted/removed
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
    return <p className="text-neutral-500">No contacts yet. Add someone by their Privex ID.</p>;
  }

  return (
    <ul className="divide-y divide-neutral-800">
      {contacts.map((c) => (
        <li key={c.px_id} className="flex items-center gap-3 py-3">
          <button
            onClick={() => nav(`/chat/${c.px_id}`)}
            className="flex-1 text-left min-w-0"
          >
            <div className="flex items-center gap-2">
              <span className="truncate font-medium">{c.name || c.px_id}</span>
              {c.verified ? (
                <span title="Verified" className="text-green-400 text-sm">
                  ✓
                </span>
              ) : (
                <span title="Not verified" className="text-yellow-500 text-sm">
                  ⚠
                </span>
              )}
            </div>
            {c.name && <div className="truncate font-mono text-xs text-neutral-600">{c.px_id}</div>}
          </button>
          <button
            onClick={() => nav(`/verify/${c.px_id}`)}
            className="rounded px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
          >
            Code
          </button>
          <button
            onClick={() => void rename(c)}
            className="rounded px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
          >
            Rename
          </button>
          <button
            onClick={() => void remove(c)}
            className="rounded px-2 py-1 text-xs text-red-400 hover:bg-neutral-800"
          >
            Remove
          </button>
        </li>
      ))}
    </ul>
  );
}
