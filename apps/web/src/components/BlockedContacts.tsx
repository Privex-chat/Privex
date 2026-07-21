// Blocked contacts (client-only; the server never learns who you blocked). While
// blocked, a sender's incoming messages AND contact requests are decrypted then
// silently dropped (receiveMessage). Unblock restores them to a normal contact,
// keeping any chat history; "Delete chat" purges everything locally.
import { useCallback, useEffect, useState } from "react";
import { listContacts, removeContact, unblockContact, type PlainContact } from "../data/contacts";
import { onContactsChanged } from "../services/events";

export default function BlockedContacts() {
  const [blocked, setBlocked] = useState<PlainContact[]>([]);

  const reload = useCallback(() => {
    void listContacts().then((all) => setBlocked(all.filter((c) => c.status === "blocked")));
  }, []);
  useEffect(() => {
    reload();
    return onContactsChanged(reload);
  }, [reload]);

  if (blocked.length === 0) {
    return (
      <p className="mt-6 text-sm text-text-muted">
        No blocked contacts. Blocking someone silently drops their messages and requests.
      </p>
    );
  }

  return (
    <ul className="mt-4 divide-y divide-divider">
      {blocked.map((c) => (
        <li key={c.px_id} className="flex items-center gap-3 py-3">
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm">{c.name || c.px_id}</div>
            {c.name && <div className="truncate font-mono text-xs text-text-subtle">{c.px_id}</div>}
          </div>
          <button
            onClick={() => void unblockContact(c.px_id)}
            className="rounded bg-raised px-3 py-1 text-xs font-medium hover:bg-border-strong"
          >
            Unblock
          </button>
          <button
            onClick={() => {
              if (window.confirm(`Delete chat with ${c.name || c.px_id}? This can't be undone.`))
                void removeContact(c.px_id);
            }}
            className="rounded px-2 py-1 text-xs text-danger hover:bg-raised"
          >
            Delete chat
          </button>
        </li>
      ))}
    </ul>
  );
}
