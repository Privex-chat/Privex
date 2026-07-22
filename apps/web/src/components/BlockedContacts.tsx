// Blocked contacts (client-only; the server never learns who you blocked). While
// blocked, a sender's incoming messages AND contact requests are decrypted then
// silently dropped (receiveMessage). Unblock restores them to a normal contact,
// keeping any chat history; "Delete chat" purges everything locally.
import { useCallback, useEffect, useState } from "react";
import { listContacts, removeContact, unblockContact, type PlainContact } from "../data/contacts";
import { onContactsChanged } from "../services/events";
import Avatar from "./Avatar";
import { ConfirmDialog } from "./Modal";

export default function BlockedContacts() {
  const [blocked, setBlocked] = useState<PlainContact[]>([]);
  const [removing, setRemoving] = useState<PlainContact | null>(null);

  const reload = useCallback(() => {
    void listContacts().then((all) => setBlocked(all.filter((c) => c.status === "blocked")));
  }, []);
  useEffect(() => {
    reload();
    return onContactsChanged(reload);
  }, [reload]);

  if (blocked.length === 0) {
    return (
      <p className="mt-4 text-sm text-text-muted">
        No blocked contacts. Blocking someone silently drops their messages and requests.
      </p>
    );
  }

  return (
    <>
      <ul className="mt-3 divide-y divide-divider">
        {blocked.map((c) => (
          <li key={c.px_id} className="flex items-center gap-3 py-3">
            <Avatar seed={c.px_id} size={36} title={c.name || c.px_id} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{c.name || c.px_id}</div>
              {c.name && <div className="truncate font-mono text-xs text-text-subtle">{c.px_id}</div>}
            </div>
            <button
              onClick={() => void unblockContact(c.px_id)}
              className="rounded-lg bg-raised px-3 py-1.5 text-xs font-medium hover:bg-border-strong"
            >
              Unblock
            </button>
            <button
              onClick={() => setRemoving(c)}
              className="rounded-lg px-2 py-1.5 text-xs text-danger hover:bg-raised"
            >
              Delete chat
            </button>
          </li>
        ))}
      </ul>

      <ConfirmDialog
        open={removing !== null}
        title="Delete chat"
        message={`Delete your chat with ${removing?.name || removing?.px_id}? This removes it and its messages from this device.`}
        confirmLabel="Delete"
        danger
        onConfirm={() => {
          if (removing) void removeContact(removing.px_id);
          setRemoving(null);
        }}
        onCancel={() => setRemoving(null)}
      />
    </>
  );
}
