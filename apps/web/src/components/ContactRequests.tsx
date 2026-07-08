// Incoming friend requests (opt-in). An unsolicited inbound - a ContactHello or a
// first message from someone we never added - lands as `pending_inbound` and shows
// here (the "Requests" tab of /add-contact), NOT in the home contact list. The user
// accepts (→ a normal chat) or declines (→ dropped locally; no signal is sent to the
// requester, so there's no accept/decline oracle).
import { useCallback, useEffect, useState } from "react";
import { acceptContact, listContacts, removeContact, type PlainContact } from "../data/contacts";
import { onContactsChanged } from "../services/events";

export default function ContactRequests() {
  const [requests, setRequests] = useState<PlainContact[]>([]);

  const reload = useCallback(() => {
    void listContacts().then((all) =>
      setRequests(all.filter((c) => c.status === "pending_inbound")),
    );
  }, []);
  useEffect(() => {
    reload();
    return onContactsChanged(reload); // accept/decline/new-request all re-fire this
  }, [reload]);

  if (requests.length === 0) {
    return (
      <p className="mt-6 text-sm text-text-muted">
        No pending requests. When someone adds you, they'll appear here for you to accept.
      </p>
    );
  }

  return (
    <ul className="mt-4 divide-y divide-divider">
      {requests.map((c) => (
        <li key={c.px_id} className="flex items-center gap-3 py-3">
          <div className="min-w-0 flex-1">
            <div className="truncate font-mono text-sm">{c.px_id}</div>
            <div className="text-xs text-text-muted">wants to connect</div>
          </div>
          <button
            onClick={() => void acceptContact(c.px_id)}
            className="rounded bg-accent px-3 py-1 text-xs font-medium hover:bg-accent-hover"
          >
            Accept
          </button>
          <button
            onClick={() => void removeContact(c.px_id)}
            className="rounded px-2 py-1 text-xs text-text-secondary hover:bg-raised"
          >
            Decline
          </button>
        </li>
      ))}
    </ul>
  );
}
