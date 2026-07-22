// Friend requests (Discord-style, opt-in). Two sections:
//  - INCOMING (`pending_inbound`): someone requested us → Accept (sends a sealed
//    contact_accept back so they learn the outcome), Decline (dropped locally; NO
//    signal is sent, so there's no accept/decline oracle — they just stay on
//    "pending"; they CAN request again later), or Block (drops this request AND
//    all their future requests/messages, without ever accepting them). All silent.
//  - OUTGOING (`pending_outbound`): we requested them and are waiting. Cancel just
//    forgets it locally (there is no server-side request record to retract).
// Everything rides Sealed Sender, so the server still learns no social graph.
import { useCallback, useEffect, useState } from "react";
import { blockContact, listContacts, removeContact, type PlainContact } from "../data/contacts";
import { acceptContactRequest } from "../services/messaging";
import { onContactsChanged } from "../services/events";

export default function ContactRequests() {
  const [incoming, setIncoming] = useState<PlainContact[]>([]);
  const [outgoing, setOutgoing] = useState<PlainContact[]>([]);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    void listContacts().then((all) => {
      setIncoming(all.filter((c) => c.status === "pending_inbound"));
      setOutgoing(all.filter((c) => c.status === "pending_outbound"));
    });
  }, []);
  useEffect(() => {
    reload();
    return onContactsChanged(reload); // accept/decline/new-request all re-fire this
  }, [reload]);

  // Surface store/network failures instead of discarding the rejected promise -
  // a silent Block failure would give a false sense of privacy (finding parity
  // with Chat.block()).
  const run = (p: Promise<unknown>, fallback: string) => {
    setError(null);
    void p.catch((e) => setError(e instanceof Error ? e.message : fallback));
  };

  if (incoming.length === 0 && outgoing.length === 0) {
    return (
      <p className="mt-6 text-sm text-text-muted">
        No pending requests. When someone adds you, they&rsquo;ll appear here for you to accept.
      </p>
    );
  }

  return (
    <div className="mt-4 space-y-6">
      {error && <p className="text-sm text-danger">{error}</p>}
      {incoming.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">Incoming</h3>
          <ul className="mt-2 divide-y divide-divider">
            {incoming.map((c) => (
              <li key={c.px_id} className="flex items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-sm">{c.name || c.px_id}</div>
                  <div className="text-xs text-text-muted">wants to connect</div>
                </div>
                <button
                  onClick={() => run(acceptContactRequest(c.px_id), "Couldn't accept.")}
                  className="rounded bg-accent px-3 py-1 text-xs font-medium hover:bg-accent-hover"
                >
                  Accept
                </button>
                <button
                  onClick={() => run(removeContact(c.px_id), "Couldn't decline.")}
                  className="rounded px-2 py-1 text-xs text-text-secondary hover:bg-raised"
                >
                  Decline
                </button>
                <button
                  onClick={() => run(blockContact(c.px_id), "Couldn't block this contact.")}
                  title="Block — drops this and all their future requests/messages"
                  className="rounded px-2 py-1 text-xs text-danger hover:bg-raised"
                >
                  Block
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {outgoing.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">Sent</h3>
          <ul className="mt-2 divide-y divide-divider">
            {outgoing.map((c) => (
              <li key={c.px_id} className="flex items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-sm">{c.name || c.px_id}</div>
                  <div className="text-xs text-text-muted">Request sent — waiting for them to accept</div>
                </div>
                <button
                  onClick={() => run(removeContact(c.px_id), "Couldn't cancel.")}
                  className="rounded px-2 py-1 text-xs text-text-secondary hover:bg-raised"
                >
                  Cancel
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
