import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ContactList from "../components/ContactList";
import ConnectionStatus from "../components/ConnectionStatus";
import { UserPlusIcon } from "../components/icons";
import { listContacts } from "../data/contacts";
import { onContactsChanged } from "../services/events";

export default function ConversationList() {
  // Surface a Requests entry point only when something's pending - the list itself
  // lives on the /add-contact "Requests" tab, keeping this page clean.
  const [pending, setPending] = useState(0);
  const refresh = useCallback(() => {
    void listContacts().then((all) =>
      setPending(all.filter((c) => c.status === "pending_inbound").length),
    );
  }, []);
  useEffect(() => {
    refresh();
    return onContactsChanged(refresh);
  }, [refresh]);

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 p-6">
      <div className="mx-auto w-full max-w-md">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold">Conversations</h1>
            <ConnectionStatus />
          </div>
          <div className="flex items-center gap-2">
            {pending > 0 && (
              <Link
                to="/add-contact?tab=requests"
                title={`${pending} pending friend request${pending === 1 ? "" : "s"}`}
                aria-label={`${pending} pending friend requests`}
                className="relative rounded-lg border border-neutral-700 p-1.5 text-neutral-300 hover:bg-neutral-800"
              >
                <UserPlusIcon />
                <span className="absolute -right-1.5 -top-1.5 min-w-[1.1rem] rounded-full bg-indigo-600 px-1 text-center text-xs font-medium leading-[1.1rem] text-white">
                  {pending > 9 ? "9+" : pending}
                </span>
              </Link>
            )}
            <Link
              to="/add-contact"
              className="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 text-sm font-medium"
            >
              + Add contact
            </Link>
            <Link
              to="/settings"
              title="Settings"
              className="rounded-lg border border-neutral-700 hover:bg-neutral-800 px-2 py-1.5 text-sm"
            >
              ⚙
            </Link>
          </div>
        </div>
        <div className="mt-6">
          <ContactList />
        </div>
      </div>
    </main>
  );
}
