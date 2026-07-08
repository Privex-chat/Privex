import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import ContactList from "../components/ContactList";
import ConnectionStatus from "../components/ConnectionStatus";
import { UserPlusIcon } from "../components/icons";
import { listContacts } from "../data/contacts";
import { onContactsChanged } from "../services/events";

export default function ConversationList() {
  const nav = useNavigate();
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
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100">
      <div className="mx-auto w-full max-w-2xl px-4 py-6">
        {/* Header */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-indigo-600/20 text-sm font-bold text-indigo-400">
              P
            </div>
            <div>
              <h1 className="text-xl font-semibold leading-tight">Conversations</h1>
              <p className="text-xs text-neutral-500">Zero-knowledge messenger</p>
            </div>
            <ConnectionStatus />
          </div>
          <div className="flex items-center gap-2">
            {pending > 0 && (
              <button
                onClick={() => nav("/add-contact?tab=requests")}
                title={`${pending} pending request${pending === 1 ? "" : "s"}`}
                aria-label={`${pending} pending requests`}
                className="relative rounded-lg border border-neutral-700 p-2 text-neutral-300 transition-colors hover:bg-neutral-800"
              >
                <UserPlusIcon />
                <span className="absolute -right-1.5 -top-1.5 flex min-w-[1.1rem] items-center justify-center rounded-full bg-indigo-600 px-1 text-center text-xs font-medium leading-[1.1rem] text-white">
                  {pending > 9 ? "9+" : pending}
                </span>
              </button>
            )}
            <button
              onClick={() => nav("/add-contact")}
              className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium transition-colors hover:bg-indigo-500"
            >
              + Add contact
            </button>
            <button
              onClick={() => nav("/my-qr")}
              title="Show my QR"
              aria-label="Show my QR code"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-100"
            >
              <svg viewBox="0 0 24 24" fill="none" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0 1 3.75 9.375v-4.5ZM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 0 1-1.125-1.125v-4.5ZM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0 1 13.5 9.375v-4.5Z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 0 1-1.125-1.125v-4.5Z" />
              </svg>
            </button>
            <button
              onClick={() => nav("/settings/account")}
              title="Settings"
              aria-label="Settings"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-100"
            >
              <svg viewBox="0 0 24 24" fill="none" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
              </svg>
            </button>
          </div>
        </header>

        {/* Contact list */}
        <div className="mt-6">
          <ContactList />
        </div>

        {/* Subtle privacy footer */}
        <p className="mt-8 text-center text-[11px] text-neutral-700">
          Your identity exists only on this device. We never know who you are.
        </p>
      </div>
    </main>
  );
}
