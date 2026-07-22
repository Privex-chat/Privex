// Chats tab (home). The conversation list itself lives in <ContactList/>. Settings
// and Contacts (with the pending-request badge) now live in the AppShell nav, so
// this header only carries the identity mark, connection status, QR, and a quick
// "Add" shortcut into the Contacts tab.
import { useNavigate } from "react-router-dom";
import ContactList from "../components/ContactList";
import ConnectionStatus from "../components/ConnectionStatus";

export default function ConversationList() {
  const nav = useNavigate();

  return (
    <main className="min-h-full bg-surface text-text-primary">
      <div className="mx-auto w-full max-w-2xl px-4 py-6">
        <header className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent-bg text-sm font-bold text-accent-text">
              P
            </div>
            <div className="min-w-0">
              <h1 className="text-xl font-semibold leading-tight">Chats</h1>
              <p className="text-xs text-text-muted">Zero-knowledge messenger</p>
            </div>
            <ConnectionStatus />
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              onClick={() => nav("/my-qr")}
              title="Show my QR"
              aria-label="Show my QR code"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
            >
              <svg viewBox="0 0 24 24" fill="none" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0 1 3.75 9.375v-4.5ZM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 0 1-1.125-1.125v-4.5ZM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0 1 13.5 9.375v-4.5Z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 0 1-1.125-1.125v-4.5Z" />
              </svg>
            </button>
            <button
              onClick={() => nav("/contacts")}
              title="Add contact"
              aria-label="Add contact"
              className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-sm font-medium transition-colors hover:bg-accent-hover"
            >
              <span className="text-base leading-none">+</span>
              <span className="hidden sm:inline">Add</span>
            </button>
          </div>
        </header>

        {/* Contact list */}
        <div className="mt-6">
          <ContactList />
        </div>

        {/* Subtle privacy footer */}
        <p className="mt-8 text-center text-[11px] text-text-subtle">
          Your identity exists only on this device. We never know who you are.
        </p>
      </div>
    </main>
  );
}
