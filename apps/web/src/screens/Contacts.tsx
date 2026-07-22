// Add a contact by px_id. Fetches + verifies their key bundle against the pinned
// KT key (rejecting on any MITM signal) and precomputes the PQXDH session + ratchet,
// then sends the user to compare safety codes.
//
// QR scanning uses html5-qrcode, lazy-imported only when the user taps Scan - it
// never lands in the main bundle.
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { addContact } from "../contacts/add";
import { getContact, listContacts } from "../data/contacts";
import { onContactsChanged } from "../services/events";
import ContactRequests from "../components/ContactRequests";
import BlockedContacts from "../components/BlockedContacts";
import QrScanner from "../components/QrScanner";

type Tab = "add" | "requests" | "blocked";

export default function Contacts() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  // Deep-linkable: /add-contact?tab=requests|blocked.
  const raw = params.get("tab");
  const tab: Tab = raw === "requests" ? "requests" : raw === "blocked" ? "blocked" : "add";
  const setTab = (t: Tab) => setParams(t === "add" ? {} : { tab: t }, { replace: true });

  const [pendingCount, setPendingCount] = useState(0);
  const refreshCount = useCallback(() => {
    void listContacts().then((all) =>
      setPendingCount(all.filter((c) => c.status === "pending_inbound").length),
    );
  }, []);
  useEffect(() => {
    refreshCount();
    return onContactsChanged(refreshCount);
  }, [refreshCount]);

  const [pxId, setPxId] = useState("");
  const [busy, setBusy] = useState(false);
  const [showScanner, setShowScanner] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    setSent(false);
    try {
      const added = await addContact(pxId.trim());
      // If they'd already requested us (glare) → now accepted → go verify/chat.
      // Otherwise a request was just sent → confirm and switch to the Sent list.
      const status = (await getContact(added.userId))?.status;
      if (status === "accepted") {
        nav(`/verify/${added.userId}`, { replace: true });
        return;
      }
      setPxId("");
      setSent(true);
      setBusy(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not add contact.");
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-surface text-text-primary">
      <div className="mx-auto w-full max-w-2xl px-4 py-6">
        <div className="flex items-baseline justify-between gap-3">
          <h1 className="text-2xl font-semibold">Contacts</h1>
          <button
            onClick={() => nav("/settings/guide")}
            className="shrink-0 text-xs text-accent-text transition-colors hover:underline"
          >
            How this works
          </button>
        </div>

        {/* Add / Requests / Blocked tabs - requests live here (not on the Chats list). */}
        <div className="mt-5 flex gap-1 border-b border-divider text-sm">
          <button
            onClick={() => setTab("add")}
            className={`-mb-px border-b-2 px-3 py-2 ${
              tab === "add"
                ? "border-border-focus text-text-primary"
                : "border-transparent text-text-secondary hover:text-text"
            }`}
          >
            Add
          </button>
          <button
            onClick={() => setTab("requests")}
            className={`-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 ${
              tab === "requests"
                ? "border-border-focus text-text-primary"
                : "border-transparent text-text-secondary hover:text-text"
            }`}
          >
            Requests
            {pendingCount > 0 && (
              <span className="rounded-full bg-accent px-1.5 text-xs font-medium text-white">
                {pendingCount}
              </span>
            )}
          </button>
          <button
            onClick={() => setTab("blocked")}
            className={`-mb-px border-b-2 px-3 py-2 ${
              tab === "blocked"
                ? "border-border-focus text-text-primary"
                : "border-transparent text-text-secondary hover:text-text"
            }`}
          >
            Blocked
          </button>
        </div>

        {tab === "requests" ? (
          <ContactRequests />
        ) : tab === "blocked" ? (
          <BlockedContacts />
        ) : (
          <>
            <h1 className="mt-5 text-xl font-semibold">Add a contact</h1>
            <p className="mt-2 text-text-secondary text-sm">
              Paste their Privex ID or scan their QR. We fetch their keys, verify them
              against the key transparency log, and reject anything tampered with. They&rsquo;ll
              get a request to accept before you can message.
            </p>
            {sent && (
              <p className="mt-3 rounded-lg bg-success-bg px-3 py-2 text-sm text-success">
                Request sent — you can message them once they accept. See the{" "}
                <button className="underline" onClick={() => setTab("requests")}>
                  Requests
                </button>{" "}
                tab.
              </p>
            )}

            <label className="mt-6 block text-sm text-text-secondary">Privex ID</label>
            <input
              value={pxId}
              onChange={(e) => setPxId(e.target.value)}
              placeholder="px_…"
              maxLength={35}
              spellCheck={false}
              autoCapitalize="none"
              className="mt-1 w-full rounded-lg bg-input border border-border-strong px-3 py-2 font-mono text-sm outline-none focus:border-border-focus"
            />

            <div className="mt-3 flex gap-3">
              <button
                onClick={() => setShowScanner(true)}
                className="rounded-lg border border-border-strong hover:bg-elevated px-4 py-2 text-sm"
              >
                Scan QR
              </button>
            </div>

            <QrScanner
              open={showScanner}
              onClose={() => setShowScanner(false)}
              onResult={(id) => {
                setPxId(id);
                setError(null);
                setShowScanner(false);
              }}
            />

            {error && <p className="mt-3 text-sm text-danger">{error}</p>}

            <button
              disabled={busy || pxId.trim().length === 0}
              onClick={() => void submit()}
              className="mt-6 w-full rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed py-3 font-medium"
            >
              {busy ? "Verifying keys…" : "Add contact"}
            </button>
          </>
        )}
      </div>
    </main>
  );
}
