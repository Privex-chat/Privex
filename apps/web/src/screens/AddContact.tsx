// Add a contact by px_id. Fetches + verifies their key bundle against the pinned
// KT key (rejecting on any MITM signal) and precomputes the PQXDH session + ratchet,
// then sends the user to compare safety codes.
//
// QR scanning uses html5-qrcode, lazy-imported only when the user taps Scan - it
// never lands in the main bundle.
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import type { Html5Qrcode } from "html5-qrcode";
import { addContact } from "../contacts/add";
import { listContacts } from "../data/contacts";
import { onContactsChanged } from "../services/events";
import ContactRequests from "../components/ContactRequests";

const QR_ELEMENT_ID = "qr-reader";

type Tab = "add" | "requests";

export default function AddContact() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  // Deep-linkable: /add-contact?tab=requests opens straight to the requests tab.
  const tab: Tab = params.get("tab") === "requests" ? "requests" : "add";
  const setTab = (t: Tab) => setParams(t === "requests" ? { tab: "requests" } : {}, { replace: true });

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
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const added = await addContact(pxId.trim());
      nav(`/verify/${added.userId}`, { replace: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not add contact.");
      setBusy(false);
    }
  }

  async function stopScan() {
    const s = scannerRef.current;
    scannerRef.current = null;
    setScanning(false);
    if (s) await s.stop().catch(() => {});
  }

  async function startScan() {
    setError(null);
    setScanning(true);
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      const scanner = new Html5Qrcode(QR_ELEMENT_ID);
      scannerRef.current = scanner;
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 240 },
        (decoded) => {
          setPxId(decoded.trim());
          void stopScan();
        },
        () => {}, // per-frame decode failures are normal; ignore
      );
    } catch {
      setError("Couldn't start the camera. Paste the ID instead.");
      await stopScan();
    }
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 p-6">
      <div className="mx-auto w-full max-w-md">
        <button onClick={() => nav("/")} className="text-sm text-neutral-500 hover:text-neutral-300">
          ← Back
        </button>

        {/* Add / Requests tabs - requests live here (not on the home list). */}
        <div className="mt-4 flex gap-1 border-b border-neutral-800 text-sm">
          <button
            onClick={() => setTab("add")}
            className={`-mb-px border-b-2 px-3 py-2 ${
              tab === "add"
                ? "border-indigo-500 text-neutral-100"
                : "border-transparent text-neutral-400 hover:text-neutral-200"
            }`}
          >
            Add
          </button>
          <button
            onClick={() => setTab("requests")}
            className={`-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 ${
              tab === "requests"
                ? "border-indigo-500 text-neutral-100"
                : "border-transparent text-neutral-400 hover:text-neutral-200"
            }`}
          >
            Requests
            {pendingCount > 0 && (
              <span className="rounded-full bg-indigo-600 px-1.5 text-xs font-medium text-white">
                {pendingCount}
              </span>
            )}
          </button>
        </div>

        {tab === "requests" ? (
          <ContactRequests />
        ) : (
          <>
            <h1 className="mt-5 text-xl font-semibold">Add a contact</h1>
            <p className="mt-2 text-neutral-400 text-sm">
              Paste their Privex ID or scan their QR. We fetch their keys, verify them
              against the key transparency log, and reject anything tampered with.
            </p>

            <label className="mt-6 block text-sm text-neutral-300">Privex ID</label>
            <input
              value={pxId}
              onChange={(e) => setPxId(e.target.value)}
              placeholder="px_…"
              spellCheck={false}
              autoCapitalize="none"
              className="mt-1 w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-2 font-mono text-sm outline-none focus:border-indigo-500"
            />

            {/* html5-qrcode renders the camera preview into this element while scanning. */}
            <div id={QR_ELEMENT_ID} className={scanning ? "mt-4 overflow-hidden rounded-lg" : "hidden"} />

            <div className="mt-3 flex gap-3">
              {scanning ? (
                <button
                  onClick={() => void stopScan()}
                  className="rounded-lg border border-neutral-700 hover:bg-neutral-900 px-4 py-2 text-sm"
                >
                  Cancel scan
                </button>
              ) : (
                <button
                  onClick={() => void startScan()}
                  className="rounded-lg border border-neutral-700 hover:bg-neutral-900 px-4 py-2 text-sm"
                >
                  Scan QR
                </button>
              )}
            </div>

            {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

            <button
              disabled={busy || pxId.trim().length === 0}
              onClick={() => void submit()}
              className="mt-6 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 font-medium"
            >
              {busy ? "Verifying keys…" : "Add contact"}
            </button>
          </>
        )}
      </div>
    </main>
  );
}
