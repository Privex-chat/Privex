// Safety-code verification (docs 4.1, Signal-style Safety Numbers). Both parties
// see the SAME 8×5-digit code (SHA-256 over their two sorted Ed25519 identity
// keys). Comparing it out-of-band rules out a MITM on the key exchange.
// The QR on this page can now ALSO be scanned — the scanner reads the numeric
// code and compares it against the local computation, auto-verifying on match.
import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import type { Html5Qrcode } from "html5-qrcode";
import { safetyCode } from "../crypto/contact-crypto";
import { getContact, setVerified } from "../data/contacts";
import { loadBundle } from "../onboarding/store";

const QR_ELEMENT_ID = "verify-qr-reader";

export default function KeyVerification() {
  const { id } = useParams();
  const nav = useNavigate();
  const [code, setCode] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [verified, setVerifiedState] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<"match" | "no-match" | null>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);

  useEffect(() => {
    let off = false;
    void (async () => {
      try {
        const me = await loadBundle();
        const contact = id ? await getContact(id) : undefined;
        if (!me || !contact || contact.ik_ed25519.length === 0) {
          if (!off) setError("Contact not found.");
          return;
        }
        const c = await safetyCode(me.identity.ed25519_pub, contact.ik_ed25519);
        if (off) return;
        setCode(c);
        setName(contact.name || contact.px_id);
        setVerifiedState(contact.verified);
        const { toDataURL } = await import("qrcode");
        const url = await toDataURL(c, { margin: 1, width: 220 });
        if (!off) setQr(url);
      } catch {
        if (!off) setError("Could not compute the safety code.");
      }
    })();
    return () => {
      off = true;
    };
  }, [id]);

  useEffect(() => {
    return () => {
      if (scannerRef.current) {
        void scannerRef.current.stop().catch(() => {});
      }
    };
  }, []);

  async function markVerified() {
    if (!id || !code) return;
    await setVerified(id, code);
    setVerifiedState(true);
  }

  async function stopScan() {
    const s = scannerRef.current;
    scannerRef.current = null;
    setScanning(false);
    if (s) await s.stop().catch(() => {});
  }

  async function startScan() {
    setError(null);
    setScanResult(null);
    setScanning(true);
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      const scanner = new Html5Qrcode(QR_ELEMENT_ID);
      scannerRef.current = scanner;
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 240 },
        (decoded) => {
          const trimmed = decoded.trim();
          if (trimmed === code) {
            setScanResult("match");
            void stopScan();
            if (id && code) void setVerified(id, code);
            setVerifiedState(true);
          } else {
            setScanResult("no-match");
            void stopScan();
          }
        },
        () => {},
      );
    } catch {
      setError("Couldn't start the camera. Compare the code manually instead.");
      await stopScan();
    }
  }

  const groups = code ? code.split(" ") : [];

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 p-6">
      <div className="mx-auto w-full max-w-md">
        <button onClick={() => nav("/")} className="text-sm text-neutral-500 hover:text-neutral-300">
          ← Back
        </button>
        <h1 className="mt-4 text-xl font-semibold">Verify {name}</h1>

        {error && <p className="mt-4 text-red-400 text-sm">{error}</p>}

        {code && (
          <>
            <div className="mt-6 grid grid-cols-4 gap-2 rounded-xl bg-neutral-900 p-4 font-mono text-lg tracking-widest">
              {groups.map((g, i) => (
                <span key={i} className="text-center text-indigo-300">
                  {g}
                </span>
              ))}
            </div>
            {qr && (
              <div className="mt-4 flex justify-center">
                <img src={qr} alt="Safety code QR" className="rounded-lg bg-white p-2" />
              </div>
            )}
            <p className="mt-4 text-neutral-400 text-sm">
              Compare this code with {name} over a separate channel — in person, a
              phone call, or another app. If it matches exactly, tap Verified.
            </p>

            <div id={QR_ELEMENT_ID} className={scanning ? "mt-4 overflow-hidden rounded-lg" : "hidden"} />

            {scanResult === "match" && (
              <p className="mt-4 text-green-400 text-sm">✓ Codes match — automatically verified.</p>
            )}
            {scanResult === "no-match" && (
              <p className="mt-4 text-red-400 text-sm">✗ Codes do not match. Do not verify.</p>
            )}

            {verified ? (
              <p className="mt-6 text-green-400">✓ Verified</p>
            ) : (
              <div className="mt-6 space-y-3">
                {scanning ? (
                  <button
                    onClick={() => void stopScan()}
                    className="w-full rounded-lg border border-neutral-700 hover:bg-neutral-900 py-3 text-sm"
                  >
                    Cancel scan
                  </button>
                ) : (
                  <button
                    onClick={() => void startScan()}
                    className="w-full rounded-lg border border-neutral-700 hover:bg-neutral-900 py-3 text-sm"
                  >
                    Scan their QR
                  </button>
                )}
                <button
                  onClick={() => void markVerified()}
                  className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium"
                >
                  It matches — mark Verified
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}
