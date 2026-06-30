// Safety-code verification (docs 4.1, Signal-style Safety Numbers). Both parties
// see the SAME 8×5-digit code (SHA-256 over their two sorted Ed25519 identity
// keys). Comparing it out-of-band rules out a MITM on the key exchange.
//
// ponytail: the code is also meant to render as a QR - skipped with the scanner
// (no QR lib yet). The decimal code is the verifiable artifact; add QR later.
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { safetyCode } from "../crypto/contact-crypto";
import { getContact, setVerified } from "../data/contacts";
import { loadBundle } from "../onboarding/store";

export default function KeyVerification() {
  const { id } = useParams();
  const nav = useNavigate();
  const [code, setCode] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [verified, setVerifiedState] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        // Render the code as a QR for easy comparison (lazy - qrcode stays out of
        // the main bundle). Data-URL <img> is permitted by the img-src CSP.
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

  async function markVerified() {
    if (!id || !code) return;
    await setVerified(id, code);
    setVerifiedState(true);
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
              Compare this code with {name} over a separate channel - in person, a
              phone call, or another app. If it matches exactly, tap Verified.
            </p>

            {verified ? (
              <p className="mt-6 text-green-400">✓ Verified</p>
            ) : (
              <button
                onClick={() => void markVerified()}
                className="mt-6 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium"
              >
                It matches - mark Verified
              </button>
            )}
          </>
        )}
      </div>
    </main>
  );
}
