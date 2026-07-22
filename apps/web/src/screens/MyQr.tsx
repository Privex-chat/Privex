// Shows the user's own Privex ID as a QR code for someone else to scan from the
// Contacts tab. The QR encodes the raw px_... string — exactly what Scan QR expects.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../store/auth";

export default function MyQr() {
  const nav = useNavigate();
  const pxId = useAuth((s) => s.userId) ?? "";
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void (async () => {
      const { toDataURL } = await import("qrcode");
      setQrUrl(await toDataURL(pxId, { margin: 2, width: 280 }));
    })();
  }, [pxId]);

  async function copy() {
    await navigator.clipboard?.writeText(pxId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const navBack = () => nav(-1);

  return (
    <main className="min-h-screen bg-surface text-text-primary flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-sm text-center">
        <button
          onClick={navBack}
          className="flex h-9 w-9 items-center justify-center rounded-full text-lg text-text-secondary transition-colors hover:bg-raised hover:text-text-primary"
        >
          ←
        </button>
        <h1 className="mt-4 text-xl font-semibold">Your Privex ID</h1>
        <p className="mt-2 text-sm text-text-secondary">Ask them to scan this to add you.</p>

        {qrUrl && (
          <img
            src={qrUrl}
            alt="Your Privex ID QR code"
            className="mx-auto mt-6 rounded-xl bg-qr-bg p-3"
          />
        )}

        <code className="mt-6 block break-all rounded-lg bg-elevated p-3 font-mono text-xs text-accent-subtle">
          {pxId}
        </code>

        <button
          onClick={() => void copy()}
          className="mt-4 rounded-lg bg-raised hover:bg-border-strong px-4 py-2 text-sm transition-colors"
        >
          {copied ? "Copied" : "Copy ID"}
        </button>

        <p className="mt-8 text-xs text-text-subtle">
          Your ID is safe to share — it&rsquo;s only used to establish encrypted sessions.
        </p>
      </div>
    </main>
  );
}
