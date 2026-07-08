// Device-to-device history transfer UI (history sync Option B).
//   Send  (existing device): show a transfer CODE (copy it, or let the other device
//          scan the QR), wait for the new device, confirm the 6-digit code matches on
//          both screens, then stream history.
//   Receive (new device): PASTE the code (works without a webcam) or scan the QR,
//          confirm the code, import history.
// The 6-digit code is the anti-MITM check: the relay is untrusted, so the user MUST
// confirm the codes match before any data moves. QR libs are lazy-imported.
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Html5Qrcode } from "html5-qrcode";
import {
  encodeTransferToken,
  parseTransferToken,
  startExport,
  startImport,
  type QrPayload,
  type TransferHandle,
} from "../services/devicelink";

type Mode = "choose" | "send" | "receive";
const QR_ELEMENT_ID = "devlink-qr-reader";

const STATUS_TEXT: Record<string, string> = {
  connecting: "Connecting…",
  waiting: "Waiting for the other device…",
  confirm: "Check the codes match on both devices.",
  transferring: "Transferring…",
  done: "Done.",
};

export default function DeviceTransfer() {
  const nav = useNavigate();
  const [mode, setMode] = useState<Mode>("choose");
  const [code, setCode] = useState<string | null>(null); // the transfer token (sender)
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [sas, setSas] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("");
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [finished, setFinished] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [paste, setPaste] = useState("");
  const handleRef = useRef<TransferHandle | null>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);

  useEffect(() => {
    return () => {
      handleRef.current?.cancel();
      void scannerRef.current?.stop().catch(() => {});
    };
  }, []);

  const callbacks = {
    onSas: setSas,
    onStatus: setStatus,
    onProgress: (done: number, total: number) => setProgress({ done, total }),
    onError: (m: string) => setError(m),
  };

  function watchDone(h: TransferHandle) {
    handleRef.current = h;
    h.done.then((n) => setFinished(n)).catch(() => {});
  }

  async function beginSend() {
    setMode("send");
    setError(null);
    setStatus("connecting");
    try {
      const h = await startExport({
        ...callbacks,
        onQr: async (qr: QrPayload) => {
          const token = encodeTransferToken(qr);
          setCode(token);
          const { toDataURL } = await import("qrcode");
          setQrUrl(await toDataURL(token, { margin: 2, width: 240, errorCorrectionLevel: "M" }));
        },
      });
      watchDone(h);
    } catch {
      setError("Couldn't start the transfer. Check your connection and try again.");
    }
  }

  async function beginReceive(payload: string) {
    setError(null);
    const qr = parseTransferToken(payload);
    if (!qr) {
      setError("That isn't a valid Privex transfer code.");
      return;
    }
    setStatus("connecting");
    try {
      watchDone(await startImport(qr, callbacks));
    } catch {
      setError("Couldn't connect to the other device.");
    }
  }

  async function copyCode() {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("Couldn't copy - select the code and copy it manually.");
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
    // Let React mount + lay out the (visible, sized) reader element BEFORE start,
    // otherwise html5-qrcode starts the camera in a zero-size box and never decodes.
    await new Promise((r) => setTimeout(r, 60));
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      const scanner = new Html5Qrcode(QR_ELEMENT_ID);
      scannerRef.current = scanner;
      await scanner.start(
        { facingMode: "environment" },
        {
          fps: 10,
          qrbox: (w: number, h: number) => {
            const s = Math.floor(Math.min(w, h) * 0.8);
            return { width: s, height: s };
          },
        },
        (decoded) => {
          void stopScan();
          void beginReceive(decoded);
        },
        () => {},
      );
    } catch {
      setError("Couldn't start the camera. Paste the code instead.");
      await stopScan();
    }
  }

  function confirm() {
    handleRef.current?.confirm();
    setConfirmed(true);
  }

  const pct = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 p-6">
      <div className="mx-auto w-full max-w-md">
        <button onClick={() => nav("/settings/account")} className="text-sm text-neutral-500 hover:text-neutral-300">
          ← Back
        </button>
        <h1 className="mt-4 text-xl font-semibold">Transfer history</h1>

        {mode === "choose" && (
          <div className="mt-4 space-y-3">
            <p className="text-sm text-neutral-400">
              Move your chat history to another device directly - encrypted end-to-end, nothing stored on the
              server. Both devices must be online.
            </p>
            <button onClick={() => void beginSend()} className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium">
              Send from this device
            </button>
            <button onClick={() => setMode("receive")} className="w-full rounded-lg border border-neutral-700 hover:bg-neutral-900 py-3 font-medium">
              Receive on this device
            </button>
          </div>
        )}

        {mode === "send" && !sas && (
          <div className="mt-4 space-y-3">
            <p className="text-sm text-neutral-400">
              On your other device, choose <span className="text-neutral-200">Receive</span>, then paste this code
              (or scan the QR):
            </p>
            <div className="flex gap-2">
              <input
                readOnly
                value={code ?? "…"}
                onFocus={(e) => e.currentTarget.select()}
                className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 font-mono text-xs outline-none"
              />
              <button
                onClick={() => void copyCode()}
                disabled={!code}
                className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-3 py-2 text-sm font-medium"
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            {qrUrl && (
              <div className="flex justify-center pt-1">
                <img src={qrUrl} alt="Transfer QR" className="rounded-lg bg-white p-2" />
              </div>
            )}
          </div>
        )}

        {mode === "receive" && !sas && (
          <div className="mt-4 space-y-3">
            <p className="text-sm text-neutral-400">Paste the code from your other device:</p>
            <textarea
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              rows={2}
              placeholder="abcd….0123…"
              className="w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 font-mono text-xs outline-none focus:border-indigo-500"
            />
            <div className="flex gap-2">
              <button
                disabled={paste.trim().length === 0}
                onClick={() => void beginReceive(paste)}
                className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-4 py-2 text-sm font-medium"
              >
                Connect
              </button>
              {scanning ? (
                <button onClick={() => void stopScan()} className="rounded-lg border border-neutral-700 hover:bg-neutral-900 px-4 py-2 text-sm">
                  Stop camera
                </button>
              ) : (
                <button onClick={() => void startScan()} className="rounded-lg border border-neutral-700 hover:bg-neutral-900 px-4 py-2 text-sm">
                  Scan with camera
                </button>
              )}
            </div>
            <div id={QR_ELEMENT_ID} className={scanning ? "mt-2 min-h-[240px] overflow-hidden rounded-lg" : "hidden"} />
          </div>
        )}

        {/* Shared: SAS confirm + progress + result, for both modes. */}
        {sas && finished === null && (
          <div className="mt-6">
            <p className="text-sm text-neutral-400">Verify this code matches on both devices:</p>
            <div className="mt-2 text-center font-mono text-3xl tracking-[0.3em] text-indigo-300">{sas}</div>
            {!confirmed ? (
              <button onClick={confirm} className="mt-4 w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 py-3 font-medium">
                The codes match
              </button>
            ) : (
              <p className="mt-4 text-center text-sm text-neutral-400">{STATUS_TEXT[status] ?? "Working…"}</p>
            )}
          </div>
        )}

        {progress && finished === null && confirmed && (
          <div className="mt-4">
            <div className="h-1.5 w-full overflow-hidden rounded bg-neutral-800">
              <div className="h-full bg-indigo-500 transition-all" style={{ width: `${pct}%` }} />
            </div>
            <p className="mt-1 text-xs text-neutral-500">{progress.done} / {progress.total}</p>
          </div>
        )}

        {finished !== null && (
          <div className="mt-6 text-center">
            <p className="text-green-400">✓ Transferred {finished} items.</p>
            <button onClick={() => nav("/")} className="mt-4 rounded-lg bg-indigo-600 hover:bg-indigo-500 px-5 py-2 font-medium">
              Done
            </button>
          </div>
        )}

        {status && !sas && finished === null && mode !== "choose" && (
          <p className="mt-4 text-sm text-neutral-500">{STATUS_TEXT[status] ?? status}</p>
        )}
        {error && <p className="mt-4 text-sm text-red-400">{error}</p>}
      </div>
    </main>
  );
}
