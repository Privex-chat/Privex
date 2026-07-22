// Shows the user's own Privex ID as a QR code for someone else to scan from the
// Contacts tab. The QR encodes the raw px_... string — exactly what the scanner
// expects. It also carries the user's identicon baked into the centre so the code
// is recognisably *theirs*: the QR is generated at error-correction level H (~30%
// recoverable), and the badge covers well under that, so scannability is intact.
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../store/auth";
import { identiconCells, identiconHue } from "../components/Avatar";

/** Draw the identicon badge into the centre of an already-rendered QR canvas. */
function drawIdenticonBadge(canvas: HTMLCanvasElement, seed: string): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width;
  const tile = Math.round(W * 0.2); // identicon covers ~20% (ECC-H tolerates ~30%)
  const pad = Math.round(tile * 0.18); // white ring so it reads as a deliberate badge
  const outer = tile + pad * 2;
  const ox = Math.round((W - outer) / 2);
  const oy = Math.round((W - outer) / 2);

  const rr = (x: number, y: number, w: number, h: number, r: number) => {
    if (typeof ctx.roundRect === "function") {
      ctx.beginPath();
      ctx.roundRect(x, y, w, h, r);
      ctx.fill();
    } else {
      ctx.fillRect(x, y, w, h);
    }
  };

  const hue = identiconHue(seed);
  ctx.fillStyle = "#ffffff"; // clean backing replaces the modules under the badge
  rr(ox, oy, outer, outer, Math.round(outer * 0.22));
  ctx.fillStyle = `hsl(${hue} 62% 55% / 0.16)`;
  rr(ox + pad, oy + pad, tile, tile, Math.round(tile * 0.22));

  const cells = identiconCells(seed);
  const c = tile / 5;
  ctx.fillStyle = `hsl(${hue} 62% 55%)`;
  for (let i = 0; i < cells.length; i++) {
    if (!cells[i]) continue;
    const cx = ox + pad + (i % 5) * c;
    const cy = oy + pad + Math.floor(i / 5) * c;
    ctx.fillRect(cx, cy, c + 0.5, c + 0.5); // +0.5 hides hairline seams
  }
}

export default function MyQr() {
  const nav = useNavigate();
  const pxId = useAuth((s) => s.userId) ?? "";
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!pxId) return;
    let done = false;
    void (async () => {
      const { toCanvas } = await import("qrcode");
      const canvas = canvasRef.current;
      if (done || !canvas) return;
      // Level H so the centred identicon badge can't break scanning.
      await toCanvas(canvas, pxId, { errorCorrectionLevel: "H", margin: 2, width: 280 });
      if (done) return;
      drawIdenticonBadge(canvas, pxId);
    })();
    return () => {
      done = true;
    };
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

        {/* Keyed on pxId so a sign-out/account switch remounts a blank canvas
            instead of leaving the previous ID's QR bitmap on screen. */}
        {pxId ? (
          <canvas
            key={pxId}
            ref={canvasRef}
            role="img"
            aria-label="Your Privex ID QR code"
            className="mx-auto mt-6 h-auto max-w-full rounded-xl bg-qr-bg p-3"
          />
        ) : null}

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
