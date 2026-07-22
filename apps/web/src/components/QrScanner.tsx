// Full-screen QR scanner overlay. Two inputs, one validated output:
//   - live camera (rear-facing by default), and
//   - a still image from the gallery/filesystem.
// Every decode - from either source - passes through parseScannedPxId before it
// can leave this component, so nothing but a real Privex ID ever reaches the
// caller. html5-qrcode is lazy-imported (kept out of the main bundle) and the
// camera stream is always torn down on close/unmount.
//
// State is an explicit machine rather than a tangle of booleans:
//   starting → scanning ⇄ decoding → (valid → onResult+close) | error
// Errors are recoverable: the gallery path stays available even if the camera is
// denied or absent, and "Use camera" restarts a clean session.
import { useCallback, useEffect, useRef, useState } from "react";
import type { Html5Qrcode } from "html5-qrcode";
import { parseScannedPxId } from "../services/qr";
import { XIcon } from "./icons";

type State =
  | { s: "starting" }
  | { s: "scanning"; note?: string } // note = transient "that wasn't a Privex QR"
  | { s: "decoding" } // decoding a picked image
  | { s: "error"; msg: string };

type Props = {
  open: boolean;
  onResult: (pxId: string) => void;
  onClose: () => void;
};

const READER_ID = "privex-qr-reader";
const MAX_IMAGE_BYTES = 15 * 1024 * 1024;

/** Stop + release a scanner instance without throwing if it wasn't running.
 *  stop() throws/rejects when the camera loop isn't active; clear() throws when
 *  there's nothing rendered - both are expected and swallowed. */
async function release(inst: Html5Qrcode | null): Promise<void> {
  if (!inst) return;
  try {
    await inst.stop();
  } catch {
    /* already stopped */
  }
  try {
    inst.clear();
  } catch {
    /* nothing rendered */
  }
}

function cameraErrorMessage(e: unknown): string {
  const name = (e as { name?: string })?.name;
  if (name === "NotAllowedError" || name === "SecurityError")
    return "Camera permission was denied. You can still scan a photo from your device.";
  if (name === "NotFoundError" || name === "DevicesNotFoundError")
    return "No camera found. Scan a photo from your device instead.";
  return "Couldn't start the camera. Scan a photo from your device instead.";
}

export default function QrScanner({ open, onResult, onClose }: Props) {
  const [state, setState] = useState<State>({ s: "starting" });
  const instRef = useRef<Html5Qrcode | null>(null);
  const startRef = useRef<Promise<unknown> | null>(null); // in-flight start(), if any
  const handledRef = useRef(false); // guard: process at most one valid hit
  const fileRef = useRef<HTMLInputElement>(null);

  // Deliver a validated id exactly once, then tear down.
  const succeed = useCallback(
    (pxId: string) => {
      if (handledRef.current) return;
      handledRef.current = true;
      void release(instRef.current).then(() => {
        onResult(pxId);
        onClose();
      });
    },
    [onResult, onClose],
  );

  // Start (or restart) the live camera on the shared instance.
  const startCamera = useCallback(async () => {
    const inst = instRef.current;
    if (!inst) return;
    setState({ s: "starting" });
    try {
      await release(inst); // clean slate if a previous session/file decode ran
      if (instRef.current !== inst) return; // closed during setup - don't start
      const starting = inst.start(
        { facingMode: "environment" },
        {
          fps: 10,
          qrbox: (vw: number, vh: number) => {
            const size = Math.floor(Math.min(vw, vh) * 0.7);
            return { width: size, height: size };
          },
        },
        (decoded) => {
          const id = parseScannedPxId(decoded);
          if (id) succeed(id);
          else setState({ s: "scanning", note: "That QR isn't a Privex ID." });
        },
        () => {}, // per-frame decode misses are normal; ignore
      );
      startRef.current = starting;
      await starting;
      if (!handledRef.current) setState({ s: "scanning" });
    } catch (e) {
      setState({ s: "error", msg: cameraErrorMessage(e) });
    } finally {
      startRef.current = null;
    }
  }, [succeed]);

  // Keep the latest startCamera reachable from the open-effect without making it a
  // dependency (the parent passes inline onResult/onClose, so startCamera changes
  // every render - depending on it would restart the camera on each parent render).
  const startCameraRef = useRef(startCamera);
  startCameraRef.current = startCamera;

  // Open → build the instance and start the camera. Close/unmount → release it.
  // Keyed on `open` ONLY, so the camera starts once per open and tears down once.
  useEffect(() => {
    if (!open) return;
    handledRef.current = false;
    let cancelled = false;
    void (async () => {
      try {
        const { Html5Qrcode } = await import("html5-qrcode");
        if (cancelled) return;
        instRef.current = new Html5Qrcode(READER_ID, { verbose: false });
        await startCameraRef.current();
      } catch {
        if (!cancelled) setState({ s: "error", msg: "Couldn't load the scanner. Please try again." });
      }
    })();
    return () => {
      cancelled = true;
      const inst = instRef.current;
      instRef.current = null;
      // html5-qrcode #830: stop() no-ops while start() is still pending and can
      // leave the camera live once it resolves - wait for the start to settle first.
      const pending = startRef.current;
      void Promise.resolve(pending)
        .catch(() => {})
        .then(() => release(inst));
    };
  }, [open]);

  // Escape closes.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  async function onPickFile(file: File | undefined) {
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setState({ s: "error", msg: "That's not an image file." });
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setState({ s: "error", msg: "That image is too large (max 15 MB)." });
      return;
    }
    const inst = instRef.current;
    if (!inst) return;
    setState({ s: "decoding" });
    try {
      await release(inst); // scanFile needs the camera stopped
      const decoded = await inst.scanFile(file, false);
      const id = parseScannedPxId(decoded);
      if (id) succeed(id);
      else setState({ s: "error", msg: "No Privex QR found in that image." });
    } catch {
      setState({ s: "error", msg: "No Privex QR found in that image." });
    }
  }

  if (!open) return null;

  const scanning = state.s === "scanning" || state.s === "starting";

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col bg-black/95"
      role="dialog"
      aria-modal="true"
      aria-label="Scan a Privex QR code"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 text-white">
        <span className="text-sm font-medium">Scan a Privex QR</span>
        <button
          onClick={onClose}
          aria-label="Close scanner"
          className="flex h-9 w-9 items-center justify-center rounded-full text-white/80 transition-colors hover:bg-white/10 hover:text-white"
        >
          <XIcon className="h-5 w-5" />
        </button>
      </div>

      {/* Viewport */}
      <div className="flex flex-1 items-center justify-center px-4">
        <div className="w-full max-w-md">
          <div className="relative mx-auto aspect-square w-full overflow-hidden rounded-2xl bg-black">
            {/* html5-qrcode injects the <video> here */}
            <div id={READER_ID} className="h-full w-full [&_video]:h-full [&_video]:w-full [&_video]:object-cover" />

            {/* Reticle + status overlays (never intercept taps) */}
            <div className="pointer-events-none absolute inset-0">
              {scanning && (
                <div className="absolute inset-[15%] rounded-xl border-2 border-white/70" />
              )}
              {state.s === "starting" && (
                <div className="absolute inset-0 flex items-center justify-center text-sm text-white/80">
                  Starting camera…
                </div>
              )}
              {state.s === "decoding" && (
                <div className="absolute inset-0 flex items-center justify-center bg-black/50 text-sm text-white/90">
                  Reading image…
                </div>
              )}
              {state.s === "error" && (
                <div className="absolute inset-0 flex items-center justify-center bg-black/60 px-6 text-center text-sm text-white/90">
                  {state.msg}
                </div>
              )}
            </div>
          </div>

          {/* Hint line */}
          <p className="mt-4 h-5 text-center text-xs text-white/70">
            {state.s === "scanning" && (state.note ?? "Point your camera at their Privex QR.")}
            {state.s === "error" && "Try a photo instead, or use the camera again."}
          </p>

          {/* Actions */}
          <div className="mt-3 flex items-center justify-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                void onPickFile(e.target.files?.[0]);
                e.target.value = ""; // allow re-picking the same file
              }}
            />
            <button
              onClick={() => fileRef.current?.click()}
              className="rounded-lg bg-white/10 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-white/20"
            >
              Scan from photo
            </button>
            {state.s === "error" && (
              <button
                onClick={() => void startCamera()}
                className="rounded-lg bg-white/10 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-white/20"
              >
                Use camera
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
