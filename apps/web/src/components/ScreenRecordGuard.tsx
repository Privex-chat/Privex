import { useEffect, useState } from "react";
import { db } from "../db";

const SETTINGS_KEY = "screen_record_protection";

export async function isScreenRecordProtectionEnabled(): Promise<boolean> {
  const row = await db.settings.get(SETTINGS_KEY);
  return row?.value === true;
}

export async function setScreenRecordProtectionEnabled(v: boolean): Promise<void> {
  await db.settings.put({ key: SETTINGS_KEY, value: v });
}

const ANIM_STYLE = `
@keyframes privex-watermark-shift {
  0% { background-position: 0 0; }
  33% { background-position: 16px 10px; }
  66% { background-position: 8px -6px; }
  100% { background-position: 0 0; }
}
`;

export default function ScreenRecordGuard({ pxId }: { pxId: string }) {
  const [hidden, setHidden] = useState(false);
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    void isScreenRecordProtectionEnabled().then(setEnabled);
  }, []);

  useEffect(() => {
    if (!enabled) return;
    const handler = () => setHidden(document.hidden);
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, [enabled]);

  if (!enabled || !pxId) return null;

  const watermarkSvg = encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240">
      <style>text { fill: currentColor; font-family: monospace; font-size: 11px; opacity: 0.2; }</style>
      <text x="10" y="20">${pxId}</text>
      <text x="130" y="60">${pxId}</text>
      <text x="40" y="100">${pxId}</text>
      <text x="160" y="140">${pxId}</text>
      <text x="10" y="180">${pxId}</text>
      <text x="130" y="220">${pxId}</text>
    </svg>`,
  );

  return (
    <>
      <style>{ANIM_STYLE}</style>
      <div
        className="pointer-events-none fixed inset-0 z-[9998]"
        style={{
          backgroundImage: `url("data:image/svg+xml,${watermarkSvg}")`,
          backgroundSize: "240px 240px",
          animation: "privex-watermark-shift 8s ease-in-out infinite",
          opacity: 0.03,
        }}
      />
      {hidden && (
        <div
          className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
          style={{ backdropFilter: "blur(24px)", WebkitBackdropFilter: "blur(24px)" }}
        >
          <div className="text-center text-neutral-300">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="mx-auto mb-3 h-12 w-12">
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
            </svg>
            <p className="text-sm">Content hidden</p>
            <p className="mt-1 text-xs text-neutral-500">Privex is protecting your privacy</p>
          </div>
        </div>
      )}
    </>
  );
}
