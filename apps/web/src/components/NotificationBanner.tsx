// Notification permission flow (prompt §5): NEVER ask on load. We ask only after
// the first message activity, and explain WHY first - the OS prompt can't carry our
// reason. onMessage fires on every send + receive, so the first one reveals the ask.
import { useEffect, useState } from "react";
import { onMessage } from "../services/events";

export default function NotificationBanner() {
  const [show, setShow] = useState(false);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    if (typeof Notification === "undefined") return;
    const maybe = () => {
      if (Notification.permission === "default") setShow(true);
    };
    return onMessage(maybe);
  }, []);

  if (!show) return null;

  async function enable() {
    const res = await Notification.requestPermission();
    if (res === "denied") {
      setDenied(true);
      setTimeout(() => setShow(false), 5000);
    } else {
      setShow(false);
    }
  }

  return (
    <div className="fixed inset-x-0 top-0 z-40 flex justify-center p-3">
      <div className="w-full max-w-md rounded-xl border border-neutral-800 bg-neutral-900/95 px-4 py-3 shadow-lg backdrop-blur">
        {denied ? (
          <p className="text-xs text-neutral-400">
            Notifications are blocked, so messages will only arrive while Privex is open. You can
            re-enable them in your browser settings.
          </p>
        ) : (
          <div className="flex items-center gap-3">
            <p className="flex-1 text-sm text-neutral-300">
              Turn on notifications to receive messages when Privex isn&rsquo;t open.
            </p>
            <button
              onClick={() => void enable()}
              className="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 text-sm font-medium"
            >
              Enable
            </button>
            <button onClick={() => setShow(false)} className="text-neutral-500 hover:text-neutral-300 text-sm">
              Not now
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
