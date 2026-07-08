import { useEffect, useState } from "react";
import { onMessage } from "../services/events";
import { isNotificationEnabled, requestPermissionAndSubscribe } from "../services/notifications";

export default function NotificationBanner() {
  const [show, setShow] = useState(false);
  const [denied, setDenied] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    void isNotificationEnabled().then((v) => {
      setEnabled(v);
      setLoaded(true);
    });
  }, []);

  useEffect(() => {
    if (!loaded || !enabled) return;
    if (typeof Notification === "undefined") return;
    const maybe = () => {
      if (Notification.permission === "default") setShow(true);
    };
    return onMessage(maybe);
  }, [loaded, enabled]);

  if (!show) return null;

  async function handleEnable() {
    const ok = await requestPermissionAndSubscribe();
    if (!ok) {
      setDenied(true);
      setTimeout(() => setShow(false), 5000);
    } else {
      setShow(false);
    }
  }

  return (
    <div className="fixed inset-x-0 top-0 z-40 flex justify-center p-3">
      <div className="w-full max-w-md rounded-xl border border-divider bg-elevated px-4 py-3 shadow-lg backdrop-blur">
        {denied ? (
          <p className="text-xs text-text-secondary">
            Notifications are blocked in your browser settings. You can manage this in
            Settings → Privacy.
          </p>
        ) : (
          <div className="flex items-center gap-3">
            <p className="flex-1 text-sm text-text-secondary">
              Turn on notifications to receive messages when Privex isn&rsquo;t open.
            </p>
            <button
              onClick={() => void handleEnable()}
              className="rounded-lg bg-accent hover:bg-accent-hover px-3 py-1.5 text-sm font-medium"
            >
              Enable
            </button>
            <button onClick={() => setShow(false)} className="text-text-muted hover:text-text-secondary text-sm">
              Not now
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
