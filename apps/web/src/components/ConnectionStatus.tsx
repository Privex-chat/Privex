// Header indicator: a subtle dot (green online / amber offline) plus a count of
// messages still waiting in the offline outbox.
import { useEffect, useState } from "react";
import { onOutboxChanged } from "../services/events";
import { outboxCount } from "../services/outbox";

export default function ConnectionStatus() {
  const [online, setOnline] = useState(navigator.onLine);
  const [queued, setQueued] = useState(0);

  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    const refresh = () => void outboxCount().then(setQueued);
    refresh();
    const unsub = onOutboxChanged(refresh);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
      unsub();
    };
  }, []);

  const waiting = queued > 0 ? `${queued} waiting` : null;
  const label = online ? waiting : waiting ? `Offline · ${waiting}` : "Offline";
  return (
    <span
      className="flex items-center gap-1.5 text-xs text-neutral-500"
      title={online ? "Connected" : "Offline - messages send when you reconnect"}
    >
      <span className={`inline-block h-2 w-2 rounded-full ${online ? "bg-green-500" : "bg-amber-500"}`} />
      {label && <span>{label}</span>}
    </span>
  );
}
