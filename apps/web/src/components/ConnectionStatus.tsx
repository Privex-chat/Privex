// Header indicator: a subtle dot (green online / amber offline) plus a count of
// messages still waiting in the offline outbox, and a clock warning when the
// device's clock disagrees with the signed server time by >90s (docs 9.6 - warn,
// never silently correct).
import { useEffect, useState } from "react";
import { onOutboxChanged } from "../services/events";
import { outboxCount } from "../services/outbox";
import { clockStatus, onClockStatusChanged } from "../services/time-sync";

function formatDrift(secs: number): string {
  const abs = Math.abs(secs);
  const human = abs >= 3600 ? `${Math.round(abs / 3600)} h` : abs >= 60 ? `${Math.round(abs / 60)} min` : `${abs} s`;
  return `${human} ${secs > 0 ? "ahead" : "behind"}`;
}

export default function ConnectionStatus() {
  const [online, setOnline] = useState(navigator.onLine);
  const [queued, setQueued] = useState(0);
  const [clock, setClock] = useState(clockStatus());

  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    const refresh = () => void outboxCount().then(setQueued);
    refresh();
    const unsub = onOutboxChanged(refresh);
    const unsubClock = onClockStatusChanged(() => setClock(clockStatus()));
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
      unsub();
      unsubClock();
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
      {clock.warning && (
        <span
          className="text-amber-400"
          title={`Your device clock may be incorrect (${formatDrift(clock.driftSeconds)} vs the server). Message order is anchored to signed server time; fix your clock to clear this.`}
        >
          ⚠ clock
        </span>
      )}
    </span>
  );
}
