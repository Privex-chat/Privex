// Header indicator: a subtle dot (green online / amber offline) plus a count of
// messages still waiting in the offline outbox, and a clock warning when the
// device's clock disagrees with the signed server time by >90s (docs 9.6 - warn,
// never silently correct).
import { useEffect, useState } from "react";
import { onOutboxChanged } from "../services/events";
import { outboxCount } from "../services/outbox";
import { clockStatus, onClockStatusChanged } from "../services/time-sync";
import { getWsStatus, onWsStatusChanged } from "../services/websocket";
import { WarningTriangleIcon } from "./icons";

function formatDrift(secs: number): string {
  const abs = Math.abs(secs);
  const human = abs >= 3600 ? `${Math.round(abs / 3600)} h` : abs >= 60 ? `${Math.round(abs / 60)} min` : `${abs} s`;
  return `${human} ${secs > 0 ? "ahead" : "behind"}`;
}

export default function ConnectionStatus() {
  // "Online" here means the app can actually reach Privex, not just that the OS
  // reports a network interface: navigator.onLine only reflects the latter, so
  // a dead-but-not-yet-detected WebSocket (e.g. a suspended PWA tab that missed
  // its own reconnect) used to show a false green dot. Real socket state from
  // websocket.ts closes that gap.
  const [netOnline, setNetOnline] = useState(navigator.onLine);
  const [wsConnected, setWsConnected] = useState(getWsStatus() === "connected");
  const [queued, setQueued] = useState(0);
  const [clock, setClock] = useState(clockStatus());

  useEffect(() => {
    const on = () => setNetOnline(true);
    const off = () => setNetOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    const unsubWs = onWsStatusChanged((s) => setWsConnected(s === "connected"));
    const refresh = () => void outboxCount().then(setQueued);
    refresh();
    const unsub = onOutboxChanged(refresh);
    const unsubClock = onClockStatusChanged(() => setClock(clockStatus()));
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
      unsubWs();
      unsub();
      unsubClock();
    };
  }, []);

  const online = netOnline && wsConnected;

  const waiting = queued > 0 ? `${queued} waiting` : null;
  const label = online ? waiting : waiting ? `Offline · ${waiting}` : "Offline";
  return (
    <span
      className="flex items-center gap-1.5 text-xs text-text-muted"
      title={online ? "Connected" : "Offline - messages send when you reconnect"}
    >
      <span className={`inline-block h-2 w-2 rounded-full ${online ? "bg-success-bg" : "bg-offline"}`} />
      {label && <span>{label}</span>}
      {clock.warning && (
        <span
          className="inline-flex items-center gap-1 text-offline"
          title={`Your device clock may be incorrect (${formatDrift(clock.driftSeconds)} vs the server). Message order is anchored to signed server time; fix your clock to clear this.`}
        >
          <WarningTriangleIcon className="h-3.5 w-3.5" /> clock
        </span>
      )}
    </span>
  );
}
