// App shell. Hash-based routing (docs 9.1) for static-deployment compatibility.
// On boot we restore the returning user's session from the locally-persisted
// identity (the in-memory token is lost on every reload) and open the WebSocket.
import { useEffect, useRef, useState } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./store/auth";
import { restoreSession } from "./services/auth-session";
import { connectWebSocket, disconnectWebSocket } from "./services/websocket";
import { flushOutbox } from "./services/outbox";
import { startCoverTraffic, stopCoverTraffic } from "./services/cover-traffic";
import Onboarding from "./screens/Onboarding";
import ConversationList from "./screens/ConversationList";
import Chat from "./screens/Chat";
import Call from "./screens/Call";
import Settings from "./screens/Settings";
import KeyVerification from "./screens/KeyVerification";
import AddContact from "./screens/AddContact";
import Recovery from "./screens/Recovery";
import DeviceTransfer from "./screens/DeviceTransfer";
import MyQr from "./screens/MyQr";
import UnlockScreen from "./screens/UnlockScreen";
import AnnouncementBanner from "./components/AnnouncementBanner";
import InstallPrompt from "./components/InstallPrompt";
import NotificationBanner from "./components/NotificationBanner";
import AppLockGuard from "./components/AppLockGuard";
import ScreenRecordGuard from "./components/ScreenRecordGuard";
import { isLockEnabled, isUnlocked } from "./services/applock";

type Boot = "loading" | "ready" | "offline" | "locked";

function Center({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-neutral-100 flex items-center justify-center p-6">
      {children}
    </main>
  );
}

const MAX_BOOT_RETRIES = 6;

export default function App() {
  const [boot, setBoot] = useState<Boot>("loading");
  const authenticated = useAuth((s) => s.authenticated);
  const token = useAuth((s) => s.sessionToken);
  const started = useRef(false);
  const retries = useRef(0);

  // Self-healing boot: a failed restore with an existing identity means the
  // server is briefly unreachable (e.g. a restart) - auto-retry with backoff so a
  // transient blip resolves itself instead of getting stuck on the offline screen.
  // Only show offline (manual retry) after several attempts. A `false` result =
  // genuinely not onboarded → render the app (routes to onboarding). NEVER dump an
  // onboarded user into fresh onboarding (that would mint a new identity).
  function attempt() {
    setBoot("loading");
    restoreSession()
      .then(() => setBoot("ready"))
      .catch((e: unknown) => {
        console.error("[privex] session restore failed:", e);
        retries.current += 1;
        if (retries.current <= MAX_BOOT_RETRIES) {
          const delay = Math.min(15000, 1500 * 2 ** (retries.current - 1));
          setTimeout(attempt, delay);
        } else {
          setBoot("offline");
        }
      });
  }

  function tryRestore() {
    retries.current = 0;
    attempt();
  }

  // Boot: if the cryptographic app lock is on and this session hasn't unlocked yet,
  // gate on the unlock screen FIRST (the master key is unreachable until then).
  async function startBoot() {
    if ((await isLockEnabled()) && !isUnlocked()) {
      setBoot("locked");
      return;
    }
    attempt();
  }

  function onUnlocked() {
    // Within a session the token survives a lock; on a fresh load re-restore it.
    if (useAuth.getState().authenticated) setBoot("ready");
    else {
      retries.current = 0;
      attempt();
    }
  }

  useEffect(() => {
    // StrictMode double-invokes effects in dev; guard so the retry loop starts once
    // (restoreSession also dedupes concurrent calls).
    if (started.current) return;
    started.current = true;
    void startBoot();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Open the realtime socket whenever we hold a live token (restore or onboarding),
  // and run the Poisson cover-traffic ticks that drain queued receipts (docs 4.10/5.3).
  useEffect(() => {
    if (authenticated && token) {
      void connectWebSocket(token);
      void startCoverTraffic();
      return () => {
        stopCoverTraffic();
        disconnectWebSocket();
      };
    }
  }, [authenticated, token]);

  // Drain the offline outbox when the network returns, or when the Service Worker's
  // background-sync/push wakes us (it can't send itself - no key/token). Gated on an
  // authenticated (i.e. NOT locked) session: a locked app must stay inert - no sends.
  useEffect(() => {
    const flushIfActive = () => {
      if (useAuth.getState().authenticated) void flushOutbox();
    };
    const onOnline = () => flushIfActive();
    window.addEventListener("online", onOnline);
    const sw = navigator.serviceWorker;
    const onMsg = (e: MessageEvent) => {
      if ((e.data as { type?: string } | null)?.type === "flush-outbox") flushIfActive();
    };
    sw?.addEventListener("message", onMsg);
    return () => {
      window.removeEventListener("online", onOnline);
      sw?.removeEventListener("message", onMsg);
    };
  }, []);

  if (boot === "locked") {
    return <UnlockScreen onUnlocked={onUnlocked} />;
  }
  if (boot === "loading") {
    return (
      <Center>
        <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-neutral-600 border-t-indigo-400" />
      </Center>
    );
  }
  if (boot === "offline") {
    return (
      <Center>
        <div className="text-center">
          <p className="text-neutral-300">Can&rsquo;t reach Privex right now.</p>
          <p className="mt-1 text-neutral-500 text-sm">Your identity is safe on this device.</p>
          <button
            onClick={tryRestore}
            className="mt-6 rounded-lg bg-indigo-600 hover:bg-indigo-500 px-5 py-2 font-medium"
          >
            Retry
          </button>
        </div>
      </Center>
    );
  }

  return (
    <>
      <AnnouncementBanner />
      <HashRouter>
        <Routes>
          <Route
            path="/"
            element={authenticated ? <ConversationList /> : <Navigate to="/onboarding" replace />}
          />
          <Route path="/onboarding" element={<Onboarding />} />
          <Route path="/recover" element={<Recovery />} />
          <Route path="/add-contact" element={<AddContact />} />
          <Route path="/chat/:id" element={<Chat />} />
          <Route path="/call/:id" element={<Call />} />
          <Route path="/settings/:tab?" element={<Settings />} />
          <Route path="/device-transfer" element={<DeviceTransfer />} />
          <Route path="/my-qr" element={<MyQr />} />
          <Route path="/verify/:id" element={<KeyVerification />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </HashRouter>
      <InstallPrompt />
      <NotificationBanner />
      <ScreenRecordGuard pxId={useAuth.getState().userId ?? ""} />
      <AppLockGuard onLock={() => setBoot("locked")} />
    </>
  );
}
