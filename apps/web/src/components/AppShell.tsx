// App shell for the three primary tabs (Chats / Contacts / Settings). Renders the
// active tab via <Outlet/> plus persistent navigation: a bottom tab bar on mobile
// and a slim left rail on desktop (docs 9 - web-first, PWA). Full-screen pushes
// (Chat, Call, onboarding, verify, my-qr, device-transfer) render OUTSIDE this
// shell and have no nav.
import { NavLink, Outlet } from "react-router-dom";
import { useEffect, useState } from "react";
import { ChatBubbleIcon, GearIcon, UsersIcon } from "./icons";
import { listContacts } from "../data/contacts";
import { onContactsChanged } from "../services/events";
import AnnouncementBanner from "./AnnouncementBanner";

type Item = { to: string; label: string; Icon: (p: { className?: string }) => JSX.Element; badge?: number };

function usePendingCount(): number {
  const [n, setN] = useState(0);
  useEffect(() => {
    const refresh = () =>
      void listContacts().then((all) => setN(all.filter((c) => c.status === "pending_inbound").length));
    refresh();
    return onContactsChanged(refresh);
  }, []);
  return n;
}

function Badge({ n }: { n: number }) {
  if (n <= 0) return null;
  return (
    <span className="absolute -right-2 -top-1 flex min-w-[1.05rem] items-center justify-center rounded-full bg-accent px-1 text-[10px] font-medium leading-[1.05rem] text-white">
      {n > 9 ? "9+" : n}
    </span>
  );
}

export default function AppShell() {
  const pending = usePendingCount();
  const items: Item[] = [
    { to: "/", label: "Chats", Icon: ChatBubbleIcon },
    { to: "/contacts", label: "Contacts", Icon: UsersIcon, badge: pending },
    { to: "/settings", label: "Settings", Icon: GearIcon },
  ];

  // NavLink active styling. "Chats" (/) needs `end` so it isn't active everywhere.
  const cls = (active: boolean) =>
    active ? "text-accent-text" : "text-text-muted hover:text-text-primary";

  return (
    // Mobile: a fixed-height (100dvh) column so the content region scrolls INSIDE
    // itself and the bottom bar is a pinned flow sibling - no page overflow, so a
    // screen that fits the viewport never scrolls. Desktop: normal document flow
    // with a fixed left rail (md:pl-16 makes room for it).
    <div className="flex h-[100dvh] flex-col bg-surface text-text-primary md:h-auto md:min-h-screen md:pl-16">
      {/* Desktop: fixed left rail */}
      <nav
        aria-label="Primary"
        className="fixed inset-y-0 left-0 z-30 hidden w-16 flex-col items-center gap-1 border-r border-divider bg-header py-4 backdrop-blur-sm md:flex"
      >
        <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-xl bg-accent-bg text-sm font-bold text-accent-text">
          P
        </div>
        {items.map(({ to, label, Icon, badge }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            title={label}
            aria-label={label}
            className={({ isActive }) =>
              "relative flex w-12 flex-col items-center gap-1 rounded-xl py-2 text-[10px] transition-colors " +
              cls(isActive)
            }
          >
            <span className="relative">
              <Icon className="h-6 w-6" />
              {badge ? <Badge n={badge} /> : null}
            </span>
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Announcement bar: a shrink-0 flow sibling at the top of the column, so it
          reduces the content region instead of pushing the whole 100dvh app down
          (which shoved the bottom nav off-screen when it lived at the App root). */}
      <AnnouncementBanner />

      {/* Content region: internal scroll on mobile, document scroll on desktop. */}
      <div className="min-h-0 flex-1 overflow-y-auto md:overflow-visible">
        <Outlet />
      </div>

      {/* Mobile: pinned bottom tab bar (a flow sibling, not an overlay). */}
      <nav
        aria-label="Primary"
        className="flex shrink-0 border-t border-divider bg-header md:hidden"
        style={{ paddingBottom: "env(safe-area-inset-bottom)" }}
      >
        {items.map(({ to, label, Icon, badge }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            aria-label={label}
            className={({ isActive }) =>
              "relative flex flex-1 flex-col items-center gap-0.5 py-2.5 text-[11px] transition-colors " +
              cls(isActive)
            }
          >
            <span className="relative">
              <Icon className="h-6 w-6" />
              {badge ? <Badge n={badge} /> : null}
            </span>
            {label}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
