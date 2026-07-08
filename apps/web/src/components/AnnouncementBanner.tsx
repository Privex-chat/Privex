import { useEffect, useState } from "react";
import type { Announcement } from "../services/announcement";
import { dismissAnnouncement, fetchAnnouncement, getDismissedVersion } from "../services/announcement";

const severityStyles: Record<Announcement["severity"], string> = {
  info: "border-blue-800 bg-blue-950/80 text-blue-200",
  warning: "border-amber-700 bg-amber-950/80 text-amber-200",
  error: "border-red-700 bg-red-950/80 text-red-200",
};

export default function AnnouncementBanner() {
  const [announcement, setAnnouncement] = useState<Announcement | null>(null);

  useEffect(() => {
    void fetchAnnouncement().then((a) => {
      if (!a) return;
      if (a.dismissible && a.version <= getDismissedVersion()) return;
      setAnnouncement(a);
    });
  }, []);

  if (!announcement) return null;

  function handleDismiss() {
    dismissAnnouncement(announcement.version);
    setAnnouncement(null);
  }

  return (
    <div
      className={`fixed inset-x-0 top-0 z-50 flex items-center gap-3 border-b px-4 py-2.5 text-sm ${severityStyles[announcement.severity]}`}
    >
      <span className="flex-1 text-center font-medium">{announcement.message}</span>
      {announcement.dismissible && (
        <button
          onClick={handleDismiss}
          className="shrink-0 rounded p-1 opacity-70 hover:opacity-100"
          aria-label="Dismiss"
        >
          <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
            <path
              fillRule="evenodd"
              d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      )}
    </div>
  );
}
