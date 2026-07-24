import { useEffect, useState } from "react";
import type { Announcement } from "../services/announcement";
import { dismissAnnouncement, fetchAnnouncement, getDismissedVersion } from "../services/announcement";

const severityStyles: Record<Announcement["severity"], string> = {
  info: "border-announce-info-border bg-announce-info-bg text-announce-info-text",
  warning: "border-announce-warn-border bg-announce-warn-bg text-announce-warn-text",
  error: "border-announce-err-border bg-announce-err-bg text-announce-err-text",
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

  const style = severityStyles[announcement.severity];
  const current = announcement;

  function handleDismiss() {
    dismissAnnouncement(current.version);
    setAnnouncement(null);
  }

  return (
    <div
      className={`flex shrink-0 items-center gap-3 border-b px-4 py-2.5 text-sm ${style}`}
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
