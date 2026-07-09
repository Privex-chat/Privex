// Announcement banner — fetches a static JSON served by nginx.
// Changing the JSON file (version bump) re-shows the banner to all users.
export interface Announcement {
  version: number;
  message: string;
  severity: "info" | "warning" | "error";
  dismissible: boolean;
}

const ANNOUNCEMENT_URL = "/announcement.json";
const DISMISSED_KEY = "privex_announcement_dismissed";

const MAX_MESSAGE_CHARS = 500;
const SEVERITIES = new Set(["info", "warning", "error"]);

/** Reject a malformed announcement instead of letting a bad shape (e.g. `message`
 *  as an object) throw at banner render (PVX-26). */
function parseAnnouncement(v: unknown): Announcement | null {
  if (typeof v !== "object" || v === null) return null;
  const a = v as Record<string, unknown>;
  if (typeof a.version !== "number") return null;
  if (typeof a.message !== "string" || a.message.length > MAX_MESSAGE_CHARS) return null;
  if (typeof a.severity !== "string" || !SEVERITIES.has(a.severity)) return null;
  if (typeof a.dismissible !== "boolean") return null;
  return {
    version: a.version,
    message: a.message,
    severity: a.severity as Announcement["severity"],
    dismissible: a.dismissible,
  };
}

export async function fetchAnnouncement(): Promise<Announcement | null> {
  try {
    const res = await fetch(ANNOUNCEMENT_URL);
    if (!res.ok) return null;
    return parseAnnouncement(await res.json());
  } catch {
    return null;
  }
}

export function getDismissedVersion(): number {
  try {
    return Number(localStorage.getItem(DISMISSED_KEY)) || 0;
  } catch {
    return 0;
  }
}

export function dismissAnnouncement(version: number): void {
  try {
    localStorage.setItem(DISMISSED_KEY, String(version));
  } catch {
    // localStorage may be unavailable (private browsing)
  }
}
