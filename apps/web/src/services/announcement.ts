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

export async function fetchAnnouncement(): Promise<Announcement | null> {
  try {
    const res = await fetch(ANNOUNCEMENT_URL);
    if (!res.ok) return null;
    return (await res.json()) as Announcement;
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
