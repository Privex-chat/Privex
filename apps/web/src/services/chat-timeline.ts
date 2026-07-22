// Turns a flat, ascending list of messages into render rows for the chat view:
// day separators ("Today" / "Yesterday" / a date) plus grouping flags so a run of
// consecutive messages from the same side reads as one cluster (one timestamp at
// the end, tighter spacing, tucked corners). Pure and time-injectable so it can be
// unit-tested without a clock.

/** Messages are grouped while they share a side and day and land within this gap. */
export const GROUP_GAP_SECONDS = 5 * 60;

export type TimelineRow<T> =
  | { kind: "day"; key: string; label: string }
  | { kind: "msg"; key: string; m: T; firstOfGroup: boolean; lastOfGroup: boolean };

type MsgLike = { timestamp: number; direction: string; msg_id: string };

function startOfLocalDay(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/** "Today" / "Yesterday" / "Mar 4" / "Mar 4, 2024" (year only when not this year). */
export function dayLabel(timestampSeconds: number, now: Date = new Date()): string {
  const d = new Date(timestampSeconds * 1000);
  const diffDays = Math.round((startOfLocalDay(now) - startOfLocalDay(d)) / 86_400_000);
  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  return d.toLocaleDateString([], {
    month: "short",
    day: "numeric",
    year: d.getFullYear() === now.getFullYear() ? undefined : "numeric",
  });
}

export function buildChatTimeline<T extends MsgLike>(msgs: T[], now: Date = new Date()): TimelineRow<T>[] {
  const rows: TimelineRow<T>[] = [];
  for (let i = 0; i < msgs.length; i++) {
    const m = msgs[i];
    const prev = msgs[i - 1];
    const next = msgs[i + 1];

    const newDay = !prev || startOfLocalDay(new Date(m.timestamp * 1000)) !== startOfLocalDay(new Date(prev.timestamp * 1000));
    if (newDay) rows.push({ kind: "day", key: `day-${m.msg_id}`, label: dayLabel(m.timestamp, now) });

    // A group breaks on a new day, a side change, or a gap longer than GROUP_GAP.
    const firstOfGroup =
      newDay || !prev || prev.direction !== m.direction || m.timestamp - prev.timestamp > GROUP_GAP_SECONDS;
    const sameDayAsNext =
      !!next && startOfLocalDay(new Date(m.timestamp * 1000)) === startOfLocalDay(new Date(next.timestamp * 1000));
    const lastOfGroup =
      !next || !sameDayAsNext || next.direction !== m.direction || next.timestamp - m.timestamp > GROUP_GAP_SECONDS;

    rows.push({ kind: "msg", key: m.msg_id, m, firstOfGroup, lastOfGroup });
  }
  return rows;
}
