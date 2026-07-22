import { describe, expect, it } from "vitest";
import { buildChatTimeline, dayLabel } from "../services/chat-timeline";

// Fixed "now": 2026-03-04 12:00 local.
const NOW = new Date(2026, 2, 4, 12, 0, 0);
const day = (y: number, mo: number, d: number, h = 10, mi = 0) =>
  Math.floor(new Date(y, mo, d, h, mi, 0).getTime() / 1000);

function msg(id: string, ts: number, direction: "in" | "out") {
  return { msg_id: id, timestamp: ts, direction };
}

describe("dayLabel", () => {
  it("names today / yesterday, else a date", () => {
    expect(dayLabel(day(2026, 2, 4), NOW)).toBe("Today");
    expect(dayLabel(day(2026, 2, 3), NOW)).toBe("Yesterday");
    expect(dayLabel(day(2026, 2, 1), NOW)).toMatch(/Mar 1/);
    expect(dayLabel(day(2025, 11, 25), NOW)).toMatch(/2025/); // prior year shows year
  });
});

describe("buildChatTimeline", () => {
  it("prepends a day row and groups a same-side run (time only on the last)", () => {
    const rows = buildChatTimeline(
      [msg("a", day(2026, 2, 4, 10, 0), "in"), msg("b", day(2026, 2, 4, 10, 1), "in")],
      NOW,
    );
    expect(rows.map((r) => r.kind)).toEqual(["day", "msg", "msg"]);
    const [, first, second] = rows;
    expect(first.kind === "msg" && first.firstOfGroup).toBe(true);
    expect(first.kind === "msg" && first.lastOfGroup).toBe(false);
    expect(second.kind === "msg" && second.firstOfGroup).toBe(false);
    expect(second.kind === "msg" && second.lastOfGroup).toBe(true);
  });

  it("breaks the group on a side change", () => {
    const rows = buildChatTimeline(
      [msg("a", day(2026, 2, 4, 10, 0), "in"), msg("b", day(2026, 2, 4, 10, 1), "out")],
      NOW,
    ).filter((r) => r.kind === "msg");
    expect(rows.every((r) => r.kind === "msg" && r.firstOfGroup && r.lastOfGroup)).toBe(true);
  });

  it("breaks the group on a >5min gap even same side/day", () => {
    const rows = buildChatTimeline(
      [msg("a", day(2026, 2, 4, 10, 0), "in"), msg("b", day(2026, 2, 4, 10, 10), "in")],
      NOW,
    ).filter((r) => r.kind === "msg");
    expect(rows.every((r) => r.kind === "msg" && r.firstOfGroup && r.lastOfGroup)).toBe(true);
  });

  it("inserts a fresh day row when the day changes", () => {
    const rows = buildChatTimeline(
      [msg("a", day(2026, 2, 3, 23, 0), "in"), msg("b", day(2026, 2, 4, 0, 30), "in")],
      NOW,
    );
    expect(rows.filter((r) => r.kind === "day").map((r) => r.kind === "day" && r.label)).toEqual([
      "Yesterday",
      "Today",
    ]);
  });
});
