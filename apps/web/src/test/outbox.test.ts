// Offline outbox: queue order, stop-on-network-failure, drop-on-server-error.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db";
import { enqueue, flushOutbox, outboxCount } from "../services/outbox";
import * as api from "../api/client";

const row = (msg_id: string, timestamp: number, status: string) =>
  db.messages.put({
    msg_id,
    session_id: "px_1",
    content_enc: new Uint8Array(),
    timestamp,
    status,
    direction: "out" as const,
    kind: "text" as const,
  });

describe("offline outbox", () => {
  beforeEach(async () => {
    await db.outbox.clear();
    await db.messages.clear();
  });

  it("queues, flushes oldest-first, and keeps the rest after a network failure", async () => {
    await row("a", 1, "queued");
    await row("b", 2, "queued");
    await enqueue("px_1", "AAA", "a");
    await enqueue("px_1", "BBB", "b");
    expect(await outboxCount()).toBe(2);

    const order: string[] = [];
    let calls = 0;
    const send = vi.fn(async (_p: string, b64: string) => {
      order.push(b64);
      if (++calls === 1) return { message_id: "srv-a" };
      throw new TypeError("offline"); // bare network failure
    });

    await flushOutbox(send, "tok");
    expect(order).toEqual(["AAA", "BBB"]); // oldest first
    expect(await outboxCount()).toBe(1); // the failed one is retained
    expect((await db.messages.get("a"))?.status).toBe("sent");
    expect((await db.messages.get("b"))?.status).toBe("queued");

    // Reconnect: the queue drains and the row flips to sent.
    await flushOutbox(vi.fn(async () => ({ message_id: "srv-b" })), "tok");
    expect(await outboxCount()).toBe(0);
    expect((await db.messages.get("b"))?.status).toBe("sent");
  });

  it("keeps a transient server error (429/401) for a later retry", async () => {
    await enqueue("px_2", "X", "");
    await flushOutbox(
      vi.fn(async () => {
        throw new api.ApiError(429);
      }),
      "tok",
    );
    expect(await outboxCount()).toBe(1); // not dropped - will retry
  });

  it("drops a permanently-rejected (400) blob and marks the row failed", async () => {
    await row("c", 1, "queued");
    await enqueue("px_2", "X", "c");
    await flushOutbox(
      vi.fn(async () => {
        throw new api.ApiError(400);
      }),
      "tok",
    );
    expect(await outboxCount()).toBe(0);
    expect((await db.messages.get("c"))?.status).toBe("failed");
  });

  it("does nothing without a session token", async () => {
    await enqueue("px_3", "Y", "");
    const send = vi.fn(async () => ({ message_id: "x" }));
    await flushOutbox(send, null);
    expect(send).not.toHaveBeenCalled();
    expect(await outboxCount()).toBe(1);
  });

  // Per-message TTL (docs 4.12): the TTL counts from compose time, so a blob
  // parked past its own TTL is dropped as failed - never sent with a fresh
  // server window - and a still-live one is sent with its REMAINING seconds.
  it("drops a parked blob whose per-message TTL has already expired", async () => {
    await row("d", 1, "queued");
    await db.outbox.add({
      peer_id: "px_4",
      sealed_b64: "OLD",
      local_msg_id: "d",
      created_at: Date.now() - 2 * 3600 * 1000, // composed 2 h ago
      attempts: 0,
      ttl_seconds: 3600, // 1 h TTL → already expired
    });
    const send = vi.fn(async () => ({ message_id: "x" }));
    await flushOutbox(send, "tok");
    expect(send).not.toHaveBeenCalled();
    expect(await outboxCount()).toBe(0);
    expect((await db.messages.get("d"))?.status).toBe("failed");
  });

  it("sends a live TTL blob with its remaining seconds (legacy rows without a stored TTL send undefined)", async () => {
    await db.outbox.add({
      peer_id: "px_5",
      sealed_b64: "LIVE",
      local_msg_id: "",
      created_at: Date.now() - 3600 * 1000, // composed 1 h ago
      attempts: 0,
      ttl_seconds: 6 * 3600, // 6 h TTL → ~5 h left
    });
    await enqueue("px_5", "DEFAULT", ""); // legacy row shape (no TTL) → undefined on the wire
    const ttls: Array<number | undefined> = [];
    const send = vi.fn(async (_p: string, _b: string, _t: string, ttl?: number) => {
      ttls.push(ttl);
      return { message_id: "x" };
    });
    await flushOutbox(send, "tok");
    expect(await outboxCount()).toBe(0);
    expect(ttls).toHaveLength(2);
    expect(ttls[0]).toBeGreaterThan(4 * 3600);
    expect(ttls[0]).toBeLessThanOrEqual(5 * 3600);
    expect(ttls[1]).toBeUndefined();
  });
});
