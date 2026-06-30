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
});
