// Shared message types for the Nym transport worker.

export interface NymStatus {
  type: "status";
  status: "connected" | "disconnected";
  reason?: string;
}

export interface NymInbound {
  type: "message";
  payload: Uint8Array;
}

export type NymWorkerOut = NymStatus | NymInbound;

export type NymWorkerIn =
  | { type: "connect"; gateway?: string }
  | { type: "send"; payload: Uint8Array; recipient: string };
