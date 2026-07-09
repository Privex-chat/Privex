// Typed server API. Same-origin by default (Caddy proxies in prod; the Vite dev
// server proxies to the local backend). Override with VITE_API_BASE for other
// setups. The session token rides in the X-Privex-Auth header only - never a
// query string (those can land in proxy logs).
const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

export class ApiError extends Error {
  constructor(public status: number) {
    super(`api ${status}`);
  }
}

async function post<T>(path: string, body: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["X-Privex-Auth"] = token;
  const res = await fetch(BASE + path, { method: "POST", headers, body: JSON.stringify(body) });
  if (!res.ok) throw new ApiError(res.status);
  return res.json() as Promise<T>;
}

async function get<T>(path: string, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers["X-Privex-Auth"] = token;
  const res = await fetch(BASE + path, { headers });
  if (!res.ok) throw new ApiError(res.status);
  return res.json() as Promise<T>;
}

async function del<T>(path: string, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers["X-Privex-Auth"] = token;
  const res = await fetch(BASE + path, { method: "DELETE", headers });
  if (!res.ok) throw new ApiError(res.status);
  return res.json() as Promise<T>;
}

// --- PoW + registration ---

export interface PowChallenge {
  challenge_id: string;
  challenge: string; // hex
  difficulty: number;
  expires_at: number;
}
export const powChallenge = () => post<PowChallenge>("/auth/pow_challenge", {});

/** A solved PoW the server consumes single-use (registration + the PoW-gated
 *  public fetches). solution_hash is hex SHA-256(challenge || nonce_le). */
export interface PowProof {
  challenge_id: string;
  nonce: number;
  solution_hash: string; // hex
}

export interface OpkReq {
  opk_id: number;
  opk_x25519_pub: string; // hex
}
export interface RegisterReq {
  user_id: string;
  ik_ed25519_pub: string;
  ik_dilithium3_pub: string;
  ik_x25519_pub: string;
  spk_x25519_pub: string;
  spk_sig_ed: string;
  spk_sig_dil: string;
  kyber1024_pub: string;
  opks: OpkReq[];
  pow: PowProof;
}
export const register = (req: RegisterReq) => post<{ registered: boolean }>("/keys/register", req);

// --- key fetching (public; POST /keys/{id}, PoW-gated) ---
// All key-material fields are HEX (server convention). Every fetch carries a KT
// inclusion proof - the client MUST verify it (see crypto/contact-crypto.ts).
// The fetch costs a solved PoW (closes account enumeration / OPK drain) - the
// caller solves a challenge and passes it here. The body is POSTed because a GET
// can't carry the proof.

export interface KtProofNode {
  left: boolean;
  hash: string; // hex
}
export interface KtProof {
  leaf: string; // hex
  path: KtProofNode[];
  root: string; // hex
  root_sig_ed: string; // hex Ed25519 sig over the 32-byte root
  timestamp: number; // entry timestamp (needed to reconstruct the leaf)
}
export interface KeyBundleResp {
  user_id: string;
  ik_ed25519: string;
  ik_dilithium3: string;
  ik_x25519: string;
  spk_x25519: string;
  spk_sig_ed: string;
  spk_sig_dil: string;
  kyber1024_pub: string;
  opk: string | null;
  opk_id: number | null;
  kt_proof: KtProof;
}
export const fetchKeyBundle = (userId: string, pow: PowProof) =>
  post<KeyBundleResp>(`/keys/${encodeURIComponent(userId)}`, { pow });

// --- prekey replenish (authenticated) ---

export interface OpkUpload {
  opk_id: number;
  opk_x25519_pub: string; // hex
}
export const replenishPrekeys = (opks: OpkUpload[], token: string) =>
  post<{ stored: number }>("/keys/prekeys/replenish", { opks }, token);

// --- messaging + WS ticket (authenticated) ---

export const wsTicket = (token: string) =>
  post<{ ticket: string; expires_at: number }>("/auth/ws_ticket", {}, token);

export const sendMessage = (recipientId: string, contentB64: string, token: string) =>
  post<{ queued: boolean; message_id: string }>(
    "/messages/send",
    { recipient_id: recipientId, content: contentB64 },
    token,
  );

export const ackMessages = (messageIds: string[], token: string) =>
  post<{ deleted: number }>("/messages/ack", { message_ids: messageIds }, token);

// --- blob store (authenticated; content-addressed by SHA-256(bytes)) ---
// Raw bytes, not JSON. chunk_id MUST equal SHA-256 of the body (server enforces).

export async function putBlob(chunkId: string, bytes: Uint8Array, token: string): Promise<void> {
  const res = await fetch(`${BASE}/blobs/${encodeURIComponent(chunkId)}`, {
    method: "POST",
    headers: { "X-Privex-Auth": token, "Content-Type": "application/octet-stream" },
    body: bytes as unknown as BodyInit,
  });
  if (!res.ok) throw new ApiError(res.status);
}

export async function getBlob(chunkId: string, token: string): Promise<Uint8Array> {
  const res = await fetch(`${BASE}/blobs/${encodeURIComponent(chunkId)}`, {
    headers: { "X-Privex-Auth": token },
  });
  if (!res.ok) throw new ApiError(res.status);
  return new Uint8Array(await res.arrayBuffer());
}

// --- auth (signed challenge → session token) ---

export const authChallenge = (userId: string) =>
  post<{ challenge: string; expires_at: number }>("/auth/challenge", { user_id: userId });

export interface VerifyReq {
  user_id: string;
  challenge: string; // hex
  sig_ed: string; // hex
  sig_dil: string; // hex
  timestamp: number;
}
export const authVerify = (req: VerifyReq) =>
  post<{ session_token: string; expires_at: number }>("/auth/verify", req);

// --- OPAQUE recovery setup (authenticated) ---

export const opaqueRegisterStart = (registrationRequestHex: string, token: string) =>
  post<{ registration_response: string }>(
    "/recovery/opaque/register/start",
    { registration_request: registrationRequestHex },
    token,
  );

export const opaqueRegisterFinish = (
  body: { registration_upload: string; envelope: string; envelope_mac: string },
  token: string,
) => post<{ stored: boolean }>("/recovery/opaque/register/finish", body, token);

export const opaqueStatus = (token: string) =>
  get<{ enabled: boolean }>("/recovery/opaque/status", token);

export const opaqueDisable = (token: string) =>
  del<{ enabled: boolean }>("/recovery/opaque", token);

// --- OPAQUE recovery login (no auth - the user lost their device) ---

export const opaqueLoginInit = (userId: string, credentialRequestHex: string, pow: PowProof) =>
  post<{ login_id: string; credential_response: string; envelope: string; envelope_mac: string }>(
    "/recovery/opaque/init",
    { user_id: userId, credential_request: credentialRequestHex, pow },
  );

export const opaqueLoginComplete = (loginId: string, finalizationHex: string) =>
  post<{ session_token: string; expires_at: number }>("/recovery/opaque/complete", {
    login_id: loginId,
    credential_finalization: finalizationHex,
  });

// --- recovery shares + key management + logout (authenticated) ---

export const storeShares = (
  shares: { share_index: number; encrypted_share: string }[],
  token: string,
) => post<{ stored: number }>("/recovery/shares/store", { shares }, token);

export const spkRotate = (
  body: { spk_x25519_pub: string; spk_sig_ed: string; spk_sig_dil: string },
  token: string,
) => post<{ rotated: boolean }>("/keys/spk/rotate", body, token);

export const logoutAll = (token: string) =>
  post<{ revoked: boolean }>("/auth/logout_all", {}, token);

// --- encrypted history backup (Option A; authenticated, opt-in) ---
// Blobs are AES-GCM ciphertext under the client's history_key - the server can't
// read them. Scoped to the authenticated user.

export interface HistoryBlobWire {
  blob_id: string;
  ciphertext: string; // base64
  created_at: number;
}

export const uploadHistory = (blobs: { blob_id: string; ciphertext: string }[], token: string) =>
  post<{ stored: number }>("/history/blobs", { blobs }, token);

export const listHistory = (token: string, after?: string, limit = 200) =>
  get<{ blobs: HistoryBlobWire[]; next: string | null }>(
    `/history/blobs?limit=${limit}${after ? `&after=${encodeURIComponent(after)}` : ""}`,
    token,
  );

export const historyStatus = (token: string) =>
  get<{ count: number; bytes: number }>("/history/status", token);

export const deleteHistory = (token: string) =>
  del<{ deleted: number }>("/history/blobs", token);
