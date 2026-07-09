// Returning-user session restore. The in-memory session token (docs 4.9) is lost
// on every page load, so on boot we re-derive it from the locally-persisted
// (encrypted) identity: load the bundle, sign a fresh auth challenge, exchange it
// for a new 24h token. No password/seed needed on the same device - the master
// key (a non-extractable WebCrypto key in IndexedDB) decrypts the identity.
import * as api from "../api/client";
import { cryptoCall } from "../workers/crypto-client";
import { useAuth } from "../store/auth";
import { loadBundle, loadProgress } from "../onboarding/store";
import { fromHex, toHex, type HybridSig, type IdentityBundle } from "../crypto/onboarding-crypto";

/** Sign a fresh auth challenge with the identity's keys → a 24h session token
 *  (docs 4.9). Used by boot-restore and by seed-phrase recovery. */
export async function authenticateBundle(bundle: IdentityBundle): Promise<string> {
  const chal = await api.authChallenge(bundle.userId);
  const ts = Math.floor(Date.now() / 1000);
  const sig = await cryptoCall<HybridSig>("sign_challenge", [
    fromHex(chal.challenge),
    bundle.userId,
    ts,
    bundle.identity.ed25519_priv,
    bundle.identity.dilithium3_priv,
  ]);
  const res = await api.authVerify({
    user_id: bundle.userId,
    challenge: chal.challenge,
    sig_ed: toHex(sig.ed),
    sig_dil: toHex(sig.dil),
    timestamp: ts,
  });
  return res.session_token;
}

// The auth challenge is single-use per identity (server GETDEL) and rate-limited
// 5/60s. Two concurrent restores (e.g. React StrictMode double-invoking the boot
// effect in dev) would each fetch a challenge, overwrite each other's, and both
// fail verification → a false "offline". Dedupe to a single in-flight attempt.
let inFlight: Promise<boolean> | null = null;

/** Returns true if a finished identity was found and re-authenticated. A false
 *  result (not onboarded) routes the app to onboarding; a thrown error (server
 *  unreachable) is handled by the caller - the identity is intact, retry later. */
export function restoreSession(): Promise<boolean> {
  if (inFlight) return inFlight;
  inFlight = doRestore().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

async function doRestore(): Promise<boolean> {
  const progress = await loadProgress();
  if (progress.step !== "done") return false;

  const bundle = await loadBundle();
  if (!bundle) return false;

  const token = await authenticateBundle(bundle);
  useAuth.getState().setSession(token, bundle.userId);
  useAuth.getState().setAuthenticated(bundle.userId);
  scheduleRenewal();
  return true;
}

// --- silent token renewal + 401 recovery (docs 4.9, PVX-07) ---
// The 24h session token never rotated in-session: a tab open past 24h got a 401
// nothing recovered from. Renew in the background at ~T-2h, and re-mint on demand
// when an authenticated call 401s (stale token / post-renewal race).

const TOKEN_TTL_MS = 24 * 3600 * 1000; // server token::TTL_SECS
const RENEW_LEAD_MS = 2 * 3600 * 1000; // renew 2h before expiry (docs 4.9)
let renewTimer: ReturnType<typeof setTimeout> | null = null;

// ponytail: fixed-lead schedule (TTL is a server constant). If the server TTL
// ever varies, thread authVerify's expires_at through and schedule against that.
function scheduleRenewal(): void {
  if (renewTimer) clearTimeout(renewTimer);
  renewTimer = setTimeout(() => {
    void reauthenticate();
  }, Math.max(60_000, TOKEN_TTL_MS - RENEW_LEAD_MS));
}

/** Start/reset the background renewal timer. Idempotent - safe to call on every
 *  session change (App wires it to the authenticated+token effect). */
export function startTokenRenewal(): void {
  scheduleRenewal();
}

/** Stop the renewal timer (sign-out / socket teardown). */
export function stopTokenRenewal(): void {
  if (renewTimer) clearTimeout(renewTimer);
  renewTimer = null;
}

let reauthInFlight: Promise<boolean> | null = null;

/** Re-mint the session token from the locally-stored identity and reschedule
 *  renewal. Deduped so concurrent 401s don't race two auth challenges (each
 *  fetch is single-use and would invalidate the other). Returns false when not
 *  onboarded or the re-auth fails (server unreachable). */
export function reauthenticate(): Promise<boolean> {
  if (reauthInFlight) return reauthInFlight;
  reauthInFlight = doReauth().finally(() => {
    reauthInFlight = null;
  });
  return reauthInFlight;
}

async function doReauth(): Promise<boolean> {
  const bundle = await loadBundle();
  if (!bundle) return false;
  const token = await authenticateBundle(bundle);
  useAuth.getState().setSession(token, bundle.userId);
  scheduleRenewal();
  return true;
}
