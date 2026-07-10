// Registration pipeline. Orchestrates worker crypto + server API + encrypted
// persistence. The crypto surface is injectable (CryptoApi) so the whole flow is
// testable in Node against the wasm directly, with a mocked fetch - no
// SharedWorker required.
//
// Order note: the build guide sketches OPAQUE setup *before* PoW registration,
// but the live server (post-S12 audit C1) makes OPAQUE setup a SEPARATE
// AUTHENTICATED step. So the real order is: register keys (PoW), obtain a
// session token (signed challenge), then let the user opt into OPAQUE recovery
// from onboarding or Settings.
import * as api from "../api/client";
import { useAuth } from "../store/auth";
import {
  fromHex,
  toHex,
  type IdentityBundle,
  type PowArgonParams,
  type PowResult,
  type HybridSig,
} from "../crypto/onboarding-crypto";
import { cryptoCall } from "../workers/crypto-client";
import { finalizeIdentity, loadBundle, persistGeneratedIdentity, saveProgress } from "./store";

export interface CryptoApi {
  genIdentity(entropy: Uint8Array): Promise<IdentityBundle>;
  solvePow(
    challenge: Uint8Array,
    difficulty: number,
    onProgress?: (n: number) => void,
    argon?: PowArgonParams,
  ): Promise<PowResult>;
  signChallenge(
    challenge: Uint8Array,
    userId: string,
    timestamp: number,
    edPriv: Uint8Array,
    dilPriv: Uint8Array,
  ): Promise<HybridSig>;
}

/** Production crypto: routes to the SharedWorker. */
export const workerCrypto: CryptoApi = {
  genIdentity: (e) => cryptoCall("gen_identity", [e]),
  solvePow: (c, d, onP, a) => cryptoCall("solve_pow", [c, d, a], onP),
  signChallenge: (c, uid, ts, ed, dil) => cryptoCall("sign_challenge", [c, uid, ts, ed, dil]),
};

function randomEntropy(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/** STEP 2: generate the identity in the worker and persist it encrypted. Returns
 *  the px_id for display. Idempotent-ish: a fresh call replaces any half-done
 *  bundle (only reached before server registration). */
export async function generateIdentity(crypto: CryptoApi = workerCrypto): Promise<string> {
  const bundle = await crypto.genIdentity(randomEntropy());
  await persistGeneratedIdentity(bundle);
  return bundle.userId;
}

async function authenticate(bundle: IdentityBundle, crypto: CryptoApi): Promise<string> {
  const chal = await api.authChallenge(bundle.userId);
  const ts = Math.floor(Date.now() / 1000);
  const sig = await crypto.signChallenge(
    fromHex(chal.challenge),
    bundle.userId,
    ts,
    bundle.identity.ed25519_priv,
    bundle.identity.dilithium3_priv,
  );
  const res = await api.authVerify({
    user_id: bundle.userId,
    challenge: chal.challenge,
    sig_ed: toHex(sig.ed),
    sig_dil: toHex(sig.dil),
    timestamp: ts,
  });
  return res.session_token;
}

/** STEP 4: solve PoW, register keys, and obtain a session token. OPAQUE
 *  password recovery is opt-in after signup or from Settings. The server
 *  registration is atomic; on success the token is held in
 *  memory (Zustand) - never localStorage. */
export async function completeRegistration(
  onPow?: (percent: number) => void,
  crypto: CryptoApi = workerCrypto,
): Promise<void> {
  const bundle = await loadBundle();
  if (!bundle) throw new Error("no identity to register");

  const chal = await api.powChallenge();
  // Progress is best-effort: PoW attempt count → a rough percent of the expected
  // ~2^(total bits)/2 average nonce count. Hybrid challenges (docs 8.5.1) grind
  // 2^(sha + argon) nonces on average. Capped at 99% until the solution lands.
  const totalBits = chal.difficulty + (chal.argon?.difficulty ?? 0);
  const expected = Math.pow(2, totalBits - 1);
  const pow = await crypto.solvePow(
    fromHex(chal.challenge),
    chal.difficulty,
    (n) => {
      onPow?.(Math.min(99, Math.floor((n / expected) * 100)));
    },
    chal.argon,
  );

  try {
    await api.register({
      user_id: bundle.userId,
      ik_ed25519_pub: toHex(bundle.identity.ed25519_pub),
      ik_dilithium3_pub: toHex(bundle.identity.dilithium3_pub),
      ik_x25519_pub: toHex(bundle.identity.x25519_pub),
      spk_x25519_pub: toHex(bundle.spk.pub),
      spk_sig_ed: toHex(bundle.spkSig.ed),
      spk_sig_dil: toHex(bundle.spkSig.dil),
      kyber1024_pub: toHex(bundle.identity.kyber1024_pub),
      opks: bundle.opks.map((o) => ({ opk_id: o.id, opk_x25519_pub: toHex(o.pub) })),
      pow: { challenge_id: chal.challenge_id, nonce: pow.nonce, solution_hash: toHex(pow.solutionHash) },
    });
  } catch (e) {
    // 409 = our px_id already exists: a resume after keys were registered. The
    // account is ours (px_id derives from our own identity key), so continue to
    // auth and recovery choices.
    if (!(e instanceof api.ApiError && e.status === 409)) throw e;
  }
  onPow?.(100);

  const token = await authenticate(bundle, crypto);

  await saveProgress("registered", bundle.userId);
  // Token held in memory only; authenticated flips at the end of onboarding.
  useAuth.getState().setSession(token, bundle.userId);
}

/** STEP 6: ensure a live session (re-auth if the in-memory token was lost to a
 *  refresh), strip the mnemonic from storage, and enter the app. */
export async function finishOnboarding(crypto: CryptoApi = workerCrypto): Promise<void> {
  const bundle = await loadBundle();
  if (!bundle) throw new Error("no identity to finalize");

  let token = useAuth.getState().sessionToken;
  if (!token) {
    token = await authenticate(bundle, crypto);
    useAuth.getState().setSession(token, bundle.userId);
  }
  await finalizeIdentity(bundle);
  useAuth.getState().setAuthenticated(bundle.userId);
}
