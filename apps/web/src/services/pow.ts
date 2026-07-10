// Client-side Proof-of-Work for the PoW-gated public endpoints (key-bundle fetch,
// KT proof, OPAQUE login init). Mirrors registration: fetch a fresh single-use
// challenge, solve it in the crypto worker, return the proof the server consumes.
// This is what lets adding a contact / probing the directory cost real compute
// instead of an IP/identity rate limit - preserving zero-knowledge.
//
// Hybrid challenges (docs 8.5.1) carry Argon2id parameters; the solver runs the
// memory-hard layer on top of the SHA pre-filter. Challenges without the argon
// block (old server / emergency rollback) solve as legacy SHA-only.
import * as api from "../api/client";
import { fromHex, toHex, type PowArgonParams, type PowResult } from "../crypto/onboarding-crypto";

export type SolvePow = (
  challenge: Uint8Array,
  difficulty: number,
  argon?: PowArgonParams,
) => Promise<PowResult>;

/** Get a challenge, solve it (difficulty is server-chosen and climbs under load),
 *  and return the proof. `solve` is injectable so the flow is testable without a
 *  SharedWorker. */
export async function solveServerPow(solve: SolvePow): Promise<api.PowProof> {
  const chal = await api.powChallenge();
  const sol = await solve(fromHex(chal.challenge), chal.difficulty, chal.argon);
  return {
    challenge_id: chal.challenge_id,
    nonce: sol.nonce,
    solution_hash: toHex(sol.solutionHash),
  };
}
