// Hybrid PoW (docs 8.5.1): the client must solve whatever the server issued —
// legacy SHA-only when the challenge has no argon block, the Argon2id hybrid
// when it does — against the REAL wasm solver.
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import { solvePow, toHex, type PowArgonParams } from "../crypto/onboarding-crypto";
import { solveServerPow, type SolvePow } from "../services/pow";

beforeAll(async () => {
  const wasmUrl = new URL(
    "../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm",
    import.meta.url,
  );
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});

// Tiny params keep the test fast; production issues 32 MiB / bit targets that
// climb with load. The scheme is identical.
const ARGON: PowArgonParams = { m_cost_kib: 64, t_cost: 1, difficulty: 1 };
const CHALLENGE = new Uint8Array(32).fill(0xab);

describe("hybrid PoW solver", () => {
  it("solves a hybrid challenge; the exact wire hash verifies, a tampered one doesn't", () => {
    const sol = solvePow(wasm, CHALLENGE, 8, undefined, ARGON);
    // The verifier (like the server's hybrid_valid) recomputes the Argon2id
    // output and requires an EXACT byte match of the returned solution hash.
    expect(
      wasm.pow_verify_hybrid(
        CHALLENGE,
        BigInt(sol.nonce),
        8,
        ARGON.m_cost_kib,
        ARGON.t_cost,
        ARGON.difficulty,
        sol.solutionHash,
      ),
    ).toBe(true);
    // Same nonce, a single flipped byte in the wire hash → rejected.
    const tampered = new Uint8Array(sol.solutionHash);
    tampered[0] ^= 0x80;
    expect(
      wasm.pow_verify_hybrid(
        CHALLENGE,
        BigInt(sol.nonce),
        8,
        ARGON.m_cost_kib,
        ARGON.t_cost,
        ARGON.difficulty,
        tampered,
      ),
    ).toBe(false);
    // And the hybrid wire hash is the Argon2id output, never the plain SHA hash:
    // it can't be replayed against the legacy SHA-only verifier.
    const sha = solvePow(wasm, CHALLENGE, 8);
    expect(toHex(sol.solutionHash)).not.toBe(toHex(sha.solutionHash));
  });

  it("still solves legacy SHA-only challenges (old server / rollback)", () => {
    const sol = solvePow(wasm, CHALLENGE, 8);
    expect(wasm.pow_verify(CHALLENGE, BigInt(sol.nonce), 8)).toBe(true);
  });

  it("solveServerPow passes the issued argon params through to the solver", async () => {
    const issued = {
      challenge_id: "22222222-2222-4222-8222-222222222222",
      challenge: toHex(CHALLENGE),
      difficulty: 8,
      expires_at: 0,
      argon: { m_cost_kib: 64, t_cost: 1, difficulty: 1 },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(issued), { status: 200 })),
    );
    const seen: unknown[] = [];
    const solve: SolvePow = async (c, d, a) => {
      seen.push(c.length, d, a);
      return { nonce: 7, solutionHash: new Uint8Array(32) };
    };
    const proof = await solveServerPow(solve);
    expect(seen).toEqual([32, 8, issued.argon]);
    expect(proof.challenge_id).toBe(issued.challenge_id);
    expect(proof.nonce).toBe(7);
  });

  afterEach(() => vi.unstubAllGlobals());
});
