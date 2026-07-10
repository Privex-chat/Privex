// Server-side Proof-of-Work verification (mirrors crypto-wasm's hashcash):
// SHA-256(challenge || nonce_le) must have >= difficulty leading zero bits.
//
// HYBRID LAYER 2 (docs 8.5.1): challenges issued with Argon2id parameters
// additionally require the memory-hard condition
//   h2 = Argon2id(pwd = h1, salt = challenge, m, t, p=1)
// to meet `argon.difficulty` leading zero bits, and the submitted solution_hash
// is h2 (not h1). The SHA layer stays as a cheap pre-filter, so garbage
// submissions are rejected before the server spends an Argon2id evaluation.
// Verification cost is bounded: every verify first consumes a single-use
// challenge, and challenge issuance is globally capped (routes/auth.rs).

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

/// Argon2id parameters bound to a challenge at ISSUE time (stored in Redis with
/// the challenge, echoed to the client). Verification always uses the stored
/// copy, so parameter tuning never breaks in-flight challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgonParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    /// Leading-zero-bit target over the Argon2id output.
    pub difficulty: u32,
}

fn pow_hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for &b in hash {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

fn argon2id_32(input: &[u8], salt: &[u8], m_cost_kib: u32, t_cost: u32) -> Option<[u8; 32]> {
    let params = Params::new(m_cost_kib, t_cost, 1, Some(32)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon.hash_password_into(input, salt, &mut out).ok()?;
    Some(out)
}

/// True if `nonce` solves `challenge` at `difficulty` and matches `solution_hash`.
pub fn pow_valid(challenge: &[u8], nonce: u64, difficulty: u32, solution_hash: &[u8]) -> bool {
    let h = pow_hash(challenge, nonce);
    leading_zero_bits(&h) >= difficulty && h.as_slice() == solution_hash
}

/// Hybrid check (docs 8.5.1). Cheap SHA pre-filter FIRST; the Argon2id
/// evaluation only runs for solutions that already pass it.
pub fn hybrid_valid(
    challenge: &[u8],
    nonce: u64,
    sha_difficulty: u32,
    argon: &ArgonParams,
    solution_hash: &[u8],
) -> bool {
    let h1 = pow_hash(challenge, nonce);
    if leading_zero_bits(&h1) < sha_difficulty {
        return false;
    }
    let Some(h2) = argon2id_32(&h1, challenge, argon.m_cost_kib, argon.t_cost) else {
        return false;
    };
    leading_zero_bits(&h2) >= argon.difficulty && h2.as_slice() == solution_hash
}

/// Native solver - used by tests to produce a valid solution.
pub fn pow_solve(challenge: &[u8], difficulty: u32) -> (u64, [u8; 32]) {
    let mut nonce = 0u64;
    loop {
        let h = pow_hash(challenge, nonce);
        if leading_zero_bits(&h) >= difficulty {
            return (nonce, h);
        }
        nonce += 1;
    }
}

/// Native hybrid solver - used by tests to produce a valid hybrid solution.
pub fn hybrid_solve(challenge: &[u8], sha_difficulty: u32, argon: &ArgonParams) -> (u64, [u8; 32]) {
    let mut nonce = 0u64;
    loop {
        let h1 = pow_hash(challenge, nonce);
        if leading_zero_bits(&h1) >= sha_difficulty {
            let h2 = argon2id_32(&h1, challenge, argon.m_cost_kib, argon.t_cost)
                .expect("argon2 params");
            if leading_zero_bits(&h2) >= argon.difficulty {
                return (nonce, h2);
            }
        }
        nonce += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny params keep tests fast; production issues 32 MiB (pow_difficulty.rs).
    const TEST_ARGON: ArgonParams = ArgonParams {
        m_cost_kib: 64,
        t_cost: 1,
        difficulty: 1,
    };

    #[test]
    fn sha_solve_verify_tamper() {
        let challenge = b"privex-server-pow";
        let (nonce, hash) = pow_solve(challenge, 12);
        assert!(pow_valid(challenge, nonce, 12, &hash));
        assert!(!pow_valid(challenge, nonce ^ 1, 12, &hash));
        let mut bad = hash;
        bad[31] ^= 1;
        assert!(!pow_valid(challenge, nonce, 12, &bad));
    }

    #[test]
    fn hybrid_solve_verify_tamper() {
        let challenge = b"privex-server-hybrid-pow";
        let (nonce, h2) = hybrid_solve(challenge, 8, &TEST_ARGON);
        assert!(hybrid_valid(challenge, nonce, 8, &TEST_ARGON, &h2));
        // Wrong nonce fails.
        assert!(!hybrid_valid(challenge, nonce ^ 1, 8, &TEST_ARGON, &h2));
        // Tampered solution hash fails even with the right nonce.
        let mut bad = h2;
        bad[0] ^= 0x80;
        assert!(!hybrid_valid(challenge, nonce, 8, &TEST_ARGON, &bad));
        // Submitting the SHA hash (legacy shape) against a hybrid challenge fails:
        // the wire hash must be the Argon2id output.
        let h1 = pow_hash(challenge, nonce);
        if h1 != h2 {
            assert!(!hybrid_valid(challenge, nonce, 8, &TEST_ARGON, &h1));
        }
    }

    #[test]
    fn hybrid_rejects_cheap_sha_bypass() {
        // A nonce that fails the SHA pre-filter is rejected WITHOUT running
        // Argon2id, whatever hash is submitted.
        let challenge = b"privex-prefilter";
        let mut nonce = 0u64;
        while leading_zero_bits(&pow_hash(challenge, nonce)) >= 8 {
            nonce += 1;
        }
        assert!(!hybrid_valid(challenge, nonce, 8, &TEST_ARGON, &[0u8; 32]));
    }
}
