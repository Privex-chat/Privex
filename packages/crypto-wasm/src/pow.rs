// Proof of Work - hashcash over SHA-256 (docs 8.5). Sanctioned custom component
// (CLAUDE.md). A solution is a nonce s.t. SHA-256(challenge || nonce_le) has at
// least `difficulty` leading zero BITS. Registration uses this instead of IP
// rate-limiting, so no IP is ever needed.
//
// HYBRID LAYER 2 (docs 8.5.1): when the server issues Argon2id parameters with
// the challenge, the solution must ALSO satisfy a memory-hard condition:
//   h1 = SHA-256(challenge || nonce_le)        with >= sha_difficulty zero bits
//   h2 = Argon2id(pwd=h1, salt=challenge, m, t) with >= argon_difficulty zero bits
//   solution_hash = h2
// The SHA layer is a cheap pre-filter (bounds the number of Argon2id evals to an
// expected 2^argon_difficulty); the Argon2id layer is what GPU/ASIC farms cannot
// parallelize cheaply - every attempt needs its own m KiB of memory bandwidth.

use argon2::{Algorithm, Argon2, Params, Version};
use js_sys::Function;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

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

/// Native solver (no JS callbacks) - used by host tests and the bench.
pub fn pow_solve_native(challenge: &[u8], difficulty: u32) -> (u64, [u8; 32]) {
    let mut nonce = 0u64;
    loop {
        let h = pow_hash(challenge, nonce);
        if leading_zero_bits(&h) >= difficulty {
            return (nonce, h);
        }
        nonce += 1;
    }
}

#[wasm_bindgen(getter_with_clone)]
pub struct PowSolution {
    pub nonce: u64,
    pub solution_hash: Vec<u8>,
}

/// Solve a PoW challenge. Reports progress (the attempt count) every 10k tries
/// via `progress`, and checks `abort` (truthy return aborts) - both optional.
#[wasm_bindgen]
pub fn pow_solve(
    challenge: &[u8],
    difficulty: u32,
    progress: Option<Function>,
    abort: Option<Function>,
) -> Result<PowSolution, JsError> {
    let mut nonce = 0u64;
    loop {
        if nonce > 0 && nonce % 10_000 == 0 {
            if let Some(cb) = &progress {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from_f64(nonce as f64));
            }
            if let Some(cb) = &abort {
                if let Ok(v) = cb.call0(&JsValue::NULL) {
                    if v.is_truthy() {
                        return Err(JsError::new("pow_solve aborted"));
                    }
                }
            }
        }
        let h = pow_hash(challenge, nonce);
        if leading_zero_bits(&h) >= difficulty {
            return Ok(PowSolution {
                nonce,
                solution_hash: h.to_vec(),
            });
        }
        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| JsError::new("pow_solve: nonce space exhausted"))?;
    }
}

/// Verify a PoW solution without solving.
#[wasm_bindgen]
pub fn pow_verify(challenge: &[u8], nonce: u64, difficulty: u32) -> bool {
    leading_zero_bits(&pow_hash(challenge, nonce)) >= difficulty
}

// --- hybrid Layer 2 (SHA-256 pre-filter + Argon2id finisher, docs 8.5.1) ---

fn argon2id_32(input: &[u8], salt: &[u8], m_cost_kib: u32, t_cost: u32) -> Result<[u8; 32], JsError> {
    let params =
        Params::new(m_cost_kib, t_cost, 1, Some(32)).map_err(|_| JsError::new("argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(input, salt, &mut out)
        .map_err(|_| JsError::new("argon2"))?;
    Ok(out)
}

/// Native hybrid solver (no JS callbacks) - host tests.
pub fn pow_solve_hybrid_native(
    challenge: &[u8],
    sha_difficulty: u32,
    m_cost_kib: u32,
    t_cost: u32,
    argon_difficulty: u32,
) -> (u64, [u8; 32]) {
    let mut nonce = 0u64;
    loop {
        let h1 = pow_hash(challenge, nonce);
        if leading_zero_bits(&h1) >= sha_difficulty {
            let h2 = argon2id_32(&h1, challenge, m_cost_kib, t_cost).expect("argon2");
            if leading_zero_bits(&h2) >= argon_difficulty {
                return (nonce, h2);
            }
        }
        nonce += 1;
    }
}

/// Solve a HYBRID PoW challenge (docs 8.5.1). Same progress/abort contract as
/// `pow_solve`; progress additionally fires after every Argon2id evaluation (the
/// slow step), so the UI stays live even when SHA batches are fast.
#[wasm_bindgen]
pub fn pow_solve_hybrid(
    challenge: &[u8],
    sha_difficulty: u32,
    m_cost_kib: u32,
    t_cost: u32,
    argon_difficulty: u32,
    progress: Option<Function>,
    abort: Option<Function>,
) -> Result<PowSolution, JsError> {
    let mut nonce = 0u64;
    loop {
        if nonce > 0 && nonce % 10_000 == 0 {
            if let Some(cb) = &progress {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from_f64(nonce as f64));
            }
            if let Some(cb) = &abort {
                if let Ok(v) = cb.call0(&JsValue::NULL) {
                    if v.is_truthy() {
                        return Err(JsError::new("pow_solve aborted"));
                    }
                }
            }
        }
        let h1 = pow_hash(challenge, nonce);
        if leading_zero_bits(&h1) >= sha_difficulty {
            let h2 = argon2id_32(&h1, challenge, m_cost_kib, t_cost)?;
            if leading_zero_bits(&h2) >= argon_difficulty {
                return Ok(PowSolution {
                    nonce,
                    solution_hash: h2.to_vec(),
                });
            }
            if let Some(cb) = &progress {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from_f64(nonce as f64));
            }
        }
        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| JsError::new("pow_solve: nonce space exhausted"))?;
    }
}

/// Verify a hybrid solution without solving. Faithful mirror of the server's
/// `powcheck::hybrid_valid`: BOTH difficulty checks AND an exact byte match of
/// the submitted `solution_hash` against the recomputed Argon2id output.
#[wasm_bindgen]
pub fn pow_verify_hybrid(
    challenge: &[u8],
    nonce: u64,
    sha_difficulty: u32,
    m_cost_kib: u32,
    t_cost: u32,
    argon_difficulty: u32,
    solution_hash: &[u8],
) -> Result<bool, JsError> {
    let h1 = pow_hash(challenge, nonce);
    if leading_zero_bits(&h1) < sha_difficulty {
        return Ok(false);
    }
    let h2 = argon2id_32(&h1, challenge, m_cost_kib, t_cost)?;
    Ok(leading_zero_bits(&h2) >= argon_difficulty && h2.as_slice() == solution_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify_and_tamper() {
        let challenge = b"privex-pow-test";
        let difficulty = 16; // fast in debug
        let (nonce, hash) = pow_solve_native(challenge, difficulty);
        assert!(leading_zero_bits(&hash) >= difficulty);
        assert!(pow_verify(challenge, nonce, difficulty));
        // flip the nonce → must fail
        assert!(!pow_verify(challenge, nonce ^ 1, difficulty));
    }

    #[test]
    fn hybrid_solve_then_verify_and_tamper() {
        let challenge = b"privex-hybrid-pow-test-salt"; // >= 8 bytes (argon2 salt min)
        // Tiny params keep the test fast; production uses 32 MiB and real bits.
        let (sha_d, m, t, argon_d) = (8, 64, 1, 1);
        let (nonce, h2) = pow_solve_hybrid_native(challenge, sha_d, m, t, argon_d);
        // The returned hash is the Argon2id output and meets the bit target.
        assert!(leading_zero_bits(&h2) >= argon_d);
        assert_eq!(
            argon2id_32(&pow_hash(challenge, nonce), challenge, m, t).unwrap(),
            h2
        );
        // The SHA pre-filter held too.
        assert!(leading_zero_bits(&pow_hash(challenge, nonce)) >= sha_d);
        // Tampered nonce fails one gate or the other.
        let h1x = pow_hash(challenge, nonce ^ 1);
        let failed = leading_zero_bits(&h1x) < sha_d
            || leading_zero_bits(&argon2id_32(&h1x, challenge, m, t).unwrap()) < argon_d
            || argon2id_32(&h1x, challenge, m, t).unwrap() != h2;
        assert!(failed);

        // The public verifier accepts the exact solution and rejects a tampered
        // wire hash even with the correct nonce (exact-match, like the server).
        assert!(pow_verify_hybrid(challenge, nonce, sha_d, m, t, argon_d, &h2).unwrap());
        let mut wrong = h2;
        wrong[0] ^= 0x80;
        assert!(!pow_verify_hybrid(challenge, nonce, sha_d, m, t, argon_d, &wrong).unwrap());
    }
}
