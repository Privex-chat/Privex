// Proof of Work - hashcash over SHA-256 (docs 8.5). Sanctioned custom component
// (CLAUDE.md). A solution is a nonce s.t. SHA-256(challenge || nonce_le) has at
// least `difficulty` leading zero BITS. Registration uses this instead of IP
// rate-limiting, so no IP is ever needed.

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
}
