// Server-side Proof-of-Work verification (mirrors crypto-wasm's hashcash):
// SHA-256(challenge || nonce_le) must have >= difficulty leading zero bits.

use sha2::{Digest, Sha256};

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

/// True if `nonce` solves `challenge` at `difficulty` and matches `solution_hash`.
pub fn pow_valid(challenge: &[u8], nonce: u64, difficulty: u32, solution_hash: &[u8]) -> bool {
    let h = pow_hash(challenge, nonce);
    leading_zero_bits(&h) >= difficulty && h.as_slice() == solution_hash
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
