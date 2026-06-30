// Shamir's Secret Sharing over GF(256) (AES field, poly 0x11b). Sanctioned as a
// custom in-house component by CLAUDE.md ("custom Shamir in crypto-wasm (GF256)")
// - it is a standard, well-defined scheme, not an invented cipher.
//
// Each share is: [threshold, x, payload...]. The secret is augmented with a
// 4-byte SHA-256 tag before splitting so that reconstruction from the wrong or
// too few shares ERRORS instead of silently returning garbage (plain Shamir
// cannot detect insufficient shares on its own).

use js_sys::Uint8Array;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const TAG_LEN: usize = 4;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // reduction by AES polynomial
        }
        b >>= 1;
    }
    p
}

// a^254 == a^-1 in GF(256) (since a^255 == 1 for a != 0).
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    for _ in 0..254 {
        result = gf_mul(result, a);
    }
    result
}

fn eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

fn interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                num = gf_mul(num, xj); // (0 - xj) == xj in GF(2^8)
                den = gf_mul(den, xi ^ xj); // (xi - xj) == xi ^ xj
            }
        }
        secret ^= gf_mul(yi, gf_mul(num, gf_inv(den)));
    }
    secret
}

pub(crate) fn split_core(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Vec<u8>>, String> {
    if threshold < 1 {
        return Err("threshold must be >= 1".into());
    }
    if total < threshold {
        return Err("total must be >= threshold".into());
    }
    // x ranges over 1..=total, and x must be distinct non-zero GF(256) elements.
    if total == 0 || total as u16 > 255 {
        return Err("total must be in 1..=255".into());
    }

    let mut augmented = secret.to_vec();
    augmented.extend_from_slice(&Sha256::digest(secret)[..TAG_LEN]);

    let mut shares: Vec<Vec<u8>> = (1..=total).map(|x| vec![threshold, x]).collect();
    for &byte in &augmented {
        let mut coeffs = vec![byte];
        let mut rnd = vec![0u8; (threshold - 1) as usize];
        getrandom::getrandom(&mut rnd).map_err(|e| e.to_string())?;
        coeffs.extend_from_slice(&rnd);
        for (i, x) in (1..=total).enumerate() {
            shares[i].push(eval(&coeffs, x));
        }
    }
    Ok(shares)
}

pub(crate) fn reconstruct_core(shares: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("no shares provided".into());
    }
    let threshold = shares[0][0];
    if shares.iter().any(|s| s.len() < 2 || s[0] != threshold) {
        return Err("shares are malformed or from different splits".into());
    }
    if shares.len() < threshold as usize {
        return Err(format!(
            "need at least {threshold} shares, got {}",
            shares.len()
        ));
    }

    let used = &shares[..threshold as usize];
    let payload_len = used[0].len() - 2;
    if used.iter().any(|s| s.len() != used[0].len()) {
        return Err("shares have inconsistent length".into());
    }

    let mut augmented = Vec::with_capacity(payload_len);
    for j in 0..payload_len {
        let points: Vec<(u8, u8)> = used.iter().map(|s| (s[1], s[2 + j])).collect();
        augmented.push(interpolate_at_zero(&points));
    }

    if augmented.len() < TAG_LEN {
        return Err("reconstructed data too short".into());
    }
    let split_at = augmented.len() - TAG_LEN;
    let secret = augmented[..split_at].to_vec();
    let tag = &augmented[split_at..];
    if Sha256::digest(&secret)[..TAG_LEN] != *tag {
        return Err("shares inconsistent - wrong or corrupted shares".into());
    }
    Ok(secret)
}

#[wasm_bindgen]
pub fn shamir_split(
    secret: &[u8],
    threshold: u8,
    total: u8,
) -> Result<Vec<Uint8Array>, JsError> {
    let shares = split_core(secret, threshold, total).map_err(|e| JsError::new(&e))?;
    Ok(shares
        .into_iter()
        .map(|s| Uint8Array::from(s.as_slice()))
        .collect())
}

#[wasm_bindgen]
pub fn shamir_reconstruct(shares: Vec<Uint8Array>) -> Result<Vec<u8>, JsError> {
    let owned: Vec<Vec<u8>> = shares.iter().map(|u| u.to_vec()).collect();
    reconstruct_core(&owned).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_of_five_every_combination() {
        let secret: Vec<u8> = (0..32).map(|i| i as u8 ^ 0xa5).collect();
        let shares = split_core(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Every 3-of-5 combination reconstructs exactly.
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let subset = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(reconstruct_core(&subset).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn below_threshold_errors() {
        let secret: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let shares = split_core(&secret, 3, 5).unwrap();
        let two = vec![shares[0].clone(), shares[1].clone()];
        assert!(reconstruct_core(&two).is_err());
    }

    #[test]
    fn corrupted_share_errors() {
        let secret: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let mut shares = split_core(&secret, 3, 5).unwrap();
        shares[1][5] ^= 0xff; // flip a payload byte
        let subset = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        assert!(reconstruct_core(&subset).is_err());
    }
}
