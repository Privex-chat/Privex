// Private Set Intersection client side (docs 7) - OPRF blinding on Ristretto255.
// The client blinds a hash, the server applies its secret OPRF key, the client
// unblinds to get the OPRF output, then checks membership in a precomputed set.
// The server never learns the client's hash.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;
use wasm_bindgen::prelude::*;

fn decompress(bytes: &[u8]) -> Result<RistrettoPoint, JsError> {
    let compressed =
        CompressedRistretto::from_slice(bytes).map_err(|_| JsError::new("point must be 32 bytes"))?;
    compressed
        .decompress()
        .ok_or_else(|| JsError::new("invalid ristretto point"))
}

fn scalar_from(bytes: &[u8]) -> Result<Scalar, JsError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("scalar must be 32 bytes"))?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| JsError::new("non-canonical scalar"))
}

#[wasm_bindgen(getter_with_clone)]
pub struct PSIBlindResult {
    pub blinded: Vec<u8>,
    pub r: Vec<u8>,
}

/// blinded = r * H_to_curve(hash); returns the blinded point and the blind r.
#[wasm_bindgen]
pub fn psi_blind_hash(hash: &[u8]) -> PSIBlindResult {
    let point = RistrettoPoint::hash_from_bytes::<Sha512>(hash);
    let r = Scalar::random(&mut OsRng);
    let blinded = point * r;
    PSIBlindResult {
        blinded: blinded.compress().to_bytes().to_vec(),
        r: r.to_bytes().to_vec(),
    }
}

/// unblinded = (1/r) * server_response - the OPRF output for the client's hash.
#[wasm_bindgen]
pub fn psi_unblind(server_response: &[u8], r: &[u8]) -> Result<Vec<u8>, JsError> {
    let response = decompress(server_response)?;
    let inv = scalar_from(r)?.invert();
    Ok((response * inv).compress().to_bytes().to_vec())
}

/// Binary search for `unblinded` in a sorted set of 32-byte entries.
#[wasm_bindgen]
pub fn psi_check_membership(unblinded: &[u8], precomputed_set: &[u8]) -> bool {
    if unblinded.len() != 32 || precomputed_set.len() % 32 != 0 {
        return false;
    }
    let n = precomputed_set.len() / 32;
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry = &precomputed_set[mid * 32..mid * 32 + 32];
        match entry.cmp(unblinded) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oprf_blind_unblind_and_membership() {
        let hash = b"perceptual-hash-of-an-image";

        // Client blinds.
        let blinded = psi_blind_hash(hash);

        // Server applies its secret OPRF key k.
        let k = Scalar::random(&mut OsRng);
        let blinded_pt = decompress(&blinded.blinded).unwrap();
        let response = (blinded_pt * k).compress().to_bytes();

        // Client unblinds → should equal k * H(hash).
        let unblinded = psi_unblind(&response, &blinded.r).unwrap();
        let expected = (RistrettoPoint::hash_from_bytes::<Sha512>(hash) * k)
            .compress()
            .to_bytes()
            .to_vec();
        assert_eq!(unblinded, expected);

        // Membership: present in the set, absent when altered.
        assert!(psi_check_membership(&unblinded, &expected));
        let mut other = expected.clone();
        other[0] ^= 0xff;
        assert!(!psi_check_membership(&other, &expected));
    }
}
