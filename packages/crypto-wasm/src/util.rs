// Misc crypto utilities: PDQ perceptual hash (CSAM check, Phase 2) and an
// HKDF-SHA256 helper exposed to the app.

use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// 256-bit PDQ perceptual hash of an RGBA image (width*height*4 bytes).
/// Returns 32 bytes. Used by the CSAM check in Phase 2.
#[wasm_bindgen]
pub fn pdq_hash(image_data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, JsError> {
    let buf = image::RgbaImage::from_raw(width, height, image_data.to_vec())
        .ok_or_else(|| JsError::new("image_data length must equal width*height*4"))?;
    let dynimg = image::DynamicImage::ImageRgba8(buf);
    let (hash, _quality) = pdqhash::generate_pdq_full_size(&dynimg);
    Ok(hash.to_vec())
}

/// HKDF-SHA256: derive `len` bytes from `input` under `salt`/`info`. Empty salt
/// means no salt.
#[wasm_bindgen]
pub fn hkdf_derive(input: &[u8], salt: &[u8], info: &str, len: u32) -> Result<Vec<u8>, JsError> {
    let salt_opt = (!salt.is_empty()).then_some(salt);
    let hk = Hkdf::<Sha256>::new(salt_opt, input);
    let mut out = vec![0u8; len as usize];
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|_| JsError::new("hkdf: requested length too large"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdq_hash_is_deterministic_32_bytes() {
        // Simple 64x64 RGBA gradient.
        let (w, h) = (64u32, 64u32);
        let mut img = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                img.extend_from_slice(&[x as u8, y as u8, (x ^ y) as u8, 255]);
            }
        }
        let a = pdq_hash(&img, w, h).unwrap();
        let b = pdq_hash(&img, w, h).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_derive_lengths_and_determinism() {
        let a = hkdf_derive(b"ikm", b"salt", "privex", 32).unwrap();
        let b = hkdf_derive(b"ikm", b"salt", "privex", 32).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
        assert_eq!(hkdf_derive(b"ikm", b"", "x", 64).unwrap().len(), 64);
    }
}
