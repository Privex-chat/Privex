// Stateless PoW challenge tickets (docs 8.5). The server SIGNS each challenge
// instead of storing it: issuing costs one HMAC and leaves nothing in Redis, so
// /auth/pow_challenge needs no issuance cap (a global cap let one client lock
// every user out of registration, contact adds and recovery). Only SPENT tickets
// are remembered (rds::spend_pow_ticket), and verification only writes that
// marker after the cheap SHA pre-filter passes (routes::verify_pow).
//
// Wire: "v1." || b64url(payload) || "." || b64url(HMAC-SHA256(key, DOMAIN || payload))
// The client treats it as an opaque `challenge_id`. Every PoW parameter is bound
// into the MAC at issue time, so tuning never breaks in-flight tickets.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::powcheck::ArgonParams;

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "v1.";
const DOMAIN: &[u8] = b"privex-pow-ticket-v1";
// id(16) challenge(32) difficulty(1) has_argon(1) m_cost_kib(4) t_cost(1)
// argon_difficulty(1) issued_at_ms(8) expires_at(8)
const PAYLOAD_LEN: usize = 72;

/// Hard ceiling on the Argon2id memory a ticket may request - the server only
/// ever ISSUES pow_difficulty::ARGON_M_COST_KIB (32 MiB). 64 MiB leaves headroom
/// for a future memory-cost bump (docs 8.5.1); raise in lockstep if exceeded.
const MAX_ARGON_M_COST_KIB: u32 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowTicket {
    /// Random id - the single-use key in the spent set.
    pub id: [u8; 16],
    pub challenge: [u8; 32],
    /// SHA-256 leading-zero-bit target (the pre-filter for hybrid tickets).
    pub difficulty: u32,
    /// Argon2id Layer-2 params (docs 8.5.1); None = legacy SHA-only ticket.
    pub argon: Option<ArgonParams>,
    pub issued_at_ms: u64,
    /// Unix seconds.
    pub expires_at: i64,
}

fn params_ok(difficulty: u32, argon: Option<ArgonParams>) -> bool {
    let argon_ok = match argon {
        None => true,
        // Argon2 spec minimum m is 8 KiB per lane.
        Some(a) => {
            (8..=MAX_ARGON_M_COST_KIB).contains(&a.m_cost_kib)
                && (1..=8).contains(&a.t_cost)
                && (1..=16).contains(&a.difficulty)
        }
    };
    (1..=31).contains(&difficulty) && argon_ok
}

fn tag(key: &[u8; 32], payload: &[u8]) -> HmacSha256 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(DOMAIN);
    mac.update(payload);
    mac
}

/// Sign a fresh ticket. Errors only on out-of-range parameters or RNG failure.
pub fn mint(
    key: &[u8; 32],
    challenge: [u8; 32],
    difficulty: u32,
    argon: Option<ArgonParams>,
    issued_at_ms: u64,
    expires_at: i64,
) -> anyhow::Result<String> {
    if !params_ok(difficulty, argon) {
        anyhow::bail!("invalid pow ticket params");
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| anyhow::anyhow!("rng: {e}"))?;

    let a = argon.unwrap_or(ArgonParams {
        m_cost_kib: 0,
        t_cost: 0,
        difficulty: 0,
    });
    let mut p = Vec::with_capacity(PAYLOAD_LEN);
    p.extend_from_slice(&id);
    p.extend_from_slice(&challenge);
    p.push(difficulty as u8);
    p.push(argon.is_some() as u8);
    p.extend_from_slice(&a.m_cost_kib.to_be_bytes());
    p.push(a.t_cost as u8);
    p.push(a.difficulty as u8);
    p.extend_from_slice(&issued_at_ms.to_be_bytes());
    p.extend_from_slice(&expires_at.to_be_bytes());
    debug_assert_eq!(p.len(), PAYLOAD_LEN);

    let sig = tag(key, &p).finalize().into_bytes();
    Ok(format!(
        "{PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(&p),
        URL_SAFE_NO_PAD.encode(sig)
    ))
}

/// Parse + authenticate a ticket. None on ANY malformation or a bad MAC (checked
/// in constant time). Expiry is the caller's check (it owns the clock).
pub fn open(key: &[u8; 32], ticket: &str) -> Option<PowTicket> {
    // Bound the work before decoding: a real ticket is ~143 chars.
    if ticket.len() > 256 {
        return None;
    }
    let (p_b64, t_b64) = ticket.strip_prefix(PREFIX)?.split_once('.')?;
    let p = URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let t = URL_SAFE_NO_PAD.decode(t_b64).ok()?;
    if p.len() != PAYLOAD_LEN {
        return None;
    }
    tag(key, &p).verify_slice(&t).ok()?;

    let u32_at = |i: usize| u32::from_be_bytes(p[i..i + 4].try_into().unwrap());
    let u64_at = |i: usize| u64::from_be_bytes(p[i..i + 8].try_into().unwrap());
    let difficulty = p[48] as u32;
    let argon = match p[49] {
        0 => None,
        1 => Some(ArgonParams {
            m_cost_kib: u32_at(50),
            t_cost: p[54] as u32,
            difficulty: p[55] as u32,
        }),
        _ => return None,
    };
    // Defense in depth: even a correctly-MACed ticket must carry sane params.
    if !params_ok(difficulty, argon) {
        return None;
    }
    Some(PowTicket {
        id: p[0..16].try_into().unwrap(),
        challenge: p[16..48].try_into().unwrap(),
        difficulty,
        argon,
        issued_at_ms: u64_at(56),
        expires_at: u64_at(64) as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [5u8; 32];
    const ARGON: ArgonParams = ArgonParams {
        m_cost_kib: 32 * 1024,
        t_cost: 1,
        difficulty: 2,
    };

    #[test]
    fn roundtrip_hybrid_and_legacy() {
        let t = mint(&KEY, [7u8; 32], 21, Some(ARGON), 1_000, 2_000).unwrap();
        assert!(t.len() <= 256);
        let o = open(&KEY, &t).unwrap();
        assert_eq!(o.challenge, [7u8; 32]);
        assert_eq!(o.difficulty, 21);
        assert_eq!(o.argon, Some(ARGON));
        assert_eq!((o.issued_at_ms, o.expires_at), (1_000, 2_000));

        let l = open(&KEY, &mint(&KEY, [1u8; 32], 22, None, 0, 9).unwrap()).unwrap();
        assert_eq!(l.argon, None);
        assert_eq!(l.difficulty, 22);
    }

    #[test]
    fn ids_are_unique() {
        let a = open(&KEY, &mint(&KEY, [0u8; 32], 8, None, 0, 1).unwrap()).unwrap();
        let b = open(&KEY, &mint(&KEY, [0u8; 32], 8, None, 0, 1).unwrap()).unwrap();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn rejects_forgery_tamper_and_garbage() {
        let t = mint(&KEY, [7u8; 32], 21, Some(ARGON), 1_000, 2_000).unwrap();
        // Wrong key.
        assert!(open(&[6u8; 32], &t).is_none());
        // Any payload change breaks the MAC (e.g. lowering the difficulty).
        let (p_b64, t_b64) = t.strip_prefix(PREFIX).unwrap().split_once('.').unwrap();
        let mut p = URL_SAFE_NO_PAD.decode(p_b64).unwrap();
        p[48] = 1;
        let tampered = format!("{PREFIX}{}.{t_b64}", URL_SAFE_NO_PAD.encode(&p));
        assert!(open(&KEY, &tampered).is_none());
        // Garbage / legacy UUID ids / oversize input.
        for bad in ["", "v1.", "v1.a.b", "550e8400-e29b-41d4-a716-446655440000"] {
            assert!(open(&KEY, bad).is_none(), "{bad}");
        }
        assert!(open(&KEY, &"v".repeat(300)).is_none());
    }

    #[test]
    fn refuses_out_of_range_params() {
        assert!(mint(&KEY, [0u8; 32], 0, None, 0, 1).is_err());
        assert!(mint(&KEY, [0u8; 32], 32, None, 0, 1).is_err());
        let huge = ArgonParams {
            m_cost_kib: MAX_ARGON_M_COST_KIB + 1,
            ..ARGON
        };
        assert!(mint(&KEY, [0u8; 32], 21, Some(huge), 0, 1).is_err());
    }
}
