// Key Transparency Merkle log (docs 8.2). Append-only tree over key-directory
// entries. Domain-separated hashing (0x00 leaf, 0x01 node) prevents
// second-preimage attacks. Odd nodes are promoted (RFC-6962 style, no
// duplication). The exact byte layout is mirrored in packages/crypto-wasm so
// the browser can verify inclusion independently.

use sha2::{Digest, Sha256};

/// bundle_hash = SHA-256 over ALL public bundle fields, in this fixed order.
/// Includes ik_x25519 and BOTH SPK signatures.
#[allow(clippy::too_many_arguments)]
pub fn bundle_hash(
    ik_ed25519: &[u8],
    ik_dilithium3: &[u8],
    ik_x25519: &[u8],
    spk_x25519: &[u8],
    spk_sig_ed: &[u8],
    spk_sig_dil: &[u8],
    kyber1024_pub: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        ik_ed25519,
        ik_dilithium3,
        ik_x25519,
        spk_x25519,
        spk_sig_ed,
        spk_sig_dil,
        kyber1024_pub,
    ] {
        h.update(part);
    }
    h.finalize().into()
}

/// Leaf = SHA-256(0x00 || user_id || bundle_hash || timestamp_be_u64).
pub fn leaf_hash(user_id: &str, bundle_hash: &[u8], timestamp: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(user_id.as_bytes());
    h.update(bundle_hash);
    h.update((timestamp as u64).to_be_bytes());
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Merkle root over the ordered leaves. Empty log → all-zero root.
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]); // promote odd node
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

/// One sibling on the path from a leaf to the root. `left` = sibling sits on the
/// left (so the running hash goes on the right).
#[derive(Clone, Copy)]
pub struct ProofNode {
    pub left: bool,
    pub hash: [u8; 32],
}

pub fn inclusion_proof(leaves: &[[u8; 32]], mut idx: usize) -> Vec<ProofNode> {
    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if idx % 2 == 1 {
            proof.push(ProofNode {
                left: true,
                hash: level[idx - 1],
            });
        } else if idx + 1 < level.len() {
            proof.push(ProofNode {
                left: false,
                hash: level[idx + 1],
            });
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        idx /= 2;
        level = next;
    }
    proof
}

pub fn verify_inclusion(leaf: [u8; 32], proof: &[ProofNode], root: [u8; 32]) -> bool {
    let mut h = leaf;
    for node in proof {
        h = if node.left {
            node_hash(&node.hash, &h)
        } else {
            node_hash(&h, &node.hash)
        };
    }
    h == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> [u8; 32] {
        leaf_hash(
            &format!("px_{}", "0".repeat(31) + &i.to_string()),
            &[i; 32],
            i as i64,
        )
    }

    #[test]
    fn inclusion_proof_roundtrip_and_tamper() {
        let leaves: Vec<[u8; 32]> = (0..10u8).map(leaf).collect();
        let root = compute_root(&leaves);

        // proof for entry 5 verifies
        let proof = inclusion_proof(&leaves, 5);
        assert!(verify_inclusion(leaves[5], &proof, root));

        // tampered leaf fails
        let mut bad = leaves[5];
        bad[0] ^= 0xff;
        assert!(!verify_inclusion(bad, &proof, root));

        // adding an entry changes the root → old proof no longer valid
        let mut more = leaves.clone();
        more.push(leaf(99));
        let new_root = compute_root(&more);
        assert_ne!(root, new_root);
        assert!(!verify_inclusion(leaves[5], &proof, new_root));
        // but a fresh proof against the new root verifies
        let proof2 = inclusion_proof(&more, 5);
        assert!(verify_inclusion(more[5], &proof2, new_root));
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaves = vec![leaf(1)];
        assert_eq!(compute_root(&leaves), leaves[0]);
        assert!(verify_inclusion(
            leaves[0],
            &inclusion_proof(&leaves, 0),
            leaves[0]
        ));
    }
}
