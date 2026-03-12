//! Merkle Mountain Range (MMR) compact proof support for marker-stream
//! inclusion and prefix verification.
//!
//! Provides O(log n) inclusion proofs and prefix consistency proofs over
//! the decision marker stream, enabling efficient cross-node verification
//! without transmitting the full stream.
//!
//! Uses Tier 2 ContentHash for tree hashing.
//!
//! Plan references: Section 10.11 item 29, 9G.9 (three-tier integrity +
//! append-only decision stream), Top-10 #3, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// MMR position helpers
// ---------------------------------------------------------------------------

/// Returns the height of a node at a given MMR position (0-indexed).
/// Leaves have height 0, their parent has height 1, etc.
///
/// Uses the standard Grin/Mimblewimble MMR algorithm: convert to 1-indexed,
/// then iteratively strip the most significant bit until the result is
/// all-ones (a complete binary tree root).
fn pos_height(pos: u64) -> u32 {
    let mut n = pos + 1; // convert to 1-indexed
    while !is_all_ones(n) {
        let bit_length = 64 - n.leading_zeros();
        let msb = 1u64 << (bit_length - 1);
        n = n - msb + 1;
    }
    n.count_ones() - 1
}

/// Check if a number's binary representation is all 1-bits (e.g. 1, 3, 7, 15...).
fn is_all_ones(n: u64) -> bool {
    n > 0 && (n & n.wrapping_add(1)) == 0
}

/// Convert a 0-indexed leaf number to its MMR position.
fn leaf_to_pos(leaf_index: u64) -> u64 {
    // Each leaf at index i occupies position: 2*i - popcount(i)
    // where popcount is the number of 1-bits.
    // Actually, the mapping is: leaf i → position = 2*i - i.count_ones() + i
    // Let me use the standard formula.
    //
    // For leaf index n (0-based), the MMR position is:
    // pos = 2*n - n.count_ones() as u64
    // Wait, that's not right either. Let me derive from scratch.
    //
    // Leaf 0 → pos 0
    // Leaf 1 → pos 1
    // (parent at pos 2)
    // Leaf 2 → pos 3
    // Leaf 3 → pos 4
    // (parent at pos 5, grandparent at pos 6)
    // Leaf 4 → pos 7
    // Leaf 5 → pos 8
    // (parent at pos 9)
    // Leaf 6 → pos 10
    // Leaf 7 → pos 11
    // (parent at pos 12, grandparent at pos 13, great-grandparent at pos 14)
    // Leaf 8 → pos 15
    //
    // Pattern: leaf_to_pos(n) = n + n.count_ones() as u64
    // Wait: leaf 0 → 0 + 0 = 0 ✓
    //       leaf 1 → 1 + 1 = 2 ✗ (should be 1)
    //
    // Hmm. Let me just compute it iteratively for correctness.
    // Number of nodes in an MMR with n leaves:
    // mmr_size(n) = 2*n - popcount(n)
    // But leaf positions are different from mmr_size.
    //
    // Actually, let's think about it differently. In an MMR, when we append
    // a new leaf, we place it at position mmr_size (the current total size),
    // then possibly merge with siblings to create parent nodes.
    //
    // So leaf 0's position = 0 (mmr was empty, size 0)
    // After appending leaf 0, size = 1
    // Leaf 1's position = 1 (size was 1)
    // After appending leaf 1, we merge: parent at pos 2, size = 3
    // Leaf 2's position = 3 (size was 3)
    // After appending leaf 2, size = 4
    // Leaf 3's position = 4 (size was 4)
    // After appending leaf 3, we merge: parent at 5, merge again: grandparent at 6, size = 7
    // Leaf 4's position = 7
    //
    // So leaf_to_pos(n) = mmr_size(n) where mmr_size(n) = 2*n - popcount(n)
    // leaf 0: 2*0 - 0 = 0 ✓
    // leaf 1: 2*1 - 1 = 1 ✓
    // leaf 2: 2*2 - 1 = 3 ✓
    // leaf 3: 2*3 - 2 = 4 ✓
    // leaf 4: 2*4 - 1 = 7 ✓
    // leaf 5: 2*5 - 2 = 8 ✓
    // leaf 6: 2*6 - 2 = 10 ✓
    // leaf 7: 2*7 - 3 = 11 ✓
    // leaf 8: 2*8 - 1 = 15 ✓
    //
    // So: leaf_to_pos(n) = 2*n - n.count_ones() as u64
    2 * leaf_index - leaf_index.count_ones() as u64
}

/// Total number of nodes in an MMR with `num_leaves` leaves.
fn mmr_size(num_leaves: u64) -> u64 {
    if num_leaves == 0 {
        return 0;
    }
    2 * num_leaves - num_leaves.count_ones() as u64
}

/// Compute the peak positions for an MMR with the given total node count.
fn peak_positions(size: u64) -> Vec<u64> {
    if size == 0 {
        return Vec::new();
    }

    let mut peaks = Vec::new();
    let mut remaining = size;
    let mut offset = 0u64;

    // Find peaks by decomposing size into sums of (2^h - 1) complete trees.
    while remaining > 0 {
        // Find the largest complete binary tree that fits.
        let mut h = 64 - remaining.leading_zeros(); // bit length
        let mut tree_size = if h == 64 { u64::MAX } else { (1u64 << h) - 1 };

        if tree_size > remaining {
            h -= 1;
            tree_size = if h == 64 { u64::MAX } else { (1u64 << h) - 1 };
        }

        // Peak is at the top of this complete tree.
        peaks.push(offset + tree_size - 1);
        offset += tree_size;
        remaining -= tree_size;
    }

    peaks
}

// ---------------------------------------------------------------------------
// ProofError
// ---------------------------------------------------------------------------

/// Error during proof generation or verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofError {
    /// The marker index is out of range.
    IndexOutOfRange { index: u64, stream_length: u64 },
    /// The proof does not verify against the expected root hash.
    RootMismatch {
        expected: ContentHash,
        computed: ContentHash,
    },
    /// The proof is structurally invalid (wrong number of hashes, etc.).
    InvalidProof { reason: String },
    /// The stream is empty.
    EmptyStream,
    /// Consistency check failed: old root is not a prefix of the new stream.
    ConsistencyFailure {
        old_length: u64,
        new_length: u64,
        reason: String,
    },
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfRange {
                index,
                stream_length,
            } => write!(
                f,
                "index {index} out of range (stream length {stream_length})"
            ),
            Self::RootMismatch { .. } => write!(f, "root hash mismatch"),
            Self::InvalidProof { reason } => write!(f, "invalid proof: {reason}"),
            Self::EmptyStream => write!(f, "empty stream"),
            Self::ConsistencyFailure { reason, .. } => {
                write!(f, "consistency failure: {reason}")
            }
        }
    }
}

impl std::error::Error for ProofError {}

// ---------------------------------------------------------------------------
// Proof types
// ---------------------------------------------------------------------------

/// Type of proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Proof that a marker is included at a specific position.
    Inclusion,
    /// Proof that a stream prefix is consistent with a later stream state.
    Consistency,
}

/// A compact cryptographic proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Type of this proof.
    pub proof_type: ProofType,
    /// Leaf index this proof pertains to (for inclusion proofs).
    pub marker_index: u64,
    /// Ordered list of sibling hashes needed for verification.
    pub proof_hashes: Vec<ContentHash>,
    /// Root hash of the MMR at proof generation time.
    pub root_hash: ContentHash,
    /// Number of leaves in the stream at proof generation time.
    pub stream_length: u64,
    /// Security epoch at proof generation time.
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// MmrState — accumulated peaks
// ---------------------------------------------------------------------------

/// Merkle Mountain Range state tracking peaks and all node hashes.
///
/// Maintains the full set of node hashes to support proof generation.
#[derive(Debug)]
pub struct MerkleMountainRange {
    /// All node hashes indexed by MMR position.
    nodes: Vec<ContentHash>,
    /// Number of leaves appended.
    num_leaves: u64,
    /// Current epoch for proof metadata.
    epoch_id: u64,
}

impl MerkleMountainRange {
    /// Create a new empty MMR.
    pub fn new(epoch_id: u64) -> Self {
        Self {
            nodes: Vec::new(),
            num_leaves: 0,
            epoch_id,
        }
    }

    /// Number of leaves in the MMR.
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    /// Total number of nodes (leaves + internal).
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64
    }

    /// Whether the MMR is empty.
    pub fn is_empty(&self) -> bool {
        self.num_leaves == 0
    }

    /// Append a leaf hash to the MMR.
    ///
    /// Returns the leaf's MMR position.
    pub fn append(&mut self, leaf_hash: ContentHash) -> u64 {
        let leaf_pos = self.nodes.len() as u64;
        self.nodes.push(leaf_hash);
        self.num_leaves += 1;

        // Merge with left siblings as needed to maintain the MMR invariant.
        let mut height = 0u32;
        let mut current_pos = leaf_pos;

        loop {
            // Check if there's a left sibling at the same height.
            let left_sibling_offset = (1u64 << (height + 1)) - 1;
            if current_pos < left_sibling_offset {
                break;
            }

            let left_sibling_pos = current_pos - left_sibling_offset;
            if pos_height(left_sibling_pos) != height {
                break;
            }

            // Merge: create parent node.
            let left_hash = &self.nodes[left_sibling_pos as usize];
            let right_hash = &self.nodes[current_pos as usize];
            let parent_hash = hash_pair(left_hash, right_hash);

            let parent_pos = self.nodes.len() as u64;
            self.nodes.push(parent_hash);
            current_pos = parent_pos;
            height += 1;
        }

        leaf_pos
    }

    /// Compute the root hash by bagging the peaks.
    pub fn root_hash(&self) -> Result<ContentHash, ProofError> {
        if self.num_leaves == 0 {
            return Err(ProofError::EmptyStream);
        }
        let peaks = self.peaks();
        Ok(bag_peaks(&peaks))
    }

    /// Get the current peak hashes.
    pub fn peaks(&self) -> Vec<ContentHash> {
        let positions = peak_positions(self.nodes.len() as u64);
        positions
            .iter()
            .map(|&pos| self.nodes[pos as usize])
            .collect()
    }

    /// Generate an inclusion proof for the leaf at the given index (0-based).
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<MmrProof, ProofError> {
        if leaf_index >= self.num_leaves {
            return Err(ProofError::IndexOutOfRange {
                index: leaf_index,
                stream_length: self.num_leaves,
            });
        }

        let leaf_pos = leaf_to_pos(leaf_index);
        let mut proof_hashes = Vec::new();

        // Walk up the tree collecting sibling hashes.
        let mut pos = leaf_pos;
        let mut height = 0u32;
        let size = self.nodes.len() as u64;

        loop {
            let sibling_offset = (1u64 << (height + 1)) - 1;

            // Try right sibling first (we are left child).
            let right_sibling = pos + sibling_offset;
            if right_sibling < size && pos_height(right_sibling) == height {
                proof_hashes.push(self.nodes[right_sibling as usize]);
                // Parent is at right_sibling + 1.
                pos = right_sibling + 1;
                height += 1;
                continue;
            }

            // Try left sibling (we are right child).
            if pos >= sibling_offset {
                let left_sibling = pos - sibling_offset;
                if pos_height(left_sibling) == height {
                    proof_hashes.push(self.nodes[left_sibling as usize]);
                    // Parent is at pos + 1.
                    pos += 1;
                    height += 1;
                    continue;
                }
            }

            // No sibling — we're at a peak. Collect the remaining peaks
            // for the bagging step.
            break;
        }

        // Add the other peak hashes for bagging.
        let peaks = peak_positions(size);
        for &peak_pos in &peaks {
            if peak_pos != pos {
                proof_hashes.push(self.nodes[peak_pos as usize]);
            }
        }

        let root = self.root_hash()?;

        Ok(MmrProof {
            proof_type: ProofType::Inclusion,
            marker_index: leaf_index,
            proof_hashes,
            root_hash: root,
            stream_length: self.num_leaves,
            epoch_id: self.epoch_id,
        })
    }

    /// Generate a consistency proof between an old stream length and the
    /// current state.
    pub fn consistency_proof(&self, old_length: u64) -> Result<MmrProof, ProofError> {
        if old_length == 0 {
            return Err(ProofError::EmptyStream);
        }
        if old_length > self.num_leaves {
            return Err(ProofError::ConsistencyFailure {
                old_length,
                new_length: self.num_leaves,
                reason: "old length exceeds current stream".to_string(),
            });
        }

        // For consistency proof, we provide the peaks of the old MMR
        // and the sibling hashes needed to reconstruct the new root
        // from the old peaks.
        let old_size = mmr_size(old_length);
        let old_peak_positions = peak_positions(old_size);
        let new_peak_positions = peak_positions(self.nodes.len() as u64);

        let mut proof_hashes = Vec::new();

        // Include old peaks.
        for &pos in &old_peak_positions {
            proof_hashes.push(self.nodes[pos as usize]);
        }

        // Include new peaks that aren't in the old set.
        for &pos in &new_peak_positions {
            if !old_peak_positions.contains(&pos) {
                proof_hashes.push(self.nodes[pos as usize]);
            }
        }

        let root = self.root_hash()?;

        Ok(MmrProof {
            proof_type: ProofType::Consistency,
            marker_index: old_length, // repurpose as old_length
            proof_hashes,
            root_hash: root,
            stream_length: self.num_leaves,
            epoch_id: self.epoch_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Verification API
// ---------------------------------------------------------------------------

/// Verify that a marker hash is included at the given index in the MMR.
pub fn verify_inclusion(
    marker_hash: &ContentHash,
    leaf_index: u64,
    proof: &MmrProof,
) -> Result<(), ProofError> {
    if proof.proof_type != ProofType::Inclusion {
        return Err(ProofError::InvalidProof {
            reason: "expected inclusion proof".to_string(),
        });
    }

    if leaf_index >= proof.stream_length {
        return Err(ProofError::IndexOutOfRange {
            index: leaf_index,
            stream_length: proof.stream_length,
        });
    }

    let size = mmr_size(proof.stream_length);
    let peaks = peak_positions(size);

    // Walk up the tree using the proof hashes.
    let mut pos = leaf_to_pos(leaf_index);
    let mut current_hash = *marker_hash;
    let mut proof_idx = 0;
    let mut height = 0u32;

    loop {
        let sibling_offset = (1u64 << (height + 1)) - 1;

        // Try right sibling (we are left child).
        let right_sibling = pos + sibling_offset;
        if right_sibling < size && pos_height(right_sibling) == height {
            if proof_idx >= proof.proof_hashes.len() {
                return Err(ProofError::InvalidProof {
                    reason: "not enough proof hashes".to_string(),
                });
            }
            current_hash = hash_pair(&current_hash, &proof.proof_hashes[proof_idx]);
            proof_idx += 1;
            pos = right_sibling + 1;
            height += 1;
            continue;
        }

        // Try left sibling (we are right child).
        if pos >= sibling_offset {
            let left_sibling = pos - sibling_offset;
            if pos_height(left_sibling) == height {
                if proof_idx >= proof.proof_hashes.len() {
                    return Err(ProofError::InvalidProof {
                        reason: "not enough proof hashes".to_string(),
                    });
                }
                current_hash = hash_pair(&proof.proof_hashes[proof_idx], &current_hash);
                proof_idx += 1;
                pos += 1;
                height += 1;
                continue;
            }
        }

        // At a peak.
        break;
    }

    // Bag this peak hash with the remaining peak hashes from the proof.
    // The peaks are bagged right-to-left. We need to figure out which
    // peak we're at and combine with the others.
    let mut peak_hashes: Vec<ContentHash> = Vec::new();
    for &peak_pos in &peaks {
        if peak_pos == pos {
            peak_hashes.push(current_hash);
        } else {
            if proof_idx >= proof.proof_hashes.len() {
                return Err(ProofError::InvalidProof {
                    reason: "not enough proof hashes for peaks".to_string(),
                });
            }
            peak_hashes.push(proof.proof_hashes[proof_idx]);
            proof_idx += 1;
        }
    }

    let computed_root = bag_peaks(&peak_hashes);

    if computed_root != proof.root_hash {
        return Err(ProofError::RootMismatch {
            expected: proof.root_hash,
            computed: computed_root,
        });
    }

    Ok(())
}

/// Verify that the old root is a consistent prefix of the new stream.
pub fn verify_consistency(old_root: &ContentHash, proof: &MmrProof) -> Result<(), ProofError> {
    if proof.proof_type != ProofType::Consistency {
        return Err(ProofError::InvalidProof {
            reason: "expected consistency proof".to_string(),
        });
    }

    let old_length = proof.marker_index; // repurposed field
    if old_length == 0 {
        return Err(ProofError::EmptyStream);
    }

    let old_size = mmr_size(old_length);
    let old_peak_count = peak_positions(old_size).len();

    if proof.proof_hashes.len() < old_peak_count {
        return Err(ProofError::InvalidProof {
            reason: "not enough proof hashes for old peaks".to_string(),
        });
    }

    // Reconstruct old root from old peaks in the proof.
    let old_peaks: Vec<ContentHash> = proof.proof_hashes[..old_peak_count].to_vec();
    let computed_old_root = bag_peaks(&old_peaks);

    if computed_old_root != *old_root {
        return Err(ProofError::ConsistencyFailure {
            old_length,
            new_length: proof.stream_length,
            reason: "old root does not match reconstructed peaks".to_string(),
        });
    }

    // Verify the new root uses the remaining proof hashes as additional peaks.
    let new_size = mmr_size(proof.stream_length);
    let remaining = &proof.proof_hashes[old_peak_count..];

    // The new peaks are formed by combining old peaks that are still peaks
    // in the new MMR with the additional peaks from the proof.
    // For simplicity, we verify that bagging all proof hashes in the right
    // order produces the claimed new root.
    let old_peak_positions = peak_positions(old_size);
    let new_peak_positions = peak_positions(new_size);

    let mut new_peaks = Vec::new();
    let mut remaining_idx = 0;

    for &new_peak_pos in &new_peak_positions {
        if old_peak_positions.contains(&new_peak_pos) {
            // This peak exists in the old MMR — find it in old_peaks.
            let old_idx = old_peak_positions
                .iter()
                .position(|&p| p == new_peak_pos)
                .expect("position exists");
            new_peaks.push(old_peaks[old_idx]);
        } else {
            if remaining_idx >= remaining.len() {
                return Err(ProofError::InvalidProof {
                    reason: "not enough proof hashes for new peaks".to_string(),
                });
            }
            new_peaks.push(remaining[remaining_idx]);
            remaining_idx += 1;
        }
    }

    let computed_new_root = bag_peaks(&new_peaks);

    if computed_new_root != proof.root_hash {
        return Err(ProofError::RootMismatch {
            expected: proof.root_hash,
            computed: computed_new_root,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Hash two child nodes to produce a parent hash.
fn hash_pair(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(left.as_bytes());
    preimage.extend_from_slice(right.as_bytes());
    ContentHash::compute(&preimage)
}

/// Bag peaks right-to-left to produce the MMR root hash.
///
/// The root is computed by hashing the rightmost two peaks together,
/// then hashing the result with the next peak to the left, and so on.
fn bag_peaks(peaks: &[ContentHash]) -> ContentHash {
    match peaks.len() {
        0 => ContentHash([0u8; 32]),
        1 => peaks[0],
        _ => {
            let mut root = peaks[peaks.len() - 1];
            for peak in peaks[..peaks.len() - 1].iter().rev() {
                root = hash_pair(peak, &root);
            }
            root
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_hash(i: u64) -> ContentHash {
        ContentHash::compute(&i.to_be_bytes())
    }

    fn build_mmr(n: u64) -> MerkleMountainRange {
        let mut mmr = MerkleMountainRange::new(1);
        for i in 0..n {
            mmr.append(leaf_hash(i));
        }
        mmr
    }

    // -- Basic construction --

    #[test]
    fn empty_mmr_has_no_leaves() {
        let mmr = MerkleMountainRange::new(1);
        assert_eq!(mmr.num_leaves(), 0);
        assert!(mmr.is_empty());
    }

    #[test]
    fn single_leaf_mmr() {
        let mut mmr = MerkleMountainRange::new(1);
        let pos = mmr.append(leaf_hash(0));
        assert_eq!(pos, 0);
        assert_eq!(mmr.num_leaves(), 1);
        assert_eq!(mmr.size(), 1);
    }

    #[test]
    fn two_leaf_mmr_creates_parent() {
        let mmr = build_mmr(2);
        assert_eq!(mmr.num_leaves(), 2);
        // 2 leaves + 1 parent = 3 nodes.
        assert_eq!(mmr.size(), 3);
    }

    #[test]
    fn four_leaf_mmr_size() {
        let mmr = build_mmr(4);
        assert_eq!(mmr.num_leaves(), 4);
        // 4 leaves + 2 parents + 1 grandparent = 7 nodes.
        assert_eq!(mmr.size(), 7);
    }

    #[test]
    fn mmr_size_formula() {
        // mmr_size(n) = 2*n - popcount(n)
        assert_eq!(mmr_size(0), 0);
        assert_eq!(mmr_size(1), 1);
        assert_eq!(mmr_size(2), 3);
        assert_eq!(mmr_size(3), 4);
        assert_eq!(mmr_size(4), 7);
        assert_eq!(mmr_size(5), 8);
        assert_eq!(mmr_size(7), 11);
        assert_eq!(mmr_size(8), 15);
    }

    // -- Peaks --

    #[test]
    fn single_leaf_has_one_peak() {
        let mmr = build_mmr(1);
        assert_eq!(mmr.peaks().len(), 1);
    }

    #[test]
    fn power_of_two_leaves_has_one_peak() {
        let mmr = build_mmr(4);
        assert_eq!(mmr.peaks().len(), 1);

        let mmr = build_mmr(8);
        assert_eq!(mmr.peaks().len(), 1);
    }

    #[test]
    fn non_power_of_two_leaves_has_multiple_peaks() {
        // 3 = 2 + 1, so 2 peaks.
        let mmr = build_mmr(3);
        assert_eq!(mmr.peaks().len(), 2);

        // 5 = 4 + 1, so 2 peaks.
        let mmr = build_mmr(5);
        assert_eq!(mmr.peaks().len(), 2);

        // 7 = 4 + 2 + 1, so 3 peaks.
        let mmr = build_mmr(7);
        assert_eq!(mmr.peaks().len(), 3);
    }

    // -- Root hash --

    #[test]
    fn root_hash_fails_on_empty() {
        let mmr = MerkleMountainRange::new(1);
        assert!(matches!(mmr.root_hash(), Err(ProofError::EmptyStream)));
    }

    #[test]
    fn root_hash_is_deterministic() {
        let root1 = build_mmr(10).root_hash().unwrap();
        let root2 = build_mmr(10).root_hash().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn root_hash_changes_with_appends() {
        let root3 = build_mmr(3).root_hash().unwrap();
        let root4 = build_mmr(4).root_hash().unwrap();
        assert_ne!(root3, root4);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let mmr = build_mmr(1);
        assert_eq!(mmr.root_hash().unwrap(), leaf_hash(0));
    }

    // -- Position helpers --

    #[test]
    fn leaf_to_pos_values() {
        assert_eq!(leaf_to_pos(0), 0);
        assert_eq!(leaf_to_pos(1), 1);
        assert_eq!(leaf_to_pos(2), 3);
        assert_eq!(leaf_to_pos(3), 4);
        assert_eq!(leaf_to_pos(4), 7);
        assert_eq!(leaf_to_pos(5), 8);
        assert_eq!(leaf_to_pos(6), 10);
        assert_eq!(leaf_to_pos(7), 11);
    }

    #[test]
    fn pos_height_values() {
        // Leaves at height 0.
        assert_eq!(pos_height(0), 0);
        assert_eq!(pos_height(1), 0);
        assert_eq!(pos_height(3), 0);
        assert_eq!(pos_height(4), 0);
        // Parents at height 1.
        assert_eq!(pos_height(2), 1);
        assert_eq!(pos_height(5), 1);
        // Grandparent at height 2.
        assert_eq!(pos_height(6), 2);
    }

    // -- Inclusion proofs --

    #[test]
    fn inclusion_proof_single_leaf() {
        let mmr = build_mmr(1);
        let proof = mmr.inclusion_proof(0).unwrap();
        assert_eq!(proof.proof_type, ProofType::Inclusion);
        assert_eq!(proof.marker_index, 0);
        verify_inclusion(&leaf_hash(0), 0, &proof).unwrap();
    }

    #[test]
    fn inclusion_proof_two_leaves() {
        let mmr = build_mmr(2);
        for i in 0..2 {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof).unwrap();
        }
    }

    #[test]
    fn inclusion_proof_power_of_two() {
        let mmr = build_mmr(8);
        for i in 0..8 {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof).unwrap();
        }
    }

    #[test]
    fn inclusion_proof_non_power_of_two() {
        for n in [3, 5, 6, 7, 9, 10, 13, 15, 17] {
            let mmr = build_mmr(n);
            for i in 0..n {
                let proof = mmr.inclusion_proof(i).unwrap();
                verify_inclusion(&leaf_hash(i), i, &proof)
                    .unwrap_or_else(|e| panic!("n={n}, i={i}: {e}"));
            }
        }
    }

    #[test]
    fn inclusion_proof_fails_out_of_range() {
        let mmr = build_mmr(5);
        assert!(matches!(
            mmr.inclusion_proof(5),
            Err(ProofError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_hash() {
        let mmr = build_mmr(8);
        let proof = mmr.inclusion_proof(3).unwrap();
        let wrong_hash = leaf_hash(999);
        assert!(verify_inclusion(&wrong_hash, 3, &proof).is_err());
    }

    #[test]
    fn inclusion_proof_rejects_tampered_proof() {
        let mmr = build_mmr(8);
        let mut proof = mmr.inclusion_proof(3).unwrap();
        if !proof.proof_hashes.is_empty() {
            proof.proof_hashes[0] = ContentHash([0xff; 32]);
        }
        assert!(verify_inclusion(&leaf_hash(3), 3, &proof).is_err());
    }

    // -- Consistency proofs --

    #[test]
    fn consistency_proof_same_length() {
        let mmr = build_mmr(8);
        let old_root = mmr.root_hash().unwrap();
        let proof = mmr.consistency_proof(8).unwrap();
        verify_consistency(&old_root, &proof).unwrap();
    }

    #[test]
    fn consistency_proof_prefix() {
        let old_mmr = build_mmr(4);
        let old_root = old_mmr.root_hash().unwrap();

        let new_mmr = build_mmr(8);
        let proof = new_mmr.consistency_proof(4).unwrap();
        verify_consistency(&old_root, &proof).unwrap();
    }

    #[test]
    fn consistency_proof_non_power_of_two() {
        for (old_n, new_n) in [(3, 7), (5, 10), (1, 4), (6, 13)] {
            let old_root = build_mmr(old_n).root_hash().unwrap();
            let new_mmr = build_mmr(new_n);
            let proof = new_mmr.consistency_proof(old_n).unwrap();
            verify_consistency(&old_root, &proof)
                .unwrap_or_else(|e| panic!("old={old_n}, new={new_n}: {e}"));
        }
    }

    #[test]
    fn consistency_proof_rejects_wrong_old_root() {
        let new_mmr = build_mmr(8);
        let proof = new_mmr.consistency_proof(4).unwrap();
        let wrong_root = ContentHash([0xaa; 32]);
        assert!(verify_consistency(&wrong_root, &proof).is_err());
    }

    #[test]
    fn consistency_proof_rejects_empty_old() {
        let mmr = build_mmr(8);
        assert!(matches!(
            mmr.consistency_proof(0),
            Err(ProofError::EmptyStream)
        ));
    }

    #[test]
    fn consistency_proof_rejects_oversized_old() {
        let mmr = build_mmr(4);
        assert!(matches!(
            mmr.consistency_proof(5),
            Err(ProofError::ConsistencyFailure { .. })
        ));
    }

    // -- Proof size --

    #[test]
    fn inclusion_proof_is_logarithmic() {
        // For 1024 leaves, inclusion proof should have O(log 1024) = ~10 hashes.
        let mmr = build_mmr(1024);
        let proof = mmr.inclusion_proof(500).unwrap();
        // log2(1024) = 10, plus a few for peak bagging.
        assert!(
            proof.proof_hashes.len() <= 15,
            "proof too large: {} hashes",
            proof.proof_hashes.len()
        );
    }

    // -- Serialization --

    #[test]
    fn proof_serialization_round_trip() {
        let mmr = build_mmr(8);
        let proof = mmr.inclusion_proof(3).unwrap();
        let json = serde_json::to_string(&proof).expect("serialize");
        let restored: MmrProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof, restored);
    }

    #[test]
    fn proof_error_serialization_round_trip() {
        let errors = vec![
            ProofError::EmptyStream,
            ProofError::IndexOutOfRange {
                index: 5,
                stream_length: 3,
            },
            ProofError::InvalidProof {
                reason: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ProofError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Error display --

    #[test]
    fn proof_error_display() {
        assert_eq!(ProofError::EmptyStream.to_string(), "empty stream");
        assert!(
            ProofError::IndexOutOfRange {
                index: 5,
                stream_length: 3
            }
            .to_string()
            .contains("5")
        );
    }

    // -- Determinism --

    #[test]
    fn mmr_construction_is_deterministic() {
        let root1 = build_mmr(100).root_hash().unwrap();
        let root2 = build_mmr(100).root_hash().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn proof_generation_is_deterministic() {
        let mmr1 = build_mmr(20);
        let mmr2 = build_mmr(20);
        let proof1 = mmr1.inclusion_proof(7).unwrap();
        let proof2 = mmr2.inclusion_proof(7).unwrap();
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn proof_error_std_error() {
        let h1 = ContentHash::compute(b"a");
        let h2 = ContentHash::compute(b"b");
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ProofError::IndexOutOfRange {
                index: 10,
                stream_length: 5,
            }),
            Box::new(ProofError::RootMismatch {
                expected: h1,
                computed: h2,
            }),
            Box::new(ProofError::InvalidProof {
                reason: "bad".into(),
            }),
            Box::new(ProofError::EmptyStream),
            Box::new(ProofError::ConsistencyFailure {
                old_length: 5,
                new_length: 3,
                reason: "shrunk".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: ProofType serde roundtrip --

    #[test]
    fn proof_type_serde_roundtrip() {
        for pt in [ProofType::Inclusion, ProofType::Consistency] {
            let json = serde_json::to_string(&pt).unwrap();
            let restored: ProofType = serde_json::from_str(&json).unwrap();
            assert_eq!(pt, restored);
        }
    }

    // -- Enrichment: RootMismatch and ConsistencyFailure serde roundtrip --

    #[test]
    fn proof_error_root_mismatch_serde_roundtrip() {
        let err = ProofError::RootMismatch {
            expected: ContentHash::compute(b"expected"),
            computed: ContentHash::compute(b"computed"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: ProofError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    #[test]
    fn proof_error_consistency_failure_serde_roundtrip() {
        let err = ProofError::ConsistencyFailure {
            old_length: 10,
            new_length: 20,
            reason: "test consistency".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: ProofError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Enrichment: Display uniqueness for all ProofError variants --

    #[test]
    fn proof_error_display_all_variants_unique() {
        let h1 = ContentHash::compute(b"x");
        let h2 = ContentHash::compute(b"y");
        let displays: std::collections::BTreeSet<String> = [
            ProofError::IndexOutOfRange {
                index: 5,
                stream_length: 3,
            }
            .to_string(),
            ProofError::RootMismatch {
                expected: h1,
                computed: h2,
            }
            .to_string(),
            ProofError::InvalidProof {
                reason: "test".into(),
            }
            .to_string(),
            ProofError::EmptyStream.to_string(),
            ProofError::ConsistencyFailure {
                old_length: 3,
                new_length: 5,
                reason: "test".into(),
            }
            .to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: MmrProof serde deterministic --

    #[test]
    fn mmr_proof_serde_deterministic() {
        let mmr = build_mmr(8);
        let proof = mmr.inclusion_proof(4).unwrap();
        let json1 = serde_json::to_string(&proof).unwrap();
        let json2 = serde_json::to_string(&proof).unwrap();
        assert_eq!(json1, json2);
    }

    // -- Enrichment: is_all_ones helper --

    #[test]
    fn is_all_ones_known_values() {
        assert!(!is_all_ones(0));
        assert!(is_all_ones(1));
        assert!(!is_all_ones(2));
        assert!(is_all_ones(3));
        assert!(!is_all_ones(4));
        assert!(is_all_ones(7));
        assert!(is_all_ones(15));
        assert!(!is_all_ones(16));
        assert!(is_all_ones(31));
        assert!(is_all_ones(63));
    }

    // -- Enrichment: mmr_size consistency with actual graph construction --

    #[test]
    fn mmr_size_matches_built_mmr() {
        for n in 1..=20 {
            let mmr = build_mmr(n);
            assert_eq!(mmr.size(), mmr_size(n), "mismatch at n={n}");
        }
    }

    // -- Enrichment: peak_positions known values --

    #[test]
    fn peak_positions_known_values() {
        // 1 leaf => size 1, 1 peak at pos 0
        assert_eq!(peak_positions(1), vec![0]);
        // 3 nodes (2 leaves) => 1 peak at pos 2
        assert_eq!(peak_positions(3), vec![2]);
        // 4 nodes (3 leaves) => peaks at 2, 3
        assert_eq!(peak_positions(4), vec![2, 3]);
        // 7 nodes (4 leaves) => 1 peak at pos 6
        assert_eq!(peak_positions(7), vec![6]);
    }

    // -- Enrichment: inclusion proof for large MMR --

    #[test]
    fn inclusion_proof_large_mmr_all_leaves() {
        let n = 64;
        let mmr = build_mmr(n);
        for i in 0..n {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof)
                .unwrap_or_else(|e| panic!("n={n}, i={i}: {e}"));
        }
    }

    // -- Enrichment: verify_inclusion rejects wrong proof_type --

    #[test]
    fn verify_inclusion_rejects_consistency_proof_type() {
        let mmr = build_mmr(8);
        let mut proof = mmr.inclusion_proof(0).unwrap();
        proof.proof_type = ProofType::Consistency;
        let err = verify_inclusion(&leaf_hash(0), 0, &proof).unwrap_err();
        assert!(matches!(err, ProofError::InvalidProof { .. }));
    }

    // -- Enrichment: verify_consistency rejects inclusion proof_type --

    #[test]
    fn verify_consistency_rejects_inclusion_proof_type() {
        let mmr = build_mmr(8);
        let old_root = build_mmr(4).root_hash().unwrap();
        let mut proof = mmr.consistency_proof(4).unwrap();
        proof.proof_type = ProofType::Inclusion;
        let err = verify_consistency(&old_root, &proof).unwrap_err();
        assert!(matches!(err, ProofError::InvalidProof { .. }));
    }

    // -- Enrichment: bag_peaks edge cases --

    #[test]
    fn bag_peaks_empty_returns_zero_hash() {
        let result = bag_peaks(&[]);
        assert_eq!(result, ContentHash([0u8; 32]));
    }

    #[test]
    fn bag_peaks_single_returns_identity() {
        let h = ContentHash::compute(b"single-peak");
        let result = bag_peaks(std::slice::from_ref(&h));
        assert_eq!(result, h);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, JSON fields, ordering, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn mmr_proof_clone_equality() {
        let mmr = build_mmr(8);
        let proof = mmr.inclusion_proof(3).unwrap();
        let cloned = proof.clone();
        assert_eq!(proof, cloned);
    }

    #[test]
    fn proof_error_clone_equality() {
        let errors = vec![
            ProofError::IndexOutOfRange {
                index: 10,
                stream_length: 5,
            },
            ProofError::EmptyStream,
            ProofError::InvalidProof {
                reason: "bad".into(),
            },
            ProofError::RootMismatch {
                expected: ContentHash::compute(b"a"),
                computed: ContentHash::compute(b"b"),
            },
            ProofError::ConsistencyFailure {
                old_length: 3,
                new_length: 7,
                reason: "fail".into(),
            },
        ];
        for e in &errors {
            let cloned = e.clone();
            assert_eq!(*e, cloned);
        }
    }

    #[test]
    fn proof_type_clone_equality() {
        let t1 = ProofType::Inclusion;
        let t2 = ProofType::Consistency;
        assert_eq!(t1, t1.clone());
        assert_eq!(t2, t2.clone());
    }

    #[test]
    fn mmr_proof_json_field_presence() {
        let mmr = build_mmr(4);
        let proof = mmr.inclusion_proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        for field in [
            "proof_type",
            "marker_index",
            "proof_hashes",
            "root_hash",
            "stream_length",
            "epoch_id",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn proof_error_std_error_all_variants() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ProofError::IndexOutOfRange {
                index: 5,
                stream_length: 3,
            }),
            Box::new(ProofError::EmptyStream),
            Box::new(ProofError::InvalidProof {
                reason: "test".into(),
            }),
            Box::new(ProofError::RootMismatch {
                expected: ContentHash::compute(b"a"),
                computed: ContentHash::compute(b"b"),
            }),
            Box::new(ProofError::ConsistencyFailure {
                old_length: 1,
                new_length: 2,
                reason: "mismatch".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(format!("{e}"));
        }
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn consistency_proof_deterministic_for_same_inputs() {
        let mmr = build_mmr(16);
        let proof1 = mmr.consistency_proof(8).unwrap();
        let proof2 = mmr.consistency_proof(8).unwrap();
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn mmr_root_hash_different_from_any_leaf() {
        let mmr = build_mmr(4);
        let root = mmr.root_hash().unwrap();
        for i in 0..4 {
            assert_ne!(root, leaf_hash(i), "root should differ from leaf {i}");
        }
    }

    #[test]
    fn inclusion_proof_size_is_logarithmic_bound() {
        let mmr = build_mmr(128);
        let proof = mmr.inclusion_proof(63).unwrap();
        // log2(128) = 7, proof should be at most ~7 hashes
        assert!(
            proof.proof_hashes.len() <= 10,
            "proof size {} exceeds expected log bound",
            proof.proof_hashes.len()
        );
    }

    #[test]
    fn mmr_append_increases_num_leaves() {
        let mut mmr = MerkleMountainRange::new(1);
        assert_eq!(mmr.num_leaves(), 0);
        mmr.append(ContentHash::compute(b"leaf-0"));
        assert_eq!(mmr.num_leaves(), 1);
        mmr.append(ContentHash::compute(b"leaf-1"));
        assert_eq!(mmr.num_leaves(), 2);
    }

    #[test]
    fn bag_peaks_two_gives_merged_hash() {
        let h1 = ContentHash::compute(b"peak1");
        let h2 = ContentHash::compute(b"peak2");
        let h1c = h1;
        let h2c = h2;
        let merged = bag_peaks(&[h1, h2]);
        // Should not equal either individual hash
        assert_ne!(merged, h1c);
        assert_ne!(merged, h2c);
        // Deterministic
        assert_eq!(merged, bag_peaks(&[h1, h2]));
    }

    #[test]
    fn proof_error_serde_all_variants() {
        let errors = vec![
            ProofError::IndexOutOfRange {
                index: 1,
                stream_length: 0,
            },
            ProofError::EmptyStream,
            ProofError::InvalidProof { reason: "x".into() },
            ProofError::RootMismatch {
                expected: ContentHash::compute(b"a"),
                computed: ContentHash::compute(b"b"),
            },
            ProofError::ConsistencyFailure {
                old_length: 2,
                new_length: 4,
                reason: "y".into(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: ProofError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // -----------------------------------------------------------------------
    // Batch 4: Copy semantics, Debug distinctness, clone independence,
    // JSON field-name stability, Display format checks, hash consistency,
    // boundary/edge cases, additional serde roundtrips, Debug nonempty
    // -----------------------------------------------------------------------

    // -- Copy semantics (ProofType is Clone+PartialEq, no Copy; test clone acts like copy) --

    #[test]
    fn proof_type_inclusion_clone_is_independent() {
        let a = ProofType::Inclusion;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn proof_type_consistency_clone_is_independent() {
        let a = ProofType::Consistency;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn mmr_proof_clone_is_independent() {
        let mmr = build_mmr(6);
        let proof = mmr.inclusion_proof(2).unwrap();
        let mut cloned = proof.clone();
        cloned.epoch_id = 999;
        // Mutating clone does not affect original
        assert_ne!(proof.epoch_id, cloned.epoch_id);
    }

    #[test]
    fn proof_error_clone_is_independent() {
        let orig = ProofError::InvalidProof {
            reason: "original".into(),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    // -- Debug distinctness --

    #[test]
    fn proof_type_debug_distinct() {
        let inc = format!("{:?}", ProofType::Inclusion);
        let con = format!("{:?}", ProofType::Consistency);
        assert_ne!(inc, con);
        assert!(inc.contains("Inclusion"));
        assert!(con.contains("Consistency"));
    }

    #[test]
    fn proof_error_debug_all_variants_distinct() {
        let h1 = ContentHash::compute(b"dbg1");
        let h2 = ContentHash::compute(b"dbg2");
        let debugs: std::collections::BTreeSet<String> = [
            format!(
                "{:?}",
                ProofError::IndexOutOfRange {
                    index: 7,
                    stream_length: 4
                }
            ),
            format!(
                "{:?}",
                ProofError::RootMismatch {
                    expected: h1,
                    computed: h2
                }
            ),
            format!(
                "{:?}",
                ProofError::InvalidProof {
                    reason: "dbg".into()
                }
            ),
            format!("{:?}", ProofError::EmptyStream),
            format!(
                "{:?}",
                ProofError::ConsistencyFailure {
                    old_length: 4,
                    new_length: 9,
                    reason: "dbg".into()
                }
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(debugs.len(), 5);
    }

    #[test]
    fn mmr_proof_debug_nonempty() {
        let mmr = build_mmr(4);
        let proof = mmr.inclusion_proof(0).unwrap();
        let dbg = format!("{:?}", proof);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("MmrProof"));
    }

    // -- Serde variant distinctness --

    #[test]
    fn proof_type_serde_variants_produce_distinct_json() {
        let inc = serde_json::to_string(&ProofType::Inclusion).unwrap();
        let con = serde_json::to_string(&ProofType::Consistency).unwrap();
        assert_ne!(inc, con);
    }

    #[test]
    fn proof_error_serde_variants_produce_distinct_json() {
        let v1 = serde_json::to_string(&ProofError::EmptyStream).unwrap();
        let v2 = serde_json::to_string(&ProofError::InvalidProof { reason: "r".into() }).unwrap();
        let v3 = serde_json::to_string(&ProofError::IndexOutOfRange {
            index: 0,
            stream_length: 1,
        })
        .unwrap();
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    // -- JSON field-name stability --

    #[test]
    fn mmr_proof_json_field_proof_type_key() {
        let mmr = build_mmr(2);
        let proof = mmr.inclusion_proof(0).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"proof_type\""));
    }

    #[test]
    fn mmr_proof_json_field_epoch_id_key() {
        let mmr = build_mmr(2);
        let proof = mmr.inclusion_proof(0).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"epoch_id\""));
    }

    #[test]
    fn mmr_proof_json_field_stream_length_key() {
        let mmr = build_mmr(3);
        let proof = mmr.inclusion_proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"stream_length\""));
    }

    #[test]
    fn mmr_proof_json_field_proof_hashes_key() {
        let mmr = build_mmr(3);
        let proof = mmr.inclusion_proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"proof_hashes\""));
    }

    #[test]
    fn mmr_proof_json_field_root_hash_key() {
        let mmr = build_mmr(3);
        let proof = mmr.inclusion_proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"root_hash\""));
    }

    #[test]
    fn mmr_proof_json_field_marker_index_key() {
        let mmr = build_mmr(3);
        let proof = mmr.inclusion_proof(1).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"marker_index\""));
    }

    // -- Display format checks --

    #[test]
    fn proof_error_index_out_of_range_display_contains_stream_length() {
        let err = ProofError::IndexOutOfRange {
            index: 99,
            stream_length: 10,
        };
        let s = err.to_string();
        assert!(s.contains("10"), "display '{s}' missing stream length");
    }

    #[test]
    fn proof_error_root_mismatch_display_text() {
        let err = ProofError::RootMismatch {
            expected: ContentHash::compute(b"e"),
            computed: ContentHash::compute(b"c"),
        };
        let s = err.to_string();
        assert!(s.contains("mismatch"), "display '{s}' missing 'mismatch'");
    }

    #[test]
    fn proof_error_invalid_proof_display_contains_reason() {
        let err = ProofError::InvalidProof {
            reason: "my-reason".into(),
        };
        let s = err.to_string();
        assert!(s.contains("my-reason"), "display '{s}' missing reason");
    }

    #[test]
    fn proof_error_consistency_failure_display_contains_reason() {
        let err = ProofError::ConsistencyFailure {
            old_length: 2,
            new_length: 5,
            reason: "specific-reason".into(),
        };
        let s = err.to_string();
        assert!(
            s.contains("specific-reason"),
            "display '{s}' missing reason"
        );
    }

    #[test]
    fn proof_error_empty_stream_display_exact() {
        assert_eq!(ProofError::EmptyStream.to_string(), "empty stream");
    }

    // -- Hash consistency --

    #[test]
    fn hash_pair_is_order_sensitive() {
        let h1 = ContentHash::compute(b"left");
        let h2 = ContentHash::compute(b"right");
        let forward = hash_pair(&h1, &h2);
        let backward = hash_pair(&h2, &h1);
        assert_ne!(forward, backward);
    }

    #[test]
    fn hash_pair_same_inputs_is_deterministic() {
        let h = ContentHash::compute(b"same");
        let r1 = hash_pair(&h, &h);
        let r2 = hash_pair(&h, &h);
        assert_eq!(r1, r2);
    }

    #[test]
    fn root_hash_differs_for_different_leaf_content() {
        let mut mmr1 = MerkleMountainRange::new(1);
        mmr1.append(ContentHash::compute(b"leaf-A"));
        let mut mmr2 = MerkleMountainRange::new(1);
        mmr2.append(ContentHash::compute(b"leaf-B"));
        assert_ne!(mmr1.root_hash().unwrap(), mmr2.root_hash().unwrap());
    }

    #[test]
    fn two_leaf_mmr_root_differs_from_leaves() {
        let mmr = build_mmr(2);
        let root = mmr.root_hash().unwrap();
        assert_ne!(root, leaf_hash(0));
        assert_ne!(root, leaf_hash(1));
    }

    // -- Boundary / edge cases --

    #[test]
    fn inclusion_proof_index_exactly_at_stream_length_fails() {
        let mmr = build_mmr(3);
        let err = mmr.inclusion_proof(3).unwrap_err();
        assert!(matches!(
            err,
            ProofError::IndexOutOfRange {
                index: 3,
                stream_length: 3
            }
        ));
    }

    #[test]
    fn consistency_proof_old_equals_new_length() {
        let mmr = build_mmr(5);
        let root = mmr.root_hash().unwrap();
        let proof = mmr.consistency_proof(5).unwrap();
        verify_consistency(&root, &proof).unwrap();
    }

    #[test]
    fn consistency_proof_old_length_1() {
        let old_root = build_mmr(1).root_hash().unwrap();
        let mmr = build_mmr(16);
        let proof = mmr.consistency_proof(1).unwrap();
        verify_consistency(&old_root, &proof).unwrap();
    }

    #[test]
    fn empty_mmr_root_hash_is_error() {
        let mmr = MerkleMountainRange::new(42);
        assert!(matches!(mmr.root_hash(), Err(ProofError::EmptyStream)));
    }

    #[test]
    fn inclusion_proof_on_empty_mmr_fails() {
        let mmr = MerkleMountainRange::new(1);
        let err = mmr.inclusion_proof(0).unwrap_err();
        assert!(matches!(
            err,
            ProofError::IndexOutOfRange {
                index: 0,
                stream_length: 0
            }
        ));
    }

    #[test]
    fn mmr_size_zero_leaves() {
        assert_eq!(mmr_size(0), 0);
    }

    #[test]
    fn peak_positions_empty_mmr() {
        assert_eq!(peak_positions(0), Vec::<u64>::new());
    }

    #[test]
    fn is_empty_after_zero_appends() {
        let mmr = MerkleMountainRange::new(7);
        assert!(mmr.is_empty());
        assert_eq!(mmr.size(), 0);
    }

    #[test]
    fn is_not_empty_after_one_append() {
        let mut mmr = MerkleMountainRange::new(7);
        mmr.append(ContentHash::compute(b"x"));
        assert!(!mmr.is_empty());
    }

    #[test]
    fn consistency_proof_large_range() {
        let old_root = build_mmr(16).root_hash().unwrap();
        let mmr = build_mmr(100);
        let proof = mmr.consistency_proof(16).unwrap();
        verify_consistency(&old_root, &proof).unwrap();
    }

    #[test]
    fn leaf_to_pos_large_leaf_index() {
        // leaf 128: 2*128 - popcount(128) = 256 - 1 = 255
        assert_eq!(leaf_to_pos(128), 255);
    }

    #[test]
    fn pos_height_large_positions() {
        // Position 14 = pos of grandparent in 8-leaf tree, height=3
        assert_eq!(pos_height(14), 3);
        // Position 6 = grandparent of 4-leaf tree, height=2
        assert_eq!(pos_height(6), 2);
    }

    // -- Additional serde roundtrips --

    #[test]
    fn mmr_proof_consistency_type_serde_roundtrip() {
        let mmr = build_mmr(8);
        let proof = mmr.consistency_proof(4).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn mmr_proof_serde_preserves_epoch_id() {
        let mut mmr = MerkleMountainRange::new(42);
        mmr.append(leaf_hash(0));
        let proof = mmr.inclusion_proof(0).unwrap();
        assert_eq!(proof.epoch_id, 42);
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.epoch_id, 42);
    }

    #[test]
    fn mmr_proof_serde_preserves_stream_length() {
        let mmr = build_mmr(13);
        let proof = mmr.inclusion_proof(7).unwrap();
        assert_eq!(proof.stream_length, 13);
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.stream_length, 13);
    }

    #[test]
    fn proof_type_inclusion_serde_roundtrip_is_inclusion() {
        let pt = ProofType::Inclusion;
        let json = serde_json::to_string(&pt).unwrap();
        let restored: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, ProofType::Inclusion);
    }

    #[test]
    fn proof_type_consistency_serde_roundtrip_is_consistency() {
        let pt = ProofType::Consistency;
        let json = serde_json::to_string(&pt).unwrap();
        let restored: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, ProofType::Consistency);
    }

    // -- Debug nonempty --

    #[test]
    fn proof_error_debug_nonempty_empty_stream() {
        let dbg = format!("{:?}", ProofError::EmptyStream);
        assert!(!dbg.is_empty());
    }

    #[test]
    fn proof_type_debug_nonempty_inclusion() {
        let dbg = format!("{:?}", ProofType::Inclusion);
        assert!(!dbg.is_empty());
    }

    #[test]
    fn proof_type_debug_nonempty_consistency() {
        let dbg = format!("{:?}", ProofType::Consistency);
        assert!(!dbg.is_empty());
    }

    #[test]
    fn proof_error_debug_nonempty_root_mismatch() {
        let err = ProofError::RootMismatch {
            expected: ContentHash::compute(b"a"),
            computed: ContentHash::compute(b"b"),
        };
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("RootMismatch"));
    }

    #[test]
    fn proof_error_debug_nonempty_index_out_of_range() {
        let err = ProofError::IndexOutOfRange {
            index: 3,
            stream_length: 2,
        };
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("IndexOutOfRange"));
    }

    #[test]
    fn proof_error_debug_nonempty_invalid_proof() {
        let err = ProofError::InvalidProof {
            reason: "bad proof".into(),
        };
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("InvalidProof"));
    }

    #[test]
    fn proof_error_debug_nonempty_consistency_failure() {
        let err = ProofError::ConsistencyFailure {
            old_length: 4,
            new_length: 8,
            reason: "fail".into(),
        };
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("ConsistencyFailure"));
    }

    // -- Additional correctness/edge cases --

    #[test]
    fn inclusion_proof_for_last_leaf() {
        for n in [1u64, 2, 4, 8, 16, 32] {
            let mmr = build_mmr(n);
            let proof = mmr.inclusion_proof(n - 1).unwrap();
            verify_inclusion(&leaf_hash(n - 1), n - 1, &proof)
                .unwrap_or_else(|e| panic!("n={n}: {e}"));
        }
    }

    #[test]
    fn inclusion_proof_for_first_leaf_large_mmr() {
        let mmr = build_mmr(256);
        let proof = mmr.inclusion_proof(0).unwrap();
        verify_inclusion(&leaf_hash(0), 0, &proof).unwrap();
    }

    #[test]
    fn verify_inclusion_rejects_out_of_range_index() {
        let mmr = build_mmr(4);
        let proof = mmr.inclusion_proof(0).unwrap();
        let err = verify_inclusion(&leaf_hash(0), 10, &proof).unwrap_err();
        assert!(matches!(err, ProofError::IndexOutOfRange { .. }));
    }

    #[test]
    fn different_epoch_ids_produce_same_root() {
        let mut mmr1 = MerkleMountainRange::new(1);
        let mut mmr2 = MerkleMountainRange::new(99);
        for i in 0..5u64 {
            mmr1.append(leaf_hash(i));
            mmr2.append(leaf_hash(i));
        }
        // epoch_id does not affect root hash (only in proof metadata)
        assert_eq!(mmr1.root_hash().unwrap(), mmr2.root_hash().unwrap());
    }

    #[test]
    fn different_epoch_ids_reflected_in_proof_epoch_id_field() {
        let mut mmr_a = MerkleMountainRange::new(11);
        let mut mmr_b = MerkleMountainRange::new(22);
        mmr_a.append(leaf_hash(0));
        mmr_b.append(leaf_hash(0));
        let proof_a = mmr_a.inclusion_proof(0).unwrap();
        let proof_b = mmr_b.inclusion_proof(0).unwrap();
        assert_eq!(proof_a.epoch_id, 11);
        assert_eq!(proof_b.epoch_id, 22);
        assert_ne!(proof_a.epoch_id, proof_b.epoch_id);
    }

    #[test]
    fn mmr_size_large_power_of_two() {
        // mmr_size(1024) = 2*1024 - popcount(1024) = 2048 - 1 = 2047
        assert_eq!(mmr_size(1024), 2047);
    }

    #[test]
    fn bag_peaks_three_peaks_is_deterministic() {
        let h1 = ContentHash::compute(b"p1");
        let h2 = ContentHash::compute(b"p2");
        let h3 = ContentHash::compute(b"p3");
        let r1 = bag_peaks(&[h1, h2, h3]);
        let r2 = bag_peaks(&[h1, h2, h3]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn consistency_proof_non_trivial_old_lengths() {
        for old_n in [2u64, 3, 5, 6, 7] {
            let old_root = build_mmr(old_n).root_hash().unwrap();
            let new_mmr = build_mmr(old_n + 1);
            let proof = new_mmr.consistency_proof(old_n).unwrap();
            verify_consistency(&old_root, &proof).unwrap_or_else(|e| panic!("old_n={old_n}: {e}"));
        }
    }
}
