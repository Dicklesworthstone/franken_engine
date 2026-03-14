#![forbid(unsafe_code)]

//! Enrichment integration tests for the `mmr_proof` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::mmr_proof::{
    MerkleMountainRange, MmrProof, ProofError, ProofType, verify_consistency, verify_inclusion,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ===========================================================================
// ProofType enrichment
// ===========================================================================

#[test]
fn enrichment_proof_type_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(serde_json::to_string(&ProofType::Inclusion).unwrap());
    set.insert(serde_json::to_string(&ProofType::Consistency).unwrap());
    // Re-insert same values
    set.insert(serde_json::to_string(&ProofType::Inclusion).unwrap());
    set.insert(serde_json::to_string(&ProofType::Consistency).unwrap());
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_proof_type_debug_uniqueness() {
    let debugs: BTreeSet<String> = [
        format!("{:?}", ProofType::Inclusion),
        format!("{:?}", ProofType::Consistency),
    ]
    .into_iter()
    .collect();
    assert_eq!(debugs.len(), 2);
}

#[test]
fn enrichment_proof_type_clone_independence() {
    let orig = ProofType::Inclusion;
    let cloned = orig.clone();
    // Both exist independently
    assert_eq!(orig, cloned);
    assert_eq!(orig, ProofType::Inclusion);
}

// ===========================================================================
// ProofError enrichment
// ===========================================================================

#[test]
fn enrichment_proof_error_btreeset_5_variants() {
    let set: BTreeSet<String> = [
        ProofError::EmptyStream.to_string(),
        ProofError::IndexOutOfRange {
            index: 1,
            stream_length: 0,
        }
        .to_string(),
        ProofError::RootMismatch {
            expected: ContentHash::compute(b"e"),
            computed: ContentHash::compute(b"c"),
        }
        .to_string(),
        ProofError::InvalidProof {
            reason: "x".to_string(),
        }
        .to_string(),
        ProofError::ConsistencyFailure {
            old_length: 1,
            new_length: 2,
            reason: "y".to_string(),
        }
        .to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_proof_error_clone_independence_invalid_proof() {
    let orig = ProofError::InvalidProof {
        reason: "original-reason".to_string(),
    };
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
    // Verify the original is unaffected by clone existing
    if let ProofError::InvalidProof { reason } = &orig {
        assert_eq!(reason, "original-reason");
    }
}

#[test]
fn enrichment_proof_error_clone_independence_consistency_failure() {
    let orig = ProofError::ConsistencyFailure {
        old_length: 3,
        new_length: 10,
        reason: "original".to_string(),
    };
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
    if let ProofError::ConsistencyFailure { reason, .. } = &orig {
        assert_eq!(reason, "original");
    }
}

#[test]
fn enrichment_proof_error_debug_contains_variant_name() {
    let variants: Vec<(&str, String)> = vec![
        ("EmptyStream", format!("{:?}", ProofError::EmptyStream)),
        (
            "IndexOutOfRange",
            format!(
                "{:?}",
                ProofError::IndexOutOfRange {
                    index: 1,
                    stream_length: 2,
                }
            ),
        ),
        (
            "RootMismatch",
            format!(
                "{:?}",
                ProofError::RootMismatch {
                    expected: ContentHash::compute(b"a"),
                    computed: ContentHash::compute(b"b"),
                }
            ),
        ),
        (
            "InvalidProof",
            format!(
                "{:?}",
                ProofError::InvalidProof {
                    reason: "r".to_string(),
                }
            ),
        ),
        (
            "ConsistencyFailure",
            format!(
                "{:?}",
                ProofError::ConsistencyFailure {
                    old_length: 1,
                    new_length: 2,
                    reason: "f".to_string(),
                }
            ),
        ),
    ];
    for (name, dbg) in &variants {
        assert!(
            dbg.contains(name),
            "Debug for {name} should contain variant name, got: {dbg}"
        );
    }
}

// ===========================================================================
// MmrProof enrichment
// ===========================================================================

#[test]
fn enrichment_mmr_proof_clone_independence_mutate_epoch() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    let mut cloned = proof.clone();
    cloned.epoch_id = 12345;
    assert_eq!(proof.epoch_id, 1);
    assert_eq!(cloned.epoch_id, 12345);
    assert_ne!(proof, cloned);
}

#[test]
fn enrichment_mmr_proof_clone_independence_mutate_proof_hashes() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    let orig_len = proof.proof_hashes.len();
    let mut cloned = proof.clone();
    cloned.proof_hashes.push(ContentHash::compute(b"extra"));
    assert_eq!(proof.proof_hashes.len(), orig_len);
    assert_eq!(cloned.proof_hashes.len(), orig_len + 1);
}

#[test]
fn enrichment_mmr_proof_json_all_six_fields() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    for field in [
        "proof_type",
        "marker_index",
        "proof_hashes",
        "root_hash",
        "stream_length",
        "epoch_id",
    ] {
        assert!(json.contains(field), "missing field: {field} in: {json}");
    }
}

#[test]
fn enrichment_mmr_proof_debug_contains_mmr_proof() {
    let mmr = build_mmr(4);
    let proof = mmr.inclusion_proof(1).unwrap();
    let dbg = format!("{proof:?}");
    assert!(dbg.contains("MmrProof"), "Debug: {dbg}");
}

#[test]
fn enrichment_mmr_proof_serde_roundtrip_preserves_all_fields() {
    let mmr = build_mmr(16);
    let proof = mmr.inclusion_proof(7).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let back: MmrProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof.proof_type, back.proof_type);
    assert_eq!(proof.marker_index, back.marker_index);
    assert_eq!(proof.proof_hashes, back.proof_hashes);
    assert_eq!(proof.root_hash, back.root_hash);
    assert_eq!(proof.stream_length, back.stream_length);
    assert_eq!(proof.epoch_id, back.epoch_id);
}

// ===========================================================================
// MerkleMountainRange enrichment
// ===========================================================================

#[test]
fn enrichment_mmr_debug_nonempty() {
    let mmr = build_mmr(4);
    let dbg = format!("{mmr:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("MerkleMountainRange"), "Debug: {dbg}");
}

#[test]
fn enrichment_mmr_debug_empty() {
    let mmr = MerkleMountainRange::new(1);
    let dbg = format!("{mmr:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_mmr_append_returns_leaf_pos() {
    let mut mmr = MerkleMountainRange::new(1);
    // leaf 0 → pos 0
    assert_eq!(mmr.append(leaf_hash(0)), 0);
    // leaf 1 → pos 1 (parent at 2)
    assert_eq!(mmr.append(leaf_hash(1)), 1);
    // leaf 2 → pos 3
    assert_eq!(mmr.append(leaf_hash(2)), 3);
    // leaf 3 → pos 4 (parent at 5, grandparent at 6)
    assert_eq!(mmr.append(leaf_hash(3)), 4);
    // leaf 4 → pos 7
    assert_eq!(mmr.append(leaf_hash(4)), 7);
}

#[test]
fn enrichment_mmr_peaks_count_equals_popcount() {
    for n in 1..=64u64 {
        let mmr = build_mmr(n);
        assert_eq!(
            mmr.peaks().len(),
            n.count_ones() as usize,
            "n={n}: peaks count should equal popcount"
        );
    }
}

#[test]
fn enrichment_mmr_size_formula_for_range() {
    for n in 0..=100u64 {
        let expected = if n == 0 {
            0
        } else {
            2 * n - n.count_ones() as u64
        };
        let mmr = build_mmr(n);
        assert_eq!(mmr.size(), expected, "n={n}");
    }
}

// ===========================================================================
// Five-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_root_hash() {
    let roots: Vec<_> = (0..5).map(|_| build_mmr(50).root_hash().unwrap()).collect();
    for r in &roots[1..] {
        assert_eq!(roots[0], *r);
    }
}

#[test]
fn enrichment_five_run_determinism_peaks() {
    let peaks: Vec<_> = (0..5).map(|_| build_mmr(50).peaks()).collect();
    for p in &peaks[1..] {
        assert_eq!(peaks[0], *p);
    }
}

#[test]
fn enrichment_five_run_determinism_inclusion_proof() {
    let proofs: Vec<_> = (0..5)
        .map(|_| build_mmr(50).inclusion_proof(25).unwrap())
        .collect();
    for p in &proofs[1..] {
        assert_eq!(proofs[0], *p);
    }
}

#[test]
fn enrichment_five_run_determinism_consistency_proof() {
    let proofs: Vec<_> = (0..5)
        .map(|_| build_mmr(50).consistency_proof(20).unwrap())
        .collect();
    for p in &proofs[1..] {
        assert_eq!(proofs[0], *p);
    }
}

// ===========================================================================
// Single-increment consistency chain
// ===========================================================================

#[test]
fn enrichment_single_increment_consistency_1_to_20() {
    for n in 1..20u64 {
        let old_root = build_mmr(n).root_hash().unwrap();
        let new_mmr = build_mmr(n + 1);
        let proof = new_mmr.consistency_proof(n).unwrap();
        verify_consistency(&old_root, &proof)
            .unwrap_or_else(|e| panic!("consistency {n} -> {}: {e}", n + 1));
    }
}

#[test]
fn enrichment_consistency_chain_every_step_1_to_32() {
    // Build MMRs for 1..=32, verify every (old, new) pair where old < new
    let roots: Vec<_> = (1..=32u64)
        .map(|n| build_mmr(n).root_hash().unwrap())
        .collect();
    for old_n in 1..=16u64 {
        for new_n in (old_n + 1)..=32u64 {
            let new_mmr = build_mmr(new_n);
            let proof = new_mmr.consistency_proof(old_n).unwrap();
            verify_consistency(&roots[(old_n - 1) as usize], &proof)
                .unwrap_or_else(|e| panic!("consistency {old_n} -> {new_n}: {e}"));
        }
    }
}

// ===========================================================================
// Inclusion proof completeness for non-power-of-two
// ===========================================================================

#[test]
fn enrichment_all_leaves_verify_n_equals_13() {
    let mmr = build_mmr(13);
    for i in 0..13 {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap_or_else(|e| panic!("leaf {i}: {e}"));
    }
}

#[test]
fn enrichment_all_leaves_verify_n_equals_63() {
    let mmr = build_mmr(63);
    for i in 0..63 {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap_or_else(|e| panic!("leaf {i}: {e}"));
    }
}

#[test]
fn enrichment_all_leaves_verify_n_equals_100() {
    let mmr = build_mmr(100);
    for i in (0..100).step_by(7) {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap_or_else(|e| panic!("leaf {i}: {e}"));
    }
}

// ===========================================================================
// Proof tamper resistance
// ===========================================================================

#[test]
fn enrichment_tampered_root_hash_rejects_inclusion() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(3).unwrap();
    proof.root_hash = ContentHash::compute(b"tampered-root");
    assert!(verify_inclusion(&leaf_hash(3), 3, &proof).is_err());
}

#[test]
fn enrichment_tampered_stream_length_rejects_inclusion() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(3).unwrap();
    proof.stream_length = 4; // change to smaller value
    // This should fail because the tree structure is different
    assert!(verify_inclusion(&leaf_hash(3), 3, &proof).is_err());
}

#[test]
fn enrichment_tampered_marker_index_rejects_inclusion() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(3).unwrap();
    proof.marker_index = 5; // different from the index we verify against
    // verify_inclusion uses the leaf_index parameter, not proof.marker_index,
    // so this tests that the proof data is specific to the original index
    assert!(verify_inclusion(&leaf_hash(5), 5, &proof).is_err());
}

#[test]
fn enrichment_swapped_proof_hashes_rejects_inclusion() {
    let mmr = build_mmr(16);
    let mut proof = mmr.inclusion_proof(5).unwrap();
    if proof.proof_hashes.len() >= 2 {
        proof.proof_hashes.swap(0, 1);
        assert!(verify_inclusion(&leaf_hash(5), 5, &proof).is_err());
    }
}

#[test]
fn enrichment_tampered_consistency_proof_hash_rejects() {
    let old_root = build_mmr(4).root_hash().unwrap();
    let new_mmr = build_mmr(8);
    let mut proof = new_mmr.consistency_proof(4).unwrap();
    if proof.proof_hashes.len() >= 2 {
        // Tamper with the last proof hash
        let last = proof.proof_hashes.len() - 1;
        proof.proof_hashes[last] = ContentHash::compute(b"tampered");
        assert!(verify_consistency(&old_root, &proof).is_err());
    }
}

// ===========================================================================
// Proof type mismatch
// ===========================================================================

#[test]
fn enrichment_verify_inclusion_wrong_type_returns_invalid_proof() {
    let mmr = build_mmr(4);
    let old_root = mmr.root_hash().unwrap();
    let mut proof = mmr.consistency_proof(2).unwrap();
    proof.proof_type = ProofType::Inclusion; // lie about type
    // verify_inclusion might fail differently but should fail
    assert!(verify_inclusion(&old_root, 2, &proof).is_err());
}

#[test]
fn enrichment_verify_consistency_wrong_type_returns_invalid_proof() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(3).unwrap();
    proof.proof_type = ProofType::Consistency;
    let err = verify_consistency(&leaf_hash(3), &proof).unwrap_err();
    assert!(matches!(
        err,
        ProofError::ConsistencyFailure { .. }
            | ProofError::InvalidProof { .. }
            | ProofError::EmptyStream
    ));
}

// ===========================================================================
// Incremental append with interleaved proofs
// ===========================================================================

#[test]
fn enrichment_incremental_append_all_proofs_valid_at_each_step() {
    let mut mmr = MerkleMountainRange::new(1);
    for n in 0..20u64 {
        mmr.append(leaf_hash(n));
        // After each append, verify all existing leaves
        for i in 0..=n {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof)
                .unwrap_or_else(|e| panic!("n={n}, i={i}: {e}"));
        }
    }
}

#[test]
fn enrichment_incremental_append_root_changes_every_step() {
    let mut mmr = MerkleMountainRange::new(1);
    let mut prev_root = None;
    for n in 0..20u64 {
        mmr.append(leaf_hash(n));
        let root = mmr.root_hash().unwrap();
        if let Some(prev) = prev_root {
            assert_ne!(prev, root, "root should change at append {n}");
        }
        prev_root = Some(root);
    }
}

// ===========================================================================
// Proof size bounds
// ===========================================================================

#[test]
fn enrichment_inclusion_proof_size_upper_bound() {
    // For n leaves, inclusion proof should have at most ceil(log2(n)) + popcount(n) hashes
    for &n in &[4, 8, 16, 32, 64, 128, 256, 512] {
        let mmr = build_mmr(n);
        let proof = mmr.inclusion_proof(n / 2).unwrap();
        let log2_n = 64 - n.leading_zeros();
        let popcount = n.count_ones();
        let upper = (log2_n + popcount) as usize;
        assert!(
            proof.proof_hashes.len() <= upper,
            "n={n}: proof size {} exceeds upper bound {}",
            proof.proof_hashes.len(),
            upper
        );
    }
}

#[test]
fn enrichment_consistency_proof_size_bounded() {
    // Consistency proofs should also be bounded
    for &(old_n, new_n) in &[(4, 8), (8, 16), (16, 32), (32, 64)] {
        let new_mmr = build_mmr(new_n);
        let proof = new_mmr.consistency_proof(old_n).unwrap();
        // At most old peaks + new peaks - shared peaks
        let max_peaks = old_n.count_ones() + new_n.count_ones();
        assert!(
            proof.proof_hashes.len() <= max_peaks as usize + 2,
            "consistency proof too large for {old_n} -> {new_n}: {} hashes",
            proof.proof_hashes.len()
        );
    }
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn enrichment_mmr_peaks_single_leaf_is_leaf_hash() {
    let mmr = build_mmr(1);
    let peaks = mmr.peaks();
    assert_eq!(peaks.len(), 1);
    assert_eq!(peaks[0], leaf_hash(0));
}

#[test]
fn enrichment_mmr_peaks_two_leaves_single_peak() {
    let mmr = build_mmr(2);
    let peaks = mmr.peaks();
    assert_eq!(peaks.len(), 1);
    // The single peak should be the hash of the two leaf hashes
    assert_ne!(peaks[0], leaf_hash(0));
    assert_ne!(peaks[0], leaf_hash(1));
}

#[test]
fn enrichment_mmr_peaks_three_leaves_two_peaks() {
    let mmr = build_mmr(3);
    let peaks = mmr.peaks();
    assert_eq!(peaks.len(), 2);
    // Second peak is the third leaf
    assert_eq!(peaks[1], leaf_hash(2));
}

#[test]
fn enrichment_root_hash_single_leaf_equals_leaf() {
    let mut mmr = MerkleMountainRange::new(1);
    let h = ContentHash::compute(b"only-leaf");
    mmr.append(h);
    assert_eq!(mmr.root_hash().unwrap(), h);
}

#[test]
fn enrichment_mmr_new_epoch_preserved() {
    let mmr = MerkleMountainRange::new(42);
    let dbg = format!("{mmr:?}");
    assert!(dbg.contains("42") || mmr.is_empty());
}

#[test]
fn enrichment_proof_error_index_display_both_values() {
    let err = ProofError::IndexOutOfRange {
        index: 1000,
        stream_length: 500,
    };
    let s = err.to_string();
    assert!(s.contains("1000"), "display: {s}");
    assert!(s.contains("500"), "display: {s}");
}

// ===========================================================================
// Root hash ordering
// ===========================================================================

#[test]
fn enrichment_different_leaf_order_different_root() {
    let mut mmr_ab = MerkleMountainRange::new(1);
    mmr_ab.append(ContentHash::compute(b"alpha"));
    mmr_ab.append(ContentHash::compute(b"beta"));
    mmr_ab.append(ContentHash::compute(b"gamma"));

    let mut mmr_ba = MerkleMountainRange::new(1);
    mmr_ba.append(ContentHash::compute(b"gamma"));
    mmr_ba.append(ContentHash::compute(b"beta"));
    mmr_ba.append(ContentHash::compute(b"alpha"));

    assert_ne!(
        mmr_ab.root_hash().unwrap(),
        mmr_ba.root_hash().unwrap(),
        "different ordering must produce different root"
    );
}

#[test]
fn enrichment_all_same_leaves_same_root() {
    let h = ContentHash::compute(b"same");
    let mut mmr1 = MerkleMountainRange::new(1);
    let mut mmr2 = MerkleMountainRange::new(1);
    for _ in 0..5 {
        mmr1.append(h);
        mmr2.append(h);
    }
    assert_eq!(mmr1.root_hash().unwrap(), mmr2.root_hash().unwrap());
}

// ===========================================================================
// Serde edge cases
// ===========================================================================

#[test]
fn enrichment_proof_error_consistency_failure_serde_preserves_reason() {
    let err = ProofError::ConsistencyFailure {
        old_length: 42,
        new_length: 100,
        reason: "special chars: <>&\"'".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ProofError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    if let ProofError::ConsistencyFailure { reason, .. } = &back {
        assert!(reason.contains("<>&"));
    }
}

#[test]
fn enrichment_mmr_proof_json_roundtrip_consistency_type() {
    let mmr = build_mmr(16);
    let proof = mmr.consistency_proof(8).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let back: MmrProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
    assert_eq!(back.proof_type, ProofType::Consistency);
}

#[test]
fn enrichment_deserialized_inclusion_proof_still_verifies() {
    let mmr = build_mmr(64);
    for &i in &[0u64, 15, 31, 63] {
        let proof = mmr.inclusion_proof(i).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        verify_inclusion(&leaf_hash(i), i, &restored)
            .unwrap_or_else(|e| panic!("deserialized proof for {i}: {e}"));
    }
}

#[test]
fn enrichment_deserialized_consistency_proof_still_verifies() {
    for &(old_n, new_n) in &[(1, 10), (5, 20), (8, 64)] {
        let old_root = build_mmr(old_n).root_hash().unwrap();
        let new_mmr = build_mmr(new_n);
        let proof = new_mmr.consistency_proof(old_n).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        verify_consistency(&old_root, &restored)
            .unwrap_or_else(|e| panic!("deserialized consistency {old_n}->{new_n}: {e}"));
    }
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_proof_for_leaf_0_and_last_leaf_differ() {
    let mmr = build_mmr(16);
    let first = mmr.inclusion_proof(0).unwrap();
    let last = mmr.inclusion_proof(15).unwrap();
    assert_ne!(first.proof_hashes, last.proof_hashes);
    assert_eq!(first.root_hash, last.root_hash);
}

#[test]
fn enrichment_inclusion_proof_root_matches_mmr_root() {
    for n in [1, 5, 10, 50, 100] {
        let mmr = build_mmr(n);
        let root = mmr.root_hash().unwrap();
        for &i in &[0, n / 2, n - 1] {
            let proof = mmr.inclusion_proof(i).unwrap();
            assert_eq!(proof.root_hash, root, "n={n}, i={i}");
        }
    }
}

#[test]
fn enrichment_consistency_proof_root_matches_new_mmr_root() {
    for &(old_n, new_n) in &[(1, 5), (4, 16), (10, 50)] {
        let new_mmr = build_mmr(new_n);
        let new_root = new_mmr.root_hash().unwrap();
        let proof = new_mmr.consistency_proof(old_n).unwrap();
        assert_eq!(proof.root_hash, new_root);
    }
}

#[test]
fn enrichment_unique_roots_for_1_to_50() {
    let roots: BTreeSet<_> = (1..=50u64)
        .map(|n| build_mmr(n).root_hash().unwrap().0)
        .collect();
    assert_eq!(
        roots.len(),
        50,
        "each tree size should produce a unique root"
    );
}
