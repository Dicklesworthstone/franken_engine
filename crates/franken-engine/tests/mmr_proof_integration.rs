#![forbid(unsafe_code)]

//! Integration tests for the `mmr_proof` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! MMR construction, inclusion proofs, consistency proofs, verification,
//! error conditions, Display impls, serde round-trips, and deterministic
//! replay properties.

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

fn build_mmr_epoch(n: u64, epoch: u64) -> MerkleMountainRange {
    let mut mmr = MerkleMountainRange::new(epoch);
    for i in 0..n {
        mmr.append(leaf_hash(i));
    }
    mmr
}

// ===========================================================================
// Section 1: Construction and basic properties
// ===========================================================================

#[test]
fn empty_mmr_properties() {
    let mmr = MerkleMountainRange::new(42);
    assert_eq!(mmr.num_leaves(), 0);
    assert_eq!(mmr.size(), 0);
    assert!(mmr.is_empty());
}

#[test]
fn single_leaf_mmr_properties() {
    let mut mmr = MerkleMountainRange::new(1);
    let pos = mmr.append(leaf_hash(0));
    assert_eq!(pos, 0);
    assert_eq!(mmr.num_leaves(), 1);
    assert_eq!(mmr.size(), 1);
    assert!(!mmr.is_empty());
}

#[test]
fn two_leaf_mmr_creates_parent_node() {
    let mmr = build_mmr(2);
    assert_eq!(mmr.num_leaves(), 2);
    // 2 leaves + 1 parent = 3 nodes
    assert_eq!(mmr.size(), 3);
}

#[test]
fn four_leaf_mmr_creates_full_binary_tree() {
    let mmr = build_mmr(4);
    assert_eq!(mmr.num_leaves(), 4);
    // 4 leaves + 2 parents + 1 grandparent = 7
    assert_eq!(mmr.size(), 7);
}

#[test]
fn eight_leaf_mmr_size() {
    let mmr = build_mmr(8);
    assert_eq!(mmr.num_leaves(), 8);
    // 2*8 - popcount(8) = 16 - 1 = 15
    assert_eq!(mmr.size(), 15);
}

#[test]
fn sequential_appends_increase_leaf_count_monotonically() {
    let mut mmr = MerkleMountainRange::new(1);
    for i in 0..50 {
        mmr.append(leaf_hash(i));
        assert_eq!(mmr.num_leaves(), i + 1);
        assert!(!mmr.is_empty());
    }
}

#[test]
fn large_mmr_size_follows_formula() {
    // mmr_size(n) = 2*n - popcount(n)
    for n in [1, 2, 3, 5, 7, 8, 10, 16, 31, 32, 33, 64, 100, 128, 255, 256] {
        let mmr = build_mmr(n);
        let expected = 2 * n - n.count_ones() as u64;
        assert_eq!(
            mmr.size(),
            expected,
            "mmr_size({n}) should be {expected}, got {}",
            mmr.size()
        );
    }
}

// ===========================================================================
// Section 2: Peaks
// ===========================================================================

#[test]
fn single_leaf_has_one_peak() {
    let mmr = build_mmr(1);
    assert_eq!(mmr.peaks().len(), 1);
    assert_eq!(mmr.peaks()[0], leaf_hash(0));
}

#[test]
fn power_of_two_leaves_have_single_peak() {
    for n in [2, 4, 8, 16, 32, 64] {
        let mmr = build_mmr(n);
        assert_eq!(
            mmr.peaks().len(),
            1,
            "power-of-two n={n} should have 1 peak"
        );
    }
}

#[test]
fn non_power_of_two_leaves_have_popcount_peaks() {
    // Number of peaks = number of 1-bits in the binary representation of num_leaves
    for n in [3, 5, 6, 7, 9, 10, 11, 13, 15, 17, 33, 100] {
        let mmr = build_mmr(n);
        let expected_peaks = n.count_ones() as usize;
        assert_eq!(
            mmr.peaks().len(),
            expected_peaks,
            "n={n} should have {expected_peaks} peaks, got {}",
            mmr.peaks().len()
        );
    }
}

#[test]
fn peaks_are_deterministic_across_builds() {
    let peaks1 = build_mmr(13).peaks();
    let peaks2 = build_mmr(13).peaks();
    assert_eq!(peaks1, peaks2);
}

// ===========================================================================
// Section 3: Root hash
// ===========================================================================

#[test]
fn root_hash_fails_on_empty_mmr() {
    let mmr = MerkleMountainRange::new(1);
    match mmr.root_hash() {
        Err(ProofError::EmptyStream) => {}
        other => panic!("expected EmptyStream, got {other:?}"),
    }
}

#[test]
fn single_leaf_root_equals_leaf_hash() {
    let mmr = build_mmr(1);
    assert_eq!(mmr.root_hash().unwrap(), leaf_hash(0));
}

#[test]
fn root_hash_is_deterministic() {
    for n in [1, 5, 10, 50, 100] {
        let r1 = build_mmr(n).root_hash().unwrap();
        let r2 = build_mmr(n).root_hash().unwrap();
        assert_eq!(r1, r2, "root must be deterministic for n={n}");
    }
}

#[test]
fn root_hash_changes_when_leaves_appended() {
    let mut roots = BTreeSet::new();
    for n in 1..=20 {
        let root = build_mmr(n).root_hash().unwrap();
        assert!(
            roots.insert(root),
            "root for n={n} collides with a previous root"
        );
    }
}

#[test]
fn root_hash_differs_for_different_leaf_contents() {
    let mut mmr1 = MerkleMountainRange::new(1);
    mmr1.append(ContentHash::compute(b"alpha"));
    mmr1.append(ContentHash::compute(b"beta"));

    let mut mmr2 = MerkleMountainRange::new(1);
    mmr2.append(ContentHash::compute(b"gamma"));
    mmr2.append(ContentHash::compute(b"delta"));

    assert_ne!(mmr1.root_hash().unwrap(), mmr2.root_hash().unwrap());
}

#[test]
fn root_hash_depends_on_leaf_order() {
    let mut mmr_ab = MerkleMountainRange::new(1);
    mmr_ab.append(ContentHash::compute(b"A"));
    mmr_ab.append(ContentHash::compute(b"B"));

    let mut mmr_ba = MerkleMountainRange::new(1);
    mmr_ba.append(ContentHash::compute(b"B"));
    mmr_ba.append(ContentHash::compute(b"A"));

    assert_ne!(
        mmr_ab.root_hash().unwrap(),
        mmr_ba.root_hash().unwrap(),
        "root must differ when leaf order changes"
    );
}

// ===========================================================================
// Section 4: Inclusion proofs -- generation
// ===========================================================================

#[test]
fn inclusion_proof_for_single_leaf() {
    let mmr = build_mmr(1);
    let proof = mmr.inclusion_proof(0).unwrap();
    assert_eq!(proof.proof_type, ProofType::Inclusion);
    assert_eq!(proof.marker_index, 0);
    assert_eq!(proof.stream_length, 1);
    assert_eq!(proof.epoch_id, 1);
    assert_eq!(proof.root_hash, mmr.root_hash().unwrap());
}

#[test]
fn inclusion_proof_out_of_range() {
    let mmr = build_mmr(5);
    match mmr.inclusion_proof(5) {
        Err(ProofError::IndexOutOfRange {
            index: 5,
            stream_length: 5,
        }) => {}
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }

    match mmr.inclusion_proof(100) {
        Err(ProofError::IndexOutOfRange { .. }) => {}
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn inclusion_proof_carries_correct_epoch() {
    let mmr = build_mmr_epoch(4, 99);
    let proof = mmr.inclusion_proof(2).unwrap();
    assert_eq!(proof.epoch_id, 99);
}

#[test]
fn inclusion_proof_size_is_logarithmic() {
    let mmr = build_mmr(1024);
    let proof = mmr.inclusion_proof(500).unwrap();
    // O(log2(1024)) = 10, plus peak-bagging overhead
    assert!(
        proof.proof_hashes.len() <= 15,
        "proof too large: {} hashes for 1024 leaves",
        proof.proof_hashes.len()
    );
}

#[test]
fn inclusion_proof_size_grows_logarithmically() {
    let sizes = [8, 64, 512, 4096];
    let mut prev_proof_len = 0;
    for &n in &sizes {
        let mmr = build_mmr(n);
        let proof = mmr.inclusion_proof(0).unwrap();
        // The proof size should grow roughly logarithmically
        if prev_proof_len > 0 {
            // Each 8x increase in leaves should add roughly 3 hashes
            assert!(
                proof.proof_hashes.len() <= prev_proof_len + 5,
                "proof growth too fast: {} -> {} for n={}",
                prev_proof_len,
                proof.proof_hashes.len(),
                n,
            );
        }
        prev_proof_len = proof.proof_hashes.len();
    }
}

// ===========================================================================
// Section 5: Inclusion proofs -- verification
// ===========================================================================

#[test]
fn verify_inclusion_single_leaf() {
    let mmr = build_mmr(1);
    let proof = mmr.inclusion_proof(0).unwrap();
    verify_inclusion(&leaf_hash(0), 0, &proof).unwrap();
}

#[test]
fn verify_inclusion_all_leaves_power_of_two() {
    for n in [2, 4, 8, 16] {
        let mmr = build_mmr(n);
        for i in 0..n {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof)
                .unwrap_or_else(|e| panic!("n={n}, i={i}: {e}"));
        }
    }
}

#[test]
fn verify_inclusion_all_leaves_non_power_of_two() {
    for n in [3, 5, 6, 7, 9, 10, 11, 13, 15, 17, 20, 31, 33] {
        let mmr = build_mmr(n);
        for i in 0..n {
            let proof = mmr.inclusion_proof(i).unwrap();
            verify_inclusion(&leaf_hash(i), i, &proof)
                .unwrap_or_else(|e| panic!("n={n}, i={i}: {e}"));
        }
    }
}

#[test]
fn verify_inclusion_rejects_wrong_leaf_hash() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    let wrong = ContentHash::compute(b"wrong");
    assert!(verify_inclusion(&wrong, 3, &proof).is_err());
}

#[test]
fn verify_inclusion_rejects_wrong_index() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    // Using the correct leaf hash but wrong index should fail
    assert!(verify_inclusion(&leaf_hash(3), 4, &proof).is_err());
}

#[test]
fn verify_inclusion_rejects_tampered_proof_hash() {
    let mmr = build_mmr(16);
    for i in 0..16 {
        let mut proof = mmr.inclusion_proof(i).unwrap();
        if !proof.proof_hashes.is_empty() {
            proof.proof_hashes[0] = ContentHash([0xab; 32]);
            assert!(
                verify_inclusion(&leaf_hash(i), i, &proof).is_err(),
                "tampered proof for index {i} should fail"
            );
        }
    }
}

#[test]
fn verify_inclusion_rejects_truncated_proof() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(3).unwrap();
    if proof.proof_hashes.len() > 1 {
        proof.proof_hashes.pop();
        assert!(verify_inclusion(&leaf_hash(3), 3, &proof).is_err());
    }
}

#[test]
fn verify_inclusion_rejects_consistency_proof_type() {
    let mmr = build_mmr(8);
    let mut proof = mmr.inclusion_proof(0).unwrap();
    proof.proof_type = ProofType::Consistency;
    match verify_inclusion(&leaf_hash(0), 0, &proof) {
        Err(ProofError::InvalidProof { reason }) => {
            assert!(reason.contains("inclusion"), "reason: {reason}");
        }
        other => panic!("expected InvalidProof, got {other:?}"),
    }
}

#[test]
fn verify_inclusion_rejects_out_of_range_index() {
    let mmr = build_mmr(4);
    let proof = mmr.inclusion_proof(0).unwrap();
    match verify_inclusion(&leaf_hash(0), 10, &proof) {
        Err(ProofError::IndexOutOfRange { .. }) => {}
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

// ===========================================================================
// Section 6: Consistency proofs -- generation
// ===========================================================================

#[test]
fn consistency_proof_same_length() {
    let mmr = build_mmr(8);
    let old_root = mmr.root_hash().unwrap();
    let proof = mmr.consistency_proof(8).unwrap();
    assert_eq!(proof.proof_type, ProofType::Consistency);
    assert_eq!(proof.marker_index, 8); // repurposed as old_length
    assert_eq!(proof.stream_length, 8);
    verify_consistency(&old_root, &proof).unwrap();
}

#[test]
fn consistency_proof_power_of_two_prefix() {
    let old_root = build_mmr(4).root_hash().unwrap();
    let new_mmr = build_mmr(8);
    let proof = new_mmr.consistency_proof(4).unwrap();
    verify_consistency(&old_root, &proof).unwrap();
}

#[test]
fn consistency_proof_non_power_of_two_pairs() {
    for (old_n, new_n) in [
        (1, 2),
        (1, 3),
        (1, 4),
        (2, 5),
        (3, 7),
        (5, 10),
        (6, 13),
        (7, 15),
        (8, 16),
        (10, 20),
        (15, 30),
        (1, 100),
    ] {
        let old_root = build_mmr(old_n).root_hash().unwrap();
        let new_mmr = build_mmr(new_n);
        let proof = new_mmr.consistency_proof(old_n).unwrap();
        verify_consistency(&old_root, &proof)
            .unwrap_or_else(|e| panic!("old={old_n}, new={new_n}: {e}"));
    }
}

#[test]
fn consistency_proof_rejects_zero_old_length() {
    let mmr = build_mmr(5);
    match mmr.consistency_proof(0) {
        Err(ProofError::EmptyStream) => {}
        other => panic!("expected EmptyStream, got {other:?}"),
    }
}

#[test]
fn consistency_proof_rejects_old_length_exceeding_current() {
    let mmr = build_mmr(4);
    match mmr.consistency_proof(5) {
        Err(ProofError::ConsistencyFailure {
            old_length: 5,
            new_length: 4,
            ..
        }) => {}
        other => panic!("expected ConsistencyFailure, got {other:?}"),
    }
}

#[test]
fn consistency_proof_carries_epoch() {
    let mmr = build_mmr_epoch(8, 42);
    let proof = mmr.consistency_proof(4).unwrap();
    assert_eq!(proof.epoch_id, 42);
}

// ===========================================================================
// Section 7: Consistency proofs -- verification
// ===========================================================================

#[test]
fn verify_consistency_rejects_wrong_old_root() {
    let new_mmr = build_mmr(8);
    let proof = new_mmr.consistency_proof(4).unwrap();
    let wrong_root = ContentHash([0xaa; 32]);
    assert!(verify_consistency(&wrong_root, &proof).is_err());
}

#[test]
fn verify_consistency_rejects_inclusion_proof_type() {
    let new_mmr = build_mmr(8);
    let old_root = build_mmr(4).root_hash().unwrap();
    let mut proof = new_mmr.consistency_proof(4).unwrap();
    proof.proof_type = ProofType::Inclusion;
    match verify_consistency(&old_root, &proof) {
        Err(ProofError::InvalidProof { reason }) => {
            assert!(reason.contains("consistency"), "reason: {reason}");
        }
        other => panic!("expected InvalidProof, got {other:?}"),
    }
}

#[test]
fn verify_consistency_rejects_zero_old_length() {
    // Construct a fake consistency proof with marker_index = 0
    let mmr = build_mmr(4);
    let root = mmr.root_hash().unwrap();
    let proof = MmrProof {
        proof_type: ProofType::Consistency,
        marker_index: 0,
        proof_hashes: vec![root.clone()],
        root_hash: root.clone(),
        stream_length: 4,
        epoch_id: 1,
    };
    match verify_consistency(&root, &proof) {
        Err(ProofError::EmptyStream) => {}
        other => panic!("expected EmptyStream, got {other:?}"),
    }
}

#[test]
fn verify_consistency_rejects_tampered_proof_hash() {
    let old_root = build_mmr(4).root_hash().unwrap();
    let new_mmr = build_mmr(8);
    let mut proof = new_mmr.consistency_proof(4).unwrap();
    if !proof.proof_hashes.is_empty() {
        proof.proof_hashes[0] = ContentHash([0xff; 32]);
        assert!(verify_consistency(&old_root, &proof).is_err());
    }
}

// ===========================================================================
// Section 8: ProofError -- Display impls
// ===========================================================================

#[test]
fn proof_error_empty_stream_display() {
    assert_eq!(ProofError::EmptyStream.to_string(), "empty stream");
}

#[test]
fn proof_error_index_out_of_range_display() {
    let err = ProofError::IndexOutOfRange {
        index: 42,
        stream_length: 10,
    };
    let msg = err.to_string();
    assert!(msg.contains("42"), "should contain index: {msg}");
    assert!(msg.contains("10"), "should contain stream_length: {msg}");
}

#[test]
fn proof_error_root_mismatch_display() {
    let err = ProofError::RootMismatch {
        expected: ContentHash([0; 32]),
        computed: ContentHash([1; 32]),
    };
    let msg = err.to_string();
    assert!(msg.contains("root hash mismatch"), "msg: {msg}");
}

#[test]
fn proof_error_invalid_proof_display() {
    let err = ProofError::InvalidProof {
        reason: "test reason".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("test reason"), "msg: {msg}");
    assert!(msg.contains("invalid proof"), "msg: {msg}");
}

#[test]
fn proof_error_consistency_failure_display() {
    let err = ProofError::ConsistencyFailure {
        old_length: 3,
        new_length: 10,
        reason: "prefix mismatch".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("consistency failure"), "msg: {msg}");
    assert!(msg.contains("prefix mismatch"), "msg: {msg}");
}

#[test]
fn proof_error_is_std_error() {
    let err = ProofError::EmptyStream;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// Section 9: ProofType equality and clone
// ===========================================================================

#[test]
fn proof_type_equality() {
    assert_eq!(ProofType::Inclusion, ProofType::Inclusion);
    assert_eq!(ProofType::Consistency, ProofType::Consistency);
    assert_ne!(ProofType::Inclusion, ProofType::Consistency);
}

#[test]
fn proof_type_clone() {
    let pt = ProofType::Inclusion;
    let cloned = pt.clone();
    assert_eq!(pt, cloned);
}

#[test]
fn proof_type_debug() {
    let dbg = format!("{:?}", ProofType::Inclusion);
    assert!(dbg.contains("Inclusion"), "debug: {dbg}");
}

// ===========================================================================
// Section 10: MmrProof equality and clone
// ===========================================================================

#[test]
fn mmr_proof_clone_equals_original() {
    let mmr = build_mmr(8);
    let proof = mmr.inclusion_proof(3).unwrap();
    let cloned = proof.clone();
    assert_eq!(proof, cloned);
}

#[test]
fn mmr_proof_debug_is_non_empty() {
    let mmr = build_mmr(4);
    let proof = mmr.inclusion_proof(1).unwrap();
    let dbg = format!("{proof:?}");
    assert!(!dbg.is_empty());
}

// ===========================================================================
// Section 11: Serde round-trips
// ===========================================================================

#[test]
fn proof_type_serde_round_trip() {
    for pt in [ProofType::Inclusion, ProofType::Consistency] {
        let json = serde_json::to_string(&pt).unwrap();
        let restored: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(pt, restored);
    }
}

#[test]
fn mmr_proof_serde_round_trip() {
    let mmr = build_mmr(16);
    for i in [0, 3, 7, 15] {
        let proof = mmr.inclusion_proof(i).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MmrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, restored, "round-trip failed for index {i}");
    }
}

#[test]
fn mmr_consistency_proof_serde_round_trip() {
    let mmr = build_mmr(16);
    let proof = mmr.consistency_proof(8).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let restored: MmrProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, restored);
}

#[test]
fn proof_error_serde_round_trip_all_variants() {
    let errors = [
        ProofError::EmptyStream,
        ProofError::IndexOutOfRange {
            index: 99,
            stream_length: 50,
        },
        ProofError::RootMismatch {
            expected: ContentHash([0xaa; 32]),
            computed: ContentHash([0xbb; 32]),
        },
        ProofError::InvalidProof {
            reason: "bad proof data".to_string(),
        },
        ProofError::ConsistencyFailure {
            old_length: 10,
            new_length: 20,
            reason: "mismatch".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ProofError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "round-trip failed for {err:?}");
    }
}

#[test]
fn deserialized_proof_still_verifies() {
    let mmr = build_mmr(32);
    let proof = mmr.inclusion_proof(17).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let restored: MmrProof = serde_json::from_str(&json).unwrap();
    verify_inclusion(&leaf_hash(17), 17, &restored).unwrap();
}

#[test]
fn deserialized_consistency_proof_still_verifies() {
    let old_root = build_mmr(10).root_hash().unwrap();
    let new_mmr = build_mmr(20);
    let proof = new_mmr.consistency_proof(10).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let restored: MmrProof = serde_json::from_str(&json).unwrap();
    verify_consistency(&old_root, &restored).unwrap();
}

// ===========================================================================
// Section 12: Deterministic replay
// ===========================================================================

#[test]
fn identical_append_sequences_produce_identical_roots() {
    for n in [1, 10, 50, 100] {
        let r1 = build_mmr(n).root_hash().unwrap();
        let r2 = build_mmr(n).root_hash().unwrap();
        assert_eq!(r1, r2, "replay mismatch for n={n}");
    }
}

#[test]
fn identical_append_sequences_produce_identical_proofs() {
    for n in [4, 8, 16, 32] {
        let mmr1 = build_mmr(n);
        let mmr2 = build_mmr(n);
        for i in 0..n {
            let p1 = mmr1.inclusion_proof(i).unwrap();
            let p2 = mmr2.inclusion_proof(i).unwrap();
            assert_eq!(p1, p2, "proof mismatch at n={n}, i={i}");
        }
    }
}

#[test]
fn identical_sequences_produce_identical_consistency_proofs() {
    for (old_n, new_n) in [(4, 8), (3, 7), (5, 10)] {
        let proof1 = build_mmr(new_n).consistency_proof(old_n).unwrap();
        let proof2 = build_mmr(new_n).consistency_proof(old_n).unwrap();
        assert_eq!(
            proof1, proof2,
            "consistency mismatch old={old_n}, new={new_n}"
        );
    }
}

#[test]
fn peaks_deterministic_across_replays() {
    for n in [1, 3, 5, 7, 10, 16, 31, 32] {
        let p1 = build_mmr(n).peaks();
        let p2 = build_mmr(n).peaks();
        assert_eq!(p1, p2, "peaks mismatch for n={n}");
    }
}

// ===========================================================================
// Section 13: Cross-cutting scenarios
// ===========================================================================

#[test]
fn proof_after_incremental_growth() {
    let mut mmr = MerkleMountainRange::new(1);
    // Add 4 leaves, prove all
    for i in 0..4 {
        mmr.append(leaf_hash(i));
    }
    for i in 0..4 {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap();
    }

    // Capture old root and state
    let old_root = mmr.root_hash().unwrap();
    let old_length = mmr.num_leaves();

    // Add more leaves
    for i in 4..10 {
        mmr.append(leaf_hash(i));
    }

    // Old proofs no longer valid (root changed)
    // But consistency proof from old to new should work
    let consistency = mmr.consistency_proof(old_length).unwrap();
    verify_consistency(&old_root, &consistency).unwrap();

    // New inclusion proofs work for all leaves
    for i in 0..10 {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap();
    }
}

#[test]
fn multiple_consistency_proofs_chain() {
    // Build in stages and verify consistency at each step
    let mut roots = Vec::new();
    let mut lengths = Vec::new();

    for step in [4, 8, 12, 16, 20] {
        let mmr = build_mmr(step);
        roots.push(mmr.root_hash().unwrap());
        lengths.push(step);
    }

    // Each step should be consistent with all later steps
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            let new_mmr = build_mmr(lengths[j]);
            let proof = new_mmr.consistency_proof(lengths[i]).unwrap();
            verify_consistency(&roots[i], &proof).unwrap_or_else(|e| {
                panic!(
                    "consistency chain failed: {} -> {}: {e}",
                    lengths[i], lengths[j]
                )
            });
        }
    }
}

#[test]
fn inclusion_proof_verified_against_different_mmr_with_same_prefix_fails() {
    let mmr_a = build_mmr(8);
    let proof_a = mmr_a.inclusion_proof(3).unwrap();

    // Build an MMR with the same first 8 leaves plus more
    let mmr_b = build_mmr(16);
    let proof_b = mmr_b.inclusion_proof(3).unwrap();

    // The proof from mmr_a should not verify against mmr_b's root
    assert_ne!(proof_a.root_hash, proof_b.root_hash);
}

#[test]
fn epoch_id_does_not_affect_root_hash() {
    let mmr_e1 = build_mmr_epoch(10, 1);
    let mmr_e2 = build_mmr_epoch(10, 999);
    assert_eq!(
        mmr_e1.root_hash().unwrap(),
        mmr_e2.root_hash().unwrap(),
        "epoch should not affect root hash"
    );
}

#[test]
fn large_mmr_all_inclusion_proofs_verify() {
    let mmr = build_mmr(256);
    // Verify a spread of leaf indices
    for i in (0..256).step_by(17) {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap_or_else(|e| panic!("index {i}: {e}"));
    }
}

#[test]
fn custom_leaf_content_inclusion_roundtrip() {
    let mut mmr = MerkleMountainRange::new(5);
    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("payload-{i}").into_bytes())
        .collect();
    let hashes: Vec<ContentHash> = payloads.iter().map(|p| ContentHash::compute(p)).collect();

    for h in &hashes {
        mmr.append(h.clone());
    }

    for (i, h) in hashes.iter().enumerate() {
        let proof = mmr.inclusion_proof(i as u64).unwrap();
        verify_inclusion(h, i as u64, &proof).unwrap();
    }
}

// ===========================================================================
// Section 14: ProofError equality
// ===========================================================================

#[test]
fn proof_error_equality() {
    assert_eq!(ProofError::EmptyStream, ProofError::EmptyStream);
    assert_ne!(
        ProofError::EmptyStream,
        ProofError::InvalidProof {
            reason: "x".to_string()
        }
    );
    assert_eq!(
        ProofError::IndexOutOfRange {
            index: 1,
            stream_length: 2,
        },
        ProofError::IndexOutOfRange {
            index: 1,
            stream_length: 2,
        },
    );
    assert_ne!(
        ProofError::IndexOutOfRange {
            index: 1,
            stream_length: 2,
        },
        ProofError::IndexOutOfRange {
            index: 3,
            stream_length: 4,
        },
    );
}

#[test]
fn proof_error_clone() {
    let err = ProofError::ConsistencyFailure {
        old_length: 5,
        new_length: 10,
        reason: "clone test".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

// ===========================================================================
// Section 15: Boundary conditions
// ===========================================================================

#[test]
fn mmr_with_exactly_one_leaf_consistency_to_self() {
    let mmr = build_mmr(1);
    let root = mmr.root_hash().unwrap();
    let proof = mmr.consistency_proof(1).unwrap();
    verify_consistency(&root, &proof).unwrap();
}

#[test]
fn mmr_three_leaves_all_proofs() {
    // 3 leaves = binary 11 = 2 peaks
    let mmr = build_mmr(3);
    for i in 0..3 {
        let proof = mmr.inclusion_proof(i).unwrap();
        verify_inclusion(&leaf_hash(i), i, &proof).unwrap_or_else(|e| panic!("leaf {i}: {e}"));
    }
    // Consistency from 1, 2 to 3
    for old_n in 1..=3 {
        let old_root = build_mmr(old_n).root_hash().unwrap();
        let proof = mmr.consistency_proof(old_n).unwrap();
        verify_consistency(&old_root, &proof)
            .unwrap_or_else(|e| panic!("consistency {old_n}->3: {e}"));
    }
}

#[test]
fn inclusion_proof_on_empty_mmr_fails() {
    let mmr = MerkleMountainRange::new(1);
    match mmr.inclusion_proof(0) {
        Err(ProofError::IndexOutOfRange {
            index: 0,
            stream_length: 0,
        }) => {}
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn consistency_proof_from_empty_mmr_fails() {
    let mmr = MerkleMountainRange::new(1);
    // old_length=0 => EmptyStream
    match mmr.consistency_proof(0) {
        Err(ProofError::EmptyStream) => {}
        other => panic!("expected EmptyStream, got {other:?}"),
    }
    // old_length=1 but mmr has 0 leaves => ConsistencyFailure
    match mmr.consistency_proof(1) {
        Err(ProofError::ConsistencyFailure { .. }) => {}
        other => panic!("expected ConsistencyFailure, got {other:?}"),
    }
}
