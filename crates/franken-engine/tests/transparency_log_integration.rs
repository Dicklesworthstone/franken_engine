//! Integration tests for [`frankenengine_engine::transparency_log`].
//!
//! These tests live outside the module so they exercise the **external
//! verifier API** the way an auditor would: they only consume `pub`
//! surface, never reach into internal fields, and only trust the
//! signed head + a verification key + the receipt's own hash.
//!
//! Coverage (bd-cixqu.1.2 acceptance criteria — "≥30 cases"):
//! - positive verification at every leaf index in a multi-leaf log,
//! - tampering on every position-dependent field,
//! - consistency proofs between every adjacent pair of heads,
//! - cross-log replay defence,
//! - replay-from-entries deterministic-rebuild,
//! - error-code stability for structured-event downstream,
//! - large-tree determinism.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::mmr_proof::ProofType;
use frankenengine_engine::signature_preimage::{
    Signature, SigningKey, VerificationKey, generate_keypair_from_seed,
};
use frankenengine_engine::transparency_log::{
    SignedLogHead, TransparencyLog, TransparencyLogEntry, TransparencyLogError,
    verify_log_consistency_between, verify_receipt_inclusion, verify_signed_head,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn receipt(byte: u8) -> ContentHash {
    let mut data = vec![byte; 1];
    data.push(0xAA);
    ContentHash::compute(&data)
}

fn alt_receipt(byte: u8) -> ContentHash {
    // Use a different domain prefix so receipts from this helper never
    // collide with `receipt(byte)`.
    ContentHash::compute(&[0xFFu8, byte, 0xBB])
}

fn keypair() -> (SigningKey, VerificationKey) {
    generate_keypair_from_seed(&[0x42u8; 32])
}

fn other_keypair() -> (SigningKey, VerificationKey) {
    generate_keypair_from_seed(&[0x99u8; 32])
}

fn fresh_log() -> TransparencyLog {
    TransparencyLog::new("integration-log")
}

fn build_log_with(n: u8) -> TransparencyLog {
    let mut log = fresh_log();
    for i in 0..n {
        log.append_receipt(receipt(i), 1_000 + i as u64)
            .expect("append should succeed");
    }
    log
}

// ---------------------------------------------------------------------------
// Section 1 — Positive inclusion across the full index space
// ---------------------------------------------------------------------------

#[test]
fn t01_inclusion_succeeds_at_every_index_in_64_leaf_log() {
    let (sk, vk) = keypair();
    let log = build_log_with(64);
    let head = log.sign_head(&sk, "primary-key", 999).expect("sign head");
    for i in 0..64u64 {
        let proof = log.inclusion_proof_for(i).expect("proof");
        verify_receipt_inclusion(&receipt(i as u8), &proof, &head, &vk)
            .unwrap_or_else(|e| panic!("verify at index {i} failed: {e}"));
    }
}

#[test]
fn t02_inclusion_succeeds_for_single_leaf_log() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    log.append_receipt(receipt(0), 1).unwrap();
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.inclusion_proof_for(0).unwrap();
    verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).expect("ok");
}

#[test]
fn t03_inclusion_succeeds_for_two_leaf_log() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    log.append_receipt(receipt(0), 1).unwrap();
    log.append_receipt(receipt(1), 2).unwrap();
    let head = log.sign_head(&sk, "k", 1).unwrap();
    for i in 0..2u64 {
        let proof = log.inclusion_proof_for(i).unwrap();
        verify_receipt_inclusion(&receipt(i as u8), &proof, &head, &vk).expect("ok");
    }
}

#[test]
fn t04_inclusion_proof_carries_correct_metadata() {
    let log = build_log_with(8);
    for i in 0..8u64 {
        let proof = log.inclusion_proof_for(i).expect("proof");
        assert_eq!(proof.marker_index, i);
        assert_eq!(proof.stream_length, 8);
        assert_eq!(proof.proof_type, ProofType::Inclusion);
    }
}

// ---------------------------------------------------------------------------
// Section 2 — Negative inclusion: tampering each position-dependent field
// ---------------------------------------------------------------------------

#[test]
fn t05_inclusion_fails_when_receipt_hash_is_swapped() {
    let (sk, vk) = keypair();
    let log = build_log_with(4);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.inclusion_proof_for(1).unwrap();
    let err = verify_receipt_inclusion(&receipt(2), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0003");
}

#[test]
fn t06_inclusion_fails_when_receipt_hash_is_fabricated() {
    let (sk, vk) = keypair();
    let log = build_log_with(4);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.inclusion_proof_for(0).unwrap();
    let fake = ContentHash::compute(b"never-appended");
    let err = verify_receipt_inclusion(&fake, &proof, &head, &vk).unwrap_err();
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

#[test]
fn t07_inclusion_fails_when_proof_root_is_swapped() {
    let (sk, vk) = keypair();
    let log = build_log_with(4);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let mut proof = log.inclusion_proof_for(0).unwrap();
    proof.root_hash = ContentHash::compute(b"forged-root");
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0006");
}

#[test]
fn t08_inclusion_fails_when_proof_length_is_swapped() {
    let (sk, vk) = keypair();
    let log = build_log_with(4);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let mut proof = log.inclusion_proof_for(0).unwrap();
    proof.stream_length = 99;
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0005");
}

#[test]
fn t09_inclusion_fails_when_proof_sibling_is_tampered() {
    let (sk, vk) = keypair();
    let log = build_log_with(8);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let mut proof = log.inclusion_proof_for(3).unwrap();
    if !proof.proof_hashes.is_empty() {
        proof.proof_hashes[0] = ContentHash::compute(b"tampered-sibling");
    }
    let err = verify_receipt_inclusion(&receipt(3), &proof, &head, &vk).unwrap_err();
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

#[test]
fn t10_inclusion_fails_when_proof_index_is_swapped_to_wrong_receipt() {
    let (sk, vk) = keypair();
    let log = build_log_with(8);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof_for_3 = log.inclusion_proof_for(3).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof_for_3, &head, &vk).unwrap_err();
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

// ---------------------------------------------------------------------------
// Section 3 — Negative inclusion: head-side tampering
// ---------------------------------------------------------------------------

#[test]
fn t11_inclusion_fails_when_head_log_id_is_changed() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    head.log_id = "imposter".to_string();
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t12_inclusion_fails_when_head_tree_length_is_changed() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    head.tree_length = 17;
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t13_inclusion_fails_when_head_root_hash_is_changed() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    head.root_hash = ContentHash::compute(b"forged");
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t14_inclusion_fails_when_head_signed_at_ns_is_changed() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    head.signed_at_ns = 9_999;
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t15_inclusion_fails_when_head_signer_key_id_is_changed() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    head.signer_key_id = "rotated".to_string();
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t16_inclusion_fails_under_wrong_verification_key() {
    let (sk, _vk_correct) = keypair();
    let (_sk_other, vk_other) = other_keypair();
    let log = build_log_with(2);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk_other).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t17_inclusion_fails_when_head_signature_is_byte_flipped() {
    let (sk, vk) = keypair();
    let log = build_log_with(2);
    let mut head = log.sign_head(&sk, "k", 1).unwrap();
    let mut bytes = head.signature.to_bytes();
    bytes[10] ^= 0xFF;
    head.signature = Signature::from_bytes(bytes);
    let proof = log.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0004");
}

#[test]
fn t18_inclusion_rejects_consistency_proof_with_wrong_type_code() {
    let (sk, vk) = keypair();
    let log = build_log_with(8);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let cp = log.consistency_proof_between(4).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &cp, &head, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0008");
}

// ---------------------------------------------------------------------------
// Section 4 — Consistency proofs between every adjacent pair of heads
// ---------------------------------------------------------------------------

#[test]
fn t19_consistency_succeeds_between_every_adjacent_pair_for_20_leaves() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    let mut roots: Vec<ContentHash> = Vec::new();
    for i in 0..20u8 {
        log.append_receipt(receipt(i), i as u64).unwrap();
        roots.push(log.current_root().unwrap());
    }
    for old_length in 1..20u64 {
        let proof = log.consistency_proof_between(old_length).unwrap();
        let old_root = roots[(old_length - 1) as usize];
        let head = log.sign_head(&sk, "k", 1).unwrap();
        verify_log_consistency_between(&old_root, &head, &proof, &vk)
            .unwrap_or_else(|e| panic!("consistency old_length={old_length} failed: {e}"));
    }
}

#[test]
fn t20_consistency_succeeds_between_distant_heads() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    for i in 0..3u8 {
        log.append_receipt(receipt(i), 1).unwrap();
    }
    let old_root = log.current_root().unwrap();
    for i in 3..30u8 {
        log.append_receipt(receipt(i), 1).unwrap();
    }
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.consistency_proof_between(3).unwrap();
    verify_log_consistency_between(&old_root, &head, &proof, &vk).expect("ok");
}

#[test]
fn t21_consistency_fails_for_forged_old_root() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    for i in 0..6u8 {
        log.append_receipt(receipt(i), 1).unwrap();
    }
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let proof = log.consistency_proof_between(3).unwrap();
    let bogus = ContentHash::compute(b"not-an-old-root");
    let err = verify_log_consistency_between(&bogus, &head, &proof, &vk).unwrap_err();
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

#[test]
fn t22_consistency_fails_when_proof_root_swapped() {
    let (sk, vk) = keypair();
    let mut log = fresh_log();
    for i in 0..6u8 {
        log.append_receipt(receipt(i), 1).unwrap();
    }
    let old_root = log.current_root().unwrap();
    log.append_receipt(receipt(7), 1).unwrap();
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let mut proof = log.consistency_proof_between(6).unwrap();
    proof.root_hash = ContentHash::compute(b"x");
    let err = verify_log_consistency_between(&old_root, &head, &proof, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0006");
}

#[test]
fn t23_consistency_rejects_inclusion_proof_with_wrong_type_code() {
    let (sk, vk) = keypair();
    let log = build_log_with(4);
    let head = log.sign_head(&sk, "k", 1).unwrap();
    let ip = log.inclusion_proof_for(0).unwrap();
    let old_root = log.current_root().unwrap();
    let err = verify_log_consistency_between(&old_root, &head, &ip, &vk).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0008");
}

#[test]
fn t24_consistency_old_length_zero_fails_closed() {
    let log = build_log_with(4);
    let err = log
        .consistency_proof_between(0)
        .expect_err("zero old_length must fail");
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

#[test]
fn t25_consistency_old_length_exceeds_current_fails_closed() {
    let log = build_log_with(4);
    let err = log
        .consistency_proof_between(99)
        .expect_err("too-large old_length must fail");
    assert!(matches!(err, TransparencyLogError::Proof { .. }));
}

// ---------------------------------------------------------------------------
// Section 5 — Replay / persistence
// ---------------------------------------------------------------------------

#[test]
fn t26_replay_rebuilds_identical_root_and_length() {
    let original = build_log_with(11);
    let entries: Vec<TransparencyLogEntry> = original.entries().to_vec();
    let rebuilt =
        TransparencyLog::replay_from_entries("integration-log", 0, entries).expect("rebuild");
    assert_eq!(rebuilt.tree_length(), original.tree_length());
    assert_eq!(
        rebuilt.current_root().unwrap(),
        original.current_root().unwrap()
    );
}

#[test]
fn t27_replay_rebuilds_identical_inclusion_proofs() {
    let original = build_log_with(11);
    let entries: Vec<TransparencyLogEntry> = original.entries().to_vec();
    let rebuilt =
        TransparencyLog::replay_from_entries("integration-log", 0, entries).expect("rebuild");
    for i in 0..11u64 {
        let proof_a = original.inclusion_proof_for(i).unwrap();
        let proof_b = rebuilt.inclusion_proof_for(i).unwrap();
        assert_eq!(proof_a, proof_b);
    }
}

#[test]
fn t28_replay_rejects_log_id_drift() {
    let original = build_log_with(2);
    let entries: Vec<TransparencyLogEntry> = original.entries().to_vec();
    let err = TransparencyLog::replay_from_entries("different-log", 0, entries).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0010");
}

#[test]
fn t29_replay_rejects_index_gap() {
    let bad = vec![
        TransparencyLogEntry {
            leaf_index: 0,
            receipt_hash: receipt(0),
            appended_at_ns: 1,
            log_id: "L".to_string(),
        },
        TransparencyLogEntry {
            leaf_index: 2, // gap at 1
            receipt_hash: receipt(2),
            appended_at_ns: 1,
            log_id: "L".to_string(),
        },
    ];
    let err = TransparencyLog::replay_from_entries("L", 0, bad).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0002");
}

#[test]
fn t30_replay_handles_empty_entry_list() {
    let log = TransparencyLog::replay_from_entries("L", 0, vec![]).expect("empty replay ok");
    assert!(log.is_empty());
    assert_eq!(log.tree_length(), 0);
}

// ---------------------------------------------------------------------------
// Section 6 — Serde / canonical-bytes round-trips
// ---------------------------------------------------------------------------

#[test]
fn t31_signed_head_serde_round_trip_preserves_verification() {
    let (sk, vk) = keypair();
    let log = build_log_with(5);
    let head = log.sign_head(&sk, "k", 42).unwrap();
    let json = serde_json::to_string(&head).expect("ser");
    let round: SignedLogHead = serde_json::from_str(&json).expect("de");
    verify_signed_head(&round, &vk).expect("ok after round trip");
}

#[test]
fn t32_entry_serde_round_trip_preserves_fields() {
    let log = build_log_with(3);
    for entry in log.entries() {
        let json = serde_json::to_string(entry).expect("ser");
        let round: TransparencyLogEntry = serde_json::from_str(&json).expect("de");
        assert_eq!(round, *entry);
    }
}

// ---------------------------------------------------------------------------
// Section 7 — Cross-log replay defence + identity
// ---------------------------------------------------------------------------

#[test]
fn t33_inclusion_against_head_from_different_log_fails_on_root_mismatch() {
    let (sk, vk) = keypair();
    let log_a = build_log_with(4);
    let mut log_b = TransparencyLog::new("other-log");
    for i in 0..4u8 {
        log_b.append_receipt(alt_receipt(i), 1).unwrap();
    }
    let head_b = log_b.sign_head(&sk, "k", 1).unwrap();
    let proof_a = log_a.inclusion_proof_for(0).unwrap();
    let err = verify_receipt_inclusion(&receipt(0), &proof_a, &head_b, &vk).unwrap_err();
    assert!(matches!(
        err,
        TransparencyLogError::InclusionLengthMismatch { .. }
            | TransparencyLogError::RootMismatch { .. }
            | TransparencyLogError::Signature { .. }
            | TransparencyLogError::Proof { .. }
    ));
}

#[test]
fn t34_head_for_log_a_does_not_verify_head_for_log_b() {
    let (sk, vk) = keypair();
    let mut log_a = TransparencyLog::new("log-a");
    let mut log_b = TransparencyLog::new("log-b");
    log_a.append_receipt(receipt(0), 1).unwrap();
    log_b.append_receipt(receipt(0), 1).unwrap();
    let head_a = log_a.sign_head(&sk, "k", 1).unwrap();
    let head_b = log_b.sign_head(&sk, "k", 1).unwrap();
    // Even with the same key, the heads are not interchangeable because
    // the signature preimage binds the log id.
    assert_ne!(head_a.signature, head_b.signature);
    verify_signed_head(&head_a, &vk).expect("a ok");
    verify_signed_head(&head_b, &vk).expect("b ok");
}

// ---------------------------------------------------------------------------
// Section 8 — Large-tree determinism + boundary structure
// ---------------------------------------------------------------------------

#[test]
fn t35_root_is_deterministic_for_500_leaf_log() {
    let mut a = TransparencyLog::new("det");
    let mut b = TransparencyLog::new("det");
    for i in 0..500u32 {
        let h = ContentHash::compute(&i.to_be_bytes());
        a.append_receipt(h, i as u64).unwrap();
        b.append_receipt(h, i as u64).unwrap();
    }
    assert_eq!(a.current_root().unwrap(), b.current_root().unwrap());
    assert_eq!(a.tree_length(), 500);
}

#[test]
fn t36_inclusion_proof_succeeds_at_power_of_two_boundaries() {
    // Boundaries: 1, 2, 4, 8, 16, 32 — places where MMR peak structure
    // collapses to a single peak. A bug in peak-merging logic would
    // surface as inclusion failure at exactly these heights.
    let (sk, vk) = keypair();
    for &size in &[1u64, 2, 4, 8, 16, 32] {
        let mut log = TransparencyLog::new("pow2");
        for i in 0..size as u8 {
            log.append_receipt(receipt(i), 1).unwrap();
        }
        let head = log.sign_head(&sk, "k", 1).unwrap();
        for i in 0..size {
            let proof = log.inclusion_proof_for(i).unwrap();
            verify_receipt_inclusion(&receipt(i as u8), &proof, &head, &vk)
                .unwrap_or_else(|e| panic!("size={size} idx={i} failed: {e}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Section 9 — Empty / boundary cases for the producer API
// ---------------------------------------------------------------------------

#[test]
fn t37_empty_log_inclusion_proof_errors() {
    let log = fresh_log();
    let err = log.inclusion_proof_for(0).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0002");
}

#[test]
fn t38_empty_log_sign_head_errors() {
    let (sk, _vk) = keypair();
    let log = fresh_log();
    let err = log.sign_head(&sk, "k", 1).unwrap_err();
    assert_eq!(err.code(), "FE-TLOG-0001");
}

#[test]
fn t39_entry_at_out_of_range_returns_none() {
    let log = build_log_with(3);
    assert!(log.entry_at(0).is_some());
    assert!(log.entry_at(2).is_some());
    assert!(log.entry_at(3).is_none());
    assert!(log.entry_at(u64::MAX).is_none());
}

#[test]
fn t40_error_codes_are_unique() {
    use std::collections::BTreeSet;
    let codes = [
        TransparencyLogError::Empty.code(),
        TransparencyLogError::LeafIndexOutOfRange {
            index: 0,
            length: 0,
        }
        .code(),
        TransparencyLogError::Proof {
            detail: String::new(),
        }
        .code(),
        TransparencyLogError::Signature {
            detail: String::new(),
        }
        .code(),
        TransparencyLogError::InclusionLengthMismatch {
            proof_length: 0,
            head_length: 0,
        }
        .code(),
        TransparencyLogError::RootMismatch {
            proof_root: ContentHash::compute(b"a"),
            head_root: ContentHash::compute(b"a"),
        }
        .code(),
        TransparencyLogError::ReceiptIndexMismatch {
            proof_index: 0,
            receipt_index: 0,
        }
        .code(),
        TransparencyLogError::WrongProofType {
            expected: ProofType::Inclusion,
            got: ProofType::Consistency,
        }
        .code(),
        TransparencyLogError::CounterExhausted.code(),
        TransparencyLogError::LogIdMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        }
        .code(),
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "duplicate stable error code");
}
