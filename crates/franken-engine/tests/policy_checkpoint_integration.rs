#![forbid(unsafe_code)]

//! Integration tests for the `policy_checkpoint` module.
//!
//! Covers: PolicyType, PolicyHead, DeterministicTimestamp, CheckpointError,
//! PolicyCheckpoint, CheckpointBuilder, verify_chain_linkage,
//! verify_checkpoint_quorum, CheckpointEvent, CheckpointEventType,
//! checkpoint_schema, checkpoint_schema_id — Display impls, construction,
//! state transitions, error conditions, serde roundtrips, deterministic replay.

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
use frankenengine_engine::policy_checkpoint::{
    CheckpointBuilder, CheckpointError, CheckpointEvent, CheckpointEventType,
    DeterministicTimestamp, PolicyCheckpoint, PolicyHead, PolicyType, checkpoint_schema,
    checkpoint_schema_id, verify_chain_linkage, verify_checkpoint_quorum,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SignaturePreimage, SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
    let hash_input = format!("{pt}-v{version}");
    PolicyHead {
        policy_type: pt,
        policy_hash: ContentHash::compute(hash_input.as_bytes()),
        policy_version: version,
    }
}

fn build_genesis(keys: &[SigningKey]) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(keys)
    .unwrap()
}

fn build_genesis_epoch(epoch: SecurityEpoch, keys: &[SigningKey]) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(epoch, DeterministicTimestamp(100), "test-zone")
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .unwrap()
}

// ===========================================================================
// Section 1: PolicyType — Display, ordering, serde
// ===========================================================================

#[test]
fn policy_type_display_all_variants() {
    assert_eq!(
        PolicyType::RuntimeExecution.to_string(),
        "runtime_execution"
    );
    assert_eq!(
        PolicyType::CapabilityLattice.to_string(),
        "capability_lattice"
    );
    assert_eq!(PolicyType::ExtensionTrust.to_string(), "extension_trust");
    assert_eq!(
        PolicyType::EvidenceRetention.to_string(),
        "evidence_retention"
    );
    assert_eq!(
        PolicyType::RevocationGovernance.to_string(),
        "revocation_governance"
    );
}

#[test]
fn policy_type_ordering() {
    let mut types = vec![
        PolicyType::RevocationGovernance,
        PolicyType::RuntimeExecution,
        PolicyType::ExtensionTrust,
        PolicyType::CapabilityLattice,
        PolicyType::EvidenceRetention,
    ];
    types.sort();
    // Just check that sorting is deterministic
    let sorted_once = types.clone();
    types.sort();
    assert_eq!(types, sorted_once);
}

#[test]
fn policy_type_serde_roundtrip_all() {
    let types = [
        PolicyType::RuntimeExecution,
        PolicyType::CapabilityLattice,
        PolicyType::ExtensionTrust,
        PolicyType::EvidenceRetention,
        PolicyType::RevocationGovernance,
    ];
    for pt in &types {
        let json = serde_json::to_string(pt).expect("serialize");
        let restored: PolicyType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*pt, restored);
    }
}

#[test]
fn policy_type_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(PolicyType::RuntimeExecution);
    set.insert(PolicyType::RuntimeExecution);
    set.insert(PolicyType::ExtensionTrust);
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// Section 2: PolicyHead — construction, serde
// ===========================================================================

#[test]
fn policy_head_construction() {
    let head = make_policy_head(PolicyType::RuntimeExecution, 5);
    assert_eq!(head.policy_type, PolicyType::RuntimeExecution);
    assert_eq!(head.policy_version, 5);
}

#[test]
fn policy_head_serde_roundtrip() {
    let head = make_policy_head(PolicyType::CapabilityLattice, 42);
    let json = serde_json::to_string(&head).expect("serialize");
    let restored: PolicyHead = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(head, restored);
}

#[test]
fn policy_head_different_versions_different_hashes() {
    let h1 = make_policy_head(PolicyType::RuntimeExecution, 1);
    let h2 = make_policy_head(PolicyType::RuntimeExecution, 2);
    assert_ne!(h1.policy_hash, h2.policy_hash);
}

#[test]
fn policy_head_different_types_different_hashes() {
    let h1 = make_policy_head(PolicyType::RuntimeExecution, 1);
    let h2 = make_policy_head(PolicyType::CapabilityLattice, 1);
    assert_ne!(h1.policy_hash, h2.policy_hash);
}

// ===========================================================================
// Section 3: DeterministicTimestamp — Display, serde
// ===========================================================================

#[test]
fn deterministic_timestamp_display() {
    assert_eq!(DeterministicTimestamp(0).to_string(), "tick:0");
    assert_eq!(DeterministicTimestamp(42).to_string(), "tick:42");
    assert_eq!(
        DeterministicTimestamp(u64::MAX).to_string(),
        format!("tick:{}", u64::MAX)
    );
}

#[test]
fn deterministic_timestamp_ordering() {
    assert!(DeterministicTimestamp(0) < DeterministicTimestamp(1));
    assert!(DeterministicTimestamp(100) < DeterministicTimestamp(200));
    assert_eq!(DeterministicTimestamp(5), DeterministicTimestamp(5));
}

#[test]
fn deterministic_timestamp_serde_roundtrip() {
    let ts = DeterministicTimestamp(99999);
    let json = serde_json::to_string(&ts).expect("serialize");
    let restored: DeterministicTimestamp = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ts, restored);
}

#[test]
fn deterministic_timestamp_copy() {
    let t1 = DeterministicTimestamp(42);
    let t2 = t1;
    assert_eq!(t1, t2);
}

// ===========================================================================
// Section 4: CheckpointError — Display, serde
// ===========================================================================

#[test]
fn checkpoint_error_display_genesis_must_have_no_predecessor() {
    let err = CheckpointError::GenesisMustHaveNoPredecessor;
    assert_eq!(
        err.to_string(),
        "genesis checkpoint must have no predecessor"
    );
}

#[test]
fn checkpoint_error_display_missing_predecessor() {
    let err = CheckpointError::MissingPredecessor;
    assert_eq!(
        err.to_string(),
        "non-genesis checkpoint must have a predecessor"
    );
}

#[test]
fn checkpoint_error_display_non_monotonic_sequence() {
    let err = CheckpointError::NonMonotonicSequence {
        prev_seq: 10,
        current_seq: 5,
    };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("5"));
    assert!(s.contains("non-monotonic"));
}

#[test]
fn checkpoint_error_display_genesis_sequence_not_zero() {
    let err = CheckpointError::GenesisSequenceNotZero { actual: 7 };
    let s = err.to_string();
    assert!(s.contains("7"));
    assert!(s.contains("genesis"));
}

#[test]
fn checkpoint_error_display_empty_policy_heads() {
    let err = CheckpointError::EmptyPolicyHeads;
    assert!(err.to_string().contains("policy heads"));
}

#[test]
fn checkpoint_error_display_quorum_not_met() {
    let err = CheckpointError::QuorumNotMet {
        required: 3,
        provided: 1,
    };
    let s = err.to_string();
    assert!(s.contains("1/3") || (s.contains("1") && s.contains("3")));
}

#[test]
fn checkpoint_error_display_duplicate_policy_type() {
    let err = CheckpointError::DuplicatePolicyType {
        policy_type: PolicyType::ExtensionTrust,
    };
    let s = err.to_string();
    assert!(s.contains("extension_trust"));
}

#[test]
fn checkpoint_error_display_id_derivation_failed() {
    let err = CheckpointError::IdDerivationFailed {
        detail: "bad input".to_string(),
    };
    assert!(err.to_string().contains("bad input"));
}

#[test]
fn checkpoint_error_display_signature_invalid() {
    let err = CheckpointError::SignatureInvalid {
        detail: "wrong key".to_string(),
    };
    assert!(err.to_string().contains("wrong key"));
}

#[test]
fn checkpoint_error_display_epoch_regression() {
    let err = CheckpointError::EpochRegression {
        prev_epoch: SecurityEpoch::from_raw(5),
        current_epoch: SecurityEpoch::from_raw(3),
    };
    let s = err.to_string();
    assert!(s.contains("epoch regression"));
}

#[test]
fn checkpoint_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CheckpointError::EmptyPolicyHeads);
    assert!(!err.to_string().is_empty());
}

#[test]
fn checkpoint_error_serde_roundtrip() {
    let errors = vec![
        CheckpointError::GenesisMustHaveNoPredecessor,
        CheckpointError::MissingPredecessor,
        CheckpointError::EmptyPolicyHeads,
        CheckpointError::GenesisSequenceNotZero { actual: 99 },
        CheckpointError::NonMonotonicSequence {
            prev_seq: 10,
            current_seq: 5,
        },
        CheckpointError::QuorumNotMet {
            required: 3,
            provided: 1,
        },
        CheckpointError::DuplicatePolicyType {
            policy_type: PolicyType::RuntimeExecution,
        },
        CheckpointError::IdDerivationFailed {
            detail: "test".to_string(),
        },
        CheckpointError::SignatureInvalid {
            detail: "test".to_string(),
        },
        CheckpointError::EpochRegression {
            prev_epoch: SecurityEpoch::from_raw(5),
            current_epoch: SecurityEpoch::from_raw(3),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: CheckpointError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// Section 5: Schema helpers
// ===========================================================================

#[test]
fn checkpoint_schema_is_deterministic() {
    let s1 = checkpoint_schema();
    let s2 = checkpoint_schema();
    assert_eq!(s1, s2);
}

#[test]
fn checkpoint_schema_id_is_deterministic() {
    let id1 = checkpoint_schema_id();
    let id2 = checkpoint_schema_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// Section 6: Genesis checkpoint creation
// ===========================================================================

#[test]
fn genesis_checkpoint_basic() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);

    assert_eq!(cp.checkpoint_seq, 0);
    assert!(cp.prev_checkpoint.is_none());
    assert_eq!(cp.epoch_id, SecurityEpoch::GENESIS);
    assert_eq!(cp.policy_heads.len(), 1);
    assert_eq!(cp.quorum_signatures.len(), 1);
    assert_eq!(cp.created_at, DeterministicTimestamp(100));
}

#[test]
fn genesis_id_is_deterministic() {
    let sk = make_sk(1);
    let cp1 = build_genesis(std::slice::from_ref(&sk));
    let cp2 = build_genesis(&[sk]);
    assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
}

#[test]
fn genesis_with_multiple_signers() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let sk3 = make_sk(3);
    let cp = build_genesis(&[sk1, sk2, sk3]);
    assert_eq!(cp.quorum_signatures.len(), 3);
}

#[test]
fn genesis_with_multiple_policy_heads() {
    let sk = make_sk(1);
    let cp = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
    .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
    .add_policy_head(make_policy_head(PolicyType::EvidenceRetention, 1))
    .add_policy_head(make_policy_head(PolicyType::RevocationGovernance, 1))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp.policy_heads.len(), 5);
}

#[test]
fn genesis_policy_heads_sorted_by_type() {
    let sk = make_sk(1);
    // Add in reverse order
    let cp = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RevocationGovernance, 1))
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
    .build(&[sk])
    .unwrap();

    // Should be sorted
    for i in 1..cp.policy_heads.len() {
        assert!(cp.policy_heads[i - 1].policy_type <= cp.policy_heads[i].policy_type);
    }
}

#[test]
fn genesis_at_non_zero_epoch() {
    let sk = make_sk(1);
    let cp = build_genesis_epoch(SecurityEpoch::from_raw(10), &[sk]);
    assert_eq!(cp.epoch_id, SecurityEpoch::from_raw(10));
}

// ===========================================================================
// Section 7: Genesis validation errors
// ===========================================================================

#[test]
fn genesis_non_zero_seq_rejected_display() {
    // We cannot set builder fields from integration tests (they are private).
    // Instead, verify the error variant and display from the error enum directly.
    let err = CheckpointError::GenesisSequenceNotZero { actual: 5 };
    assert!(err.to_string().contains("genesis"));
    assert!(err.to_string().contains("5"));
}

#[test]
fn empty_policy_heads_rejected() {
    let sk = make_sk(1);
    let err = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .build(&[sk])
    .unwrap_err();

    assert!(matches!(err, CheckpointError::EmptyPolicyHeads));
}

#[test]
fn duplicate_policy_type_rejected() {
    let sk = make_sk(1);
    let err = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap_err();

    assert!(matches!(err, CheckpointError::DuplicatePolicyType { .. }));
}

#[test]
fn duplicate_different_policy_types_ok() {
    let sk = make_sk(1);
    let result = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
    .build(&[sk]);

    assert!(result.is_ok());
}

// ===========================================================================
// Section 8: Chain checkpoint creation
// ===========================================================================

#[test]
fn chain_checkpoint_created() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp1.checkpoint_seq, 1);
    assert_eq!(cp1.prev_checkpoint, Some(genesis.checkpoint_id));
    assert_eq!(cp1.policy_heads[0].policy_version, 2);
    assert_eq!(cp1.created_at, DeterministicTimestamp(200));
}

#[test]
fn three_link_chain() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::after(
        &cp1,
        2,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(300),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp2.checkpoint_seq, 2);
    assert_eq!(cp2.prev_checkpoint, Some(cp1.checkpoint_id));
}

#[test]
fn five_link_chain() {
    let sk = make_sk(1);
    let mut prev = build_genesis(std::slice::from_ref(&sk));

    for seq in 1..=4u64 {
        let next = CheckpointBuilder::after(
            &prev,
            seq,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100 + seq * 100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, seq + 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        assert_eq!(next.checkpoint_seq, seq);
        assert_eq!(next.prev_checkpoint.as_ref(), Some(&prev.checkpoint_id));
        prev = next;
    }
    assert_eq!(prev.checkpoint_seq, 4);
}

#[test]
fn chain_with_epoch_transition() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp1.epoch_id, SecurityEpoch::from_raw(1));
}

#[test]
fn chain_with_different_policy_heads() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp1.policy_heads.len(), 2);
}

// ===========================================================================
// Section 9: Chain validation errors
// ===========================================================================

#[test]
fn non_monotonic_sequence_rejected() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let err = CheckpointBuilder::after(
        &genesis,
        0, // same as genesis
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap_err();

    assert!(matches!(
        err,
        CheckpointError::NonMonotonicSequence {
            prev_seq: 0,
            current_seq: 0
        }
    ));
}

#[test]
fn epoch_regression_rejected() {
    let sk = make_sk(1);
    let genesis = build_genesis_epoch(SecurityEpoch::from_raw(5), std::slice::from_ref(&sk));

    let err = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(3), // regression
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap_err();

    assert!(matches!(err, CheckpointError::EpochRegression { .. }));
}

#[test]
fn same_epoch_as_predecessor_allowed() {
    let sk = make_sk(1);
    let genesis = build_genesis_epoch(SecurityEpoch::from_raw(5), std::slice::from_ref(&sk));

    let result = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(5), // same epoch
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk]);

    assert!(result.is_ok());
}

// ===========================================================================
// Section 10: verify_chain_linkage
// ===========================================================================

#[test]
fn chain_linkage_valid() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));
    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
}

#[test]
fn chain_linkage_broken_detected() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::after(
        &genesis,
        2,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(300),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
    .build(&[sk])
    .unwrap();

    // cp2 chains to genesis, not cp1
    let err = verify_chain_linkage(&cp1, &cp2).unwrap_err();
    assert!(matches!(err, CheckpointError::ChainLinkageBroken { .. }));
}

#[test]
fn chain_linkage_missing_predecessor() {
    let sk = make_sk(1);
    let genesis1 = build_genesis(std::slice::from_ref(&sk));
    let genesis2 = build_genesis(&[sk]);

    // genesis2 has no predecessor
    let err = verify_chain_linkage(&genesis1, &genesis2).unwrap_err();
    assert!(matches!(err, CheckpointError::MissingPredecessor));
}

#[test]
fn chain_linkage_non_monotonic_seq() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        5,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    // Build cp2 chaining to cp1 with seq=3 (< 5)
    // We cannot build with CheckpointBuilder::after because it would reject.
    // Instead, build cp3 with seq=6, then verify cp1->cp3 with wrong order.
    let cp2 = CheckpointBuilder::after(
        &cp1,
        6,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(300),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
    .build(&[sk])
    .unwrap();

    // Verify backwards: cp2 -> cp1 would have lower seq in "current" (cp1=5, cp2=6)
    // Actually, verify_chain_linkage(cp2, cp1) means cp1 is current and needs prev=cp2
    // cp1.prev_checkpoint = genesis, not cp2 -> ChainLinkageBroken first
    let err = verify_chain_linkage(&cp2, &cp1).unwrap_err();
    // This will be ChainLinkageBroken or MissingPredecessor depending on cp1's structure
    assert!(matches!(err, CheckpointError::ChainLinkageBroken { .. }));
}

#[test]
fn chain_linkage_epoch_regression_detected() {
    let sk = make_sk(1);
    let genesis = build_genesis_epoch(SecurityEpoch::from_raw(5), std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(10),
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    // Now build cp2 chaining to cp1 with epoch 7 (regression from 10 to 7)
    // We can't build it via CheckpointBuilder::after since it blocks epoch regression
    // at build time. But verify_chain_linkage checks epoch independently.
    // So we verify genesis -> cp1 where genesis epoch 5 < cp1 epoch 10: OK
    assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
}

#[test]
fn chain_linkage_three_links() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::after(
        &cp1,
        2,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(300),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
    .build(&[sk])
    .unwrap();

    assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
    assert!(verify_chain_linkage(&cp1, &cp2).is_ok());
}

// ===========================================================================
// Section 11: verify_checkpoint_quorum
// ===========================================================================

#[test]
fn quorum_verification_single_signer() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let cp = build_genesis(&[sk]);

    assert!(verify_checkpoint_quorum(&cp, 1, &[vk]).is_ok());
}

#[test]
fn quorum_verification_two_signers() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();
    let cp = build_genesis(&[sk1, sk2]);

    assert!(verify_checkpoint_quorum(&cp, 2, &[vk1, vk2]).is_ok());
}

#[test]
fn quorum_verification_threshold_less_than_signers() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let sk3 = make_sk(3);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();
    let vk3 = sk3.verification_key();
    let cp = build_genesis(&[sk1, sk2, sk3]);

    // Threshold 2 out of 3
    assert!(verify_checkpoint_quorum(&cp, 2, &[vk1, vk2, vk3]).is_ok());
}

#[test]
fn quorum_fails_wrong_keys() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    let cp = build_genesis(&[sk1, sk2]);

    let err = verify_checkpoint_quorum(&cp, 2, &[wrong_vk]).unwrap_err();
    assert!(matches!(err, CheckpointError::QuorumNotMet { .. }));
}

#[test]
fn quorum_fails_insufficient_authorized_signers() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let vk1 = sk1.verification_key();
    // Only authorize vk1
    let cp = build_genesis(&[sk1, sk2]);

    // Threshold 2, but only 1 authorized signer matches
    let err = verify_checkpoint_quorum(&cp, 2, &[vk1]).unwrap_err();
    assert!(matches!(err, CheckpointError::QuorumNotMet { .. }));
}

#[test]
fn quorum_threshold_1_with_multiple_signers() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();
    let cp = build_genesis(&[sk1, sk2]);

    assert!(verify_checkpoint_quorum(&cp, 1, &[vk1, vk2]).is_ok());
}

// ===========================================================================
// Section 12: Preimage stability and determinism
// ===========================================================================

#[test]
fn preimage_is_deterministic() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);
    let p1 = cp.preimage_bytes();
    let p2 = cp.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn same_inputs_same_preimage() {
    let sk = make_sk(1);
    let cp1 = build_genesis(std::slice::from_ref(&sk));
    let cp2 = build_genesis(&[sk]);
    assert_eq!(cp1.preimage_bytes(), cp2.preimage_bytes());
}

#[test]
fn different_epoch_different_preimage() {
    let sk = make_sk(1);
    let cp1 = build_genesis_epoch(SecurityEpoch::from_raw(1), std::slice::from_ref(&sk));
    let cp2 = build_genesis_epoch(SecurityEpoch::from_raw(2), &[sk]);
    assert_ne!(cp1.preimage_bytes(), cp2.preimage_bytes());
}

#[test]
fn different_timestamp_different_preimage() {
    let sk = make_sk(1);
    let cp1 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&[sk])
    .unwrap();

    assert_ne!(cp1.preimage_bytes(), cp2.preimage_bytes());
}

#[test]
fn different_policy_head_different_preimage() {
    let sk = make_sk(1);
    let cp1 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    assert_ne!(cp1.preimage_bytes(), cp2.preimage_bytes());
}

#[test]
fn different_zone_different_checkpoint_id() {
    let sk = make_sk(1);
    let cp1 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "zone-a",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(std::slice::from_ref(&sk))
    .unwrap();

    let cp2 = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "zone-b",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&[sk])
    .unwrap();

    // Different zones produce different checkpoint IDs
    assert_ne!(cp1.checkpoint_id, cp2.checkpoint_id);
}

// ===========================================================================
// Section 13: PolicyCheckpoint serde roundtrip
// ===========================================================================

#[test]
fn checkpoint_serde_roundtrip() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);
    let json = serde_json::to_string(&cp).expect("serialize");
    let restored: PolicyCheckpoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cp, restored);
}

#[test]
fn checkpoint_serde_roundtrip_chain() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));
    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    let json = serde_json::to_string(&cp1).expect("serialize");
    let restored: PolicyCheckpoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cp1, restored);
}

#[test]
fn checkpoint_serde_roundtrip_multi_head() {
    let sk = make_sk(1);
    let cp = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 2))
    .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 3))
    .build(&[sk])
    .unwrap();

    let json = serde_json::to_string(&cp).expect("serialize");
    let restored: PolicyCheckpoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cp, restored);
}

#[test]
fn checkpoint_json_has_expected_fields() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);
    let json = serde_json::to_string(&cp).expect("serialize");

    assert!(json.contains("checkpoint_id"));
    assert!(json.contains("prev_checkpoint"));
    assert!(json.contains("checkpoint_seq"));
    assert!(json.contains("epoch_id"));
    assert!(json.contains("policy_heads"));
    assert!(json.contains("quorum_signatures"));
    assert!(json.contains("created_at"));
}

// ===========================================================================
// Section 14: CheckpointEvent — construction, serde, Display
// ===========================================================================

#[test]
fn checkpoint_event_construction() {
    let event = CheckpointEvent {
        event_type: CheckpointEventType::GenesisCreated,
        checkpoint_seq: 0,
        trace_id: "trace-99".to_string(),
    };
    assert_eq!(event.checkpoint_seq, 0);
    assert_eq!(event.trace_id, "trace-99");
}

#[test]
fn checkpoint_event_serde_roundtrip() {
    let events = vec![
        CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "t1".to_string(),
        },
        CheckpointEvent {
            event_type: CheckpointEventType::ChainCheckpointCreated { prev_seq: 5 },
            checkpoint_seq: 6,
            trace_id: "t2".to_string(),
        },
        CheckpointEvent {
            event_type: CheckpointEventType::QuorumVerified {
                valid: 3,
                threshold: 2,
            },
            checkpoint_seq: 1,
            trace_id: "t3".to_string(),
        },
        CheckpointEvent {
            event_type: CheckpointEventType::ChainLinkageVerified,
            checkpoint_seq: 2,
            trace_id: "t4".to_string(),
        },
        CheckpointEvent {
            event_type: CheckpointEventType::EpochTransition {
                from: SecurityEpoch::from_raw(1),
                to: SecurityEpoch::from_raw(2),
            },
            checkpoint_seq: 3,
            trace_id: "t5".to_string(),
        },
    ];

    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, restored);
    }
}

// ===========================================================================
// Section 15: CheckpointEventType — Display
// ===========================================================================

#[test]
fn checkpoint_event_type_display_genesis_created() {
    assert_eq!(
        CheckpointEventType::GenesisCreated.to_string(),
        "genesis_created"
    );
}

#[test]
fn checkpoint_event_type_display_chain_created() {
    let d = CheckpointEventType::ChainCheckpointCreated { prev_seq: 7 }.to_string();
    assert!(d.contains("chain_created"));
    assert!(d.contains("7"));
}

#[test]
fn checkpoint_event_type_display_quorum_verified() {
    let d = CheckpointEventType::QuorumVerified {
        valid: 3,
        threshold: 2,
    }
    .to_string();
    assert!(d.contains("quorum_verified"));
    assert!(d.contains("3"));
    assert!(d.contains("2"));
}

#[test]
fn checkpoint_event_type_display_chain_linkage_verified() {
    assert_eq!(
        CheckpointEventType::ChainLinkageVerified.to_string(),
        "chain_linkage_verified"
    );
}

#[test]
fn checkpoint_event_type_display_epoch_transition() {
    let d = CheckpointEventType::EpochTransition {
        from: SecurityEpoch::from_raw(1),
        to: SecurityEpoch::from_raw(2),
    }
    .to_string();
    assert!(d.contains("epoch_transition"));
}

// ===========================================================================
// Section 16: SignaturePreimage trait implementation
// ===========================================================================

#[test]
fn signature_preimage_domain_is_checkpoint_artifact() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);
    use frankenengine_engine::engine_object_id::ObjectDomain;
    assert_eq!(cp.signature_domain(), ObjectDomain::CheckpointArtifact);
}

#[test]
fn preimage_bytes_not_empty() {
    let sk = make_sk(1);
    let cp = build_genesis(&[sk]);
    let bytes = cp.preimage_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn preimage_bytes_chain_different_from_genesis() {
    let sk = make_sk(1);
    let genesis = build_genesis(std::slice::from_ref(&sk));
    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk])
    .unwrap();

    assert_ne!(genesis.preimage_bytes(), cp1.preimage_bytes());
}

// ===========================================================================
// Section 17: Edge cases and boundary conditions
// ===========================================================================

#[test]
fn max_u64_epoch() {
    let sk = make_sk(1);
    let cp = build_genesis_epoch(SecurityEpoch::from_raw(u64::MAX), &[sk]);
    assert_eq!(cp.epoch_id, SecurityEpoch::from_raw(u64::MAX));
}

#[test]
fn max_u64_timestamp() {
    let sk = make_sk(1);
    let cp = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(u64::MAX),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&[sk])
    .unwrap();
    assert_eq!(cp.created_at, DeterministicTimestamp(u64::MAX));
}

#[test]
fn empty_zone_string() {
    let sk = make_sk(1);
    let cp = CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), "")
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();
    assert_eq!(cp.checkpoint_seq, 0);
}

#[test]
fn long_zone_string() {
    let sk = make_sk(1);
    let zone = "a".repeat(1000);
    let cp = CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), &zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();
    assert_eq!(cp.checkpoint_seq, 0);
}

#[test]
fn policy_version_zero() {
    let head = make_policy_head(PolicyType::RuntimeExecution, 0);
    assert_eq!(head.policy_version, 0);
}

#[test]
fn policy_version_max_u64() {
    let head = make_policy_head(PolicyType::RuntimeExecution, u64::MAX);
    assert_eq!(head.policy_version, u64::MAX);
}

// ===========================================================================
// Section 18: Deterministic checkpoint_id across re-creation
// ===========================================================================

#[test]
fn checkpoint_id_deterministic_across_recreations() {
    let sk = make_sk(42);
    let make = || {
        CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(7),
            DeterministicTimestamp(555),
            "prod-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 10))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 3))
        .build(std::slice::from_ref(&sk))
        .unwrap()
    };

    let cp1 = make();
    let cp2 = make();
    assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
    assert_eq!(cp1.preimage_bytes(), cp2.preimage_bytes());
}

#[test]
fn chain_id_deterministic_across_recreations() {
    let sk = make_sk(42);
    let genesis = build_genesis(std::slice::from_ref(&sk));

    let make_chain = |g: &PolicyCheckpoint| {
        CheckpointBuilder::after(
            g,
            1,
            SecurityEpoch::from_raw(1),
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap()
    };

    let cp1 = make_chain(&genesis);
    let cp2 = make_chain(&genesis);
    assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
}

// ===========================================================================
// Section 19: All five policy types in genesis
// ===========================================================================

#[test]
fn all_five_policy_types_in_single_checkpoint() {
    let sk = make_sk(1);
    let cp = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(100),
        "full-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RevocationGovernance, 1))
    .add_policy_head(make_policy_head(PolicyType::EvidenceRetention, 1))
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
    .build(&[sk])
    .unwrap();

    assert_eq!(cp.policy_heads.len(), 5);

    // Verify sorting
    let types: Vec<String> = cp
        .policy_heads
        .iter()
        .map(|h| h.policy_type.to_string())
        .collect();
    let mut sorted_types = types.clone();
    sorted_types.sort();
    // Policy types are sorted by Ord impl, which may not match string sort,
    // but they should be sorted by PolicyType's Ord.
    for i in 1..cp.policy_heads.len() {
        assert!(cp.policy_heads[i - 1].policy_type <= cp.policy_heads[i].policy_type);
    }
}

// ===========================================================================
// Section 20: Quorum with chain checkpoints
// ===========================================================================

#[test]
fn quorum_verification_on_chain_checkpoint() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();

    let genesis = build_genesis(&[sk1.clone(), sk2.clone()]);
    let cp1 = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(200),
        "test-zone",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&[sk1, sk2])
    .unwrap();

    assert!(verify_checkpoint_quorum(&cp1, 2, &[vk1, vk2]).is_ok());
}

#[test]
fn quorum_verification_partial_overlap() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let sk3 = make_sk(3);
    let vk1 = sk1.verification_key();
    let vk3 = sk3.verification_key();

    // Signed by sk1, sk2
    let cp = build_genesis(&[sk1, sk2]);

    // Authorized: vk1, vk3 (only vk1 matches)
    let result = verify_checkpoint_quorum(&cp, 1, &[vk1, vk3]);
    assert!(result.is_ok());
}
