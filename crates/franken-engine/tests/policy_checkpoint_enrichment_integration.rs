//! Enrichment integration tests for `policy_checkpoint` (FRX-10.10).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display exact values,
//! Debug distinctness, CheckpointError coverage, PolicyType Display,
//! DeterministicTimestamp Display, checkpoint_schema determinism,
//! CheckpointBuilder validation, chain linkage verification, and quorum
//! verification.

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
use frankenengine_engine::policy_checkpoint::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ── helpers ────────────────────────────────────────────────────────────

fn test_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
    PolicyHead {
        policy_type: pt,
        policy_hash: ContentHash::compute(format!("policy-{version}").as_bytes()),
        policy_version: version,
    }
}

fn test_signing_keys(n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|i| SigningKey::from_bytes([(i as u8).wrapping_add(42); 32]))
        .collect()
}

// ── PolicyType Display ─────────────────────────────────────────────────

#[test]
fn policy_type_display_exact_runtime_execution() {
    assert_eq!(
        PolicyType::RuntimeExecution.to_string(),
        "runtime_execution"
    );
}

#[test]
fn policy_type_display_exact_capability_lattice() {
    assert_eq!(
        PolicyType::CapabilityLattice.to_string(),
        "capability_lattice"
    );
}

#[test]
fn policy_type_display_exact_extension_trust() {
    assert_eq!(PolicyType::ExtensionTrust.to_string(), "extension_trust");
}

#[test]
fn policy_type_display_exact_evidence_retention() {
    assert_eq!(
        PolicyType::EvidenceRetention.to_string(),
        "evidence_retention"
    );
}

#[test]
fn policy_type_display_exact_revocation_governance() {
    assert_eq!(
        PolicyType::RevocationGovernance.to_string(),
        "revocation_governance"
    );
}

#[test]
fn policy_type_display_all_unique() {
    let types = [
        PolicyType::RuntimeExecution,
        PolicyType::CapabilityLattice,
        PolicyType::ExtensionTrust,
        PolicyType::EvidenceRetention,
        PolicyType::RevocationGovernance,
    ];
    let mut displays = BTreeSet::new();
    for t in &types {
        displays.insert(t.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn policy_type_debug_distinct() {
    let types = [
        PolicyType::RuntimeExecution,
        PolicyType::CapabilityLattice,
        PolicyType::ExtensionTrust,
        PolicyType::EvidenceRetention,
        PolicyType::RevocationGovernance,
    ];
    let mut dbgs = BTreeSet::new();
    for t in &types {
        dbgs.insert(format!("{t:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn policy_type_serde_roundtrip_all() {
    for t in [
        PolicyType::RuntimeExecution,
        PolicyType::CapabilityLattice,
        PolicyType::ExtensionTrust,
        PolicyType::EvidenceRetention,
        PolicyType::RevocationGovernance,
    ] {
        let json = serde_json::to_vec(&t).unwrap();
        let back: PolicyType = serde_json::from_slice(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ── DeterministicTimestamp ──────────────────────────────────────────────

#[test]
fn deterministic_timestamp_display() {
    let ts = DeterministicTimestamp(42);
    assert_eq!(ts.to_string(), "tick:42");
}

#[test]
fn deterministic_timestamp_display_zero() {
    let ts = DeterministicTimestamp(0);
    assert_eq!(ts.to_string(), "tick:0");
}

#[test]
fn deterministic_timestamp_serde_roundtrip() {
    let ts = DeterministicTimestamp(1_000_000);
    let json = serde_json::to_vec(&ts).unwrap();
    let back: DeterministicTimestamp = serde_json::from_slice(&json).unwrap();
    assert_eq!(ts, back);
}

#[test]
fn deterministic_timestamp_ordering() {
    assert!(DeterministicTimestamp(1) < DeterministicTimestamp(2));
}

// ── PolicyHead ─────────────────────────────────────────────────────────

#[test]
fn policy_head_json_fields() {
    let head = test_policy_head(PolicyType::RuntimeExecution, 1);
    let v: serde_json::Value = serde_json::to_value(&head).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("policy_type"));
    assert!(obj.contains_key("policy_hash"));
    assert!(obj.contains_key("policy_version"));
}

#[test]
fn policy_head_serde_roundtrip() {
    let head = test_policy_head(PolicyType::ExtensionTrust, 5);
    let json = serde_json::to_vec(&head).unwrap();
    let back: PolicyHead = serde_json::from_slice(&json).unwrap();
    assert_eq!(head, back);
}

// ── checkpoint_schema ──────────────────────────────────────────────────

#[test]
fn checkpoint_schema_deterministic() {
    let s1 = checkpoint_schema();
    let s2 = checkpoint_schema();
    assert_eq!(s1, s2);
}

#[test]
fn checkpoint_schema_id_deterministic() {
    let id1 = checkpoint_schema_id();
    let id2 = checkpoint_schema_id();
    assert_eq!(id1, id2);
}

// ── CheckpointError Display ────────────────────────────────────────────

#[test]
fn error_display_genesis_no_predecessor() {
    let e = CheckpointError::GenesisMustHaveNoPredecessor;
    assert_eq!(e.to_string(), "genesis checkpoint must have no predecessor");
}

#[test]
fn error_display_missing_predecessor() {
    let e = CheckpointError::MissingPredecessor;
    assert_eq!(
        e.to_string(),
        "non-genesis checkpoint must have a predecessor"
    );
}

#[test]
fn error_display_non_monotonic() {
    let e = CheckpointError::NonMonotonicSequence {
        prev_seq: 5,
        current_seq: 3,
    };
    let s = e.to_string();
    assert!(s.contains("non-monotonic"));
    assert!(s.contains('5'));
    assert!(s.contains('3'));
}

#[test]
fn error_display_genesis_seq_not_zero() {
    let e = CheckpointError::GenesisSequenceNotZero { actual: 7 };
    let s = e.to_string();
    assert!(s.contains("genesis"));
    assert!(s.contains('7'));
}

#[test]
fn error_display_empty_policy_heads() {
    let e = CheckpointError::EmptyPolicyHeads;
    assert_eq!(e.to_string(), "policy heads must not be empty");
}

#[test]
fn error_display_quorum_not_met() {
    let e = CheckpointError::QuorumNotMet {
        required: 3,
        provided: 1,
    };
    let s = e.to_string();
    assert!(s.contains("quorum"));
    assert!(s.contains("1/3"));
}

#[test]
fn error_display_duplicate_policy_type() {
    let e = CheckpointError::DuplicatePolicyType {
        policy_type: PolicyType::ExtensionTrust,
    };
    let s = e.to_string();
    assert!(s.contains("duplicate"));
    assert!(s.contains("extension_trust"));
}

#[test]
fn error_display_id_derivation() {
    let e = CheckpointError::IdDerivationFailed {
        detail: "bad input".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("ID derivation"));
    assert!(s.contains("bad input"));
}

#[test]
fn error_display_signature_invalid() {
    let e = CheckpointError::SignatureInvalid {
        detail: "bad sig".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("signature invalid"));
    assert!(s.contains("bad sig"));
}

#[test]
fn error_display_epoch_regression() {
    let e = CheckpointError::EpochRegression {
        prev_epoch: SecurityEpoch::from_raw(5),
        current_epoch: SecurityEpoch::from_raw(3),
    };
    let s = e.to_string();
    assert!(s.contains("epoch regression"));
}

#[test]
fn error_is_std_error() {
    let e = CheckpointError::EmptyPolicyHeads;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn error_debug_distinct() {
    let id = frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::CheckpointArtifact,
        "test",
        &checkpoint_schema_id(),
        b"test-data",
    )
    .unwrap();
    let errors: Vec<CheckpointError> = vec![
        CheckpointError::GenesisMustHaveNoPredecessor,
        CheckpointError::MissingPredecessor,
        CheckpointError::NonMonotonicSequence {
            prev_seq: 1,
            current_seq: 0,
        },
        CheckpointError::GenesisSequenceNotZero { actual: 1 },
        CheckpointError::ChainLinkageBroken {
            expected: id.clone(),
            actual: id.clone(),
        },
        CheckpointError::EmptyPolicyHeads,
        CheckpointError::QuorumNotMet {
            required: 2,
            provided: 1,
        },
        CheckpointError::DuplicatePolicyType {
            policy_type: PolicyType::RuntimeExecution,
        },
        CheckpointError::IdDerivationFailed {
            detail: "x".to_string(),
        },
        CheckpointError::SignatureInvalid {
            detail: "y".to_string(),
        },
        CheckpointError::EpochRegression {
            prev_epoch: SecurityEpoch::from_raw(2),
            current_epoch: SecurityEpoch::from_raw(1),
        },
    ];
    let mut dbgs = BTreeSet::new();
    for e in &errors {
        dbgs.insert(format!("{e:?}"));
    }
    assert_eq!(dbgs.len(), 11);
}

// ── CheckpointBuilder validation ───────────────────────────────────────

#[test]
fn builder_genesis_empty_policy_heads_error() {
    let keys = test_signing_keys(1);
    let result = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .build(&keys);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CheckpointError::EmptyPolicyHeads));
}

#[test]
fn builder_genesis_duplicate_policy_type_error() {
    let keys = test_signing_keys(1);
    let result = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&keys);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CheckpointError::DuplicatePolicyType { .. }));
}

#[test]
fn builder_genesis_builds_successfully() {
    let keys = test_signing_keys(1);
    let checkpoint = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();
    assert!(checkpoint.prev_checkpoint.is_none());
    assert_eq!(checkpoint.checkpoint_seq, 0);
    assert_eq!(checkpoint.epoch_id, SecurityEpoch::from_raw(1));
    assert_eq!(checkpoint.policy_heads.len(), 1);
}

#[test]
fn builder_genesis_deterministic_id() {
    let keys = test_signing_keys(1);
    let cp1 = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();
    let cp2 = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();
    assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
}

#[test]
fn builder_chained_checkpoint() {
    let keys = test_signing_keys(1);
    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let chained = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(100),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&keys)
    .unwrap();

    assert_eq!(
        chained.prev_checkpoint.as_ref().unwrap(),
        &genesis.checkpoint_id
    );
    assert_eq!(chained.checkpoint_seq, 1);
}

#[test]
fn builder_chained_non_monotonic_seq_error() {
    let keys = test_signing_keys(1);
    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let result = CheckpointBuilder::after(
        &genesis,
        0, // same as genesis seq = 0, not strictly greater
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(100),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&keys);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CheckpointError::NonMonotonicSequence { .. }
    ));
}

#[test]
fn builder_chained_epoch_regression_error() {
    let keys = test_signing_keys(1);
    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(5),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let result = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(3), // epoch regression
        DeterministicTimestamp(100),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&keys);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CheckpointError::EpochRegression { .. }
    ));
}

// ── Chain linkage verification ─────────────────────────────────────────

#[test]
fn chain_linkage_valid() {
    let keys = test_signing_keys(1);
    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let chained = CheckpointBuilder::after(
        &genesis,
        1,
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(100),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 2))
    .build(&keys)
    .unwrap();

    assert!(verify_chain_linkage(&genesis, &chained).is_ok());
}

// ── Quorum verification ────────────────────────────────────────────────

#[test]
fn quorum_verification_single_signer() {
    let keys = test_signing_keys(1);
    let checkpoint = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let vks: Vec<_> = keys.iter().map(|k| k.verification_key()).collect();
    assert!(verify_checkpoint_quorum(&checkpoint, 1, &vks).is_ok());
}

#[test]
fn quorum_verification_insufficient() {
    let keys = test_signing_keys(1);
    let checkpoint = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-1",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let vks: Vec<_> = keys.iter().map(|k| k.verification_key()).collect();
    let result = verify_checkpoint_quorum(&checkpoint, 2, &vks);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CheckpointError::QuorumNotMet { .. }
    ));
}

// ── PolicyCheckpoint serde ─────────────────────────────────────────────

#[test]
fn checkpoint_serde_roundtrip() {
    let keys = test_signing_keys(2);
    let checkpoint = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-serde",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(test_policy_head(PolicyType::CapabilityLattice, 1))
    .build(&keys)
    .unwrap();

    let json = serde_json::to_vec(&checkpoint).unwrap();
    let back: PolicyCheckpoint = serde_json::from_slice(&json).unwrap();
    assert_eq!(checkpoint, back);
}

#[test]
fn checkpoint_json_fields() {
    let keys = test_signing_keys(1);
    let checkpoint = CheckpointBuilder::genesis(
        SecurityEpoch::from_raw(1),
        DeterministicTimestamp(0),
        "zone-jf",
    )
    .add_policy_head(test_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&keys)
    .unwrap();

    let v: serde_json::Value = serde_json::to_value(&checkpoint).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("checkpoint_id"));
    assert!(obj.contains_key("prev_checkpoint"));
    assert!(obj.contains_key("checkpoint_seq"));
    assert!(obj.contains_key("epoch_id"));
    assert!(obj.contains_key("policy_heads"));
    assert!(obj.contains_key("quorum_signatures"));
    assert!(obj.contains_key("created_at"));
}

// ── CheckpointEvent ────────────────────────────────────────────────────

#[test]
fn checkpoint_event_json_fields() {
    let ev = CheckpointEvent {
        event_type: CheckpointEventType::GenesisCreated,
        checkpoint_seq: 0,
        trace_id: "trace-1".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("event_type"));
    assert!(obj.contains_key("checkpoint_seq"));
    assert!(obj.contains_key("trace_id"));
}

#[test]
fn checkpoint_event_serde_roundtrip() {
    let ev = CheckpointEvent {
        event_type: CheckpointEventType::GenesisCreated,
        checkpoint_seq: 5,
        trace_id: "trace-rt".to_string(),
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: CheckpointEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}
