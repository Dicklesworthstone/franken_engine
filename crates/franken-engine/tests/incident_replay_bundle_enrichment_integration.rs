#![forbid(unsafe_code)]
//! Enrichment integration tests for `incident_replay_bundle`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, Merkle tree edge cases, and factory
//! defaults beyond the existing 41 integration tests.

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
use frankenengine_engine::incident_replay_bundle::{
    BUNDLE_FORMAT_VERSION, BundleArtifactKind, BundleError, BundleFormatVersion, BundleVerifier,
    CategorySummary, CheckOutcome, RedactionPolicy, VerificationCategory, VerificationCheck,
    build_merkle_proof, compute_merkle_root, verify_merkle_proof,
};
// ===========================================================================
// 1) BundleFormatVersion — Display
// ===========================================================================

#[test]
fn bundle_format_version_display_exact() {
    let v = BundleFormatVersion { major: 1, minor: 0 };
    assert_eq!(v.to_string(), "1.0");
}

#[test]
fn bundle_format_version_display_various() {
    let v = BundleFormatVersion { major: 2, minor: 3 };
    assert_eq!(v.to_string(), "2.3");
}

// ===========================================================================
// 2) BundleFormatVersion — is_compatible_with
// ===========================================================================

#[test]
fn version_compatible_same() {
    let v = BundleFormatVersion { major: 1, minor: 0 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn version_compatible_reader_newer_minor() {
    let reader = BundleFormatVersion { major: 1, minor: 1 };
    let bundle = BundleFormatVersion { major: 1, minor: 0 };
    assert!(reader.is_compatible_with(&bundle));
}

#[test]
fn version_incompatible_different_major() {
    let reader = BundleFormatVersion { major: 2, minor: 0 };
    let bundle = BundleFormatVersion { major: 1, minor: 0 };
    assert!(!reader.is_compatible_with(&bundle));
}

#[test]
fn version_incompatible_reader_older_minor() {
    let reader = BundleFormatVersion { major: 1, minor: 0 };
    let bundle = BundleFormatVersion { major: 1, minor: 1 };
    assert!(!reader.is_compatible_with(&bundle));
}

// ===========================================================================
// 3) BundleArtifactKind — exact Display
// ===========================================================================

#[test]
fn bundle_artifact_kind_display_exact() {
    let expected = [
        (BundleArtifactKind::Trace, "trace"),
        (BundleArtifactKind::Evidence, "evidence"),
        (BundleArtifactKind::OptReceipt, "opt-receipt"),
        (BundleArtifactKind::QuorumCheckpoint, "quorum-checkpoint"),
        (BundleArtifactKind::NondeterminismLog, "nondeterminism-log"),
        (
            BundleArtifactKind::CounterfactualResult,
            "counterfactual-result",
        ),
        (BundleArtifactKind::PolicySnapshot, "policy-snapshot"),
    ];
    for (kind, exp) in &expected {
        assert_eq!(
            kind.to_string(),
            *exp,
            "BundleArtifactKind Display mismatch for {kind:?}"
        );
    }
}

// ===========================================================================
// 4) VerificationCategory — exact Display
// ===========================================================================

#[test]
fn verification_category_display_exact() {
    let expected = [
        (VerificationCategory::Integrity, "integrity"),
        (VerificationCategory::ArtifactHash, "artifact-hash"),
        (VerificationCategory::Replay, "replay"),
        (VerificationCategory::ReceiptChain, "receipt-chain"),
        (VerificationCategory::Counterfactual, "counterfactual"),
        (VerificationCategory::Compatibility, "compatibility"),
    ];
    for (cat, exp) in &expected {
        assert_eq!(
            cat.to_string(),
            *exp,
            "VerificationCategory Display mismatch for {cat:?}"
        );
    }
}

// ===========================================================================
// 5) CheckOutcome — methods
// ===========================================================================

#[test]
fn check_outcome_pass_methods() {
    let co = CheckOutcome::Pass;
    assert!(co.is_pass());
    assert!(!co.is_fail());
}

#[test]
fn check_outcome_fail_methods() {
    let co = CheckOutcome::Fail {
        reason: "bad".into(),
    };
    assert!(!co.is_pass());
    assert!(co.is_fail());
}

#[test]
fn check_outcome_skipped_methods() {
    let co = CheckOutcome::Skipped {
        reason: "redacted".into(),
    };
    assert!(!co.is_pass());
    assert!(!co.is_fail());
}

// ===========================================================================
// 6) BundleError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn bundle_error_display_all_unique() {
    let variants: Vec<String> = vec![
        BundleError::IntegrityFailure {
            expected: "a".into(),
            actual: "b".into(),
        }
        .to_string(),
        BundleError::ArtifactHashMismatch {
            artifact_id: "c".into(),
        }
        .to_string(),
        BundleError::SignatureInvalid.to_string(),
        BundleError::ReplayDivergence {
            details: "d".into(),
        }
        .to_string(),
        BundleError::ReceiptInvalid {
            receipt_id: "e".into(),
            reason: "f".into(),
        }
        .to_string(),
        BundleError::IncompatibleVersion {
            bundle: BundleFormatVersion { major: 1, minor: 0 },
            reader: BundleFormatVersion { major: 2, minor: 0 },
        }
        .to_string(),
        BundleError::EmptyBundle.to_string(),
        BundleError::TraceNotFound {
            trace_id: "g".into(),
        }
        .to_string(),
        BundleError::IdDerivation("h".into()).to_string(),
        BundleError::ReplayFailed("i".into()).to_string(),
        BundleError::RedactionViolation { field: "j".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn bundle_error_is_std_error() {
    let e = BundleError::EmptyBundle;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 7) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_bundle_artifact_kind() {
    let variants: Vec<String> = [
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::OptReceipt,
        BundleArtifactKind::QuorumCheckpoint,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::CounterfactualResult,
        BundleArtifactKind::PolicySnapshot,
    ]
    .iter()
    .map(|k| format!("{k:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn debug_distinct_verification_category() {
    let variants: Vec<String> = [
        VerificationCategory::Integrity,
        VerificationCategory::ArtifactHash,
        VerificationCategory::Replay,
        VerificationCategory::ReceiptChain,
        VerificationCategory::Counterfactual,
        VerificationCategory::Compatibility,
    ]
    .iter()
    .map(|c| format!("{c:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_check_outcome() {
    let variants = [
        format!("{:?}", CheckOutcome::Pass),
        format!("{:?}", CheckOutcome::Fail { reason: "x".into() }),
        format!("{:?}", CheckOutcome::Skipped { reason: "y".into() }),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 8) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_bundle_artifact_kind_all() {
    let kinds = [
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::OptReceipt,
        BundleArtifactKind::QuorumCheckpoint,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::CounterfactualResult,
        BundleArtifactKind::PolicySnapshot,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let rt: BundleArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, rt);
    }
}

#[test]
fn serde_roundtrip_verification_category_all() {
    let cats = [
        VerificationCategory::Integrity,
        VerificationCategory::ArtifactHash,
        VerificationCategory::Replay,
        VerificationCategory::ReceiptChain,
        VerificationCategory::Counterfactual,
        VerificationCategory::Compatibility,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        let rt: VerificationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, rt);
    }
}

#[test]
fn serde_roundtrip_check_outcome_all() {
    let outcomes = vec![
        CheckOutcome::Pass,
        CheckOutcome::Fail {
            reason: "bad".into(),
        },
        CheckOutcome::Skipped {
            reason: "n/a".into(),
        },
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let rt: CheckOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, rt);
    }
}

#[test]
fn serde_roundtrip_bundle_error_all() {
    let variants = vec![
        BundleError::IntegrityFailure {
            expected: "a".into(),
            actual: "b".into(),
        },
        BundleError::ArtifactHashMismatch {
            artifact_id: "c".into(),
        },
        BundleError::SignatureInvalid,
        BundleError::ReplayDivergence {
            details: "d".into(),
        },
        BundleError::ReceiptInvalid {
            receipt_id: "e".into(),
            reason: "f".into(),
        },
        BundleError::IncompatibleVersion {
            bundle: BundleFormatVersion { major: 1, minor: 0 },
            reader: BundleFormatVersion { major: 2, minor: 0 },
        },
        BundleError::EmptyBundle,
        BundleError::TraceNotFound {
            trace_id: "g".into(),
        },
        BundleError::IdDerivation("h".into()),
        BundleError::ReplayFailed("i".into()),
        BundleError::RedactionViolation { field: "j".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: BundleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_bundle_format_version() {
    let v = BundleFormatVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let rt: BundleFormatVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

#[test]
fn serde_roundtrip_redaction_policy() {
    let rp = RedactionPolicy {
        redact_extension_ids: true,
        redact_evidence_metadata: false,
        redact_nondeterminism_values: true,
        redact_node_ids: false,
        custom_redaction_keys: ["key1".to_string()].into_iter().collect(),
    };
    let json = serde_json::to_string(&rp).unwrap();
    let rt: RedactionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(rp, rt);
}

#[test]
fn serde_roundtrip_category_summary() {
    let cs = CategorySummary {
        passed: 5,
        failed: 2,
        skipped: 1,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let rt: CategorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, rt);
}

// ===========================================================================
// 9) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_bundle_format_version() {
    let v = BundleFormatVersion { major: 1, minor: 0 };
    let val: serde_json::Value = serde_json::to_value(v).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["major", "minor"] {
        assert!(
            obj.contains_key(key),
            "BundleFormatVersion missing field: {key}"
        );
    }
}

#[test]
fn json_fields_redaction_policy() {
    let rp = RedactionPolicy::default();
    let val: serde_json::Value = serde_json::to_value(&rp).unwrap();
    let obj = val.as_object().unwrap();
    for key in [
        "redact_extension_ids",
        "redact_evidence_metadata",
        "redact_nondeterminism_values",
        "redact_node_ids",
        "custom_redaction_keys",
    ] {
        assert!(
            obj.contains_key(key),
            "RedactionPolicy missing field: {key}"
        );
    }
}

#[test]
fn json_fields_category_summary() {
    let cs = CategorySummary {
        passed: 1,
        failed: 2,
        skipped: 3,
    };
    let val: serde_json::Value = serde_json::to_value(&cs).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["passed", "failed", "skipped"] {
        assert!(
            obj.contains_key(key),
            "CategorySummary missing field: {key}"
        );
    }
}

#[test]
fn json_fields_verification_check() {
    let vc = VerificationCheck {
        name: "check1".into(),
        category: VerificationCategory::Integrity,
        outcome: CheckOutcome::Pass,
    };
    let val: serde_json::Value = serde_json::to_value(&vc).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["name", "category", "outcome"] {
        assert!(
            obj.contains_key(key),
            "VerificationCheck missing field: {key}"
        );
    }
}

#[test]
fn json_fields_bundle_artifact_kind_all_distinct() {
    // Verify all BundleArtifactKind variants serialize to distinct strings
    let kinds = [
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::OptReceipt,
        BundleArtifactKind::QuorumCheckpoint,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::CounterfactualResult,
        BundleArtifactKind::PolicySnapshot,
    ];
    let tags: Vec<String> = kinds
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 7);
}

// ===========================================================================
// 10) Constants stability
// ===========================================================================

#[test]
fn bundle_format_version_constant() {
    assert_eq!(BUNDLE_FORMAT_VERSION.major, 1);
    assert_eq!(BUNDLE_FORMAT_VERSION.minor, 0);
}

// ===========================================================================
// 11) RedactionPolicy default
// ===========================================================================

#[test]
fn redaction_policy_default() {
    let rp = RedactionPolicy::default();
    assert!(!rp.redact_extension_ids);
    assert!(!rp.redact_evidence_metadata);
    assert!(!rp.redact_nondeterminism_values);
    assert!(!rp.redact_node_ids);
    assert!(rp.custom_redaction_keys.is_empty());
}

// ===========================================================================
// 12) BundleVerifier default
// ===========================================================================

#[test]
fn bundle_verifier_new() {
    let _verifier = BundleVerifier::new();
}

#[test]
fn bundle_verifier_default() {
    let _verifier = BundleVerifier::default();
}

// ===========================================================================
// 13) Merkle tree functions
// ===========================================================================

#[test]
fn merkle_root_empty() {
    let root = compute_merkle_root(&[]);
    assert_ne!(root, ContentHash::compute(b"nonempty"));
}

#[test]
fn merkle_root_single_leaf() {
    let leaf = ContentHash::compute(b"hello");
    let root = compute_merkle_root(std::slice::from_ref(&leaf));
    assert_eq!(root, leaf);
}

#[test]
fn merkle_root_two_leaves_deterministic() {
    let l1 = ContentHash::compute(b"a");
    let l2 = ContentHash::compute(b"b");
    let root = compute_merkle_root(&[l1, l2]);
    let root2 = compute_merkle_root(&[l1, l2]);
    assert_eq!(root, root2);
}

#[test]
fn merkle_root_order_matters() {
    let l1 = ContentHash::compute(b"a");
    let l2 = ContentHash::compute(b"b");
    let root1 = compute_merkle_root(&[l1, l2]);
    let root2 = compute_merkle_root(&[l2, l1]);
    assert_ne!(root1, root2);
}

#[test]
fn merkle_proof_single_leaf_empty() {
    let leaf = ContentHash::compute(b"x");
    let proof = build_merkle_proof(&[leaf], 0);
    assert!(proof.is_empty());
}

#[test]
fn merkle_proof_verifies_two_leaves() {
    let l1 = ContentHash::compute(b"a");
    let l2 = ContentHash::compute(b"b");
    let leaves = [l1, l2];
    let root = compute_merkle_root(&leaves);
    let proof = build_merkle_proof(&leaves, 0);
    assert!(verify_merkle_proof(&l1, &proof, &root));
}

#[test]
fn merkle_proof_verifies_four_leaves() {
    let leaves: Vec<ContentHash> = (0..4u8).map(|i| ContentHash::compute(&[i])).collect();
    let root = compute_merkle_root(&leaves);
    for i in 0..4 {
        let proof = build_merkle_proof(&leaves, i);
        assert!(
            verify_merkle_proof(&leaves[i], &proof, &root),
            "proof failed for leaf {i}"
        );
    }
}

#[test]
fn merkle_proof_invalid_index() {
    let leaf = ContentHash::compute(b"x");
    let proof = build_merkle_proof(&[leaf], 5);
    assert!(proof.is_empty());
}

// ===========================================================================
// 14) BundleArtifactKind ordering
// ===========================================================================

#[test]
fn bundle_artifact_kind_ordering_stable() {
    let mut kinds = [
        BundleArtifactKind::PolicySnapshot,
        BundleArtifactKind::Trace,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::Evidence,
    ];
    kinds.sort();
    assert_eq!(kinds[0], BundleArtifactKind::Trace);
}

// ===========================================================================
// 15) VerificationCategory ordering
// ===========================================================================

#[test]
fn verification_category_ordering_stable() {
    let mut cats = [
        VerificationCategory::Compatibility,
        VerificationCategory::Integrity,
        VerificationCategory::Replay,
    ];
    cats.sort();
    assert_eq!(cats[0], VerificationCategory::Integrity);
}

// ===========================================================================
// Enrichment tests: ~80 new tests covering construction, validation,
// serialization, edge cases, error handling, and determinism.
// ===========================================================================

use std::collections::BTreeMap;

use frankenengine_engine::causal_replay::{
    ActionDeltaReport, CounterfactualConfig, DecisionSnapshot, NondeterminismLog,
    NondeterminismSource, RecorderConfig, RecordingMode, TraceRecord, TraceRecorder,
};
use frankenengine_engine::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
use frankenengine_engine::incident_replay_bundle::{
    ArtifactEntry, BundleBuilder, BundleInspection, BundleManifest, CounterfactualResult,
    IncidentReplayBundle, PolicySnapshot, VerificationReport,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers for enrichment tests
// ---------------------------------------------------------------------------

fn enr_signing_key() -> SigningKey {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    SigningKey::from_bytes(key)
}

fn enr_make_trace(trace_id: &str, num_decisions: usize) -> TraceRecord {
    let key = enr_signing_key();
    let config = RecorderConfig {
        trace_id: trace_id.to_string(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(100),
        start_tick: 1000,
        signing_key: key.as_bytes().to_vec(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.record_nondeterminism(
        NondeterminismSource::Timestamp,
        vec![0, 0, 0, 0, 0, 0, 3, 232],
        1001,
        None,
    );
    for i in 0..num_decisions {
        let snapshot = DecisionSnapshot {
            decision_index: i as u64,
            trace_id: trace_id.to_string(),
            decision_id: format!("decision-{i}"),
            policy_id: "test-policy".to_string(),
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(100),
            tick: 1000 + i as u64,
            threshold_millionths: 500_000,
            loss_matrix: BTreeMap::new(),
            evidence_hashes: Vec::new(),
            chosen_action: "allow".to_string(),
            outcome_millionths: 100_000,
            extension_id: "ext-001".to_string(),
            nondeterminism_range: (0, 0),
        };
        recorder.record_decision(snapshot);
    }
    recorder.finalize()
}

fn enr_make_evidence_entry() -> frankenengine_engine::evidence_ledger::EvidenceEntry {
    EvidenceEntryBuilder::new(
        "trace-001",
        "decision-001",
        "policy-001",
        SecurityEpoch::from_raw(100),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(1000)
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 100_000,
        rationale: "test rationale".to_string(),
    })
    .build()
    .unwrap()
}

fn enr_make_policy_snapshot(policy_id: &str) -> PolicySnapshot {
    PolicySnapshot {
        policy_id: policy_id.to_string(),
        policy_version: "1.0".to_string(),
        active_epoch: SecurityEpoch::from_raw(100),
        config_hash: ContentHash::compute(b"test-policy-config"),
        config_bytes: b"test-policy-config".to_vec(),
    }
}

fn enr_make_nondeterminism_log() -> NondeterminismLog {
    let mut log = NondeterminismLog::new();
    log.append(
        NondeterminismSource::Timestamp,
        vec![0, 0, 0, 0, 0, 0, 3, 232],
        1001,
        None,
    );
    log.append(
        NondeterminismSource::RandomValue,
        vec![42, 43, 44],
        1002,
        Some("ext-001".to_string()),
    );
    log
}

fn enr_make_counterfactual_result(
    branch_id: &str,
    trace_id: &str,
    harm_delta: i64,
) -> CounterfactualResult {
    CounterfactualResult {
        config: CounterfactualConfig {
            branch_id: branch_id.to_string(),
            threshold_override_millionths: Some(300_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        delta_report: ActionDeltaReport {
            config: CounterfactualConfig {
                branch_id: branch_id.to_string(),
                threshold_override_millionths: Some(300_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            harm_prevented_delta_millionths: harm_delta,
            false_positive_cost_delta_millionths: -10_000,
            containment_latency_delta_ticks: -5,
            resource_cost_delta_millionths: 20_000,
            affected_extensions: BTreeSet::new(),
            divergence_points: Vec::new(),
            decisions_evaluated: 10,
        },
        source_trace_id: trace_id.to_string(),
    }
}

fn enr_build_test_bundle() -> IncidentReplayBundle {
    let key = enr_signing_key();
    BundleBuilder::new(
        "incident-001".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "producer-key-1".to_string(),
        key,
    )
    .window(1000, 2000)
    .meta("severity".to_string(), "high".to_string())
    .trace("trace-001".to_string(), enr_make_trace("trace-001", 3))
    .evidence("evidence-001".to_string(), enr_make_evidence_entry())
    .nondeterminism("trace-001".to_string(), enr_make_nondeterminism_log())
    .policy(
        "policy-001".to_string(),
        enr_make_policy_snapshot("policy-001"),
    )
    .build()
    .expect("bundle build should succeed")
}

// ===========================================================================
// 16) Builder construction edge cases
// ===========================================================================

#[test]
fn enrichment_builder_empty_bundle_returns_empty_bundle_error() {
    let key = enr_signing_key();
    let result = BundleBuilder::new(
        "empty-test".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .build();
    assert_eq!(result, Err(BundleError::EmptyBundle));
}

#[test]
fn enrichment_builder_single_trace_produces_valid_bundle() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "single-trace".to_string(),
        SecurityEpoch::from_raw(50),
        2000,
        "producer-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.traces.len(), 1);
    assert_eq!(bundle.manifest.artifacts.len(), 1);
    assert_eq!(bundle.manifest.incident_id, "single-trace");
}

#[test]
fn enrichment_builder_single_evidence_produces_valid_bundle() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "single-evidence".to_string(),
        SecurityEpoch::from_raw(50),
        2000,
        "producer-1".to_string(),
        key,
    )
    .evidence("ev1".to_string(), enr_make_evidence_entry())
    .build()
    .unwrap();

    assert_eq!(bundle.evidence_entries.len(), 1);
    assert_eq!(bundle.manifest.artifacts.len(), 1);
}

#[test]
fn enrichment_builder_single_nondeterminism_produces_valid_bundle() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "single-nd".to_string(),
        SecurityEpoch::from_raw(50),
        2000,
        "producer-1".to_string(),
        key,
    )
    .nondeterminism("nd1".to_string(), enr_make_nondeterminism_log())
    .build()
    .unwrap();

    assert_eq!(bundle.nondeterminism_logs.len(), 1);
}

#[test]
fn enrichment_builder_single_counterfactual_produces_valid_bundle() {
    let key = enr_signing_key();
    let cf = enr_make_counterfactual_result("branch-1", "t1", 50_000);
    let bundle = BundleBuilder::new(
        "single-cf".to_string(),
        SecurityEpoch::from_raw(50),
        2000,
        "producer-1".to_string(),
        key,
    )
    .counterfactual("cf1".to_string(), cf)
    .build()
    .unwrap();

    assert_eq!(bundle.counterfactual_results.len(), 1);
}

#[test]
fn enrichment_builder_single_policy_produces_valid_bundle() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "single-policy".to_string(),
        SecurityEpoch::from_raw(50),
        2000,
        "producer-1".to_string(),
        key,
    )
    .policy("p1".to_string(), enr_make_policy_snapshot("p1"))
    .build()
    .unwrap();

    assert_eq!(bundle.policy_snapshots.len(), 1);
}

// ===========================================================================
// 17) Builder chaining and field preservation
// ===========================================================================

#[test]
fn enrichment_builder_window_zero_to_max() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "big-window".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .window(0, u64::MAX)
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.window_start_tick, 0);
    assert_eq!(bundle.manifest.window_end_tick, u64::MAX);
}

#[test]
fn enrichment_builder_multiple_metadata_deterministic_ordering() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "meta-order".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .meta("zebra".to_string(), "z".to_string())
    .meta("alpha".to_string(), "a".to_string())
    .meta("middle".to_string(), "m".to_string())
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let keys: Vec<_> = bundle.manifest.metadata.keys().collect();
    assert_eq!(keys, vec!["alpha", "middle", "zebra"]);
}

#[test]
fn enrichment_builder_metadata_overwrite_same_key() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "meta-overwrite".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .meta("key".to_string(), "first".to_string())
    .meta("key".to_string(), "second".to_string())
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(
        bundle.manifest.metadata.get("key"),
        Some(&"second".to_string())
    );
    assert_eq!(bundle.manifest.metadata.len(), 1);
}

#[test]
fn enrichment_builder_redaction_policy_preserved() {
    let key = enr_signing_key();
    let mut custom_keys = BTreeSet::new();
    custom_keys.insert("secret-field".to_string());
    let policy = RedactionPolicy {
        redact_extension_ids: true,
        redact_evidence_metadata: true,
        redact_nondeterminism_values: true,
        redact_node_ids: true,
        custom_redaction_keys: custom_keys,
    };

    let bundle = BundleBuilder::new(
        "redacted".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .redaction_policy(policy.clone())
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.redaction_policy, policy);
    assert!(bundle.manifest.redaction_policy.redact_extension_ids);
    assert!(bundle.manifest.redaction_policy.redact_evidence_metadata);
    assert!(
        bundle
            .manifest
            .redaction_policy
            .custom_redaction_keys
            .contains("secret-field")
    );
}

#[test]
fn enrichment_builder_creation_epoch_preserved() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "epoch-test".to_string(),
        SecurityEpoch::from_raw(42),
        9999,
        "pk".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.creation_epoch, SecurityEpoch::from_raw(42));
    assert_eq!(bundle.manifest.created_at_ns, 9999);
}

#[test]
fn enrichment_builder_producer_key_id_preserved() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "pk-test".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "my-special-key-id".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.producer_key_id, "my-special-key-id");
}

// ===========================================================================
// 18) Manifest signing_bytes determinism and sensitivity
// ===========================================================================

#[test]
fn enrichment_manifest_signing_bytes_deterministic() {
    let b1 = enr_build_test_bundle();
    let b2 = enr_build_test_bundle();
    assert_eq!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn enrichment_manifest_signing_bytes_differ_with_incident_id() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "incident-A".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "incident-B".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn enrichment_manifest_signing_bytes_differ_with_epoch() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "epoch-diff".to_string(),
        SecurityEpoch::from_raw(1),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "epoch-diff".to_string(),
        SecurityEpoch::from_raw(2),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn enrichment_manifest_signing_bytes_differ_with_timestamp() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "ts-diff".to_string(),
        SecurityEpoch::from_raw(100),
        1000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "ts-diff".to_string(),
        SecurityEpoch::from_raw(100),
        2000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn enrichment_manifest_signing_bytes_differ_with_window() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "win-diff".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .window(100, 200)
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "win-diff".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .window(100, 300)
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn enrichment_manifest_signing_bytes_nonempty() {
    let bundle = enr_build_test_bundle();
    let sb = bundle.manifest.signing_bytes();
    assert!(!sb.is_empty(), "signing bytes must not be empty");
    assert!(
        sb.len() > 32,
        "signing bytes should include more than just one field"
    );
}

// ===========================================================================
// 19) Bundle signature properties
// ===========================================================================

#[test]
fn enrichment_bundle_signature_length_is_64() {
    let bundle = enr_build_test_bundle();
    assert_eq!(bundle.manifest.signature.len(), 64);
}

#[test]
fn enrichment_bundle_signature_nonzero() {
    let bundle = enr_build_test_bundle();
    assert!(
        bundle.manifest.signature.iter().any(|&b| b != 0),
        "signature must not be all zeros"
    );
}

#[test]
fn enrichment_bundle_signature_deterministic() {
    let b1 = enr_build_test_bundle();
    let b2 = enr_build_test_bundle();
    assert_eq!(b1.manifest.signature, b2.manifest.signature);
}

// ===========================================================================
// 20) Bundle ID determinism and uniqueness
// ===========================================================================

#[test]
fn enrichment_bundle_id_deterministic_same_inputs() {
    let b1 = enr_build_test_bundle();
    let b2 = enr_build_test_bundle();
    assert_eq!(b1.manifest.bundle_id, b2.manifest.bundle_id);
}

#[test]
fn enrichment_bundle_id_differs_for_different_incidents() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "incident-X".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "incident-Y".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.bundle_id, b2.manifest.bundle_id);
}

#[test]
fn enrichment_bundle_id_differs_for_different_epochs() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "same-incident".to_string(),
        SecurityEpoch::from_raw(10),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "same-incident".to_string(),
        SecurityEpoch::from_raw(20),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.bundle_id, b2.manifest.bundle_id);
}

// ===========================================================================
// 21) Merkle root properties
// ===========================================================================

#[test]
fn enrichment_merkle_root_nonempty_bundle() {
    let bundle = enr_build_test_bundle();
    let empty_root = compute_merkle_root(&[]);
    assert_ne!(
        bundle.manifest.merkle_root, empty_root,
        "bundle with artifacts must have non-empty merkle root"
    );
}

#[test]
fn enrichment_merkle_root_changes_with_different_artifacts() {
    let key = enr_signing_key();
    let b1 = BundleBuilder::new(
        "mr-diff".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key.clone(),
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "mr-diff".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 5))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.merkle_root, b2.manifest.merkle_root);
}

#[test]
fn enrichment_merkle_proof_five_leaves_all_verify() {
    let leaves: Vec<ContentHash> = (0..5u8).map(|i| ContentHash::compute(&[i])).collect();
    let root = compute_merkle_root(&leaves);
    for idx in 0..5 {
        let proof = build_merkle_proof(&leaves, idx);
        assert!(
            verify_merkle_proof(&leaves[idx], &proof, &root),
            "proof failed for leaf {idx} in 5-leaf tree"
        );
    }
}

#[test]
fn enrichment_merkle_proof_seven_leaves_all_verify() {
    let leaves: Vec<ContentHash> = (0..7u8).map(|i| ContentHash::compute(&[i + 10])).collect();
    let root = compute_merkle_root(&leaves);
    for idx in 0..7 {
        let proof = build_merkle_proof(&leaves, idx);
        assert!(
            verify_merkle_proof(&leaves[idx], &proof, &root),
            "proof failed for leaf {idx} in 7-leaf tree"
        );
    }
}

#[test]
fn enrichment_merkle_proof_wrong_leaf_fails() {
    let l1 = ContentHash::compute(b"real");
    let l2 = ContentHash::compute(b"also-real");
    let fake = ContentHash::compute(b"fake");
    let root = compute_merkle_root(&[l1, l2]);
    let proof = build_merkle_proof(&[l1, l2], 0);
    assert!(!verify_merkle_proof(&fake, &proof, &root));
}

#[test]
fn enrichment_merkle_proof_wrong_root_fails() {
    let l1 = ContentHash::compute(b"a");
    let l2 = ContentHash::compute(b"b");
    let root = compute_merkle_root(&[l1, l2]);
    let proof = build_merkle_proof(&[l1, l2], 0);
    let wrong_root = ContentHash::compute(b"not-the-root");
    assert!(!verify_merkle_proof(&l1, &proof, &wrong_root));
    // But real root works:
    assert!(verify_merkle_proof(&l1, &proof, &root));
}

#[test]
fn enrichment_merkle_root_power_of_two_leaves() {
    let leaves: Vec<ContentHash> = (0..8u8).map(|i| ContentHash::compute(&[i])).collect();
    let root = compute_merkle_root(&leaves);
    let root2 = compute_merkle_root(&leaves);
    assert_eq!(root, root2, "power-of-two tree must be deterministic");
    for idx in 0..8 {
        let proof = build_merkle_proof(&leaves, idx);
        assert!(verify_merkle_proof(&leaves[idx], &proof, &root));
    }
}

#[test]
fn enrichment_merkle_root_sixteen_leaves() {
    let leaves: Vec<ContentHash> = (0..16u16)
        .map(|i| ContentHash::compute(&i.to_be_bytes()))
        .collect();
    let root = compute_merkle_root(&leaves);
    // Verify first, last, and middle
    for idx in [0, 7, 8, 15] {
        let proof = build_merkle_proof(&leaves, idx);
        assert!(verify_merkle_proof(&leaves[idx], &proof, &root));
    }
}

// ===========================================================================
// 22) Artifact entry properties
// ===========================================================================

#[test]
fn enrichment_artifact_entries_all_have_nonzero_size() {
    let bundle = enr_build_test_bundle();
    for entry in bundle.manifest.artifacts.values() {
        assert!(
            entry.size_bytes > 0,
            "artifact {:?} ({}) should have non-zero size",
            entry.kind,
            entry.artifact_id
        );
    }
}

#[test]
fn enrichment_artifact_entries_none_redacted_by_default() {
    let bundle = enr_build_test_bundle();
    for entry in bundle.manifest.artifacts.values() {
        assert!(
            !entry.redacted,
            "default-built artifacts should not be redacted"
        );
    }
}

#[test]
fn enrichment_artifact_entry_composite_keys_contain_kind() {
    let bundle = enr_build_test_bundle();
    for (key, entry) in &bundle.manifest.artifacts {
        let kind_str = entry.kind.to_string();
        assert!(
            key.starts_with(&format!("{kind_str}:")),
            "key '{key}' should start with '{kind_str}:'"
        );
    }
}

#[test]
fn enrichment_artifact_entry_ids_match_builder_ids() {
    let bundle = enr_build_test_bundle();
    let trace_entry = bundle
        .manifest
        .artifacts
        .values()
        .find(|e| e.kind == BundleArtifactKind::Trace);
    assert!(trace_entry.is_some());
    assert_eq!(trace_entry.unwrap().artifact_id, "trace-001");

    let evidence_entry = bundle
        .manifest
        .artifacts
        .values()
        .find(|e| e.kind == BundleArtifactKind::Evidence);
    assert!(evidence_entry.is_some());
    assert_eq!(evidence_entry.unwrap().artifact_id, "evidence-001");
}

// ===========================================================================
// 23) ArtifactEntry serde
// ===========================================================================

#[test]
fn enrichment_artifact_entry_serde_roundtrip_all_kinds() {
    let kinds = [
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::OptReceipt,
        BundleArtifactKind::QuorumCheckpoint,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::CounterfactualResult,
        BundleArtifactKind::PolicySnapshot,
    ];
    for kind in &kinds {
        let entry = ArtifactEntry {
            artifact_id: format!("art-{kind}"),
            kind: *kind,
            content_hash: ContentHash::compute(format!("data-{kind}").as_bytes()),
            redacted: false,
            size_bytes: 256,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: ArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }
}

#[test]
fn enrichment_artifact_entry_json_field_names() {
    let entry = ArtifactEntry {
        artifact_id: "x".to_string(),
        kind: BundleArtifactKind::Trace,
        content_hash: ContentHash::compute(b"x"),
        redacted: false,
        size_bytes: 10,
    };
    let val: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = val.as_object().unwrap();
    for field in ["artifact_id", "kind", "content_hash", "redacted", "size_bytes"] {
        assert!(obj.contains_key(field), "ArtifactEntry missing field: {field}");
    }
}

// ===========================================================================
// 24) PolicySnapshot serde and properties
// ===========================================================================

#[test]
fn enrichment_policy_snapshot_serde_roundtrip() {
    let snap = enr_make_policy_snapshot("my-policy");
    let json = serde_json::to_string(&snap).unwrap();
    let restored: PolicySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

#[test]
fn enrichment_policy_snapshot_json_field_names() {
    let snap = enr_make_policy_snapshot("p");
    let val: serde_json::Value = serde_json::to_value(&snap).unwrap();
    let obj = val.as_object().unwrap();
    for field in [
        "policy_id",
        "policy_version",
        "active_epoch",
        "config_hash",
        "config_bytes",
    ] {
        assert!(obj.contains_key(field), "PolicySnapshot missing field: {field}");
    }
}

#[test]
fn enrichment_policy_snapshot_different_ids_not_equal() {
    let p1 = enr_make_policy_snapshot("policy-a");
    let p2 = enr_make_policy_snapshot("policy-b");
    assert_ne!(p1, p2);
}

#[test]
fn enrichment_policy_snapshot_config_hash_matches_bytes() {
    let snap = enr_make_policy_snapshot("hash-test");
    assert_eq!(
        snap.config_hash,
        ContentHash::compute(&snap.config_bytes)
    );
}

// ===========================================================================
// 25) CounterfactualResult serde and properties
// ===========================================================================

#[test]
fn enrichment_counterfactual_result_serde_roundtrip() {
    let cf = enr_make_counterfactual_result("branch-x", "trace-x", 100_000);
    let json = serde_json::to_string(&cf).unwrap();
    let restored: CounterfactualResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cf, restored);
}

#[test]
fn enrichment_counterfactual_result_is_improvement_positive() {
    let cf = enr_make_counterfactual_result("b", "t", 100_000);
    assert!(cf.delta_report.is_improvement());
}

#[test]
fn enrichment_counterfactual_result_not_improvement_negative() {
    let cf = enr_make_counterfactual_result("b", "t", -100_000);
    assert!(!cf.delta_report.is_improvement());
}

#[test]
fn enrichment_counterfactual_result_not_improvement_zero() {
    let cf = enr_make_counterfactual_result("b", "t", 0);
    assert!(!cf.delta_report.is_improvement());
}

#[test]
fn enrichment_counterfactual_result_divergence_count_empty() {
    let cf = enr_make_counterfactual_result("b", "t", 50_000);
    assert_eq!(cf.delta_report.divergence_count(), 0);
}

// ===========================================================================
// 26) IncidentReplayBundle serde roundtrip
// ===========================================================================

#[test]
fn enrichment_bundle_serde_roundtrip_preserves_manifest() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.manifest.bundle_id, restored.manifest.bundle_id);
    assert_eq!(bundle.manifest.merkle_root, restored.manifest.merkle_root);
    assert_eq!(bundle.manifest.signature, restored.manifest.signature);
    assert_eq!(
        bundle.manifest.format_version,
        restored.manifest.format_version
    );
}

#[test]
fn enrichment_bundle_serde_roundtrip_preserves_traces() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.traces.len(), restored.traces.len());
    for key in bundle.traces.keys() {
        assert!(restored.traces.contains_key(key));
    }
}

#[test]
fn enrichment_bundle_serde_roundtrip_preserves_evidence() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(
        bundle.evidence_entries.len(),
        restored.evidence_entries.len()
    );
}

#[test]
fn enrichment_bundle_serde_roundtrip_preserves_policies() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(
        bundle.policy_snapshots.len(),
        restored.policy_snapshots.len()
    );
}

#[test]
fn enrichment_bundle_serde_roundtrip_preserves_nondeterminism() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(
        bundle.nondeterminism_logs.len(),
        restored.nondeterminism_logs.len()
    );
}

// ===========================================================================
// 27) BundleManifest serde
// ===========================================================================

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let bundle = enr_build_test_bundle();
    let json = serde_json::to_string(&bundle.manifest).unwrap();
    let restored: BundleManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.manifest, restored);
}

#[test]
fn enrichment_manifest_json_field_names() {
    let bundle = enr_build_test_bundle();
    let val: serde_json::Value = serde_json::to_value(&bundle.manifest).unwrap();
    let obj = val.as_object().unwrap();
    for field in [
        "format_version",
        "bundle_id",
        "incident_id",
        "creation_epoch",
        "created_at_ns",
        "producer_key_id",
        "merkle_root",
        "artifacts",
        "redaction_policy",
        "window_start_tick",
        "window_end_tick",
        "metadata",
        "signature",
    ] {
        assert!(
            obj.contains_key(field),
            "BundleManifest missing field: {field}"
        );
    }
}

// ===========================================================================
// 28) Verifier integrity checks
// ===========================================================================

#[test]
fn enrichment_verifier_integrity_all_checks_pass_for_valid_bundle() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
    assert!(report.fail_count() == 0);
    assert!(report.pass_count() > 0);
}

#[test]
fn enrichment_verifier_integrity_detects_tampered_merkle_root() {
    let mut bundle = enr_build_test_bundle();
    bundle.manifest.merkle_root = ContentHash::compute(b"tampered-root");
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);
}

#[test]
fn enrichment_verifier_integrity_report_has_compatibility_check() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    let compat_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Compatibility)
        .collect();
    assert!(!compat_checks.is_empty());
    assert!(compat_checks.iter().all(|c| c.outcome.is_pass()));
}

#[test]
fn enrichment_verifier_integrity_report_has_integrity_check() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    let integrity_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Integrity)
        .collect();
    assert!(!integrity_checks.is_empty());
}

#[test]
fn enrichment_verifier_integrity_report_has_artifact_hash_checks() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    let hash_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::ArtifactHash)
        .collect();
    // Should have one hash check per artifact.
    assert_eq!(
        hash_checks.len(),
        bundle.manifest.artifacts.len(),
        "should have one artifact hash check per artifact"
    );
}

// ===========================================================================
// 29) Verifier replay checks
// ===========================================================================

#[test]
fn enrichment_verifier_replay_passes_for_valid_traces() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_replay(&bundle, 6000);
    assert!(report.passed);
}

#[test]
fn enrichment_verifier_replay_skips_when_no_traces() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "no-trace".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .policy("p1".to_string(), enr_make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_replay(&bundle, 6000);
    assert!(report.passed);
    let skipped: Vec<_> = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
        .collect();
    assert!(!skipped.is_empty());
}

#[test]
fn enrichment_verifier_replay_check_names_contain_trace_id() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_replay(&bundle, 6000);
    let replay_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Replay)
        .collect();
    for check in &replay_checks {
        assert!(
            check.name.contains("trace-001"),
            "replay check name '{}' should contain trace id",
            check.name
        );
    }
}

// ===========================================================================
// 30) Verifier receipts checks
// ===========================================================================

#[test]
fn enrichment_verifier_receipts_skips_when_no_receipts() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_receipts(
        &bundle,
        &BTreeMap::new(),
        SecurityEpoch::from_raw(100),
        6000,
    );
    assert!(report.passed);
    let skipped: Vec<_> = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
        .collect();
    assert!(!skipped.is_empty());
}

// ===========================================================================
// 31) Verifier counterfactual checks
// ===========================================================================

#[test]
fn enrichment_verifier_counterfactual_empty_configs_is_pass() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_counterfactual(&bundle, &[], 6000);
    assert!(report.passed);
    assert_eq!(report.checks.len(), 0);
}

// ===========================================================================
// 32) Inspect API
// ===========================================================================

#[test]
fn enrichment_inspect_returns_correct_bundle_id() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.bundle_id, bundle.manifest.bundle_id);
}

#[test]
fn enrichment_inspect_returns_correct_incident_id() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.incident_id, "incident-001");
}

#[test]
fn enrichment_inspect_returns_correct_format_version() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.format_version, BUNDLE_FORMAT_VERSION);
}

#[test]
fn enrichment_inspect_returns_correct_window() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.window, (1000, 2000));
}

#[test]
fn enrichment_inspect_returns_correct_created_at_ns() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.created_at_ns, 5000);
}

#[test]
fn enrichment_inspect_returns_correct_creation_epoch() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.creation_epoch, SecurityEpoch::from_raw(100));
}

#[test]
fn enrichment_inspect_returns_correct_producer_key_id() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.producer_key_id, "producer-key-1");
}

#[test]
fn enrichment_inspect_trace_ids_match_bundle() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.trace_ids, vec!["trace-001"]);
}

#[test]
fn enrichment_inspect_artifact_counts_sum_matches_total() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    let sum: u64 = inspection.artifact_counts.values().sum();
    assert_eq!(sum, bundle.manifest.artifacts.len() as u64);
}

#[test]
fn enrichment_inspect_total_size_positive() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert!(inspection.total_size_bytes > 0);
}

#[test]
fn enrichment_inspect_no_redacted_in_default_bundle() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.redacted_count, 0);
}

#[test]
fn enrichment_inspect_metadata_preserved() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(
        inspection.metadata.get("severity"),
        Some(&"high".to_string())
    );
}

#[test]
fn enrichment_inspect_serde_roundtrip() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    let json = serde_json::to_string(&inspection).unwrap();
    let restored: BundleInspection = serde_json::from_str(&json).unwrap();
    assert_eq!(inspection, restored);
}

// ===========================================================================
// 33) VerificationReport properties
// ===========================================================================

#[test]
fn enrichment_verification_report_serde_roundtrip() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    let json = serde_json::to_string(&report).unwrap();
    let restored: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn enrichment_verification_report_pass_fail_skipped_add_up() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);

    let pass = report.pass_count();
    let fail = report.fail_count();
    let skipped: u64 = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
        .count() as u64;
    assert_eq!(pass + fail + skipped, report.checks.len() as u64);
}

#[test]
fn enrichment_verification_report_summary_categories_match_checks() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);

    let total_from_summary: u64 = report
        .summary
        .values()
        .map(|s| s.passed + s.failed + s.skipped)
        .sum();
    assert_eq!(total_from_summary, report.checks.len() as u64);
}

#[test]
fn enrichment_verification_report_verified_at_ns() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 99_999);
    assert_eq!(report.verified_at_ns, 99_999);
}

#[test]
fn enrichment_verification_report_verifier_version() {
    let bundle = enr_build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert_eq!(report.verifier_version, BUNDLE_FORMAT_VERSION);
}

// ===========================================================================
// 34) BundleError Display format exactness
// ===========================================================================

#[test]
fn enrichment_bundle_error_integrity_failure_format() {
    let err = BundleError::IntegrityFailure {
        expected: "abc123".to_string(),
        actual: "def456".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("integrity failure"));
    assert!(s.contains("abc123"));
    assert!(s.contains("def456"));
}

#[test]
fn enrichment_bundle_error_artifact_hash_mismatch_format() {
    let err = BundleError::ArtifactHashMismatch {
        artifact_id: "art-xyz".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("artifact hash mismatch"));
    assert!(s.contains("art-xyz"));
}

#[test]
fn enrichment_bundle_error_signature_invalid_format() {
    let err = BundleError::SignatureInvalid;
    assert_eq!(err.to_string(), "bundle signature invalid");
}

#[test]
fn enrichment_bundle_error_replay_divergence_format() {
    let err = BundleError::ReplayDivergence {
        details: "3 diffs".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("replay divergence"));
    assert!(s.contains("3 diffs"));
}

#[test]
fn enrichment_bundle_error_empty_bundle_format() {
    let err = BundleError::EmptyBundle;
    assert_eq!(err.to_string(), "empty bundle");
}

#[test]
fn enrichment_bundle_error_trace_not_found_format() {
    let err = BundleError::TraceNotFound {
        trace_id: "missing-trace".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("trace not found"));
    assert!(s.contains("missing-trace"));
}

#[test]
fn enrichment_bundle_error_id_derivation_format() {
    let err = BundleError::IdDerivation("bad seed data".to_string());
    let s = err.to_string();
    assert!(s.contains("id derivation"));
    assert!(s.contains("bad seed data"));
}

#[test]
fn enrichment_bundle_error_replay_failed_format() {
    let err = BundleError::ReplayFailed("timeout exceeded".to_string());
    let s = err.to_string();
    assert!(s.contains("replay failed"));
    assert!(s.contains("timeout exceeded"));
}

#[test]
fn enrichment_bundle_error_incompatible_version_format() {
    let err = BundleError::IncompatibleVersion {
        bundle: BundleFormatVersion { major: 3, minor: 1 },
        reader: BundleFormatVersion { major: 1, minor: 0 },
    };
    let s = err.to_string();
    assert!(s.contains("incompatible version"));
    assert!(s.contains("3.1"));
    assert!(s.contains("1.0"));
}

// ===========================================================================
// 35) BundleError Clone and PartialEq
// ===========================================================================

#[test]
fn enrichment_bundle_error_clone_equals_original() {
    let err = BundleError::ReplayDivergence {
        details: "test".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_bundle_error_different_variants_not_equal() {
    let a = BundleError::EmptyBundle;
    let b = BundleError::SignatureInvalid;
    assert_ne!(a, b);
}

// ===========================================================================
// 36) Multi-artifact bundles
// ===========================================================================

#[test]
fn enrichment_bundle_with_multiple_traces_integrity_passes() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "multi-t".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 1))
    .trace("t2".to_string(), enr_make_trace("t2", 2))
    .trace("t3".to_string(), enr_make_trace("t3", 3))
    .build()
    .unwrap();

    assert_eq!(bundle.traces.len(), 3);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

#[test]
fn enrichment_bundle_with_mixed_artifacts_integrity_passes() {
    let key = enr_signing_key();
    let cf = enr_make_counterfactual_result("branch-1", "t1", 50_000);
    let bundle = BundleBuilder::new(
        "mixed".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), enr_make_trace("t1", 2))
    .evidence("ev1".to_string(), enr_make_evidence_entry())
    .nondeterminism("nd1".to_string(), enr_make_nondeterminism_log())
    .policy("p1".to_string(), enr_make_policy_snapshot("p1"))
    .counterfactual("cf1".to_string(), cf)
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.artifacts.len(), 5);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

#[test]
fn enrichment_bundle_with_multiple_policies() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "multi-policy".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .policy("p1".to_string(), enr_make_policy_snapshot("p1"))
    .policy("p2".to_string(), enr_make_policy_snapshot("p2"))
    .policy("p3".to_string(), enr_make_policy_snapshot("p3"))
    .build()
    .unwrap();

    assert_eq!(bundle.policy_snapshots.len(), 3);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

#[test]
fn enrichment_bundle_with_multiple_counterfactuals() {
    let key = enr_signing_key();
    let bundle = BundleBuilder::new(
        "multi-cf".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .counterfactual(
        "cf1".to_string(),
        enr_make_counterfactual_result("b1", "t1", 100_000),
    )
    .counterfactual(
        "cf2".to_string(),
        enr_make_counterfactual_result("b2", "t1", -50_000),
    )
    .build()
    .unwrap();

    assert_eq!(bundle.counterfactual_results.len(), 2);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

// ===========================================================================
// 37) Tampering detection edge cases
// ===========================================================================

#[test]
fn enrichment_tampered_artifact_hash_detected() {
    let mut bundle = enr_build_test_bundle();
    // Tamper with an artifact's content hash in the manifest.
    if let Some(entry) = bundle.manifest.artifacts.values_mut().next() {
        entry.content_hash = ContentHash::compute(b"tampered");
    }
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);
}

#[test]
fn enrichment_tampered_incident_id_changes_signing_bytes() {
    let mut bundle = enr_build_test_bundle();
    let orig_bytes = bundle.manifest.signing_bytes();
    bundle.manifest.incident_id = "tampered".to_string();
    let new_bytes = bundle.manifest.signing_bytes();
    assert_ne!(orig_bytes, new_bytes);
}

// ===========================================================================
// 38) Format version compatibility edge cases
// ===========================================================================

#[test]
fn enrichment_version_compatible_higher_minor_reader() {
    let reader = BundleFormatVersion { major: 1, minor: 5 };
    let bundle = BundleFormatVersion { major: 1, minor: 3 };
    assert!(reader.is_compatible_with(&bundle));
}

#[test]
fn enrichment_version_incompatible_zero_major_different() {
    let reader = BundleFormatVersion { major: 0, minor: 1 };
    let bundle = BundleFormatVersion { major: 1, minor: 0 };
    assert!(!reader.is_compatible_with(&bundle));
}

#[test]
fn enrichment_version_compatible_zero_zero() {
    let v = BundleFormatVersion { major: 0, minor: 0 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn enrichment_version_display_large_numbers() {
    let v = BundleFormatVersion {
        major: 999,
        minor: 888,
    };
    assert_eq!(v.to_string(), "999.888");
}

// ===========================================================================
// 39) RedactionPolicy edge cases
// ===========================================================================

#[test]
fn enrichment_redaction_policy_custom_keys_deterministic_order() {
    let mut keys = BTreeSet::new();
    keys.insert("z-key".to_string());
    keys.insert("a-key".to_string());
    keys.insert("m-key".to_string());
    let policy = RedactionPolicy {
        redact_extension_ids: false,
        redact_evidence_metadata: false,
        redact_nondeterminism_values: false,
        redact_node_ids: false,
        custom_redaction_keys: keys,
    };
    let ordered: Vec<_> = policy.custom_redaction_keys.iter().collect();
    assert_eq!(ordered, vec!["a-key", "m-key", "z-key"]);
}

#[test]
fn enrichment_redaction_policy_clone_equals() {
    let policy = RedactionPolicy {
        redact_extension_ids: true,
        redact_evidence_metadata: false,
        redact_nondeterminism_values: true,
        redact_node_ids: false,
        custom_redaction_keys: BTreeSet::new(),
    };
    let cloned = policy.clone();
    assert_eq!(policy, cloned);
}

// ===========================================================================
// 40) CategorySummary edge cases
// ===========================================================================

#[test]
fn enrichment_category_summary_all_zero() {
    let cs = CategorySummary {
        passed: 0,
        failed: 0,
        skipped: 0,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let restored: CategorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, restored);
}

#[test]
fn enrichment_category_summary_large_values() {
    let cs = CategorySummary {
        passed: u64::MAX,
        failed: u64::MAX,
        skipped: u64::MAX,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let restored: CategorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, restored);
}

// ===========================================================================
// 41) VerificationCheck edge cases
// ===========================================================================

#[test]
fn enrichment_verification_check_with_empty_name() {
    let check = VerificationCheck {
        name: String::new(),
        category: VerificationCategory::Integrity,
        outcome: CheckOutcome::Pass,
    };
    let json = serde_json::to_string(&check).unwrap();
    let restored: VerificationCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, restored);
}

#[test]
fn enrichment_verification_check_clone_equals() {
    let check = VerificationCheck {
        name: "test".to_string(),
        category: VerificationCategory::ArtifactHash,
        outcome: CheckOutcome::Fail {
            reason: "bad".to_string(),
        },
    };
    let cloned = check.clone();
    assert_eq!(check, cloned);
}

// ===========================================================================
// 42) BundleArtifactKind Copy and Clone
// ===========================================================================

#[test]
fn enrichment_bundle_artifact_kind_copy() {
    let k = BundleArtifactKind::Trace;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn enrichment_verification_category_copy() {
    let c = VerificationCategory::Replay;
    let c2 = c;
    assert_eq!(c, c2);
}

// ===========================================================================
// 43) CheckOutcome serde stability
// ===========================================================================

#[test]
fn enrichment_check_outcome_pass_json_string() {
    let json = serde_json::to_string(&CheckOutcome::Pass).unwrap();
    assert!(json.contains("Pass"));
}

#[test]
fn enrichment_check_outcome_fail_json_contains_reason() {
    let co = CheckOutcome::Fail {
        reason: "specific-reason".to_string(),
    };
    let json = serde_json::to_string(&co).unwrap();
    assert!(json.contains("specific-reason"));
}

#[test]
fn enrichment_check_outcome_skipped_json_contains_reason() {
    let co = CheckOutcome::Skipped {
        reason: "redacted-artifact".to_string(),
    };
    let json = serde_json::to_string(&co).unwrap();
    assert!(json.contains("redacted-artifact"));
}

// ===========================================================================
// 44) Bundle format version constant stability
// ===========================================================================

#[test]
fn enrichment_bundle_format_version_v1_display() {
    assert_eq!(BUNDLE_FORMAT_VERSION.to_string(), "1.0");
}

#[test]
fn enrichment_bundle_format_version_self_compatible() {
    assert!(BUNDLE_FORMAT_VERSION.is_compatible_with(&BUNDLE_FORMAT_VERSION));
}
