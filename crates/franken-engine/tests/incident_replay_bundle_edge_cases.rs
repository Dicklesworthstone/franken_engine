//! Integration-level edge-case tests for `incident_replay_bundle`.
//!
//! Complements the inline unit tests by exercising boundary conditions,
//! serde roundtrips for all public types, ordering guarantees, Merkle tree
//! edge cases, verification report semantics, and builder API interactions.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::causal_replay::{
    ActionDeltaReport, CounterfactualConfig, DecisionSnapshot, NondeterminismLog,
    NondeterminismSource, RecorderConfig, RecordingMode, TraceRecord, TraceRecorder,
};
use frankenengine_engine::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::incident_replay_bundle::{
    ArtifactEntry, BUNDLE_FORMAT_VERSION, BundleArtifactKind, BundleBuilder, BundleError,
    BundleFormatVersion, BundleInspection, BundleManifest, BundleVerifier, CategorySummary,
    CheckOutcome, CounterfactualResult, IncidentReplayBundle, PolicySnapshot, RedactionPolicy,
    VerificationCategory, VerificationCheck, VerificationReport, build_merkle_proof,
    compute_merkle_root, verify_merkle_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> SigningKey {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    SigningKey::from_bytes(key)
}

fn make_trace(trace_id: &str, num_decisions: usize) -> TraceRecord {
    let key = test_signing_key();
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

fn make_evidence_entry() -> frankenengine_engine::evidence_ledger::EvidenceEntry {
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

fn make_policy_snapshot(policy_id: &str) -> PolicySnapshot {
    PolicySnapshot {
        policy_id: policy_id.to_string(),
        policy_version: "1.0".to_string(),
        active_epoch: SecurityEpoch::from_raw(100),
        config_hash: ContentHash::compute(b"test-policy-config"),
        config_bytes: b"test-policy-config".to_vec(),
    }
}

fn make_nondeterminism_log() -> NondeterminismLog {
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

fn build_test_bundle() -> IncidentReplayBundle {
    let key = test_signing_key();
    BundleBuilder::new(
        "incident-001".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "producer-key-1".to_string(),
        key,
    )
    .window(1000, 2000)
    .meta("severity".to_string(), "high".to_string())
    .trace("trace-001".to_string(), make_trace("trace-001", 3))
    .evidence("evidence-001".to_string(), make_evidence_entry())
    .nondeterminism("trace-001".to_string(), make_nondeterminism_log())
    .policy("policy-001".to_string(), make_policy_snapshot("policy-001"))
    .build()
    .expect("bundle build should succeed")
}

// ===========================================================================
// BundleFormatVersion
// ===========================================================================

#[test]
fn format_version_serde_roundtrip() {
    let v = BundleFormatVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let restored: BundleFormatVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn format_version_ordering() {
    let v10 = BundleFormatVersion { major: 1, minor: 0 };
    let v11 = BundleFormatVersion { major: 1, minor: 1 };
    let v20 = BundleFormatVersion { major: 2, minor: 0 };
    assert!(v10 < v11);
    assert!(v11 < v20);
    assert!(v10 < v20);
}

#[test]
fn format_version_display_zero() {
    let v = BundleFormatVersion { major: 0, minor: 0 };
    assert_eq!(v.to_string(), "0.0");
}

#[test]
fn format_version_compatibility_same_major_equal_minor() {
    let v = BundleFormatVersion { major: 1, minor: 5 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn format_version_incompatible_future_minor() {
    let reader = BundleFormatVersion { major: 1, minor: 0 };
    let bundle = BundleFormatVersion { major: 1, minor: 2 };
    assert!(!reader.is_compatible_with(&bundle));
}

#[test]
fn bundle_format_version_constant() {
    assert_eq!(BUNDLE_FORMAT_VERSION.major, 1);
    assert_eq!(BUNDLE_FORMAT_VERSION.minor, 0);
}

// ===========================================================================
// BundleError
// ===========================================================================

#[test]
fn bundle_error_serde_all_variants() {
    let errors = vec![
        BundleError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        BundleError::ArtifactHashMismatch {
            artifact_id: "art-1".to_string(),
        },
        BundleError::SignatureInvalid,
        BundleError::ReplayDivergence {
            details: "mismatch".to_string(),
        },
        BundleError::ReceiptInvalid {
            receipt_id: "r1".to_string(),
            reason: "bad sig".to_string(),
        },
        BundleError::IncompatibleVersion {
            bundle: BundleFormatVersion { major: 2, minor: 0 },
            reader: BundleFormatVersion { major: 1, minor: 0 },
        },
        BundleError::EmptyBundle,
        BundleError::TraceNotFound {
            trace_id: "t1".to_string(),
        },
        BundleError::IdDerivation("bad seed".to_string()),
        BundleError::ReplayFailed("timeout".to_string()),
        BundleError::RedactionViolation {
            field: "secret_field".to_string(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: BundleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "serde roundtrip failed for {:?}", err);
    }
}

#[test]
fn bundle_error_is_std_error() {
    let err = BundleError::SignatureInvalid;
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.source().is_none());
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn bundle_error_display_contains_details() {
    let err = BundleError::IntegrityFailure {
        expected: "abc".to_string(),
        actual: "def".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("abc"), "expected value should be in display");
    assert!(s.contains("def"), "actual value should be in display");
}

#[test]
fn bundle_error_display_receipt_invalid() {
    let err = BundleError::ReceiptInvalid {
        receipt_id: "r-42".to_string(),
        reason: "expired".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("r-42"));
    assert!(s.contains("expired"));
}

#[test]
fn bundle_error_display_redaction_violation() {
    let err = BundleError::RedactionViolation {
        field: "tenant_id".to_string(),
    };
    assert!(err.to_string().contains("tenant_id"));
}

// ===========================================================================
// BundleArtifactKind
// ===========================================================================

#[test]
fn artifact_kind_serde_all_variants() {
    let kinds = vec![
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::OptReceipt,
        BundleArtifactKind::QuorumCheckpoint,
        BundleArtifactKind::NondeterminismLog,
        BundleArtifactKind::CounterfactualResult,
        BundleArtifactKind::PolicySnapshot,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: BundleArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn artifact_kind_ordering() {
    let mut kinds = [
        BundleArtifactKind::PolicySnapshot,
        BundleArtifactKind::Trace,
        BundleArtifactKind::Evidence,
        BundleArtifactKind::NondeterminismLog,
    ];
    kinds.sort();
    // Ordering follows variant declaration order (Trace < Evidence < ... < PolicySnapshot).
    assert_eq!(kinds[0], BundleArtifactKind::Trace);
    assert_eq!(kinds[kinds.len() - 1], BundleArtifactKind::PolicySnapshot);
}

// ===========================================================================
// RedactionPolicy
// ===========================================================================

#[test]
fn redaction_policy_with_all_flags() {
    let policy = RedactionPolicy {
        redact_extension_ids: true,
        redact_evidence_metadata: true,
        redact_nondeterminism_values: true,
        redact_node_ids: true,
        custom_redaction_keys: {
            let mut s = BTreeSet::new();
            s.insert("key_a".to_string());
            s.insert("key_b".to_string());
            s
        },
    };
    let json = serde_json::to_string(&policy).unwrap();
    let restored: RedactionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
    assert_eq!(restored.custom_redaction_keys.len(), 2);
}

#[test]
fn redaction_policy_default_empty_custom_keys() {
    let policy = RedactionPolicy::default();
    assert!(policy.custom_redaction_keys.is_empty());
    assert!(!policy.redact_extension_ids);
    assert!(!policy.redact_evidence_metadata);
    assert!(!policy.redact_nondeterminism_values);
    assert!(!policy.redact_node_ids);
}

// ===========================================================================
// CheckOutcome
// ===========================================================================

#[test]
fn check_outcome_serde_all_variants() {
    let outcomes = vec![
        CheckOutcome::Pass,
        CheckOutcome::Fail {
            reason: "bad".to_string(),
        },
        CheckOutcome::Skipped {
            reason: "n/a".to_string(),
        },
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let restored: CheckOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, restored);
    }
}

#[test]
fn check_outcome_is_pass_false_for_skipped() {
    let skip = CheckOutcome::Skipped {
        reason: "redacted".to_string(),
    };
    assert!(!skip.is_pass());
    assert!(!skip.is_fail());
}

// ===========================================================================
// VerificationCategory
// ===========================================================================

#[test]
fn verification_category_serde_all_variants() {
    let cats = vec![
        VerificationCategory::Integrity,
        VerificationCategory::ArtifactHash,
        VerificationCategory::Replay,
        VerificationCategory::ReceiptChain,
        VerificationCategory::Counterfactual,
        VerificationCategory::Compatibility,
    ];
    for cat in &cats {
        let json = serde_json::to_string(cat).unwrap();
        let restored: VerificationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, restored);
    }
}

#[test]
fn verification_category_ordering() {
    assert!(VerificationCategory::Integrity < VerificationCategory::ArtifactHash);
    assert!(VerificationCategory::Replay < VerificationCategory::ReceiptChain);
    assert!(VerificationCategory::ReceiptChain < VerificationCategory::Counterfactual);
    assert!(VerificationCategory::Counterfactual < VerificationCategory::Compatibility);
}

// ===========================================================================
// VerificationCheck
// ===========================================================================

#[test]
fn verification_check_serde_roundtrip() {
    let check = VerificationCheck {
        name: "test-check".to_string(),
        category: VerificationCategory::Integrity,
        outcome: CheckOutcome::Pass,
    };
    let json = serde_json::to_string(&check).unwrap();
    let restored: VerificationCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, restored);
}

#[test]
fn verification_check_fail_serde() {
    let check = VerificationCheck {
        name: "fail-check".to_string(),
        category: VerificationCategory::ArtifactHash,
        outcome: CheckOutcome::Fail {
            reason: "hash mismatch".to_string(),
        },
    };
    let json = serde_json::to_string(&check).unwrap();
    let restored: VerificationCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, restored);
}

// ===========================================================================
// CategorySummary
// ===========================================================================

#[test]
fn category_summary_serde_roundtrip() {
    let summary = CategorySummary {
        passed: 5,
        failed: 2,
        skipped: 1,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: CategorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// ===========================================================================
// ArtifactEntry
// ===========================================================================

#[test]
fn artifact_entry_serde_roundtrip() {
    let entry = ArtifactEntry {
        artifact_id: "art-001".to_string(),
        kind: BundleArtifactKind::Evidence,
        content_hash: ContentHash::compute(b"test-data"),
        redacted: false,
        size_bytes: 1024,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn artifact_entry_redacted_flag() {
    let entry = ArtifactEntry {
        artifact_id: "redacted-art".to_string(),
        kind: BundleArtifactKind::NondeterminismLog,
        content_hash: ContentHash::compute(b"redacted"),
        redacted: true,
        size_bytes: 0,
    };
    assert!(entry.redacted);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert!(restored.redacted);
}

// ===========================================================================
// PolicySnapshot
// ===========================================================================

#[test]
fn policy_snapshot_different_epochs() {
    let p1 = PolicySnapshot {
        policy_id: "p1".to_string(),
        policy_version: "1.0".to_string(),
        active_epoch: SecurityEpoch::from_raw(1),
        config_hash: ContentHash::compute(b"cfg1"),
        config_bytes: b"cfg1".to_vec(),
    };
    let p2 = PolicySnapshot {
        policy_id: "p1".to_string(),
        policy_version: "2.0".to_string(),
        active_epoch: SecurityEpoch::from_raw(200),
        config_hash: ContentHash::compute(b"cfg2"),
        config_bytes: b"cfg2".to_vec(),
    };
    assert_ne!(p1, p2);
    assert_ne!(p1.config_hash, p2.config_hash);
}

// ===========================================================================
// Merkle tree edge cases
// ===========================================================================

#[test]
fn merkle_root_leaf_order_matters() {
    let a = ContentHash::compute(b"alpha");
    let b = ContentHash::compute(b"beta");
    let root_ab = compute_merkle_root(&[a, b]);
    let root_ba = compute_merkle_root(&[b, a]);
    assert_ne!(
        root_ab, root_ba,
        "different leaf order must produce different root"
    );
}

#[test]
fn merkle_root_three_leaves() {
    let leaves: Vec<ContentHash> = (0..3)
        .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
        .collect();
    let root = compute_merkle_root(&leaves);
    // Should succeed and differ from any single leaf.
    for leaf in &leaves {
        assert_ne!(&root, leaf);
    }
}

#[test]
fn merkle_root_large_tree() {
    let leaves: Vec<ContentHash> = (0..100)
        .map(|i| ContentHash::compute(format!("big-{i}").as_bytes()))
        .collect();
    let root1 = compute_merkle_root(&leaves);
    let root2 = compute_merkle_root(&leaves);
    assert_eq!(root1, root2, "large tree must be deterministic");
}

#[test]
fn merkle_proof_out_of_bounds_returns_empty() {
    let leaves: Vec<ContentHash> = (0..4)
        .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
        .collect();
    let proof = build_merkle_proof(&leaves, 99);
    assert!(proof.is_empty());
}

#[test]
fn merkle_proof_empty_leaves() {
    let proof = build_merkle_proof(&[], 0);
    assert!(proof.is_empty());
}

#[test]
fn merkle_proof_three_leaves_all_valid() {
    let leaves: Vec<ContentHash> = (0..3)
        .map(|i| ContentHash::compute(format!("three-{i}").as_bytes()))
        .collect();
    let root = compute_merkle_root(&leaves);
    for idx in 0..leaves.len() {
        let proof = build_merkle_proof(&leaves, idx);
        assert!(
            verify_merkle_proof(&leaves[idx], &proof, &root),
            "proof must verify for leaf {idx} in 3-leaf tree"
        );
    }
}

#[test]
fn verify_merkle_proof_empty_proof_only_valid_for_single_leaf() {
    let leaf = ContentHash::compute(b"only");
    let root = compute_merkle_root(std::slice::from_ref(&leaf));
    // Empty proof with correct leaf/root should pass.
    assert!(verify_merkle_proof(&leaf, &[], &root));
    // Empty proof with wrong root should fail.
    let wrong_root = ContentHash::compute(b"wrong");
    assert!(!verify_merkle_proof(&leaf, &[], &wrong_root));
}

// ===========================================================================
// BundleBuilder
// ===========================================================================

#[test]
fn builder_only_policy_snapshot() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "policy-only".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    assert_eq!(bundle.traces.len(), 0);
    assert_eq!(bundle.policy_snapshots.len(), 1);
    assert_eq!(bundle.manifest.artifacts.len(), 1);
}

#[test]
fn builder_with_redaction_policy() {
    let key = test_signing_key();
    let policy = RedactionPolicy {
        redact_extension_ids: true,
        redact_node_ids: true,
        ..RedactionPolicy::default()
    };
    let bundle = BundleBuilder::new(
        "redacted".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .redaction_policy(policy.clone())
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.redaction_policy, policy);
    assert!(bundle.manifest.redaction_policy.redact_extension_ids);
}

#[test]
fn builder_multiple_metadata_entries() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "meta-test".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .meta("key1".to_string(), "val1".to_string())
    .meta("key2".to_string(), "val2".to_string())
    .meta("key3".to_string(), "val3".to_string())
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.metadata.len(), 3);
    assert_eq!(
        bundle.manifest.metadata.get("key2"),
        Some(&"val2".to_string())
    );
}

#[test]
fn builder_window_values_preserved() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "window-test".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .window(42, 9999)
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.window_start_tick, 42);
    assert_eq!(bundle.manifest.window_end_tick, 9999);
}

#[test]
fn builder_default_window_is_zero() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "no-window".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.window_start_tick, 0);
    assert_eq!(bundle.manifest.window_end_tick, 0);
}

#[test]
fn builder_signature_is_64_bytes() {
    let bundle = build_test_bundle();
    assert_eq!(
        bundle.manifest.signature.len(),
        64,
        "ed25519 signature must be 64 bytes"
    );
}

#[test]
fn builder_artifact_keys_use_composite_format() {
    let bundle = build_test_bundle();
    // BundleBuilder uses "{kind}:{id}" as artifact keys.
    for (key, entry) in &bundle.manifest.artifacts {
        let expected_prefix = format!("{}:", entry.kind);
        assert!(
            key.starts_with(&expected_prefix),
            "artifact key '{key}' should start with '{expected_prefix}'"
        );
    }
}

#[test]
fn builder_artifact_sizes_positive() {
    let bundle = build_test_bundle();
    for entry in bundle.manifest.artifacts.values() {
        assert!(
            entry.size_bytes > 0,
            "artifact {:?} should have non-zero size",
            entry.kind
        );
    }
}

// ===========================================================================
// BundleVerifier
// ===========================================================================

#[test]
fn verifier_default() {
    let verifier = BundleVerifier::new();
    // Should be usable immediately.
    let bundle = build_test_bundle();
    let report = verifier.verify_integrity(&bundle, 1000);
    assert!(report.passed);
}

#[test]
fn verifier_integrity_report_has_bundle_id() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert_eq!(report.bundle_id, bundle.manifest.bundle_id);
    assert_eq!(report.incident_id, "incident-001");
}

#[test]
fn verifier_integrity_report_verified_at_ns() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 42_000);
    assert_eq!(report.verified_at_ns, 42_000);
}

#[test]
fn verifier_integrity_report_version() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert_eq!(report.verifier_version, BUNDLE_FORMAT_VERSION);
}

#[test]
fn verifier_replay_empty_bundle_skips() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "no-traces".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .policy("p1".to_string(), make_policy_snapshot("p1"))
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
    assert_eq!(skipped.len(), 1);
}

#[test]
fn verifier_receipts_empty_skips() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let vkeys = BTreeMap::new();
    let report = verifier.verify_receipts(&bundle, &vkeys, SecurityEpoch::from_raw(100), 6000);
    assert!(report.passed);

    let skipped: Vec<_> = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
        .collect();
    assert_eq!(skipped.len(), 1);
}

#[test]
fn verifier_counterfactual_empty_configs_produces_empty_report() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_counterfactual(&bundle, &[], 6000);
    assert!(report.passed);
    assert_eq!(report.checks.len(), 0);
}

// ===========================================================================
// BundleManifest signing_bytes
// ===========================================================================

#[test]
fn manifest_signing_bytes_differ_with_metadata() {
    let bundle1 = build_test_bundle();
    let key = test_signing_key();
    let bundle2 = BundleBuilder::new(
        "incident-001".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "producer-key-1".to_string(),
        key,
    )
    .window(1000, 2000)
    .meta("severity".to_string(), "low".to_string())
    .trace("trace-001".to_string(), make_trace("trace-001", 3))
    .evidence("evidence-001".to_string(), make_evidence_entry())
    .nondeterminism("trace-001".to_string(), make_nondeterminism_log())
    .policy("policy-001".to_string(), make_policy_snapshot("policy-001"))
    .build()
    .unwrap();

    // Different metadata -> different signing bytes.
    assert_ne!(
        bundle1.manifest.signing_bytes(),
        bundle2.manifest.signing_bytes()
    );
}

// ===========================================================================
// IncidentReplayBundle serde
// ===========================================================================

#[test]
fn bundle_serde_roundtrip_preserves_all_fields() {
    let bundle = build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(bundle.manifest.bundle_id, restored.manifest.bundle_id);
    assert_eq!(bundle.manifest.incident_id, restored.manifest.incident_id);
    assert_eq!(bundle.manifest.merkle_root, restored.manifest.merkle_root);
    assert_eq!(bundle.manifest.signature, restored.manifest.signature);
    assert_eq!(bundle.traces.len(), restored.traces.len());
    assert_eq!(
        bundle.evidence_entries.len(),
        restored.evidence_entries.len()
    );
    assert_eq!(
        bundle.nondeterminism_logs.len(),
        restored.nondeterminism_logs.len()
    );
    assert_eq!(
        bundle.policy_snapshots.len(),
        restored.policy_snapshots.len()
    );
}

#[test]
fn bundle_manifest_serde_roundtrip() {
    let bundle = build_test_bundle();
    let json = serde_json::to_string(&bundle.manifest).unwrap();
    let restored: BundleManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.manifest, restored);
}

// ===========================================================================
// VerificationReport
// ===========================================================================

#[test]
fn verification_report_serde_roundtrip() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    let json = serde_json::to_string(&report).unwrap();
    let restored: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn verification_report_pass_fail_counts_consistent() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);

    let total = report.pass_count() + report.fail_count();
    let skipped: u64 = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
        .count() as u64;
    assert_eq!(
        total + skipped,
        report.checks.len() as u64,
        "pass + fail + skipped must equal total checks"
    );
}

#[test]
fn verification_report_summary_matches_checks() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);

    let total_from_summary: u64 = report
        .summary
        .values()
        .map(|s| s.passed + s.failed + s.skipped)
        .sum();
    assert_eq!(total_from_summary, report.checks.len() as u64);
}

// ===========================================================================
// BundleInspection
// ===========================================================================

#[test]
fn inspection_serde_roundtrip() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    let json = serde_json::to_string(&inspection).unwrap();
    let restored: BundleInspection = serde_json::from_str(&json).unwrap();
    assert_eq!(inspection, restored);
}

#[test]
fn inspection_epochs_include_creation_and_trace_epochs() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);

    // Creation epoch (100) should be in the set.
    assert!(inspection.epochs.contains(&100));
}

#[test]
fn inspection_artifact_counts_match_bundle() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);

    let total_artifacts: u64 = inspection.artifact_counts.values().sum();
    assert_eq!(
        total_artifacts,
        bundle.manifest.artifacts.len() as u64,
        "inspection artifact count must match manifest"
    );
}

#[test]
fn inspection_no_redacted_artifacts_in_default_bundle() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.redacted_count, 0);
}

#[test]
fn inspection_window_matches_builder() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(inspection.window, (1000, 2000));
}

#[test]
fn inspection_metadata_preserved() {
    let bundle = build_test_bundle();
    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);
    assert_eq!(
        inspection.metadata.get("severity"),
        Some(&"high".to_string())
    );
}

// ===========================================================================
// CounterfactualResult
// ===========================================================================

#[test]
fn counterfactual_result_serde_with_overrides() {
    let mut loss_overrides = BTreeMap::new();
    loss_overrides.insert("action-a".to_string(), 250_000i64);

    let result = CounterfactualResult {
        config: CounterfactualConfig {
            branch_id: "alt-branch".to_string(),
            threshold_override_millionths: Some(400_000),
            loss_matrix_overrides: loss_overrides,
            policy_version_override: Some(2),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 5,
        },
        delta_report: ActionDeltaReport {
            config: CounterfactualConfig {
                branch_id: "alt-branch".to_string(),
                threshold_override_millionths: Some(400_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: Some(2),
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 5,
            },
            harm_prevented_delta_millionths: 100_000,
            false_positive_cost_delta_millionths: -50_000,
            containment_latency_delta_ticks: -10,
            resource_cost_delta_millionths: 30_000,
            affected_extensions: BTreeSet::new(),
            divergence_points: Vec::new(),
            decisions_evaluated: 20,
        },
        source_trace_id: "trace-002".to_string(),
    };

    let json = serde_json::to_string(&result).unwrap();
    let restored: CounterfactualResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// Bundle determinism
// ===========================================================================

#[test]
fn bundle_id_deterministic_across_builds() {
    let b1 = build_test_bundle();
    let b2 = build_test_bundle();
    assert_eq!(b1.manifest.bundle_id, b2.manifest.bundle_id);
}

#[test]
fn bundle_merkle_root_deterministic() {
    let b1 = build_test_bundle();
    let b2 = build_test_bundle();
    assert_eq!(b1.manifest.merkle_root, b2.manifest.merkle_root);
}

#[test]
fn bundle_signature_deterministic() {
    let b1 = build_test_bundle();
    let b2 = build_test_bundle();
    assert_eq!(b1.manifest.signature, b2.manifest.signature);
}

// ===========================================================================
// Multi-trace bundles
// ===========================================================================

#[test]
fn multi_trace_bundle_integrity() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "multi".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t-alpha".to_string(), make_trace("t-alpha", 1))
    .trace("t-beta".to_string(), make_trace("t-beta", 2))
    .trace("t-gamma".to_string(), make_trace("t-gamma", 5))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let integrity = verifier.verify_integrity(&bundle, 6000);
    assert!(integrity.passed, "multi-trace integrity: {integrity:?}");
    assert_eq!(bundle.traces.len(), 3);
}

#[test]
fn multi_trace_bundle_replay() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "replay-multi".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .trace("t2".to_string(), make_trace("t2", 3))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_replay(&bundle, 6000);
    assert!(report.passed, "multi-trace replay: {report:?}");

    // Should have chain integrity + replay fidelity checks for each trace.
    let replay_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Replay)
        .collect();
    assert!(
        replay_checks.len() >= 4,
        "expected at least 4 replay checks for 2 traces, got {}",
        replay_checks.len()
    );
}

// ===========================================================================
// Signature verification
// ===========================================================================

#[test]
fn signature_valid_with_correct_key() {
    let bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(report.passed);
    assert!(report.pass_count() > 0);
}

#[test]
fn signature_invalid_with_different_key() {
    let bundle = build_test_bundle();
    let wrong_key = SigningKey::from_bytes([0xFFu8; 32]).verification_key();
    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &wrong_key, 6000);
    assert!(!report.passed);
    assert!(report.fail_count() > 0);
}

#[test]
fn signature_invalid_with_tampered_manifest() {
    let mut bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();

    // Tamper with incident_id after signing.
    bundle.manifest.incident_id = "tampered-incident".to_string();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(
        !report.passed,
        "tampered manifest should fail signature check"
    );
}

// ===========================================================================
// Integrity tampering detection
// ===========================================================================

#[test]
fn integrity_detects_extra_artifact_in_manifest() {
    let mut bundle = build_test_bundle();
    // Add a phantom artifact entry to the manifest.
    bundle.manifest.artifacts.insert(
        "phantom:ghost".to_string(),
        ArtifactEntry {
            artifact_id: "ghost".to_string(),
            kind: BundleArtifactKind::Evidence,
            content_hash: ContentHash::compute(b"phantom"),
            redacted: false,
            size_bytes: 100,
        },
    );

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    // Merkle root and/or artifact hash checks should fail.
    assert!(!report.passed);
}

// ===========================================================================
// Edge cases with empty and minimal bundles
// ===========================================================================

#[test]
fn empty_bundle_builder_fails() {
    let key = test_signing_key();
    let result = BundleBuilder::new(
        "empty".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .build();
    assert!(matches!(result, Err(BundleError::EmptyBundle)));
}

#[test]
fn minimal_bundle_with_single_evidence() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "min-ev".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .evidence("ev1".to_string(), make_evidence_entry())
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.artifacts.len(), 1);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 2000);
    assert!(report.passed);
}

#[test]
fn minimal_bundle_with_single_nondeterminism_log() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "min-nd".to_string(),
        SecurityEpoch::from_raw(1),
        1000,
        "key-1".to_string(),
        key,
    )
    .nondeterminism("log-1".to_string(), make_nondeterminism_log())
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.artifacts.len(), 1);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 2000);
    assert!(report.passed);
}
