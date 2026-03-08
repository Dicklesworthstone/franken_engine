#![forbid(unsafe_code)]
//! Enrichment integration tests for `incident_replay_bundle`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, Merkle tree edge cases, and factory
//! defaults beyond the existing 41 integration tests.

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
    let root = compute_merkle_root(&[l1.clone(), l2.clone()]);
    let root2 = compute_merkle_root(&[l1, l2]);
    assert_eq!(root, root2);
}

#[test]
fn merkle_root_order_matters() {
    let l1 = ContentHash::compute(b"a");
    let l2 = ContentHash::compute(b"b");
    let root1 = compute_merkle_root(&[l1.clone(), l2.clone()]);
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
    let leaves = [l1.clone(), l2.clone()];
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
