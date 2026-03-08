#![forbid(unsafe_code)]
//! Enrichment integration tests for `capability_witness`.
//!
//! Adds LifecycleState Display/ordering, WitnessError Display uniqueness,
//! ProofKind/PromotionTheoremKind Display, serde roundtrips, JSON field-name
//! stability, WitnessSchemaVersion compatibility, ConfidenceInterval math,
//! and WitnessValidator/WitnessStore construction beyond the existing
//! 109 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::capability_witness::{
    ConfidenceInterval, DenialRecord, LifecycleState, PromotionTheoremKind, ProofKind,
    ProofObligation, PublicationEntryKind, RollbackToken, WitnessBuilder, WitnessError,
    WitnessSchemaVersion, WitnessStore, WitnessValidator,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

// ===========================================================================
// 1) LifecycleState — Display + ordering + methods
// ===========================================================================

#[test]
fn lifecycle_state_display_all_distinct() {
    let displays: Vec<String> = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn lifecycle_state_ordering_stable() {
    let mut states = [
        LifecycleState::Revoked,
        LifecycleState::Draft,
        LifecycleState::Active,
        LifecycleState::Validated,
    ];
    states.sort();
    let first = states[0];
    let last = states[states.len() - 1];
    assert!(first <= last);
}

#[test]
fn lifecycle_state_is_terminal() {
    assert!(!LifecycleState::Draft.is_terminal());
    assert!(!LifecycleState::Validated.is_terminal());
    assert!(!LifecycleState::Promoted.is_terminal());
    assert!(!LifecycleState::Active.is_terminal());
    assert!(LifecycleState::Superseded.is_terminal());
    assert!(LifecycleState::Revoked.is_terminal());
}

#[test]
fn lifecycle_state_is_active() {
    assert!(!LifecycleState::Draft.is_active());
    assert!(LifecycleState::Active.is_active());
    assert!(!LifecycleState::Revoked.is_active());
}

#[test]
fn lifecycle_state_transitions() {
    assert!(LifecycleState::Draft.can_transition_to(LifecycleState::Validated));
    assert!(!LifecycleState::Revoked.can_transition_to(LifecycleState::Draft));
    assert!(LifecycleState::Active.can_transition_to(LifecycleState::Superseded));
}

// ===========================================================================
// 2) ProofKind — Display + ordering
// ===========================================================================

#[test]
fn proof_kind_display_all_distinct() {
    let displays: Vec<String> = [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn proof_kind_ordering_stable() {
    let mut kinds = [
        ProofKind::InheritedFromPredecessor,
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
    ];
    kinds.sort();
    assert!(kinds[0] <= kinds[kinds.len() - 1]);
}

// ===========================================================================
// 3) PromotionTheoremKind — Display
// ===========================================================================

#[test]
fn promotion_theorem_kind_display_all_distinct() {
    let displays: Vec<String> = [
        PromotionTheoremKind::MergeLegality,
        PromotionTheoremKind::AttenuationLegality,
        PromotionTheoremKind::NonInterference,
        PromotionTheoremKind::Custom("mycheck".into()),
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn promotion_theorem_custom_display_contains_name() {
    let k = PromotionTheoremKind::Custom("my-theorem".into());
    let s = k.to_string();
    assert!(s.contains("my-theorem"), "should contain custom name: {s}");
}

// ===========================================================================
// 4) PublicationEntryKind — as_str + Display
// ===========================================================================

#[test]
fn publication_entry_kind_as_str() {
    assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
}

#[test]
fn publication_entry_kind_display_matches_as_str() {
    assert_eq!(
        PublicationEntryKind::Publish.to_string(),
        PublicationEntryKind::Publish.as_str()
    );
    assert_eq!(
        PublicationEntryKind::Revoke.to_string(),
        PublicationEntryKind::Revoke.as_str()
    );
}

// ===========================================================================
// 5) WitnessError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn witness_error_display_all_unique() {
    let variants: Vec<String> = vec![
        WitnessError::EmptyRequiredSet.to_string(),
        WitnessError::MissingProofObligation {
            capability: "cap1".into(),
        }
        .to_string(),
        WitnessError::InvalidConfidence {
            reason: "bad".into(),
        }
        .to_string(),
        WitnessError::InvalidTransition {
            from: LifecycleState::Draft,
            to: LifecycleState::Active,
        }
        .to_string(),
        WitnessError::IncompatibleSchema {
            witness: WitnessSchemaVersion { major: 1, minor: 0 },
            reader: WitnessSchemaVersion { major: 2, minor: 0 },
        }
        .to_string(),
        WitnessError::SignatureInvalid {
            detail: "bad sig".into(),
        }
        .to_string(),
        WitnessError::IntegrityFailure {
            expected: "a".into(),
            actual: "b".into(),
        }
        .to_string(),
        WitnessError::IdDerivation("derivation error".into()).to_string(),
        WitnessError::InvalidRollbackToken {
            reason: "expired".into(),
        }
        .to_string(),
        WitnessError::EpochMismatch {
            witness_epoch: 1,
            current_epoch: 2,
        }
        .to_string(),
        WitnessError::MissingPromotionTheoremProofs {
            missing_checks: vec!["x".into()],
        }
        .to_string(),
        WitnessError::PromotionTheoremFailed {
            failed_checks: vec!["y".into()],
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn witness_error_is_std_error() {
    let e = WitnessError::EmptyRequiredSet;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 6) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_lifecycle_state() {
    let variants: Vec<String> = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ]
    .iter()
    .map(|s| format!("{s:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_proof_kind() {
    let variants: Vec<String> = [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ]
    .iter()
    .map(|k| format!("{k:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 7) WitnessSchemaVersion — compatibility + Display
// ===========================================================================

#[test]
fn schema_version_current() {
    let current = WitnessSchemaVersion::CURRENT;
    assert_eq!(current.major, 1);
    assert_eq!(current.minor, 0);
}

#[test]
fn schema_version_display() {
    let v = WitnessSchemaVersion { major: 2, minor: 3 };
    assert_eq!(v.to_string(), "2.3");
}

#[test]
fn schema_version_compatible_same() {
    let v = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(v.is_compatible_with(&WitnessSchemaVersion { major: 1, minor: 0 }));
}

#[test]
fn schema_version_incompatible_different_major() {
    let reader = WitnessSchemaVersion { major: 2, minor: 0 };
    assert!(!reader.is_compatible_with(&WitnessSchemaVersion { major: 1, minor: 0 }));
}

// ===========================================================================
// 8) ConfidenceInterval — math
// ===========================================================================

#[test]
fn confidence_interval_from_trials() {
    let ci = ConfidenceInterval::from_trials(100, 95);
    assert!(ci.lower_millionths > 0);
    assert!(ci.upper_millionths <= 1_000_000);
    assert!(ci.lower_millionths <= ci.upper_millionths);
    assert_eq!(ci.n_trials, 100);
    assert_eq!(ci.n_successes, 95);
}

#[test]
fn confidence_interval_point_estimate() {
    let ci = ConfidenceInterval::from_trials(100, 50);
    let point = ci.point_estimate_millionths();
    assert!(
        point > 400_000 && point < 600_000,
        "point estimate should be ~500000: {point}"
    );
}

#[test]
fn confidence_interval_meets_threshold() {
    let ci = ConfidenceInterval::from_trials(1000, 990);
    assert!(
        ci.meets_threshold(900_000),
        "99% success rate should meet 900k threshold"
    );
}

// ===========================================================================
// 9) Serde roundtrips — structs
// ===========================================================================

#[test]
fn serde_roundtrip_lifecycle_state_all() {
    for s in [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_proof_kind_all() {
    for k in [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: ProofKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_promotion_theorem_kind() {
    for k in [
        PromotionTheoremKind::MergeLegality,
        PromotionTheoremKind::AttenuationLegality,
        PromotionTheoremKind::NonInterference,
        PromotionTheoremKind::Custom("mycheck".into()),
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: PromotionTheoremKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_witness_error_all() {
    let variants = vec![
        WitnessError::EmptyRequiredSet,
        WitnessError::MissingProofObligation {
            capability: "cap".into(),
        },
        WitnessError::InvalidConfidence {
            reason: "bad".into(),
        },
        WitnessError::InvalidTransition {
            from: LifecycleState::Draft,
            to: LifecycleState::Active,
        },
        WitnessError::IncompatibleSchema {
            witness: WitnessSchemaVersion::CURRENT,
            reader: WitnessSchemaVersion { major: 2, minor: 0 },
        },
        WitnessError::SignatureInvalid {
            detail: "sig".into(),
        },
        WitnessError::IntegrityFailure {
            expected: "a".into(),
            actual: "b".into(),
        },
        WitnessError::IdDerivation("err".into()),
        WitnessError::InvalidRollbackToken {
            reason: "exp".into(),
        },
        WitnessError::EpochMismatch {
            witness_epoch: 1,
            current_epoch: 2,
        },
        WitnessError::MissingPromotionTheoremProofs {
            missing_checks: vec!["x".into()],
        },
        WitnessError::PromotionTheoremFailed {
            failed_checks: vec!["y".into()],
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: WitnessError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_confidence_interval() {
    let ci = ConfidenceInterval::from_trials(200, 190);
    let json = serde_json::to_string(&ci).unwrap();
    let rt: ConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, rt);
}

#[test]
fn serde_roundtrip_rollback_token() {
    let rt_tok = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev"),
        previous_witness_id: Some(oid(1)),
        created_epoch: SecurityEpoch::from_raw(5),
        sequence: 3,
    };
    let json = serde_json::to_string(&rt_tok).unwrap();
    let rt: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(rt_tok, rt);
}

#[test]
fn serde_roundtrip_proof_obligation() {
    let po = ProofObligation {
        capability: Capability::new("file-read"),
        kind: ProofKind::StaticAnalysis,
        proof_artifact_id: oid(2),
        justification: "static analysis passed".into(),
        artifact_hash: ContentHash::compute(b"proof-artifact"),
    };
    let json = serde_json::to_string(&po).unwrap();
    let rt: ProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(po, rt);
}

#[test]
fn serde_roundtrip_denial_record() {
    let dr = DenialRecord {
        capability: Capability::new("network-connect"),
        reason: "policy denial".into(),
        evidence_id: Some(oid(3)),
    };
    let json = serde_json::to_string(&dr).unwrap();
    let rt: DenialRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(dr, rt);
}

// ===========================================================================
// 10) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_confidence_interval() {
    let ci = ConfidenceInterval::from_trials(10, 8);
    let v: serde_json::Value = serde_json::to_value(ci).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "lower_millionths",
        "upper_millionths",
        "n_trials",
        "n_successes",
    ] {
        assert!(
            obj.contains_key(key),
            "ConfidenceInterval missing field: {key}"
        );
    }
}

#[test]
fn json_fields_rollback_token() {
    let tok = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"h"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(0),
        sequence: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&tok).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "previous_witness_hash",
        "previous_witness_id",
        "created_epoch",
        "sequence",
    ] {
        assert!(obj.contains_key(key), "RollbackToken missing field: {key}");
    }
}

#[test]
fn json_fields_proof_obligation() {
    let po = ProofObligation {
        capability: Capability::new("file-read"),
        kind: ProofKind::DynamicAblation,
        proof_artifact_id: oid(0),
        justification: "j".into(),
        artifact_hash: ContentHash::compute(b"a"),
    };
    let v: serde_json::Value = serde_json::to_value(&po).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "capability",
        "kind",
        "proof_artifact_id",
        "justification",
        "artifact_hash",
    ] {
        assert!(
            obj.contains_key(key),
            "ProofObligation missing field: {key}"
        );
    }
}

#[test]
fn json_fields_denial_record() {
    let dr = DenialRecord {
        capability: Capability::new("network-connect"),
        reason: "r".into(),
        evidence_id: None,
    };
    let v: serde_json::Value = serde_json::to_value(&dr).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["capability", "reason", "evidence_id"] {
        assert!(obj.contains_key(key), "DenialRecord missing field: {key}");
    }
}

// ===========================================================================
// 11) WitnessValidator + WitnessStore — construction
// ===========================================================================

#[test]
fn witness_validator_new() {
    let _validator = WitnessValidator::new();
}

#[test]
fn witness_validator_default() {
    let _validator = WitnessValidator::default();
}

#[test]
fn witness_store_new_empty() {
    let store = WitnessStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

// ===========================================================================
// 12) WitnessBuilder — minimal build
// ===========================================================================

#[test]
fn witness_builder_empty_required_set_fails() {
    let key = SigningKey::from_bytes([0xAA; 32]);
    let result = WitnessBuilder::new(oid(1), oid(2), SecurityEpoch::from_raw(1), 1000, key).build();
    assert!(result.is_err());
}

// ===========================================================================
// 13) WitnessIndexError — Display, code, std::error::Error
// ===========================================================================

use frankenengine_engine::capability_witness::WitnessIndexError;
use frankenengine_engine::storage_adapter::{StorageError, StoreKind};

#[test]
fn witness_index_error_code_storage() {
    let e = WitnessIndexError::Storage(StorageError::NotFound {
        store: StoreKind::ReplayIndex,
        key: "k".into(),
    });
    assert_eq!(e.code(), "FE-WITIDX-0001");
}

#[test]
fn witness_index_error_code_serialization() {
    let e = WitnessIndexError::Serialization {
        operation: "encode".into(),
        detail: "bad json".into(),
    };
    assert_eq!(e.code(), "FE-WITIDX-0002");
}

#[test]
fn witness_index_error_code_corrupt_record() {
    let e = WitnessIndexError::CorruptRecord {
        key: "key-1".into(),
        detail: "hash mismatch".into(),
    };
    assert_eq!(e.code(), "FE-WITIDX-0003");
}

#[test]
fn witness_index_error_code_invalid_input() {
    let e = WitnessIndexError::InvalidInput {
        detail: "missing field".into(),
    };
    assert_eq!(e.code(), "FE-WITIDX-0004");
}

#[test]
fn witness_index_error_display_all_unique() {
    let variants: Vec<String> = vec![
        WitnessIndexError::Storage(StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "x".into(),
        })
        .to_string(),
        WitnessIndexError::Serialization {
            operation: "o".into(),
            detail: "d".into(),
        }
        .to_string(),
        WitnessIndexError::CorruptRecord {
            key: "k".into(),
            detail: "d".into(),
        }
        .to_string(),
        WitnessIndexError::InvalidInput { detail: "d".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn witness_index_error_is_std_error() {
    let e = WitnessIndexError::InvalidInput {
        detail: "test".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn witness_index_error_display_contains_detail() {
    let e = WitnessIndexError::Serialization {
        operation: "encode".into(),
        detail: "invalid utf8".into(),
    };
    let s = e.to_string();
    assert!(s.contains("encode"), "should contain operation: {s}");
    assert!(s.contains("invalid utf8"), "should contain detail: {s}");
}

#[test]
fn witness_index_error_from_storage_error() {
    let se = StorageError::NotFound {
        store: StoreKind::ReplayIndex,
        key: "witness-42".into(),
    };
    let wie: WitnessIndexError = se.into();
    assert_eq!(wie.code(), "FE-WITIDX-0001");
}

// ===========================================================================
// 14) WitnessPublicationError — Display uniqueness
// ===========================================================================

use frankenengine_engine::capability_witness::WitnessPublicationError;

#[test]
fn witness_publication_error_display_all_unique() {
    let variants: Vec<String> = vec![
        WitnessPublicationError::InvalidConfig { reason: "r".into() }.to_string(),
        WitnessPublicationError::WitnessNotPromoted {
            state: LifecycleState::Draft,
        }
        .to_string(),
        WitnessPublicationError::DuplicatePublication { witness_id: oid(1) }.to_string(),
        WitnessPublicationError::PublicationNotFound {
            publication_id: oid(2),
        }
        .to_string(),
        WitnessPublicationError::WitnessNotPublished { witness_id: oid(3) }.to_string(),
        WitnessPublicationError::AlreadyRevoked { witness_id: oid(4) }.to_string(),
        WitnessPublicationError::EmptyRevocationReason.to_string(),
        WitnessPublicationError::IdDerivation("x".into()).to_string(),
        WitnessPublicationError::InclusionProofFailed {
            detail: "d1".into(),
        }
        .to_string(),
        WitnessPublicationError::ConsistencyProofFailed {
            detail: "d2".into(),
        }
        .to_string(),
        WitnessPublicationError::TreeHeadSignatureInvalid {
            detail: "d3".into(),
        }
        .to_string(),
        WitnessPublicationError::TreeHeadHashMismatch {
            expected: "e".into(),
            actual: "a".into(),
        }
        .to_string(),
        WitnessPublicationError::LogEntryHashMismatch.to_string(),
        WitnessPublicationError::WitnessVerificationFailed {
            detail: "d4".into(),
        }
        .to_string(),
        WitnessPublicationError::GovernanceLedger {
            detail: "d5".into(),
        }
        .to_string(),
        WitnessPublicationError::EvidenceLedger {
            detail: "d6".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all WitnessPublicationError Display strings must be unique"
    );
}

#[test]
fn witness_publication_error_debug_distinct() {
    let variants = [
        format!(
            "{:?}",
            WitnessPublicationError::InvalidConfig { reason: "r".into() }
        ),
        format!("{:?}", WitnessPublicationError::EmptyRevocationReason),
        format!("{:?}", WitnessPublicationError::LogEntryHashMismatch),
        format!("{:?}", WitnessPublicationError::IdDerivation("x".into())),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 15) LifecycleState — exact Display values
// ===========================================================================

#[test]
fn lifecycle_state_display_exact_draft() {
    assert_eq!(LifecycleState::Draft.to_string(), "draft");
}

#[test]
fn lifecycle_state_display_exact_validated() {
    assert_eq!(LifecycleState::Validated.to_string(), "validated");
}

#[test]
fn lifecycle_state_display_exact_promoted() {
    assert_eq!(LifecycleState::Promoted.to_string(), "promoted");
}

#[test]
fn lifecycle_state_display_exact_active() {
    assert_eq!(LifecycleState::Active.to_string(), "active");
}

#[test]
fn lifecycle_state_display_exact_superseded() {
    assert_eq!(LifecycleState::Superseded.to_string(), "superseded");
}

#[test]
fn lifecycle_state_display_exact_revoked() {
    assert_eq!(LifecycleState::Revoked.to_string(), "revoked");
}

// ===========================================================================
// 16) ProofKind — exact Display values
// ===========================================================================

#[test]
fn proof_kind_display_exact_static_analysis() {
    assert_eq!(ProofKind::StaticAnalysis.to_string(), "static-analysis");
}

#[test]
fn proof_kind_display_exact_dynamic_ablation() {
    assert_eq!(ProofKind::DynamicAblation.to_string(), "dynamic-ablation");
}

#[test]
fn proof_kind_display_exact_policy_theorem() {
    assert_eq!(
        ProofKind::PolicyTheoremCheck.to_string(),
        "policy-theorem-check"
    );
}

#[test]
fn proof_kind_display_exact_operator_attestation() {
    assert_eq!(
        ProofKind::OperatorAttestation.to_string(),
        "operator-attestation"
    );
}

#[test]
fn proof_kind_display_exact_inherited() {
    assert_eq!(ProofKind::InheritedFromPredecessor.to_string(), "inherited");
}

// ===========================================================================
// 17) ConfidenceInterval — edge cases
// ===========================================================================

#[test]
fn confidence_interval_zero_trials() {
    let ci = ConfidenceInterval::from_trials(0, 0);
    assert_eq!(ci.lower_millionths, 0);
    assert_eq!(ci.upper_millionths, 0);
    assert_eq!(ci.n_trials, 0);
    assert_eq!(ci.n_successes, 0);
}

#[test]
fn confidence_interval_single_success() {
    let ci = ConfidenceInterval::from_trials(1, 1);
    assert_eq!(ci.n_trials, 1);
    assert_eq!(ci.n_successes, 1);
    assert!(ci.point_estimate_millionths() > 0);
}

#[test]
fn confidence_interval_single_failure() {
    let ci = ConfidenceInterval::from_trials(1, 0);
    assert_eq!(ci.n_trials, 1);
    assert_eq!(ci.n_successes, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
}

// ===========================================================================
// 18) WitnessSchemaVersion exact values
// ===========================================================================

#[test]
fn witness_schema_version_current_values() {
    let current = WitnessSchemaVersion::CURRENT;
    assert_eq!(current.major, 1);
    assert_eq!(current.minor, 0);
}

#[test]
fn witness_schema_version_display_format() {
    let v = WitnessSchemaVersion { major: 2, minor: 3 };
    assert_eq!(v.to_string(), "2.3");
}

// ===========================================================================
// 19) PublicationEntryKind — exact as_str values
// ===========================================================================

#[test]
fn publication_entry_kind_as_str_publish() {
    assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
}

#[test]
fn publication_entry_kind_as_str_revoke() {
    assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
}

// ===========================================================================
// 20) Serde roundtrip — WitnessIndexError
// ===========================================================================

#[test]
fn serde_roundtrip_witness_index_error_all_variants() {
    let variants = vec![
        WitnessIndexError::Storage(StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "k".into(),
        }),
        WitnessIndexError::Serialization {
            operation: "encode".into(),
            detail: "bad".into(),
        },
        WitnessIndexError::CorruptRecord {
            key: "k".into(),
            detail: "d".into(),
        },
        WitnessIndexError::InvalidInput { detail: "d".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: WitnessIndexError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}
