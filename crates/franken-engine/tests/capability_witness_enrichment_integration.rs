#![forbid(unsafe_code)]
//! Enrichment integration tests for `capability_witness`.
//!
//! Adds LifecycleState Display/ordering, WitnessError Display uniqueness,
//! ProofKind/PromotionTheoremKind Display, serde roundtrips, JSON field-name
//! stability, WitnessSchemaVersion compatibility, ConfidenceInterval math,
//! and WitnessValidator/WitnessStore construction beyond the existing
//! 109 integration tests.

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

use std::collections::BTreeMap;

use frankenengine_engine::capability_witness::{
    CapabilityWitness, ConfidenceInterval, CustomTheoremExtension, DenialRecord, LifecycleState,
    PromotionTheoremInput, PromotionTheoremKind, PromotionTheoremReport, ProofKind,
    ProofObligation, PublicationEntryKind, RollbackToken, SourceCapabilitySet, WitnessBuilder,
    WitnessError, WitnessIndexQuery, WitnessPublicationConfig, WitnessPublicationPipeline,
    WitnessSchemaVersion, WitnessStore, WitnessValidator,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
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

// ===========================================================================
// 21) Copy semantics for Copy types
// ===========================================================================

#[test]
fn copy_semantics_lifecycle_state() {
    let a = LifecycleState::Active;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_proof_kind() {
    let a = ProofKind::DynamicAblation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_witness_schema_version() {
    let a = WitnessSchemaVersion::CURRENT;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_confidence_interval() {
    let a = ConfidenceInterval::from_trials(100, 95);
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 22) Clone independence
// ===========================================================================

#[test]
fn clone_independence_rollback_token() {
    let original = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"original"),
        previous_witness_id: Some(oid(1)),
        created_epoch: SecurityEpoch::from_raw(1),
        sequence: 10,
    };
    let mut cloned = original.clone();
    cloned.sequence = 99;
    assert_eq!(original.sequence, 10);
    assert_eq!(cloned.sequence, 99);
}

#[test]
fn clone_independence_proof_obligation() {
    let original = ProofObligation {
        capability: Capability::new("cap-1"),
        kind: ProofKind::StaticAnalysis,
        proof_artifact_id: oid(1),
        justification: "original".to_string(),
        artifact_hash: ContentHash::compute(b"hash"),
    };
    let mut cloned = original.clone();
    cloned.justification = "modified".to_string();
    assert_eq!(original.justification, "original");
}

#[test]
fn clone_independence_denial_record() {
    let original = DenialRecord {
        capability: Capability::new("cap-2"),
        reason: "original".to_string(),
        evidence_id: None,
    };
    let mut cloned = original.clone();
    cloned.reason = "modified".to_string();
    assert_eq!(original.reason, "original");
}

#[test]
fn clone_independence_witness_error() {
    let original = WitnessError::MissingProofObligation {
        capability: "original".to_string(),
    };
    let mut cloned = original.clone();
    if let WitnessError::MissingProofObligation { ref mut capability } = cloned {
        *capability = "modified".to_string();
    }
    if let WitnessError::MissingProofObligation { capability } = &original {
        assert_eq!(capability, "original");
    }
}

// ===========================================================================
// 23) LifecycleState BTreeSet ordering and dedup
// ===========================================================================

#[test]
fn lifecycle_state_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(LifecycleState::Revoked);
    set.insert(LifecycleState::Draft);
    set.insert(LifecycleState::Active);
    set.insert(LifecycleState::Promoted);
    set.insert(LifecycleState::Validated);
    set.insert(LifecycleState::Superseded);
    set.insert(LifecycleState::Draft); // dup
    assert_eq!(set.len(), 6);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// ===========================================================================
// 24) LifecycleState terminal states have no transitions
// ===========================================================================

#[test]
fn lifecycle_terminal_states_no_transitions() {
    assert!(LifecycleState::Superseded.valid_transitions().is_empty());
    assert!(LifecycleState::Revoked.valid_transitions().is_empty());
    assert!(!LifecycleState::Superseded.can_transition_to(LifecycleState::Draft));
    assert!(!LifecycleState::Revoked.can_transition_to(LifecycleState::Active));
}

// ===========================================================================
// 25) LifecycleState full transition chain
// ===========================================================================

#[test]
fn lifecycle_full_transition_chain() {
    assert!(LifecycleState::Draft.can_transition_to(LifecycleState::Validated));
    assert!(LifecycleState::Validated.can_transition_to(LifecycleState::Promoted));
    assert!(LifecycleState::Promoted.can_transition_to(LifecycleState::Active));
    assert!(LifecycleState::Active.can_transition_to(LifecycleState::Superseded));
    assert!(LifecycleState::Active.can_transition_to(LifecycleState::Revoked));
    // Invalid backward transition
    assert!(!LifecycleState::Validated.can_transition_to(LifecycleState::Draft));
    assert!(!LifecycleState::Active.can_transition_to(LifecycleState::Draft));
}

// ===========================================================================
// 26) WitnessSchemaVersion compatibility edge cases
// ===========================================================================

#[test]
fn schema_version_same_major_higher_minor_compatible() {
    let reader = WitnessSchemaVersion { major: 1, minor: 2 };
    let witness = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(reader.is_compatible_with(&witness));
}

#[test]
fn schema_version_same_major_lower_minor_incompatible() {
    let reader = WitnessSchemaVersion { major: 1, minor: 0 };
    let witness = WitnessSchemaVersion { major: 1, minor: 2 };
    assert!(!reader.is_compatible_with(&witness));
}

// ===========================================================================
// 27) ConfidenceInterval all successes
// ===========================================================================

#[test]
fn confidence_interval_all_successes() {
    let ci = ConfidenceInterval::from_trials(1000, 1000);
    assert_eq!(ci.point_estimate_millionths(), 1_000_000);
    assert!(ci.meets_threshold(900_000));
}

// ===========================================================================
// 28) ConfidenceInterval no successes
// ===========================================================================

#[test]
fn confidence_interval_no_successes() {
    let ci = ConfidenceInterval::from_trials(100, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
    assert!(!ci.meets_threshold(100_000));
}

// ===========================================================================
// 29) Debug nonempty for all key types
// ===========================================================================

#[test]
fn debug_nonempty_all_key_types() {
    assert!(!format!("{:?}", LifecycleState::Draft).is_empty());
    assert!(!format!("{:?}", ProofKind::StaticAnalysis).is_empty());
    assert!(!format!("{:?}", PromotionTheoremKind::MergeLegality).is_empty());
    assert!(!format!("{:?}", WitnessSchemaVersion::CURRENT).is_empty());
    assert!(!format!("{:?}", ConfidenceInterval::from_trials(10, 9)).is_empty());
    let rt = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"x"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(0),
        sequence: 0,
    };
    assert!(!format!("{rt:?}").is_empty());
}

// ===========================================================================
// 30) WitnessError serde roundtrip EpochMismatch
// ===========================================================================

#[test]
fn serde_roundtrip_witness_error_epoch_mismatch() {
    let err = WitnessError::EpochMismatch {
        witness_epoch: 5,
        current_epoch: 10,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: WitnessError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ===========================================================================
// 31) WitnessError Display EpochMismatch contains epoch values
// ===========================================================================

#[test]
fn witness_error_display_epoch_mismatch_contains_values() {
    let err = WitnessError::EpochMismatch {
        witness_epoch: 5,
        current_epoch: 10,
    };
    let display = err.to_string();
    assert!(display.contains("5"));
    assert!(display.contains("10"));
}

// ===========================================================================
// 32) WitnessSchemaVersion serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_witness_schema_version() {
    let v = WitnessSchemaVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let back: WitnessSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// 33) PromotionTheoremKind BTreeSet ordering
// ===========================================================================

#[test]
fn promotion_theorem_kind_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(PromotionTheoremKind::NonInterference);
    set.insert(PromotionTheoremKind::MergeLegality);
    set.insert(PromotionTheoremKind::AttenuationLegality);
    set.insert(PromotionTheoremKind::Custom("z-test".to_string()));
    set.insert(PromotionTheoremKind::MergeLegality); // dup
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// ===========================================================================
// Helpers for deep integration tests
// ===========================================================================

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x42u8; 32])
}

fn test_extension_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test-ext",
        &SchemaId::from_definition(b"test-ext-schema"),
        b"ext-seed",
    )
    .unwrap()
}

fn test_policy_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test-policy",
        &SchemaId::from_definition(b"test-policy-schema"),
        b"policy-seed",
    )
    .unwrap()
}

fn test_proof_artifact_id(tag: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "test-proof",
        &SchemaId::from_definition(b"test-proof-schema"),
        tag.as_bytes(),
    )
    .unwrap()
}

fn make_proof(cap: &Capability, kind: ProofKind, tag: &str) -> ProofObligation {
    ProofObligation {
        capability: cap.clone(),
        kind,
        proof_artifact_id: test_proof_artifact_id(tag),
        justification: format!("justification for {}", cap.as_str()),
        artifact_hash: ContentHash::compute(tag.as_bytes()),
    }
}

/// Build a minimal valid witness in Draft state via WitnessBuilder.
fn build_minimal_witness() -> CapabilityWitness {
    let cap = Capability::new("fs.read");
    WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1_000_000_000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "proof-fs-read"))
    .confidence(ConfidenceInterval::from_trials(1000, 980))
    .replay_seed(42)
    .build()
    .expect("build minimal witness")
}

/// Build a witness with multiple capabilities and denial records.
fn build_rich_witness() -> CapabilityWitness {
    let cap_read = Capability::new("fs.read");
    let cap_write = Capability::new("fs.write");
    let cap_net = Capability::new("net.connect");
    WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(5),
        2_000_000_000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .require(cap_net.clone())
    .deny(Capability::new("sys.exec"), "not needed for this extension")
    .proof(make_proof(&cap_read, ProofKind::StaticAnalysis, "p-read"))
    .proof(make_proof(
        &cap_write,
        ProofKind::DynamicAblation,
        "p-write",
    ))
    .proof(make_proof(
        &cap_net,
        ProofKind::OperatorAttestation,
        "p-net",
    ))
    .confidence(ConfidenceInterval::from_trials(500, 490))
    .replay_seed(99)
    .transcript_hash(ContentHash::compute(b"rich-transcript"))
    .meta("owner", "test-team")
    .meta("version", "3")
    .build()
    .expect("build rich witness")
}

fn make_promotion_input(witness: &CapabilityWitness) -> PromotionTheoremInput {
    let caps = witness.required_capabilities.clone();
    PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src-1".to_string(),
            capabilities: caps.clone(),
        }],
        manifest_capabilities: caps,
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    }
}

fn promote_witness(witness: &mut CapabilityWitness) {
    let input = make_promotion_input(witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    witness.apply_promotion_theorem_report(&report);
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();
}

// ===========================================================================
// 34) WitnessBuilder — required/denied overlap
// ===========================================================================

#[test]
fn builder_required_denied_overlap_errors() {
    let cap = Capability::new("fs.read");
    let result = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .deny(cap, "overlapping")
    .build();
    assert!(matches!(
        result,
        Err(WitnessError::RequiredDeniedOverlap { .. })
    ));
}

// ===========================================================================
// 35) WitnessBuilder — produces Draft state
// ===========================================================================

#[test]
fn builder_produces_draft_state_with_correct_fields() {
    let witness = build_minimal_witness();
    assert_eq!(witness.lifecycle_state, LifecycleState::Draft);
    assert_eq!(witness.schema_version, WitnessSchemaVersion::CURRENT);
    assert_eq!(witness.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(witness.replay_seed, 42);
    assert!(
        witness
            .required_capabilities
            .contains(&Capability::new("fs.read"))
    );
    assert!(!witness.synthesizer_signature.is_empty());
}

// ===========================================================================
// 36) WitnessBuilder — require_all
// ===========================================================================

#[test]
fn builder_require_all_adds_multiple_capabilities() {
    let caps = vec![
        Capability::new("a"),
        Capability::new("b"),
        Capability::new("c"),
    ];
    let mut builder = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require_all(caps.clone());
    for cap in &caps {
        builder = builder.proof(make_proof(cap, ProofKind::StaticAnalysis, cap.as_str()));
    }
    let witness = builder.build().unwrap();
    assert_eq!(witness.required_capabilities.len(), 3);
}

// ===========================================================================
// 37) WitnessBuilder — metadata preserved
// ===========================================================================

#[test]
fn builder_metadata_preserved_in_witness() {
    let cap = Capability::new("fs.read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p"))
    .meta("env", "staging")
    .meta("team", "infra")
    .build()
    .unwrap();
    assert_eq!(witness.metadata.get("env").unwrap(), "staging");
    assert_eq!(witness.metadata.get("team").unwrap(), "infra");
}

// ===========================================================================
// 38) WitnessBuilder — rollback token
// ===========================================================================

#[test]
fn builder_with_rollback_token_preserved() {
    let cap = Capability::new("fs.read");
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"old-witness"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(0),
        sequence: 0,
    };
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p1"))
    .rollback(token.clone())
    .build()
    .unwrap();
    assert_eq!(witness.rollback_token, Some(token));
}

// ===========================================================================
// 39) CapabilityWitness serde roundtrip
// ===========================================================================

#[test]
fn capability_witness_serde_roundtrip() {
    let witness = build_rich_witness();
    let json = serde_json::to_string(&witness).unwrap();
    let back: CapabilityWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, back);
}

// ===========================================================================
// 40) Unsigned bytes deterministic
// ===========================================================================

#[test]
fn witness_unsigned_bytes_deterministic() {
    let w1 = build_minimal_witness();
    let w2 = build_minimal_witness();
    assert_eq!(w1.unsigned_bytes(), w2.unsigned_bytes());
}

// ===========================================================================
// 41) Content hash deterministic
// ===========================================================================

#[test]
fn witness_content_hash_deterministic() {
    let w1 = build_minimal_witness();
    let w2 = build_minimal_witness();
    assert_eq!(w1.content_hash, w2.content_hash);
}

// ===========================================================================
// 42) Witness ID is content-addressed and deterministic
// ===========================================================================

#[test]
fn witness_id_deterministic_across_builds() {
    let w1 = build_minimal_witness();
    let w2 = build_minimal_witness();
    assert_eq!(w1.witness_id, w2.witness_id);
}

// ===========================================================================
// 43) Different inputs produce different IDs
// ===========================================================================

#[test]
fn different_inputs_produce_different_witness_ids() {
    let cap = Capability::new("fs.read");
    let w1 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p"))
    .replay_seed(1)
    .build()
    .unwrap();
    let w2 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p"))
    .replay_seed(2)
    .build()
    .unwrap();
    assert_ne!(w1.witness_id, w2.witness_id);
    assert_ne!(w1.content_hash, w2.content_hash);
}

// ===========================================================================
// 44) verify_integrity passes for valid witness
// ===========================================================================

#[test]
fn verify_integrity_passes_for_valid_witness() {
    let witness = build_minimal_witness();
    assert!(witness.verify_integrity().is_ok());
}

// ===========================================================================
// 45) verify_integrity fails after tamper
// ===========================================================================

#[test]
fn verify_integrity_fails_after_tamper() {
    let mut witness = build_minimal_witness();
    witness.replay_seed = 999;
    let err = witness.verify_integrity().unwrap_err();
    assert!(matches!(err, WitnessError::IntegrityFailure { .. }));
}

// ===========================================================================
// 46) verify_proof_coverage passes when covered
// ===========================================================================

#[test]
fn verify_proof_coverage_passes_when_covered() {
    let witness = build_minimal_witness();
    assert!(witness.verify_proof_coverage().is_ok());
}

// ===========================================================================
// 47) verify_proof_coverage fails with missing proof
// ===========================================================================

#[test]
fn verify_proof_coverage_fails_missing_proof() {
    let mut witness = build_minimal_witness();
    witness
        .required_capabilities
        .insert(Capability::new("extra.cap"));
    let err = witness.verify_proof_coverage().unwrap_err();
    assert!(matches!(err, WitnessError::MissingProofObligation { .. }));
}

// ===========================================================================
// 48) verify_synthesizer_signature passes with correct key
// ===========================================================================

#[test]
fn verify_synthesizer_signature_correct_key() {
    let witness = build_minimal_witness();
    let vk = test_signing_key().verification_key();
    assert!(witness.verify_synthesizer_signature(&vk).is_ok());
}

// ===========================================================================
// 49) verify_synthesizer_signature fails with wrong key
// ===========================================================================

#[test]
fn verify_synthesizer_signature_wrong_key() {
    let witness = build_minimal_witness();
    let wrong_vk = SigningKey::from_bytes([0xAA; 32]).verification_key();
    assert!(witness.verify_synthesizer_signature(&wrong_vk).is_err());
}

// ===========================================================================
// 50) transition_to Draft -> Validated
// ===========================================================================

#[test]
fn transition_draft_to_validated() {
    let mut witness = build_minimal_witness();
    assert!(witness.transition_to(LifecycleState::Validated).is_ok());
    assert_eq!(witness.lifecycle_state, LifecycleState::Validated);
}

// ===========================================================================
// 51) transition_to invalid returns error
// ===========================================================================

#[test]
fn transition_invalid_returns_error() {
    let mut witness = build_minimal_witness();
    let err = witness.transition_to(LifecycleState::Active).unwrap_err();
    assert!(matches!(err, WitnessError::InvalidTransition { .. }));
}

// ===========================================================================
// 52) synthesis_unsigned_bytes strips theorem metadata
// ===========================================================================

#[test]
fn synthesis_unsigned_bytes_strips_theorem_metadata() {
    let mut witness = build_minimal_witness();
    witness.metadata.insert(
        "promotion_theorem.merge_legality".to_string(),
        "pass".to_string(),
    );
    let synth_bytes = witness.synthesis_unsigned_bytes();
    let clean = build_minimal_witness();
    assert_eq!(synth_bytes, clean.synthesis_unsigned_bytes());
}

// ===========================================================================
// 53) evaluate_promotion_theorems all pass
// ===========================================================================

#[test]
fn evaluate_promotion_theorems_all_pass() {
    let witness = build_rich_witness();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(report.all_passed);
    assert_eq!(report.results.len(), 3);
}

// ===========================================================================
// 54) evaluate_promotion_theorems merge fails with partial sources
// ===========================================================================

#[test]
fn evaluate_promotion_theorems_merge_fails_with_partial_sources() {
    let witness = build_rich_witness();
    let partial: BTreeSet<Capability> = vec![Capability::new("fs.read")].into_iter().collect();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "partial".to_string(),
            capabilities: partial,
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let merge = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::MergeLegality)
        .unwrap();
    assert!(!merge.passed);
    assert!(merge.counterexample.is_some());
}

// ===========================================================================
// 55) apply_promotion_theorem_report inserts metadata
// ===========================================================================

#[test]
fn apply_promotion_theorem_report_inserts_metadata() {
    let mut witness = build_rich_witness();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    witness.apply_promotion_theorem_report(&report);
    assert_eq!(
        witness
            .metadata
            .get("promotion_theorem.all_passed")
            .unwrap(),
        "true"
    );
    assert!(
        witness
            .metadata
            .contains_key("promotion_theorem.merge_legality")
    );
    assert!(
        witness
            .metadata
            .contains_key("promotion_theorem.attenuation_legality")
    );
    assert!(
        witness
            .metadata
            .contains_key("promotion_theorem.non_interference")
    );
}

// ===========================================================================
// 56) apply_promotion_theorem_report adds PolicyTheoremCheck proofs
// ===========================================================================

#[test]
fn apply_promotion_theorem_report_adds_theorem_proofs() {
    let mut witness = build_rich_witness();
    let initial_proofs = witness.proof_obligations.len();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    witness.apply_promotion_theorem_report(&report);
    let theorem_proofs = witness
        .proof_obligations
        .iter()
        .filter(|po| po.kind == ProofKind::PolicyTheoremCheck)
        .count();
    assert!(theorem_proofs > 0);
    assert!(witness.proof_obligations.len() > initial_proofs);
}

// ===========================================================================
// 57) Custom theorem extension passes
// ===========================================================================

#[test]
fn custom_theorem_extension_passes() {
    let witness = build_rich_witness();
    let caps = witness.required_capabilities.clone();
    let ext = CustomTheoremExtension {
        name: "custom-check".to_string(),
        required_capabilities: vec![Capability::new("fs.read")].into_iter().collect(),
        forbidden_capabilities: BTreeSet::new(),
    };
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src".to_string(),
            capabilities: caps.clone(),
        }],
        manifest_capabilities: caps,
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![ext],
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(report.all_passed);
    assert_eq!(report.results.len(), 4);
}

// ===========================================================================
// 58) Custom theorem extension fails with forbidden
// ===========================================================================

#[test]
fn custom_theorem_extension_fails_with_forbidden() {
    let witness = build_rich_witness();
    let caps = witness.required_capabilities.clone();
    let ext = CustomTheoremExtension {
        name: "strict-check".to_string(),
        required_capabilities: BTreeSet::new(),
        forbidden_capabilities: vec![Capability::new("fs.read")].into_iter().collect(),
    };
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src".to_string(),
            capabilities: caps.clone(),
        }],
        manifest_capabilities: caps,
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![ext],
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
}

// ===========================================================================
// 59) Non-interference fails when required depends on denied
// ===========================================================================

#[test]
fn non_interference_fails_when_required_depends_on_denied() {
    let witness = build_rich_witness();
    let caps = witness.required_capabilities.clone();
    let mut deps = BTreeMap::new();
    deps.insert(
        Capability::new("fs.read"),
        vec![Capability::new("sys.exec")].into_iter().collect(),
    );
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src".to_string(),
            capabilities: caps.clone(),
        }],
        manifest_capabilities: caps,
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: deps,
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let ni = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::NonInterference)
        .unwrap();
    assert!(!ni.passed);
    assert!(ni.counterexample.is_some());
}

// ===========================================================================
// 60) Attenuation passes with lattice expansion
// ===========================================================================

#[test]
fn attenuation_passes_with_lattice_expansion() {
    let cap_a = Capability::new("a");
    let cap_b = Capability::new("b");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_a.clone())
    .require(cap_b.clone())
    .proof(make_proof(&cap_a, ProofKind::StaticAnalysis, "pa"))
    .proof(make_proof(&cap_b, ProofKind::StaticAnalysis, "pb"))
    .confidence(ConfidenceInterval::from_trials(1000, 990))
    .build()
    .unwrap();
    let mut lattice = BTreeMap::new();
    lattice.insert(cap_a.clone(), vec![cap_b.clone()].into_iter().collect());
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src".to_string(),
            capabilities: vec![cap_a.clone(), cap_b.clone()].into_iter().collect(),
        }],
        manifest_capabilities: vec![cap_a].into_iter().collect(),
        capability_lattice: lattice,
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    let att = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::AttenuationLegality)
        .unwrap();
    assert!(att.passed);
}

// ===========================================================================
// 61) Structured events from promotion report
// ===========================================================================

#[test]
fn promotion_theorem_report_structured_events() {
    let witness = build_rich_witness();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    let events = report.structured_events("trace-1", "dec-1", "pol-1");
    assert_eq!(events.len(), 4);
    let gate_event = events.last().unwrap();
    assert_eq!(gate_event.event, "promotion_theorem_gate");
    assert_eq!(gate_event.outcome, "pass");
    assert!(gate_event.error_code.is_none());
}

// ===========================================================================
// 62) Structured events for failed report contain error codes
// ===========================================================================

#[test]
fn promotion_theorem_report_failed_events_have_error_codes() {
    let witness = build_rich_witness();
    let partial: BTreeSet<Capability> = vec![Capability::new("fs.read")].into_iter().collect();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "partial".to_string(),
            capabilities: partial,
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let events = report.structured_events("t", "d", "p");
    let gate_event = events.last().unwrap();
    assert_eq!(gate_event.outcome, "fail");
    assert!(gate_event.error_code.is_some());
}

// ===========================================================================
// 63) PromotionTheoremReport serde roundtrip
// ===========================================================================

#[test]
fn promotion_theorem_report_serde_roundtrip() {
    let witness = build_rich_witness();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: PromotionTheoremReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// 64) Full lifecycle: Draft -> Validated -> Promoted -> Active -> Revoked
// ===========================================================================

#[test]
fn full_lifecycle_transition_chain() {
    let mut witness = build_rich_witness();
    witness.transition_to(LifecycleState::Validated).unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Validated);

    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(report.all_passed);
    witness.apply_promotion_theorem_report(&report);
    witness.transition_to(LifecycleState::Promoted).unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Promoted);

    witness.transition_to(LifecycleState::Active).unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Active);

    witness.transition_to(LifecycleState::Revoked).unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Revoked);
    assert!(witness.lifecycle_state.is_terminal());
}

// ===========================================================================
// 65) Promotion without theorem proofs fails
// ===========================================================================

#[test]
fn promotion_without_theorem_proofs_fails() {
    let mut witness = build_rich_witness();
    witness.transition_to(LifecycleState::Validated).unwrap();
    let result = witness.transition_to(LifecycleState::Promoted);
    assert!(matches!(
        result,
        Err(WitnessError::MissingPromotionTheoremProofs { .. })
    ));
}

// ===========================================================================
// 66) WitnessValidator passes for valid witness
// ===========================================================================

#[test]
fn validator_passes_for_valid_witness() {
    let witness = build_minimal_witness();
    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

// ===========================================================================
// 67) WitnessValidator reports zero trials
// ===========================================================================

#[test]
fn validator_reports_zero_trials() {
    let cap = Capability::new("fs.read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p"))
    .build()
    .unwrap();
    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::InvalidConfidence { .. }))
    );
}

// ===========================================================================
// 68) WitnessValidator reports low confidence
// ===========================================================================

#[test]
fn validator_reports_low_confidence() {
    let cap = Capability::new("fs.read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "p"))
    .confidence(ConfidenceInterval::from_trials(100, 50))
    .build()
    .unwrap();
    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::InvalidConfidence { .. }))
    );
}

// ===========================================================================
// 69) WitnessValidator reports schema incompatibility
// ===========================================================================

#[test]
fn validator_reports_schema_incompatibility() {
    let mut witness = build_minimal_witness();
    witness.schema_version = WitnessSchemaVersion {
        major: 99,
        minor: 0,
    };
    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::IncompatibleSchema { .. }))
    );
}

// ===========================================================================
// 70) WitnessStore insert and get
// ===========================================================================

#[test]
fn store_insert_and_get() {
    let mut store = WitnessStore::new();
    let witness = build_minimal_witness();
    let wid = witness.witness_id.clone();
    store.insert(witness.clone());
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    let retrieved = store.get(&wid).unwrap();
    assert_eq!(retrieved.witness_id, wid);
}

// ===========================================================================
// 71) WitnessStore by_state
// ===========================================================================

#[test]
fn store_by_state_filters_correctly() {
    let mut store = WitnessStore::new();
    store.insert(build_minimal_witness());
    let drafts = store.by_state(LifecycleState::Draft);
    assert_eq!(drafts.len(), 1);
    let actives = store.by_state(LifecycleState::Active);
    assert!(actives.is_empty());
}

// ===========================================================================
// 72) WitnessStore transition
// ===========================================================================

#[test]
fn store_transition_draft_to_validated() {
    let mut store = WitnessStore::new();
    let witness = build_minimal_witness();
    let wid = witness.witness_id.clone();
    store.insert(witness);
    store.transition(&wid, LifecycleState::Validated).unwrap();
    assert_eq!(
        store.get(&wid).unwrap().lifecycle_state,
        LifecycleState::Validated
    );
}

// ===========================================================================
// 73) WitnessStore active_for_extension
// ===========================================================================

#[test]
fn store_active_for_extension_tracks_active_witness() {
    let mut store = WitnessStore::new();
    let mut witness = build_minimal_witness();
    let ext_id = witness.extension_id.clone();
    promote_witness(&mut witness);
    witness.transition_to(LifecycleState::Active).unwrap();
    let wid = witness.witness_id.clone();
    store.insert(witness);
    let active = store.active_for_extension(&ext_id).unwrap();
    assert_eq!(active.witness_id, wid);
}

// ===========================================================================
// 74) WitnessStore serde roundtrip
// ===========================================================================

#[test]
fn store_serde_roundtrip() {
    let mut store = WitnessStore::new();
    store.insert(build_minimal_witness());
    let json = serde_json::to_string(&store).unwrap();
    let back: WitnessStore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 1);
}

// ===========================================================================
// 75) WitnessStore iter returns all witnesses
// ===========================================================================

#[test]
fn store_iter_returns_all_witnesses() {
    let mut store = WitnessStore::new();
    store.insert(build_minimal_witness());
    store.insert(build_rich_witness());
    let count = store.iter().count();
    assert_eq!(count, 2);
}

// ===========================================================================
// 76) WitnessIndexQuery default
// ===========================================================================

#[test]
fn witness_index_query_default_values() {
    let q = WitnessIndexQuery::default();
    assert!(q.extension_id.is_none());
    assert!(q.policy_id.is_none());
    assert!(q.epoch.is_none());
    assert!(q.lifecycle_state.is_none());
    assert!(q.capability.is_none());
    assert_eq!(q.limit, 128);
    assert!(q.include_revoked);
}

// ===========================================================================
// 77) WitnessIndexQuery serde roundtrip
// ===========================================================================

#[test]
fn witness_index_query_serde_roundtrip() {
    let q = WitnessIndexQuery {
        extension_id: Some(test_extension_id()),
        policy_id: None,
        epoch: Some(SecurityEpoch::from_raw(3)),
        lifecycle_state: Some(LifecycleState::Active),
        capability: Some(Capability::new("net.connect")),
        start_timestamp_ns: Some(100),
        end_timestamp_ns: Some(200),
        include_revoked: false,
        cursor: Some("cursor-abc".to_string()),
        limit: 50,
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: WitnessIndexQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

// ===========================================================================
// 78) WitnessPublicationConfig default
// ===========================================================================

#[test]
fn publication_config_default_values() {
    let cfg = WitnessPublicationConfig::default();
    assert_eq!(cfg.checkpoint_interval, 8);
    assert_eq!(cfg.policy_id, "capability-witness-policy");
    assert!(cfg.governance_ledger_config.is_none());
}

// ===========================================================================
// 79) WitnessPublicationConfig serde roundtrip
// ===========================================================================

#[test]
fn publication_config_serde_roundtrip() {
    let cfg = WitnessPublicationConfig {
        checkpoint_interval: 16,
        policy_id: "custom-policy".to_string(),
        governance_ledger_config: None,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: WitnessPublicationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// 80) Pipeline zero checkpoint interval errors
// ===========================================================================

#[test]
fn pipeline_zero_checkpoint_interval_errors() {
    let cfg = WitnessPublicationConfig {
        checkpoint_interval: 0,
        ..WitnessPublicationConfig::default()
    };
    let result =
        WitnessPublicationPipeline::new(SecurityEpoch::from_raw(1), test_signing_key(), cfg);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::InvalidConfig { .. })
    ));
}

// ===========================================================================
// 81) Pipeline empty policy ID errors
// ===========================================================================

#[test]
fn pipeline_empty_policy_id_errors() {
    let cfg = WitnessPublicationConfig {
        policy_id: "  ".to_string(),
        ..WitnessPublicationConfig::default()
    };
    let result =
        WitnessPublicationPipeline::new(SecurityEpoch::from_raw(1), test_signing_key(), cfg);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::InvalidConfig { .. })
    ));
}

// ===========================================================================
// 82) Pipeline publish and query
// ===========================================================================

use frankenengine_engine::capability_witness::WitnessPublicationQuery;

#[test]
fn pipeline_publish_and_query() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let pub_id = pipeline.publish_witness(witness, 100).unwrap();
    let results = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].publication_id, pub_id);
    assert!(!results[0].is_revoked());
}

// ===========================================================================
// 83) Pipeline publish draft fails
// ===========================================================================

#[test]
fn pipeline_publish_draft_fails() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let witness = build_minimal_witness();
    let result = pipeline.publish_witness(witness, 100);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::WitnessNotPromoted { .. })
    ));
}

// ===========================================================================
// 84) Pipeline duplicate publish fails
// ===========================================================================

#[test]
fn pipeline_duplicate_publish_fails() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let witness_clone = witness.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    let result = pipeline.publish_witness(witness_clone, 200);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::DuplicatePublication { .. })
    ));
}

// ===========================================================================
// 85) Pipeline revoke and query excluding revoked
// ===========================================================================

#[test]
fn pipeline_revoke_and_query_excluding_revoked() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "compromised", 200).unwrap();
    let all = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 1);
    assert!(all[0].is_revoked());
    let active_only = pipeline.query(&WitnessPublicationQuery {
        include_revoked: false,
        ..WitnessPublicationQuery::all()
    });
    assert!(active_only.is_empty());
}

// ===========================================================================
// 86) Pipeline revoke empty reason fails
// ===========================================================================

#[test]
fn pipeline_revoke_empty_reason_fails() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    let result = pipeline.revoke_witness(&wid, "  ", 200);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::EmptyRevocationReason)
    ));
}

// ===========================================================================
// 87) Pipeline revoke already revoked fails
// ===========================================================================

#[test]
fn pipeline_revoke_already_revoked_fails() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "reason-1", 200).unwrap();
    let result = pipeline.revoke_witness(&wid, "reason-2", 300);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::AlreadyRevoked { .. })
    ));
}

// ===========================================================================
// 88) Pipeline events emitted
// ===========================================================================

#[test]
fn pipeline_events_emitted() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "bad", 200).unwrap();
    let events = pipeline.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "publish_witness");
    assert_eq!(events[1].event, "revoke_witness");
}

// ===========================================================================
// 89) Pipeline evidence entries emitted
// ===========================================================================

#[test]
fn pipeline_evidence_entries_emitted() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    pipeline.publish_witness(witness, 100).unwrap();
    assert!(!pipeline.evidence_entries().is_empty());
}

// ===========================================================================
// 90) Pipeline verify_publication succeeds
// ===========================================================================

#[test]
fn pipeline_verify_publication_succeeds() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        sk,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let pub_id = pipeline.publish_witness(witness, 100).unwrap();
    let result = pipeline.verify_publication(&pub_id, &vk, &vk);
    assert!(result.is_ok());
}

// ===========================================================================
// 91) Pipeline log entries and checkpoints
// ===========================================================================

#[test]
fn pipeline_log_entries_grow_with_publications() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            ..WitnessPublicationConfig::default()
        },
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    pipeline.publish_witness(witness, 100).unwrap();
    assert_eq!(pipeline.log_entries().len(), 1);
    assert!(!pipeline.checkpoints().is_empty());
}

// ===========================================================================
// 92) Pipeline query by extension_id
// ===========================================================================

#[test]
fn pipeline_query_by_extension_id() {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let mut witness = build_rich_witness();
    promote_witness(&mut witness);
    let ext_id = witness.extension_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    let results = pipeline.query(&WitnessPublicationQuery {
        extension_id: Some(ext_id),
        ..WitnessPublicationQuery::all()
    });
    assert_eq!(results.len(), 1);
    let no_match = pipeline.query(&WitnessPublicationQuery {
        extension_id: Some(oid(0xFF)),
        ..WitnessPublicationQuery::all()
    });
    assert!(no_match.is_empty());
}

// ===========================================================================
// 93) ConfidenceInterval successes clamped to trials
// ===========================================================================

#[test]
fn confidence_interval_successes_clamped_to_trials() {
    let ci = ConfidenceInterval::from_trials(10, 20);
    assert_eq!(ci.n_successes, 10);
    assert_eq!(ci.n_trials, 10);
}

// ===========================================================================
// 94) WitnessError RequiredDeniedOverlap display
// ===========================================================================

#[test]
fn witness_error_required_denied_overlap_display() {
    let err = WitnessError::RequiredDeniedOverlap {
        capabilities: vec!["a".to_string(), "b".to_string()],
    };
    let display = err.to_string();
    assert!(display.contains("a,b"));
    assert!(display.contains("overlap"));
}

// ===========================================================================
// 95) SourceCapabilitySet serde roundtrip
// ===========================================================================

#[test]
fn source_capability_set_serde_roundtrip() {
    let scs = SourceCapabilitySet {
        source_id: "test-src".to_string(),
        capabilities: vec![Capability::new("a"), Capability::new("b")]
            .into_iter()
            .collect(),
    };
    let json = serde_json::to_string(&scs).unwrap();
    let back: SourceCapabilitySet = serde_json::from_str(&json).unwrap();
    assert_eq!(scs, back);
}

// ===========================================================================
// 96) CustomTheoremExtension serde roundtrip
// ===========================================================================

#[test]
fn custom_theorem_extension_serde_roundtrip() {
    let ext = CustomTheoremExtension {
        name: "my-ext".to_string(),
        required_capabilities: vec![Capability::new("x")].into_iter().collect(),
        forbidden_capabilities: vec![Capability::new("y")].into_iter().collect(),
    };
    let json = serde_json::to_string(&ext).unwrap();
    let back: CustomTheoremExtension = serde_json::from_str(&json).unwrap();
    assert_eq!(ext, back);
}

// ===========================================================================
// 97) Promotion to Active then Superseded via new witness in store
// ===========================================================================

#[test]
fn store_supersedes_previous_active_witness_on_new_active() {
    let mut store = WitnessStore::new();

    // First witness -> Active
    let mut w1 = build_minimal_witness();
    promote_witness(&mut w1);
    w1.transition_to(LifecycleState::Active).unwrap();
    let w1_id = w1.witness_id.clone();
    let ext_id = w1.extension_id.clone();
    store.insert(w1);

    // Second witness for same extension -> Active
    let cap = Capability::new("fs.read");
    let mut w2 = WitnessBuilder::new(
        ext_id.clone(),
        test_policy_id(),
        SecurityEpoch::from_raw(2),
        3_000_000_000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap, ProofKind::StaticAnalysis, "proof2"))
    .confidence(ConfidenceInterval::from_trials(1000, 990))
    .build()
    .unwrap();
    promote_witness(&mut w2);
    w2.transition_to(LifecycleState::Active).unwrap();
    let w2_id = w2.witness_id.clone();
    store.insert(w2);

    // w1 should be superseded
    assert_eq!(
        store.get(&w1_id).unwrap().lifecycle_state,
        LifecycleState::Superseded
    );
    // w2 should be active
    let active = store.active_for_extension(&ext_id).unwrap();
    assert_eq!(active.witness_id, w2_id);
}

// ===========================================================================
// 98) WitnessPublicationQuery::all()
// ===========================================================================

#[test]
fn publication_query_all_defaults() {
    let q = WitnessPublicationQuery::all();
    assert!(q.extension_id.is_none());
    assert!(q.policy_id.is_none());
    assert!(q.epoch.is_none());
    assert!(q.content_hash.is_none());
    assert!(q.include_revoked);
}

// ===========================================================================
// 99) ConfidenceInterval bounds are clamped to [0, 1_000_000]
// ===========================================================================

#[test]
fn confidence_interval_bounds_clamped() {
    let ci = ConfidenceInterval::from_trials(1, 1);
    assert!(ci.lower_millionths >= 0);
    assert!(ci.upper_millionths <= 1_000_000);

    let ci = ConfidenceInterval::from_trials(1, 0);
    assert!(ci.lower_millionths >= 0);
    assert!(ci.upper_millionths <= 1_000_000);
}

// ===========================================================================
// 100) apply_promotion_theorem_report does not add proofs on failure
// ===========================================================================

#[test]
fn apply_promotion_theorem_report_no_proofs_on_failure() {
    let mut witness = build_rich_witness();
    let partial: BTreeSet<Capability> = vec![Capability::new("fs.read")].into_iter().collect();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "partial".to_string(),
            capabilities: partial,
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let proofs_before = witness.proof_obligations.len();
    witness.apply_promotion_theorem_report(&report);
    let theorem_proofs = witness
        .proof_obligations
        .iter()
        .filter(|po| po.kind == ProofKind::PolicyTheoremCheck)
        .count();
    assert_eq!(theorem_proofs, 0);
    assert_eq!(witness.proof_obligations.len(), proofs_before);
    assert_eq!(
        witness
            .metadata
            .get("promotion_theorem.all_passed")
            .unwrap(),
        "false"
    );
}

// ===========================================================================
// 101) Pipeline with governance ledger is None by default
// ===========================================================================

#[test]
fn pipeline_governance_ledger_none_by_default() {
    let pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        test_signing_key(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    assert!(pipeline.governance_ledger().is_none());
}

// ===========================================================================
// 102) WitnessStore transition to nonexistent witness errors
// ===========================================================================

#[test]
fn store_transition_nonexistent_witness_errors() {
    let mut store = WitnessStore::new();
    let result = store.transition(&oid(0xFF), LifecycleState::Validated);
    assert!(result.is_err());
}

// ===========================================================================
// 103) Verify integrity roundtrip on promoted witness
// ===========================================================================

#[test]
fn verify_integrity_stable_after_promotion_theorem_application() {
    let mut witness = build_rich_witness();
    let input = make_promotion_input(&witness);
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    witness.apply_promotion_theorem_report(&report);
    // verify_integrity uses synthesis_unsigned_bytes which strips theorem
    // metadata, so integrity should still hold
    assert!(witness.verify_integrity().is_ok());
}
