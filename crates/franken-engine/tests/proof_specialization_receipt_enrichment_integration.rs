//! Enrichment integration tests for `proof_specialization_receipt` module.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips,
//! Display coverage, Debug nonempty, std::error::Error, builder lifecycle,
//! ReceiptIndex queries, signature sign/verify, validation, epoch consistency,
//! content-addressable identity, JSON field-name stability, determinism.

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_specialization_receipt::{
    EquivalenceEvidence, EquivalenceMethod, OptimizationClass, PerformanceDelta, ProofInput,
    ProofType, ReceiptBuilder, ReceiptError, ReceiptEvent, ReceiptEventKind, ReceiptIndex,
    ReceiptSchemaVersion, RollbackToken, SpecializationReceipt, TransformationWitness,
    test_equivalence_evidence, test_performance_delta, test_proof_input, test_receipt,
    test_rollback_token, test_transformation_witness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([1u8; 32])
}

// =========================================================================
// Copy semantics
// =========================================================================

#[test]
fn enrichment_proof_type_copy() {
    let a = ProofType::CapabilityWitness;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_optimization_class_copy() {
    let a = OptimizationClass::SuperinstructionFusion;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_equivalence_method_copy() {
    let a = EquivalenceMethod::Bisimulation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_receipt_schema_version_copy() {
    let a = ReceiptSchemaVersion::CURRENT;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_receipt_event_kind_copy() {
    let a = ReceiptEventKind::Created;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// Clone independence
// =========================================================================

#[test]
fn enrichment_receipt_clone_independence() {
    let original = test_receipt(epoch());
    let mut cloned = original.clone();
    cloned.timestamp_ns = 999_999;
    assert_eq!(original.timestamp_ns, 1_000_000);
    assert_ne!(original.timestamp_ns, cloned.timestamp_ns);
}

#[test]
fn enrichment_transformation_witness_clone_independence() {
    let original = test_transformation_witness();
    let mut cloned = original.clone();
    cloned.description = "mutated".to_string();
    assert_ne!(original.description, cloned.description);
}

#[test]
fn enrichment_equivalence_evidence_clone_independence() {
    let original = test_equivalence_evidence();
    let mut cloned = original.clone();
    cloned.test_count = 0;
    assert_ne!(original.test_count, cloned.test_count);
}

#[test]
fn enrichment_rollback_token_clone_independence() {
    let original = test_rollback_token();
    let mut cloned = original.clone();
    cloned.validated = false;
    assert!(original.validated);
    assert!(!cloned.validated);
}

#[test]
fn enrichment_receipt_index_clone_independence() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let cloned = idx.clone();
    idx.insert(test_receipt(SecurityEpoch::from_raw(99)))
        .unwrap();
    assert_eq!(cloned.len(), 1);
    assert_eq!(idx.len(), 2);
}

// =========================================================================
// BTreeSet ordering
// =========================================================================

#[test]
fn enrichment_proof_type_btreeset_ordering() {
    let set: BTreeSet<ProofType> = [
        ProofType::ReplayMotif,
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
    let items: Vec<_> = set.into_iter().collect();
    // Ord is derived in declaration order: CapabilityWitness < FlowProof < ReplayMotif
    assert_eq!(items[0], ProofType::CapabilityWitness);
    assert_eq!(items[1], ProofType::FlowProof);
    assert_eq!(items[2], ProofType::ReplayMotif);
}

#[test]
fn enrichment_optimization_class_btreeset_ordering() {
    let set: BTreeSet<OptimizationClass> = [
        OptimizationClass::PathElimination,
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::IfcCheckElision,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(items[0], OptimizationClass::HostcallDispatchSpecialization);
    assert_eq!(items[1], OptimizationClass::IfcCheckElision);
    assert_eq!(items[2], OptimizationClass::SuperinstructionFusion);
    assert_eq!(items[3], OptimizationClass::PathElimination);
}

#[test]
fn enrichment_equivalence_method_btreeset_ordering() {
    let set: BTreeSet<EquivalenceMethod> = [
        EquivalenceMethod::Bisimulation,
        EquivalenceMethod::DifferentialTesting,
        EquivalenceMethod::TranslationValidation,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(items[0], EquivalenceMethod::DifferentialTesting);
    assert_eq!(items[1], EquivalenceMethod::TranslationValidation);
    assert_eq!(items[2], EquivalenceMethod::Bisimulation);
}

#[test]
fn enrichment_proof_type_btreeset_dedup() {
    let set: BTreeSet<ProofType> = [
        ProofType::FlowProof,
        ProofType::FlowProof,
        ProofType::CapabilityWitness,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 2);
}

// =========================================================================
// Serde roundtrips
// =========================================================================

#[test]
fn enrichment_proof_type_serde_all_variants() {
    for pt in [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ] {
        let json = serde_json::to_string(&pt).unwrap();
        let back: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(pt, back);
    }
}

#[test]
fn enrichment_optimization_class_serde_all_variants() {
    for oc in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ] {
        let json = serde_json::to_string(&oc).unwrap();
        let back: OptimizationClass = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, back);
    }
}

#[test]
fn enrichment_equivalence_method_serde_all_variants() {
    for em in [
        EquivalenceMethod::DifferentialTesting,
        EquivalenceMethod::TranslationValidation,
        EquivalenceMethod::Bisimulation,
    ] {
        let json = serde_json::to_string(&em).unwrap();
        let back: EquivalenceMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(em, back);
    }
}

#[test]
fn enrichment_receipt_schema_version_serde_roundtrip() {
    let v = ReceiptSchemaVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReceiptSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_proof_input_serde_roundtrip() {
    let pi = test_proof_input(ProofType::FlowProof, epoch());
    let json = serde_json::to_string(&pi).unwrap();
    let back: ProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(pi, back);
}

#[test]
fn enrichment_transformation_witness_serde_roundtrip() {
    let tw = test_transformation_witness();
    let json = serde_json::to_string(&tw).unwrap();
    let back: TransformationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(tw, back);
}

#[test]
fn enrichment_equivalence_evidence_serde_roundtrip() {
    let ee = test_equivalence_evidence();
    let json = serde_json::to_string(&ee).unwrap();
    let back: EquivalenceEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ee, back);
}

#[test]
fn enrichment_rollback_token_serde_roundtrip() {
    let rt = test_rollback_token();
    let json = serde_json::to_string(&rt).unwrap();
    let back: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, back);
}

#[test]
fn enrichment_performance_delta_serde_roundtrip() {
    let pd = test_performance_delta();
    let json = serde_json::to_string(&pd).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, back);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let receipt = test_receipt(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SpecializationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_receipt_error_serde_all_variants() {
    let errors = [
        ReceiptError::EmptyProofInputs,
        ReceiptError::EmptyTransformationDescription,
        ReceiptError::EmptyFallbackPath,
        ReceiptError::IdenticalIrDigests,
        ReceiptError::NoEquivalenceTests,
        ReceiptError::ZeroTestCount,
        ReceiptError::PassRateOutOfRange { value: 2_000_000 },
        ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 500_000,
        },
        ReceiptError::ZeroBenchmarkSamples,
        ReceiptError::UnvalidatedRollback,
        ReceiptError::EpochMismatch {
            receipt_epoch: 1,
            proof_epoch: 2,
        },
        ReceiptError::ProofExpired {
            proof_id: "p1".to_string(),
            window_ticks: 100,
        },
        ReceiptError::IdDerivation("err".to_string()),
        ReceiptError::SignatureInvalid {
            detail: "bad".to_string(),
        },
        ReceiptError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        ReceiptError::IncompatibleSchema {
            receipt: ReceiptSchemaVersion { major: 2, minor: 0 },
            reader: ReceiptSchemaVersion { major: 1, minor: 0 },
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReceiptError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &back);
    }
}

#[test]
fn enrichment_receipt_event_serde_roundtrip() {
    let event = ReceiptEvent {
        trace_id: "tr-99".to_string(),
        component: "proof_specialization_receipt".to_string(),
        event: ReceiptEventKind::Signed,
        receipt_id: Some("rid-abc".to_string()),
        optimization_class: Some("ifc_check_elision".to_string()),
        outcome: "ok".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_receipt_index_serde_roundtrip() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let json = serde_json::to_string(&idx).unwrap();
    let back: ReceiptIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 1);
}

// =========================================================================
// Display coverage
// =========================================================================

#[test]
fn enrichment_proof_type_display_all() {
    assert_eq!(
        ProofType::CapabilityWitness.to_string(),
        "capability_witness"
    );
    assert_eq!(ProofType::FlowProof.to_string(), "flow_proof");
    assert_eq!(ProofType::ReplayMotif.to_string(), "replay_motif");
}

#[test]
fn enrichment_optimization_class_display_all() {
    assert_eq!(
        OptimizationClass::HostcallDispatchSpecialization.to_string(),
        "hostcall_dispatch_specialization"
    );
    assert_eq!(
        OptimizationClass::IfcCheckElision.to_string(),
        "ifc_check_elision"
    );
    assert_eq!(
        OptimizationClass::SuperinstructionFusion.to_string(),
        "superinstruction_fusion"
    );
    assert_eq!(
        OptimizationClass::PathElimination.to_string(),
        "path_elimination"
    );
}

#[test]
fn enrichment_equivalence_method_display_all() {
    assert_eq!(
        EquivalenceMethod::DifferentialTesting.to_string(),
        "differential_testing"
    );
    assert_eq!(
        EquivalenceMethod::TranslationValidation.to_string(),
        "translation_validation"
    );
    assert_eq!(EquivalenceMethod::Bisimulation.to_string(), "bisimulation");
}

#[test]
fn enrichment_receipt_schema_version_display() {
    assert_eq!(ReceiptSchemaVersion::CURRENT.to_string(), "1.0");
    let v23 = ReceiptSchemaVersion { major: 2, minor: 3 };
    assert_eq!(v23.to_string(), "2.3");
}

#[test]
fn enrichment_receipt_event_kind_display_all() {
    assert_eq!(ReceiptEventKind::Created.to_string(), "created");
    assert_eq!(ReceiptEventKind::Signed.to_string(), "signed");
    assert_eq!(ReceiptEventKind::Validated.to_string(), "validated");
    assert_eq!(ReceiptEventKind::Indexed.to_string(), "indexed");
    assert_eq!(ReceiptEventKind::Invalidated.to_string(), "invalidated");
    assert_eq!(ReceiptEventKind::Queried.to_string(), "queried");
}

#[test]
fn enrichment_receipt_error_display_all_variants() {
    let errors: Vec<(ReceiptError, &str)> = vec![
        (
            ReceiptError::EmptyProofInputs,
            "proof_inputs must not be empty",
        ),
        (
            ReceiptError::EmptyTransformationDescription,
            "transformation_witness description is empty",
        ),
        (ReceiptError::EmptyFallbackPath, "fallback path is empty"),
        (
            ReceiptError::IdenticalIrDigests,
            "before and after IR digests are identical",
        ),
        (
            ReceiptError::NoEquivalenceTests,
            "equivalence_evidence has no differential test hashes",
        ),
        (
            ReceiptError::ZeroTestCount,
            "equivalence_evidence test_count is zero",
        ),
        (
            ReceiptError::ZeroBenchmarkSamples,
            "performance_delta sample_count is zero",
        ),
        (
            ReceiptError::UnvalidatedRollback,
            "rollback_token has not been validated",
        ),
    ];
    for (err, expected) in errors {
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn enrichment_receipt_error_display_parameterized() {
    let err = ReceiptError::PassRateOutOfRange { value: 2_000_000 };
    let s = err.to_string();
    assert!(s.contains("2000000"));

    let err = ReceiptError::InsufficientPassRate {
        required: 1_000_000,
        actual: 500_000,
    };
    let s = err.to_string();
    assert!(s.contains("500000"));
    assert!(s.contains("1000000"));

    let err = ReceiptError::EpochMismatch {
        receipt_epoch: 10,
        proof_epoch: 20,
    };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("20"));

    let err = ReceiptError::ProofExpired {
        proof_id: "proof-xyz".to_string(),
        window_ticks: 500,
    };
    let s = err.to_string();
    assert!(s.contains("proof-xyz"));
    assert!(s.contains("500"));

    let err = ReceiptError::IdDerivation("derivation failed".to_string());
    assert!(err.to_string().contains("derivation failed"));

    let err = ReceiptError::SignatureInvalid {
        detail: "tampered".to_string(),
    };
    assert!(err.to_string().contains("tampered"));

    let err = ReceiptError::IntegrityFailure {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("aaa"));
    assert!(s.contains("bbb"));

    let err = ReceiptError::IncompatibleSchema {
        receipt: ReceiptSchemaVersion { major: 2, minor: 0 },
        reader: ReceiptSchemaVersion { major: 1, minor: 0 },
    };
    let s = err.to_string();
    assert!(s.contains("2.0"));
    assert!(s.contains("1.0"));
}

// =========================================================================
// std::error::Error
// =========================================================================

#[test]
fn enrichment_receipt_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ReceiptError::EmptyProofInputs);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_receipt_error_source_is_none() {
    let err = ReceiptError::EmptyProofInputs;
    assert!(std::error::Error::source(&err).is_none());
}

// =========================================================================
// Debug nonempty
// =========================================================================

#[test]
fn enrichment_proof_type_debug() {
    let d = format!("{:?}", ProofType::CapabilityWitness);
    assert!(!d.is_empty());
}

#[test]
fn enrichment_optimization_class_debug() {
    let d = format!("{:?}", OptimizationClass::IfcCheckElision);
    assert!(!d.is_empty());
}

#[test]
fn enrichment_equivalence_method_debug() {
    let d = format!("{:?}", EquivalenceMethod::TranslationValidation);
    assert!(!d.is_empty());
}

#[test]
fn enrichment_receipt_debug() {
    let d = format!("{:?}", test_receipt(epoch()));
    assert!(!d.is_empty());
    assert!(d.contains("SpecializationReceipt"));
}

#[test]
fn enrichment_receipt_error_debug() {
    let d = format!("{:?}", ReceiptError::EmptyProofInputs);
    assert!(!d.is_empty());
}

#[test]
fn enrichment_receipt_index_debug() {
    let d = format!("{:?}", ReceiptIndex::new());
    assert!(!d.is_empty());
}

#[test]
fn enrichment_receipt_event_debug() {
    let event = ReceiptEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: ReceiptEventKind::Created,
        receipt_id: None,
        optimization_class: None,
        outcome: "ok".to_string(),
    };
    let d = format!("{:?}", event);
    assert!(!d.is_empty());
}

#[test]
fn enrichment_receipt_builder_debug() {
    let b = ReceiptBuilder::new(OptimizationClass::PathElimination, epoch());
    let d = format!("{:?}", b);
    assert!(!d.is_empty());
}

// =========================================================================
// Default coverage
// =========================================================================

#[test]
fn enrichment_receipt_index_default() {
    let idx = ReceiptIndex::default();
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
}

// =========================================================================
// Schema version compatibility
// =========================================================================

#[test]
fn enrichment_schema_version_compatible_same_major_higher_minor() {
    let v11 = ReceiptSchemaVersion { major: 1, minor: 1 };
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    assert!(v11.is_compatible_with(&v10));
}

#[test]
fn enrichment_schema_version_compatible_same_exact() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    assert!(v10.is_compatible_with(&v10));
}

#[test]
fn enrichment_schema_version_incompatible_lower_minor() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    let v11 = ReceiptSchemaVersion { major: 1, minor: 1 };
    assert!(!v10.is_compatible_with(&v11));
}

#[test]
fn enrichment_schema_version_incompatible_different_major() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    let v20 = ReceiptSchemaVersion { major: 2, minor: 0 };
    assert!(!v10.is_compatible_with(&v20));
    assert!(!v20.is_compatible_with(&v10));
}

// =========================================================================
// Validation
// =========================================================================

#[test]
fn enrichment_validate_valid_receipt_passes() {
    let receipt = test_receipt(epoch());
    assert!(receipt.validate().is_ok());
}

#[test]
fn enrichment_validate_empty_proof_inputs() {
    let mut receipt = test_receipt(epoch());
    receipt.proof_inputs.clear();
    assert_eq!(receipt.validate(), Err(ReceiptError::EmptyProofInputs));
}

#[test]
fn enrichment_validate_empty_transformation_description() {
    let mut receipt = test_receipt(epoch());
    receipt.transformation_witness.description.clear();
    assert_eq!(
        receipt.validate(),
        Err(ReceiptError::EmptyTransformationDescription)
    );
}

#[test]
fn enrichment_validate_identical_ir_digests() {
    let mut receipt = test_receipt(epoch());
    receipt.transformation_witness.after_ir_digest =
        receipt.transformation_witness.before_ir_digest;
    assert_eq!(receipt.validate(), Err(ReceiptError::IdenticalIrDigests));
}

#[test]
fn enrichment_validate_no_equivalence_tests() {
    let mut receipt = test_receipt(epoch());
    receipt
        .equivalence_evidence
        .differential_test_hashes
        .clear();
    assert_eq!(receipt.validate(), Err(ReceiptError::NoEquivalenceTests));
}

#[test]
fn enrichment_validate_zero_test_count() {
    let mut receipt = test_receipt(epoch());
    receipt.equivalence_evidence.test_count = 0;
    assert_eq!(receipt.validate(), Err(ReceiptError::ZeroTestCount));
}

#[test]
fn enrichment_validate_pass_rate_out_of_range() {
    let mut receipt = test_receipt(epoch());
    receipt.equivalence_evidence.pass_rate_millionths = 1_000_001;
    assert_eq!(
        receipt.validate(),
        Err(ReceiptError::PassRateOutOfRange { value: 1_000_001 })
    );
}

#[test]
fn enrichment_validate_insufficient_pass_rate() {
    let mut receipt = test_receipt(epoch());
    receipt.equivalence_evidence.pass_rate_millionths = 999_999;
    assert_eq!(
        receipt.validate(),
        Err(ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 999_999,
        })
    );
}

#[test]
fn enrichment_validate_unvalidated_rollback() {
    let mut receipt = test_receipt(epoch());
    receipt.rollback_token.validated = false;
    assert_eq!(receipt.validate(), Err(ReceiptError::UnvalidatedRollback));
}

#[test]
fn enrichment_validate_zero_benchmark_samples() {
    let mut receipt = test_receipt(epoch());
    receipt.performance_delta.sample_count = 0;
    assert_eq!(receipt.validate(), Err(ReceiptError::ZeroBenchmarkSamples));
}

#[test]
fn enrichment_validate_empty_fallback_path() {
    let mut receipt = test_receipt(epoch());
    receipt.fallback_path.clear();
    assert_eq!(receipt.validate(), Err(ReceiptError::EmptyFallbackPath));
}

// =========================================================================
// Epoch consistency
// =========================================================================

#[test]
fn enrichment_epoch_consistency_passes_matching() {
    let receipt = test_receipt(epoch());
    assert!(receipt.validate_epoch_consistency().is_ok());
}

#[test]
fn enrichment_epoch_consistency_fails_mismatch() {
    let mut receipt = test_receipt(epoch());
    receipt.proof_inputs[0].proof_epoch = SecurityEpoch::from_raw(99);
    let err = receipt.validate_epoch_consistency().unwrap_err();
    assert_eq!(
        err,
        ReceiptError::EpochMismatch {
            receipt_epoch: 42,
            proof_epoch: 99,
        }
    );
}

#[test]
fn enrichment_epoch_consistency_checks_all_inputs() {
    let mut receipt = test_receipt(epoch());
    // First input matches, second doesn't
    receipt.proof_inputs[1].proof_epoch = SecurityEpoch::from_raw(7);
    let err = receipt.validate_epoch_consistency().unwrap_err();
    assert_eq!(
        err,
        ReceiptError::EpochMismatch {
            receipt_epoch: 42,
            proof_epoch: 7,
        }
    );
}

// =========================================================================
// Content-addressable identity
// =========================================================================

#[test]
fn enrichment_content_hash_deterministic() {
    let r1 = test_receipt(epoch());
    let r2 = test_receipt(epoch());
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_receipt_id_deterministic() {
    let r1 = test_receipt(epoch());
    let r2 = test_receipt(epoch());
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_different_epoch_different_id() {
    let r1 = test_receipt(SecurityEpoch::from_raw(1));
    let r2 = test_receipt(SecurityEpoch::from_raw(2));
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_different_class_different_id() {
    let r1 = test_receipt(epoch());
    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, epoch())
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch()))
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::path::unspecialized")
        .performance_delta(test_performance_delta())
        .timestamp_ns(1_000_000)
        .build()
        .unwrap();
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_derive_receipt_id_deterministic() {
    let r1 = test_receipt(epoch());
    let r2 = test_receipt(epoch());
    let d1 = r1.derive_receipt_id().unwrap();
    let d2 = r2.derive_receipt_id().unwrap();
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_content_hash_differs_from_different_receipt() {
    let r1 = test_receipt(SecurityEpoch::from_raw(1));
    let r2 = test_receipt(SecurityEpoch::from_raw(2));
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// =========================================================================
// Signature sign/verify
// =========================================================================

#[test]
fn enrichment_sign_and_verify_roundtrip() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&vk).is_ok());
}

#[test]
fn enrichment_verify_fails_wrong_key() {
    let key = signing_key();
    let wrong_vk = SigningKey::from_bytes([2u8; 32]).verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&wrong_vk).is_err());
}

#[test]
fn enrichment_verify_fails_after_mutation() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    receipt.timestamp_ns = 999;
    assert!(receipt.verify(&vk).is_err());
}

#[test]
fn enrichment_sign_twice_produces_same_signature() {
    let key = signing_key();
    let mut r1 = test_receipt(epoch());
    let mut r2 = test_receipt(epoch());
    r1.sign(&key).unwrap();
    r2.sign(&key).unwrap();
    assert_eq!(r1.signature, r2.signature);
}

// =========================================================================
// Builder lifecycle
// =========================================================================

#[test]
fn enrichment_builder_valid_build() {
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::ifc::baseline")
        .performance_delta(test_performance_delta())
        .timestamp_ns(42)
        .metadata("env", "test")
        .build();
    assert!(receipt.is_ok());
    let r = receipt.unwrap();
    assert_eq!(r.optimization_class, OptimizationClass::IfcCheckElision);
    assert_eq!(r.timestamp_ns, 42);
    assert_eq!(r.metadata.get("env").unwrap(), "test");
    assert_eq!(r.schema_version, ReceiptSchemaVersion::CURRENT);
}

#[test]
fn enrichment_builder_rejects_empty_proof_inputs() {
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .build();
    assert_eq!(result.unwrap_err(), ReceiptError::EmptyProofInputs);
}

#[test]
fn enrichment_builder_rejects_missing_transformation() {
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .build();
    assert_eq!(
        result.unwrap_err(),
        ReceiptError::EmptyTransformationDescription
    );
}

#[test]
fn enrichment_builder_rejects_missing_equivalence() {
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .build();
    assert_eq!(result.unwrap_err(), ReceiptError::NoEquivalenceTests);
}

#[test]
fn enrichment_builder_rejects_missing_rollback() {
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .build();
    assert_eq!(result.unwrap_err(), ReceiptError::UnvalidatedRollback);
}

#[test]
fn enrichment_builder_rejects_missing_performance_delta() {
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback")
        .build();
    assert_eq!(result.unwrap_err(), ReceiptError::ZeroBenchmarkSamples);
}

#[test]
fn enrichment_builder_rejects_unvalidated_rollback_token() {
    let mut rt = test_rollback_token();
    rt.validated = false;
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(rt)
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .build();
    assert_eq!(result.unwrap_err(), ReceiptError::UnvalidatedRollback);
}

#[test]
fn enrichment_builder_multiple_proof_inputs() {
    let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, epoch())
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch()))
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::fusion::baseline")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert_eq!(receipt.proof_inputs.len(), 3);
}

#[test]
fn enrichment_builder_metadata_multiple_entries() {
    let receipt = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, epoch())
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback")
        .performance_delta(test_performance_delta())
        .metadata("k1", "v1")
        .metadata("k2", "v2")
        .metadata("k3", "v3")
        .build()
        .unwrap();
    assert_eq!(receipt.metadata.len(), 3);
    assert_eq!(receipt.metadata.get("k2").unwrap(), "v2");
}

// =========================================================================
// ReceiptIndex queries
// =========================================================================

#[test]
fn enrichment_index_insert_and_len() {
    let mut idx = ReceiptIndex::new();
    assert!(idx.is_empty());
    idx.insert(test_receipt(epoch())).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());
}

#[test]
fn enrichment_index_insert_validates() {
    let mut idx = ReceiptIndex::new();
    let mut bad = test_receipt(epoch());
    bad.proof_inputs.clear();
    assert!(idx.insert(bad).is_err());
    assert!(idx.is_empty());
}

#[test]
fn enrichment_index_all() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    assert_eq!(idx.all().len(), 1);
}

#[test]
fn enrichment_index_specializations_from_proof() {
    let mut idx = ReceiptIndex::new();
    let receipt = test_receipt(epoch());
    let proof_id = receipt.proof_inputs[0].proof_id.clone();
    idx.insert(receipt).unwrap();

    let found = idx.specializations_from_proof(&proof_id);
    assert_eq!(found.len(), 1);

    let unknown = EngineObjectId([0xFFu8; 32]);
    assert!(idx.specializations_from_proof(&unknown).is_empty());
}

#[test]
fn enrichment_index_proofs_for_specialization() {
    let mut idx = ReceiptIndex::new();
    let receipt = test_receipt(epoch());
    let rid = receipt.receipt_id.clone();
    idx.insert(receipt).unwrap();

    let proofs = idx.proofs_for_specialization(&rid);
    assert_eq!(proofs.len(), 2);

    let unknown = EngineObjectId([0xFFu8; 32]);
    assert!(idx.proofs_for_specialization(&unknown).is_empty());
}

#[test]
fn enrichment_index_by_optimization_class() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    assert_eq!(
        idx.by_optimization_class(OptimizationClass::HostcallDispatchSpecialization)
            .len(),
        1
    );
    assert!(
        idx.by_optimization_class(OptimizationClass::PathElimination)
            .is_empty()
    );
}

#[test]
fn enrichment_index_by_epoch() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    let e99 = SecurityEpoch::from_raw(99);
    idx.insert(test_receipt(e42)).unwrap();
    assert_eq!(idx.by_epoch(e42).len(), 1);
    assert!(idx.by_epoch(e99).is_empty());
}

#[test]
fn enrichment_index_invalidate_stale_removes() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    let e43 = SecurityEpoch::from_raw(43);
    idx.insert(test_receipt(e42)).unwrap();
    let stale = idx.invalidate_stale(e43);
    assert_eq!(stale.len(), 1);
    assert!(idx.is_empty());
}

#[test]
fn enrichment_index_invalidate_stale_keeps_matching() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    idx.insert(test_receipt(e42)).unwrap();
    let stale = idx.invalidate_stale(e42);
    assert!(stale.is_empty());
    assert_eq!(idx.len(), 1);
}

#[test]
fn enrichment_index_multiple_receipts_different_classes() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, epoch())
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::path::baseline")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    idx.insert(r2).unwrap();
    assert_eq!(idx.len(), 2);
    assert_eq!(
        idx.by_optimization_class(OptimizationClass::HostcallDispatchSpecialization)
            .len(),
        1
    );
    assert_eq!(
        idx.by_optimization_class(OptimizationClass::PathElimination)
            .len(),
        1
    );
}

#[test]
fn enrichment_index_shared_proof_across_receipts() {
    let mut idx = ReceiptIndex::new();
    let e = epoch();
    let pi = test_proof_input(ProofType::CapabilityWitness, e);
    let proof_id = pi.proof_id.clone();

    let r1 = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, e)
        .add_proof_input(pi.clone())
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback-1")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();

    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(pi)
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback-2")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();

    idx.insert(r1).unwrap();
    idx.insert(r2).unwrap();

    let found = idx.specializations_from_proof(&proof_id);
    assert_eq!(found.len(), 2);
}

// =========================================================================
// TransformationWitness validation
// =========================================================================

#[test]
fn enrichment_transformation_witness_validate_ok() {
    let tw = test_transformation_witness();
    assert!(tw.validate().is_ok());
}

#[test]
fn enrichment_transformation_witness_validate_empty_description() {
    let tw = TransformationWitness {
        description: String::new(),
        before_ir_digest: ContentHash::compute(b"before"),
        after_ir_digest: ContentHash::compute(b"after"),
    };
    assert_eq!(
        tw.validate(),
        Err(ReceiptError::EmptyTransformationDescription)
    );
}

#[test]
fn enrichment_transformation_witness_validate_identical_digests() {
    let h = ContentHash::compute(b"same");
    let tw = TransformationWitness {
        description: "transform".to_string(),
        before_ir_digest: h,
        after_ir_digest: h,
    };
    assert_eq!(tw.validate(), Err(ReceiptError::IdenticalIrDigests));
}

// =========================================================================
// EquivalenceEvidence validation
// =========================================================================

#[test]
fn enrichment_equivalence_evidence_validate_ok() {
    let ee = test_equivalence_evidence();
    assert!(ee.validate().is_ok());
}

#[test]
fn enrichment_equivalence_evidence_validate_no_tests() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![],
        test_count: 10,
        pass_rate_millionths: 1_000_000,
    };
    assert_eq!(ee.validate(), Err(ReceiptError::NoEquivalenceTests));
}

#[test]
fn enrichment_equivalence_evidence_validate_zero_count() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"test")],
        test_count: 0,
        pass_rate_millionths: 1_000_000,
    };
    assert_eq!(ee.validate(), Err(ReceiptError::ZeroTestCount));
}

#[test]
fn enrichment_equivalence_evidence_validate_pass_rate_too_high() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"test")],
        test_count: 10,
        pass_rate_millionths: 1_000_001,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::PassRateOutOfRange { value: 1_000_001 })
    );
}

#[test]
fn enrichment_equivalence_evidence_validate_insufficient_pass_rate() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"test")],
        test_count: 10,
        pass_rate_millionths: 999_000,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 999_000,
        })
    );
}

// =========================================================================
// PerformanceDelta validation
// =========================================================================

#[test]
fn enrichment_performance_delta_validate_ok() {
    let pd = test_performance_delta();
    assert!(pd.validate().is_ok());
}

#[test]
fn enrichment_performance_delta_validate_zero_samples() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: 500_000,
        throughput_increase_millionths: 200_000,
        sample_count: 0,
    };
    assert_eq!(pd.validate(), Err(ReceiptError::ZeroBenchmarkSamples));
}

// =========================================================================
// JSON field-name stability
// =========================================================================

#[test]
fn enrichment_json_fields_proof_input() {
    let pi = test_proof_input(ProofType::FlowProof, epoch());
    let json = serde_json::to_string(&pi).unwrap();
    assert!(json.contains("\"proof_type\""));
    assert!(json.contains("\"proof_id\""));
    assert!(json.contains("\"proof_epoch\""));
    assert!(json.contains("\"validity_window_ticks\""));
}

#[test]
fn enrichment_json_fields_transformation_witness() {
    let tw = test_transformation_witness();
    let json = serde_json::to_string(&tw).unwrap();
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"before_ir_digest\""));
    assert!(json.contains("\"after_ir_digest\""));
}

#[test]
fn enrichment_json_fields_equivalence_evidence() {
    let ee = test_equivalence_evidence();
    let json = serde_json::to_string(&ee).unwrap();
    assert!(json.contains("\"method\""));
    assert!(json.contains("\"differential_test_hashes\""));
    assert!(json.contains("\"test_count\""));
    assert!(json.contains("\"pass_rate_millionths\""));
}

#[test]
fn enrichment_json_fields_rollback_token() {
    let rt = test_rollback_token();
    let json = serde_json::to_string(&rt).unwrap();
    assert!(json.contains("\"baseline_hash\""));
    assert!(json.contains("\"rollback_procedure_hash\""));
    assert!(json.contains("\"validated\""));
}

#[test]
fn enrichment_json_fields_performance_delta() {
    let pd = test_performance_delta();
    let json = serde_json::to_string(&pd).unwrap();
    assert!(json.contains("\"latency_reduction_millionths\""));
    assert!(json.contains("\"throughput_increase_millionths\""));
    assert!(json.contains("\"sample_count\""));
}

#[test]
fn enrichment_json_fields_receipt() {
    let receipt = test_receipt(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"receipt_id\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"proof_inputs\""));
    assert!(json.contains("\"optimization_class\""));
    assert!(json.contains("\"transformation_witness\""));
    assert!(json.contains("\"equivalence_evidence\""));
    assert!(json.contains("\"rollback_token\""));
    assert!(json.contains("\"validity_epoch\""));
    assert!(json.contains("\"fallback_path\""));
    assert!(json.contains("\"performance_delta\""));
    assert!(json.contains("\"timestamp_ns\""));
    assert!(json.contains("\"signature\""));
    assert!(json.contains("\"metadata\""));
}

#[test]
fn enrichment_json_fields_receipt_event() {
    let event = ReceiptEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: ReceiptEventKind::Created,
        receipt_id: Some("r".to_string()),
        optimization_class: Some("oc".to_string()),
        outcome: "ok".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"event\""));
    assert!(json.contains("\"receipt_id\""));
    assert!(json.contains("\"optimization_class\""));
    assert!(json.contains("\"outcome\""));
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn enrichment_receipt_deterministic_100_times() {
    let first = test_receipt(epoch());
    for _ in 0..100 {
        let r = test_receipt(epoch());
        assert_eq!(r.receipt_id, first.receipt_id);
        assert_eq!(r.content_hash(), first.content_hash());
    }
}

#[test]
fn enrichment_test_helpers_deterministic() {
    let tw1 = test_transformation_witness();
    let tw2 = test_transformation_witness();
    assert_eq!(tw1, tw2);

    let ee1 = test_equivalence_evidence();
    let ee2 = test_equivalence_evidence();
    assert_eq!(ee1, ee2);

    let rt1 = test_rollback_token();
    let rt2 = test_rollback_token();
    assert_eq!(rt1, rt2);

    let pd1 = test_performance_delta();
    let pd2 = test_performance_delta();
    assert_eq!(pd1, pd2);
}

#[test]
fn enrichment_proof_input_deterministic() {
    let pi1 = test_proof_input(ProofType::CapabilityWitness, epoch());
    let pi2 = test_proof_input(ProofType::CapabilityWitness, epoch());
    assert_eq!(pi1, pi2);
}

#[test]
fn enrichment_different_proof_types_different_ids() {
    let pi1 = test_proof_input(ProofType::CapabilityWitness, epoch());
    let pi2 = test_proof_input(ProofType::FlowProof, epoch());
    assert_ne!(pi1.proof_id, pi2.proof_id);
}

// =========================================================================
// ReceiptEventKind all variants serde
// =========================================================================

#[test]
fn enrichment_receipt_event_kind_serde_all() {
    for kind in [
        ReceiptEventKind::Created,
        ReceiptEventKind::Signed,
        ReceiptEventKind::Validated,
        ReceiptEventKind::Indexed,
        ReceiptEventKind::Invalidated,
        ReceiptEventKind::Queried,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ReceiptEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn enrichment_receipt_event_none_fields() {
    let event = ReceiptEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: ReceiptEventKind::Queried,
        receipt_id: None,
        optimization_class: None,
        outcome: "none".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.receipt_id.is_none());
    assert!(back.optimization_class.is_none());
}

#[test]
fn enrichment_schema_version_ord() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    let v11 = ReceiptSchemaVersion { major: 1, minor: 1 };
    let v20 = ReceiptSchemaVersion { major: 2, minor: 0 };
    assert!(v10 < v11);
    assert!(v11 < v20);
    assert!(v10 < v20);
}

#[test]
fn enrichment_receipt_empty_metadata() {
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::ifc::baseline")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert!(receipt.metadata.is_empty());
}

#[test]
fn enrichment_invalidate_empty_index() {
    let mut idx = ReceiptIndex::new();
    let stale = idx.invalidate_stale(epoch());
    assert!(stale.is_empty());
}

#[test]
fn enrichment_performance_delta_high_values() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: u64::MAX,
        throughput_increase_millionths: u64::MAX,
        sample_count: 1,
    };
    assert!(pd.validate().is_ok());
}

#[test]
fn enrichment_receipt_schema_version_current() {
    assert_eq!(ReceiptSchemaVersion::CURRENT.major, 1);
    assert_eq!(ReceiptSchemaVersion::CURRENT.minor, 0);
}
