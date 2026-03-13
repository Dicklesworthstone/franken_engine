#![forbid(unsafe_code)]
//! Integration tests for the `proof_specialization_receipt` module.
//!
//! Covers schema versioning, enum Display/serde, struct validation,
//! builder ergonomics, receipt signing/verification, index queries,
//! epoch consistency, error Display, and event logging.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_specialization_receipt::{
    EquivalenceEvidence, EquivalenceMethod, OptimizationClass, PerformanceDelta, ProofType,
    ReceiptBuilder, ReceiptError, ReceiptEvent, ReceiptEventKind, ReceiptIndex,
    ReceiptSchemaVersion, RollbackToken, SpecializationReceipt, TransformationWitness,
    test_equivalence_evidence, test_performance_delta, test_proof_input, test_receipt,
    test_rollback_token, test_transformation_witness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([7u8; 32])
}

/// Build a fully-valid receipt with a specific optimization class and epoch.
fn build_valid_receipt(class: OptimizationClass, ep: SecurityEpoch) -> SpecializationReceipt {
    ReceiptBuilder::new(class, ep)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, ep))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::test::fallback")
        .performance_delta(test_performance_delta())
        .timestamp_ns(1_000_000)
        .build()
        .expect("valid receipt")
}

// ===========================================================================
// 1. ReceiptSchemaVersion
// ===========================================================================

#[test]
fn schema_version_current_is_1_0() {
    let v = ReceiptSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
}

#[test]
fn schema_version_display() {
    assert_eq!(ReceiptSchemaVersion::CURRENT.to_string(), "1.0");
    let v23 = ReceiptSchemaVersion { major: 2, minor: 3 };
    assert_eq!(v23.to_string(), "2.3");
}

#[test]
fn schema_version_compatible_same_major_same_minor() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    assert!(v10.is_compatible_with(&v10));
}

#[test]
fn schema_version_compatible_higher_minor_reader() {
    let reader = ReceiptSchemaVersion { major: 1, minor: 2 };
    let receipt = ReceiptSchemaVersion { major: 1, minor: 0 };
    // Reader 1.2 can read receipt 1.0.
    assert!(reader.is_compatible_with(&receipt));
}

#[test]
fn schema_version_incompatible_lower_minor_reader() {
    let reader = ReceiptSchemaVersion { major: 1, minor: 0 };
    let receipt = ReceiptSchemaVersion { major: 1, minor: 1 };
    // Reader 1.0 cannot read receipt 1.1.
    assert!(!reader.is_compatible_with(&receipt));
}

#[test]
fn schema_version_incompatible_different_major() {
    let reader = ReceiptSchemaVersion { major: 2, minor: 0 };
    let receipt = ReceiptSchemaVersion { major: 1, minor: 0 };
    assert!(!reader.is_compatible_with(&receipt));
}

// ===========================================================================
// 2. ProofType Display + serde
// ===========================================================================

#[test]
fn proof_type_display_all_variants() {
    assert_eq!(
        ProofType::CapabilityWitness.to_string(),
        "capability_witness"
    );
    assert_eq!(ProofType::FlowProof.to_string(), "flow_proof");
    assert_eq!(ProofType::ReplayMotif.to_string(), "replay_motif");
}

#[test]
fn proof_type_serde_roundtrip() {
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

// ===========================================================================
// 3. OptimizationClass Display + serde
// ===========================================================================

#[test]
fn optimization_class_display_all_variants() {
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
fn optimization_class_serde_roundtrip() {
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

// ===========================================================================
// 4. EquivalenceMethod Display + serde
// ===========================================================================

#[test]
fn equivalence_method_display_all_variants() {
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
fn equivalence_method_serde_roundtrip() {
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

// ===========================================================================
// 5. TransformationWitness validation + serde
// ===========================================================================

#[test]
fn transformation_witness_valid() {
    let tw = test_transformation_witness();
    assert!(tw.validate().is_ok());
}

#[test]
fn transformation_witness_empty_description_error() {
    let tw = TransformationWitness {
        description: String::new(),
        before_ir_digest: ContentHash::compute(b"a"),
        after_ir_digest: ContentHash::compute(b"b"),
    };
    assert_eq!(
        tw.validate(),
        Err(ReceiptError::EmptyTransformationDescription)
    );
}

#[test]
fn transformation_witness_identical_digests_error() {
    let hash = ContentHash::compute(b"same");
    let tw = TransformationWitness {
        description: "some transform".to_string(),
        before_ir_digest: hash,
        after_ir_digest: hash,
    };
    assert_eq!(tw.validate(), Err(ReceiptError::IdenticalIrDigests));
}

#[test]
fn transformation_witness_serde_roundtrip() {
    let tw = test_transformation_witness();
    let json = serde_json::to_string(&tw).unwrap();
    let back: TransformationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(tw, back);
}

// ===========================================================================
// 6. EquivalenceEvidence validation + serde
// ===========================================================================

#[test]
fn equivalence_evidence_valid_full_pass_rate() {
    let ee = test_equivalence_evidence();
    assert!(ee.validate().is_ok());
}

#[test]
fn equivalence_evidence_no_test_hashes_error() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![],
        test_count: 10,
        pass_rate_millionths: 1_000_000,
    };
    assert_eq!(ee.validate(), Err(ReceiptError::NoEquivalenceTests));
}

#[test]
fn equivalence_evidence_zero_test_count_error() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::TranslationValidation,
        differential_test_hashes: vec![ContentHash::compute(b"t1")],
        test_count: 0,
        pass_rate_millionths: 1_000_000,
    };
    assert_eq!(ee.validate(), Err(ReceiptError::ZeroTestCount));
}

#[test]
fn equivalence_evidence_pass_rate_out_of_range_error() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::Bisimulation,
        differential_test_hashes: vec![ContentHash::compute(b"t1")],
        test_count: 5,
        pass_rate_millionths: 1_000_001,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::PassRateOutOfRange { value: 1_000_001 })
    );
}

#[test]
fn equivalence_evidence_insufficient_pass_rate_error() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"t1")],
        test_count: 100,
        pass_rate_millionths: 999_999,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 999_999,
        })
    );
}

#[test]
fn equivalence_evidence_serde_roundtrip() {
    let ee = test_equivalence_evidence();
    let json = serde_json::to_string(&ee).unwrap();
    let back: EquivalenceEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ee, back);
}

// ===========================================================================
// 7. PerformanceDelta validation + serde
// ===========================================================================

#[test]
fn performance_delta_valid() {
    let pd = test_performance_delta();
    assert!(pd.validate().is_ok());
}

#[test]
fn performance_delta_zero_samples_error() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: 100_000,
        throughput_increase_millionths: 50_000,
        sample_count: 0,
    };
    assert_eq!(pd.validate(), Err(ReceiptError::ZeroBenchmarkSamples));
}

#[test]
fn performance_delta_serde_roundtrip() {
    let pd = test_performance_delta();
    let json = serde_json::to_string(&pd).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, back);
}

// ===========================================================================
// 8. RollbackToken serde
// ===========================================================================

#[test]
fn rollback_token_serde_roundtrip() {
    let rt = test_rollback_token();
    let json = serde_json::to_string(&rt).unwrap();
    let back: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, back);
}

#[test]
fn rollback_token_validated_false_serde() {
    let rt = RollbackToken {
        baseline_hash: ContentHash::compute(b"base"),
        rollback_procedure_hash: ContentHash::compute(b"proc"),
        validated: false,
    };
    let json = serde_json::to_string(&rt).unwrap();
    let back: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, back);
    assert!(!back.validated);
}

// ===========================================================================
// 9. ReceiptBuilder
// ===========================================================================

#[test]
fn builder_full_valid_build() {
    let receipt = build_valid_receipt(OptimizationClass::HostcallDispatchSpecialization, epoch());
    assert!(receipt.validate().is_ok());
    assert_eq!(receipt.schema_version, ReceiptSchemaVersion::CURRENT);
    assert_eq!(
        receipt.optimization_class,
        OptimizationClass::HostcallDispatchSpecialization
    );
}

#[test]
fn builder_empty_proof_inputs_error() {
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
fn builder_no_transformation_witness_error() {
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
fn builder_no_equivalence_evidence_error() {
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
fn builder_no_rollback_token_error() {
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
fn builder_unvalidated_rollback_error() {
    let rt = RollbackToken {
        baseline_hash: ContentHash::compute(b"base"),
        rollback_procedure_hash: ContentHash::compute(b"proc"),
        validated: false,
    };
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
fn builder_no_performance_delta_error() {
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
fn builder_deterministic_receipt_id() {
    let r1 = build_valid_receipt(OptimizationClass::PathElimination, epoch());
    let r2 = build_valid_receipt(OptimizationClass::PathElimination, epoch());
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn builder_metadata_preserved() {
    let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, epoch())
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, epoch()))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::fusion::baseline")
        .performance_delta(test_performance_delta())
        .metadata("author", "integration-test")
        .metadata("version", "42")
        .build()
        .unwrap();
    assert_eq!(receipt.metadata.get("author").unwrap(), "integration-test");
    assert_eq!(receipt.metadata.get("version").unwrap(), "42");
}

#[test]
fn builder_multiple_proof_inputs() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::ifc::baseline")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert_eq!(receipt.proof_inputs.len(), 3);
    assert!(receipt.validate().is_ok());
}

// ===========================================================================
// 10. SpecializationReceipt
// ===========================================================================

#[test]
fn receipt_validate_valid() {
    let receipt = test_receipt(epoch());
    assert!(receipt.validate().is_ok());
}

#[test]
fn receipt_validate_epoch_consistency_matching() {
    let receipt = test_receipt(epoch());
    assert!(receipt.validate_epoch_consistency().is_ok());
}

#[test]
fn receipt_validate_epoch_consistency_mismatch() {
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
fn receipt_content_hash_deterministic() {
    let r1 = test_receipt(epoch());
    let r2 = test_receipt(epoch());
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_content_hash_changes_with_different_input() {
    let r1 = build_valid_receipt(OptimizationClass::HostcallDispatchSpecialization, epoch());
    let r2 = build_valid_receipt(OptimizationClass::PathElimination, epoch());
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_sign_and_verify_roundtrip() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&vk).is_ok());
}

#[test]
fn receipt_verify_fails_wrong_key() {
    let key = signing_key();
    let wrong_vk = SigningKey::from_bytes([99u8; 32]).verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&wrong_vk).is_err());
}

#[test]
fn receipt_verify_fails_after_mutation() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    receipt.timestamp_ns = 12345;
    assert!(receipt.verify(&vk).is_err());
}

#[test]
fn receipt_derive_receipt_id_deterministic() {
    let r1 = test_receipt(epoch());
    let r2 = test_receipt(epoch());
    let id1 = r1.derive_receipt_id().unwrap();
    let id2 = r2.derive_receipt_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn receipt_serde_roundtrip() {
    let receipt = test_receipt(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SpecializationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn receipt_json_has_expected_keys() {
    let receipt = test_receipt(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    for key in [
        "receipt_id",
        "schema_version",
        "proof_inputs",
        "optimization_class",
        "transformation_witness",
        "equivalence_evidence",
        "rollback_token",
        "validity_epoch",
        "fallback_path",
        "performance_delta",
        "timestamp_ns",
        "signature",
        "metadata",
    ] {
        assert!(json.contains(key), "JSON missing key: {key}");
    }
}

// ===========================================================================
// 11. ReceiptIndex
// ===========================================================================

#[test]
fn index_new_is_empty() {
    let idx = ReceiptIndex::new();
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert!(idx.all().is_empty());
}

#[test]
fn index_default_is_empty() {
    let idx = ReceiptIndex::default();
    assert!(idx.is_empty());
}

#[test]
fn index_insert_valid_receipt() {
    let mut idx = ReceiptIndex::new();
    let receipt = test_receipt(epoch());
    assert!(idx.insert(receipt).is_ok());
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());
}

#[test]
fn index_insert_validates_receipt() {
    let mut idx = ReceiptIndex::new();
    let mut bad_receipt = test_receipt(epoch());
    bad_receipt.proof_inputs.clear();
    let err = idx.insert(bad_receipt).unwrap_err();
    assert_eq!(err, ReceiptError::EmptyProofInputs);
    assert!(idx.is_empty());
}

#[test]
fn index_specializations_from_proof_found() {
    let mut idx = ReceiptIndex::new();
    let receipt = test_receipt(epoch());
    let proof_id = receipt.proof_inputs[0].proof_id.clone();
    idx.insert(receipt).unwrap();
    let found = idx.specializations_from_proof(&proof_id);
    assert_eq!(found.len(), 1);
}

#[test]
fn index_specializations_from_proof_not_found() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let unknown = EngineObjectId([0xFFu8; 32]);
    assert!(idx.specializations_from_proof(&unknown).is_empty());
}

#[test]
fn index_proofs_for_specialization_found() {
    let mut idx = ReceiptIndex::new();
    let receipt = test_receipt(epoch());
    let rid = receipt.receipt_id.clone();
    idx.insert(receipt).unwrap();
    let proofs = idx.proofs_for_specialization(&rid);
    assert_eq!(proofs.len(), 2); // test_receipt has 2 proof inputs
}

#[test]
fn index_proofs_for_specialization_not_found() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let unknown = EngineObjectId([0xFFu8; 32]);
    assert!(idx.proofs_for_specialization(&unknown).is_empty());
}

#[test]
fn index_by_optimization_class() {
    let mut idx = ReceiptIndex::new();
    // test_receipt uses HostcallDispatchSpecialization
    idx.insert(test_receipt(epoch())).unwrap();
    let found = idx.by_optimization_class(OptimizationClass::HostcallDispatchSpecialization);
    assert_eq!(found.len(), 1);
    let empty = idx.by_optimization_class(OptimizationClass::PathElimination);
    assert!(empty.is_empty());
}

#[test]
fn index_by_epoch() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    let e99 = SecurityEpoch::from_raw(99);
    idx.insert(test_receipt(e42)).unwrap();
    assert_eq!(idx.by_epoch(e42).len(), 1);
    assert!(idx.by_epoch(e99).is_empty());
}

#[test]
fn index_invalidate_stale_removes_old_epoch() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    let e43 = SecurityEpoch::from_raw(43);
    idx.insert(test_receipt(e42)).unwrap();
    let stale = idx.invalidate_stale(e43);
    assert_eq!(stale.len(), 1);
    assert!(idx.is_empty());
}

#[test]
fn index_invalidate_stale_keeps_current_epoch() {
    let mut idx = ReceiptIndex::new();
    let e42 = SecurityEpoch::from_raw(42);
    idx.insert(test_receipt(e42)).unwrap();
    let stale = idx.invalidate_stale(e42);
    assert!(stale.is_empty());
    assert_eq!(idx.len(), 1);
}

#[test]
fn index_multiple_receipts_same_proof() {
    let e = epoch();
    let pi = test_proof_input(ProofType::CapabilityWitness, e);
    let mut idx = ReceiptIndex::new();

    let r1 = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, e)
        .add_proof_input(pi.clone())
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback_a")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(pi.clone())
        .transformation_witness(TransformationWitness {
            description: "Eliminate dead path".to_string(),
            before_ir_digest: ContentHash::compute(b"before-path"),
            after_ir_digest: ContentHash::compute(b"after-path"),
        })
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback_b")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();

    idx.insert(r1).unwrap();
    idx.insert(r2).unwrap();

    let found = idx.specializations_from_proof(&pi.proof_id);
    assert_eq!(found.len(), 2);
}

#[test]
fn index_serde_roundtrip() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let json = serde_json::to_string(&idx).unwrap();
    let back: ReceiptIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 1);
}

// ===========================================================================
// 12. ReceiptError Display + std::error::Error
// ===========================================================================

#[test]
fn receipt_error_display_empty_proof_inputs() {
    let err = ReceiptError::EmptyProofInputs;
    assert_eq!(err.to_string(), "proof_inputs must not be empty");
}

#[test]
fn receipt_error_display_identical_ir_digests() {
    let err = ReceiptError::IdenticalIrDigests;
    assert_eq!(err.to_string(), "before and after IR digests are identical");
}

#[test]
fn receipt_error_display_insufficient_pass_rate() {
    let err = ReceiptError::InsufficientPassRate {
        required: 1_000_000,
        actual: 500_000,
    };
    assert_eq!(err.to_string(), "pass_rate 500000 below required 1000000");
}

#[test]
fn receipt_error_display_epoch_mismatch() {
    let err = ReceiptError::EpochMismatch {
        receipt_epoch: 10,
        proof_epoch: 20,
    };
    assert_eq!(err.to_string(), "epoch mismatch: receipt=10, proof=20");
}

#[test]
fn receipt_error_display_incompatible_schema() {
    let err = ReceiptError::IncompatibleSchema {
        receipt: ReceiptSchemaVersion { major: 2, minor: 0 },
        reader: ReceiptSchemaVersion { major: 1, minor: 0 },
    };
    assert_eq!(
        err.to_string(),
        "schema incompatible: receipt=2.0, reader=1.0"
    );
}

#[test]
fn receipt_error_is_std_error() {
    let err = ReceiptError::EmptyProofInputs;
    // Verify it implements std::error::Error by calling source().
    let _source: Option<&dyn std::error::Error> = std::error::Error::source(&err);
}

#[test]
fn receipt_error_all_variants_display_non_empty() {
    let errors: Vec<ReceiptError> = vec![
        ReceiptError::EmptyProofInputs,
        ReceiptError::EmptyTransformationDescription,
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
        ReceiptError::IdDerivation("test".to_string()),
        ReceiptError::SignatureInvalid {
            detail: "bad".to_string(),
        },
        ReceiptError::IntegrityFailure {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        ReceiptError::IncompatibleSchema {
            receipt: ReceiptSchemaVersion { major: 2, minor: 0 },
            reader: ReceiptSchemaVersion { major: 1, minor: 0 },
        },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display for {err:?} should not be empty");
    }
}

#[test]
fn receipt_error_serde_roundtrip() {
    let err = ReceiptError::EpochMismatch {
        receipt_epoch: 42,
        proof_epoch: 99,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ReceiptError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ===========================================================================
// 13. ReceiptEvent / ReceiptEventKind
// ===========================================================================

#[test]
fn receipt_event_kind_display_all_variants() {
    assert_eq!(ReceiptEventKind::Created.to_string(), "created");
    assert_eq!(ReceiptEventKind::Signed.to_string(), "signed");
    assert_eq!(ReceiptEventKind::Validated.to_string(), "validated");
    assert_eq!(ReceiptEventKind::Indexed.to_string(), "indexed");
    assert_eq!(ReceiptEventKind::Invalidated.to_string(), "invalidated");
    assert_eq!(ReceiptEventKind::Queried.to_string(), "queried");
}

#[test]
fn receipt_event_serde_roundtrip() {
    let event = ReceiptEvent {
        trace_id: "trace-integration-1".to_string(),
        component: "proof_specialization_receipt".to_string(),
        event: ReceiptEventKind::Validated,
        receipt_id: Some("rid-42".to_string()),
        optimization_class: Some("ifc_check_elision".to_string()),
        outcome: "success".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn receipt_event_none_fields_serde() {
    let event = ReceiptEvent {
        trace_id: "trace-2".to_string(),
        component: "test".to_string(),
        event: ReceiptEventKind::Queried,
        receipt_id: None,
        optimization_class: None,
        outcome: "not_found".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.receipt_id.is_none());
    assert!(back.optimization_class.is_none());
}

#[test]
fn receipt_event_kind_serde_roundtrip() {
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

// ===========================================================================
// Cross-cutting: determinism, different-class-different-id
// ===========================================================================

#[test]
fn different_optimization_class_yields_different_receipt_id() {
    let r1 = build_valid_receipt(OptimizationClass::HostcallDispatchSpecialization, epoch());
    let r2 = build_valid_receipt(OptimizationClass::PathElimination, epoch());
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn different_epoch_yields_different_receipt_id() {
    let r1 = build_valid_receipt(
        OptimizationClass::HostcallDispatchSpecialization,
        SecurityEpoch::from_raw(1),
    );
    let r2 = build_valid_receipt(
        OptimizationClass::HostcallDispatchSpecialization,
        SecurityEpoch::from_raw(2),
    );
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn receipt_deterministic_across_50_iterations() {
    let first = test_receipt(epoch());
    for _ in 0..50 {
        let r = test_receipt(epoch());
        assert_eq!(r.receipt_id, first.receipt_id);
        assert_eq!(r.content_hash(), first.content_hash());
    }
}

// ===========================================================================
// Enrichment tests (~90 new tests)
// ===========================================================================

use frankenengine_engine::proof_specialization_receipt::ProofInput;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// E1. ReceiptSchemaVersion enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_clone() {
    let v = ReceiptSchemaVersion { major: 5, minor: 9 };
    let c = v.clone();
    assert_eq!(v, c);
    assert_eq!(c.major, 5);
    assert_eq!(c.minor, 9);
}

#[test]
fn enrichment_schema_version_debug_contains_fields() {
    let v = ReceiptSchemaVersion { major: 1, minor: 0 };
    let dbg = format!("{v:?}");
    assert!(dbg.contains("major"));
    assert!(dbg.contains("minor"));
    assert!(dbg.contains('1'));
    assert!(dbg.contains('0'));
}

#[test]
fn enrichment_schema_version_serde_roundtrip_nondefault() {
    let v = ReceiptSchemaVersion {
        major: 99,
        minor: 77,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReceiptSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_schema_version_ord() {
    let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
    let v11 = ReceiptSchemaVersion { major: 1, minor: 1 };
    let v20 = ReceiptSchemaVersion { major: 2, minor: 0 };
    assert!(v10 < v11);
    assert!(v11 < v20);
}

#[test]
fn enrichment_schema_version_compatible_self() {
    for major in 0..3 {
        for minor in 0..3 {
            let v = ReceiptSchemaVersion { major, minor };
            assert!(
                v.is_compatible_with(&v),
                "version {v} not compatible with itself"
            );
        }
    }
}

#[test]
fn enrichment_schema_version_display_zero() {
    let v = ReceiptSchemaVersion { major: 0, minor: 0 };
    assert_eq!(v.to_string(), "0.0");
}

// ---------------------------------------------------------------------------
// E2. ProofType enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_type_clone() {
    let pt = ProofType::FlowProof;
    let c = pt.clone();
    assert_eq!(pt, c);
}

#[test]
fn enrichment_proof_type_debug_format() {
    let dbg = format!("{:?}", ProofType::CapabilityWitness);
    assert_eq!(dbg, "CapabilityWitness");
    assert_eq!(format!("{:?}", ProofType::FlowProof), "FlowProof");
    assert_eq!(format!("{:?}", ProofType::ReplayMotif), "ReplayMotif");
}

#[test]
fn enrichment_proof_type_ord_total() {
    let mut types = vec![
        ProofType::ReplayMotif,
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
    ];
    types.sort();
    assert_eq!(types[0], ProofType::CapabilityWitness);
    assert_eq!(types[1], ProofType::FlowProof);
    assert_eq!(types[2], ProofType::ReplayMotif);
}

#[test]
fn enrichment_proof_type_display_not_eq_debug() {
    for pt in [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ] {
        assert_ne!(pt.to_string(), format!("{pt:?}"));
    }
}

// ---------------------------------------------------------------------------
// E3. OptimizationClass enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_optimization_class_clone() {
    let oc = OptimizationClass::PathElimination;
    let c = oc.clone();
    assert_eq!(oc, c);
}

#[test]
fn enrichment_optimization_class_debug_format() {
    assert_eq!(
        format!("{:?}", OptimizationClass::HostcallDispatchSpecialization),
        "HostcallDispatchSpecialization"
    );
    assert_eq!(
        format!("{:?}", OptimizationClass::IfcCheckElision),
        "IfcCheckElision"
    );
}

#[test]
fn enrichment_optimization_class_ord_total_sort() {
    let mut classes = vec![
        OptimizationClass::PathElimination,
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::IfcCheckElision,
    ];
    classes.sort();
    assert_eq!(
        classes[0],
        OptimizationClass::HostcallDispatchSpecialization
    );
    assert_eq!(classes[3], OptimizationClass::PathElimination);
}

#[test]
fn enrichment_optimization_class_display_not_eq_debug() {
    for oc in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ] {
        assert_ne!(oc.to_string(), format!("{oc:?}"));
    }
}

// ---------------------------------------------------------------------------
// E4. EquivalenceMethod enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_equivalence_method_clone() {
    let em = EquivalenceMethod::TranslationValidation;
    let c = em.clone();
    assert_eq!(em, c);
}

#[test]
fn enrichment_equivalence_method_ord_total_sort() {
    let mut methods = vec![
        EquivalenceMethod::Bisimulation,
        EquivalenceMethod::DifferentialTesting,
        EquivalenceMethod::TranslationValidation,
    ];
    methods.sort();
    assert_eq!(methods[0], EquivalenceMethod::DifferentialTesting);
    assert_eq!(methods[1], EquivalenceMethod::TranslationValidation);
    assert_eq!(methods[2], EquivalenceMethod::Bisimulation);
}

#[test]
fn enrichment_equivalence_method_debug_format() {
    assert_eq!(
        format!("{:?}", EquivalenceMethod::DifferentialTesting),
        "DifferentialTesting"
    );
    assert_eq!(
        format!("{:?}", EquivalenceMethod::Bisimulation),
        "Bisimulation"
    );
}

// ---------------------------------------------------------------------------
// E5. ProofInput enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_input_serde_roundtrip() {
    let pi = test_proof_input(ProofType::ReplayMotif, epoch());
    let json = serde_json::to_string(&pi).unwrap();
    let back: ProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(pi, back);
}

#[test]
fn enrichment_proof_input_clone_independence() {
    let original = test_proof_input(ProofType::CapabilityWitness, epoch());
    let mut cloned = original.clone();
    cloned.validity_window_ticks = 42;
    assert_eq!(original.validity_window_ticks, 1000);
    assert_eq!(cloned.validity_window_ticks, 42);
}

#[test]
fn enrichment_proof_input_debug_contains_type() {
    let pi = test_proof_input(ProofType::FlowProof, epoch());
    let dbg = format!("{pi:?}");
    assert!(dbg.contains("FlowProof"));
    assert!(dbg.contains("proof_type"));
}

#[test]
fn enrichment_proof_input_ord_sorts_by_type_then_id() {
    let e = epoch();
    let a = test_proof_input(ProofType::CapabilityWitness, e);
    let b = test_proof_input(ProofType::FlowProof, e);
    let c = test_proof_input(ProofType::ReplayMotif, e);
    let mut inputs = vec![c.clone(), a.clone(), b.clone()];
    inputs.sort();
    assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
    assert_eq!(inputs[1].proof_type, ProofType::FlowProof);
    assert_eq!(inputs[2].proof_type, ProofType::ReplayMotif);
}

#[test]
fn enrichment_proof_input_different_epochs_differ() {
    let a = test_proof_input(ProofType::CapabilityWitness, SecurityEpoch::from_raw(1));
    let b = test_proof_input(ProofType::CapabilityWitness, SecurityEpoch::from_raw(2));
    assert_ne!(a, b);
}

#[test]
fn enrichment_proof_input_json_field_names() {
    let pi = test_proof_input(ProofType::FlowProof, epoch());
    let json = serde_json::to_string(&pi).unwrap();
    for key in [
        "proof_type",
        "proof_id",
        "proof_epoch",
        "validity_window_ticks",
    ] {
        assert!(json.contains(key), "ProofInput JSON missing field: {key}");
    }
}

// ---------------------------------------------------------------------------
// E6. TransformationWitness enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transformation_witness_clone_deep() {
    let tw = test_transformation_witness();
    let c = tw.clone();
    assert_eq!(tw.description, c.description);
    assert_eq!(tw.before_ir_digest, c.before_ir_digest);
    assert_eq!(tw.after_ir_digest, c.after_ir_digest);
}

#[test]
fn enrichment_transformation_witness_debug_has_description() {
    let tw = test_transformation_witness();
    let dbg = format!("{tw:?}");
    assert!(dbg.contains("Specialized hostcall dispatch"));
}

#[test]
fn enrichment_transformation_witness_validate_whitespace_only_description() {
    let tw = TransformationWitness {
        description: "   ".to_string(),
        before_ir_digest: ContentHash::compute(b"a"),
        after_ir_digest: ContentHash::compute(b"b"),
    };
    // whitespace-only is not empty, so validate passes
    assert!(tw.validate().is_ok());
}

#[test]
fn enrichment_transformation_witness_json_field_names_all() {
    let tw = TransformationWitness {
        description: "test-transform".to_string(),
        before_ir_digest: ContentHash::compute(b"x"),
        after_ir_digest: ContentHash::compute(b"y"),
    };
    let json = serde_json::to_string(&tw).unwrap();
    assert!(json.contains("description"));
    assert!(json.contains("before_ir_digest"));
    assert!(json.contains("after_ir_digest"));
}

// ---------------------------------------------------------------------------
// E7. EquivalenceEvidence enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_equivalence_evidence_clone_deep() {
    let ee = test_equivalence_evidence();
    let c = ee.clone();
    assert_eq!(ee.method, c.method);
    assert_eq!(
        ee.differential_test_hashes.len(),
        c.differential_test_hashes.len()
    );
    assert_eq!(ee.test_count, c.test_count);
    assert_eq!(ee.pass_rate_millionths, c.pass_rate_millionths);
}

#[test]
fn enrichment_equivalence_evidence_debug_has_method() {
    let ee = test_equivalence_evidence();
    let dbg = format!("{ee:?}");
    assert!(dbg.contains("DifferentialTesting"));
}

#[test]
fn enrichment_equivalence_evidence_validate_exactly_100_percent() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::Bisimulation,
        differential_test_hashes: vec![ContentHash::compute(b"h1")],
        test_count: 1,
        pass_rate_millionths: 1_000_000,
    };
    assert!(ee.validate().is_ok());
}

#[test]
fn enrichment_equivalence_evidence_validate_one_below_100_percent() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::TranslationValidation,
        differential_test_hashes: vec![ContentHash::compute(b"h1")],
        test_count: 1000,
        pass_rate_millionths: 999_999,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 999_999,
        })
    );
}

#[test]
fn enrichment_equivalence_evidence_validate_zero_pass_rate() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"h1")],
        test_count: 100,
        pass_rate_millionths: 0,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 0,
        })
    );
}

#[test]
fn enrichment_equivalence_evidence_validate_max_u64_pass_rate() {
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![ContentHash::compute(b"h1")],
        test_count: 1,
        pass_rate_millionths: u64::MAX,
    };
    assert_eq!(
        ee.validate(),
        Err(ReceiptError::PassRateOutOfRange { value: u64::MAX })
    );
}

#[test]
fn enrichment_equivalence_evidence_multiple_hashes() {
    let hashes: Vec<ContentHash> = (0..10)
        .map(|i| ContentHash::compute(format!("test-{i}").as_bytes()))
        .collect();
    let ee = EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: hashes.clone(),
        test_count: 10,
        pass_rate_millionths: 1_000_000,
    };
    assert!(ee.validate().is_ok());
    let json = serde_json::to_string(&ee).unwrap();
    let back: EquivalenceEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back.differential_test_hashes.len(), 10);
}

// ---------------------------------------------------------------------------
// E8. RollbackToken enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_token_clone_deep() {
    let rt = test_rollback_token();
    let c = rt.clone();
    assert_eq!(rt.baseline_hash, c.baseline_hash);
    assert_eq!(rt.rollback_procedure_hash, c.rollback_procedure_hash);
    assert_eq!(rt.validated, c.validated);
}

#[test]
fn enrichment_rollback_token_debug_has_validated() {
    let rt = test_rollback_token();
    let dbg = format!("{rt:?}");
    assert!(dbg.contains("validated"));
    assert!(dbg.contains("true"));
}

#[test]
fn enrichment_rollback_token_different_hashes_not_equal() {
    let a = RollbackToken {
        baseline_hash: ContentHash::compute(b"alpha"),
        rollback_procedure_hash: ContentHash::compute(b"proc-a"),
        validated: true,
    };
    let b = RollbackToken {
        baseline_hash: ContentHash::compute(b"beta"),
        rollback_procedure_hash: ContentHash::compute(b"proc-b"),
        validated: true,
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// E9. PerformanceDelta enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_performance_delta_clone_deep() {
    let pd = test_performance_delta();
    let c = pd.clone();
    assert_eq!(
        pd.latency_reduction_millionths,
        c.latency_reduction_millionths
    );
    assert_eq!(
        pd.throughput_increase_millionths,
        c.throughput_increase_millionths
    );
    assert_eq!(pd.sample_count, c.sample_count);
}

#[test]
fn enrichment_performance_delta_debug_has_fields() {
    let pd = test_performance_delta();
    let dbg = format!("{pd:?}");
    assert!(dbg.contains("latency_reduction_millionths"));
    assert!(dbg.contains("throughput_increase_millionths"));
    assert!(dbg.contains("sample_count"));
}

#[test]
fn enrichment_performance_delta_validate_single_sample() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: 0,
        throughput_increase_millionths: 0,
        sample_count: 1,
    };
    assert!(pd.validate().is_ok());
}

#[test]
fn enrichment_performance_delta_validate_large_values() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: u64::MAX,
        throughput_increase_millionths: u64::MAX,
        sample_count: u64::MAX,
    };
    assert!(pd.validate().is_ok());
}

#[test]
fn enrichment_performance_delta_zero_latency_and_throughput_valid() {
    let pd = PerformanceDelta {
        latency_reduction_millionths: 0,
        throughput_increase_millionths: 0,
        sample_count: 50,
    };
    assert!(pd.validate().is_ok());
}

// ---------------------------------------------------------------------------
// E10. ReceiptError enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_error_clone_all_variants() {
    let errors: Vec<ReceiptError> = vec![
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
            receipt_epoch: 10,
            proof_epoch: 20,
        },
        ReceiptError::ProofExpired {
            proof_id: "p1".to_string(),
            window_ticks: 100,
        },
        ReceiptError::IdDerivation("test-deriv".to_string()),
        ReceiptError::SignatureInvalid {
            detail: "bad-sig".to_string(),
        },
        ReceiptError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        ReceiptError::IncompatibleSchema {
            receipt: ReceiptSchemaVersion { major: 3, minor: 1 },
            reader: ReceiptSchemaVersion { major: 2, minor: 5 },
        },
    ];
    for err in &errors {
        let c = err.clone();
        assert_eq!(err, &c);
    }
}

#[test]
fn enrichment_receipt_error_display_empty_transformation_description() {
    let err = ReceiptError::EmptyTransformationDescription;
    assert_eq!(
        err.to_string(),
        "transformation_witness description is empty"
    );
}

#[test]
fn enrichment_receipt_error_display_empty_fallback_path() {
    let err = ReceiptError::EmptyFallbackPath;
    assert_eq!(err.to_string(), "fallback path is empty");
}

#[test]
fn enrichment_receipt_error_display_no_equivalence_tests() {
    let err = ReceiptError::NoEquivalenceTests;
    assert_eq!(
        err.to_string(),
        "equivalence_evidence has no differential test hashes"
    );
}

#[test]
fn enrichment_receipt_error_display_zero_test_count() {
    let err = ReceiptError::ZeroTestCount;
    assert_eq!(err.to_string(), "equivalence_evidence test_count is zero");
}

#[test]
fn enrichment_receipt_error_display_pass_rate_out_of_range() {
    let err = ReceiptError::PassRateOutOfRange { value: 2_000_000 };
    assert_eq!(
        err.to_string(),
        "pass_rate_millionths 2000000 exceeds maximum 1000000"
    );
}

#[test]
fn enrichment_receipt_error_display_zero_benchmark_samples() {
    let err = ReceiptError::ZeroBenchmarkSamples;
    assert_eq!(err.to_string(), "performance_delta sample_count is zero");
}

#[test]
fn enrichment_receipt_error_display_unvalidated_rollback() {
    let err = ReceiptError::UnvalidatedRollback;
    assert_eq!(err.to_string(), "rollback_token has not been validated");
}

#[test]
fn enrichment_receipt_error_display_proof_expired() {
    let err = ReceiptError::ProofExpired {
        proof_id: "proof-42".to_string(),
        window_ticks: 500,
    };
    assert_eq!(err.to_string(), "proof proof-42 expired (window=500)");
}

#[test]
fn enrichment_receipt_error_display_id_derivation() {
    let err = ReceiptError::IdDerivation("bad input".to_string());
    assert_eq!(err.to_string(), "ID derivation error: bad input");
}

#[test]
fn enrichment_receipt_error_display_signature_invalid() {
    let err = ReceiptError::SignatureInvalid {
        detail: "corrupted".to_string(),
    };
    assert_eq!(err.to_string(), "signature invalid: corrupted");
}

#[test]
fn enrichment_receipt_error_display_integrity_failure() {
    let err = ReceiptError::IntegrityFailure {
        expected: "abc123".to_string(),
        actual: "def456".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "content hash mismatch: expected=abc123, actual=def456"
    );
}

#[test]
fn enrichment_receipt_error_serde_roundtrip_all_variants() {
    let errors: Vec<ReceiptError> = vec![
        ReceiptError::EmptyProofInputs,
        ReceiptError::EmptyTransformationDescription,
        ReceiptError::EmptyFallbackPath,
        ReceiptError::IdenticalIrDigests,
        ReceiptError::NoEquivalenceTests,
        ReceiptError::ZeroTestCount,
        ReceiptError::PassRateOutOfRange { value: 42 },
        ReceiptError::InsufficientPassRate {
            required: 1_000_000,
            actual: 500,
        },
        ReceiptError::ZeroBenchmarkSamples,
        ReceiptError::UnvalidatedRollback,
        ReceiptError::EpochMismatch {
            receipt_epoch: 7,
            proof_epoch: 8,
        },
        ReceiptError::ProofExpired {
            proof_id: "pid".to_string(),
            window_ticks: 99,
        },
        ReceiptError::IdDerivation("test".to_string()),
        ReceiptError::SignatureInvalid {
            detail: "hmac".to_string(),
        },
        ReceiptError::IntegrityFailure {
            expected: "e".to_string(),
            actual: "a".to_string(),
        },
        ReceiptError::IncompatibleSchema {
            receipt: ReceiptSchemaVersion { major: 4, minor: 2 },
            reader: ReceiptSchemaVersion { major: 3, minor: 1 },
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReceiptError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &back);
    }
}

#[test]
fn enrichment_receipt_error_source_is_none() {
    let errors: Vec<ReceiptError> = vec![
        ReceiptError::EmptyProofInputs,
        ReceiptError::EmptyFallbackPath,
        ReceiptError::IdDerivation("x".into()),
        ReceiptError::SignatureInvalid { detail: "y".into() },
    ];
    for err in &errors {
        assert!(std::error::Error::source(err).is_none());
    }
}

// ---------------------------------------------------------------------------
// E11. ReceiptEvent / ReceiptEventKind enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_event_kind_clone() {
    let kind = ReceiptEventKind::Indexed;
    let c = kind.clone();
    assert_eq!(kind, c);
}

#[test]
fn enrichment_receipt_event_kind_debug_format() {
    assert_eq!(format!("{:?}", ReceiptEventKind::Created), "Created");
    assert_eq!(format!("{:?}", ReceiptEventKind::Signed), "Signed");
    assert_eq!(format!("{:?}", ReceiptEventKind::Validated), "Validated");
    assert_eq!(format!("{:?}", ReceiptEventKind::Indexed), "Indexed");
    assert_eq!(
        format!("{:?}", ReceiptEventKind::Invalidated),
        "Invalidated"
    );
    assert_eq!(format!("{:?}", ReceiptEventKind::Queried), "Queried");
}

#[test]
fn enrichment_receipt_event_clone_deep() {
    let original = ReceiptEvent {
        trace_id: "tr-99".to_string(),
        component: "comp-x".to_string(),
        event: ReceiptEventKind::Signed,
        receipt_id: Some("rid-7".to_string()),
        optimization_class: Some("path_elimination".to_string()),
        outcome: "ok".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_receipt_event_debug_has_trace_id() {
    let event = ReceiptEvent {
        trace_id: "unique-trace-123".to_string(),
        component: "test-comp".to_string(),
        event: ReceiptEventKind::Invalidated,
        receipt_id: None,
        optimization_class: None,
        outcome: "stale".to_string(),
    };
    let dbg = format!("{event:?}");
    assert!(dbg.contains("unique-trace-123"));
}

#[test]
fn enrichment_receipt_event_json_field_names_with_nones() {
    let event = ReceiptEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: ReceiptEventKind::Created,
        receipt_id: None,
        optimization_class: None,
        outcome: "ok".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("trace_id"));
    assert!(json.contains("component"));
    assert!(json.contains("event"));
    assert!(json.contains("outcome"));
}

#[test]
fn enrichment_receipt_event_all_kinds_round_trip() {
    let kinds = [
        ReceiptEventKind::Created,
        ReceiptEventKind::Signed,
        ReceiptEventKind::Validated,
        ReceiptEventKind::Indexed,
        ReceiptEventKind::Invalidated,
        ReceiptEventKind::Queried,
    ];
    for kind in &kinds {
        let event = ReceiptEvent {
            trace_id: format!("trace-{kind}"),
            component: "psr".to_string(),
            event: *kind,
            receipt_id: Some("rid".to_string()),
            optimization_class: None,
            outcome: "success".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

// ---------------------------------------------------------------------------
// E12. SpecializationReceipt enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_clone_deep_independence() {
    let original = test_receipt(epoch());
    let mut cloned = original.clone();
    cloned
        .metadata
        .insert("new-key".to_string(), "val".to_string());
    assert!(original.metadata.get("new-key").is_none());
    assert!(cloned.metadata.get("new-key").is_some());
}

#[test]
fn enrichment_receipt_debug_has_receipt_id() {
    let receipt = test_receipt(epoch());
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("receipt_id"));
    assert!(dbg.contains("schema_version"));
    assert!(dbg.contains("optimization_class"));
}

#[test]
fn enrichment_receipt_serde_preserves_all_fields() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, e)
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::fusion::fallback")
        .performance_delta(test_performance_delta())
        .timestamp_ns(999_999)
        .metadata("key1", "val1")
        .metadata("key2", "val2")
        .build()
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SpecializationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.receipt_id, back.receipt_id);
    assert_eq!(receipt.schema_version, back.schema_version);
    assert_eq!(receipt.optimization_class, back.optimization_class);
    assert_eq!(receipt.proof_inputs.len(), back.proof_inputs.len());
    assert_eq!(receipt.fallback_path, back.fallback_path);
    assert_eq!(receipt.timestamp_ns, back.timestamp_ns);
    assert_eq!(receipt.metadata, back.metadata);
}

#[test]
fn enrichment_receipt_validate_empty_fallback_path() {
    let e = epoch();
    let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("")
        .performance_delta(test_performance_delta())
        .build();
    // Builder builds but validate catches empty fallback
    let receipt = result.unwrap();
    assert_eq!(receipt.validate(), Err(ReceiptError::EmptyFallbackPath));
}

#[test]
fn enrichment_receipt_derive_id_consistency() {
    let receipt = test_receipt(epoch());
    let derived = receipt.derive_receipt_id().unwrap();
    assert_eq!(receipt.receipt_id, derived);
}

#[test]
fn enrichment_receipt_content_hash_changes_on_metadata_change() {
    let e = epoch();
    let r1 = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback-a")
        .performance_delta(test_performance_delta())
        .metadata("key", "value-1")
        .build()
        .unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fallback-a")
        .performance_delta(test_performance_delta())
        .metadata("key", "value-2")
        .build()
        .unwrap();
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_receipt_content_hash_changes_on_timestamp_change() {
    let e = epoch();
    let r1 = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .timestamp_ns(100)
        .build()
        .unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .timestamp_ns(200)
        .build()
        .unwrap();
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_receipt_sign_verify_all_opt_classes() {
    let key = signing_key();
    let vk = key.verification_key();
    for class in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ] {
        let mut receipt = build_valid_receipt(class, epoch());
        receipt.sign(&key).unwrap();
        assert!(receipt.verify(&vk).is_ok(), "verify failed for {class}");
    }
}

#[test]
fn enrichment_receipt_sign_changes_signature_field() {
    let key = signing_key();
    let mut receipt = test_receipt(epoch());
    let sig_before = receipt.signature.clone();
    receipt.sign(&key).unwrap();
    assert_ne!(receipt.signature, sig_before);
}

#[test]
fn enrichment_receipt_verify_fails_on_proof_input_mutation() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    receipt.proof_inputs[0].validity_window_ticks = 9999;
    assert!(receipt.verify(&vk).is_err());
}

#[test]
fn enrichment_receipt_verify_fails_on_fallback_path_mutation() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut receipt = test_receipt(epoch());
    receipt.sign(&key).unwrap();
    receipt.fallback_path = "mutated::path".to_string();
    assert!(receipt.verify(&vk).is_err());
}

#[test]
fn enrichment_receipt_epoch_consistency_all_matching() {
    let e = SecurityEpoch::from_raw(77);
    let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, e)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert!(receipt.validate_epoch_consistency().is_ok());
}

#[test]
fn enrichment_receipt_epoch_consistency_second_input_mismatch() {
    let e = SecurityEpoch::from_raw(50);
    let mut receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    receipt.proof_inputs[1].proof_epoch = SecurityEpoch::from_raw(999);
    let err = receipt.validate_epoch_consistency().unwrap_err();
    assert_eq!(
        err,
        ReceiptError::EpochMismatch {
            receipt_epoch: 50,
            proof_epoch: 999,
        }
    );
}

#[test]
fn enrichment_receipt_json_field_proof_inputs_is_array() {
    let receipt = test_receipt(epoch());
    let val: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    assert!(val["proof_inputs"].is_array());
    assert_eq!(val["proof_inputs"].as_array().unwrap().len(), 2);
}

#[test]
fn enrichment_receipt_json_field_metadata_is_object() {
    let receipt = test_receipt(epoch());
    let val: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    assert!(val["metadata"].is_object());
}

#[test]
fn enrichment_receipt_json_field_timestamp_ns_is_number() {
    let receipt = test_receipt(epoch());
    let val: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    assert!(val["timestamp_ns"].is_number());
}

// ---------------------------------------------------------------------------
// E13. ReceiptBuilder enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_builder_debug_format() {
    let builder = ReceiptBuilder::new(OptimizationClass::PathElimination, epoch());
    let dbg = format!("{builder:?}");
    assert!(dbg.contains("PathElimination"));
}

#[test]
fn enrichment_builder_timestamp_ns_zero_default() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert_eq!(receipt.timestamp_ns, 0);
}

#[test]
fn enrichment_builder_metadata_overwrite_same_key() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .metadata("key", "first")
        .metadata("key", "second")
        .build()
        .unwrap();
    assert_eq!(receipt.metadata.get("key").unwrap(), "second");
    assert_eq!(receipt.metadata.len(), 1);
}

#[test]
fn enrichment_builder_no_metadata() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert!(receipt.metadata.is_empty());
}

#[test]
fn enrichment_builder_schema_version_always_current() {
    for class in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ] {
        let receipt = build_valid_receipt(class, epoch());
        assert_eq!(receipt.schema_version, ReceiptSchemaVersion::CURRENT);
    }
}

#[test]
fn enrichment_builder_all_four_optimization_classes() {
    let e = epoch();
    let classes = [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ];
    let mut ids = BTreeSet::new();
    for class in &classes {
        let receipt = build_valid_receipt(*class, e);
        assert!(receipt.validate().is_ok());
        ids.insert(format!("{:?}", receipt.receipt_id));
    }
    assert_eq!(ids.len(), 4, "all 4 classes produce distinct receipt IDs");
}

// ---------------------------------------------------------------------------
// E14. ReceiptIndex enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_index_all_returns_inserted_order() {
    let mut idx = ReceiptIndex::new();
    let e1 = SecurityEpoch::from_raw(10);
    let e2 = SecurityEpoch::from_raw(20);
    let r1 = build_valid_receipt(OptimizationClass::HostcallDispatchSpecialization, e1);
    let r2 = build_valid_receipt(OptimizationClass::PathElimination, e2);
    let id1 = r1.receipt_id.clone();
    let id2 = r2.receipt_id.clone();
    idx.insert(r1).unwrap();
    idx.insert(r2).unwrap();
    let all = idx.all();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].receipt_id, id1);
    assert_eq!(all[1].receipt_id, id2);
}

#[test]
fn enrichment_index_clone_independence() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let cloned = idx.clone();
    assert_eq!(cloned.len(), 1);
    idx.insert(build_valid_receipt(
        OptimizationClass::PathElimination,
        SecurityEpoch::from_raw(99),
    ))
    .unwrap();
    assert_eq!(idx.len(), 2);
    assert_eq!(cloned.len(), 1);
}

#[test]
fn enrichment_index_debug_shows_receipts() {
    let mut idx = ReceiptIndex::new();
    idx.insert(test_receipt(epoch())).unwrap();
    let dbg = format!("{idx:?}");
    assert!(dbg.contains("receipts"));
}

#[test]
fn enrichment_index_invalidate_stale_mixed_epochs() {
    let mut idx = ReceiptIndex::new();
    let e10 = SecurityEpoch::from_raw(10);
    let e20 = SecurityEpoch::from_raw(20);
    let e30 = SecurityEpoch::from_raw(30);
    idx.insert(build_valid_receipt(
        OptimizationClass::HostcallDispatchSpecialization,
        e10,
    ))
    .unwrap();
    idx.insert(build_valid_receipt(OptimizationClass::IfcCheckElision, e20))
        .unwrap();
    idx.insert(build_valid_receipt(OptimizationClass::PathElimination, e20))
        .unwrap();
    assert_eq!(idx.len(), 3);
    let stale = idx.invalidate_stale(e20);
    assert_eq!(stale.len(), 1); // only e10 receipt
    assert_eq!(idx.len(), 2);
    let stale2 = idx.invalidate_stale(e30);
    assert_eq!(stale2.len(), 2);
    assert!(idx.is_empty());
}

#[test]
fn enrichment_index_invalidate_stale_empty_index() {
    let mut idx = ReceiptIndex::new();
    let stale = idx.invalidate_stale(SecurityEpoch::from_raw(1));
    assert!(stale.is_empty());
    assert!(idx.is_empty());
}

#[test]
fn enrichment_index_by_class_multiple_results() {
    let mut idx = ReceiptIndex::new();
    let e = epoch();
    // Two receipts with same optimization class but different fallback paths
    let r1 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb-a")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(TransformationWitness {
            description: "Different transform".to_string(),
            before_ir_digest: ContentHash::compute(b"b2"),
            after_ir_digest: ContentHash::compute(b"a2"),
        })
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb-b")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    idx.insert(r1).unwrap();
    idx.insert(r2).unwrap();
    let found = idx.by_optimization_class(OptimizationClass::PathElimination);
    assert_eq!(found.len(), 2);
}

#[test]
fn enrichment_index_by_epoch_multiple_results() {
    let mut idx = ReceiptIndex::new();
    let e = SecurityEpoch::from_raw(55);
    let r1 = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, e)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb1")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(TransformationWitness {
            description: "path elim".to_string(),
            before_ir_digest: ContentHash::compute(b"before-pe"),
            after_ir_digest: ContentHash::compute(b"after-pe"),
        })
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb2")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    idx.insert(r1).unwrap();
    idx.insert(r2).unwrap();
    let found = idx.by_epoch(e);
    assert_eq!(found.len(), 2);
}

#[test]
fn enrichment_index_serde_preserves_multiple_receipts() {
    let mut idx = ReceiptIndex::new();
    let e = epoch();
    idx.insert(build_valid_receipt(
        OptimizationClass::HostcallDispatchSpecialization,
        e,
    ))
    .unwrap();
    idx.insert(build_valid_receipt(OptimizationClass::PathElimination, e))
        .unwrap();
    let json = serde_json::to_string(&idx).unwrap();
    let back: ReceiptIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
}

// ---------------------------------------------------------------------------
// E15. Cross-cutting determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_content_hash_100_iterations() {
    let receipt = test_receipt(epoch());
    let hash = receipt.content_hash();
    for _ in 0..100 {
        let r = test_receipt(epoch());
        assert_eq!(r.content_hash(), hash);
    }
}

#[test]
fn enrichment_determinism_derive_id_100_iterations() {
    let receipt = test_receipt(epoch());
    let id = receipt.derive_receipt_id().unwrap();
    for _ in 0..100 {
        let r = test_receipt(epoch());
        assert_eq!(r.derive_receipt_id().unwrap(), id);
    }
}

#[test]
fn enrichment_determinism_builder_same_inputs_same_id() {
    let e = SecurityEpoch::from_raw(7);
    let mut ids = BTreeSet::new();
    for _ in 0..20 {
        let receipt = build_valid_receipt(OptimizationClass::SuperinstructionFusion, e);
        ids.insert(format!("{:?}", receipt.receipt_id));
    }
    assert_eq!(ids.len(), 1, "20 identical builds must yield same ID");
}

// ---------------------------------------------------------------------------
// E16. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_epoch_zero() {
    let e = SecurityEpoch::from_raw(0);
    let receipt = build_valid_receipt(OptimizationClass::HostcallDispatchSpecialization, e);
    assert!(receipt.validate().is_ok());
    assert!(receipt.validate_epoch_consistency().is_ok());
}

#[test]
fn enrichment_receipt_epoch_max() {
    let e = SecurityEpoch::from_raw(u64::MAX);
    let receipt = build_valid_receipt(OptimizationClass::PathElimination, e);
    assert!(receipt.validate().is_ok());
    assert!(receipt.validate_epoch_consistency().is_ok());
}

#[test]
fn enrichment_receipt_long_fallback_path() {
    let e = epoch();
    let long_path = "a".repeat(10_000);
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path(&long_path)
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert_eq!(receipt.fallback_path.len(), 10_000);
    assert!(receipt.validate().is_ok());
}

#[test]
fn enrichment_receipt_many_proof_inputs() {
    let e = epoch();
    let mut builder = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, e);
    // Add same type multiple times (different objects due to same derivation seed though)
    for _ in 0..20 {
        builder = builder.add_proof_input(test_proof_input(ProofType::CapabilityWitness, e));
    }
    let receipt = builder
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    assert_eq!(receipt.proof_inputs.len(), 20);
    assert!(receipt.validate().is_ok());
}

#[test]
fn enrichment_receipt_many_metadata_entries() {
    let e = epoch();
    let mut builder = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
        .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta());
    for i in 0..50 {
        builder = builder.metadata(format!("key-{i}"), format!("val-{i}"));
    }
    let receipt = builder.build().unwrap();
    assert_eq!(receipt.metadata.len(), 50);
    // serde roundtrip preserves all metadata
    let json = serde_json::to_string(&receipt).unwrap();
    let back: SpecializationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.metadata.len(), 50);
}

#[test]
fn enrichment_receipt_timestamp_ns_max() {
    let e = epoch();
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(test_proof_input(ProofType::FlowProof, e))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .timestamp_ns(u64::MAX)
        .build()
        .unwrap();
    assert_eq!(receipt.timestamp_ns, u64::MAX);
    assert!(receipt.validate().is_ok());
}

#[test]
fn enrichment_receipt_each_proof_type_standalone() {
    let e = epoch();
    for pt in [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ] {
        let receipt = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, e)
            .add_proof_input(test_proof_input(pt, e))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fb")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.proof_inputs[0].proof_type, pt);
    }
}

#[test]
fn enrichment_receipt_equivalence_all_methods() {
    let e = epoch();
    for method in [
        EquivalenceMethod::DifferentialTesting,
        EquivalenceMethod::TranslationValidation,
        EquivalenceMethod::Bisimulation,
    ] {
        let ee = EquivalenceEvidence {
            method,
            differential_test_hashes: vec![ContentHash::compute(b"hash")],
            test_count: 10,
            pass_rate_millionths: 1_000_000,
        };
        let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
            .add_proof_input(test_proof_input(ProofType::FlowProof, e))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(ee)
            .rollback_token(test_rollback_token())
            .fallback_path("fb")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.equivalence_evidence.method, method);
    }
}

#[test]
fn enrichment_receipt_proof_input_validity_window_zero() {
    let e = epoch();
    let mut pi = test_proof_input(ProofType::FlowProof, e);
    pi.validity_window_ticks = 0;
    let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
        .add_proof_input(pi)
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("fb")
        .performance_delta(test_performance_delta())
        .build()
        .unwrap();
    // validate does not check validity_window_ticks
    assert!(receipt.validate().is_ok());
}

#[test]
fn enrichment_index_specializations_from_proof_with_shared_input() {
    let e = epoch();
    let shared_pi = test_proof_input(ProofType::ReplayMotif, e);
    let mut idx = ReceiptIndex::new();
    for class in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
    ] {
        let r = ReceiptBuilder::new(class, e)
            .add_proof_input(shared_pi.clone())
            .transformation_witness(TransformationWitness {
                description: format!("transform for {class}"),
                before_ir_digest: ContentHash::compute(format!("before-{class}").as_bytes()),
                after_ir_digest: ContentHash::compute(format!("after-{class}").as_bytes()),
            })
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path(format!("fb-{class}"))
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        idx.insert(r).unwrap();
    }
    let found = idx.specializations_from_proof(&shared_pi.proof_id);
    assert_eq!(found.len(), 3);
}
