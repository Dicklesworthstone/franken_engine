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
        before_ir_digest: hash.clone(),
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
