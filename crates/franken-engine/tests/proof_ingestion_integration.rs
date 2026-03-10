//! Integration tests for the `proof_ingestion` module.
//!
//! Covers: ProofType, ProofInput, ProofValidationStatus, HypothesisKind,
//! RiskLevel, OptimizerHypothesis, IngestionEvent, IngestionEventType,
//! SpecializationReceipt, ActivationStageLocal, IngestionError,
//! IngestionConfig, ProofIngestionEngine lifecycle, churn dampening,
//! and the `create_proof_input` helper.

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

use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_ingestion::{
    ActivationStageLocal, HypothesisKind, IngestionConfig, IngestionError, IngestionEvent,
    IngestionEventType, OptimizerHypothesis, ProofIngestionEngine, ProofInput, ProofType,
    ProofValidationStatus, RiskLevel, SpecializationReceipt, create_proof_input,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers — mirror the inline helpers
// ---------------------------------------------------------------------------

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    key
}

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn test_config() -> IngestionConfig {
    IngestionConfig {
        active_policy_id: "policy-001".to_string(),
        signing_key: test_key(),
        ..IngestionConfig::default()
    }
}

fn test_engine() -> ProofIngestionEngine {
    ProofIngestionEngine::new(test_epoch(), test_config())
}

fn make_proof(proof_type: ProofType, payload: &[u8], policy: &str) -> ProofInput {
    create_proof_input(proof_type, test_epoch(), 0, 0, policy, payload, &test_key()).unwrap()
}

fn make_default_proof(proof_type: ProofType) -> ProofInput {
    make_proof(proof_type, b"test-payload", "policy-001")
}

fn fake_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &SchemaId::from_definition(b"fake"),
        b"fake",
    )
    .unwrap()
}

// ===========================================================================
// ProofType — serde + display
// ===========================================================================

#[test]
fn proof_type_serde_roundtrip_all_variants() {
    let variants = [
        ProofType::PlasCapabilityWitness,
        ProofType::IfcFlowProof,
        ProofType::ReplaySequenceMotif,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn proof_type_display_strings() {
    assert_eq!(
        ProofType::PlasCapabilityWitness.to_string(),
        "plas-capability-witness"
    );
    assert_eq!(ProofType::IfcFlowProof.to_string(), "ifc-flow-proof");
    assert_eq!(
        ProofType::ReplaySequenceMotif.to_string(),
        "replay-sequence-motif"
    );
}

#[test]
fn proof_type_ord_is_stable() {
    assert!(ProofType::PlasCapabilityWitness < ProofType::IfcFlowProof);
    assert!(ProofType::IfcFlowProof < ProofType::ReplaySequenceMotif);
}

// ===========================================================================
// HypothesisKind — serde + display
// ===========================================================================

#[test]
fn hypothesis_kind_serde_roundtrip_all_variants() {
    let variants = [
        HypothesisKind::DeadCodeElimination,
        HypothesisKind::DispatchSpecialization,
        HypothesisKind::FlowCheckElision,
        HypothesisKind::SuperinstructionFusion,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: HypothesisKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn hypothesis_kind_display_strings() {
    assert_eq!(
        HypothesisKind::DeadCodeElimination.to_string(),
        "dead-code-elimination"
    );
    assert_eq!(
        HypothesisKind::DispatchSpecialization.to_string(),
        "dispatch-specialization"
    );
    assert_eq!(
        HypothesisKind::FlowCheckElision.to_string(),
        "flow-check-elision"
    );
    assert_eq!(
        HypothesisKind::SuperinstructionFusion.to_string(),
        "superinstruction-fusion"
    );
}

// ===========================================================================
// RiskLevel — serde + display + ord
// ===========================================================================

#[test]
fn risk_level_serde_roundtrip() {
    for v in [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn risk_level_display_strings() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
}

#[test]
fn risk_level_ordering() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
}

// ===========================================================================
// ActivationStageLocal — serde + display
// ===========================================================================

#[test]
fn activation_stage_serde_roundtrip() {
    for v in [
        ActivationStageLocal::Shadow,
        ActivationStageLocal::Canary,
        ActivationStageLocal::Ramp,
        ActivationStageLocal::Default,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: ActivationStageLocal = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn activation_stage_display_strings() {
    assert_eq!(ActivationStageLocal::Shadow.to_string(), "shadow");
    assert_eq!(ActivationStageLocal::Canary.to_string(), "canary");
    assert_eq!(ActivationStageLocal::Ramp.to_string(), "ramp");
    assert_eq!(ActivationStageLocal::Default.to_string(), "default");
}

#[test]
fn activation_stage_ordering() {
    assert!(ActivationStageLocal::Shadow < ActivationStageLocal::Canary);
    assert!(ActivationStageLocal::Canary < ActivationStageLocal::Ramp);
    assert!(ActivationStageLocal::Ramp < ActivationStageLocal::Default);
}

// ===========================================================================
// ProofValidationStatus — serde + display
// ===========================================================================

#[test]
fn proof_validation_status_serde_all_variants() {
    let statuses = vec![
        ProofValidationStatus::Accepted,
        ProofValidationStatus::SignatureInvalid,
        ProofValidationStatus::EpochStale {
            proof_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        ProofValidationStatus::Expired {
            validity_end_ns: 100,
            current_ns: 200,
        },
        ProofValidationStatus::PolicyMismatch {
            proof_policy: "a".to_string(),
            active_policy: "b".to_string(),
        },
        ProofValidationStatus::SemanticCheckFailed {
            reason: "bad".to_string(),
        },
        ProofValidationStatus::Duplicate {
            existing_id: fake_id(),
        },
    ];

    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let restored: ProofValidationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn proof_validation_status_display_non_empty() {
    let statuses = vec![
        ProofValidationStatus::Accepted,
        ProofValidationStatus::SignatureInvalid,
        ProofValidationStatus::EpochStale {
            proof_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        ProofValidationStatus::Expired {
            validity_end_ns: 100,
            current_ns: 200,
        },
        ProofValidationStatus::PolicyMismatch {
            proof_policy: "a".to_string(),
            active_policy: "b".to_string(),
        },
        ProofValidationStatus::SemanticCheckFailed {
            reason: "test".to_string(),
        },
        ProofValidationStatus::Duplicate {
            existing_id: fake_id(),
        },
    ];

    for s in &statuses {
        assert!(
            !s.to_string().is_empty(),
            "display should not be empty: {s:?}"
        );
    }
}

// ===========================================================================
// IngestionError — serde + display + std::error
// ===========================================================================

#[test]
fn ingestion_error_serde_all_variants() {
    let errors: Vec<IngestionError> = vec![
        IngestionError::ValidationFailed {
            proof_id: fake_id(),
            status: ProofValidationStatus::SignatureInvalid,
        },
        IngestionError::NoHypothesesGenerated {
            proof_id: fake_id(),
        },
        IngestionError::HypothesisGenerationFailed {
            reason: "test".to_string(),
        },
        IngestionError::UnsupportedProofType {
            proof_type: ProofType::IfcFlowProof,
        },
        IngestionError::IdDerivation("oops".to_string()),
        IngestionError::ConservativeModeActive {
            invalidation_count: 5,
            window_ns: 1000,
        },
    ];

    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: IngestionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn ingestion_error_display_non_empty() {
    let errors: Vec<IngestionError> = vec![
        IngestionError::ValidationFailed {
            proof_id: fake_id(),
            status: ProofValidationStatus::SignatureInvalid,
        },
        IngestionError::NoHypothesesGenerated {
            proof_id: fake_id(),
        },
        IngestionError::HypothesisGenerationFailed {
            reason: "test".to_string(),
        },
        IngestionError::UnsupportedProofType {
            proof_type: ProofType::PlasCapabilityWitness,
        },
        IngestionError::IdDerivation("msg".to_string()),
        IngestionError::ConservativeModeActive {
            invalidation_count: 10,
            window_ns: 60_000_000_000,
        },
    ];

    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty(), "error display should not be empty: {e:?}");
    }
}

#[test]
fn ingestion_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(IngestionError::IdDerivation("x".to_string()));
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// IngestionConfig — default
// ===========================================================================

#[test]
fn ingestion_config_default_values() {
    let cfg = IngestionConfig::default();
    assert!(cfg.active_policy_id.is_empty());
    assert_eq!(cfg.signing_key, [0u8; 32]);
    assert_eq!(cfg.churn_threshold, 10);
    assert_eq!(cfg.churn_window_ns, 60_000_000_000);
    assert_eq!(cfg.plas_speedup_estimate, 1_200_000);
    assert_eq!(cfg.ifc_speedup_estimate, 1_100_000);
    assert_eq!(cfg.replay_speedup_estimate, 1_500_000);
}

#[test]
fn ingestion_config_serde_roundtrip() {
    let cfg = test_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: IngestionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// ProofInput — canonical_bytes + serde
// ===========================================================================

#[test]
fn proof_input_canonical_bytes_deterministic() {
    let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
    let p2 = make_default_proof(ProofType::PlasCapabilityWitness);
    assert_eq!(p1.canonical_bytes(), p2.canonical_bytes());
}

#[test]
fn proof_input_canonical_bytes_differ_by_type() {
    let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
    let p2 = make_default_proof(ProofType::IfcFlowProof);
    assert_ne!(p1.canonical_bytes(), p2.canonical_bytes());
}

#[test]
fn proof_input_serde_roundtrip() {
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let json = serde_json::to_string(&proof).unwrap();
    let restored: ProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, restored);
}

// ===========================================================================
// create_proof_input helper
// ===========================================================================

#[test]
fn create_proof_input_derives_id() {
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"payload",
        &test_key(),
    )
    .unwrap();

    assert!(!proof.proof_id.as_bytes().iter().all(|&b| b == 0));
    assert_eq!(proof.proof_type, ProofType::PlasCapabilityWitness);
    assert_eq!(proof.proof_epoch, test_epoch());
    assert_eq!(proof.linked_policy_id, "policy-001");
}

#[test]
fn create_proof_input_deterministic_id() {
    let p1 = create_proof_input(
        ProofType::IfcFlowProof,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"same",
        &test_key(),
    )
    .unwrap();
    let p2 = create_proof_input(
        ProofType::IfcFlowProof,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"same",
        &test_key(),
    )
    .unwrap();
    assert_eq!(p1.proof_id, p2.proof_id);
}

#[test]
fn create_proof_input_different_payload_different_id() {
    let p1 = create_proof_input(
        ProofType::ReplaySequenceMotif,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"aaa",
        &test_key(),
    )
    .unwrap();
    let p2 = create_proof_input(
        ProofType::ReplaySequenceMotif,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"bbb",
        &test_key(),
    )
    .unwrap();
    assert_ne!(p1.proof_id, p2.proof_id);
}

#[test]
fn create_proof_input_signs_with_key() {
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    assert!(!proof.issuer_signature.is_empty());
}

// ===========================================================================
// ProofIngestionEngine — construction
// ===========================================================================

#[test]
fn engine_starts_empty() {
    let engine = test_engine();
    assert_eq!(engine.current_epoch(), test_epoch());
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
    assert!(engine.receipts().is_empty());
    assert!(engine.events().is_empty());
    assert!(!engine.is_conservative_mode());
}

// ===========================================================================
// Proof ingestion — PLAS
// ===========================================================================

#[test]
fn ingest_plas_generates_two_hypotheses() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    assert_eq!(hypotheses.len(), 2);

    let kinds: BTreeSet<_> = hypotheses.iter().map(|h| h.kind.clone()).collect();
    assert!(kinds.contains(&HypothesisKind::DeadCodeElimination));
    assert!(kinds.contains(&HypothesisKind::DispatchSpecialization));
}

#[test]
fn ingest_plas_dce_hypothesis_properties() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    let dce = hypotheses
        .iter()
        .find(|h| h.kind == HypothesisKind::DeadCodeElimination)
        .unwrap();

    assert!(dce.source_proof_ids.contains(&proof_id));
    assert_eq!(dce.risk, RiskLevel::Low);
    assert_eq!(dce.validity_epoch, test_epoch());
    assert_eq!(dce.expected_speedup_millionths, 1_200_000);
}

#[test]
fn ingest_plas_dispatch_hypothesis_properties() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    let ds = hypotheses
        .iter()
        .find(|h| h.kind == HypothesisKind::DispatchSpecialization)
        .unwrap();

    assert_eq!(ds.risk, RiskLevel::Medium);
    assert_eq!(ds.expected_speedup_millionths, 1_200_000);
}

// ===========================================================================
// Proof ingestion — IFC
// ===========================================================================

#[test]
fn ingest_ifc_generates_one_hypothesis() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    assert_eq!(hypotheses.len(), 1);
    assert_eq!(hypotheses[0].kind, HypothesisKind::FlowCheckElision);
    assert_eq!(hypotheses[0].risk, RiskLevel::High);
    assert_eq!(hypotheses[0].expected_speedup_millionths, 1_100_000);
}

// ===========================================================================
// Proof ingestion — Replay
// ===========================================================================

#[test]
fn ingest_replay_generates_one_hypothesis() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    assert_eq!(hypotheses.len(), 1);
    assert_eq!(hypotheses[0].kind, HypothesisKind::SuperinstructionFusion);
    assert_eq!(hypotheses[0].risk, RiskLevel::Medium);
    assert_eq!(hypotheses[0].expected_speedup_millionths, 1_500_000);
}

// ===========================================================================
// Proof ingestion — all three accumulate
// ===========================================================================

#[test]
fn multiple_proofs_accumulate() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");

    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();
    engine.ingest_proof(p3, 1000).unwrap();

    assert_eq!(engine.active_proofs().len(), 3);
    assert_eq!(engine.active_hypotheses().len(), 4); // 2 + 1 + 1
}

// ===========================================================================
// Validation failures
// ===========================================================================

#[test]
fn reject_duplicate_proof() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof.clone(), 1000).unwrap();

    let err = engine.ingest_proof(proof, 2000).unwrap_err();
    match err {
        IngestionError::ValidationFailed { status, .. } => {
            assert!(matches!(status, ProofValidationStatus::Duplicate { .. }));
        }
        other => panic!("expected ValidationFailed, got {other:?}"),
    }
}

#[test]
fn reject_stale_epoch_proof() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::IfcFlowProof,
        SecurityEpoch::from_raw(50), // stale
        0,
        0,
        "policy-001",
        b"data",
        &test_key(),
    )
    .unwrap();

    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    match err {
        IngestionError::ValidationFailed { status, .. } => {
            assert!(matches!(status, ProofValidationStatus::EpochStale { .. }));
        }
        other => panic!("expected ValidationFailed with EpochStale, got {other:?}"),
    }
}

#[test]
fn reject_expired_proof() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        500, // expires at ns=500
        "policy-001",
        b"data",
        &test_key(),
    )
    .unwrap();

    let err = engine.ingest_proof(proof, 1000).unwrap_err(); // current_ns=1000 > 500
    match err {
        IngestionError::ValidationFailed { status, .. } => {
            assert!(matches!(status, ProofValidationStatus::Expired { .. }));
        }
        other => panic!("expected ValidationFailed with Expired, got {other:?}"),
    }
}

#[test]
fn reject_policy_mismatch_proof() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "wrong-policy",
        b"data",
        &test_key(),
    )
    .unwrap();

    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    match err {
        IngestionError::ValidationFailed { status, .. } => {
            assert!(matches!(
                status,
                ProofValidationStatus::PolicyMismatch { .. }
            ));
        }
        other => panic!("expected ValidationFailed with PolicyMismatch, got {other:?}"),
    }
}

#[test]
fn reject_bad_signature_proof() {
    let mut engine = test_engine();
    let mut proof = make_default_proof(ProofType::PlasCapabilityWitness);
    proof.issuer_signature = vec![0u8; 32]; // corrupted

    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    match err {
        IngestionError::ValidationFailed { status, .. } => {
            assert_eq!(status, ProofValidationStatus::SignatureInvalid);
        }
        other => panic!("expected ValidationFailed with SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn proof_with_zero_validity_end_never_expires() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0, // unbounded
        "policy-001",
        b"test",
        &test_key(),
    )
    .unwrap();

    let result = engine.ingest_proof(proof, u64::MAX / 2);
    assert!(result.is_ok());
}

#[test]
fn empty_active_policy_accepts_any_policy() {
    let mut engine = ProofIngestionEngine::new(
        test_epoch(),
        IngestionConfig {
            active_policy_id: String::new(),
            signing_key: test_key(),
            ..IngestionConfig::default()
        },
    );

    let proof = create_proof_input(
        ProofType::IfcFlowProof,
        test_epoch(),
        0,
        0,
        "any-policy",
        b"data",
        &test_key(),
    )
    .unwrap();

    assert!(engine.ingest_proof(proof, 1000).is_ok());
}

// ===========================================================================
// set_active_policy
// ===========================================================================

#[test]
fn set_active_policy_changes_validation() {
    let mut engine = test_engine();
    engine.set_active_policy("new-policy");

    // Old policy should be rejected.
    let proof = make_proof(ProofType::PlasCapabilityWitness, b"data", "policy-001");
    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::PolicyMismatch { .. },
            ..
        }
    ));

    // New policy should be accepted.
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "new-policy",
        b"data2",
        &test_key(),
    )
    .unwrap();
    assert!(engine.ingest_proof(proof, 1000).is_ok());
}

// ===========================================================================
// Epoch transitions
// ===========================================================================

#[test]
fn advance_epoch_invalidates_stale_proofs() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();

    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
    assert_eq!(invalidated, 3); // 2 plas + 1 ifc
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
}

#[test]
fn advance_epoch_updates_current_epoch() {
    let mut engine = test_engine();
    engine.advance_epoch(SecurityEpoch::from_raw(200), 5000);
    assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(200));
}

#[test]
fn advance_epoch_with_no_proofs_returns_zero() {
    let mut engine = test_engine();
    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
    assert_eq!(invalidated, 0);
}

// ===========================================================================
// Targeted invalidation
// ===========================================================================

#[test]
fn invalidate_proof_removes_proof_and_hypotheses() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    engine.ingest_proof(proof, 1000).unwrap();

    assert_eq!(engine.active_proofs().len(), 1);
    assert_eq!(engine.active_hypotheses().len(), 2);

    let count = engine.invalidate_proof(&proof_id, "compromised", 2000);
    assert_eq!(count, 2); // 2 hypotheses
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
}

#[test]
fn invalidate_nonexistent_proof_returns_zero() {
    let mut engine = test_engine();
    let count = engine.invalidate_proof(&fake_id(), "gone", 1000);
    assert_eq!(count, 0);
}

#[test]
fn invalidate_proof_leaves_other_proofs_intact() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    let p1_id = p1.proof_id.clone();
    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();

    engine.invalidate_proof(&p1_id, "reason", 2000);
    assert_eq!(engine.active_proofs().len(), 1);
    assert_eq!(engine.active_hypotheses().len(), 1); // only IFC remains
}

// ===========================================================================
// Churn dampening
// ===========================================================================

#[test]
fn churn_triggers_conservative_mode() {
    let mut engine = ProofIngestionEngine::new(
        test_epoch(),
        IngestionConfig {
            active_policy_id: "policy-001".to_string(),
            signing_key: test_key(),
            churn_threshold: 3,
            churn_window_ns: 10_000,
            ..IngestionConfig::default()
        },
    );

    // Ingest and invalidate enough proofs to trigger conservative mode.
    for i in 0u8..3 {
        let proof = make_proof(ProofType::PlasCapabilityWitness, &[i, i, i], "policy-001");
        let pid = proof.proof_id.clone();
        engine.ingest_proof(proof, 1000).unwrap();
        engine.invalidate_proof(&pid, "churn", 1000 + u64::from(i));
    }

    assert!(engine.is_conservative_mode());
}

#[test]
fn churn_window_expiry_clears_conservative_mode() {
    let mut engine = ProofIngestionEngine::new(
        test_epoch(),
        IngestionConfig {
            active_policy_id: "policy-001".to_string(),
            signing_key: test_key(),
            churn_threshold: 2,
            churn_window_ns: 1000,
            ..IngestionConfig::default()
        },
    );

    // Trigger conservative mode.
    for i in 0u8..2 {
        let proof = make_proof(
            ProofType::PlasCapabilityWitness,
            &[i, i, i, i],
            "policy-001",
        );
        let pid = proof.proof_id.clone();
        engine.ingest_proof(proof, 100).unwrap();
        engine.invalidate_proof(&pid, "churn", 100 + u64::from(i));
    }
    assert!(engine.is_conservative_mode());

    // Advance epoch far in the future — window expired.
    // Need to cause an invalidation event to trigger update_churn_state.
    let proof = make_proof(ProofType::IfcFlowProof, b"late", "policy-001");
    let pid = proof.proof_id.clone();
    engine.ingest_proof(proof, 5000).unwrap();
    engine.invalidate_proof(&pid, "late", 5000);

    // The old timestamps (100, 101) are now outside the 1000ns window.
    assert!(!engine.is_conservative_mode());
}

// ===========================================================================
// Specialization receipt emission
// ===========================================================================

#[test]
fn emit_receipt_success() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();
    let hyp_id = hypotheses[0].hypothesis_id.clone();

    let receipt = engine
        .emit_receipt(
            &hyp_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();

    assert_eq!(receipt.hypothesis_id, hyp_id);
    assert_eq!(receipt.activation_stage, ActivationStageLocal::Shadow);
    assert_eq!(receipt.epoch, test_epoch());
    assert!(!receipt.signature.is_empty());
    assert_eq!(engine.receipts().len(), 1);
}

#[test]
fn emit_receipt_for_each_activation_stage() {
    let mut engine = test_engine();
    let stages = [
        ActivationStageLocal::Shadow,
        ActivationStageLocal::Canary,
        ActivationStageLocal::Ramp,
        ActivationStageLocal::Default,
    ];

    for (i, stage) in stages.iter().enumerate() {
        let proof = make_proof(ProofType::IfcFlowProof, &[i as u8, 0xAA], "policy-001");
        let hyps = engine.ingest_proof(proof, 1000).unwrap();

        let receipt = engine
            .emit_receipt(
                &hyps[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                *stage,
                2000 + i as u64,
            )
            .unwrap();

        assert_eq!(receipt.activation_stage, *stage);
    }
    assert_eq!(engine.receipts().len(), 4);
}

#[test]
fn emit_receipt_fails_for_unknown_hypothesis() {
    let mut engine = test_engine();
    let err = engine
        .emit_receipt(
            &fake_id(),
            ContentHash::compute(b"a"),
            ContentHash::compute(b"b"),
            ContentHash::compute(b"c"),
            ActivationStageLocal::Default,
            1000,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        IngestionError::HypothesisGenerationFailed { .. }
    ));
}

#[test]
fn receipt_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

    let receipt = engine
        .emit_receipt(
            &hypotheses[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Canary,
            2000,
        )
        .unwrap();

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: SpecializationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// ===========================================================================
// hypotheses_for_proof / hypotheses_by_kind
// ===========================================================================

#[test]
fn hypotheses_for_proof_returns_matching() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    engine.ingest_proof(proof, 1000).unwrap();

    let hyps = engine.hypotheses_for_proof(&proof_id);
    assert_eq!(hyps.len(), 2);
}

#[test]
fn hypotheses_for_unknown_proof_returns_empty() {
    let engine = test_engine();
    let hyps = engine.hypotheses_for_proof(&fake_id());
    assert!(hyps.is_empty());
}

#[test]
fn hypotheses_by_kind_filters_correctly() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");
    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();
    engine.ingest_proof(p3, 1000).unwrap();

    assert_eq!(
        engine
            .hypotheses_by_kind(&HypothesisKind::DeadCodeElimination)
            .len(),
        1
    );
    assert_eq!(
        engine
            .hypotheses_by_kind(&HypothesisKind::DispatchSpecialization)
            .len(),
        1
    );
    assert_eq!(
        engine
            .hypotheses_by_kind(&HypothesisKind::FlowCheckElision)
            .len(),
        1
    );
    assert_eq!(
        engine
            .hypotheses_by_kind(&HypothesisKind::SuperinstructionFusion)
            .len(),
        1
    );
}

// ===========================================================================
// OptimizerHypothesis — canonical_bytes + serde
// ===========================================================================

#[test]
fn hypothesis_canonical_bytes_deterministic() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();

    let bytes1 = hyps[0].canonical_bytes();
    let bytes2 = hyps[0].canonical_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn hypothesis_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();

    let json = serde_json::to_string(&hyps[0]).unwrap();
    let restored: OptimizerHypothesis = serde_json::from_str(&json).unwrap();
    assert_eq!(hyps[0], restored);
}

// ===========================================================================
// Audit events
// ===========================================================================

#[test]
fn events_have_monotonic_sequence() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();

    for (i, event) in engine.events().iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

#[test]
fn events_record_epoch() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();

    for event in engine.events() {
        assert_eq!(event.epoch, test_epoch());
    }
}

#[test]
fn ingestion_produces_submitted_and_validated_events() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    engine.ingest_proof(proof, 1000).unwrap();

    let types: Vec<_> = engine
        .events()
        .iter()
        .map(|e| std::mem::discriminant(&e.event_type))
        .collect();

    // ProofSubmitted, ProofValidated, HypothesisGenerated
    assert!(types.len() >= 3);
}

#[test]
fn ingestion_event_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();

    let event = &engine.events()[0];
    let json = serde_json::to_string(event).unwrap();
    let restored: IngestionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*event, restored);
}

#[test]
fn epoch_advance_produces_invalidation_events() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();

    let pre_events = engine.events().len();
    engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
    let post_events = engine.events().len();

    // Should have hypothesis invalidation and proof invalidation events.
    assert!(post_events > pre_events);
}

#[test]
fn receipt_emission_produces_event() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();

    let pre_events = engine.events().len();
    engine
        .emit_receipt(
            &hyps[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();

    let last = engine.events().last().unwrap();
    assert!(matches!(
        last.event_type,
        IngestionEventType::SpecializationReceiptEmitted { .. }
    ));
    assert!(engine.events().len() > pre_events);
}

// ===========================================================================
// IngestionEventType — serde roundtrip
// ===========================================================================

#[test]
fn ingestion_event_type_serde_all_variants() {
    let fid = fake_id();
    let variants: Vec<IngestionEventType> = vec![
        IngestionEventType::ProofSubmitted {
            proof_id: fid.clone(),
            proof_type: ProofType::PlasCapabilityWitness,
        },
        IngestionEventType::ProofValidated {
            proof_id: fid.clone(),
            status: ProofValidationStatus::Accepted,
        },
        IngestionEventType::HypothesisGenerated {
            hypothesis_id: fid.clone(),
            kind: HypothesisKind::DeadCodeElimination,
            source_proof_count: 1,
        },
        IngestionEventType::ProofInvalidated {
            proof_id: fid.clone(),
            reason: "test".to_string(),
        },
        IngestionEventType::HypothesisInvalidated {
            hypothesis_id: fid.clone(),
            reason: "test".to_string(),
        },
        IngestionEventType::SpecializationReceiptEmitted {
            receipt_id: fid.clone(),
            hypothesis_id: fid.clone(),
        },
    ];

    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: IngestionEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// Stress test — many proofs + epoch + receipts
// ===========================================================================

#[test]
fn stress_30_proofs_with_epoch_and_receipts() {
    let mut engine = test_engine();
    let types = [
        ProofType::PlasCapabilityWitness,
        ProofType::IfcFlowProof,
        ProofType::ReplaySequenceMotif,
    ];

    let mut all_hyp_ids = Vec::new();

    for i in 0u32..30 {
        let pt = types[(i % 3) as usize];
        let payload = format!("payload-{i}");
        let proof = make_proof(pt, payload.as_bytes(), "policy-001");
        let hyps = engine.ingest_proof(proof, 1000 + u64::from(i)).unwrap();
        all_hyp_ids.extend(hyps.iter().map(|h| h.hypothesis_id.clone()));
    }

    // 30 proofs: 10 PLAS (2 each) + 10 IFC (1 each) + 10 Replay (1 each) = 40
    assert_eq!(engine.active_proofs().len(), 30);
    assert_eq!(engine.active_hypotheses().len(), 40);

    // Emit receipts for the first 5 hypotheses.
    for (i, hid) in all_hyp_ids.iter().take(5).enumerate() {
        engine
            .emit_receipt(
                hid,
                ContentHash::compute(format!("tw-{i}").as_bytes()),
                ContentHash::compute(format!("ee-{i}").as_bytes()),
                ContentHash::compute(format!("rt-{i}").as_bytes()),
                ActivationStageLocal::Shadow,
                2000 + i as u64,
            )
            .unwrap();
    }
    assert_eq!(engine.receipts().len(), 5);

    // Advance epoch — all proofs invalidated.
    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 3000);
    assert_eq!(invalidated, 40);
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
    // Receipts survive epoch transitions.
    assert_eq!(engine.receipts().len(), 5);

    // Events monotonic.
    for (i, event) in engine.events().iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

// ===========================================================================
// Proof type → hypothesis kind mapping exhaustive
// ===========================================================================

#[test]
fn all_proof_type_to_hypothesis_kind_mapping() {
    let mut engine = test_engine();
    let mapping: Vec<(ProofType, Vec<HypothesisKind>)> = vec![
        (
            ProofType::PlasCapabilityWitness,
            vec![
                HypothesisKind::DeadCodeElimination,
                HypothesisKind::DispatchSpecialization,
            ],
        ),
        (
            ProofType::IfcFlowProof,
            vec![HypothesisKind::FlowCheckElision],
        ),
        (
            ProofType::ReplaySequenceMotif,
            vec![HypothesisKind::SuperinstructionFusion],
        ),
    ];

    for (i, (pt, expected_kinds)) in mapping.iter().enumerate() {
        let payload = format!("mapping-{i}");
        let proof = make_proof(*pt, payload.as_bytes(), "policy-001");
        let hyps = engine.ingest_proof(proof, 1000).unwrap();
        let actual_kinds: BTreeSet<_> = hyps.iter().map(|h| h.kind.clone()).collect();
        let expected: BTreeSet<_> = expected_kinds.iter().cloned().collect();
        assert_eq!(actual_kinds, expected, "mapping mismatch for {pt}");
    }
}

// ===========================================================================
// Receipt properties
// ===========================================================================

#[test]
fn receipt_links_back_to_proof_ids() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    let hyps = engine.ingest_proof(proof, 1000).unwrap();

    let receipt = engine
        .emit_receipt(
            &hyps[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();

    assert!(receipt.proof_input_ids.contains(&proof_id));
}

#[test]
fn receipt_id_is_deterministic_for_same_hypothesis_and_timestamp() {
    // Build two separate engines and emit at same timestamp.
    let mut e1 = test_engine();
    let mut e2 = test_engine();

    let proof1 = make_default_proof(ProofType::IfcFlowProof);
    let proof2 = make_default_proof(ProofType::IfcFlowProof);

    let h1 = e1.ingest_proof(proof1, 1000).unwrap();
    let h2 = e2.ingest_proof(proof2, 1000).unwrap();

    let r1 = e1
        .emit_receipt(
            &h1[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();
    let r2 = e2
        .emit_receipt(
            &h2[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();

    assert_eq!(r1.receipt_id, r2.receipt_id);
}
