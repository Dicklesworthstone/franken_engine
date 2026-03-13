//! Enrichment integration tests for the `proof_ingestion` module.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior, edge cases, deterministic hash behavior, builder patterns,
//! epoch transitions, churn dampening, receipt emission, and canonical bytes.

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_ingestion::*;
use frankenengine_engine::proof_schema::OptimizationClass;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
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
        ..Default::default()
    }
}

fn test_engine() -> ProofIngestionEngine {
    ProofIngestionEngine::new(test_epoch(), test_config())
}

fn make_proof(proof_type: ProofType, payload: &[u8], policy_id: &str) -> ProofInput {
    create_proof_input(
        proof_type,
        test_epoch(),
        0,
        0,
        policy_id,
        payload,
        &test_key(),
    )
    .expect("proof creation should succeed")
}

fn make_default_proof(proof_type: ProofType) -> ProofInput {
    make_proof(proof_type, b"test-payload", "policy-001")
}

fn fake_id(tag: &[u8]) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &SchemaId::from_definition(b"fake"),
        tag,
    )
    .unwrap()
}

// ===========================================================================
// Display uniqueness tests
// ===========================================================================

#[test]
fn enrichment_proof_type_display_uniqueness() {
    let variants = [
        ProofType::PlasCapabilityWitness,
        ProofType::IfcFlowProof,
        ProofType::ReplaySequenceMotif,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_hypothesis_kind_display_uniqueness() {
    let variants = [
        HypothesisKind::DeadCodeElimination,
        HypothesisKind::DispatchSpecialization,
        HypothesisKind::FlowCheckElision,
        HypothesisKind::SuperinstructionFusion,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_risk_level_display_uniqueness() {
    let variants = [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_activation_stage_display_uniqueness() {
    let variants = [
        ActivationStageLocal::Shadow,
        ActivationStageLocal::Canary,
        ActivationStageLocal::Ramp,
        ActivationStageLocal::Default,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_ingestion_error_display_uniqueness_across_variants() {
    let id = fake_id(b"err-uniq");
    let errors = [
        IngestionError::ValidationFailed {
            proof_id: id.clone(),
            status: ProofValidationStatus::SignatureInvalid,
        },
        IngestionError::NoHypothesesGenerated {
            proof_id: id.clone(),
        },
        IngestionError::HypothesisGenerationFailed {
            reason: "reason-a".to_string(),
        },
        IngestionError::UnsupportedProofType {
            proof_type: ProofType::PlasCapabilityWitness,
        },
        IngestionError::IdDerivation("id-err".to_string()),
        IngestionError::ConservativeModeActive {
            invalidation_count: 5,
            window_ns: 1000,
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn enrichment_proof_validation_status_display_uniqueness() {
    let id = fake_id(b"status-uniq");
    let statuses = [
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
            proof_policy: "pol-x".to_string(),
            active_policy: "pol-y".to_string(),
        },
        ProofValidationStatus::SemanticCheckFailed {
            reason: "bad".to_string(),
        },
        ProofValidationStatus::Duplicate { existing_id: id },
    ];
    let set: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), statuses.len());
}

// ===========================================================================
// Serde roundtrip tests
// ===========================================================================

#[test]
fn enrichment_proof_type_serde_roundtrip_all() {
    for pt in [
        ProofType::PlasCapabilityWitness,
        ProofType::IfcFlowProof,
        ProofType::ReplaySequenceMotif,
    ] {
        let json = serde_json::to_string(&pt).unwrap();
        let restored: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, pt);
    }
}

#[test]
fn enrichment_hypothesis_kind_serde_roundtrip_all() {
    for hk in [
        HypothesisKind::DeadCodeElimination,
        HypothesisKind::DispatchSpecialization,
        HypothesisKind::FlowCheckElision,
        HypothesisKind::SuperinstructionFusion,
    ] {
        let json = serde_json::to_string(&hk).unwrap();
        let restored: HypothesisKind = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, hk);
    }
}

#[test]
fn enrichment_risk_level_serde_roundtrip_all() {
    for rl in [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High] {
        let json = serde_json::to_string(&rl).unwrap();
        let restored: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, rl);
    }
}

#[test]
fn enrichment_activation_stage_serde_roundtrip_all() {
    for stage in [
        ActivationStageLocal::Shadow,
        ActivationStageLocal::Canary,
        ActivationStageLocal::Ramp,
        ActivationStageLocal::Default,
    ] {
        let json = serde_json::to_string(&stage).unwrap();
        let restored: ActivationStageLocal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, stage);
    }
}

#[test]
fn enrichment_proof_input_serde_roundtrip() {
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let json = serde_json::to_string(&proof).unwrap();
    let restored: ProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, restored);
}

#[test]
fn enrichment_optimizer_hypothesis_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hypotheses = engine.ingest_proof(proof, 1000).unwrap();
    let json = serde_json::to_string(&hypotheses[0]).unwrap();
    let restored: OptimizerHypothesis = serde_json::from_str(&json).unwrap();
    assert_eq!(hypotheses[0], restored);
}

#[test]
fn enrichment_specialization_receipt_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let receipt = engine
        .emit_receipt(
            &hyps[0].hypothesis_id,
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

#[test]
fn enrichment_ingestion_event_serde_roundtrip() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    for event in engine.events() {
        let json = serde_json::to_string(event).unwrap();
        let restored: IngestionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, restored);
    }
}

#[test]
fn enrichment_ingestion_config_serde_roundtrip() {
    let cfg = test_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: IngestionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, cfg);
}

#[test]
fn enrichment_ingestion_config_default_serde_roundtrip() {
    let cfg = IngestionConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: IngestionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, cfg);
}

#[test]
fn enrichment_ingestion_error_serde_roundtrip_all_variants() {
    let id = fake_id(b"err-serde");
    let errors = vec![
        IngestionError::ValidationFailed {
            proof_id: id.clone(),
            status: ProofValidationStatus::Accepted,
        },
        IngestionError::NoHypothesesGenerated {
            proof_id: id.clone(),
        },
        IngestionError::HypothesisGenerationFailed {
            reason: "test-reason".to_string(),
        },
        IngestionError::UnsupportedProofType {
            proof_type: ProofType::ReplaySequenceMotif,
        },
        IngestionError::IdDerivation("derivation-msg".to_string()),
        IngestionError::ConservativeModeActive {
            invalidation_count: 42,
            window_ns: 60_000_000_000,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: IngestionError = serde_json::from_str(&json).unwrap();
        assert_eq!(&restored, err);
    }
}

#[test]
fn enrichment_proof_validation_status_serde_roundtrip_all_variants() {
    let id = fake_id(b"pvs-serde");
    let statuses = vec![
        ProofValidationStatus::Accepted,
        ProofValidationStatus::SignatureInvalid,
        ProofValidationStatus::EpochStale {
            proof_epoch: SecurityEpoch::from_raw(10),
            current_epoch: SecurityEpoch::from_raw(20),
        },
        ProofValidationStatus::Expired {
            validity_end_ns: 500,
            current_ns: 1000,
        },
        ProofValidationStatus::PolicyMismatch {
            proof_policy: "old-pol".to_string(),
            active_policy: "new-pol".to_string(),
        },
        ProofValidationStatus::SemanticCheckFailed {
            reason: "unsupported".to_string(),
        },
        ProofValidationStatus::Duplicate { existing_id: id },
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let restored: ProofValidationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&restored, s);
    }
}

#[test]
fn enrichment_ingestion_event_type_serde_all_variants() {
    let id = fake_id(b"iet-serde");
    let variants = vec![
        IngestionEventType::ProofSubmitted {
            proof_id: id.clone(),
            proof_type: ProofType::IfcFlowProof,
        },
        IngestionEventType::ProofValidated {
            proof_id: id.clone(),
            status: ProofValidationStatus::Accepted,
        },
        IngestionEventType::HypothesisGenerated {
            hypothesis_id: id.clone(),
            kind: HypothesisKind::SuperinstructionFusion,
            source_proof_count: 3,
        },
        IngestionEventType::ProofInvalidated {
            proof_id: id.clone(),
            reason: "epoch change".to_string(),
        },
        IngestionEventType::HypothesisInvalidated {
            hypothesis_id: id.clone(),
            reason: "source revoked".to_string(),
        },
        IngestionEventType::SpecializationReceiptEmitted {
            receipt_id: id.clone(),
            hypothesis_id: id.clone(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: IngestionEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(&restored, v);
    }
}

#[test]
fn enrichment_empty_engine_serde_roundtrip() {
    let engine = test_engine();
    let json = serde_json::to_string(&engine).unwrap();
    let restored: ProofIngestionEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.current_epoch(), test_epoch());
    assert!(restored.active_proofs().is_empty());
    assert!(restored.active_hypotheses().is_empty());
    assert!(restored.receipts().is_empty());
    assert!(restored.events().is_empty());
    assert!(!restored.is_conservative_mode());
}

// ===========================================================================
// Display format content tests
// ===========================================================================

#[test]
fn enrichment_proof_type_display_exact_strings() {
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
fn enrichment_hypothesis_kind_display_exact_strings() {
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

#[test]
fn enrichment_risk_level_display_exact_strings() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
}

#[test]
fn enrichment_activation_stage_display_exact_strings() {
    assert_eq!(ActivationStageLocal::Shadow.to_string(), "shadow");
    assert_eq!(ActivationStageLocal::Canary.to_string(), "canary");
    assert_eq!(ActivationStageLocal::Ramp.to_string(), "ramp");
    assert_eq!(ActivationStageLocal::Default.to_string(), "default");
}

#[test]
fn enrichment_ingestion_error_display_conservative_mode_content() {
    let err = IngestionError::ConservativeModeActive {
        invalidation_count: 15,
        window_ns: 60_000,
    };
    let s = err.to_string();
    assert!(s.contains("15"));
    assert!(s.contains("60000"));
    assert!(s.contains("conservative mode"));
}

#[test]
fn enrichment_ingestion_error_display_unsupported_type_content() {
    let err = IngestionError::UnsupportedProofType {
        proof_type: ProofType::IfcFlowProof,
    };
    assert!(err.to_string().contains("ifc-flow-proof"));
}

#[test]
fn enrichment_ingestion_error_display_id_derivation_content() {
    let err = IngestionError::IdDerivation("something went wrong".to_string());
    assert!(err.to_string().contains("something went wrong"));
    assert!(err.to_string().contains("id derivation"));
}

#[test]
fn enrichment_validation_status_display_epoch_stale_content() {
    let s = ProofValidationStatus::EpochStale {
        proof_epoch: SecurityEpoch::from_raw(5),
        current_epoch: SecurityEpoch::from_raw(10),
    };
    let display = s.to_string();
    assert!(display.contains("epoch-stale"));
    assert!(display.contains("5"));
    assert!(display.contains("10"));
}

#[test]
fn enrichment_validation_status_display_policy_mismatch_content() {
    let s = ProofValidationStatus::PolicyMismatch {
        proof_policy: "alpha".to_string(),
        active_policy: "beta".to_string(),
    };
    let display = s.to_string();
    assert!(display.contains("policy-mismatch"));
    assert!(display.contains("alpha"));
    assert!(display.contains("beta"));
}

#[test]
fn enrichment_validation_status_display_expired_content() {
    let s = ProofValidationStatus::Expired {
        validity_end_ns: 500,
        current_ns: 999,
    };
    let display = s.to_string();
    assert!(display.contains("expired"));
    assert!(display.contains("500"));
    assert!(display.contains("999"));
}

#[test]
fn enrichment_validation_status_display_semantic_check_content() {
    let s = ProofValidationStatus::SemanticCheckFailed {
        reason: "payload malformed".to_string(),
    };
    let display = s.to_string();
    assert!(display.contains("semantic-check-failed"));
    assert!(display.contains("payload malformed"));
}

// ===========================================================================
// Ordering tests
// ===========================================================================

#[test]
fn enrichment_proof_type_ordering_matches_declaration() {
    assert!(ProofType::PlasCapabilityWitness < ProofType::IfcFlowProof);
    assert!(ProofType::IfcFlowProof < ProofType::ReplaySequenceMotif);
}

#[test]
fn enrichment_hypothesis_kind_ordering_matches_declaration() {
    assert!(HypothesisKind::DeadCodeElimination < HypothesisKind::DispatchSpecialization);
    assert!(HypothesisKind::DispatchSpecialization < HypothesisKind::FlowCheckElision);
    assert!(HypothesisKind::FlowCheckElision < HypothesisKind::SuperinstructionFusion);
}

#[test]
fn enrichment_risk_level_ordering_low_medium_high() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
}

#[test]
fn enrichment_activation_stage_ordering_shadow_to_default() {
    assert!(ActivationStageLocal::Shadow < ActivationStageLocal::Canary);
    assert!(ActivationStageLocal::Canary < ActivationStageLocal::Ramp);
    assert!(ActivationStageLocal::Ramp < ActivationStageLocal::Default);
}

// ===========================================================================
// IngestionConfig default values
// ===========================================================================

#[test]
fn enrichment_config_default_values() {
    let cfg = IngestionConfig::default();
    assert!(cfg.active_policy_id.is_empty());
    assert_eq!(cfg.signing_key, [0u8; 32]);
    assert_eq!(cfg.churn_threshold, 10);
    assert_eq!(cfg.churn_window_ns, 60_000_000_000);
    assert_eq!(cfg.plas_speedup_estimate, 1_200_000);
    assert_eq!(cfg.ifc_speedup_estimate, 1_100_000);
    assert_eq!(cfg.replay_speedup_estimate, 1_500_000);
}

// ===========================================================================
// Proof creation and deterministic ID derivation
// ===========================================================================

#[test]
fn enrichment_create_proof_input_deterministic_id() {
    let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
    let p2 = make_default_proof(ProofType::PlasCapabilityWitness);
    assert_eq!(p1.proof_id, p2.proof_id);
    assert_eq!(p1.issuer_signature, p2.issuer_signature);
    assert_eq!(p1.canonical_hash, p2.canonical_hash);
}

#[test]
fn enrichment_different_proof_types_yield_different_ids() {
    let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
    let p2 = make_default_proof(ProofType::IfcFlowProof);
    let p3 = make_default_proof(ProofType::ReplaySequenceMotif);
    let ids: BTreeSet<_> = [&p1.proof_id, &p2.proof_id, &p3.proof_id]
        .into_iter()
        .collect();
    assert_eq!(ids.len(), 3);
}

#[test]
fn enrichment_different_payloads_yield_different_ids() {
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"alpha", "policy-001");
    let p2 = make_proof(ProofType::PlasCapabilityWitness, b"bravo", "policy-001");
    assert_ne!(p1.proof_id, p2.proof_id);
    assert_ne!(p1.canonical_hash, p2.canonical_hash);
}

#[test]
fn enrichment_different_policies_yield_different_ids() {
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"same", "policy-a");
    let p2 = make_proof(ProofType::PlasCapabilityWitness, b"same", "policy-b");
    assert_ne!(p1.proof_id, p2.proof_id);
}

#[test]
fn enrichment_proof_input_fields_populated_correctly() {
    let proof = create_proof_input(
        ProofType::IfcFlowProof,
        SecurityEpoch::from_raw(42),
        100,
        999,
        "pol-99",
        b"hello-payload",
        &test_key(),
    )
    .unwrap();
    assert_eq!(proof.proof_type, ProofType::IfcFlowProof);
    assert_eq!(proof.proof_epoch, SecurityEpoch::from_raw(42));
    assert_eq!(proof.validity_start_ns, 100);
    assert_eq!(proof.validity_end_ns, 999);
    assert_eq!(proof.linked_policy_id, "pol-99");
    assert_eq!(proof.payload, b"hello-payload");
    assert!(!proof.issuer_signature.is_empty());
}

// ===========================================================================
// Canonical bytes tests
// ===========================================================================

#[test]
fn enrichment_proof_canonical_bytes_deterministic() {
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let b1 = proof.canonical_bytes();
    let b2 = proof.canonical_bytes();
    assert_eq!(b1, b2);
    assert!(!b1.is_empty());
}

#[test]
fn enrichment_proof_canonical_bytes_starts_with_proof_id() {
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let bytes = proof.canonical_bytes();
    assert_eq!(
        &bytes[..proof.proof_id.as_bytes().len()],
        proof.proof_id.as_bytes()
    );
}

#[test]
fn enrichment_proof_canonical_bytes_ends_with_policy_id() {
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let bytes = proof.canonical_bytes();
    assert_eq!(
        &bytes[bytes.len() - proof.linked_policy_id.len()..],
        proof.linked_policy_id.as_bytes()
    );
}

#[test]
fn enrichment_proof_canonical_bytes_different_for_different_types() {
    let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
    let p2 = make_default_proof(ProofType::IfcFlowProof);
    assert_ne!(p1.canonical_bytes(), p2.canonical_bytes());
}

#[test]
fn enrichment_hypothesis_canonical_bytes_deterministic() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let b1 = hyps[0].canonical_bytes();
    let b2 = hyps[0].canonical_bytes();
    assert_eq!(b1, b2);
    assert!(!b1.is_empty());
}

#[test]
fn enrichment_hypothesis_canonical_bytes_includes_source_proof_ids() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id_len = proof.proof_id.as_bytes().len();
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let bytes = hyps[0].canonical_bytes();
    let hid_len = hyps[0].hypothesis_id.as_bytes().len();
    // canonical_bytes must be >= hypothesis_id + at least one source proof id
    assert!(bytes.len() >= hid_len + proof_id_len);
}

// ===========================================================================
// Engine ingestion tests
// ===========================================================================

#[test]
fn enrichment_ingest_plas_generates_two_hypotheses() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps.len(), 2);
    assert_eq!(hyps[0].kind, HypothesisKind::DeadCodeElimination);
    assert_eq!(hyps[1].kind, HypothesisKind::DispatchSpecialization);
}

#[test]
fn enrichment_ingest_ifc_generates_one_hypothesis() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps.len(), 1);
    assert_eq!(hyps[0].kind, HypothesisKind::FlowCheckElision);
}

#[test]
fn enrichment_ingest_replay_generates_one_hypothesis() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps.len(), 1);
    assert_eq!(hyps[0].kind, HypothesisKind::SuperinstructionFusion);
}

#[test]
fn enrichment_plas_hypothesis_risk_and_class() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].risk, RiskLevel::Low);
    assert_eq!(
        hyps[0].optimization_class,
        OptimizationClass::TraceSpecialization
    );
    assert_eq!(hyps[1].risk, RiskLevel::Medium);
    assert_eq!(
        hyps[1].optimization_class,
        OptimizationClass::DevirtualizedHostcallFastPath
    );
}

#[test]
fn enrichment_ifc_hypothesis_risk_and_class() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].risk, RiskLevel::High);
    assert_eq!(
        hyps[0].optimization_class,
        OptimizationClass::LayoutSpecialization
    );
}

#[test]
fn enrichment_replay_hypothesis_risk_and_class() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].risk, RiskLevel::Medium);
    assert_eq!(
        hyps[0].optimization_class,
        OptimizationClass::Superinstruction
    );
}

#[test]
fn enrichment_plas_speedup_matches_config() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    for h in &hyps {
        assert_eq!(h.expected_speedup_millionths, 1_200_000);
    }
}

#[test]
fn enrichment_ifc_speedup_matches_config() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].expected_speedup_millionths, 1_100_000);
}

#[test]
fn enrichment_replay_speedup_matches_config() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].expected_speedup_millionths, 1_500_000);
}

#[test]
fn enrichment_hypothesis_validity_epoch_matches_proof() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    for h in &hyps {
        assert_eq!(h.validity_epoch, test_epoch());
    }
}

#[test]
fn enrichment_hypothesis_derivation_hash_is_content_hash_of_payload() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let expected_hash = ContentHash::compute(&proof.payload);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(hyps[0].derivation_hash, expected_hash);
}

#[test]
fn enrichment_hypothesis_source_proof_ids_contain_proof_id() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    for h in &hyps {
        assert!(h.source_proof_ids.contains(&proof_id));
        assert_eq!(h.source_proof_ids.len(), 1);
    }
}

// ===========================================================================
// Engine state tracking tests
// ===========================================================================

#[test]
fn enrichment_ingested_proof_tracked_in_active_proofs() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    engine.ingest_proof(proof, 1000).unwrap();
    assert!(engine.active_proofs().contains_key(&proof_id));
}

#[test]
fn enrichment_hypotheses_tracked_in_active_hypotheses() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(engine.active_hypotheses().len(), 2);
}

#[test]
fn enrichment_hypotheses_for_proof_returns_correct_set() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    engine.ingest_proof(proof, 1000).unwrap();
    let hyps = engine.hypotheses_for_proof(&proof_id);
    assert_eq!(hyps.len(), 2);
}

#[test]
fn enrichment_hypotheses_for_unknown_proof_returns_empty() {
    let engine = test_engine();
    let id = fake_id(b"unknown-proof");
    assert!(engine.hypotheses_for_proof(&id).is_empty());
}

#[test]
fn enrichment_hypotheses_by_kind_filters_correctly() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"plas-data", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"ifc-data", "policy-001");
    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"replay-data", "policy-001");
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

#[test]
fn enrichment_multiple_proofs_accumulate() {
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
// Validation failure tests
// ===========================================================================

#[test]
fn enrichment_rejects_duplicate_proof() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof.clone(), 1000).unwrap();
    let err = engine.ingest_proof(proof, 2000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::Duplicate { .. },
            ..
        }
    ));
}

#[test]
fn enrichment_rejects_stale_epoch() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        SecurityEpoch::from_raw(50),
        0,
        0,
        "policy-001",
        b"stale",
        &test_key(),
    )
    .unwrap();
    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::EpochStale { .. },
            ..
        }
    ));
}

#[test]
fn enrichment_rejects_expired_proof() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        500,
        "policy-001",
        b"exp",
        &test_key(),
    )
    .unwrap();
    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::Expired { .. },
            ..
        }
    ));
}

#[test]
fn enrichment_rejects_policy_mismatch() {
    let mut engine = test_engine();
    let proof = make_proof(ProofType::PlasCapabilityWitness, b"test", "wrong-policy");
    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::PolicyMismatch { .. },
            ..
        }
    ));
}

#[test]
fn enrichment_rejects_tampered_signature() {
    let mut engine = test_engine();
    let mut proof = make_default_proof(ProofType::PlasCapabilityWitness);
    proof.issuer_signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let err = engine.ingest_proof(proof, 1000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::SignatureInvalid,
            ..
        }
    ));
}

#[test]
fn enrichment_proof_valid_at_exact_expiry_boundary() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        5000,
        "policy-001",
        b"boundary",
        &test_key(),
    )
    .unwrap();
    // current_ns == validity_end_ns => NOT expired (condition is >)
    assert!(engine.ingest_proof(proof, 5000).is_ok());
}

#[test]
fn enrichment_proof_with_zero_validity_end_never_expires() {
    let mut engine = test_engine();
    let proof = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "policy-001",
        b"unbounded",
        &test_key(),
    )
    .unwrap();
    assert!(engine.ingest_proof(proof, u64::MAX / 2).is_ok());
}

#[test]
fn enrichment_empty_active_policy_accepts_any_proof_policy() {
    let mut config = test_config();
    config.active_policy_id = String::new();
    let mut engine = ProofIngestionEngine::new(test_epoch(), config);
    let proof = make_proof(
        ProofType::PlasCapabilityWitness,
        b"xyz",
        "any-random-policy",
    );
    assert!(engine.ingest_proof(proof, 1000).is_ok());
}

#[test]
fn enrichment_set_active_policy_changes_validation() {
    let mut engine = test_engine();
    let proof = make_proof(ProofType::PlasCapabilityWitness, b"before", "policy-001");
    assert!(engine.ingest_proof(proof, 1000).is_ok());

    engine.set_active_policy("policy-002");
    let proof2 = make_proof(ProofType::IfcFlowProof, b"after", "policy-001");
    let err = engine.ingest_proof(proof2, 2000).unwrap_err();
    assert!(matches!(
        err,
        IngestionError::ValidationFailed {
            status: ProofValidationStatus::PolicyMismatch { .. },
            ..
        }
    ));
}

// ===========================================================================
// Epoch transition and invalidation tests
// ===========================================================================

#[test]
fn enrichment_epoch_advance_invalidates_stale_proofs() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    assert_eq!(engine.active_proofs().len(), 1);
    assert_eq!(engine.active_hypotheses().len(), 2);

    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
    assert_eq!(invalidated, 2);
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
}

#[test]
fn enrichment_epoch_advance_preserves_current_epoch_proofs() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    let invalidated = engine.advance_epoch(test_epoch(), 2000);
    assert_eq!(invalidated, 0);
    assert_eq!(engine.active_proofs().len(), 1);
}

#[test]
fn enrichment_epoch_advance_invalidates_all_accumulated_proofs() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");
    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();
    engine.ingest_proof(p3, 1000).unwrap();
    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
    assert_eq!(invalidated, 4); // 2 + 1 + 1
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
}

#[test]
fn enrichment_invalidate_specific_proof() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let proof_id = proof.proof_id.clone();
    engine.ingest_proof(proof, 1000).unwrap();
    let count = engine.invalidate_proof(&proof_id, "revoked", 2000);
    assert_eq!(count, 2);
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
}

#[test]
fn enrichment_invalidate_unknown_proof_returns_zero() {
    let mut engine = test_engine();
    let id = fake_id(b"nonexistent");
    let count = engine.invalidate_proof(&id, "test", 1000);
    assert_eq!(count, 0);
}

#[test]
fn enrichment_invalidation_does_not_affect_other_proofs() {
    let mut engine = test_engine();
    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"keep", "policy-001");
    let p2 = make_proof(ProofType::IfcFlowProof, b"remove", "policy-001");
    let p1_id = p1.proof_id.clone();
    let p2_id = p2.proof_id.clone();
    engine.ingest_proof(p1, 1000).unwrap();
    engine.ingest_proof(p2, 1000).unwrap();

    engine.invalidate_proof(&p2_id, "targeted removal", 2000);
    assert!(engine.active_proofs().contains_key(&p1_id));
    assert!(!engine.active_proofs().contains_key(&p2_id));
    assert_eq!(engine.active_hypotheses().len(), 2); // p1's 2 hypotheses remain
}

// ===========================================================================
// Churn dampening tests
// ===========================================================================

#[test]
fn enrichment_churn_dampening_activates_on_threshold() {
    let mut config = test_config();
    config.churn_threshold = 3;
    config.churn_window_ns = 10_000;
    let mut engine = ProofIngestionEngine::new(test_epoch(), config);

    for i in 0..3 {
        let proof = make_proof(
            ProofType::PlasCapabilityWitness,
            format!("churn-{i}").as_bytes(),
            "policy-001",
        );
        let proof_id = proof.proof_id.clone();
        engine.ingest_proof(proof, 1000 + i * 100).unwrap();
        engine.invalidate_proof(&proof_id, "churn", 1000 + i * 100 + 50);
    }
    assert!(engine.is_conservative_mode());
}

#[test]
fn enrichment_churn_dampening_deactivates_after_window() {
    let mut config = test_config();
    config.churn_threshold = 2;
    config.churn_window_ns = 1000;
    let mut engine = ProofIngestionEngine::new(test_epoch(), config);

    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
    let p1_id = p1.proof_id.clone();
    engine.ingest_proof(p1, 100).unwrap();
    engine.invalidate_proof(&p1_id, "test", 200);

    let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
    let p2_id = p2.proof_id.clone();
    engine.ingest_proof(p2, 300).unwrap();
    engine.invalidate_proof(&p2_id, "test", 400);

    assert!(engine.is_conservative_mode());

    // Ingest and invalidate well past the window
    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");
    let p3_id = p3.proof_id.clone();
    engine.ingest_proof(p3, 5000).unwrap();
    engine.invalidate_proof(&p3_id, "test", 5100);

    assert!(!engine.is_conservative_mode());
}

#[test]
fn enrichment_new_engine_not_in_conservative_mode() {
    let engine = test_engine();
    assert!(!engine.is_conservative_mode());
}

// ===========================================================================
// Specialization receipt tests
// ===========================================================================

#[test]
fn enrichment_emit_receipt_success() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let hyp_id = hyps[0].hypothesis_id.clone();

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
    assert_eq!(receipt.issued_at_ns, 2000);
    assert!(!receipt.signature.is_empty());
    assert_eq!(engine.receipts().len(), 1);
}

#[test]
fn enrichment_emit_receipt_fails_for_unknown_hypothesis() {
    let mut engine = test_engine();
    let id = fake_id(b"no-such-hyp");
    let err = engine
        .emit_receipt(
            &id,
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
fn enrichment_receipt_proof_input_ids_match_hypothesis_sources() {
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
            ActivationStageLocal::Ramp,
            2000,
        )
        .unwrap();
    assert!(receipt.proof_input_ids.contains(&proof_id));
    assert_eq!(receipt.proof_input_ids.len(), 1);
}

#[test]
fn enrichment_receipt_deterministic_id() {
    let mut engine1 = test_engine();
    let proof1 = make_default_proof(ProofType::IfcFlowProof);
    let hyps1 = engine1.ingest_proof(proof1, 1000).unwrap();
    let r1 = engine1
        .emit_receipt(
            &hyps1[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Canary,
            2000,
        )
        .unwrap();

    let mut engine2 = test_engine();
    let proof2 = make_default_proof(ProofType::IfcFlowProof);
    let hyps2 = engine2.ingest_proof(proof2, 1000).unwrap();
    let r2 = engine2
        .emit_receipt(
            &hyps2[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Canary,
            2000,
        )
        .unwrap();

    assert_eq!(r1.receipt_id, r2.receipt_id);
    assert_eq!(r1.signature, r2.signature);
}

#[test]
fn enrichment_multiple_receipts_different_timestamps_different_ids() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::ReplaySequenceMotif);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let hyp_id = hyps[0].hypothesis_id.clone();

    let r1 = engine
        .emit_receipt(
            &hyp_id,
            ContentHash::compute(b"tw1"),
            ContentHash::compute(b"ee1"),
            ContentHash::compute(b"rt1"),
            ActivationStageLocal::Shadow,
            2000,
        )
        .unwrap();

    let r2 = engine
        .emit_receipt(
            &hyp_id,
            ContentHash::compute(b"tw2"),
            ContentHash::compute(b"ee2"),
            ContentHash::compute(b"rt2"),
            ActivationStageLocal::Canary,
            3000,
        )
        .unwrap();

    assert_ne!(r1.receipt_id, r2.receipt_id);
    assert_eq!(engine.receipts().len(), 2);
}

#[test]
fn enrichment_receipt_optimization_class_from_hypothesis() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let receipt = engine
        .emit_receipt(
            &hyps[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Default,
            2000,
        )
        .unwrap();
    assert_eq!(
        receipt.optimization_class,
        OptimizationClass::LayoutSpecialization
    );
}

// ===========================================================================
// Audit event tests
// ===========================================================================

#[test]
fn enrichment_events_have_monotonic_sequence() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    for (i, event) in engine.events().iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

#[test]
fn enrichment_events_record_correct_epoch() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    for event in engine.events() {
        assert_eq!(event.epoch, test_epoch());
    }
}

#[test]
fn enrichment_ingestion_generates_submitted_and_validated_events() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();

    let submitted_count = engine
        .events()
        .iter()
        .filter(|e| matches!(e.event_type, IngestionEventType::ProofSubmitted { .. }))
        .count();
    let validated_count = engine
        .events()
        .iter()
        .filter(|e| matches!(e.event_type, IngestionEventType::ProofValidated { .. }))
        .count();
    let generated_count = engine
        .events()
        .iter()
        .filter(|e| matches!(e.event_type, IngestionEventType::HypothesisGenerated { .. }))
        .count();

    assert_eq!(submitted_count, 1);
    assert_eq!(validated_count, 1);
    assert_eq!(generated_count, 2); // PLAS generates 2 hypotheses
}

#[test]
fn enrichment_epoch_advance_generates_invalidation_events() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::PlasCapabilityWitness);
    engine.ingest_proof(proof, 1000).unwrap();
    engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);

    let hyp_invalidated: Vec<_> = engine
        .events()
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                IngestionEventType::HypothesisInvalidated { .. }
            )
        })
        .collect();
    let proof_invalidated: Vec<_> = engine
        .events()
        .iter()
        .filter(|e| matches!(e.event_type, IngestionEventType::ProofInvalidated { .. }))
        .collect();

    assert_eq!(hyp_invalidated.len(), 2);
    assert_eq!(proof_invalidated.len(), 1);
}

#[test]
fn enrichment_receipt_emission_generates_event() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    let hyps = engine.ingest_proof(proof, 1000).unwrap();
    let pre_count = engine.events().len();

    let receipt = engine
        .emit_receipt(
            &hyps[0].hypothesis_id,
            ContentHash::compute(b"tw"),
            ContentHash::compute(b"ee"),
            ContentHash::compute(b"rt"),
            ActivationStageLocal::Default,
            2000,
        )
        .unwrap();

    assert_eq!(engine.events().len(), pre_count + 1);
    let last = engine.events().last().unwrap();
    assert!(matches!(
        &last.event_type,
        IngestionEventType::SpecializationReceiptEmitted {
            receipt_id,
            hypothesis_id,
        } if *receipt_id == receipt.receipt_id
            && *hypothesis_id == hyps[0].hypothesis_id
    ));
}

#[test]
fn enrichment_failed_ingestion_still_emits_events() {
    let mut engine = test_engine();
    let mut proof = make_default_proof(ProofType::PlasCapabilityWitness);
    proof.issuer_signature = vec![0xFF]; // tamper
    let _ = engine.ingest_proof(proof, 1000);

    // Should have ProofSubmitted and ProofValidated events even on failure
    assert!(engine.events().len() >= 2);
    assert!(matches!(
        engine.events()[0].event_type,
        IngestionEventType::ProofSubmitted { .. }
    ));
    assert!(matches!(
        engine.events()[1].event_type,
        IngestionEventType::ProofValidated { .. }
    ));
}

// ===========================================================================
// Engine accessor tests
// ===========================================================================

#[test]
fn enrichment_current_epoch_accessor() {
    let engine = test_engine();
    assert_eq!(engine.current_epoch(), test_epoch());
}

#[test]
fn enrichment_current_epoch_updates_after_advance() {
    let mut engine = test_engine();
    engine.advance_epoch(SecurityEpoch::from_raw(200), 1000);
    assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(200));
}

#[test]
fn enrichment_empty_engine_has_no_proofs() {
    let engine = test_engine();
    assert!(engine.active_proofs().is_empty());
    assert!(engine.active_hypotheses().is_empty());
    assert!(engine.receipts().is_empty());
    assert!(engine.events().is_empty());
}

// ===========================================================================
// Error trait implementation
// ===========================================================================

#[test]
fn enrichment_ingestion_error_implements_std_error() {
    let err = IngestionError::IdDerivation("test".to_string());
    let _: &dyn std::error::Error = &err;
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn enrichment_ingestion_error_all_variants_have_source_none() {
    let id = fake_id(b"err-src");
    let errors: Vec<IngestionError> = vec![
        IngestionError::ValidationFailed {
            proof_id: id.clone(),
            status: ProofValidationStatus::SignatureInvalid,
        },
        IngestionError::NoHypothesesGenerated { proof_id: id },
        IngestionError::HypothesisGenerationFailed {
            reason: "x".to_string(),
        },
        IngestionError::UnsupportedProofType {
            proof_type: ProofType::PlasCapabilityWitness,
        },
        IngestionError::IdDerivation("y".to_string()),
        IngestionError::ConservativeModeActive {
            invalidation_count: 1,
            window_ns: 1,
        },
    ];
    for e in &errors {
        assert!(std::error::Error::source(e).is_none());
    }
}

// ===========================================================================
// Deterministic hash behavior
// ===========================================================================

#[test]
fn enrichment_proof_canonical_hash_from_payload() {
    let proof = make_proof(
        ProofType::PlasCapabilityWitness,
        b"specific-payload",
        "policy-001",
    );
    assert_eq!(
        proof.canonical_hash,
        ContentHash::compute(b"specific-payload")
    );
}

#[test]
fn enrichment_different_payloads_produce_different_canonical_hashes() {
    let p1 = make_proof(
        ProofType::PlasCapabilityWitness,
        b"payload-one",
        "policy-001",
    );
    let p2 = make_proof(
        ProofType::PlasCapabilityWitness,
        b"payload-two",
        "policy-001",
    );
    assert_ne!(p1.canonical_hash, p2.canonical_hash);
}

#[test]
fn enrichment_signature_depends_on_signing_key() {
    let key1 = test_key();
    let mut key2 = [0u8; 32];
    for (i, b) in key2.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }

    let p1 = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "pol",
        b"data",
        &key1,
    )
    .unwrap();
    let p2 = create_proof_input(
        ProofType::PlasCapabilityWitness,
        test_epoch(),
        0,
        0,
        "pol",
        b"data",
        &key2,
    )
    .unwrap();

    assert_ne!(p1.issuer_signature, p2.issuer_signature);
}

// ===========================================================================
// Custom config speedup estimates
// ===========================================================================

#[test]
fn enrichment_custom_speedup_estimates_reflected_in_hypotheses() {
    let config = IngestionConfig {
        active_policy_id: "pol-custom".to_string(),
        signing_key: test_key(),
        churn_threshold: 10,
        churn_window_ns: 60_000_000_000,
        plas_speedup_estimate: 2_000_000,   // 2.0x
        ifc_speedup_estimate: 3_000_000,    // 3.0x
        replay_speedup_estimate: 4_000_000, // 4.0x
    };
    let mut engine = ProofIngestionEngine::new(test_epoch(), config);

    let p1 = make_proof(ProofType::PlasCapabilityWitness, b"p", "pol-custom");
    let hyps = engine.ingest_proof(p1, 1000).unwrap();
    assert_eq!(hyps[0].expected_speedup_millionths, 2_000_000);
    assert_eq!(hyps[1].expected_speedup_millionths, 2_000_000);

    let p2 = make_proof(ProofType::IfcFlowProof, b"i", "pol-custom");
    let hyps = engine.ingest_proof(p2, 1000).unwrap();
    assert_eq!(hyps[0].expected_speedup_millionths, 3_000_000);

    let p3 = make_proof(ProofType::ReplaySequenceMotif, b"r", "pol-custom");
    let hyps = engine.ingest_proof(p3, 1000).unwrap();
    assert_eq!(hyps[0].expected_speedup_millionths, 4_000_000);
}

// ===========================================================================
// Receipt all activation stages
// ===========================================================================

#[test]
fn enrichment_emit_receipt_all_activation_stages() {
    let stages = [
        ActivationStageLocal::Shadow,
        ActivationStageLocal::Canary,
        ActivationStageLocal::Ramp,
        ActivationStageLocal::Default,
    ];
    for (i, stage) in stages.iter().enumerate() {
        let mut engine = test_engine();
        let proof = make_proof(
            ProofType::IfcFlowProof,
            format!("stage-{i}").as_bytes(),
            "policy-001",
        );
        let hyps = engine.ingest_proof(proof, 1000).unwrap();
        let receipt = engine
            .emit_receipt(
                &hyps[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                *stage,
                2000,
            )
            .unwrap();
        assert_eq!(receipt.activation_stage, *stage);
    }
}

// ===========================================================================
// Edge case: epoch advance with no proofs
// ===========================================================================

#[test]
fn enrichment_epoch_advance_no_proofs_returns_zero() {
    let mut engine = test_engine();
    let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(200), 1000);
    assert_eq!(invalidated, 0);
    assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(200));
}

// ===========================================================================
// IngestionEvent struct fields
// ===========================================================================

#[test]
fn enrichment_ingestion_event_timestamp_preserved() {
    let mut engine = test_engine();
    let proof = make_default_proof(ProofType::IfcFlowProof);
    engine.ingest_proof(proof, 42_000).unwrap();
    for event in engine.events() {
        assert_eq!(event.timestamp_ns, 42_000);
    }
}
