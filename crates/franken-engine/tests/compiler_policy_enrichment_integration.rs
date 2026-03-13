#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff,
    clippy::len_zero
)]

use std::collections::BTreeSet;

use frankenengine_engine::compiler_policy::*;
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::proof_specialization_receipt::{
    OptimizationClass, ProofInput, ProofType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCHEMA_DEF: &[u8] = b"CompilerPolicy.v1";

fn test_schema_id() -> SchemaId {
    SchemaId::from_definition(SCHEMA_DEF)
}

fn make_proof_id(tag: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &test_schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn cap_witness_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
    SecurityProof::CapabilityWitness {
        proof_id: make_proof_id(tag),
        capability_name: format!("cap_{tag}"),
        epoch,
        validity_window_ticks: 1000,
    }
}

fn flow_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
    SecurityProof::FlowProof {
        proof_id: make_proof_id(tag),
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        epoch,
        validity_window_ticks: 500,
    }
}

fn replay_motif_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
    SecurityProof::ReplayMotif {
        proof_id: make_proof_id(tag),
        motif_hash: format!("motif_{tag}"),
        epoch,
        validity_window_ticks: 2000,
    }
}

fn make_region(
    region_id: &str,
    class: OptimizationClass,
    proof_ids: Vec<frankenengine_engine::engine_object_id::EngineObjectId>,
) -> MarkedRegion {
    MarkedRegion {
        region_id: region_id.to_string(),
        optimization_class: class,
        proof_refs: proof_ids,
        elided_check_description: format!("elide check in {region_id}"),
    }
}

fn default_engine(epoch: SecurityEpoch) -> CompilerPolicyEngine {
    let config = CompilerPolicyConfig::new("test-policy", epoch);
    CompilerPolicyEngine::new(config)
}

// =========================================================================
// SecurityProof — construction, accessors, serde
// =========================================================================

#[test]
fn enrichment_security_proof_capability_witness_accessors() {
    let epoch = SecurityEpoch::from_raw(10);
    let proof = cap_witness_proof("cw-acc", epoch);
    assert_eq!(proof.proof_type(), ProofType::CapabilityWitness);
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.validity_window_ticks(), 1000);
    assert!(!proof.proof_id().to_hex().is_empty());
}

#[test]
fn enrichment_security_proof_flow_proof_accessors() {
    let epoch = SecurityEpoch::from_raw(20);
    let proof = flow_proof("fp-acc", epoch);
    assert_eq!(proof.proof_type(), ProofType::FlowProof);
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.validity_window_ticks(), 500);
}

#[test]
fn enrichment_security_proof_replay_motif_accessors() {
    let epoch = SecurityEpoch::from_raw(30);
    let proof = replay_motif_proof("rm-acc", epoch);
    assert_eq!(proof.proof_type(), ProofType::ReplayMotif);
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.validity_window_ticks(), 2000);
}

#[test]
fn enrichment_security_proof_proof_id_deterministic() {
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = cap_witness_proof("det-id", epoch);
    let p2 = cap_witness_proof("det-id", epoch);
    assert_eq!(p1.proof_id(), p2.proof_id());
}

#[test]
fn enrichment_security_proof_proof_id_differs_by_tag() {
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = cap_witness_proof("tag-a", epoch);
    let p2 = cap_witness_proof("tag-b", epoch);
    assert_ne!(p1.proof_id(), p2.proof_id());
}

#[test]
fn enrichment_security_proof_serde_roundtrip_capability_witness() {
    let proof = cap_witness_proof("serde-cw", SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&proof).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn enrichment_security_proof_serde_roundtrip_flow_proof() {
    let proof = flow_proof("serde-fp", SecurityEpoch::from_raw(2));
    let json = serde_json::to_string(&proof).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn enrichment_security_proof_serde_roundtrip_replay_motif() {
    let proof = replay_motif_proof("serde-rm", SecurityEpoch::from_raw(3));
    let json = serde_json::to_string(&proof).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn enrichment_security_proof_serde_all_variants_distinct() {
    let epoch = SecurityEpoch::from_raw(1);
    let cw = serde_json::to_string(&cap_witness_proof("sv-d", epoch)).unwrap();
    let fp = serde_json::to_string(&flow_proof("sv-d", epoch)).unwrap();
    let rm = serde_json::to_string(&replay_motif_proof("sv-d", epoch)).unwrap();
    let set: BTreeSet<String> = [cw, fp, rm].into_iter().collect();
    assert_eq!(set.len(), 3, "each variant serializes to distinct JSON");
}

#[test]
fn enrichment_security_proof_clone_equality() {
    let proof = cap_witness_proof("clone-eq", SecurityEpoch::from_raw(1));
    let cloned = proof.clone();
    assert_eq!(proof, cloned);
}

#[test]
fn enrichment_security_proof_clone_independence() {
    let proof = flow_proof("clone-ind", SecurityEpoch::from_raw(1));
    let cloned = proof.clone();
    // They are equal but are independent objects.
    assert_eq!(proof, cloned);
    // Changing one doesn't affect the other (both are owned data).
    let proof2 = flow_proof("clone-ind-2", SecurityEpoch::from_raw(1));
    assert_ne!(proof, proof2);
}

#[test]
fn enrichment_security_proof_debug_non_empty() {
    let epoch = SecurityEpoch::from_raw(1);
    let cw = format!("{:?}", cap_witness_proof("dbg-1", epoch));
    let fp = format!("{:?}", flow_proof("dbg-2", epoch));
    let rm = format!("{:?}", replay_motif_proof("dbg-3", epoch));
    assert!(!cw.is_empty());
    assert!(!fp.is_empty());
    assert!(!rm.is_empty());
    assert_ne!(cw, fp);
    assert_ne!(fp, rm);
}

#[test]
fn enrichment_security_proof_proof_type_maps_correctly() {
    let epoch = SecurityEpoch::from_raw(1);
    assert_eq!(
        cap_witness_proof("pt-cw", epoch).proof_type(),
        ProofType::CapabilityWitness
    );
    assert_eq!(
        flow_proof("pt-fp", epoch).proof_type(),
        ProofType::FlowProof
    );
    assert_eq!(
        replay_motif_proof("pt-rm", epoch).proof_type(),
        ProofType::ReplayMotif
    );
}

#[test]
fn enrichment_security_proof_flow_proof_labels() {
    let epoch = SecurityEpoch::from_raw(1);
    let pid = make_proof_id("lbl-test");
    let proof = SecurityProof::FlowProof {
        proof_id: pid,
        source_label: Label::Secret,
        sink_clearance: Label::TopSecret,
        epoch,
        validity_window_ticks: 999,
    };
    assert_eq!(proof.validity_window_ticks(), 999);
    assert_eq!(proof.proof_type(), ProofType::FlowProof);
}

#[test]
fn enrichment_security_proof_replay_motif_custom_hash() {
    let epoch = SecurityEpoch::from_raw(1);
    let pid = make_proof_id("custom-motif");
    let proof = SecurityProof::ReplayMotif {
        proof_id: pid,
        motif_hash: "sha256:abcdef0123456789".to_string(),
        epoch,
        validity_window_ticks: 42,
    };
    assert_eq!(proof.validity_window_ticks(), 42);
    assert_eq!(proof.proof_type(), ProofType::ReplayMotif);
}

// =========================================================================
// MarkedRegion — construction, serde
// =========================================================================

#[test]
fn enrichment_marked_region_field_access() {
    let pid = make_proof_id("mr-fa");
    let region = MarkedRegion {
        region_id: "region-42".to_string(),
        optimization_class: OptimizationClass::PathElimination,
        proof_refs: vec![pid.clone()],
        elided_check_description: "elide path check".to_string(),
    };
    assert_eq!(region.region_id, "region-42");
    assert_eq!(
        region.optimization_class,
        OptimizationClass::PathElimination
    );
    assert_eq!(region.proof_refs.len(), 1);
    assert_eq!(region.proof_refs[0], pid);
    assert_eq!(region.elided_check_description, "elide path check");
}

#[test]
fn enrichment_marked_region_serde_roundtrip() {
    let pid = make_proof_id("mr-serde");
    let region = MarkedRegion {
        region_id: "r-99".to_string(),
        optimization_class: OptimizationClass::SuperinstructionFusion,
        proof_refs: vec![pid],
        elided_check_description: "fuse hot loop".to_string(),
    };
    let json = serde_json::to_string(&region).unwrap();
    let back: MarkedRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

#[test]
fn enrichment_marked_region_empty_proof_refs() {
    let region = MarkedRegion {
        region_id: "empty-refs".to_string(),
        optimization_class: OptimizationClass::IfcCheckElision,
        proof_refs: vec![],
        elided_check_description: "no proofs".to_string(),
    };
    assert!(region.proof_refs.is_empty());
    let json = serde_json::to_string(&region).unwrap();
    let back: MarkedRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

#[test]
fn enrichment_marked_region_clone_independence() {
    let region = MarkedRegion {
        region_id: "orig".to_string(),
        optimization_class: OptimizationClass::PathElimination,
        proof_refs: vec![make_proof_id("ci")],
        elided_check_description: "original".to_string(),
    };
    let mut cloned = region.clone();
    cloned.region_id = "mutated".to_string();
    assert_eq!(region.region_id, "orig");
}

#[test]
fn enrichment_marked_region_json_field_names() {
    let region = MarkedRegion {
        region_id: "fn-test".to_string(),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        proof_refs: vec![],
        elided_check_description: "check desc".to_string(),
    };
    let json = serde_json::to_string(&region).unwrap();
    assert!(json.contains("\"region_id\""));
    assert!(json.contains("\"optimization_class\""));
    assert!(json.contains("\"proof_refs\""));
    assert!(json.contains("\"elided_check_description\""));
}

#[test]
fn enrichment_marked_region_multiple_proof_refs() {
    let ids: Vec<_> = (0..5)
        .map(|i| make_proof_id(&format!("multi-{i}")))
        .collect();
    let region = MarkedRegion {
        region_id: "multi".to_string(),
        optimization_class: OptimizationClass::SuperinstructionFusion,
        proof_refs: ids.clone(),
        elided_check_description: "multi proof".to_string(),
    };
    assert_eq!(region.proof_refs.len(), 5);
    let json = serde_json::to_string(&region).unwrap();
    let back: MarkedRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back.proof_refs, ids);
}

// =========================================================================
// OptimizationClassPolicy — defaults, serde, edge cases
// =========================================================================

#[test]
fn enrichment_optimization_class_policy_default_values() {
    let policy = OptimizationClassPolicy::default();
    assert!(policy.enabled);
    assert_eq!(policy.min_proof_count, 1);
    assert!(policy.required_proof_types.is_empty());
    assert!(!policy.governance_approved);
}

#[test]
fn enrichment_optimization_class_policy_serde_roundtrip() {
    let mut required = BTreeSet::new();
    required.insert(ProofType::CapabilityWitness);
    required.insert(ProofType::FlowProof);
    let policy = OptimizationClassPolicy {
        enabled: true,
        min_proof_count: 3,
        required_proof_types: required,
        governance_approved: true,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: OptimizationClassPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_optimization_class_policy_disabled() {
    let policy = OptimizationClassPolicy {
        enabled: false,
        min_proof_count: 0,
        required_proof_types: BTreeSet::new(),
        governance_approved: false,
    };
    assert!(!policy.enabled);
    assert_eq!(policy.min_proof_count, 0);
}

#[test]
fn enrichment_optimization_class_policy_clone_independence() {
    let orig = OptimizationClassPolicy {
        enabled: true,
        min_proof_count: 5,
        required_proof_types: BTreeSet::from([ProofType::ReplayMotif]),
        governance_approved: true,
    };
    let mut cloned = orig.clone();
    cloned.enabled = false;
    cloned.min_proof_count = 1;
    assert!(orig.enabled);
    assert_eq!(orig.min_proof_count, 5);
}

#[test]
fn enrichment_optimization_class_policy_all_three_proof_types() {
    let all = BTreeSet::from([
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ]);
    let policy = OptimizationClassPolicy {
        enabled: true,
        min_proof_count: 3,
        required_proof_types: all.clone(),
        governance_approved: true,
    };
    assert_eq!(policy.required_proof_types.len(), 3);
    let json = serde_json::to_string(&policy).unwrap();
    let back: OptimizationClassPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back.required_proof_types, all);
}

// =========================================================================
// CompilerPolicyConfig — construction, serde, accessors
// =========================================================================

#[test]
fn enrichment_compiler_policy_config_new_defaults() {
    let epoch = SecurityEpoch::from_raw(99);
    let config = CompilerPolicyConfig::new("pol-99", epoch);
    assert_eq!(config.policy_id, "pol-99");
    assert_eq!(config.current_epoch, epoch);
    assert!(!config.global_disable);
    assert!(config.class_policies.is_empty());
}

#[test]
fn enrichment_compiler_policy_config_serde_roundtrip_empty() {
    let config = CompilerPolicyConfig::new("empty-pol", SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&config).unwrap();
    let back: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_compiler_policy_config_serde_roundtrip_with_class_policies() {
    let mut config = CompilerPolicyConfig::new("cp-rich", SecurityEpoch::from_raw(5));
    config.global_disable = true;
    config.class_policies.insert(
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClassPolicy {
            enabled: false,
            min_proof_count: 2,
            required_proof_types: BTreeSet::from([ProofType::CapabilityWitness]),
            governance_approved: true,
        },
    );
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 1,
            required_proof_types: BTreeSet::new(),
            governance_approved: false,
        },
    );
    let json = serde_json::to_string(&config).unwrap();
    let back: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_compiler_policy_config_clone_independence() {
    let orig = CompilerPolicyConfig::new("orig", SecurityEpoch::from_raw(1));
    let mut cloned = orig.clone();
    cloned.global_disable = true;
    cloned.policy_id = "cloned".to_string();
    assert!(!orig.global_disable);
    assert_eq!(orig.policy_id, "orig");
}

#[test]
fn enrichment_compiler_policy_config_json_field_names() {
    let config = CompilerPolicyConfig::new("fn-check", SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"current_epoch\""));
    assert!(json.contains("\"class_policies\""));
    assert!(json.contains("\"global_disable\""));
    assert!(json.contains("\"policy_id\""));
}

// =========================================================================
// SpecializationOutcome — all variants, error codes, is_applied
// =========================================================================

#[test]
fn enrichment_specialization_outcome_is_applied_only_for_applied() {
    assert!(SpecializationOutcome::Applied.is_applied());
    let non_applied = [
        SpecializationOutcome::RejectedGlobalDisable,
        SpecializationOutcome::RejectedClassDisabled,
        SpecializationOutcome::RejectedNoProofs,
        SpecializationOutcome::RejectedInsufficientProofs,
        SpecializationOutcome::RejectedMissingRequiredProofTypes,
        SpecializationOutcome::RejectedProofExpired,
        SpecializationOutcome::RejectedEpochMismatch,
        SpecializationOutcome::RejectedProofNotFound,
        SpecializationOutcome::InvalidatedByEpochChange,
    ];
    for o in &non_applied {
        assert!(!o.is_applied(), "{:?} should not be applied", o);
    }
}

#[test]
fn enrichment_specialization_outcome_error_codes_unique() {
    let outcomes = [
        SpecializationOutcome::Applied,
        SpecializationOutcome::RejectedGlobalDisable,
        SpecializationOutcome::RejectedClassDisabled,
        SpecializationOutcome::RejectedNoProofs,
        SpecializationOutcome::RejectedInsufficientProofs,
        SpecializationOutcome::RejectedMissingRequiredProofTypes,
        SpecializationOutcome::RejectedProofExpired,
        SpecializationOutcome::RejectedEpochMismatch,
        SpecializationOutcome::RejectedProofNotFound,
        SpecializationOutcome::InvalidatedByEpochChange,
    ];
    let codes: BTreeSet<&str> = outcomes.iter().map(|o| o.error_code()).collect();
    assert_eq!(codes.len(), 10);
}

#[test]
fn enrichment_specialization_outcome_error_code_applied() {
    assert_eq!(SpecializationOutcome::Applied.error_code(), "APPLIED");
}

#[test]
fn enrichment_specialization_outcome_error_code_global_disable() {
    assert_eq!(
        SpecializationOutcome::RejectedGlobalDisable.error_code(),
        "GLOBAL_DISABLE"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_class_disabled() {
    assert_eq!(
        SpecializationOutcome::RejectedClassDisabled.error_code(),
        "CLASS_DISABLED"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_no_proofs() {
    assert_eq!(
        SpecializationOutcome::RejectedNoProofs.error_code(),
        "NO_PROOFS"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_insufficient_proofs() {
    assert_eq!(
        SpecializationOutcome::RejectedInsufficientProofs.error_code(),
        "INSUFFICIENT_PROOFS"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_missing_required() {
    assert_eq!(
        SpecializationOutcome::RejectedMissingRequiredProofTypes.error_code(),
        "MISSING_REQUIRED_PROOF_TYPES"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_expired() {
    assert_eq!(
        SpecializationOutcome::RejectedProofExpired.error_code(),
        "PROOF_EXPIRED"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_epoch_mismatch() {
    assert_eq!(
        SpecializationOutcome::RejectedEpochMismatch.error_code(),
        "EPOCH_MISMATCH"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_not_found() {
    assert_eq!(
        SpecializationOutcome::RejectedProofNotFound.error_code(),
        "PROOF_NOT_FOUND"
    );
}

#[test]
fn enrichment_specialization_outcome_error_code_invalidated() {
    assert_eq!(
        SpecializationOutcome::InvalidatedByEpochChange.error_code(),
        "INVALIDATED_EPOCH_CHANGE"
    );
}

#[test]
fn enrichment_specialization_outcome_serde_roundtrip_all() {
    let outcomes = [
        SpecializationOutcome::Applied,
        SpecializationOutcome::RejectedGlobalDisable,
        SpecializationOutcome::RejectedClassDisabled,
        SpecializationOutcome::RejectedNoProofs,
        SpecializationOutcome::RejectedInsufficientProofs,
        SpecializationOutcome::RejectedMissingRequiredProofTypes,
        SpecializationOutcome::RejectedProofExpired,
        SpecializationOutcome::RejectedEpochMismatch,
        SpecializationOutcome::RejectedProofNotFound,
        SpecializationOutcome::InvalidatedByEpochChange,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: SpecializationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn enrichment_specialization_outcome_copy_semantics() {
    let a = SpecializationOutcome::Applied;
    let b = a;
    assert_eq!(a, b);
    let c = SpecializationOutcome::RejectedGlobalDisable;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_specialization_outcome_debug_distinct() {
    let outcomes = [
        SpecializationOutcome::Applied,
        SpecializationOutcome::RejectedGlobalDisable,
        SpecializationOutcome::RejectedClassDisabled,
        SpecializationOutcome::RejectedNoProofs,
        SpecializationOutcome::RejectedInsufficientProofs,
        SpecializationOutcome::RejectedMissingRequiredProofTypes,
        SpecializationOutcome::RejectedProofExpired,
        SpecializationOutcome::RejectedEpochMismatch,
        SpecializationOutcome::RejectedProofNotFound,
        SpecializationOutcome::InvalidatedByEpochChange,
    ];
    let debugs: BTreeSet<String> = outcomes.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(debugs.len(), 10);
}

#[test]
fn enrichment_specialization_outcome_serde_variants_distinct_json() {
    let outcomes = [
        SpecializationOutcome::Applied,
        SpecializationOutcome::RejectedGlobalDisable,
        SpecializationOutcome::RejectedClassDisabled,
        SpecializationOutcome::RejectedNoProofs,
        SpecializationOutcome::RejectedInsufficientProofs,
        SpecializationOutcome::RejectedMissingRequiredProofTypes,
        SpecializationOutcome::RejectedProofExpired,
        SpecializationOutcome::RejectedEpochMismatch,
        SpecializationOutcome::RejectedProofNotFound,
        SpecializationOutcome::InvalidatedByEpochChange,
    ];
    let jsons: BTreeSet<String> = outcomes
        .iter()
        .map(|o| serde_json::to_string(o).unwrap())
        .collect();
    assert_eq!(jsons.len(), 10);
}

// =========================================================================
// SpecializationDecision — serde, field coverage
// =========================================================================

#[test]
fn enrichment_specialization_decision_serde_roundtrip() {
    let decision = SpecializationDecision {
        trace_id: "trace-serde".to_string(),
        decision_id: "cpe-42".to_string(),
        policy_id: "pol-1".to_string(),
        region_id: "r-serde".to_string(),
        optimization_class: OptimizationClass::IfcCheckElision,
        outcome: SpecializationOutcome::Applied,
        detail: "applied ok".to_string(),
        proof_ids: vec![make_proof_id("sd-1"), make_proof_id("sd-2")],
        epoch: SecurityEpoch::from_raw(7),
        timestamp_ns: 123_456_789,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: SpecializationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_specialization_decision_json_field_names() {
    let decision = SpecializationDecision {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        region_id: "r".to_string(),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        outcome: SpecializationOutcome::RejectedNoProofs,
        detail: "detail".to_string(),
        proof_ids: vec![],
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 0,
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"region_id\""));
    assert!(json.contains("\"optimization_class\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"detail\""));
    assert!(json.contains("\"proof_ids\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"timestamp_ns\""));
}

#[test]
fn enrichment_specialization_decision_clone_equality() {
    let decision = SpecializationDecision {
        trace_id: "ce".to_string(),
        decision_id: "cpe-ce".to_string(),
        policy_id: "p-ce".to_string(),
        region_id: "r-ce".to_string(),
        optimization_class: OptimizationClass::PathElimination,
        outcome: SpecializationOutcome::Applied,
        detail: "ok".to_string(),
        proof_ids: vec![make_proof_id("ce-1")],
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 100,
    };
    assert_eq!(decision.clone(), decision);
}

// =========================================================================
// CompilerPolicyEvent — serde, field coverage
// =========================================================================

#[test]
fn enrichment_compiler_policy_event_serde_roundtrip_no_error() {
    let event = CompilerPolicyEvent {
        trace_id: "te-1".to_string(),
        decision_id: "de-1".to_string(),
        policy_id: "pe-1".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_applied".to_string(),
        outcome: "APPLIED".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_compiler_policy_event_serde_roundtrip_with_error() {
    let event = CompilerPolicyEvent {
        trace_id: "te-2".to_string(),
        decision_id: "de-2".to_string(),
        policy_id: "pe-2".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_rejected".to_string(),
        outcome: "GLOBAL_DISABLE".to_string(),
        error_code: Some("GLOBAL_DISABLE".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.error_code.as_deref(), Some("GLOBAL_DISABLE"));
}

#[test]
fn enrichment_compiler_policy_event_json_field_names() {
    let event = CompilerPolicyEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: Some("err".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"event\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"error_code\""));
}

// =========================================================================
// ProofStore — CRUD, invalidation, resolve, serde
// =========================================================================

#[test]
fn enrichment_proof_store_new_is_empty() {
    let store = ProofStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn enrichment_proof_store_default_is_empty() {
    let store = ProofStore::default();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn enrichment_proof_store_insert_get() {
    let mut store = ProofStore::new();
    let proof = cap_witness_proof("ig-1", SecurityEpoch::from_raw(1));
    let pid = proof.proof_id().clone();
    store.insert(proof.clone());
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    let retrieved = store.get(&pid).unwrap();
    assert_eq!(retrieved, &proof);
}

#[test]
fn enrichment_proof_store_insert_replaces_same_id() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = SecurityProof::CapabilityWitness {
        proof_id: make_proof_id("replace"),
        capability_name: "original".to_string(),
        epoch,
        validity_window_ticks: 100,
    };
    let p2 = SecurityProof::CapabilityWitness {
        proof_id: make_proof_id("replace"),
        capability_name: "updated".to_string(),
        epoch,
        validity_window_ticks: 200,
    };
    store.insert(p1);
    assert_eq!(store.len(), 1);
    store.insert(p2);
    assert_eq!(store.len(), 1);
    let got = store.get(&make_proof_id("replace")).unwrap();
    assert_eq!(got.validity_window_ticks(), 200);
}

#[test]
fn enrichment_proof_store_remove() {
    let mut store = ProofStore::new();
    let proof = cap_witness_proof("rm-1", SecurityEpoch::from_raw(1));
    let pid = proof.proof_id().clone();
    store.insert(proof);
    assert_eq!(store.len(), 1);
    let removed = store.remove(&pid);
    assert!(removed.is_some());
    assert!(store.is_empty());
}

#[test]
fn enrichment_proof_store_remove_nonexistent_returns_none() {
    let mut store = ProofStore::new();
    let fake_id = make_proof_id("nonexistent");
    let removed = store.remove(&fake_id);
    assert!(removed.is_none());
}

#[test]
fn enrichment_proof_store_get_nonexistent_returns_none() {
    let store = ProofStore::new();
    assert!(store.get(&make_proof_id("no-such")).is_none());
}

#[test]
fn enrichment_proof_store_resolve_all() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = cap_witness_proof("res-1", epoch);
    let p2 = flow_proof("res-2", epoch);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    store.insert(p1);
    store.insert(p2);
    let resolved = store.resolve(&[id1, id2]);
    assert_eq!(resolved.len(), 2);
}

#[test]
fn enrichment_proof_store_resolve_partial() {
    let mut store = ProofStore::new();
    let proof = cap_witness_proof("res-p", SecurityEpoch::from_raw(1));
    let pid = proof.proof_id().clone();
    store.insert(proof);
    let fake = make_proof_id("fake-resolve");
    let resolved = store.resolve(&[pid, fake]);
    assert_eq!(resolved.len(), 1);
}

#[test]
fn enrichment_proof_store_resolve_empty_ids() {
    let store = ProofStore::new();
    let resolved = store.resolve(&[]);
    assert!(resolved.is_empty());
}

#[test]
fn enrichment_proof_store_invalidate_epoch_removes_matching() {
    let mut store = ProofStore::new();
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    store.insert(cap_witness_proof("inv-a", e1));
    store.insert(cap_witness_proof("inv-b", e1));
    store.insert(cap_witness_proof("inv-c", e2));
    assert_eq!(store.len(), 3);
    let removed = store.invalidate_epoch(e1);
    assert_eq!(removed.len(), 2);
    assert_eq!(store.len(), 1);
}

#[test]
fn enrichment_proof_store_invalidate_epoch_no_match() {
    let mut store = ProofStore::new();
    store.insert(cap_witness_proof("no-match", SecurityEpoch::from_raw(1)));
    let removed = store.invalidate_epoch(SecurityEpoch::from_raw(99));
    assert!(removed.is_empty());
    assert_eq!(store.len(), 1);
}

#[test]
fn enrichment_proof_store_invalidate_epoch_empty_store() {
    let mut store = ProofStore::new();
    let removed = store.invalidate_epoch(SecurityEpoch::from_raw(1));
    assert!(removed.is_empty());
}

#[test]
fn enrichment_proof_store_serde_roundtrip() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    store.insert(cap_witness_proof("serde-a", epoch));
    store.insert(flow_proof("serde-b", epoch));
    store.insert(replay_motif_proof("serde-c", epoch));
    let json = serde_json::to_string(&store).unwrap();
    let back: ProofStore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 3);
}

#[test]
fn enrichment_proof_store_clone_independence() {
    let mut original = ProofStore::new();
    let proof = cap_witness_proof("clone-ps", SecurityEpoch::from_raw(1));
    let pid = proof.proof_id().clone();
    original.insert(proof);
    let mut cloned = original.clone();
    cloned.remove(&pid);
    assert_eq!(original.len(), 1);
    assert!(cloned.is_empty());
}

#[test]
fn enrichment_proof_store_multiple_epochs() {
    let mut store = ProofStore::new();
    for i in 1..=5 {
        let epoch = SecurityEpoch::from_raw(i);
        store.insert(cap_witness_proof(&format!("me-{i}"), epoch));
    }
    assert_eq!(store.len(), 5);
    let removed = store.invalidate_epoch(SecurityEpoch::from_raw(3));
    assert_eq!(removed.len(), 1);
    assert_eq!(store.len(), 4);
}

// =========================================================================
// CompilerPolicyEngine — construction, evaluate, workflows
// =========================================================================

#[test]
fn enrichment_engine_new_initial_state() {
    let epoch = SecurityEpoch::from_raw(1);
    let engine = default_engine(epoch);
    assert_eq!(engine.config().current_epoch, epoch);
    assert_eq!(engine.config().policy_id, "test-policy");
    assert!(engine.proof_store().is_empty());
    assert!(engine.decisions().is_empty());
    assert!(engine.events().is_empty());
    assert_eq!(engine.applied_count(), 0);
    assert_eq!(engine.rejected_count(), 0);
}

#[test]
fn enrichment_engine_register_proof_and_access() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("reg-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    assert_eq!(engine.proof_store().len(), 1);
    assert!(engine.proof_store().get(&pid).is_some());
}

#[test]
fn enrichment_engine_evaluate_applied_with_valid_proof() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("eval-ok", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-eval-ok",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid.clone()],
    );
    let d = engine.evaluate(&region, "trace-eval", 1000);
    assert_eq!(d.outcome, SpecializationOutcome::Applied);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids, vec![pid]);
    assert_eq!(d.region_id, "r-eval-ok");
    assert_eq!(d.trace_id, "trace-eval");
    assert_eq!(d.timestamp_ns, 1000);
    assert!(d.decision_id.starts_with("cpe-"));
    assert_eq!(engine.applied_count(), 1);
    assert_eq!(engine.rejected_count(), 0);
}

#[test]
fn enrichment_engine_evaluate_rejected_global_disable() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("glob-dis", epoch);
    config.global_disable = true;
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = cap_witness_proof("gd-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-gd",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-gd", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
    assert!(!d.outcome.is_applied());
    assert_eq!(engine.rejected_count(), 1);
}

#[test]
fn enrichment_engine_evaluate_rejected_class_disabled() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("class-dis", epoch);
    config.class_policies.insert(
        OptimizationClass::IfcCheckElision,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = flow_proof("cd-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region("r-cd", OptimizationClass::IfcCheckElision, vec![pid]);
    let d = engine.evaluate(&region, "t-cd", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedClassDisabled);
}

#[test]
fn enrichment_engine_evaluate_rejected_no_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let region = make_region("r-np", OptimizationClass::PathElimination, vec![]);
    let d = engine.evaluate(&region, "t-np", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedNoProofs);
}

#[test]
fn enrichment_engine_evaluate_rejected_proof_not_found() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let fake = make_proof_id("does-not-exist");
    let region = make_region(
        "r-pnf",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![fake],
    );
    let d = engine.evaluate(&region, "t-pnf", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofNotFound);
}

#[test]
fn enrichment_engine_evaluate_rejected_insufficient_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("insuf", epoch);
    config.class_policies.insert(
        OptimizationClass::SuperinstructionFusion,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 3,
            required_proof_types: BTreeSet::new(),
            governance_approved: false,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = cap_witness_proof("insuf-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-insuf",
        OptimizationClass::SuperinstructionFusion,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-insuf", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedInsufficientProofs);
}

#[test]
fn enrichment_engine_evaluate_rejected_missing_required_proof_types() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("missing-pt", epoch);
    config.class_policies.insert(
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 1,
            required_proof_types: BTreeSet::from([
                ProofType::CapabilityWitness,
                ProofType::FlowProof,
            ]),
            governance_approved: false,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    // Only provide CapabilityWitness, FlowProof missing
    let proof = cap_witness_proof("mpt-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-mpt",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-mpt", 0);
    assert_eq!(
        d.outcome,
        SpecializationOutcome::RejectedMissingRequiredProofTypes
    );
}

#[test]
fn enrichment_engine_evaluate_rejected_epoch_mismatch() {
    let epoch = SecurityEpoch::from_raw(10);
    let wrong = SecurityEpoch::from_raw(5);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("em-1", wrong);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-em",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-em", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedEpochMismatch);
}

#[test]
fn enrichment_engine_evaluate_rejected_proof_expired() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let pid = make_proof_id("expired-1");
    engine.register_proof(SecurityProof::CapabilityWitness {
        proof_id: pid.clone(),
        capability_name: "exp".to_string(),
        epoch,
        validity_window_ticks: 0,
    });
    let region = make_region(
        "r-exp",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-exp", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
}

// =========================================================================
// Engine — epoch change workflow
// =========================================================================

#[test]
fn enrichment_engine_epoch_change_invalidates_old_proofs() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    engine.register_proof(cap_witness_proof("ec-a", e1));
    engine.register_proof(cap_witness_proof("ec-b", e1));
    assert_eq!(engine.proof_store().len(), 2);
    let invalidated = engine.on_epoch_change(e1, e2, "trace-ec", 5000);
    assert_eq!(invalidated.len(), 2);
    assert!(engine.proof_store().is_empty());
    assert_eq!(engine.config().current_epoch, e2);
}

#[test]
fn enrichment_engine_epoch_change_preserves_new_epoch_proofs() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    engine.register_proof(cap_witness_proof("old", e1));
    engine.register_proof(cap_witness_proof("new", e2));
    let invalidated = engine.on_epoch_change(e1, e2, "trace-ec", 5000);
    assert_eq!(invalidated.len(), 1);
    assert_eq!(engine.proof_store().len(), 1);
}

#[test]
fn enrichment_engine_epoch_change_emits_event_when_invalidated() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    engine.register_proof(cap_witness_proof("ev-1", e1));
    let events_before = engine.events().len();
    engine.on_epoch_change(e1, e2, "trace-ec", 5000);
    assert!(engine.events().len() > events_before);
    let last = engine.events().last().unwrap();
    assert_eq!(last.event, "epoch_change_invalidation");
    assert_eq!(last.error_code.as_deref(), Some("INVALIDATED_EPOCH_CHANGE"));
}

#[test]
fn enrichment_engine_epoch_change_no_event_when_nothing_invalidated() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    let events_before = engine.events().len();
    engine.on_epoch_change(e1, e2, "trace-ec", 5000);
    assert_eq!(engine.events().len(), events_before);
}

#[test]
fn enrichment_engine_after_epoch_change_old_proofs_fail() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    let proof = cap_witness_proof("post-ec", e1);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    // Before epoch change: applied
    let region = make_region(
        "r-post-ec",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid.clone()],
    );
    let d1 = engine.evaluate(&region, "t-1", 1000);
    assert!(d1.outcome.is_applied());

    // Epoch change
    engine.on_epoch_change(e1, e2, "trace-ec", 2000);

    // After epoch change: not found
    let d2 = engine.evaluate(&region, "t-2", 3000);
    assert_eq!(d2.outcome, SpecializationOutcome::RejectedProofNotFound);
}

#[test]
fn enrichment_engine_re_evaluate_with_new_proofs_after_epoch_change() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);
    let old = cap_witness_proof("old-re", e1);
    let old_id = old.proof_id().clone();
    engine.register_proof(old);

    let region = make_region(
        "r-re",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![old_id],
    );
    let d1 = engine.evaluate(&region, "t-1", 1000);
    assert!(d1.outcome.is_applied());

    engine.on_epoch_change(e1, e2, "trace-ec", 2000);

    let new = cap_witness_proof("new-re", e2);
    let new_id = new.proof_id().clone();
    engine.register_proof(new);

    let region2 = make_region(
        "r-re",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![new_id],
    );
    let d2 = engine.evaluate(&region2, "t-2", 3000);
    assert!(d2.outcome.is_applied());
}

// =========================================================================
// Engine — audit trail, events, decisions
// =========================================================================

#[test]
fn enrichment_engine_decisions_are_logged() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("log-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let r1 = make_region(
        "r-log-ok",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    engine.evaluate(&r1, "t-1", 1000);

    let r2 = make_region(
        "r-log-fail",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    engine.evaluate(&r2, "t-2", 2000);

    assert_eq!(engine.decisions().len(), 2);
    assert_eq!(engine.events().len(), 2);
    assert!(engine.decisions()[0].outcome.is_applied());
    assert!(!engine.decisions()[1].outcome.is_applied());
}

#[test]
fn enrichment_engine_event_structure_for_applied() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("ev-struct", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-ev",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    engine.evaluate(&region, "t-ev", 1000);

    let event = &engine.events()[0];
    assert_eq!(event.trace_id, "t-ev");
    assert_eq!(event.policy_id, "test-policy");
    assert_eq!(event.component, "compiler_policy");
    assert_eq!(event.event, "specialization_applied");
    assert_eq!(event.outcome, "APPLIED");
    assert!(event.error_code.is_none());
}

#[test]
fn enrichment_engine_event_structure_for_rejected() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let region = make_region("r-rej-ev", OptimizationClass::PathElimination, vec![]);
    engine.evaluate(&region, "t-rej", 0);

    let event = &engine.events()[0];
    assert_eq!(event.event, "specialization_rejected");
    assert_eq!(event.error_code.as_deref(), Some("NO_PROOFS"));
}

#[test]
fn enrichment_engine_decisions_for_region_filtering() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let p1 = cap_witness_proof("dfr-1", epoch);
    let p2 = cap_witness_proof("dfr-2", epoch);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    engine.register_proof(p1);
    engine.register_proof(p2);

    let ra = make_region(
        "region-A",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![id1],
    );
    let rb = make_region("region-B", OptimizationClass::PathElimination, vec![id2]);

    engine.evaluate(&ra, "t-1", 1000);
    engine.evaluate(&rb, "t-2", 2000);
    engine.evaluate(&ra, "t-3", 3000);

    assert_eq!(engine.decisions_for_region("region-A").len(), 2);
    assert_eq!(engine.decisions_for_region("region-B").len(), 1);
    assert_eq!(engine.decisions_for_region("region-C").len(), 0);
}

#[test]
fn enrichment_engine_decisions_for_region_empty_engine() {
    let engine = default_engine(SecurityEpoch::from_raw(1));
    assert!(engine.decisions_for_region("anything").is_empty());
}

// =========================================================================
// Engine — proof input extraction
// =========================================================================

#[test]
fn enrichment_engine_last_applied_proof_inputs_returns_inputs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("lapi-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-lapi",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    engine.evaluate(&region, "t-lapi", 1000);

    let inputs = engine.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
    assert_eq!(inputs[0].validity_window_ticks, 1000);
    assert_eq!(inputs[0].proof_epoch, epoch);
}

#[test]
fn enrichment_engine_last_applied_proof_inputs_none_when_no_applied() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let region = make_region("r-none", OptimizationClass::PathElimination, vec![]);
    engine.evaluate(&region, "t-none", 0);
    assert!(engine.last_applied_proof_inputs().is_none());
}

#[test]
fn enrichment_engine_last_applied_proof_inputs_none_on_fresh_engine() {
    let engine = default_engine(SecurityEpoch::from_raw(1));
    assert!(engine.last_applied_proof_inputs().is_none());
}

#[test]
fn enrichment_engine_last_applied_proof_inputs_multiple_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let cw = cap_witness_proof("multi-cw", epoch);
    let fp = flow_proof("multi-fp", epoch);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    engine.register_proof(cw);
    engine.register_proof(fp);

    let region = make_region(
        "r-multi-pi",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![cw_id, fp_id],
    );
    engine.evaluate(&region, "t-multi", 1000);

    let inputs = engine.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 2);
    let types: BTreeSet<ProofType> = inputs.iter().map(|i| i.proof_type).collect();
    assert!(types.contains(&ProofType::CapabilityWitness));
    assert!(types.contains(&ProofType::FlowProof));
}

// =========================================================================
// Engine — applied/rejected counts
// =========================================================================

#[test]
fn enrichment_engine_applied_and_rejected_counts() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("cnt-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    // Applied
    let r1 = make_region(
        "r-cnt-ok",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    engine.evaluate(&r1, "t-cnt-1", 0);
    assert_eq!(engine.applied_count(), 1);
    assert_eq!(engine.rejected_count(), 0);

    // Rejected (no proofs)
    let r2 = make_region(
        "r-cnt-fail",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    engine.evaluate(&r2, "t-cnt-2", 0);
    assert_eq!(engine.applied_count(), 1);
    assert_eq!(engine.rejected_count(), 1);
}

#[test]
fn enrichment_engine_multiple_evaluations_accumulate() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    for i in 0..10 {
        let tag = format!("accum-{i}");
        let proof = cap_witness_proof(&tag, epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);
        let region = make_region(
            &format!("r-accum-{i}"),
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        engine.evaluate(&region, &format!("t-accum-{i}"), i as u64 * 1000);
    }
    assert_eq!(engine.applied_count(), 10);
    assert_eq!(engine.decisions().len(), 10);
    assert_eq!(engine.events().len(), 10);
}

// =========================================================================
// Engine — proof_store_mut access
// =========================================================================

#[test]
fn enrichment_engine_proof_store_mut_allows_direct_insert() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = flow_proof("mut-1", epoch);
    let pid = proof.proof_id().clone();
    engine.proof_store_mut().insert(proof);
    assert_eq!(engine.proof_store().len(), 1);
    assert!(engine.proof_store().get(&pid).is_some());
}

#[test]
fn enrichment_engine_proof_store_mut_allows_remove() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("mut-rm", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    assert_eq!(engine.proof_store().len(), 1);
    engine.proof_store_mut().remove(&pid);
    assert!(engine.proof_store().is_empty());
}

// =========================================================================
// Engine — decision_id monotonicity
// =========================================================================

#[test]
fn enrichment_engine_decision_ids_are_monotonic() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("mono-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-mono",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d1 = engine.evaluate(&region, "t-1", 1000);
    // Also do a rejection to ensure counter increments
    let region_empty = make_region("r-mono-rej", OptimizationClass::PathElimination, vec![]);
    let d2 = engine.evaluate(&region_empty, "t-2", 2000);

    // decision_ids are "cpe-N" with increasing N
    assert!(d1.decision_id.starts_with("cpe-"));
    assert!(d2.decision_id.starts_with("cpe-"));
    let n1: u64 = d1
        .decision_id
        .strip_prefix("cpe-")
        .unwrap()
        .parse()
        .unwrap();
    let n2: u64 = d2
        .decision_id
        .strip_prefix("cpe-")
        .unwrap()
        .parse()
        .unwrap();
    assert!(n2 > n1);
}

// =========================================================================
// Engine — class policy fallback to default
// =========================================================================

#[test]
fn enrichment_engine_unconfigured_class_uses_default_policy() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("fallback", epoch);
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = cap_witness_proof("fb-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    // HostcallDispatchSpecialization not configured -> default -> enabled
    let r1 = make_region(
        "r-fb-ok",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d1 = engine.evaluate(&r1, "t-fb-1", 0);
    assert!(d1.outcome.is_applied());

    // PathElimination configured -> disabled
    let proof2 = cap_witness_proof("fb-2", epoch);
    let pid2 = proof2.proof_id().clone();
    engine.register_proof(proof2);
    let r2 = make_region("r-fb-dis", OptimizationClass::PathElimination, vec![pid2]);
    let d2 = engine.evaluate(&r2, "t-fb-2", 0);
    assert_eq!(d2.outcome, SpecializationOutcome::RejectedClassDisabled);
}

// =========================================================================
// Engine — mixed proof types in single region
// =========================================================================

#[test]
fn enrichment_engine_mixed_proof_types_applied() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let cw = cap_witness_proof("mix-cw", epoch);
    let fp = flow_proof("mix-fp", epoch);
    let rm = replay_motif_proof("mix-rm", epoch);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    let rm_id = rm.proof_id().clone();
    engine.register_proof(cw);
    engine.register_proof(fp);
    engine.register_proof(rm);

    let region = make_region(
        "r-mix",
        OptimizationClass::SuperinstructionFusion,
        vec![cw_id, fp_id, rm_id],
    );
    let d = engine.evaluate(&region, "t-mix", 0);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 3);
}

#[test]
fn enrichment_engine_all_required_types_present_applies() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("all-req", epoch);
    config.class_policies.insert(
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 2,
            required_proof_types: BTreeSet::from([
                ProofType::CapabilityWitness,
                ProofType::FlowProof,
            ]),
            governance_approved: true,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let cw = cap_witness_proof("ar-cw", epoch);
    let fp = flow_proof("ar-fp", epoch);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    engine.register_proof(cw);
    engine.register_proof(fp);

    let region = make_region(
        "r-ar",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![cw_id, fp_id],
    );
    let d = engine.evaluate(&region, "t-ar", 0);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 2);
}

// =========================================================================
// Engine — edge cases and boundary conditions
// =========================================================================

#[test]
fn enrichment_engine_validity_window_zero_rejects_flow_proof() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let pid = make_proof_id("fp-zero");
    engine.register_proof(SecurityProof::FlowProof {
        proof_id: pid.clone(),
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        epoch,
        validity_window_ticks: 0,
    });
    let region = make_region("r-fp-z", OptimizationClass::IfcCheckElision, vec![pid]);
    let d = engine.evaluate(&region, "t-fp-z", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
}

#[test]
fn enrichment_engine_validity_window_zero_rejects_replay_motif() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let pid = make_proof_id("rm-zero");
    engine.register_proof(SecurityProof::ReplayMotif {
        proof_id: pid.clone(),
        motif_hash: "hash".to_string(),
        epoch,
        validity_window_ticks: 0,
    });
    let region = make_region(
        "r-rm-z",
        OptimizationClass::SuperinstructionFusion,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-rm-z", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
}

#[test]
fn enrichment_engine_max_validity_window_ticks_passes() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let pid = make_proof_id("max-tick");
    engine.register_proof(SecurityProof::CapabilityWitness {
        proof_id: pid.clone(),
        capability_name: "max".to_string(),
        epoch,
        validity_window_ticks: u64::MAX,
    });
    let region = make_region(
        "r-max-tick",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-max", u64::MAX);
    assert!(d.outcome.is_applied());
    assert_eq!(d.timestamp_ns, u64::MAX);
}

#[test]
fn enrichment_engine_empty_region_id_is_valid() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("empty-rid", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-empty-rid", 0);
    assert!(d.outcome.is_applied());
    assert_eq!(d.region_id, "");
    assert_eq!(engine.decisions_for_region("").len(), 1);
}

#[test]
fn enrichment_engine_min_proof_count_zero_passes_count_check() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("min-zero", epoch);
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 0,
            required_proof_types: BTreeSet::new(),
            governance_approved: false,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = cap_witness_proof("mz-1", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region("r-mz", OptimizationClass::PathElimination, vec![pid]);
    let d = engine.evaluate(&region, "t-mz", 0);
    assert!(d.outcome.is_applied());
}

#[test]
fn enrichment_engine_epoch_zero_is_valid() {
    let epoch = SecurityEpoch::from_raw(0);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("epoch-zero", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-ez",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-ez", 0);
    assert!(d.outcome.is_applied());
}

#[test]
fn enrichment_engine_max_epoch_is_valid() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("epoch-max", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);
    let region = make_region(
        "r-em-max",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-em-max", 0);
    assert!(d.outcome.is_applied());
}

// =========================================================================
// Engine — clone
// =========================================================================

#[test]
fn enrichment_engine_clone_independence() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("clone-eng", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-clone",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    engine.evaluate(&region, "t-clone", 0);

    let mut cloned = engine.clone();
    // Mutate clone
    let region2 = make_region("r-clone-2", OptimizationClass::PathElimination, vec![]);
    cloned.evaluate(&region2, "t-clone-2", 0);

    // Original unaffected
    assert_eq!(engine.decisions().len(), 1);
    assert_eq!(cloned.decisions().len(), 2);
}

// =========================================================================
// Determinism — same inputs yield same outputs
// =========================================================================

#[test]
fn enrichment_deterministic_evaluation_same_inputs() {
    let epoch = SecurityEpoch::from_raw(1);
    for _ in 0..3 {
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("det-eval", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);
        let region = make_region(
            "r-det",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d = engine.evaluate(&region, "t-det", 42);
        assert!(d.outcome.is_applied());
        assert_eq!(d.trace_id, "t-det");
        assert_eq!(d.timestamp_ns, 42);
        assert_eq!(d.decision_id, "cpe-1");
    }
}

#[test]
fn enrichment_deterministic_proof_id_generation() {
    let id1 = make_proof_id("stable-tag");
    let id2 = make_proof_id("stable-tag");
    assert_eq!(id1, id2);
    assert_eq!(id1.to_hex(), id2.to_hex());
}

// =========================================================================
// OptimizationClass and ProofType — Display, serde, Copy
// =========================================================================

#[test]
fn enrichment_optimization_class_display_exact() {
    assert_eq!(
        format!("{}", OptimizationClass::HostcallDispatchSpecialization),
        "hostcall_dispatch_specialization"
    );
    assert_eq!(
        format!("{}", OptimizationClass::IfcCheckElision),
        "ifc_check_elision"
    );
    assert_eq!(
        format!("{}", OptimizationClass::SuperinstructionFusion),
        "superinstruction_fusion"
    );
    assert_eq!(
        format!("{}", OptimizationClass::PathElimination),
        "path_elimination"
    );
}

#[test]
fn enrichment_optimization_class_serde_roundtrip() {
    let classes = [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ];
    for c in &classes {
        let json = serde_json::to_string(c).unwrap();
        let back: OptimizationClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_optimization_class_serde_distinct() {
    let classes = [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ];
    let jsons: BTreeSet<String> = classes
        .iter()
        .map(|c| serde_json::to_string(c).unwrap())
        .collect();
    assert_eq!(jsons.len(), 4);
}

#[test]
fn enrichment_optimization_class_copy_semantics() {
    let a = OptimizationClass::HostcallDispatchSpecialization;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_proof_type_display_exact() {
    assert_eq!(
        format!("{}", ProofType::CapabilityWitness),
        "capability_witness"
    );
    assert_eq!(format!("{}", ProofType::FlowProof), "flow_proof");
    assert_eq!(format!("{}", ProofType::ReplayMotif), "replay_motif");
}

#[test]
fn enrichment_proof_type_serde_roundtrip() {
    let types = [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn enrichment_proof_type_serde_distinct() {
    let types = [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ];
    let jsons: BTreeSet<String> = types
        .iter()
        .map(|t| serde_json::to_string(t).unwrap())
        .collect();
    assert_eq!(jsons.len(), 3);
}

#[test]
fn enrichment_proof_type_copy_semantics() {
    let a = ProofType::CapabilityWitness;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// ProofInput — serde (from proof_specialization_receipt)
// =========================================================================

#[test]
fn enrichment_proof_input_serde_roundtrip() {
    let input = ProofInput {
        proof_type: ProofType::CapabilityWitness,
        proof_id: make_proof_id("pi-serde"),
        proof_epoch: SecurityEpoch::from_raw(5),
        validity_window_ticks: 1000,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: ProofInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn enrichment_proof_input_field_names() {
    let input = ProofInput {
        proof_type: ProofType::FlowProof,
        proof_id: make_proof_id("pi-fn"),
        proof_epoch: SecurityEpoch::from_raw(1),
        validity_window_ticks: 500,
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains("\"proof_type\""));
    assert!(json.contains("\"proof_id\""));
    assert!(json.contains("\"proof_epoch\""));
    assert!(json.contains("\"validity_window_ticks\""));
}

// =========================================================================
// Full workflow: register -> evaluate -> epoch change -> re-register -> evaluate
// =========================================================================

#[test]
fn enrichment_full_lifecycle_workflow() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut engine = default_engine(e1);

    // Phase 1: Register proofs and evaluate
    let cw = cap_witness_proof("lc-cw", e1);
    let fp = flow_proof("lc-fp", e1);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    engine.register_proof(cw);
    engine.register_proof(fp);

    let r1 = make_region(
        "r-lc-1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![cw_id.clone()],
    );
    let d1 = engine.evaluate(&r1, "t-lc-1", 1000);
    assert!(d1.outcome.is_applied());

    let r2 = make_region(
        "r-lc-2",
        OptimizationClass::IfcCheckElision,
        vec![fp_id.clone()],
    );
    let d2 = engine.evaluate(&r2, "t-lc-2", 2000);
    assert!(d2.outcome.is_applied());

    assert_eq!(engine.applied_count(), 2);
    assert_eq!(engine.rejected_count(), 0);

    // Phase 2: Epoch change
    let invalidated = engine.on_epoch_change(e1, e2, "t-ec", 3000);
    assert_eq!(invalidated.len(), 2);
    assert!(engine.proof_store().is_empty());
    assert_eq!(engine.config().current_epoch, e2);

    // Phase 3: Old proofs no longer work
    let d3 = engine.evaluate(&r1, "t-lc-3", 4000);
    assert_eq!(d3.outcome, SpecializationOutcome::RejectedProofNotFound);

    // Phase 4: Register new proofs at new epoch
    let new_cw = cap_witness_proof("lc-cw-new", e2);
    let new_cw_id = new_cw.proof_id().clone();
    engine.register_proof(new_cw);

    let r3 = make_region(
        "r-lc-3",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![new_cw_id],
    );
    let d4 = engine.evaluate(&r3, "t-lc-4", 5000);
    assert!(d4.outcome.is_applied());

    // Verify audit trail
    assert_eq!(engine.applied_count(), 3);
    assert_eq!(engine.rejected_count(), 1);
    assert_eq!(engine.decisions().len(), 4);
    // events: 2 applied + 1 epoch_change + 1 rejected + 1 applied = 5
    assert!(engine.events().len() >= 5);
}

// =========================================================================
// Governance-approved policy interactions
// =========================================================================

#[test]
fn enrichment_governance_approved_with_all_required_types() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("gov-ok", epoch);
    config.class_policies.insert(
        OptimizationClass::SuperinstructionFusion,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 3,
            required_proof_types: BTreeSet::from([
                ProofType::CapabilityWitness,
                ProofType::FlowProof,
                ProofType::ReplayMotif,
            ]),
            governance_approved: true,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let cw = cap_witness_proof("gov-cw", epoch);
    let fp = flow_proof("gov-fp", epoch);
    let rm = replay_motif_proof("gov-rm", epoch);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    let rm_id = rm.proof_id().clone();
    engine.register_proof(cw);
    engine.register_proof(fp);
    engine.register_proof(rm);

    let region = make_region(
        "r-gov",
        OptimizationClass::SuperinstructionFusion,
        vec![cw_id, fp_id, rm_id],
    );
    let d = engine.evaluate(&region, "t-gov", 0);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 3);
}

// =========================================================================
// Global disable overrides all other checks
// =========================================================================

#[test]
fn enrichment_global_disable_overrides_even_with_valid_proofs_and_policy() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("gd-override", epoch);
    config.global_disable = true;
    config.class_policies.insert(
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 1,
            required_proof_types: BTreeSet::new(),
            governance_approved: true,
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let proof = cap_witness_proof("gd-o", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-gd-o",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = engine.evaluate(&region, "t-gd-o", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
}

// =========================================================================
// Policy priority: global > class > proofs > types > epoch > validity
// =========================================================================

#[test]
fn enrichment_rejection_priority_global_before_class() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("pri-gc", epoch);
    config.global_disable = true;
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let region = make_region("r-pri", OptimizationClass::PathElimination, vec![]);
    let d = engine.evaluate(&region, "t-pri", 0);
    // Global disable takes priority over class disabled
    assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
}

#[test]
fn enrichment_rejection_priority_class_before_no_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("pri-cn", epoch);
    config.class_policies.insert(
        OptimizationClass::IfcCheckElision,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut engine = CompilerPolicyEngine::new(config);
    let region = make_region("r-pri-cn", OptimizationClass::IfcCheckElision, vec![]);
    let d = engine.evaluate(&region, "t-pri-cn", 0);
    // Class disabled takes priority over no proofs
    assert_eq!(d.outcome, SpecializationOutcome::RejectedClassDisabled);
}

// =========================================================================
// Multiple epoch changes
// =========================================================================

#[test]
fn enrichment_multiple_epoch_changes() {
    let mut engine = default_engine(SecurityEpoch::from_raw(1));
    for i in 1..=5u64 {
        let epoch = SecurityEpoch::from_raw(i);
        let proof = cap_witness_proof(&format!("mec-{i}"), epoch);
        engine.register_proof(proof);
    }
    assert_eq!(engine.proof_store().len(), 5);

    // Invalidate epochs 1 through 4
    for i in 1..=4u64 {
        engine.on_epoch_change(
            SecurityEpoch::from_raw(i),
            SecurityEpoch::from_raw(i + 1),
            &format!("t-mec-{i}"),
            i * 1000,
        );
    }
    // Only epoch 5 proof should remain
    assert_eq!(engine.proof_store().len(), 1);
    assert_eq!(engine.config().current_epoch, SecurityEpoch::from_raw(5));
}

// =========================================================================
// Large batch of proofs
// =========================================================================

#[test]
fn enrichment_large_proof_batch() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let mut ids = Vec::new();
    for i in 0..50 {
        let proof = cap_witness_proof(&format!("batch-{i}"), epoch);
        ids.push(proof.proof_id().clone());
        engine.register_proof(proof);
    }
    assert_eq!(engine.proof_store().len(), 50);

    // Evaluate with the first proof
    let region = make_region(
        "r-batch",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![ids[0].clone()],
    );
    let d = engine.evaluate(&region, "t-batch", 0);
    assert!(d.outcome.is_applied());

    // Invalidate all
    let removed = engine.on_epoch_change(epoch, SecurityEpoch::from_raw(2), "t-batch-ec", 1000);
    assert_eq!(removed.len(), 50);
    assert!(engine.proof_store().is_empty());
}

// =========================================================================
// Same region evaluated multiple times
// =========================================================================

#[test]
fn enrichment_same_region_evaluated_multiple_times() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut engine = default_engine(epoch);
    let proof = cap_witness_proof("same-r", epoch);
    let pid = proof.proof_id().clone();
    engine.register_proof(proof);

    let region = make_region(
        "r-same",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    for i in 0..5 {
        let d = engine.evaluate(&region, &format!("t-same-{i}"), i as u64 * 100);
        assert!(d.outcome.is_applied());
    }
    assert_eq!(engine.decisions_for_region("r-same").len(), 5);
    assert_eq!(engine.applied_count(), 5);
}
