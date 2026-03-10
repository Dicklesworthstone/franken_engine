//! Comprehensive integration tests for `compiler_policy`.
//!
//! Covers: SecurityProof (all variants, accessors, proof_type, to_proof_input),
//! MarkedRegion, OptimizationClassPolicy (default, custom, serde),
//! CompilerPolicyConfig (new, class_policy fallback, global_disable, serde),
//! SpecializationOutcome (is_applied, error_code, uniqueness, serde),
//! SpecializationDecision (field population, serde),
//! CompilerPolicyEvent (serde, error_code presence),
//! ProofStore (insert, get, remove, len, is_empty, resolve, invalidate_epoch),
//! CompilerPolicyEngine (evaluate all 7 rejection paths + applied, register_proof,
//! on_epoch_change, last_applied_proof_inputs, decisions_for_region,
//! applied_count, rejected_count, accessors, multi-evaluate accumulation).

#![forbid(unsafe_code)]
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

use frankenengine_engine::compiler_policy::{
    CompilerPolicyConfig, CompilerPolicyEngine, CompilerPolicyEvent, MarkedRegion,
    OptimizationClassPolicy, ProofStore, SecurityProof, SpecializationDecision,
    SpecializationOutcome,
};
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::proof_specialization_receipt::{OptimizationClass, ProofType};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn schema_id() -> SchemaId {
    SchemaId::from_definition(b"CompilerPolicy.v1")
}

fn make_id(tag: &str) -> EngineObjectId {
    derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn cap_proof(tag: &str, epoch: SecurityEpoch, window: u64) -> SecurityProof {
    SecurityProof::CapabilityWitness {
        proof_id: make_id(tag),
        capability_name: format!("cap_{tag}"),
        epoch,
        validity_window_ticks: window,
    }
}

fn flow_proof(tag: &str, epoch: SecurityEpoch, window: u64) -> SecurityProof {
    SecurityProof::FlowProof {
        proof_id: make_id(tag),
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        epoch,
        validity_window_ticks: window,
    }
}

fn motif_proof(tag: &str, epoch: SecurityEpoch, window: u64) -> SecurityProof {
    SecurityProof::ReplayMotif {
        proof_id: make_id(tag),
        motif_hash: format!("motif_{tag}"),
        epoch,
        validity_window_ticks: window,
    }
}

fn region(id: &str, class: OptimizationClass, proof_ids: Vec<EngineObjectId>) -> MarkedRegion {
    MarkedRegion {
        region_id: id.to_string(),
        optimization_class: class,
        proof_refs: proof_ids,
        elided_check_description: format!("elide check in {id}"),
    }
}

fn engine_at(epoch: SecurityEpoch) -> CompilerPolicyEngine {
    CompilerPolicyEngine::new(CompilerPolicyConfig::new("integ-policy", epoch))
}

fn e(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ── Section 1: SecurityProof accessors ──────────────────────────────────────

#[test]
fn security_proof_capability_witness_accessors() {
    let epoch = e(7);
    let p = cap_proof("cw1", epoch, 1000);
    assert_eq!(*p.proof_id(), make_id("cw1"));
    assert_eq!(p.epoch(), epoch);
    assert_eq!(p.validity_window_ticks(), 1000);
    assert_eq!(p.proof_type(), ProofType::CapabilityWitness);
}

#[test]
fn security_proof_flow_proof_accessors() {
    let epoch = e(8);
    let p = flow_proof("fp1", epoch, 500);
    assert_eq!(*p.proof_id(), make_id("fp1"));
    assert_eq!(p.epoch(), epoch);
    assert_eq!(p.validity_window_ticks(), 500);
    assert_eq!(p.proof_type(), ProofType::FlowProof);
}

#[test]
fn security_proof_replay_motif_accessors() {
    let epoch = e(9);
    let p = motif_proof("rm1", epoch, 2000);
    assert_eq!(*p.proof_id(), make_id("rm1"));
    assert_eq!(p.epoch(), epoch);
    assert_eq!(p.validity_window_ticks(), 2000);
    assert_eq!(p.proof_type(), ProofType::ReplayMotif);
}

#[test]
fn security_proof_clone_eq() {
    let p = cap_proof("clone-test", e(1), 100);
    let p2 = p.clone();
    assert_eq!(p, p2);
}

// ── Section 2: SecurityProof serde round-trips ──────────────────────────────

#[test]
fn serde_capability_witness_roundtrip() {
    let p = cap_proof("serde-cw", e(3), 999);
    let json = serde_json::to_string(&p).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_flow_proof_roundtrip() {
    let p = flow_proof("serde-fp", e(4), 500);
    let json = serde_json::to_string(&p).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_replay_motif_roundtrip() {
    let p = motif_proof("serde-rm", e(5), 1500);
    let json = serde_json::to_string(&p).unwrap();
    let back: SecurityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ── Section 3: MarkedRegion ─────────────────────────────────────────────────

#[test]
fn marked_region_fields_accessible() {
    let id = make_id("rgn1");
    let r = MarkedRegion {
        region_id: "region-42".to_string(),
        optimization_class: OptimizationClass::PathElimination,
        proof_refs: vec![id.clone()],
        elided_check_description: "elide path check".to_string(),
    };
    assert_eq!(r.region_id, "region-42");
    assert_eq!(r.optimization_class, OptimizationClass::PathElimination);
    assert_eq!(r.proof_refs, vec![id]);
    assert_eq!(r.elided_check_description, "elide path check");
}

#[test]
fn marked_region_serde_roundtrip() {
    let r = region(
        "r-serde",
        OptimizationClass::IfcCheckElision,
        vec![make_id("x")],
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: MarkedRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn marked_region_empty_proof_refs() {
    let r = region("empty", OptimizationClass::SuperinstructionFusion, vec![]);
    assert!(r.proof_refs.is_empty());
}

// ── Section 4: OptimizationClassPolicy ──────────────────────────────────────

#[test]
fn optimization_class_policy_default_values() {
    let p = OptimizationClassPolicy::default();
    assert!(p.enabled);
    assert_eq!(p.min_proof_count, 1);
    assert!(p.required_proof_types.is_empty());
    assert!(!p.governance_approved);
}

#[test]
fn optimization_class_policy_serde_roundtrip() {
    let mut required = BTreeSet::new();
    required.insert(ProofType::CapabilityWitness);
    required.insert(ProofType::FlowProof);
    let p = OptimizationClassPolicy {
        enabled: true,
        min_proof_count: 3,
        required_proof_types: required,
        governance_approved: true,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: OptimizationClassPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ── Section 5: CompilerPolicyConfig ─────────────────────────────────────────

#[test]
fn config_new_defaults() {
    let cfg = CompilerPolicyConfig::new("pol-1", e(42));
    assert_eq!(cfg.policy_id, "pol-1");
    assert_eq!(cfg.current_epoch, e(42));
    assert!(!cfg.global_disable);
    assert!(cfg.class_policies.is_empty());
}

#[test]
fn config_serde_roundtrip() {
    let mut cfg = CompilerPolicyConfig::new("pol-serde", e(10));
    cfg.global_disable = true;
    cfg.class_policies.insert(
        OptimizationClass::IfcCheckElision,
        OptimizationClassPolicy {
            enabled: false,
            min_proof_count: 2,
            required_proof_types: BTreeSet::from([ProofType::FlowProof]),
            governance_approved: true,
        },
    );
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_with_multiple_class_policies() {
    let mut cfg = CompilerPolicyConfig::new("multi", e(1));
    cfg.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    cfg.class_policies.insert(
        OptimizationClass::SuperinstructionFusion,
        OptimizationClassPolicy {
            min_proof_count: 5,
            ..Default::default()
        },
    );
    assert_eq!(cfg.class_policies.len(), 2);
}

// ── Section 6: SpecializationOutcome ────────────────────────────────────────

#[test]
fn outcome_is_applied_only_for_applied() {
    assert!(SpecializationOutcome::Applied.is_applied());
    let others = [
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
    for o in &others {
        assert!(!o.is_applied(), "{:?} should not be applied", o);
    }
}

#[test]
fn outcome_error_codes_are_unique() {
    let all = [
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
    let codes: BTreeSet<&str> = all.iter().map(|o| o.error_code()).collect();
    assert_eq!(codes.len(), 10);
}

#[test]
fn outcome_specific_error_codes() {
    assert_eq!(SpecializationOutcome::Applied.error_code(), "APPLIED");
    assert_eq!(
        SpecializationOutcome::RejectedGlobalDisable.error_code(),
        "GLOBAL_DISABLE"
    );
    assert_eq!(
        SpecializationOutcome::RejectedClassDisabled.error_code(),
        "CLASS_DISABLED"
    );
    assert_eq!(
        SpecializationOutcome::RejectedNoProofs.error_code(),
        "NO_PROOFS"
    );
    assert_eq!(
        SpecializationOutcome::RejectedInsufficientProofs.error_code(),
        "INSUFFICIENT_PROOFS"
    );
    assert_eq!(
        SpecializationOutcome::RejectedMissingRequiredProofTypes.error_code(),
        "MISSING_REQUIRED_PROOF_TYPES"
    );
    assert_eq!(
        SpecializationOutcome::RejectedProofExpired.error_code(),
        "PROOF_EXPIRED"
    );
    assert_eq!(
        SpecializationOutcome::RejectedEpochMismatch.error_code(),
        "EPOCH_MISMATCH"
    );
    assert_eq!(
        SpecializationOutcome::RejectedProofNotFound.error_code(),
        "PROOF_NOT_FOUND"
    );
    assert_eq!(
        SpecializationOutcome::InvalidatedByEpochChange.error_code(),
        "INVALIDATED_EPOCH_CHANGE"
    );
}

#[test]
fn outcome_serde_roundtrip_all_variants() {
    let all = [
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
    for o in &all {
        let json = serde_json::to_string(o).unwrap();
        let back: SpecializationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn outcome_debug_format() {
    let dbg = format!("{:?}", SpecializationOutcome::Applied);
    assert_eq!(dbg, "Applied");
    let dbg2 = format!("{:?}", SpecializationOutcome::RejectedGlobalDisable);
    assert_eq!(dbg2, "RejectedGlobalDisable");
}

// ── Section 7: SpecializationDecision serde ─────────────────────────────────

#[test]
fn decision_serde_roundtrip() {
    let d = SpecializationDecision {
        trace_id: "t1".to_string(),
        decision_id: "cpe-1".to_string(),
        policy_id: "p1".to_string(),
        region_id: "r1".to_string(),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        outcome: SpecializationOutcome::Applied,
        detail: "ok".to_string(),
        proof_ids: vec![make_id("x")],
        epoch: e(1),
        timestamp_ns: 999,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: SpecializationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ── Section 8: CompilerPolicyEvent serde ────────────────────────────────────

#[test]
fn event_serde_roundtrip_no_error() {
    let ev = CompilerPolicyEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_applied".to_string(),
        outcome: "APPLIED".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
    assert!(back.error_code.is_none());
}

#[test]
fn event_serde_roundtrip_with_error() {
    let ev = CompilerPolicyEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_rejected".to_string(),
        outcome: "NO_PROOFS".to_string(),
        error_code: Some("NO_PROOFS".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
    assert_eq!(back.error_code.as_deref(), Some("NO_PROOFS"));
}

// ── Section 9: ProofStore ───────────────────────────────────────────────────

#[test]
fn proof_store_new_is_empty() {
    let s = ProofStore::new();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn proof_store_insert_and_get() {
    let mut s = ProofStore::new();
    let p = cap_proof("ps1", e(1), 100);
    let pid = p.proof_id().clone();
    s.insert(p.clone());
    assert_eq!(s.len(), 1);
    assert!(!s.is_empty());
    let got = s.get(&pid).unwrap();
    assert_eq!(got, &p);
}

#[test]
fn proof_store_remove() {
    let mut s = ProofStore::new();
    let p = cap_proof("rm", e(1), 100);
    let pid = p.proof_id().clone();
    s.insert(p);
    let removed = s.remove(&pid).unwrap();
    assert_eq!(removed.proof_id(), &pid);
    assert!(s.is_empty());
    assert!(s.remove(&pid).is_none());
}

#[test]
fn proof_store_get_nonexistent_returns_none() {
    let s = ProofStore::new();
    assert!(s.get(&make_id("ghost")).is_none());
}

#[test]
fn proof_store_resolve_full() {
    let mut s = ProofStore::new();
    let p1 = cap_proof("r1", e(1), 100);
    let p2 = flow_proof("r2", e(1), 200);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    s.insert(p1);
    s.insert(p2);
    let resolved = s.resolve(&[id1, id2]);
    assert_eq!(resolved.len(), 2);
}

#[test]
fn proof_store_resolve_partial() {
    let mut s = ProofStore::new();
    let p = cap_proof("rp1", e(1), 100);
    let id = p.proof_id().clone();
    s.insert(p);
    let resolved = s.resolve(&[id, make_id("missing")]);
    assert_eq!(resolved.len(), 1);
}

#[test]
fn proof_store_resolve_empty_input() {
    let s = ProofStore::new();
    assert!(s.resolve(&[]).is_empty());
}

#[test]
fn proof_store_invalidate_epoch_selective() {
    let mut s = ProofStore::new();
    s.insert(cap_proof("a", e(1), 100));
    s.insert(cap_proof("b", e(1), 200));
    s.insert(cap_proof("c", e(2), 300));
    assert_eq!(s.len(), 3);
    let inv = s.invalidate_epoch(e(1));
    assert_eq!(inv.len(), 2);
    assert_eq!(s.len(), 1);
}

#[test]
fn proof_store_invalidate_epoch_no_match() {
    let mut s = ProofStore::new();
    s.insert(cap_proof("x", e(5), 100));
    let inv = s.invalidate_epoch(e(99));
    assert!(inv.is_empty());
    assert_eq!(s.len(), 1);
}

#[test]
fn proof_store_insert_and_len() {
    // NOTE: ProofStore uses BTreeMap<EngineObjectId, _> internally,
    // which does not support JSON serde (key must be a string).
    // We test the API instead.
    let mut s = ProofStore::new();
    assert_eq!(s.len(), 0);
    s.insert(cap_proof("s1", e(1), 100));
    assert_eq!(s.len(), 1);
    s.insert(flow_proof("s2", e(2), 200));
    assert_eq!(s.len(), 2);
}

// ── Section 10: CompilerPolicyEngine — happy path ───────────────────────────

#[test]
fn evaluate_applied_with_capability_witness() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("apply-cw", e(1), 1000);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid.clone()],
    );
    let d = eng.evaluate(&r, "t1", 100);
    assert_eq!(d.outcome, SpecializationOutcome::Applied);
    assert_eq!(d.proof_ids, vec![pid]);
    assert_eq!(eng.applied_count(), 1);
    assert_eq!(eng.rejected_count(), 0);
}

#[test]
fn evaluate_applied_with_flow_proof() {
    let mut eng = engine_at(e(2));
    let p = flow_proof("apply-fp", e(2), 500);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-fp", OptimizationClass::IfcCheckElision, vec![pid]);
    let d = eng.evaluate(&r, "t1", 200);
    assert!(d.outcome.is_applied());
}

#[test]
fn evaluate_applied_with_replay_motif() {
    let mut eng = engine_at(e(3));
    let p = motif_proof("apply-rm", e(3), 2000);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-rm", OptimizationClass::SuperinstructionFusion, vec![pid]);
    let d = eng.evaluate(&r, "t1", 300);
    assert!(d.outcome.is_applied());
}

#[test]
fn evaluate_applied_multiple_mixed_proofs() {
    let mut eng = engine_at(e(1));
    let cw = cap_proof("mix-cw", e(1), 100);
    let fp = flow_proof("mix-fp", e(1), 200);
    let rm = motif_proof("mix-rm", e(1), 300);
    let ids: Vec<EngineObjectId> = vec![
        cw.proof_id().clone(),
        fp.proof_id().clone(),
        rm.proof_id().clone(),
    ];
    eng.register_proof(cw);
    eng.register_proof(fp);
    eng.register_proof(rm);
    let r = region(
        "r-mix",
        OptimizationClass::SuperinstructionFusion,
        ids.clone(),
    );
    let d = eng.evaluate(&r, "t1", 400);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 3);
}

// ── Section 11: Engine — rejection paths ────────────────────────────────────

#[test]
fn reject_global_disable() {
    let mut cfg = CompilerPolicyConfig::new("disabled", e(1));
    cfg.global_disable = true;
    let mut eng = CompilerPolicyEngine::new(cfg);
    let p = cap_proof("gd", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r1", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
}

#[test]
fn reject_class_disabled() {
    let mut cfg = CompilerPolicyConfig::new("cls-off", e(1));
    cfg.class_policies.insert(
        OptimizationClass::IfcCheckElision,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut eng = CompilerPolicyEngine::new(cfg);
    let p = flow_proof("cd", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-cd", OptimizationClass::IfcCheckElision, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedClassDisabled);
}

#[test]
fn reject_no_proofs() {
    let mut eng = engine_at(e(1));
    let r = region("r-np", OptimizationClass::PathElimination, vec![]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedNoProofs);
}

#[test]
fn reject_proof_not_found() {
    let mut eng = engine_at(e(1));
    let r = region(
        "r-pnf",
        OptimizationClass::PathElimination,
        vec![make_id("ghost")],
    );
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofNotFound);
}

#[test]
fn reject_insufficient_proofs() {
    let mut cfg = CompilerPolicyConfig::new("min3", e(1));
    cfg.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            min_proof_count: 3,
            ..Default::default()
        },
    );
    let mut eng = CompilerPolicyEngine::new(cfg);
    let p = cap_proof("ip1", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-ip", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedInsufficientProofs);
}

#[test]
fn reject_missing_required_proof_types() {
    let mut cfg = CompilerPolicyConfig::new("reqtypes", e(1));
    cfg.class_policies.insert(
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
    let mut eng = CompilerPolicyEngine::new(cfg);
    // Only provide CapabilityWitness, missing FlowProof
    let p = cap_proof("mrpt", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region(
        "r-mrpt",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(
        d.outcome,
        SpecializationOutcome::RejectedMissingRequiredProofTypes
    );
}

#[test]
fn reject_epoch_mismatch() {
    let mut eng = engine_at(e(5));
    let p = cap_proof("em", e(3), 100); // epoch 3 != current 5
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-em", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedEpochMismatch);
}

#[test]
fn reject_proof_expired() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("exp", e(1), 0); // validity_window_ticks == 0
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-exp", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
}

// ── Section 12: Engine — epoch change ───────────────────────────────────────

#[test]
fn epoch_change_invalidates_old_proofs() {
    let mut eng = engine_at(e(1));
    eng.register_proof(cap_proof("ec1", e(1), 100));
    eng.register_proof(cap_proof("ec2", e(1), 200));
    assert_eq!(eng.proof_store().len(), 2);
    let inv = eng.on_epoch_change(e(1), e(2), "t-ec", 5000);
    assert_eq!(inv.len(), 2);
    assert!(eng.proof_store().is_empty());
    assert_eq!(eng.config().current_epoch, e(2));
}

#[test]
fn epoch_change_preserves_new_epoch_proofs() {
    let mut eng = engine_at(e(1));
    eng.register_proof(cap_proof("old", e(1), 100));
    eng.register_proof(cap_proof("new", e(2), 200));
    let inv = eng.on_epoch_change(e(1), e(2), "t-ec", 5000);
    assert_eq!(inv.len(), 1);
    assert_eq!(eng.proof_store().len(), 1);
}

#[test]
fn epoch_change_emits_event_when_proofs_invalidated() {
    let mut eng = engine_at(e(1));
    eng.register_proof(cap_proof("ev-ec", e(1), 100));
    let events_before = eng.events().len();
    eng.on_epoch_change(e(1), e(2), "t-ec", 5000);
    assert!(eng.events().len() > events_before);
    let last = eng.events().last().unwrap();
    assert_eq!(last.event, "epoch_change_invalidation");
    assert_eq!(last.error_code.as_deref(), Some("INVALIDATED_EPOCH_CHANGE"));
}

#[test]
fn epoch_change_no_event_when_nothing_invalidated() {
    let mut eng = engine_at(e(1));
    let events_before = eng.events().len();
    eng.on_epoch_change(e(1), e(2), "t-ec", 5000);
    assert_eq!(eng.events().len(), events_before);
}

#[test]
fn after_epoch_change_old_proofs_cannot_justify() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("aec", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region(
        "r-aec",
        OptimizationClass::PathElimination,
        vec![pid.clone()],
    );

    let d1 = eng.evaluate(&r, "t1", 100);
    assert!(d1.outcome.is_applied());

    eng.on_epoch_change(e(1), e(2), "t-ec", 200);
    let d2 = eng.evaluate(&r, "t2", 300);
    assert_eq!(d2.outcome, SpecializationOutcome::RejectedProofNotFound);
}

#[test]
fn re_evaluate_with_new_proofs_after_epoch_change() {
    let mut eng = engine_at(e(1));
    let old = cap_proof("old-p", e(1), 100);
    let old_id = old.proof_id().clone();
    eng.register_proof(old);

    let r = region("r-renew", OptimizationClass::PathElimination, vec![old_id]);
    let d1 = eng.evaluate(&r, "t1", 100);
    assert!(d1.outcome.is_applied());

    eng.on_epoch_change(e(1), e(2), "t-ec", 200);

    let fresh = cap_proof("new-p", e(2), 500);
    let fresh_id = fresh.proof_id().clone();
    eng.register_proof(fresh);
    let r2 = region(
        "r-renew",
        OptimizationClass::PathElimination,
        vec![fresh_id],
    );
    let d2 = eng.evaluate(&r2, "t2", 300);
    assert!(d2.outcome.is_applied());
}

// ── Section 13: Engine — last_applied_proof_inputs ──────────────────────────

#[test]
fn last_applied_proof_inputs_returns_some() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("lapi", e(1), 777);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-lapi", OptimizationClass::PathElimination, vec![pid]);
    eng.evaluate(&r, "t1", 100);
    let inputs = eng.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
    assert_eq!(inputs[0].validity_window_ticks, 777);
    assert_eq!(inputs[0].proof_epoch, e(1));
}

#[test]
fn last_applied_proof_inputs_none_when_only_rejections() {
    let mut eng = engine_at(e(1));
    let r = region("r-none", OptimizationClass::PathElimination, vec![]);
    eng.evaluate(&r, "t1", 100);
    assert!(eng.last_applied_proof_inputs().is_none());
}

#[test]
fn last_applied_proof_inputs_finds_most_recent_applied() {
    let mut eng = engine_at(e(1));
    let p1 = cap_proof("lapi1", e(1), 100);
    let p2 = cap_proof("lapi2", e(1), 999);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    eng.register_proof(p1);
    eng.register_proof(p2);

    let r1 = region("r1", OptimizationClass::PathElimination, vec![id1]);
    eng.evaluate(&r1, "t1", 100);

    // Rejected in between
    let r_bad = region("r-bad", OptimizationClass::PathElimination, vec![]);
    eng.evaluate(&r_bad, "t2", 200);

    let r2 = region("r2", OptimizationClass::PathElimination, vec![id2]);
    eng.evaluate(&r2, "t3", 300);

    let inputs = eng.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].validity_window_ticks, 999);
}

// ── Section 14: Engine — decisions_for_region ───────────────────────────────

#[test]
fn decisions_for_region_filtering() {
    let mut eng = engine_at(e(1));
    let p1 = cap_proof("dfr1", e(1), 100);
    let p2 = cap_proof("dfr2", e(1), 200);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    eng.register_proof(p1);
    eng.register_proof(p2);

    let ra = region("A", OptimizationClass::PathElimination, vec![id1.clone()]);
    let rb = region("B", OptimizationClass::PathElimination, vec![id2]);
    eng.evaluate(&ra, "t1", 100);
    eng.evaluate(&rb, "t2", 200);
    eng.evaluate(&ra, "t3", 300);

    assert_eq!(eng.decisions_for_region("A").len(), 2);
    assert_eq!(eng.decisions_for_region("B").len(), 1);
    assert_eq!(eng.decisions_for_region("C").len(), 0);
}

// ── Section 15: Engine — counters and accumulation ──────────────────────────

#[test]
fn applied_and_rejected_counts() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("cnt", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    let r_ok = region("ok", OptimizationClass::PathElimination, vec![pid]);
    eng.evaluate(&r_ok, "t1", 100);
    assert_eq!(eng.applied_count(), 1);
    assert_eq!(eng.rejected_count(), 0);

    let r_bad = region("bad", OptimizationClass::PathElimination, vec![]);
    eng.evaluate(&r_bad, "t2", 200);
    assert_eq!(eng.applied_count(), 1);
    assert_eq!(eng.rejected_count(), 1);
}

#[test]
fn multiple_evaluations_accumulate_decisions_and_events() {
    let mut eng = engine_at(e(1));
    for i in 0..5 {
        let tag = format!("acc-{i}");
        let p = cap_proof(&tag, e(1), 100);
        let pid = p.proof_id().clone();
        eng.register_proof(p);
        let r = region(
            &format!("r-{i}"),
            OptimizationClass::PathElimination,
            vec![pid],
        );
        eng.evaluate(&r, &format!("t-{i}"), i as u64 * 100);
    }
    assert_eq!(eng.applied_count(), 5);
    assert_eq!(eng.decisions().len(), 5);
    assert_eq!(eng.events().len(), 5);
}

// ── Section 16: Engine — decision field correctness ─────────────────────────

#[test]
fn decision_fields_populated_correctly() {
    let mut eng = engine_at(e(10));
    let p = cap_proof("df", e(10), 1000);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region(
        "r-df",
        OptimizationClass::IfcCheckElision,
        vec![pid.clone()],
    );
    let d = eng.evaluate(&r, "trace-99", 42_000);

    assert_eq!(d.trace_id, "trace-99");
    assert!(d.decision_id.starts_with("cpe-"));
    assert_eq!(d.policy_id, "integ-policy");
    assert_eq!(d.region_id, "r-df");
    assert_eq!(d.optimization_class, OptimizationClass::IfcCheckElision);
    assert_eq!(d.epoch, e(10));
    assert_eq!(d.timestamp_ns, 42_000);
    assert_eq!(d.proof_ids, vec![pid]);
}

// ── Section 17: Engine — event structure ────────────────────────────────────

#[test]
fn applied_event_structure() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("ev-ok", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-ev", OptimizationClass::PathElimination, vec![pid]);
    eng.evaluate(&r, "trace-ev", 100);

    let ev = &eng.events()[0];
    assert_eq!(ev.trace_id, "trace-ev");
    assert_eq!(ev.policy_id, "integ-policy");
    assert_eq!(ev.component, "compiler_policy");
    assert_eq!(ev.event, "specialization_applied");
    assert_eq!(ev.outcome, "APPLIED");
    assert!(ev.error_code.is_none());
}

#[test]
fn rejected_event_has_error_code() {
    let mut eng = engine_at(e(1));
    let r = region("r-rej", OptimizationClass::PathElimination, vec![]);
    eng.evaluate(&r, "trace-rej", 100);

    let ev = &eng.events()[0];
    assert_eq!(ev.event, "specialization_rejected");
    assert_eq!(ev.error_code.as_deref(), Some("NO_PROOFS"));
}

// ── Section 18: Engine — accessors ──────────────────────────────────────────

#[test]
fn engine_config_accessor() {
    let eng = engine_at(e(42));
    assert_eq!(eng.config().current_epoch, e(42));
    assert_eq!(eng.config().policy_id, "integ-policy");
    assert!(!eng.config().global_disable);
}

#[test]
fn engine_proof_store_accessor() {
    let eng = engine_at(e(1));
    assert!(eng.proof_store().is_empty());
}

#[test]
fn engine_proof_store_mut_accessor() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("mut-acc", e(1), 100);
    eng.proof_store_mut().insert(p);
    assert_eq!(eng.proof_store().len(), 1);
}

#[test]
fn engine_decisions_empty_initially() {
    let eng = engine_at(e(1));
    assert!(eng.decisions().is_empty());
}

#[test]
fn engine_events_empty_initially() {
    let eng = engine_at(e(1));
    assert!(eng.events().is_empty());
}

// ── Section 19: Engine — class policy fallback ──────────────────────────────

#[test]
fn unconfigured_class_uses_default() {
    let mut cfg = CompilerPolicyConfig::new("fallback", e(1));
    cfg.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let eng = CompilerPolicyEngine::new(cfg);

    // Unconfigured class should use default
    let mut eng2 = eng.clone();
    let p = cap_proof("fb", e(1), 100);
    let pid = p.proof_id().clone();
    eng2.register_proof(p);
    let r = region(
        "r-fb",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d = eng2.evaluate(&r, "t1", 100);
    assert!(d.outcome.is_applied());
}

// ── Section 20: Full required-types pass ────────────────────────────────────

#[test]
fn all_required_proof_types_present_applies() {
    let mut cfg = CompilerPolicyConfig::new("reqpass", e(1));
    cfg.class_policies.insert(
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
    let mut eng = CompilerPolicyEngine::new(cfg);
    let cw = cap_proof("rp-cw", e(1), 100);
    let fp = flow_proof("rp-fp", e(1), 200);
    let cw_id = cw.proof_id().clone();
    let fp_id = fp.proof_id().clone();
    eng.register_proof(cw);
    eng.register_proof(fp);

    let r = region(
        "r-rp",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![cw_id, fp_id],
    );
    let d = eng.evaluate(&r, "t1", 100);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 2);
}

// ── Section 21: Decision ID incrementing ────────────────────────────────────

#[test]
fn decision_ids_increment() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("inc", e(1), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    let r = region("r-inc", OptimizationClass::PathElimination, vec![pid]);
    let d1 = eng.evaluate(&r, "t1", 100);
    let d2 = eng.evaluate(&r, "t2", 200);
    assert_eq!(d1.decision_id, "cpe-1");
    assert_eq!(d2.decision_id, "cpe-2");
}

// ── Section 22: Proof not found detail includes missing ID ──────────────────

#[test]
fn proof_not_found_detail_includes_missing_hex() {
    let mut eng = engine_at(e(1));
    let ghost = make_id("ghost-hex");
    let r = region(
        "r-gh",
        OptimizationClass::PathElimination,
        vec![ghost.clone()],
    );
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofNotFound);
    assert!(d.detail.contains(&ghost.to_hex()));
}

// ── Section 23: Epoch mismatch detail shows both epochs ─────────────────────

#[test]
fn epoch_mismatch_detail_shows_epochs() {
    let mut eng = engine_at(e(10));
    let p = cap_proof("emd", e(3), 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-emd", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedEpochMismatch);
    assert!(d.detail.contains("3"));
    assert!(d.detail.contains("10"));
}

// ── Section 24: Expired proof detail ────────────────────────────────────────

#[test]
fn expired_proof_detail_mentions_window_zero() {
    let mut eng = engine_at(e(1));
    let p = cap_proof("expd", e(1), 0);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region("r-expd", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 0);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
    assert!(d.detail.contains("expired"));
    assert!(d.detail.contains("window=0"));
}

// ── Section 25: ProofStore insert overwrites same ID ────────────────────────

#[test]
fn proof_store_insert_overwrites_same_id() {
    let mut s = ProofStore::new();
    let p1 = SecurityProof::CapabilityWitness {
        proof_id: make_id("dup"),
        capability_name: "cap_a".to_string(),
        epoch: e(1),
        validity_window_ticks: 100,
    };
    let p2 = SecurityProof::CapabilityWitness {
        proof_id: make_id("dup"),
        capability_name: "cap_b".to_string(),
        epoch: e(1),
        validity_window_ticks: 999,
    };
    s.insert(p1);
    s.insert(p2);
    assert_eq!(s.len(), 1);
    let got = s.get(&make_id("dup")).unwrap();
    assert_eq!(got.validity_window_ticks(), 999);
}
