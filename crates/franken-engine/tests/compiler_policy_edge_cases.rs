//! Edge-case integration tests for `compiler_policy`.
//!
//! Covers: SecurityProof, MarkedRegion, OptimizationClassPolicy,
//! CompilerPolicyConfig, SpecializationOutcome, SpecializationDecision,
//! CompilerPolicyEvent, ProofStore, CompilerPolicyEngine.

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
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::proof_specialization_receipt::{OptimizationClass, ProofType};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn schema_id() -> SchemaId {
    SchemaId::from_definition(b"CompilerPolicy.v1")
}

fn proof_id(tag: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn cap_proof(tag: &str, epoch: SecurityEpoch, ticks: u64) -> SecurityProof {
    SecurityProof::CapabilityWitness {
        proof_id: proof_id(tag),
        capability_name: format!("cap_{tag}"),
        epoch,
        validity_window_ticks: ticks,
    }
}

fn flow_proof_with_ticks(tag: &str, epoch: SecurityEpoch, ticks: u64) -> SecurityProof {
    SecurityProof::FlowProof {
        proof_id: proof_id(tag),
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        epoch,
        validity_window_ticks: ticks,
    }
}

fn replay_proof(tag: &str, epoch: SecurityEpoch, ticks: u64) -> SecurityProof {
    SecurityProof::ReplayMotif {
        proof_id: proof_id(tag),
        motif_hash: format!("motif_{tag}"),
        epoch,
        validity_window_ticks: ticks,
    }
}

fn region(
    id: &str,
    class: OptimizationClass,
    ids: Vec<frankenengine_engine::engine_object_id::EngineObjectId>,
) -> MarkedRegion {
    MarkedRegion {
        region_id: id.to_string(),
        optimization_class: class,
        proof_refs: ids,
        elided_check_description: format!("elide in {id}"),
    }
}

fn engine(epoch: SecurityEpoch) -> CompilerPolicyEngine {
    CompilerPolicyEngine::new(CompilerPolicyConfig::new("test-policy", epoch))
}

// ── SpecializationOutcome ───────────────────────────────────────────────────

#[test]
fn outcome_serde_all_ten() {
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
        assert_eq!(&back, o);
    }
}

#[test]
fn outcome_copy_semantics() {
    let a = SpecializationOutcome::Applied;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn outcome_error_codes_non_empty() {
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
        assert!(!o.error_code().is_empty());
    }
}

// ── SecurityProof ───────────────────────────────────────────────────────────

#[test]
fn security_proof_serde_all_three_variants() {
    let epoch = SecurityEpoch::from_raw(1);
    let proofs = [
        cap_proof("c1", epoch, 1000),
        flow_proof_with_ticks("f1", epoch, 500),
        replay_proof("r1", epoch, 2000),
    ];
    for p in &proofs {
        let json = serde_json::to_string(p).unwrap();
        let back: SecurityProof = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, p);
    }
}

#[test]
fn security_proof_proof_type_mapping() {
    let epoch = SecurityEpoch::from_raw(1);
    assert_eq!(
        cap_proof("a", epoch, 1).proof_type(),
        ProofType::CapabilityWitness
    );
    assert_eq!(
        flow_proof_with_ticks("b", epoch, 1).proof_type(),
        ProofType::FlowProof
    );
    assert_eq!(
        replay_proof("c", epoch, 1).proof_type(),
        ProofType::ReplayMotif
    );
}

#[test]
fn security_proof_epoch_accessor() {
    let e5 = SecurityEpoch::from_raw(5);
    assert_eq!(cap_proof("x", e5, 100).epoch(), e5);
    assert_eq!(flow_proof_with_ticks("x", e5, 100).epoch(), e5);
    assert_eq!(replay_proof("x", e5, 100).epoch(), e5);
}

#[test]
fn security_proof_validity_window_accessor() {
    let epoch = SecurityEpoch::from_raw(1);
    assert_eq!(cap_proof("x", epoch, 42).validity_window_ticks(), 42);
    assert_eq!(
        flow_proof_with_ticks("x", epoch, 99).validity_window_ticks(),
        99
    );
    assert_eq!(replay_proof("x", epoch, 777).validity_window_ticks(), 777);
}

#[test]
fn security_proof_proof_id_accessor() {
    let epoch = SecurityEpoch::from_raw(1);
    let p = cap_proof("unique_tag", epoch, 1);
    let expected_id = proof_id("unique_tag");
    assert_eq!(p.proof_id(), &expected_id);
}

// ── MarkedRegion ────────────────────────────────────────────────────────────

#[test]
fn marked_region_serde() {
    let r = MarkedRegion {
        region_id: "r1".to_string(),
        optimization_class: OptimizationClass::IfcCheckElision,
        proof_refs: vec![proof_id("a"), proof_id("b")],
        elided_check_description: "elide ifc check".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MarkedRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn marked_region_empty_proof_refs() {
    let r = region("r-empty", OptimizationClass::PathElimination, vec![]);
    assert!(r.proof_refs.is_empty());
}

// ── OptimizationClassPolicy ─────────────────────────────────────────────────

#[test]
fn optimization_class_policy_default() {
    let p = OptimizationClassPolicy::default();
    assert!(p.enabled);
    assert_eq!(p.min_proof_count, 1);
    assert!(p.required_proof_types.is_empty());
    assert!(!p.governance_approved);
}

#[test]
fn optimization_class_policy_serde() {
    let mut required = BTreeSet::new();
    required.insert(ProofType::CapabilityWitness);
    required.insert(ProofType::FlowProof);
    let p = OptimizationClassPolicy {
        enabled: false,
        min_proof_count: 3,
        required_proof_types: required,
        governance_approved: true,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: OptimizationClassPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

// ── CompilerPolicyConfig ────────────────────────────────────────────────────

#[test]
fn config_new_fields() {
    let epoch = SecurityEpoch::from_raw(99);
    let config = CompilerPolicyConfig::new("policy-99", epoch);
    assert_eq!(config.policy_id, "policy-99");
    assert_eq!(config.current_epoch, epoch);
    assert!(!config.global_disable);
    assert!(config.class_policies.is_empty());
}

#[test]
fn config_serde_with_global_disable() {
    let mut config = CompilerPolicyConfig::new("p1", SecurityEpoch::from_raw(1));
    config.global_disable = true;
    let json = serde_json::to_string(&config).unwrap();
    let back: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
    assert!(back.global_disable);
}

#[test]
fn config_serde_with_class_policies() {
    let mut config = CompilerPolicyConfig::new("p1", SecurityEpoch::from_raw(1));
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            min_proof_count: 5,
            required_proof_types: BTreeSet::from([ProofType::ReplayMotif]),
            governance_approved: true,
        },
    );
    let json = serde_json::to_string(&config).unwrap();
    let back: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ── CompilerPolicyEvent ─────────────────────────────────────────────────────

#[test]
fn compiler_policy_event_serde() {
    let event = CompilerPolicyEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_applied".to_string(),
        outcome: "APPLIED".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn compiler_policy_event_with_error_code_serde() {
    let event = CompilerPolicyEvent {
        trace_id: "t2".to_string(),
        decision_id: "d2".to_string(),
        policy_id: "p1".to_string(),
        component: "compiler_policy".to_string(),
        event: "specialization_rejected".to_string(),
        outcome: "EPOCH_MISMATCH".to_string(),
        error_code: Some("EPOCH_MISMATCH".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("EPOCH_MISMATCH".to_string()));
}

// ── SpecializationDecision ──────────────────────────────────────────────────

#[test]
fn specialization_decision_serde() {
    let d = SpecializationDecision {
        trace_id: "t1".to_string(),
        decision_id: "cpe-1".to_string(),
        policy_id: "p1".to_string(),
        region_id: "r1".to_string(),
        optimization_class: OptimizationClass::SuperinstructionFusion,
        outcome: SpecializationOutcome::RejectedProofExpired,
        detail: "expired".to_string(),
        proof_ids: vec![proof_id("x")],
        epoch: SecurityEpoch::from_raw(3),
        timestamp_ns: 12345,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: SpecializationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ── ProofStore ──────────────────────────────────────────────────────────────

#[test]
fn proof_store_empty() {
    let store = ProofStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.get(&proof_id("x")).is_none());
}

#[test]
fn proof_store_insert_duplicate_overwrites() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = cap_proof("same", epoch, 100);
    let p2 = cap_proof("same", epoch, 200); // same tag = same proof_id

    store.insert(p1);
    store.insert(p2);
    assert_eq!(store.len(), 1);
    let stored = store.get(&proof_id("same")).unwrap();
    assert_eq!(stored.validity_window_ticks(), 200); // overwritten
}

#[test]
fn proof_store_resolve_empty_list() {
    let store = ProofStore::new();
    let resolved = store.resolve(&[]);
    assert!(resolved.is_empty());
}

#[test]
fn proof_store_resolve_all_found() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    let p1 = cap_proof("a", epoch, 100);
    let p2 = cap_proof("b", epoch, 200);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    store.insert(p1);
    store.insert(p2);
    let resolved = store.resolve(&[id1, id2]);
    assert_eq!(resolved.len(), 2);
}

#[test]
fn proof_store_invalidate_epoch_no_matching() {
    let mut store = ProofStore::new();
    let epoch = SecurityEpoch::from_raw(1);
    store.insert(cap_proof("a", epoch, 100));
    let invalidated = store.invalidate_epoch(SecurityEpoch::from_raw(99));
    assert!(invalidated.is_empty());
    assert_eq!(store.len(), 1);
}

#[test]
fn proof_store_remove_nonexistent() {
    let mut store = ProofStore::new();
    assert!(store.remove(&proof_id("nope")).is_none());
}

// ProofStore serde is not supported because EngineObjectId as BTreeMap key
// cannot be directly serialized to JSON (non-string keys).

// ── CompilerPolicyEngine ────────────────────────────────────────────────────

#[test]
fn engine_initial_state() {
    let e = engine(SecurityEpoch::from_raw(1));
    assert!(e.decisions().is_empty());
    assert!(e.events().is_empty());
    assert!(e.proof_store().is_empty());
    assert_eq!(e.applied_count(), 0);
    assert_eq!(e.rejected_count(), 0);
}

#[test]
fn engine_decision_counter_increments() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut e = engine(epoch);
    let p = cap_proof("p1", epoch, 100);
    let pid = p.proof_id().clone();
    e.register_proof(p);

    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    let d1 = e.evaluate(&r, "t1", 1000);
    assert_eq!(d1.decision_id, "cpe-1");

    // Rejected (no proofs)
    let r2 = region(
        "r2",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    let d2 = e.evaluate(&r2, "t2", 2000);
    assert_eq!(d2.decision_id, "cpe-2");
}

#[test]
fn engine_decision_counter_across_epoch_change() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut eng = engine(e1);
    let p = cap_proof("p1", e1, 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    eng.evaluate(&r, "t1", 1000); // cpe-1

    eng.on_epoch_change(e1, e2, "t-ec", 2000); // cpe-2 (epoch event)

    let r2 = region(
        "r2",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    let d3 = eng.evaluate(&r2, "t3", 3000);
    assert_eq!(d3.decision_id, "cpe-3");
}

#[test]
fn engine_global_disable_checked_first() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("test", epoch);
    config.global_disable = true;
    // Also disable the class
    config.class_policies.insert(
        OptimizationClass::IfcCheckElision,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut eng = CompilerPolicyEngine::new(config);

    let r = region("r1", OptimizationClass::IfcCheckElision, vec![]);
    let d = eng.evaluate(&r, "t1", 1000);
    // Should be GlobalDisable, not ClassDisabled
    assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
}

#[test]
fn engine_class_disabled_checked_before_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("test", epoch);
    config.class_policies.insert(
        OptimizationClass::PathElimination,
        OptimizationClassPolicy {
            enabled: false,
            ..Default::default()
        },
    );
    let mut eng = CompilerPolicyEngine::new(config);

    let p = cap_proof("p1", epoch, 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    let r = region("r1", OptimizationClass::PathElimination, vec![pid]);
    let d = eng.evaluate(&r, "t1", 1000);
    // Should be ClassDisabled, not Applied (even though proof is valid)
    assert_eq!(d.outcome, SpecializationOutcome::RejectedClassDisabled);
}

#[test]
fn engine_proof_not_found_checked_before_count() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("test", epoch);
    config.class_policies.insert(
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 3,
            ..Default::default()
        },
    );
    let mut eng = CompilerPolicyEngine::new(config);

    // Reference a nonexistent proof
    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![proof_id("nonexistent")],
    );
    let d = eng.evaluate(&r, "t1", 1000);
    // Should be ProofNotFound, not InsufficientProofs
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofNotFound);
}

#[test]
fn engine_one_of_multiple_proofs_expired() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);

    let good = cap_proof("good", epoch, 100);
    let expired = cap_proof("expired", epoch, 0); // ticks=0 → expired
    let gid = good.proof_id().clone();
    let eid = expired.proof_id().clone();
    eng.register_proof(good);
    eng.register_proof(expired);

    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![gid, eid],
    );
    let d = eng.evaluate(&r, "t1", 1000);
    // First valid proof passes, second is expired → rejected
    assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);
}

#[test]
fn engine_one_of_multiple_proofs_wrong_epoch() {
    let current = SecurityEpoch::from_raw(5);
    let old = SecurityEpoch::from_raw(3);
    let mut eng = engine(current);

    let good = cap_proof("good", current, 100);
    let bad = cap_proof("bad", old, 100);
    let gid = good.proof_id().clone();
    let bid = bad.proof_id().clone();
    eng.register_proof(good);
    eng.register_proof(bad);

    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![gid, bid],
    );
    let d = eng.evaluate(&r, "t1", 1000);
    assert_eq!(d.outcome, SpecializationOutcome::RejectedEpochMismatch);
}

#[test]
fn engine_shared_proof_across_regions() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);
    let p = cap_proof("shared", epoch, 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    let r1 = region(
        "r-a",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid.clone()],
    );
    let r2 = region("r-b", OptimizationClass::PathElimination, vec![pid.clone()]);
    let r3 = region("r-c", OptimizationClass::SuperinstructionFusion, vec![pid]);

    assert!(eng.evaluate(&r1, "t1", 1000).outcome.is_applied());
    assert!(eng.evaluate(&r2, "t2", 2000).outcome.is_applied());
    assert!(eng.evaluate(&r3, "t3", 3000).outcome.is_applied());
    assert_eq!(eng.applied_count(), 3);
}

#[test]
fn engine_last_applied_proof_inputs_skips_rejections() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);
    let p = cap_proof("p1", epoch, 500);
    let pid = p.proof_id().clone();
    eng.register_proof(p);

    // Applied
    let r1 = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    eng.evaluate(&r1, "t1", 1000);

    // Rejected (no proofs)
    let r2 = region(
        "r2",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    eng.evaluate(&r2, "t2", 2000);

    // last_applied should still find the first one
    let inputs = eng.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
    assert_eq!(inputs[0].validity_window_ticks, 500);
}

#[test]
fn engine_last_applied_proof_inputs_finds_most_recent() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);
    let p1 = cap_proof("p1", epoch, 100);
    let p2 = flow_proof_with_ticks("p2", epoch, 200);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    eng.register_proof(p1);
    eng.register_proof(p2);

    eng.evaluate(
        &region(
            "r1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![id1],
        ),
        "t1",
        1000,
    );
    eng.evaluate(
        &region("r2", OptimizationClass::IfcCheckElision, vec![id2]),
        "t2",
        2000,
    );

    let inputs = eng.last_applied_proof_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].proof_type, ProofType::FlowProof); // most recent
}

#[test]
fn engine_decisions_for_region_empty() {
    let eng = engine(SecurityEpoch::from_raw(1));
    assert!(eng.decisions_for_region("nonexistent").is_empty());
}

#[test]
fn engine_proof_store_mut_access() {
    let mut eng = engine(SecurityEpoch::from_raw(1));
    let epoch = SecurityEpoch::from_raw(1);
    let p = cap_proof("manual", epoch, 100);
    let pid = p.proof_id().clone();
    eng.proof_store_mut().insert(p);
    assert!(eng.proof_store().get(&pid).is_some());
}

// ── Epoch change edge cases ─────────────────────────────────────────────────

#[test]
fn epoch_change_multiple_times() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let e3 = SecurityEpoch::from_raw(3);
    let mut eng = engine(e1);

    eng.register_proof(cap_proof("p1", e1, 100));
    eng.register_proof(cap_proof("p2", e2, 100));

    let inv1 = eng.on_epoch_change(e1, e2, "t1", 1000);
    assert_eq!(inv1.len(), 1); // p1 invalidated
    assert_eq!(eng.proof_store().len(), 1); // p2 remains
    assert_eq!(eng.config().current_epoch, e2);

    let inv2 = eng.on_epoch_change(e2, e3, "t2", 2000);
    assert_eq!(inv2.len(), 1); // p2 invalidated
    assert!(eng.proof_store().is_empty());
    assert_eq!(eng.config().current_epoch, e3);
}

#[test]
fn epoch_change_no_proofs_no_event() {
    let mut eng = engine(SecurityEpoch::from_raw(1));
    eng.on_epoch_change(
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(2),
        "t1",
        1000,
    );
    assert!(eng.events().is_empty());
}

#[test]
fn epoch_change_with_proofs_emits_event() {
    let e1 = SecurityEpoch::from_raw(1);
    let mut eng = engine(e1);
    eng.register_proof(cap_proof("p1", e1, 100));
    eng.on_epoch_change(e1, SecurityEpoch::from_raw(2), "trace-ec", 1000);
    assert_eq!(eng.events().len(), 1);
    assert_eq!(eng.events()[0].event, "epoch_change_invalidation");
}

// ── Integration: full lifecycle ─────────────────────────────────────────────

#[test]
fn integration_full_lifecycle_with_epoch_transition() {
    let e1 = SecurityEpoch::from_raw(1);
    let e2 = SecurityEpoch::from_raw(2);
    let mut eng = engine(e1);

    // Register proofs in epoch 1
    let p1 = cap_proof("cap1", e1, 1000);
    let p2 = flow_proof_with_ticks("flow1", e1, 500);
    let id1 = p1.proof_id().clone();
    let id2 = p2.proof_id().clone();
    eng.register_proof(p1);
    eng.register_proof(p2);

    // Evaluate: both should apply
    let r1 = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![id1.clone()],
    );
    let r2 = region("r2", OptimizationClass::IfcCheckElision, vec![id2.clone()]);
    assert!(eng.evaluate(&r1, "t1", 1000).outcome.is_applied());
    assert!(eng.evaluate(&r2, "t2", 2000).outcome.is_applied());
    assert_eq!(eng.applied_count(), 2);

    // Epoch change → invalidate epoch 1 proofs
    eng.on_epoch_change(e1, e2, "t-ec", 3000);
    assert!(eng.proof_store().is_empty());

    // Re-evaluate: should fail (proofs gone)
    assert_eq!(
        eng.evaluate(&r1, "t3", 4000).outcome,
        SpecializationOutcome::RejectedProofNotFound
    );

    // Register new proofs for epoch 2
    let p3 = cap_proof("cap2", e2, 2000);
    let id3 = p3.proof_id().clone();
    eng.register_proof(p3);

    let r3 = region(
        "r3",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![id3],
    );
    assert!(eng.evaluate(&r3, "t4", 5000).outcome.is_applied());
    assert_eq!(eng.applied_count(), 3);
    assert_eq!(eng.rejected_count(), 1); // the failed re-evaluate
}

#[test]
fn integration_required_proof_types_with_multiple_proofs() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut config = CompilerPolicyConfig::new("test", epoch);
    let mut required = BTreeSet::new();
    required.insert(ProofType::CapabilityWitness);
    required.insert(ProofType::FlowProof);
    required.insert(ProofType::ReplayMotif);
    config.class_policies.insert(
        OptimizationClass::SuperinstructionFusion,
        OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 3,
            required_proof_types: required,
            governance_approved: true,
        },
    );
    let mut eng = CompilerPolicyEngine::new(config);

    let c = cap_proof("c", epoch, 100);
    let f = flow_proof_with_ticks("f", epoch, 200);
    let r = replay_proof("r", epoch, 300);
    let cid = c.proof_id().clone();
    let fid = f.proof_id().clone();
    let rid = r.proof_id().clone();
    eng.register_proof(c);
    eng.register_proof(f);
    eng.register_proof(r);

    // All three → should apply
    let reg = region(
        "r-all",
        OptimizationClass::SuperinstructionFusion,
        vec![cid.clone(), fid.clone(), rid],
    );
    let d = eng.evaluate(&reg, "t1", 1000);
    assert!(d.outcome.is_applied());
    assert_eq!(d.proof_ids.len(), 3);

    // Only two (missing ReplayMotif) → should reject with InsufficientProofs
    // because min_proof_count=3 is checked before required_proof_types
    let reg2 = region(
        "r-partial",
        OptimizationClass::SuperinstructionFusion,
        vec![cid, fid],
    );
    let d2 = eng.evaluate(&reg2, "t2", 2000);
    assert_eq!(
        d2.outcome,
        SpecializationOutcome::RejectedInsufficientProofs
    );
}

// ── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn determinism_100x_same_outcome() {
    for _ in 0..100 {
        let epoch = SecurityEpoch::from_raw(1);
        let mut eng = engine(epoch);
        let p = cap_proof("p1", epoch, 100);
        let pid = p.proof_id().clone();
        eng.register_proof(p);
        let r = region(
            "r1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d = eng.evaluate(&r, "t1", 1000);
        assert!(d.outcome.is_applied());
    }
}

// ── Event structure correctness ─────────────────────────────────────────────

#[test]
fn applied_event_has_no_error_code() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);
    let p = cap_proof("p1", epoch, 100);
    let pid = p.proof_id().clone();
    eng.register_proof(p);
    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![pid],
    );
    eng.evaluate(&r, "t1", 1000);
    assert!(eng.events()[0].error_code.is_none());
    assert_eq!(eng.events()[0].event, "specialization_applied");
}

#[test]
fn rejected_event_has_matching_error_code() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut eng = engine(epoch);

    // No proofs
    let r = region(
        "r1",
        OptimizationClass::HostcallDispatchSpecialization,
        vec![],
    );
    eng.evaluate(&r, "t1", 1000);
    assert_eq!(eng.events()[0].error_code.as_deref(), Some("NO_PROOFS"));
    assert_eq!(eng.events()[0].event, "specialization_rejected");
}

#[test]
fn all_rejection_outcomes_produce_events_with_error_codes() {
    let epoch = SecurityEpoch::from_raw(1);

    // Global disable
    {
        let mut config = CompilerPolicyConfig::new("test", epoch);
        config.global_disable = true;
        let mut eng = CompilerPolicyEngine::new(config);
        eng.evaluate(
            &region("r", OptimizationClass::PathElimination, vec![]),
            "t",
            0,
        );
        assert_eq!(
            eng.events()[0].error_code.as_deref(),
            Some("GLOBAL_DISABLE")
        );
    }

    // Class disabled
    {
        let mut config = CompilerPolicyConfig::new("test", epoch);
        config.class_policies.insert(
            OptimizationClass::PathElimination,
            OptimizationClassPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        let mut eng = CompilerPolicyEngine::new(config);
        eng.evaluate(
            &region("r", OptimizationClass::PathElimination, vec![]),
            "t",
            0,
        );
        assert_eq!(
            eng.events()[0].error_code.as_deref(),
            Some("CLASS_DISABLED")
        );
    }
}
