#![forbid(unsafe_code)]

//! Integration tests for the `proof_specialization_linkage` module.
//!
//! Covers the full lifecycle of proof-to-specialization linkage for IR3/IR4
//! artifacts: registration, attach to IR3, execution recording, epoch-based
//! invalidation, proof revocation, manual invalidation, query helpers,
//! witness event production, serde roundtrips, and error / display contracts.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Module, Ir4Module, WitnessEventKind};
use frankenengine_engine::proof_specialization_linkage::{
    ExecutionRecord, InvalidationCause, LinkageEngine, LinkageError, LinkageEvent, LinkageId,
    LinkageRecord, PerformanceDelta, ProofInputRef, RollbackState, error_code,
};
use frankenengine_engine::proof_specialization_receipt::{OptimizationClass, ProofType};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(val: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(val)
}

fn hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn proof_input(id: &str, ep: u64) -> ProofInputRef {
    ProofInputRef {
        proof_id: id.to_string(),
        proof_type: ProofType::CapabilityWitness,
        proof_epoch: epoch(ep),
        validity_window_ticks: 1000,
    }
}

fn linkage_record(id: &str, ep: u64, proof_ids: &[&str]) -> LinkageRecord {
    let baseline = hash(format!("baseline-{id}").as_bytes());
    let specialized = hash(format!("specialized-{id}").as_bytes());
    LinkageRecord {
        id: LinkageId::new(id),
        proof_inputs: proof_ids.iter().map(|pid| proof_input(pid, ep)).collect(),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        validity_epoch: epoch(ep),
        specialized_ir3_hash: specialized,
        rollback: RollbackState {
            baseline_ir3_hash: baseline,
            activation_epoch: epoch(ep),
            activation_tick: 100,
        },
        active: true,
        performance_delta: None,
        execution_count: 0,
    }
}

fn engine(ep: u64) -> LinkageEngine {
    LinkageEngine::new("integration-policy", epoch(ep))
}

fn ir3() -> Ir3Module {
    Ir3Module::new(hash(b"ir3-source"), "test-ir3")
}

fn ir4() -> Ir4Module {
    Ir4Module::new(hash(b"ir4-source"), "test-ir4")
}

// =========================================================================
// 1. LinkageEngine basics
// =========================================================================

#[test]
fn engine_new_has_correct_policy_and_epoch() {
    let eng = engine(7);
    assert_eq!(eng.policy_id(), "integration-policy");
    assert_eq!(eng.current_epoch(), epoch(7));
    assert_eq!(eng.total_count(), 0);
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 0);
    assert!(eng.linkages().is_empty());
    assert!(eng.invalidations().is_empty());
    assert!(eng.events().is_empty());
}

#[test]
fn register_single_linkage_and_query_counts() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-1", 5, &["proof-a"]);
    eng.register(rec, "trace-1").unwrap();

    assert_eq!(eng.total_count(), 1);
    assert_eq!(eng.active_count(), 1);
    assert_eq!(eng.inactive_count(), 0);
    assert!(eng.linkages().contains_key(&LinkageId::new("lnk-1")));
}

#[test]
fn register_multiple_linkages() {
    let mut eng = engine(5);
    for i in 0..5 {
        let id = format!("lnk-{i}");
        let rec = linkage_record(&id, 5, &["proof-x"]);
        eng.register(rec, "trace").unwrap();
    }
    assert_eq!(eng.total_count(), 5);
    assert_eq!(eng.active_count(), 5);
}

// =========================================================================
// 2. Register errors
// =========================================================================

#[test]
fn register_empty_proof_inputs_rejected() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-1", 5, &["p"]);
    rec.proof_inputs.clear();
    let err = eng.register(rec, "t").unwrap_err();
    assert_eq!(err, LinkageError::EmptyProofInputs);
    // Event emitted
    assert!(!eng.events().is_empty());
    let last = eng.events().last().unwrap();
    assert_eq!(last.outcome, "rejected");
    assert_eq!(
        last.error_code.as_deref(),
        Some("LINKAGE_EMPTY_PROOF_INPUTS")
    );
}

#[test]
fn register_duplicate_id_rejected() {
    let mut eng = engine(5);
    let r1 = linkage_record("lnk-dup", 5, &["p1"]);
    let r2 = linkage_record("lnk-dup", 5, &["p2"]);
    eng.register(r1, "t1").unwrap();
    let err = eng.register(r2, "t2").unwrap_err();
    match &err {
        LinkageError::DuplicateLinkage { id } => assert_eq!(id, "lnk-dup"),
        other => panic!("expected DuplicateLinkage, got {other:?}"),
    }
    // Event for duplicate contains error code
    let dup_events: Vec<_> = eng
        .events()
        .iter()
        .filter(|e| e.error_code.as_deref() == Some("LINKAGE_DUPLICATE"))
        .collect();
    assert_eq!(dup_events.len(), 1);
}

// =========================================================================
// 3. attach_to_ir3
// =========================================================================

#[test]
fn attach_to_ir3_success() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-1", 5, &["proof-a", "proof-b"]);
    eng.register(rec.clone(), "t1").unwrap();

    let mut module = ir3();
    assert!(module.specialization.is_none());

    let lid = LinkageId::new("lnk-1");
    eng.attach_to_ir3(&lid, &mut module, "t2").unwrap();

    let spec = module.specialization.as_ref().unwrap();
    assert_eq!(spec.proof_input_ids, vec!["proof-a", "proof-b"]);
    assert_eq!(
        spec.optimization_class,
        OptimizationClass::HostcallDispatchSpecialization.to_string()
    );
    assert_eq!(spec.validity_epoch, 5);
    assert_eq!(spec.rollback_token, rec.rollback.baseline_ir3_hash);
}

#[test]
fn attach_to_ir3_already_specialized_error() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t1")
        .unwrap();
    eng.register(linkage_record("lnk-2", 5, &["p2"]), "t1")
        .unwrap();

    let mut module = ir3();
    let lid1 = LinkageId::new("lnk-1");
    let lid2 = LinkageId::new("lnk-2");
    eng.attach_to_ir3(&lid1, &mut module, "t2").unwrap();

    let err = eng.attach_to_ir3(&lid2, &mut module, "t3").unwrap_err();
    assert_eq!(err, LinkageError::Ir3AlreadySpecialized);
    assert_eq!(error_code(&err), "LINKAGE_IR3_ALREADY_SPECIALIZED");
}

#[test]
fn attach_to_ir3_linkage_not_found() {
    let mut eng = engine(5);
    let mut module = ir3();
    let lid = LinkageId::new("does-not-exist");
    let err = eng.attach_to_ir3(&lid, &mut module, "t1").unwrap_err();
    assert_eq!(
        err,
        LinkageError::LinkageNotFound {
            id: "does-not-exist".to_string()
        }
    );
}

#[test]
fn attach_to_ir3_inactive_linkage_error() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inactive", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t1").unwrap();

    let mut module = ir3();
    let lid = LinkageId::new("lnk-inactive");
    let err = eng.attach_to_ir3(&lid, &mut module, "t2").unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-inactive".to_string()
        }
    );
}

#[test]
fn attach_to_ir3_epoch_mismatch_error() {
    let mut eng = engine(10);
    // Register linkage at epoch 5, engine is at epoch 10
    let rec = linkage_record("lnk-old", 5, &["p1"]);
    eng.register(rec, "t1").unwrap();

    let mut module = ir3();
    let lid = LinkageId::new("lnk-old");
    let err = eng.attach_to_ir3(&lid, &mut module, "t2").unwrap_err();
    match &err {
        LinkageError::EpochMismatch {
            linkage_epoch,
            current_epoch,
        } => {
            assert_eq!(*linkage_epoch, epoch(5));
            assert_eq!(*current_epoch, epoch(10));
        }
        other => panic!("expected EpochMismatch, got {other:?}"),
    }
}

#[test]
fn attach_to_ir3_at_tick_expired_window_fail_closed() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-expire", 5, &["p1"]);
    rec.rollback.activation_tick = 200;
    rec.proof_inputs[0].validity_window_ticks = 25; // expires at 225
    eng.register(rec, "t1").unwrap();

    let mut module = ir3();
    let lid = LinkageId::new("lnk-expire");
    let err = eng
        .attach_to_ir3_at_tick(&lid, &mut module, 225, "t2")
        .unwrap_err();

    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-expire".to_string()
        }
    );
    assert!(module.specialization.is_none());
    assert!(!eng.get(&lid).unwrap().active);

    let cause = &eng.invalidations()[0].1;
    match cause {
        InvalidationCause::PolicyChange { reason } => {
            assert!(reason.contains("proof_window_expired"));
            assert!(reason.contains("proof_id=p1"));
            assert!(reason.contains("expiry_tick=225"));
            assert!(reason.contains("observed_tick=225"));
        }
        other => panic!("expected PolicyChange, got {other:?}"),
    }
}

#[test]
fn attach_to_ir3_at_tick_before_expiry_succeeds() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-ok", 5, &["p1"]);
    rec.rollback.activation_tick = 200;
    rec.proof_inputs[0].validity_window_ticks = 25; // expires at 225
    eng.register(rec, "t1").unwrap();

    let mut module = ir3();
    let lid = LinkageId::new("lnk-ok");
    eng.attach_to_ir3_at_tick(&lid, &mut module, 224, "t2")
        .unwrap();

    assert!(module.specialization.is_some());
    assert!(eng.invalidations().is_empty());
    assert!(eng.get(&lid).unwrap().active);
}

// =========================================================================
// 4. record_execution
// =========================================================================

#[test]
fn record_execution_success_updates_counters_and_ir4() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t1")
        .unwrap();

    let mut module = ir4();
    module.instructions_executed = 200;
    module.duration_ticks = 80;

    let lid = LinkageId::new("lnk-1");
    let perf = PerformanceDelta {
        speedup_millionths: 1_500_000,
        instruction_ratio_millionths: 750_000,
    };
    let exec = eng.record_execution(&lid, &mut module, perf, "t2").unwrap();

    // ExecutionRecord fields
    assert_eq!(exec.linkage_id, lid);
    assert_eq!(exec.performance_delta.speedup_millionths, 1_500_000);
    assert_eq!(exec.performance_delta.instruction_ratio_millionths, 750_000);
    assert_eq!(exec.instructions_executed, 200);
    assert_eq!(exec.duration_ticks, 80);

    // IR4 updated with specialization id
    assert!(
        module
            .active_specialization_ids
            .contains(&"lnk-1".to_string())
    );

    // Engine internal counters
    let stored = eng.get(&lid).unwrap();
    assert_eq!(stored.execution_count, 1);
    assert_eq!(
        stored.performance_delta.unwrap().speedup_millionths,
        1_500_000
    );
}

#[test]
fn record_execution_increments_count_on_multiple_calls() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t1")
        .unwrap();

    let lid = LinkageId::new("lnk-1");
    let perf = PerformanceDelta::NEUTRAL;

    for _ in 0..3 {
        let mut module = ir4();
        eng.record_execution(&lid, &mut module, perf, "t").unwrap();
    }

    let stored = eng.get(&lid).unwrap();
    assert_eq!(stored.execution_count, 3);
}

#[test]
fn record_execution_does_not_duplicate_ir4_specialization_id() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t1")
        .unwrap();

    let mut module = ir4();
    let lid = LinkageId::new("lnk-1");
    let perf = PerformanceDelta::NEUTRAL;

    eng.record_execution(&lid, &mut module, perf, "t").unwrap();
    eng.record_execution(&lid, &mut module, perf, "t").unwrap();

    // Should still only appear once
    let count = module
        .active_specialization_ids
        .iter()
        .filter(|s| *s == "lnk-1")
        .count();
    assert_eq!(count, 1);
}

#[test]
fn record_execution_not_found_error() {
    let mut eng = engine(5);
    let mut module = ir4();
    let lid = LinkageId::new("lnk-missing");
    let err = eng
        .record_execution(&lid, &mut module, PerformanceDelta::NEUTRAL, "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::LinkageNotFound {
            id: "lnk-missing".to_string()
        }
    );
}

#[test]
fn record_execution_inactive_linkage_error() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inactive", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t1").unwrap();

    let mut module = ir4();
    let lid = LinkageId::new("lnk-inactive");
    let err = eng
        .record_execution(&lid, &mut module, PerformanceDelta::NEUTRAL, "t2")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-inactive".to_string()
        }
    );
}

#[test]
fn record_execution_at_tick_expired_window_fail_closed() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-expire-exec", 5, &["p1"]);
    rec.rollback.activation_tick = 200;
    rec.proof_inputs[0].validity_window_ticks = 25; // expires at 225
    eng.register(rec, "t1").unwrap();

    let mut module = ir4();
    let lid = LinkageId::new("lnk-expire-exec");
    let err = eng
        .record_execution_at_tick(&lid, &mut module, PerformanceDelta::NEUTRAL, 225, "t2")
        .unwrap_err();

    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-expire-exec".to_string()
        }
    );
    assert!(!eng.get(&lid).unwrap().active);

    let cause = &eng.invalidations()[0].1;
    match cause {
        InvalidationCause::PolicyChange { reason } => {
            assert!(reason.contains("proof_window_expired"));
            assert!(reason.contains("proof_id=p1"));
            assert!(reason.contains("expiry_tick=225"));
            assert!(reason.contains("observed_tick=225"));
        }
        other => panic!("expected PolicyChange, got {other:?}"),
    }
}

#[test]
fn record_execution_at_tick_before_expiry_succeeds() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-ok-exec", 5, &["p1"]);
    rec.rollback.activation_tick = 200;
    rec.proof_inputs[0].validity_window_ticks = 25; // expires at 225
    eng.register(rec, "t1").unwrap();

    let mut module = ir4();
    module.instructions_executed = 144;
    module.duration_ticks = 9;
    let lid = LinkageId::new("lnk-ok-exec");

    let exec = eng
        .record_execution_at_tick(
            &lid,
            &mut module,
            PerformanceDelta {
                speedup_millionths: 1_250_000,
                instruction_ratio_millionths: 850_000,
            },
            224,
            "t2",
        )
        .unwrap();

    assert_eq!(exec.instructions_executed, 144);
    assert_eq!(exec.duration_ticks, 9);
    assert_eq!(eng.get(&lid).unwrap().execution_count, 1);
}

// =========================================================================
// 5. on_epoch_change
// =========================================================================

#[test]
fn on_epoch_change_invalidates_stale_linkages() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["pa"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["pb"]), "t")
        .unwrap();

    let rollbacks = eng.on_epoch_change(epoch(6), "t-epoch");
    assert_eq!(rollbacks.len(), 2);
    assert_eq!(eng.current_epoch(), epoch(6));
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 2);

    // Rollback hashes correspond to baseline
    for (lid, baseline_hash) in &rollbacks {
        let stored = eng.get(lid).unwrap();
        assert!(!stored.active);
        assert_eq!(*baseline_hash, stored.rollback.baseline_ir3_hash);
    }
}

#[test]
fn on_epoch_change_preserves_linkages_matching_new_epoch() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-match", 6, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-stale", 5, &["p2"]), "t")
        .unwrap();

    let rollbacks = eng.on_epoch_change(epoch(6), "t-epoch");
    // Only the stale one (epoch 5) should be invalidated
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].0, LinkageId::new("lnk-stale"));
    assert_eq!(eng.active_count(), 1);

    let matching = eng.get(&LinkageId::new("lnk-match")).unwrap();
    assert!(matching.active);
}

#[test]
fn on_epoch_change_records_invalidation_causes() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    eng.on_epoch_change(epoch(6), "t-epoch");

    assert_eq!(eng.invalidations().len(), 1);
    let (ref lid, ref cause) = eng.invalidations()[0];
    assert_eq!(*lid, LinkageId::new("lnk-1"));
    match cause {
        InvalidationCause::EpochChange {
            old_epoch,
            new_epoch,
        } => {
            assert_eq!(*old_epoch, epoch(5));
            assert_eq!(*new_epoch, epoch(6));
        }
        other => panic!("expected EpochChange, got {other:?}"),
    }
}

#[test]
fn on_epoch_change_skips_already_inactive() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inactive", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let rollbacks = eng.on_epoch_change(epoch(6), "t");
    assert!(rollbacks.is_empty());
    assert!(eng.invalidations().is_empty());
}

// =========================================================================
// 6. invalidate_by_proof
// =========================================================================

#[test]
fn invalidate_by_proof_hits_all_linkages_using_proof() {
    let mut eng = engine(5);
    // Two linkages share proof "shared-proof", one does not
    eng.register(
        linkage_record("lnk-a", 5, &["shared-proof", "unique-a"]),
        "t",
    )
    .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["shared-proof"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-c", 5, &["other-proof"]), "t")
        .unwrap();

    let rollbacks = eng.invalidate_by_proof("shared-proof", "t-revoke");
    assert_eq!(rollbacks.len(), 2);

    let ids: Vec<_> = rollbacks.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&"lnk-a"));
    assert!(ids.contains(&"lnk-b"));

    assert_eq!(eng.active_count(), 1);
    let remaining = eng.get(&LinkageId::new("lnk-c")).unwrap();
    assert!(remaining.active);
}

#[test]
fn invalidate_by_proof_records_cause() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["revoked-proof"]), "t")
        .unwrap();

    eng.invalidate_by_proof("revoked-proof", "t-revoke");

    assert_eq!(eng.invalidations().len(), 1);
    match &eng.invalidations()[0].1 {
        InvalidationCause::ProofRevoked { proof_id } => {
            assert_eq!(proof_id, "revoked-proof");
        }
        other => panic!("expected ProofRevoked, got {other:?}"),
    }
}

#[test]
fn invalidate_by_proof_ignores_inactive_linkages() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-already-off", 5, &["some-proof"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let rollbacks = eng.invalidate_by_proof("some-proof", "t");
    assert!(rollbacks.is_empty());
}

#[test]
fn invalidate_by_proof_returns_empty_for_unknown_proof() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    let rollbacks = eng.invalidate_by_proof("nonexistent-proof", "t");
    assert!(rollbacks.is_empty());
}

#[test]
fn invalidate_expired_proof_windows_boundary_is_deterministic() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-expiring", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 25; // expires at 125
    eng.register(rec, "t").unwrap();

    let before = eng.invalidate_expired_proof_windows(124, "t-window-1");
    assert!(before.is_empty());
    assert_eq!(eng.active_count(), 1);

    let at_boundary = eng.invalidate_expired_proof_windows(125, "t-window-2");
    assert_eq!(at_boundary.len(), 1);
    assert_eq!(at_boundary[0].0, LinkageId::new("lnk-expiring"));
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 1);

    let cause = &eng.invalidations()[0].1;
    match cause {
        InvalidationCause::PolicyChange { reason } => {
            assert!(reason.contains("proof_window_expired"));
            assert!(reason.contains("proof_id=p1"));
            assert!(reason.contains("expiry_tick=125"));
            assert!(reason.contains("observed_tick=125"));
        }
        other => panic!("expected PolicyChange, got {other:?}"),
    }
}

#[test]
fn invalidate_expired_proof_windows_ignores_unbounded_input() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-unbounded", 5, &["p1"]);
    rec.proof_inputs[0].validity_window_ticks = 0; // unbounded
    eng.register(rec, "t").unwrap();

    let rollbacks = eng.invalidate_expired_proof_windows(u64::MAX, "t-window");
    assert!(rollbacks.is_empty());
    assert_eq!(eng.active_count(), 1);
    assert!(eng.invalidations().is_empty());
}

// =========================================================================
// 7. invalidate_manual
// =========================================================================

#[test]
fn invalidate_manual_success() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-1", 5, &["p1"]);
    let expected_baseline = rec.rollback.baseline_ir3_hash;
    eng.register(rec, "t").unwrap();

    let lid = LinkageId::new("lnk-1");
    let baseline = eng
        .invalidate_manual(&lid, "operator-42", "t-manual")
        .unwrap();
    assert_eq!(baseline, expected_baseline);

    let stored = eng.get(&lid).unwrap();
    assert!(!stored.active);
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 1);

    // Invalidation cause recorded
    assert_eq!(eng.invalidations().len(), 1);
    match &eng.invalidations()[0].1 {
        InvalidationCause::ManualInvalidation { operator_id } => {
            assert_eq!(operator_id, "operator-42");
        }
        other => panic!("expected ManualInvalidation, got {other:?}"),
    }
}

#[test]
fn invalidate_manual_not_found_error() {
    let mut eng = engine(5);
    let lid = LinkageId::new("phantom");
    let err = eng.invalidate_manual(&lid, "op", "t").unwrap_err();
    assert_eq!(
        err,
        LinkageError::LinkageNotFound {
            id: "phantom".to_string()
        }
    );
}

#[test]
fn invalidate_manual_already_inactive_error() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-off", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let lid = LinkageId::new("lnk-off");
    let err = eng.invalidate_manual(&lid, "op", "t").unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-off".to_string()
        }
    );
}

// =========================================================================
// 8. Query helpers
// =========================================================================

#[test]
fn active_linkages_returns_only_active() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["p1"]), "t")
        .unwrap();
    let mut rec_b = linkage_record("lnk-b", 5, &["p2"]);
    rec_b.active = false;
    eng.register(rec_b, "t").unwrap();

    let active = eng.active_linkages();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, LinkageId::new("lnk-a"));
}

#[test]
fn get_returns_some_for_existing_and_none_for_missing() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    assert!(eng.get(&LinkageId::new("lnk-1")).is_some());
    assert!(eng.get(&LinkageId::new("lnk-missing")).is_none());
}

#[test]
fn counts_reflect_active_and_inactive() {
    let mut eng = engine(5);
    eng.register(linkage_record("a", 5, &["p"]), "t").unwrap();
    eng.register(linkage_record("b", 5, &["p"]), "t").unwrap();
    let mut inactive = linkage_record("c", 5, &["p"]);
    inactive.active = false;
    eng.register(inactive, "t").unwrap();

    assert_eq!(eng.total_count(), 3);
    assert_eq!(eng.active_count(), 2);
    assert_eq!(eng.inactive_count(), 1);
}

#[test]
fn rollback_plan_lists_active_linkages_with_baseline_hashes() {
    let mut eng = engine(5);
    let rec_a = linkage_record("lnk-a", 5, &["p1"]);
    let expected_a = rec_a.rollback.baseline_ir3_hash;
    eng.register(rec_a, "t").unwrap();

    let mut rec_b = linkage_record("lnk-b", 5, &["p2"]);
    rec_b.active = false;
    eng.register(rec_b, "t").unwrap();

    let plan = eng.rollback_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, LinkageId::new("lnk-a"));
    assert_eq!(plan[0].1, expected_a);
}

#[test]
fn consumed_proof_ids_deduplicates_and_sorts() {
    let mut eng = engine(5);
    // Two linkages share "proof-shared"
    eng.register(
        linkage_record("lnk-1", 5, &["proof-shared", "proof-alpha"]),
        "t",
    )
    .unwrap();
    eng.register(
        linkage_record("lnk-2", 5, &["proof-shared", "proof-beta"]),
        "t",
    )
    .unwrap();

    let ids = eng.consumed_proof_ids();
    // Should be sorted and deduplicated
    assert_eq!(ids, vec!["proof-alpha", "proof-beta", "proof-shared"]);
}

#[test]
fn consumed_proof_ids_excludes_inactive_linkages() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-active", 5, &["proof-a"]), "t")
        .unwrap();
    let mut inactive = linkage_record("lnk-inactive", 5, &["proof-b"]);
    inactive.active = false;
    eng.register(inactive, "t").unwrap();

    let ids = eng.consumed_proof_ids();
    assert_eq!(ids, vec!["proof-a"]);
}

// =========================================================================
// 9. produce_witness_events
// =========================================================================

#[test]
fn produce_witness_events_for_active_linkages_only() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["p2"]), "t")
        .unwrap();
    let mut inactive = linkage_record("lnk-c", 5, &["p3"]);
    inactive.active = false;
    eng.register(inactive, "t").unwrap();

    let events = eng.produce_witness_events(100, 42);
    assert_eq!(events.len(), 2);

    // Check sequence numbers start from base_seq
    assert_eq!(events[0].seq, 100);
    assert_eq!(events[1].seq, 101);

    // All events are CapabilityChecked
    for e in &events {
        assert_eq!(e.kind, WitnessEventKind::CapabilityChecked);
        assert_eq!(e.timestamp_tick, 42);
    }
}

#[test]
fn produce_witness_events_empty_when_no_active_linkages() {
    let eng = engine(5);
    let events = eng.produce_witness_events(0, 0);
    assert!(events.is_empty());
}

// =========================================================================
// 10. LinkageRecord: to_ir3_linkage and proofs_valid_at
// =========================================================================

#[test]
fn to_ir3_linkage_carries_all_proof_ids() {
    let rec = linkage_record("lnk-1", 5, &["pa", "pb", "pc"]);
    let spec = rec.to_ir3_linkage();
    assert_eq!(spec.proof_input_ids, vec!["pa", "pb", "pc"]);
}

#[test]
fn proofs_valid_at_same_epoch() {
    let rec = linkage_record("lnk-1", 5, &["p1"]);
    assert!(rec.proofs_valid_at(epoch(5)));
}

#[test]
fn proofs_valid_at_later_epoch() {
    let rec = linkage_record("lnk-1", 5, &["p1"]);
    assert!(rec.proofs_valid_at(epoch(100)));
}

#[test]
fn proofs_not_valid_at_earlier_epoch() {
    let rec = linkage_record("lnk-1", 5, &["p1"]);
    assert!(!rec.proofs_valid_at(epoch(4)));
}

#[test]
fn proofs_valid_at_with_mixed_epochs() {
    let mut rec = linkage_record("lnk-1", 3, &["p1"]);
    rec.proof_inputs.push(proof_input("p2", 7));
    // Epoch 3 proof and epoch 7 proof: need epoch >= 7 for all to be valid
    assert!(!rec.proofs_valid_at(epoch(5)));
    assert!(rec.proofs_valid_at(epoch(7)));
    assert!(rec.proofs_valid_at(epoch(10)));
}

// =========================================================================
// 11. Serde roundtrips
// =========================================================================

#[test]
fn serde_roundtrip_linkage_id() {
    let id = LinkageId::new("serde-test-id");
    let json = serde_json::to_string(&id).unwrap();
    let back: LinkageId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn serde_roundtrip_proof_input_ref() {
    let pir = ProofInputRef {
        proof_id: "proof-serde".to_string(),
        proof_type: ProofType::CapabilityWitness,
        proof_epoch: epoch(9),
        validity_window_ticks: 5000,
    };
    let json = serde_json::to_string(&pir).unwrap();
    let back: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(pir, back);
}

#[test]
fn serde_roundtrip_performance_delta() {
    let pd = PerformanceDelta {
        speedup_millionths: 2_000_000,
        instruction_ratio_millionths: 500_000,
    };
    let json = serde_json::to_string(&pd).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, back);
}

#[test]
fn serde_roundtrip_rollback_state() {
    let rs = RollbackState {
        baseline_ir3_hash: hash(b"rs-baseline"),
        activation_epoch: epoch(3),
        activation_tick: 999,
    };
    let json = serde_json::to_string(&rs).unwrap();
    let back: RollbackState = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, back);
}

#[test]
fn serde_roundtrip_linkage_record() {
    let rec = linkage_record("serde-rec", 5, &["p1", "p2"]);
    let json = serde_json::to_string(&rec).unwrap();
    let back: LinkageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn serde_roundtrip_invalidation_cause_all_variants() {
    let causes = [
        InvalidationCause::EpochChange {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationCause::ProofRevoked {
            proof_id: "revoked".to_string(),
        },
        InvalidationCause::PolicyChange {
            reason: "new-rule".to_string(),
        },
        InvalidationCause::ManualInvalidation {
            operator_id: "op-7".to_string(),
        },
    ];
    for cause in &causes {
        let json = serde_json::to_string(cause).unwrap();
        let back: InvalidationCause = serde_json::from_str(&json).unwrap();
        assert_eq!(*cause, back);
    }
}

#[test]
fn serde_roundtrip_linkage_event() {
    let ev = LinkageEvent {
        trace_id: "trace-42".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "linkage_engine".to_string(),
        event: "register".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LinkageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_linkage_event_with_error_code() {
    let ev = LinkageEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "rejected".to_string(),
        error_code: Some("LINKAGE_DUPLICATE".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LinkageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_execution_record() {
    let er = ExecutionRecord {
        linkage_id: LinkageId::new("exec-rec"),
        witness_hash: hash(b"witness"),
        performance_delta: PerformanceDelta {
            speedup_millionths: 1_100_000,
            instruction_ratio_millionths: 950_000,
        },
        instructions_executed: 300,
        duration_ticks: 120,
    };
    let json = serde_json::to_string(&er).unwrap();
    let back: ExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(er, back);
}

// =========================================================================
// 12. Display / error contracts
// =========================================================================

#[test]
fn linkage_error_display_duplicate() {
    let err = LinkageError::DuplicateLinkage {
        id: "lnk-x".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("duplicate linkage"));
    assert!(msg.contains("lnk-x"));
}

#[test]
fn linkage_error_display_not_found() {
    let err = LinkageError::LinkageNotFound {
        id: "lnk-y".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("linkage not found"));
    assert!(msg.contains("lnk-y"));
}

#[test]
fn linkage_error_display_already_inactive() {
    let err = LinkageError::AlreadyInactive {
        id: "lnk-z".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("already inactive"));
    assert!(msg.contains("lnk-z"));
}

#[test]
fn linkage_error_display_empty_proof_inputs() {
    let err = LinkageError::EmptyProofInputs;
    assert!(err.to_string().contains("no proof inputs"));
}

#[test]
fn linkage_error_display_epoch_mismatch() {
    let err = LinkageError::EpochMismatch {
        linkage_epoch: epoch(3),
        current_epoch: epoch(7),
    };
    let msg = err.to_string();
    assert!(msg.contains("epoch mismatch"));
}

#[test]
fn linkage_error_display_ir3_already_specialized() {
    let err = LinkageError::Ir3AlreadySpecialized;
    assert!(err.to_string().contains("already has specialization"));
}

#[test]
fn linkage_error_is_std_error() {
    let err = LinkageError::EmptyProofInputs;
    // Confirm it implements std::error::Error by using it as dyn Error
    let _boxed: Box<dyn std::error::Error> = Box::new(err);
}

#[test]
fn error_code_returns_stable_strings() {
    assert_eq!(
        error_code(&LinkageError::DuplicateLinkage { id: String::new() }),
        "LINKAGE_DUPLICATE"
    );
    assert_eq!(
        error_code(&LinkageError::LinkageNotFound { id: String::new() }),
        "LINKAGE_NOT_FOUND"
    );
    assert_eq!(
        error_code(&LinkageError::AlreadyInactive { id: String::new() }),
        "LINKAGE_ALREADY_INACTIVE"
    );
    assert_eq!(
        error_code(&LinkageError::EmptyProofInputs),
        "LINKAGE_EMPTY_PROOF_INPUTS"
    );
    assert_eq!(
        error_code(&LinkageError::EpochMismatch {
            linkage_epoch: epoch(0),
            current_epoch: epoch(0),
        }),
        "LINKAGE_EPOCH_MISMATCH"
    );
    assert_eq!(
        error_code(&LinkageError::Ir3AlreadySpecialized),
        "LINKAGE_IR3_ALREADY_SPECIALIZED"
    );
}

#[test]
fn invalidation_cause_display_epoch_change() {
    let cause = InvalidationCause::EpochChange {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
    };
    let s = cause.to_string();
    assert!(s.contains("epoch_change"));
}

#[test]
fn invalidation_cause_display_proof_revoked() {
    let cause = InvalidationCause::ProofRevoked {
        proof_id: "pid".to_string(),
    };
    assert!(cause.to_string().contains("proof_revoked(pid)"));
}

#[test]
fn invalidation_cause_display_policy_change() {
    let cause = InvalidationCause::PolicyChange {
        reason: "new-rule".to_string(),
    };
    assert!(cause.to_string().contains("policy_change(new-rule)"));
}

#[test]
fn invalidation_cause_display_manual() {
    let cause = InvalidationCause::ManualInvalidation {
        operator_id: "admin".to_string(),
    };
    assert!(cause.to_string().contains("manual_invalidation(admin)"));
}

#[test]
fn linkage_id_display() {
    let lid = LinkageId::new("display-test");
    assert_eq!(lid.to_string(), "display-test");
    assert_eq!(lid.as_str(), "display-test");
}

// =========================================================================
// 13. PerformanceDelta: NEUTRAL const and Default impl
// =========================================================================

#[test]
fn performance_delta_neutral_values() {
    let n = PerformanceDelta::NEUTRAL;
    assert_eq!(n.speedup_millionths, 1_000_000);
    assert_eq!(n.instruction_ratio_millionths, 1_000_000);
}

#[test]
fn performance_delta_default_equals_neutral() {
    assert_eq!(PerformanceDelta::default(), PerformanceDelta::NEUTRAL);
}

// =========================================================================
// 14. Multi-step integration scenarios
// =========================================================================

#[test]
fn full_lifecycle_register_attach_execute_invalidate() {
    // Create engine at epoch 5
    let mut eng = engine(5);

    // Register two linkages
    let rec_a = linkage_record("lifecycle-a", 5, &["proof-1", "proof-2"]);
    let rec_b = linkage_record("lifecycle-b", 5, &["proof-3"]);
    eng.register(rec_a, "t-reg").unwrap();
    eng.register(rec_b, "t-reg").unwrap();
    assert_eq!(eng.active_count(), 2);

    // Attach linkage-a to IR3
    let mut mod_ir3 = ir3();
    let lid_a = LinkageId::new("lifecycle-a");
    eng.attach_to_ir3(&lid_a, &mut mod_ir3, "t-attach").unwrap();
    assert!(mod_ir3.specialization.is_some());

    // Record execution
    let mut mod_ir4 = ir4();
    mod_ir4.instructions_executed = 500;
    mod_ir4.duration_ticks = 200;
    let perf = PerformanceDelta {
        speedup_millionths: 1_300_000,
        instruction_ratio_millionths: 800_000,
    };
    let exec = eng
        .record_execution(&lid_a, &mut mod_ir4, perf, "t-exec")
        .unwrap();
    assert_eq!(exec.instructions_executed, 500);

    // Epoch change invalidates both
    let rollbacks = eng.on_epoch_change(epoch(6), "t-epoch");
    assert_eq!(rollbacks.len(), 2);
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 2);

    // Rollback plan is now empty (no active linkages)
    assert!(eng.rollback_plan().is_empty());

    // Consumed proof IDs empty (no active linkages)
    assert!(eng.consumed_proof_ids().is_empty());

    // Witness events empty
    assert!(eng.produce_witness_events(0, 0).is_empty());
}

#[test]
fn events_accumulate_across_operations() {
    let mut eng = engine(5);
    // register ok
    eng.register(linkage_record("lnk-1", 5, &["p"]), "t1")
        .unwrap();
    // register duplicate
    let _ = eng.register(linkage_record("lnk-1", 5, &["p"]), "t2");
    // attach
    let mut m = ir3();
    let lid = LinkageId::new("lnk-1");
    eng.attach_to_ir3(&lid, &mut m, "t3").unwrap();
    // execution
    let mut m4 = ir4();
    eng.record_execution(&lid, &mut m4, PerformanceDelta::NEUTRAL, "t4")
        .unwrap();
    // epoch change
    eng.on_epoch_change(epoch(6), "t5");

    // At least 5 events emitted
    assert!(eng.events().len() >= 5);
    // All events have policy_id set
    for ev in eng.events() {
        assert_eq!(ev.policy_id, "integration-policy");
        assert_eq!(ev.component, "proof_specialization_linkage");
    }
}
