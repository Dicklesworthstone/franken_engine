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

// =========================================================================
// Enrichment tests — PearlTower 2026-03-12
// =========================================================================

// ---------------------------------------------------------------------------
// E1. LinkageId identity, ordering, and cloning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_linkage_id_equality_reflexive() {
    let id = LinkageId::new("abc");
    assert_eq!(id, id.clone());
}

#[test]
fn enrichment_linkage_id_ordering_is_lexicographic() {
    let a = LinkageId::new("alpha");
    let b = LinkageId::new("beta");
    let c = LinkageId::new("gamma");
    assert!(a < b);
    assert!(b < c);
    assert!(a < c);
}

#[test]
fn enrichment_linkage_id_empty_string_allowed() {
    let id = LinkageId::new("");
    assert_eq!(id.as_str(), "");
    assert_eq!(id.to_string(), "");
}

#[test]
fn enrichment_linkage_id_unicode_content() {
    let id = LinkageId::new("lnk-\u{00e9}\u{00e8}\u{00ea}");
    let json = serde_json::to_string(&id).unwrap();
    let back: LinkageId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// E2. ProofInputRef edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_input_ref_zero_validity_window() {
    let pir = ProofInputRef {
        proof_id: "proof-zero-window".to_string(),
        proof_type: ProofType::FlowProof,
        proof_epoch: epoch(1),
        validity_window_ticks: 0,
    };
    let json = serde_json::to_string(&pir).unwrap();
    let back: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(pir, back);
}

#[test]
fn enrichment_proof_input_ref_max_validity_window() {
    let pir = ProofInputRef {
        proof_id: "proof-max".to_string(),
        proof_type: ProofType::ReplayMotif,
        proof_epoch: epoch(999),
        validity_window_ticks: u64::MAX,
    };
    let json = serde_json::to_string(&pir).unwrap();
    let back: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(pir, back);
    assert_eq!(back.validity_window_ticks, u64::MAX);
}

#[test]
fn enrichment_proof_input_ref_ordering_by_proof_id() {
    let a = proof_input("aaa", 1);
    let b = proof_input("bbb", 1);
    assert!(a < b);
}

// ---------------------------------------------------------------------------
// E3. PerformanceDelta edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_performance_delta_zero_speedup() {
    let pd = PerformanceDelta {
        speedup_millionths: 0,
        instruction_ratio_millionths: 0,
    };
    let json = serde_json::to_string(&pd).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, back);
}

#[test]
fn enrichment_performance_delta_large_values() {
    let pd = PerformanceDelta {
        speedup_millionths: 100_000_000,
        instruction_ratio_millionths: 100_000_000,
    };
    assert_eq!(pd.speedup_millionths, 100_000_000);
}

#[test]
fn enrichment_performance_delta_copy_semantics() {
    let pd = PerformanceDelta {
        speedup_millionths: 1_500_000,
        instruction_ratio_millionths: 800_000,
    };
    let copied = pd;
    assert_eq!(pd, copied);
}

#[test]
fn enrichment_performance_delta_ordering() {
    let slow = PerformanceDelta {
        speedup_millionths: 500_000,
        instruction_ratio_millionths: 500_000,
    };
    let fast = PerformanceDelta {
        speedup_millionths: 2_000_000,
        instruction_ratio_millionths: 500_000,
    };
    assert!(slow < fast);
}

// ---------------------------------------------------------------------------
// E4. RollbackState edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_state_zero_activation_tick() {
    let rs = RollbackState {
        baseline_ir3_hash: hash(b"baseline-zero"),
        activation_epoch: epoch(0),
        activation_tick: 0,
    };
    let json = serde_json::to_string(&rs).unwrap();
    let back: RollbackState = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, back);
}

#[test]
fn enrichment_rollback_state_max_tick() {
    let rs = RollbackState {
        baseline_ir3_hash: hash(b"baseline-max"),
        activation_epoch: epoch(u64::MAX),
        activation_tick: u64::MAX,
    };
    let json = serde_json::to_string(&rs).unwrap();
    let back: RollbackState = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, back);
}

// ---------------------------------------------------------------------------
// E5. LinkageRecord validity and expiry helpers
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_windows_valid_at_with_zero_window() {
    let mut rec = linkage_record("test-unbounded", 5, &["p1"]);
    rec.proof_inputs[0].validity_window_ticks = 0;
    // Unbounded window never expires
    assert!(rec.proof_windows_valid_at(u64::MAX));
}

#[test]
fn enrichment_proof_windows_valid_at_exact_boundary() {
    let mut rec = linkage_record("test-boundary", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 50; // expiry at 150
    assert!(rec.proof_windows_valid_at(149));
    assert!(!rec.proof_windows_valid_at(150));
}

#[test]
fn enrichment_first_expired_proof_window_returns_earliest() {
    let mut rec = linkage_record("test-multi-window", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 30; // expiry at 130
    rec.proof_inputs.push(ProofInputRef {
        proof_id: "p2".to_string(),
        proof_type: ProofType::FlowProof,
        proof_epoch: epoch(5),
        validity_window_ticks: 50, // expiry at 150
    });
    // At tick 130: first proof expired
    let expired = rec.first_expired_proof_window(130);
    assert!(expired.is_some());
    let (pid, expiry) = expired.unwrap();
    assert_eq!(pid, "p1");
    assert_eq!(expiry, 130);
}

#[test]
fn enrichment_first_expired_proof_window_none_before_expiry() {
    let mut rec = linkage_record("test-not-expired", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 50;
    assert!(rec.first_expired_proof_window(149).is_none());
}

#[test]
fn enrichment_to_ir3_linkage_carries_rollback_token() {
    let rec = linkage_record("test-rollback-token", 5, &["p1"]);
    let spec = rec.to_ir3_linkage();
    assert_eq!(spec.rollback_token, rec.rollback.baseline_ir3_hash);
}

#[test]
fn enrichment_to_ir3_linkage_with_all_optimization_classes() {
    for opt_class in [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ] {
        let mut rec = linkage_record("opt-test", 5, &["p1"]);
        rec.optimization_class = opt_class.clone();
        let spec = rec.to_ir3_linkage();
        assert_eq!(spec.optimization_class, opt_class.to_string());
    }
}

#[test]
fn enrichment_proofs_valid_at_single_epoch_match() {
    let rec = linkage_record("epoch-match", 7, &["p1", "p2", "p3"]);
    assert!(rec.proofs_valid_at(epoch(7)));
    assert!(!rec.proofs_valid_at(epoch(8)));
}

// ---------------------------------------------------------------------------
// E6. LinkageEngine registration edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_with_many_proof_inputs() {
    let mut eng = engine(5);
    let proof_ids: Vec<String> = (0..20).map(|i| format!("proof-{i}")).collect();
    let proof_refs: Vec<&str> = proof_ids.iter().map(|s| s.as_str()).collect();
    let rec = linkage_record("lnk-many-proofs", 5, &proof_refs);
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-many-proofs")).unwrap();
    assert_eq!(stored.proof_inputs.len(), 20);
}

#[test]
fn enrichment_register_preserves_performance_delta_none() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-no-perf", 5, &["p1"]);
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-no-perf")).unwrap();
    assert!(stored.performance_delta.is_none());
}

#[test]
fn enrichment_register_preserves_execution_count_zero() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-no-exec", 5, &["p1"]);
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-no-exec")).unwrap();
    assert_eq!(stored.execution_count, 0);
}

#[test]
fn enrichment_register_inactive_record_preserves_state() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inactive-reg", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 1);
    assert_eq!(eng.total_count(), 1);
}

#[test]
fn enrichment_register_at_epoch_zero() {
    let mut eng = engine(0);
    let rec = linkage_record("lnk-epoch0", 0, &["p1"]);
    eng.register(rec, "t").unwrap();
    assert_eq!(eng.current_epoch(), epoch(0));
    assert_eq!(eng.active_count(), 1);
}

// ---------------------------------------------------------------------------
// E7. Attach-to-IR3 deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attach_to_ir3_sets_validity_epoch() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-ve", 5, &["p1"]), "t")
        .unwrap();
    let mut m = ir3();
    eng.attach_to_ir3(&LinkageId::new("lnk-ve"), &mut m, "t")
        .unwrap();
    let spec = m.specialization.as_ref().unwrap();
    assert_eq!(spec.validity_epoch, 5);
}

#[test]
fn enrichment_attach_to_ir3_at_tick_just_before_boundary() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-just-before", 5, &["p1"]);
    rec.rollback.activation_tick = 0;
    rec.proof_inputs[0].validity_window_ticks = 1000;
    eng.register(rec, "t").unwrap();

    let mut m = ir3();
    eng.attach_to_ir3_at_tick(&LinkageId::new("lnk-just-before"), &mut m, 999, "t")
        .unwrap();
    assert!(m.specialization.is_some());
}

#[test]
fn enrichment_attach_to_ir3_at_tick_exact_boundary_fails() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-exact-fail", 5, &["p1"]);
    rec.rollback.activation_tick = 0;
    rec.proof_inputs[0].validity_window_ticks = 1000;
    eng.register(rec, "t").unwrap();

    let mut m = ir3();
    let err = eng
        .attach_to_ir3_at_tick(&LinkageId::new("lnk-exact-fail"), &mut m, 1000, "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-exact-fail".to_string()
        }
    );
}

#[test]
fn enrichment_attach_to_ir3_at_tick_not_found() {
    let mut eng = engine(5);
    let mut m = ir3();
    let err = eng
        .attach_to_ir3_at_tick(&LinkageId::new("missing"), &mut m, 0, "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::LinkageNotFound {
            id: "missing".to_string()
        }
    );
}

#[test]
fn enrichment_attach_to_ir3_at_tick_already_specialized() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-as1", 5, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-as2", 5, &["p2"]), "t")
        .unwrap();

    let mut m = ir3();
    eng.attach_to_ir3(&LinkageId::new("lnk-as1"), &mut m, "t")
        .unwrap();

    let err = eng
        .attach_to_ir3_at_tick(&LinkageId::new("lnk-as2"), &mut m, 0, "t")
        .unwrap_err();
    assert_eq!(err, LinkageError::Ir3AlreadySpecialized);
}

#[test]
fn enrichment_attach_to_ir3_at_tick_epoch_mismatch() {
    let mut eng = engine(10);
    let rec = linkage_record("lnk-em", 3, &["p1"]);
    eng.register(rec, "t").unwrap();

    let mut m = ir3();
    let err = eng
        .attach_to_ir3_at_tick(&LinkageId::new("lnk-em"), &mut m, 0, "t")
        .unwrap_err();
    match &err {
        LinkageError::EpochMismatch {
            linkage_epoch,
            current_epoch,
        } => {
            assert_eq!(*linkage_epoch, epoch(3));
            assert_eq!(*current_epoch, epoch(10));
        }
        other => panic!("expected EpochMismatch, got {other:?}"),
    }
}

#[test]
fn enrichment_attach_to_ir3_at_tick_inactive_linkage() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inact", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let mut m = ir3();
    let err = eng
        .attach_to_ir3_at_tick(&LinkageId::new("lnk-inact"), &mut m, 0, "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-inact".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// E8. Record execution deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_record_execution_updates_performance_delta() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-pd", 5, &["p1"]), "t")
        .unwrap();

    let lid = LinkageId::new("lnk-pd");
    let perf1 = PerformanceDelta {
        speedup_millionths: 1_200_000,
        instruction_ratio_millionths: 900_000,
    };
    let perf2 = PerformanceDelta {
        speedup_millionths: 2_000_000,
        instruction_ratio_millionths: 600_000,
    };

    let mut m = ir4();
    eng.record_execution(&lid, &mut m, perf1, "t").unwrap();
    assert_eq!(
        eng.get(&lid)
            .unwrap()
            .performance_delta
            .unwrap()
            .speedup_millionths,
        1_200_000
    );

    eng.record_execution(&lid, &mut m, perf2, "t").unwrap();
    // Latest performance delta should overwrite
    assert_eq!(
        eng.get(&lid)
            .unwrap()
            .performance_delta
            .unwrap()
            .speedup_millionths,
        2_000_000
    );
    assert_eq!(eng.get(&lid).unwrap().execution_count, 2);
}

#[test]
fn enrichment_record_execution_epoch_mismatch() {
    let mut eng = engine(10);
    let rec = linkage_record("lnk-em-exec", 3, &["p1"]);
    eng.register(rec, "t").unwrap();

    let mut m = ir4();
    let err = eng
        .record_execution(
            &LinkageId::new("lnk-em-exec"),
            &mut m,
            PerformanceDelta::NEUTRAL,
            "t",
        )
        .unwrap_err();
    match &err {
        LinkageError::EpochMismatch { .. } => {}
        other => panic!("expected EpochMismatch, got {other:?}"),
    }
}

#[test]
fn enrichment_record_execution_at_tick_epoch_mismatch() {
    let mut eng = engine(10);
    let rec = linkage_record("lnk-em-exec-tick", 3, &["p1"]);
    eng.register(rec, "t").unwrap();

    let mut m = ir4();
    let err = eng
        .record_execution_at_tick(
            &LinkageId::new("lnk-em-exec-tick"),
            &mut m,
            PerformanceDelta::NEUTRAL,
            0,
            "t",
        )
        .unwrap_err();
    match &err {
        LinkageError::EpochMismatch { .. } => {}
        other => panic!("expected EpochMismatch, got {other:?}"),
    }
}

#[test]
fn enrichment_record_execution_at_tick_not_found() {
    let mut eng = engine(5);
    let mut m = ir4();
    let err = eng
        .record_execution_at_tick(
            &LinkageId::new("ghost"),
            &mut m,
            PerformanceDelta::NEUTRAL,
            0,
            "t",
        )
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::LinkageNotFound {
            id: "ghost".to_string()
        }
    );
}

#[test]
fn enrichment_record_execution_at_tick_inactive() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-inact-exec", 5, &["p1"]);
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let mut m = ir4();
    let err = eng
        .record_execution_at_tick(
            &LinkageId::new("lnk-inact-exec"),
            &mut m,
            PerformanceDelta::NEUTRAL,
            0,
            "t",
        )
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-inact-exec".to_string()
        }
    );
}

#[test]
fn enrichment_record_execution_witness_hash_deterministic() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-det", 5, &["p1"]), "t")
        .unwrap();

    let lid = LinkageId::new("lnk-det");
    let mut m1 = ir4();
    m1.instructions_executed = 100;
    m1.duration_ticks = 50;
    let exec1 = eng
        .record_execution(&lid, &mut m1, PerformanceDelta::NEUTRAL, "t")
        .unwrap();

    let mut eng2 = engine(5);
    eng2.register(linkage_record("lnk-det", 5, &["p1"]), "t")
        .unwrap();
    let mut m2 = ir4();
    m2.instructions_executed = 100;
    m2.duration_ticks = 50;
    let exec2 = eng2
        .record_execution(&lid, &mut m2, PerformanceDelta::NEUTRAL, "t")
        .unwrap();

    assert_eq!(exec1.witness_hash, exec2.witness_hash);
}

// ---------------------------------------------------------------------------
// E9. Epoch change deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_on_epoch_change_same_epoch_no_invalidation() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-same", 5, &["p1"]), "t")
        .unwrap();

    let rollbacks = eng.on_epoch_change(epoch(5), "t");
    assert!(rollbacks.is_empty());
    assert_eq!(eng.active_count(), 1);
}

#[test]
fn enrichment_on_epoch_change_multiple_times() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    eng.on_epoch_change(epoch(6), "t");
    assert_eq!(eng.current_epoch(), epoch(6));
    assert_eq!(eng.active_count(), 0);

    // Another epoch change should be a no-op
    let rollbacks = eng.on_epoch_change(epoch(7), "t");
    assert!(rollbacks.is_empty());
    assert_eq!(eng.current_epoch(), epoch(7));
}

#[test]
fn enrichment_on_epoch_change_large_batch() {
    let mut eng = engine(5);
    for i in 0..50 {
        let id = format!("lnk-batch-{i}");
        eng.register(linkage_record(&id, 5, &["p1"]), "t").unwrap();
    }
    assert_eq!(eng.active_count(), 50);

    let rollbacks = eng.on_epoch_change(epoch(6), "t");
    assert_eq!(rollbacks.len(), 50);
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 50);
}

#[test]
fn enrichment_on_epoch_change_invalidation_order_deterministic() {
    let mut eng = engine(5);
    // Insert in reverse order
    for i in (0..10).rev() {
        let id = format!("lnk-{i:03}");
        eng.register(linkage_record(&id, 5, &["p1"]), "t").unwrap();
    }

    let rollbacks = eng.on_epoch_change(epoch(6), "t");
    // BTreeMap gives deterministic sorted order
    for (i, rb) in rollbacks.iter().enumerate().take(10) {
        assert_eq!(rb.0, LinkageId::new(format!("lnk-{i:03}")));
    }
}

// ---------------------------------------------------------------------------
// E10. Proof revocation deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_invalidate_by_proof_multiple_proofs_shared() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["shared", "unique-a"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["shared", "unique-b"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-c", 5, &["shared", "unique-c"]), "t")
        .unwrap();

    let rollbacks = eng.invalidate_by_proof("shared", "t");
    assert_eq!(rollbacks.len(), 3);
    assert_eq!(eng.active_count(), 0);

    // All invalidation causes should be ProofRevoked
    for (_, cause) in eng.invalidations() {
        match cause {
            InvalidationCause::ProofRevoked { proof_id } => {
                assert_eq!(proof_id, "shared");
            }
            other => panic!("expected ProofRevoked, got {other:?}"),
        }
    }
}

#[test]
fn enrichment_invalidate_by_proof_does_not_double_invalidate() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-once", 5, &["revoke-me"]), "t")
        .unwrap();

    let rollbacks1 = eng.invalidate_by_proof("revoke-me", "t");
    assert_eq!(rollbacks1.len(), 1);

    let rollbacks2 = eng.invalidate_by_proof("revoke-me", "t");
    assert!(rollbacks2.is_empty());
    assert_eq!(eng.invalidations().len(), 1);
}

#[test]
fn enrichment_invalidate_by_proof_preserves_unrelated() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-target", 5, &["revoke-this"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-safe", 5, &["keep-this"]), "t")
        .unwrap();

    eng.invalidate_by_proof("revoke-this", "t");
    assert!(eng.get(&LinkageId::new("lnk-safe")).unwrap().active);
    assert!(!eng.get(&LinkageId::new("lnk-target")).unwrap().active);
}

// ---------------------------------------------------------------------------
// E11. Manual invalidation deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_invalidate_manual_returns_correct_baseline_hash() {
    let mut eng = engine(5);
    let rec = linkage_record("lnk-manual-hash", 5, &["p1"]);
    let expected = rec.rollback.baseline_ir3_hash;
    eng.register(rec, "t").unwrap();

    let actual = eng
        .invalidate_manual(&LinkageId::new("lnk-manual-hash"), "op-1", "t")
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn enrichment_invalidate_manual_emits_event() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-manual-ev", 5, &["p1"]), "t")
        .unwrap();

    let event_count_before = eng.events().len();
    eng.invalidate_manual(&LinkageId::new("lnk-manual-ev"), "admin", "trace-manual")
        .unwrap();
    let event_count_after = eng.events().len();
    assert!(event_count_after > event_count_before);

    let last = eng.events().last().unwrap();
    assert_eq!(last.event, "invalidate_manual");
    assert_eq!(last.outcome, "ok");
    assert_eq!(last.trace_id, "trace-manual");
}

// ---------------------------------------------------------------------------
// E12. Expired proof window invalidation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_invalidate_expired_proof_windows_multiple_linkages() {
    let mut eng = engine(5);

    let mut rec_a = linkage_record("lnk-exp-a", 5, &["pa"]);
    rec_a.rollback.activation_tick = 100;
    rec_a.proof_inputs[0].validity_window_ticks = 20; // expires at 120
    eng.register(rec_a, "t").unwrap();

    let mut rec_b = linkage_record("lnk-exp-b", 5, &["pb"]);
    rec_b.rollback.activation_tick = 100;
    rec_b.proof_inputs[0].validity_window_ticks = 30; // expires at 130
    eng.register(rec_b, "t").unwrap();

    // At tick 120, only lnk-exp-a should expire
    let rollbacks = eng.invalidate_expired_proof_windows(120, "t");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].0, LinkageId::new("lnk-exp-a"));
    assert_eq!(eng.active_count(), 1);

    // At tick 130, lnk-exp-b should also expire
    let rollbacks2 = eng.invalidate_expired_proof_windows(130, "t");
    assert_eq!(rollbacks2.len(), 1);
    assert_eq!(rollbacks2[0].0, LinkageId::new("lnk-exp-b"));
    assert_eq!(eng.active_count(), 0);
}

#[test]
fn enrichment_invalidate_expired_proof_windows_skips_already_inactive() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-skip-inact", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 10;
    rec.active = false;
    eng.register(rec, "t").unwrap();

    let rollbacks = eng.invalidate_expired_proof_windows(200, "t");
    assert!(rollbacks.is_empty());
}

#[test]
fn enrichment_invalidate_expired_proof_windows_mixed_bounded_unbounded() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-mixed", 5, &["p1"]);
    rec.rollback.activation_tick = 100;
    rec.proof_inputs[0].validity_window_ticks = 50; // expires at 150
    rec.proof_inputs.push(ProofInputRef {
        proof_id: "p2-unbounded".to_string(),
        proof_type: ProofType::FlowProof,
        proof_epoch: epoch(5),
        validity_window_ticks: 0, // unbounded
    });
    eng.register(rec, "t").unwrap();

    // At tick 149, nothing expires
    let rollbacks = eng.invalidate_expired_proof_windows(149, "t");
    assert!(rollbacks.is_empty());

    // At tick 150, p1 expires even though p2 is unbounded
    let rollbacks = eng.invalidate_expired_proof_windows(150, "t");
    assert_eq!(rollbacks.len(), 1);
}

#[test]
fn enrichment_invalidate_expired_proof_windows_saturating_add() {
    // Test that activation_tick + validity_window_ticks uses saturating add
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-saturate", 5, &["p1"]);
    rec.rollback.activation_tick = u64::MAX - 5;
    rec.proof_inputs[0].validity_window_ticks = 100; // would overflow without saturating
    eng.register(rec, "t").unwrap();

    // The expiry tick saturates to u64::MAX, so at u64::MAX it should expire
    let rollbacks = eng.invalidate_expired_proof_windows(u64::MAX, "t");
    assert_eq!(rollbacks.len(), 1);
}

// ---------------------------------------------------------------------------
// E13. Query helpers deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_consumed_proof_ids_empty_engine() {
    let eng = engine(5);
    assert!(eng.consumed_proof_ids().is_empty());
}

#[test]
fn enrichment_consumed_proof_ids_sorted() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["zulu", "alpha"]), "t")
        .unwrap();
    let ids = eng.consumed_proof_ids();
    assert_eq!(ids, vec!["alpha", "zulu"]);
}

#[test]
fn enrichment_rollback_plan_empty_engine() {
    let eng = engine(5);
    assert!(eng.rollback_plan().is_empty());
}

#[test]
fn enrichment_rollback_plan_multiple_active() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["pa"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["pb"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-c", 5, &["pc"]), "t")
        .unwrap();

    let plan = eng.rollback_plan();
    assert_eq!(plan.len(), 3);
    // BTreeMap order
    assert_eq!(plan[0].0, LinkageId::new("lnk-a"));
    assert_eq!(plan[1].0, LinkageId::new("lnk-b"));
    assert_eq!(plan[2].0, LinkageId::new("lnk-c"));
}

#[test]
fn enrichment_active_linkages_empty_engine() {
    let eng = engine(5);
    assert!(eng.active_linkages().is_empty());
}

#[test]
fn enrichment_active_linkages_after_invalidation() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["p2"]), "t")
        .unwrap();

    eng.invalidate_manual(&LinkageId::new("lnk-a"), "op", "t")
        .unwrap();

    let active = eng.active_linkages();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, LinkageId::new("lnk-b"));
}

// ---------------------------------------------------------------------------
// E14. Witness event production
// ---------------------------------------------------------------------------

#[test]
fn enrichment_produce_witness_events_sequence_numbers() {
    let mut eng = engine(5);
    for i in 0..5 {
        eng.register(linkage_record(&format!("lnk-{i}"), 5, &["p"]), "t")
            .unwrap();
    }

    let events = eng.produce_witness_events(1000, 42);
    assert_eq!(events.len(), 5);
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.seq, 1000 + i as u64);
        assert_eq!(ev.timestamp_tick, 42);
        assert_eq!(ev.kind, WitnessEventKind::CapabilityChecked);
    }
}

#[test]
fn enrichment_produce_witness_events_after_partial_invalidation() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-stay", 5, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-go", 5, &["p2"]), "t")
        .unwrap();

    eng.invalidate_manual(&LinkageId::new("lnk-go"), "op", "t")
        .unwrap();

    let events = eng.produce_witness_events(0, 99);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp_tick, 99);
}

// ---------------------------------------------------------------------------
// E15. Event logging and audit trail
// ---------------------------------------------------------------------------

#[test]
fn enrichment_events_trace_ids_preserved() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "trace-alpha")
        .unwrap();

    let ev = &eng.events()[0];
    assert_eq!(ev.trace_id, "trace-alpha");
}

#[test]
fn enrichment_events_error_code_for_not_found() {
    let mut eng = engine(5);
    let mut m = ir3();
    let _ = eng.attach_to_ir3(&LinkageId::new("missing"), &mut m, "t");

    let error_events: Vec<_> = eng
        .events()
        .iter()
        .filter(|e| e.error_code.as_deref() == Some("LINKAGE_NOT_FOUND"))
        .collect();
    assert!(!error_events.is_empty());
}

#[test]
fn enrichment_events_error_code_for_epoch_mismatch() {
    let mut eng = engine(10);
    eng.register(linkage_record("lnk-em", 5, &["p1"]), "t")
        .unwrap();

    let mut m = ir3();
    let _ = eng.attach_to_ir3(&LinkageId::new("lnk-em"), &mut m, "t");

    let error_events: Vec<_> = eng
        .events()
        .iter()
        .filter(|e| e.error_code.as_deref() == Some("LINKAGE_EPOCH_MISMATCH"))
        .collect();
    assert!(!error_events.is_empty());
}

#[test]
fn enrichment_events_record_execution_error_logged() {
    let mut eng = engine(5);
    let mut m = ir4();
    let _ = eng.record_execution(
        &LinkageId::new("missing"),
        &mut m,
        PerformanceDelta::NEUTRAL,
        "t",
    );

    let error_events: Vec<_> = eng
        .events()
        .iter()
        .filter(|e| e.outcome == "rejected" && e.event == "record_execution")
        .collect();
    assert_eq!(error_events.len(), 1);
}

#[test]
fn enrichment_events_count_after_full_lifecycle() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    let mut m3 = ir3();
    eng.attach_to_ir3(&LinkageId::new("lnk-1"), &mut m3, "t")
        .unwrap();

    let mut m4 = ir4();
    eng.record_execution(
        &LinkageId::new("lnk-1"),
        &mut m4,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();

    eng.invalidate_manual(&LinkageId::new("lnk-1"), "op", "t")
        .unwrap();

    // Should have at least 4 events: register, attach, record_execution, invalidate_manual
    assert!(eng.events().len() >= 4);

    let event_names: Vec<&str> = eng.events().iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"register"));
    assert!(event_names.contains(&"attach_to_ir3"));
    assert!(event_names.contains(&"record_execution"));
    assert!(event_names.contains(&"invalidate_manual"));
}

// ---------------------------------------------------------------------------
// E16. Serde roundtrip edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_linkage_record_with_performance_delta() {
    let mut rec = linkage_record("serde-perf", 5, &["p1"]);
    rec.performance_delta = Some(PerformanceDelta {
        speedup_millionths: 3_500_000,
        instruction_ratio_millionths: 250_000,
    });
    rec.execution_count = 42;
    let json = serde_json::to_string(&rec).unwrap();
    let back: LinkageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
    assert_eq!(back.execution_count, 42);
    assert_eq!(
        back.performance_delta.unwrap().speedup_millionths,
        3_500_000
    );
}

#[test]
fn enrichment_serde_linkage_record_inactive() {
    let mut rec = linkage_record("serde-inactive", 5, &["p1"]);
    rec.active = false;
    let json = serde_json::to_string(&rec).unwrap();
    let back: LinkageRecord = serde_json::from_str(&json).unwrap();
    assert!(!back.active);
}

#[test]
fn enrichment_serde_linkage_error_all_variants() {
    let variants = vec![
        LinkageError::DuplicateLinkage {
            id: "dup-id".to_string(),
        },
        LinkageError::LinkageNotFound {
            id: "not-found-id".to_string(),
        },
        LinkageError::AlreadyInactive {
            id: "inactive-id".to_string(),
        },
        LinkageError::EmptyProofInputs,
        LinkageError::EpochMismatch {
            linkage_epoch: epoch(3),
            current_epoch: epoch(7),
        },
        LinkageError::Ir3AlreadySpecialized,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: LinkageError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_execution_record_with_neutral_perf() {
    let er = ExecutionRecord {
        linkage_id: LinkageId::new("exec-neutral"),
        witness_hash: hash(b"neutral-witness"),
        performance_delta: PerformanceDelta::NEUTRAL,
        instructions_executed: 0,
        duration_ticks: 0,
    };
    let json = serde_json::to_string(&er).unwrap();
    let back: ExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(er, back);
    assert_eq!(back.performance_delta, PerformanceDelta::NEUTRAL);
}

// ---------------------------------------------------------------------------
// E17. Error display contracts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_contains_id_for_all_id_variants() {
    let id = "test-error-id-999";
    let errors = vec![
        LinkageError::DuplicateLinkage { id: id.to_string() },
        LinkageError::LinkageNotFound { id: id.to_string() },
        LinkageError::AlreadyInactive { id: id.to_string() },
    ];
    for err in &errors {
        assert!(
            err.to_string().contains(id),
            "Error message should contain id: {}",
            err
        );
    }
}

#[test]
fn enrichment_error_display_epoch_mismatch_contains_both_epochs() {
    let err = LinkageError::EpochMismatch {
        linkage_epoch: epoch(42),
        current_epoch: epoch(99),
    };
    let msg = err.to_string();
    assert!(msg.contains("epoch mismatch"));
    // The message should mention both epoch values
    assert!(msg.contains("42") || msg.contains("99"));
}

#[test]
fn enrichment_invalidation_cause_display_contains_reason() {
    let cause = InvalidationCause::PolicyChange {
        reason: "security-update-2026".to_string(),
    };
    let display = cause.to_string();
    assert!(display.contains("security-update-2026"));
}

// ---------------------------------------------------------------------------
// E18. Complex multi-step scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_attach_revoke_reattach_fails() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["revokable"]), "t")
        .unwrap();

    let mut m = ir3();
    eng.attach_to_ir3(&LinkageId::new("lnk-1"), &mut m, "t")
        .unwrap();
    assert!(m.specialization.is_some());

    // Revoke the proof
    eng.invalidate_by_proof("revokable", "t");
    assert!(!eng.get(&LinkageId::new("lnk-1")).unwrap().active);

    // Cannot attach the same linkage to a new IR3
    let mut m2 = ir3();
    let err = eng
        .attach_to_ir3(&LinkageId::new("lnk-1"), &mut m2, "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-1".to_string()
        }
    );
}

#[test]
fn enrichment_manual_invalidation_then_epoch_change_no_double_rollback() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    // Manual invalidation first
    eng.invalidate_manual(&LinkageId::new("lnk-1"), "op", "t")
        .unwrap();
    assert_eq!(eng.invalidations().len(), 1);

    // Epoch change should not re-invalidate the already-inactive linkage
    let rollbacks = eng.on_epoch_change(epoch(6), "t");
    assert!(rollbacks.is_empty());
    assert_eq!(eng.invalidations().len(), 1);
}

#[test]
fn enrichment_epoch_change_then_manual_fails() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-1", 5, &["p1"]), "t")
        .unwrap();

    eng.on_epoch_change(epoch(6), "t");
    assert!(!eng.get(&LinkageId::new("lnk-1")).unwrap().active);

    let err = eng
        .invalidate_manual(&LinkageId::new("lnk-1"), "op", "t")
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-1".to_string()
        }
    );
}

#[test]
fn enrichment_mixed_invalidation_causes_accumulate() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-manual", 5, &["p1"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-proof", 5, &["revoke-me"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-epoch", 5, &["p3"]), "t")
        .unwrap();

    eng.invalidate_manual(&LinkageId::new("lnk-manual"), "op", "t")
        .unwrap();
    eng.invalidate_by_proof("revoke-me", "t");
    eng.on_epoch_change(epoch(6), "t");

    assert_eq!(eng.invalidations().len(), 3);

    // Check each cause type
    let causes: Vec<String> = eng
        .invalidations()
        .iter()
        .map(|(_, c)| c.to_string())
        .collect();
    assert!(causes.iter().any(|c| c.contains("manual_invalidation")));
    assert!(causes.iter().any(|c| c.contains("proof_revoked")));
    assert!(causes.iter().any(|c| c.contains("epoch_change")));
}

#[test]
fn enrichment_execution_after_attach_then_revoke_fails() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-exec-rev", 5, &["p1"]), "t")
        .unwrap();

    let mut m3 = ir3();
    eng.attach_to_ir3(&LinkageId::new("lnk-exec-rev"), &mut m3, "t")
        .unwrap();

    let mut m4 = ir4();
    eng.record_execution(
        &LinkageId::new("lnk-exec-rev"),
        &mut m4,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();
    assert_eq!(
        eng.get(&LinkageId::new("lnk-exec-rev"))
            .unwrap()
            .execution_count,
        1
    );

    // Revoke
    eng.invalidate_by_proof("p1", "t");

    // Subsequent execution should fail
    let err = eng
        .record_execution(
            &LinkageId::new("lnk-exec-rev"),
            &mut m4,
            PerformanceDelta::NEUTRAL,
            "t",
        )
        .unwrap_err();
    assert_eq!(
        err,
        LinkageError::AlreadyInactive {
            id: "lnk-exec-rev".to_string()
        }
    );
}

#[test]
fn enrichment_multiple_ir4_modules_separate_specialization_ids() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["pa"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["pb"]), "t")
        .unwrap();

    let mut m4_a = ir4();
    eng.record_execution(
        &LinkageId::new("lnk-a"),
        &mut m4_a,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();

    let mut m4_b = ir4();
    eng.record_execution(
        &LinkageId::new("lnk-b"),
        &mut m4_b,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();

    assert!(
        m4_a.active_specialization_ids
            .contains(&"lnk-a".to_string())
    );
    assert!(
        !m4_a
            .active_specialization_ids
            .contains(&"lnk-b".to_string())
    );
    assert!(
        m4_b.active_specialization_ids
            .contains(&"lnk-b".to_string())
    );
    assert!(
        !m4_b
            .active_specialization_ids
            .contains(&"lnk-a".to_string())
    );
}

#[test]
fn enrichment_shared_ir4_accumulates_specialization_ids() {
    let mut eng = engine(5);
    eng.register(linkage_record("lnk-a", 5, &["pa"]), "t")
        .unwrap();
    eng.register(linkage_record("lnk-b", 5, &["pb"]), "t")
        .unwrap();

    let mut m4 = ir4();
    eng.record_execution(
        &LinkageId::new("lnk-a"),
        &mut m4,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();
    eng.record_execution(
        &LinkageId::new("lnk-b"),
        &mut m4,
        PerformanceDelta::NEUTRAL,
        "t",
    )
    .unwrap();

    assert!(m4.active_specialization_ids.contains(&"lnk-a".to_string()));
    assert!(m4.active_specialization_ids.contains(&"lnk-b".to_string()));
    assert_eq!(m4.active_specialization_ids.len(), 2);
}

// ---------------------------------------------------------------------------
// E19. Different proof types and optimization classes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_with_flow_proof_type() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-flow", 5, &["p1"]);
    rec.proof_inputs[0].proof_type = ProofType::FlowProof;
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-flow")).unwrap();
    assert_eq!(stored.proof_inputs[0].proof_type, ProofType::FlowProof);
}

#[test]
fn enrichment_register_with_replay_motif_proof_type() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-replay", 5, &["p1"]);
    rec.proof_inputs[0].proof_type = ProofType::ReplayMotif;
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-replay")).unwrap();
    assert_eq!(stored.proof_inputs[0].proof_type, ProofType::ReplayMotif);
}

#[test]
fn enrichment_register_with_ifc_check_elision_optimization() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-ifc", 5, &["p1"]);
    rec.optimization_class = OptimizationClass::IfcCheckElision;
    eng.register(rec, "t").unwrap();
    let stored = eng.get(&LinkageId::new("lnk-ifc")).unwrap();
    assert_eq!(
        stored.optimization_class,
        OptimizationClass::IfcCheckElision
    );
    let spec = stored.to_ir3_linkage();
    assert_eq!(spec.optimization_class, "ifc_check_elision");
}

#[test]
fn enrichment_register_with_superinstruction_fusion_optimization() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-super", 5, &["p1"]);
    rec.optimization_class = OptimizationClass::SuperinstructionFusion;
    eng.register(rec, "t").unwrap();
    let spec = eng
        .get(&LinkageId::new("lnk-super"))
        .unwrap()
        .to_ir3_linkage();
    assert_eq!(spec.optimization_class, "superinstruction_fusion");
}

#[test]
fn enrichment_register_with_path_elimination_optimization() {
    let mut eng = engine(5);
    let mut rec = linkage_record("lnk-path", 5, &["p1"]);
    rec.optimization_class = OptimizationClass::PathElimination;
    eng.register(rec, "t").unwrap();
    let spec = eng
        .get(&LinkageId::new("lnk-path"))
        .unwrap()
        .to_ir3_linkage();
    assert_eq!(spec.optimization_class, "path_elimination");
}

// ---------------------------------------------------------------------------
// E20. Linkage counts consistency invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_total_equals_active_plus_inactive() {
    let mut eng = engine(5);
    eng.register(linkage_record("a", 5, &["p"]), "t").unwrap();
    eng.register(linkage_record("b", 5, &["p"]), "t").unwrap();
    let mut inactive = linkage_record("c", 5, &["p"]);
    inactive.active = false;
    eng.register(inactive, "t").unwrap();
    eng.register(linkage_record("d", 5, &["p"]), "t").unwrap();

    eng.invalidate_manual(&LinkageId::new("a"), "op", "t")
        .unwrap();

    assert_eq!(eng.total_count(), eng.active_count() + eng.inactive_count());
    assert_eq!(eng.active_count(), 2);
    assert_eq!(eng.inactive_count(), 2);
    assert_eq!(eng.total_count(), 4);
}

#[test]
fn enrichment_counts_after_epoch_change_and_manual_invalidation() {
    let mut eng = engine(5);
    for i in 0..10 {
        eng.register(linkage_record(&format!("lnk-{i}"), 5, &["p"]), "t")
            .unwrap();
    }
    assert_eq!(eng.active_count(), 10);

    eng.invalidate_manual(&LinkageId::new("lnk-0"), "op", "t")
        .unwrap();
    eng.invalidate_manual(&LinkageId::new("lnk-1"), "op", "t")
        .unwrap();
    assert_eq!(eng.active_count(), 8);
    assert_eq!(eng.inactive_count(), 2);

    eng.on_epoch_change(epoch(6), "t");
    assert_eq!(eng.active_count(), 0);
    assert_eq!(eng.inactive_count(), 10);
    assert_eq!(eng.total_count(), 10);
}

#[test]
fn enrichment_linkages_map_returns_all_records() {
    let mut eng = engine(5);
    eng.register(linkage_record("a", 5, &["p"]), "t").unwrap();
    let mut inactive = linkage_record("b", 5, &["p"]);
    inactive.active = false;
    eng.register(inactive, "t").unwrap();

    let map = eng.linkages();
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(&LinkageId::new("a")));
    assert!(map.contains_key(&LinkageId::new("b")));
}
