//! Enrichment integration tests for the `proof_specialization_linkage` module.
//!
//! Covers: LinkageId ordering/Hash, PerformanceDelta Ord/serde, proof-window
//! expiry boundary logic, attach_to_ir3_at_tick fail-close on expired windows,
//! record_execution_at_tick fail-close, invalidate_expired_proof_windows sweep,
//! invalidate_by_proof multi-linkage, consumed_proof_ids ordering,
//! produce_witness_events sequencing, Debug formatting, determinism.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Module, Ir4Module};
use frankenengine_engine::proof_specialization_linkage::{
    ExecutionRecord, InvalidationCause, LinkageEngine, LinkageError, LinkageEvent, LinkageId,
    LinkageRecord, PerformanceDelta, ProofInputRef, RollbackState, error_code,
};
use frankenengine_engine::proof_specialization_receipt::{OptimizationClass, ProofType};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn proof_input(id: &str, epoch_n: u64, window: u64) -> ProofInputRef {
    ProofInputRef {
        proof_id: id.to_string(),
        proof_type: ProofType::CapabilityWitness,
        proof_epoch: epoch(epoch_n),
        validity_window_ticks: window,
    }
}

fn make_record(lid: &str, epoch_n: u64, proofs: Vec<ProofInputRef>) -> LinkageRecord {
    LinkageRecord {
        id: LinkageId::new(lid),
        proof_inputs: proofs,
        optimization_class: OptimizationClass::IfcCheckElision,
        validity_epoch: epoch(epoch_n),
        specialized_ir3_hash: hash(lid.as_bytes()),
        rollback: RollbackState {
            baseline_ir3_hash: hash(b"baseline"),
            activation_epoch: epoch(epoch_n),
            activation_tick: 100,
        },
        active: true,
        performance_delta: None,
        execution_count: 0,
    }
}

fn make_engine() -> LinkageEngine {
    LinkageEngine::new("pol-001", epoch(1))
}

fn blank_ir3() -> Ir3Module {
    Ir3Module::new(hash(b"source"), "test-module")
}

fn blank_ir4() -> Ir4Module {
    Ir4Module::new(hash(b"ir3-hash"), "test-witness")
}

// =========================================================================
// A. LinkageId — ordering, Hash, Display
// =========================================================================

#[test]
fn enrichment_linkage_id_ordering() {
    let a = LinkageId::new("aaa");
    let b = LinkageId::new("bbb");
    let c = LinkageId::new("zzz");
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn enrichment_linkage_id_hash_distinct() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ids = ["alpha", "beta", "gamma"];
    let hashes: BTreeSet<u64> = ids
        .iter()
        .map(|s| {
            let mut h = DefaultHasher::new();
            LinkageId::new(*s).hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(hashes.len(), 3);
}

#[test]
fn enrichment_linkage_id_as_str_matches_display() {
    let id = LinkageId::new("link-42");
    assert_eq!(id.as_str(), "link-42");
    assert_eq!(id.to_string(), "link-42");
}

// =========================================================================
// B. PerformanceDelta — Ord, serde, neutral
// =========================================================================

#[test]
fn enrichment_performance_delta_ordering() {
    let a = PerformanceDelta {
        speedup_millionths: 500_000,
        instruction_ratio_millionths: 1_000_000,
    };
    let b = PerformanceDelta {
        speedup_millionths: 1_500_000,
        instruction_ratio_millionths: 1_000_000,
    };
    assert!(a < b);
}

#[test]
fn enrichment_performance_delta_serde_roundtrip() {
    let delta = PerformanceDelta {
        speedup_millionths: 2_000_000,
        instruction_ratio_millionths: 600_000,
    };
    let json = serde_json::to_string(&delta).unwrap();
    let restored: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, restored);
}

#[test]
fn enrichment_performance_delta_neutral_is_default() {
    assert_eq!(PerformanceDelta::default(), PerformanceDelta::NEUTRAL);
    assert_eq!(PerformanceDelta::NEUTRAL.speedup_millionths, 1_000_000);
    assert_eq!(
        PerformanceDelta::NEUTRAL.instruction_ratio_millionths,
        1_000_000
    );
}

// =========================================================================
// C. Proof-window expiry boundary logic
// =========================================================================

#[test]
fn enrichment_proof_window_zero_means_unbounded() {
    let record = make_record("link-1", 1, vec![proof_input("p1", 1, 0)]);
    // Even at a very large tick, window 0 never expires
    assert!(record.proof_windows_valid_at(u64::MAX));
    assert!(record.first_expired_proof_window(u64::MAX).is_none());
}

#[test]
fn enrichment_proof_window_exact_expiry_boundary() {
    let mut record = make_record("link-1", 1, vec![proof_input("p1", 1, 50)]);
    record.rollback.activation_tick = 100;
    // Expiry is activation_tick + window = 100 + 50 = 150
    // At tick 149, still valid
    assert!(record.proof_windows_valid_at(149));
    // At tick 150, expired (>= expiry_tick)
    assert!(!record.proof_windows_valid_at(150));
    let (id, expiry) = record.first_expired_proof_window(150).unwrap();
    assert_eq!(id, "p1");
    assert_eq!(expiry, 150);
}

#[test]
fn enrichment_proof_window_multiple_proofs_first_expired() {
    let mut record = make_record(
        "link-1",
        1,
        vec![proof_input("p-short", 1, 10), proof_input("p-long", 1, 100)],
    );
    record.rollback.activation_tick = 100;
    // p-short expires at 110, p-long at 200
    // At tick 115, p-short is expired
    let (id, _) = record.first_expired_proof_window(115).unwrap();
    assert_eq!(id, "p-short");
}

// =========================================================================
// D. attach_to_ir3_at_tick — fail-close on expired proof window
// =========================================================================

#[test]
fn enrichment_attach_at_tick_fails_closed_on_expired_window() {
    let mut engine = make_engine();
    let mut rec = make_record("link-1", 1, vec![proof_input("p1", 1, 50)]);
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t-reg").unwrap();

    let mut ir3 = blank_ir3();
    // tick 150 = exactly at expiry
    let result = engine.attach_to_ir3_at_tick(&LinkageId::new("link-1"), &mut ir3, 150, "t-att");
    assert!(matches!(result, Err(LinkageError::AlreadyInactive { .. })));

    // Linkage should now be inactive
    let record = engine.get(&LinkageId::new("link-1")).unwrap();
    assert!(!record.active);

    // Invalidation should be logged
    assert!(!engine.invalidations().is_empty());
}

#[test]
fn enrichment_attach_at_tick_succeeds_before_expiry() {
    let mut engine = make_engine();
    let mut rec = make_record("link-1", 1, vec![proof_input("p1", 1, 50)]);
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t-reg").unwrap();

    let mut ir3 = blank_ir3();
    // tick 149 = just before expiry
    engine
        .attach_to_ir3_at_tick(&LinkageId::new("link-1"), &mut ir3, 149, "t-att")
        .unwrap();
    assert!(ir3.specialization.is_some());
}

// =========================================================================
// E. record_execution_at_tick — fail-close on expired proof window
// =========================================================================

#[test]
fn enrichment_record_execution_at_tick_fails_on_expired_window() {
    let mut engine = make_engine();
    let mut rec = make_record("link-1", 1, vec![proof_input("p1", 1, 30)]);
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t-reg").unwrap();

    let mut ir4 = blank_ir4();
    let result = engine.record_execution_at_tick(
        &LinkageId::new("link-1"),
        &mut ir4,
        PerformanceDelta::NEUTRAL,
        130, // exactly at expiry
        "t-exec",
    );
    assert!(matches!(result, Err(LinkageError::AlreadyInactive { .. })));
}

// =========================================================================
// F. invalidate_expired_proof_windows — sweep
// =========================================================================

#[test]
fn enrichment_invalidate_expired_sweep_catches_all_expired() {
    let mut engine = make_engine();

    // Two linkages with different windows
    let mut r1 = make_record("link-1", 1, vec![proof_input("p1", 1, 20)]);
    r1.rollback.activation_tick = 100;
    engine.register(r1, "t-r1").unwrap();

    let mut r2 = make_record("link-2", 1, vec![proof_input("p2", 1, 30)]);
    r2.rollback.activation_tick = 100;
    engine.register(r2, "t-r2").unwrap();

    let mut r3 = make_record("link-3", 1, vec![proof_input("p3", 1, 0)]);
    r3.rollback.activation_tick = 100;
    engine.register(r3, "t-r3").unwrap();

    // At tick 130: link-1 expired (120), link-2 expired (130), link-3 unbounded
    let rollbacks = engine.invalidate_expired_proof_windows(130, "t-sweep");
    assert_eq!(rollbacks.len(), 2);
    // link-3 should still be active
    assert!(engine.get(&LinkageId::new("link-3")).unwrap().active);
    assert_eq!(engine.active_count(), 1);
}

// =========================================================================
// G. invalidate_by_proof — targets correct linkages
// =========================================================================

#[test]
fn enrichment_invalidate_by_proof_targets_only_matching() {
    let mut engine = make_engine();

    engine
        .register(
            make_record("link-a", 1, vec![proof_input("shared-proof", 1, 0)]),
            "t-a",
        )
        .unwrap();
    engine
        .register(
            make_record("link-b", 1, vec![proof_input("other-proof", 1, 0)]),
            "t-b",
        )
        .unwrap();
    engine
        .register(
            make_record(
                "link-c",
                1,
                vec![
                    proof_input("shared-proof", 1, 0),
                    proof_input("another", 1, 0),
                ],
            ),
            "t-c",
        )
        .unwrap();

    let rollbacks = engine.invalidate_by_proof("shared-proof", "t-inv");
    assert_eq!(rollbacks.len(), 2); // link-a and link-c
    assert!(!engine.get(&LinkageId::new("link-a")).unwrap().active);
    assert!(engine.get(&LinkageId::new("link-b")).unwrap().active);
    assert!(!engine.get(&LinkageId::new("link-c")).unwrap().active);
}

// =========================================================================
// H. consumed_proof_ids — dedup and sorted
// =========================================================================

#[test]
fn enrichment_consumed_proof_ids_dedup_and_sorted() {
    let mut engine = make_engine();
    engine
        .register(
            make_record(
                "link-1",
                1,
                vec![proof_input("proof-b", 1, 0), proof_input("proof-a", 1, 0)],
            ),
            "t-1",
        )
        .unwrap();
    engine
        .register(
            make_record("link-2", 1, vec![proof_input("proof-a", 1, 0)]),
            "t-2",
        )
        .unwrap();

    let ids = engine.consumed_proof_ids();
    assert_eq!(ids, vec!["proof-a", "proof-b"]);
}

// =========================================================================
// I. produce_witness_events — sequencing
// =========================================================================

#[test]
fn enrichment_witness_events_sequential_seqs() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-1",
        )
        .unwrap();
    engine
        .register(
            make_record("link-2", 1, vec![proof_input("p2", 1, 0)]),
            "t-2",
        )
        .unwrap();

    let events = engine.produce_witness_events(10, 500);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, 10);
    assert_eq!(events[1].seq, 11);
    assert_eq!(events[0].timestamp_tick, 500);
}

// =========================================================================
// J. LinkageError — error_code stable strings all distinct
// =========================================================================

#[test]
fn enrichment_error_code_stable_and_distinct() {
    let errors: Vec<LinkageError> = vec![
        LinkageError::DuplicateLinkage {
            id: "x".to_string(),
        },
        LinkageError::LinkageNotFound {
            id: "x".to_string(),
        },
        LinkageError::AlreadyInactive {
            id: "x".to_string(),
        },
        LinkageError::EmptyProofInputs,
        LinkageError::EpochMismatch {
            linkage_epoch: epoch(1),
            current_epoch: epoch(2),
        },
        LinkageError::Ir3AlreadySpecialized,
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| error_code(e)).collect();
    assert_eq!(codes.len(), 6);
}

// =========================================================================
// K. LinkageError — serde roundtrip all variants
// =========================================================================

#[test]
fn enrichment_linkage_error_serde_all_variants() {
    let errors: Vec<LinkageError> = vec![
        LinkageError::DuplicateLinkage {
            id: "dup".to_string(),
        },
        LinkageError::LinkageNotFound {
            id: "nf".to_string(),
        },
        LinkageError::AlreadyInactive {
            id: "ai".to_string(),
        },
        LinkageError::EmptyProofInputs,
        LinkageError::EpochMismatch {
            linkage_epoch: epoch(1),
            current_epoch: epoch(2),
        },
        LinkageError::Ir3AlreadySpecialized,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: LinkageError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// L. InvalidationCause — serde roundtrip all variants
// =========================================================================

#[test]
fn enrichment_invalidation_cause_serde_all_variants() {
    let causes: Vec<InvalidationCause> = vec![
        InvalidationCause::EpochChange {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationCause::ProofRevoked {
            proof_id: "prf-123".to_string(),
        },
        InvalidationCause::PolicyChange {
            reason: "config update".to_string(),
        },
        InvalidationCause::ManualInvalidation {
            operator_id: "ops-1".to_string(),
        },
    ];
    for c in &causes {
        let json = serde_json::to_string(c).unwrap();
        let restored: InvalidationCause = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

// =========================================================================
// M. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", LinkageId::new("x")).is_empty());
    assert!(!format!("{:?}", PerformanceDelta::NEUTRAL).is_empty());
    assert!(
        !format!(
            "{:?}",
            RollbackState {
                baseline_ir3_hash: hash(b"b"),
                activation_epoch: epoch(1),
                activation_tick: 0,
            }
        )
        .is_empty()
    );
    assert!(!format!("{:?}", LinkageError::EmptyProofInputs).is_empty());
    assert!(
        !format!(
            "{:?}",
            InvalidationCause::ManualInvalidation {
                operator_id: "x".to_string()
            }
        )
        .is_empty()
    );
}

// =========================================================================
// N. Engine — deterministic behavior across runs
// =========================================================================

#[test]
fn enrichment_engine_deterministic_across_runs() {
    let run = || {
        let mut engine = make_engine();
        engine
            .register(
                make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
                "t-1",
            )
            .unwrap();
        engine
            .register(
                make_record("link-2", 1, vec![proof_input("p2", 1, 0)]),
                "t-2",
            )
            .unwrap();
        let rollbacks = engine.on_epoch_change(epoch(2), "t-epoch");
        let active = engine.active_count();
        let inactive = engine.inactive_count();
        (rollbacks.len(), active, inactive)
    };

    let (r1, a1, i1) = run();
    let (r2, a2, i2) = run();
    assert_eq!(r1, r2);
    assert_eq!(a1, a2);
    assert_eq!(i1, i2);
}

// =========================================================================
// O. Engine — rollback_plan only active
// =========================================================================

#[test]
fn enrichment_rollback_plan_excludes_inactive() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-1",
        )
        .unwrap();
    engine
        .register(
            make_record("link-2", 1, vec![proof_input("p2", 1, 0)]),
            "t-2",
        )
        .unwrap();

    // Manually invalidate one
    engine
        .invalidate_manual(&LinkageId::new("link-1"), "ops", "t-inv")
        .unwrap();

    let plan = engine.rollback_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, LinkageId::new("link-2"));
}

// =========================================================================
// P. ExecutionRecord — serde roundtrip
// =========================================================================

#[test]
fn enrichment_execution_record_serde_roundtrip() {
    let rec = ExecutionRecord {
        linkage_id: LinkageId::new("exec-link"),
        witness_hash: hash(b"witness"),
        performance_delta: PerformanceDelta {
            speedup_millionths: 1_200_000,
            instruction_ratio_millionths: 900_000,
        },
        instructions_executed: 42_000,
        duration_ticks: 500,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let restored: ExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
}

// =========================================================================
// Q. LinkageEvent — serde roundtrip
// =========================================================================

#[test]
fn enrichment_linkage_event_serde_with_and_without_error_code() {
    let ev1 = LinkageEvent {
        trace_id: "t-1".to_string(),
        decision_id: String::new(),
        policy_id: "pol-1".to_string(),
        component: "proof_specialization_linkage".to_string(),
        event: "register".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json1 = serde_json::to_string(&ev1).unwrap();
    let restored1: LinkageEvent = serde_json::from_str(&json1).unwrap();
    assert_eq!(ev1, restored1);

    let ev2 = LinkageEvent {
        error_code: Some("LINKAGE_DUPLICATE".to_string()),
        ..ev1.clone()
    };
    let json2 = serde_json::to_string(&ev2).unwrap();
    let restored2: LinkageEvent = serde_json::from_str(&json2).unwrap();
    assert_eq!(ev2, restored2);
}

// =========================================================================
// R. Engine accessors — policy_id, current_epoch, total_count
// =========================================================================

#[test]
fn enrichment_engine_accessors() {
    let engine = make_engine();
    assert_eq!(engine.policy_id(), "pol-001");
    assert_eq!(engine.current_epoch(), epoch(1));
    assert_eq!(engine.total_count(), 0);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.inactive_count(), 0);
    assert!(engine.events().is_empty());
    assert!(engine.invalidations().is_empty());
    assert!(engine.linkages().is_empty());
}

// =========================================================================
// S. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_linkage_record() {
    let original = make_record("link-orig", 1, vec![proof_input("p1", 1, 0)]);
    let mut cloned = original.clone();
    cloned.active = false;
    cloned.execution_count = 999;
    assert!(original.active);
    assert_eq!(original.execution_count, 0);
}

#[test]
fn enrichment_clone_independence_rollback_state() {
    let original = RollbackState {
        baseline_ir3_hash: hash(b"baseline"),
        activation_epoch: epoch(1),
        activation_tick: 100,
    };
    let cloned = original.clone();
    assert_eq!(original.activation_tick, cloned.activation_tick);
    assert_eq!(original.baseline_ir3_hash, cloned.baseline_ir3_hash);
}

#[test]
fn enrichment_clone_independence_proof_input_ref() {
    let original = proof_input("p1", 1, 50);
    let mut cloned = original.clone();
    cloned.validity_window_ticks = 9999;
    assert_eq!(original.validity_window_ticks, 50);
}

#[test]
fn enrichment_clone_independence_linkage_event() {
    let original = LinkageEvent {
        trace_id: "t-1".to_string(),
        decision_id: String::new(),
        policy_id: "pol".to_string(),
        component: "comp".to_string(),
        event: "register".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.outcome = "rejected".to_string();
    assert_eq!(original.outcome, "ok");
}

// =========================================================================
// T. InvalidationCause Display all distinct
// =========================================================================

#[test]
fn enrichment_invalidation_cause_display_all_distinct() {
    let causes = [
        InvalidationCause::EpochChange {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationCause::ProofRevoked {
            proof_id: "p1".to_string(),
        },
        InvalidationCause::PolicyChange {
            reason: "config".to_string(),
        },
        InvalidationCause::ManualInvalidation {
            operator_id: "ops".to_string(),
        },
    ];
    let displays: BTreeSet<String> = causes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// U. LinkageError Display distinct + std::error::Error
// =========================================================================

#[test]
fn enrichment_linkage_error_display_all_distinct() {
    let errors = [
        LinkageError::DuplicateLinkage {
            id: "x".to_string(),
        },
        LinkageError::LinkageNotFound {
            id: "x".to_string(),
        },
        LinkageError::AlreadyInactive {
            id: "x".to_string(),
        },
        LinkageError::EmptyProofInputs,
        LinkageError::EpochMismatch {
            linkage_epoch: epoch(1),
            current_epoch: epoch(2),
        },
        LinkageError::Ir3AlreadySpecialized,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_linkage_error_is_std_error() {
    let err = LinkageError::EmptyProofInputs;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
    assert!(dyn_err.source().is_none());
}

// =========================================================================
// V. proofs_valid_at boundary
// =========================================================================

#[test]
fn enrichment_proofs_valid_at_same_epoch() {
    let record = make_record("link-1", 5, vec![proof_input("p1", 5, 0)]);
    assert!(record.proofs_valid_at(epoch(5)));
}

#[test]
fn enrichment_proofs_valid_at_different_epoch() {
    let record = make_record("link-1", 5, vec![proof_input("p1", 5, 0)]);
    assert!(!record.proofs_valid_at(epoch(6)));
    assert!(!record.proofs_valid_at(epoch(4)));
}

#[test]
fn enrichment_proofs_valid_at_mixed_epochs() {
    let record = make_record(
        "link-1",
        5,
        vec![proof_input("p1", 5, 0), proof_input("p2", 3, 0)],
    );
    // Not all proofs at epoch 5
    assert!(!record.proofs_valid_at(epoch(5)));
}

// =========================================================================
// W. to_ir3_linkage field mapping
// =========================================================================

#[test]
fn enrichment_to_ir3_linkage_maps_all_fields() {
    let record = make_record(
        "link-1",
        7,
        vec![proof_input("p1", 7, 0), proof_input("p2", 7, 0)],
    );
    let ir3_linkage = record.to_ir3_linkage();
    assert_eq!(ir3_linkage.proof_input_ids, vec!["p1", "p2"]);
    assert_eq!(ir3_linkage.validity_epoch, 7);
    assert_eq!(
        ir3_linkage.rollback_token,
        record.rollback.baseline_ir3_hash
    );
    assert!(!ir3_linkage.optimization_class.is_empty());
}

// =========================================================================
// X. attach_to_ir3 (non-ticked) error paths
// =========================================================================

#[test]
fn enrichment_attach_to_ir3_nonexistent() {
    let mut engine = make_engine();
    let mut ir3 = blank_ir3();
    let result = engine.attach_to_ir3(&LinkageId::new("no-such"), &mut ir3, "t1");
    assert!(matches!(result, Err(LinkageError::LinkageNotFound { .. })));
}

#[test]
fn enrichment_attach_to_ir3_already_specialized() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-reg1",
        )
        .unwrap();
    engine
        .register(
            make_record("link-2", 1, vec![proof_input("p2", 1, 0)]),
            "t-reg2",
        )
        .unwrap();
    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-1"), &mut ir3, "t-att1")
        .unwrap();
    let result = engine.attach_to_ir3(&LinkageId::new("link-2"), &mut ir3, "t-att2");
    assert!(matches!(result, Err(LinkageError::Ir3AlreadySpecialized)));
}

#[test]
fn enrichment_attach_to_ir3_epoch_mismatch() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 2, vec![proof_input("p1", 2, 0)]),
            "t-reg",
        )
        .unwrap();
    let mut ir3 = blank_ir3();
    let result = engine.attach_to_ir3(&LinkageId::new("link-1"), &mut ir3, "t-att");
    assert!(matches!(result, Err(LinkageError::EpochMismatch { .. })));
}

// =========================================================================
// Y. Record execution with performance delta updates
// =========================================================================

#[test]
fn enrichment_record_execution_updates_counters_and_delta() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-reg",
        )
        .unwrap();

    let mut ir4 = blank_ir4();
    ir4.instructions_executed = 500;
    ir4.duration_ticks = 250;

    let perf = PerformanceDelta {
        speedup_millionths: 1_800_000,
        instruction_ratio_millionths: 700_000,
    };
    let exec = engine
        .record_execution(&LinkageId::new("link-1"), &mut ir4, perf, "t-exec")
        .unwrap();

    assert_eq!(exec.instructions_executed, 500);
    assert_eq!(exec.duration_ticks, 250);
    assert_eq!(exec.performance_delta.speedup_millionths, 1_800_000);
    assert_eq!(exec.linkage_id, LinkageId::new("link-1"));

    let stored = engine.get(&LinkageId::new("link-1")).unwrap();
    assert_eq!(stored.execution_count, 1);
    assert_eq!(
        stored.performance_delta.unwrap().speedup_millionths,
        1_800_000
    );
}

#[test]
fn enrichment_record_execution_idempotent_ir4_specialization_ids() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-reg",
        )
        .unwrap();

    let mut ir4 = blank_ir4();
    let lid = LinkageId::new("link-1");
    engine
        .record_execution(&lid, &mut ir4, PerformanceDelta::NEUTRAL, "t1")
        .unwrap();
    engine
        .record_execution(&lid, &mut ir4, PerformanceDelta::NEUTRAL, "t2")
        .unwrap();

    // Only one entry in IR4 specialization IDs
    assert_eq!(
        ir4.active_specialization_ids
            .iter()
            .filter(|id| *id == "link-1")
            .count(),
        1
    );
    // But execution count is 2
    assert_eq!(engine.get(&lid).unwrap().execution_count, 2);
}

// =========================================================================
// Z. Multiple epoch changes cascading
// =========================================================================

#[test]
fn enrichment_multiple_epoch_changes() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-e1", 1, vec![proof_input("p1", 1, 0)]),
            "t1",
        )
        .unwrap();

    // First epoch change
    let r1 = engine.on_epoch_change(epoch(2), "t-e2");
    assert_eq!(r1.len(), 1);
    assert_eq!(engine.current_epoch(), epoch(2));
    assert_eq!(engine.active_count(), 0);

    // Register new at epoch 2
    engine
        .register(
            make_record("link-e2", 2, vec![proof_input("p2", 2, 0)]),
            "t2",
        )
        .unwrap();
    assert_eq!(engine.active_count(), 1);

    // Second epoch change
    let r2 = engine.on_epoch_change(epoch(3), "t-e3");
    assert_eq!(r2.len(), 1);
    assert_eq!(engine.current_epoch(), epoch(3));
    assert_eq!(engine.inactive_count(), 2);
    assert_eq!(engine.total_count(), 2);
}

// =========================================================================
// AA. invalidate_expired_proof_windows — no expired returns empty
// =========================================================================

#[test]
fn enrichment_invalidate_expired_no_expired_returns_empty() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t1",
        )
        .unwrap();
    // Window 0 = unbounded, so nothing expires
    let rollbacks = engine.invalidate_expired_proof_windows(u64::MAX, "t-sweep");
    assert!(rollbacks.is_empty());
    assert_eq!(engine.active_count(), 1);
}

// =========================================================================
// BB. active_linkages query
// =========================================================================

#[test]
fn enrichment_active_linkages_returns_only_active() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-active", 1, vec![proof_input("p1", 1, 0)]),
            "t1",
        )
        .unwrap();
    let mut inactive = make_record("link-inactive", 1, vec![proof_input("p2", 1, 0)]);
    inactive.active = false;
    engine.register(inactive, "t2").unwrap();

    let active = engine.active_linkages();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, LinkageId::new("link-active"));
}

// =========================================================================
// CC. Event trace_id propagation
// =========================================================================

#[test]
fn enrichment_event_trace_id_propagation() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "trace-42",
        )
        .unwrap();
    let last_event = engine.events().last().unwrap();
    assert_eq!(last_event.trace_id, "trace-42");
    assert_eq!(last_event.policy_id, "pol-001");
    assert_eq!(last_event.component, "proof_specialization_linkage");
}

#[test]
fn enrichment_error_event_carries_error_code() {
    let mut engine = make_engine();
    let mut record = make_record("link-1", 1, vec![proof_input("p1", 1, 0)]);
    record.proof_inputs.clear();
    let _ = engine.register(record, "trace-err");
    let last_event = engine.events().last().unwrap();
    assert_eq!(last_event.outcome, "rejected");
    assert_eq!(
        last_event.error_code.as_deref(),
        Some("LINKAGE_EMPTY_PROOF_INPUTS")
    );
}

// =========================================================================
// DD. Serde roundtrips for additional types
// =========================================================================

#[test]
fn enrichment_proof_input_ref_serde_roundtrip() {
    let input = proof_input("proof-abc", 3, 100);
    let json = serde_json::to_string(&input).unwrap();
    let restored: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

#[test]
fn enrichment_rollback_state_serde_roundtrip() {
    let rs = RollbackState {
        baseline_ir3_hash: hash(b"rs-test"),
        activation_epoch: epoch(7),
        activation_tick: 42,
    };
    let json = serde_json::to_string(&rs).unwrap();
    let restored: RollbackState = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, restored);
}

#[test]
fn enrichment_linkage_record_serde_roundtrip() {
    let mut record = make_record("link-serde", 5, vec![proof_input("p1", 5, 100)]);
    record.performance_delta = Some(PerformanceDelta {
        speedup_millionths: 2_000_000,
        instruction_ratio_millionths: 500_000,
    });
    record.execution_count = 42;
    let json = serde_json::to_string(&record).unwrap();
    let restored: LinkageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// =========================================================================
// EE. BTreeMap ordering in engine
// =========================================================================

#[test]
fn enrichment_linkages_btreemap_ordering() {
    let mut engine = make_engine();
    // Insert in reverse order
    engine
        .register(make_record("zzz", 1, vec![proof_input("p1", 1, 0)]), "t1")
        .unwrap();
    engine
        .register(make_record("aaa", 1, vec![proof_input("p2", 1, 0)]), "t2")
        .unwrap();
    engine
        .register(make_record("mmm", 1, vec![proof_input("p3", 1, 0)]), "t3")
        .unwrap();

    let keys: Vec<&LinkageId> = engine.linkages().keys().collect();
    assert_eq!(keys[0].as_str(), "aaa");
    assert_eq!(keys[1].as_str(), "mmm");
    assert_eq!(keys[2].as_str(), "zzz");
}

// =========================================================================
// FF. Manual invalidation returns baseline hash
// =========================================================================

#[test]
fn enrichment_manual_invalidation_returns_correct_baseline() {
    let mut engine = make_engine();
    let record = make_record("link-1", 1, vec![proof_input("p1", 1, 0)]);
    let expected_baseline = record.rollback.baseline_ir3_hash;
    engine.register(record, "t-reg").unwrap();

    let baseline = engine
        .invalidate_manual(&LinkageId::new("link-1"), "ops-1", "t-inv")
        .unwrap();
    assert_eq!(baseline, expected_baseline);

    // Verify it's now inactive
    assert!(!engine.get(&LinkageId::new("link-1")).unwrap().active);

    // Verify invalidation cause is logged
    let (_, cause) = engine.invalidations().last().unwrap();
    match cause {
        InvalidationCause::ManualInvalidation { operator_id } => {
            assert_eq!(operator_id, "ops-1");
        }
        other => panic!("expected ManualInvalidation, got {other:?}"),
    }
}

#[test]
fn enrichment_manual_invalidation_double_fails() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("p1", 1, 0)]),
            "t-reg",
        )
        .unwrap();

    engine
        .invalidate_manual(&LinkageId::new("link-1"), "ops-1", "t-inv1")
        .unwrap();

    let result = engine.invalidate_manual(&LinkageId::new("link-1"), "ops-1", "t-inv2");
    assert!(matches!(result, Err(LinkageError::AlreadyInactive { .. })));
}

// =========================================================================
// GG. PerformanceDelta Copy semantics
// =========================================================================

#[test]
fn enrichment_performance_delta_copy() {
    let a = PerformanceDelta {
        speedup_millionths: 1_500_000,
        instruction_ratio_millionths: 800_000,
    };
    let b = a; // Copy
    assert_eq!(a, b);
    assert_eq!(a.speedup_millionths, b.speedup_millionths);
}

// =========================================================================
// HH. Full lifecycle: register → attach → execute → epoch change
// =========================================================================

#[test]
fn enrichment_full_lifecycle_end_to_end() {
    let mut engine = make_engine();

    // Register
    let record = make_record("link-lifecycle", 1, vec![proof_input("p1", 1, 0)]);
    let baseline_hash = record.rollback.baseline_ir3_hash;
    engine.register(record, "t-reg").unwrap();
    assert_eq!(engine.active_count(), 1);

    // Attach to IR3
    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-lifecycle"), &mut ir3, "t-att")
        .unwrap();
    assert!(ir3.specialization.is_some());

    // Record execution
    let mut ir4 = blank_ir4();
    ir4.instructions_executed = 1000;
    ir4.duration_ticks = 500;
    let exec = engine
        .record_execution(
            &LinkageId::new("link-lifecycle"),
            &mut ir4,
            PerformanceDelta {
                speedup_millionths: 1_300_000,
                instruction_ratio_millionths: 850_000,
            },
            "t-exec",
        )
        .unwrap();
    assert_eq!(exec.instructions_executed, 1000);

    // Epoch change invalidates
    let rollbacks = engine.on_epoch_change(epoch(2), "t-epoch");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].0, LinkageId::new("link-lifecycle"));
    assert_eq!(rollbacks[0].1, baseline_hash);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.inactive_count(), 1);

    // Cannot reuse after invalidation
    let mut ir3_2 = blank_ir3();
    let result = engine.attach_to_ir3(&LinkageId::new("link-lifecycle"), &mut ir3_2, "t-reuse");
    assert!(matches!(result, Err(LinkageError::AlreadyInactive { .. })));
}

// =========================================================================
// II. Proof window saturation — u64::MAX activation_tick
// =========================================================================

#[test]
fn enrichment_proof_window_saturating_add() {
    let mut record = make_record("link-sat", 1, vec![proof_input("p1", 1, 100)]);
    record.rollback.activation_tick = u64::MAX - 10;
    // Window 100 + (MAX-10) saturates to MAX
    // At tick MAX, MAX >= MAX → expired
    assert!(!record.proof_windows_valid_at(u64::MAX));
    // At tick MAX-1, still valid since expiry is MAX (saturated)
    let (_, expiry) = record.first_expired_proof_window(u64::MAX).unwrap();
    assert_eq!(expiry, u64::MAX);
}

// =========================================================================
// JJ. Engine — register many then selective invalidation
// =========================================================================

#[test]
fn enrichment_register_10_invalidate_every_other() {
    let mut engine = make_engine();
    for i in 0..10 {
        let lid = format!("link-{i:02}");
        engine
            .register(
                make_record(&lid, 1, vec![proof_input(&format!("p{i}"), 1, 0)]),
                "t",
            )
            .unwrap();
    }
    assert_eq!(engine.active_count(), 10);

    for i in (0..10).step_by(2) {
        let lid = LinkageId::new(format!("link-{i:02}"));
        engine.invalidate_manual(&lid, "ops", "t-inv").unwrap();
    }
    assert_eq!(engine.active_count(), 5);
    assert_eq!(engine.inactive_count(), 5);

    let active = engine.active_linkages();
    for rec in &active {
        let n: usize = rec
            .id
            .as_str()
            .strip_prefix("link-")
            .unwrap()
            .parse()
            .unwrap();
        assert!(n % 2 == 1, "only odd ids should remain active");
    }
}

#[test]
fn enrichment_register_then_invalidate_all_by_proof() {
    let mut engine = make_engine();
    for i in 0..5 {
        engine
            .register(
                make_record(&format!("link-{i}"), 1, vec![proof_input("shared", 1, 0)]),
                "t",
            )
            .unwrap();
    }
    let rollbacks = engine.invalidate_by_proof("shared", "t-rev");
    assert_eq!(rollbacks.len(), 5);
    assert_eq!(engine.active_count(), 0);
}

// =========================================================================
// KK. Rollback plan ordering determinism
// =========================================================================

#[test]
fn enrichment_rollback_plan_ordering_is_deterministic() {
    let mut engine = make_engine();
    // Insert in reverse alphabetical order
    for c in ['z', 'y', 'x', 'w', 'v'] {
        let lid = format!("link-{c}");
        engine
            .register(
                make_record(&lid, 1, vec![proof_input(&format!("p-{c}"), 1, 0)]),
                "t",
            )
            .unwrap();
    }

    let plan = engine.rollback_plan();
    assert_eq!(plan.len(), 5);
    // BTreeMap yields sorted order
    assert_eq!(plan[0].0.as_str(), "link-v");
    assert_eq!(plan[1].0.as_str(), "link-w");
    assert_eq!(plan[2].0.as_str(), "link-x");
    assert_eq!(plan[3].0.as_str(), "link-y");
    assert_eq!(plan[4].0.as_str(), "link-z");
}

#[test]
fn enrichment_rollback_plan_baseline_hashes_correct() {
    let mut engine = make_engine();
    let rec = make_record("link-hash-check", 1, vec![proof_input("p1", 1, 0)]);
    let expected_hash = rec.rollback.baseline_ir3_hash;
    engine.register(rec, "t").unwrap();

    let plan = engine.rollback_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].1, expected_hash);
}

// =========================================================================
// LL. consumed_proof_ids after various invalidations
// =========================================================================

#[test]
fn enrichment_consumed_proof_ids_excludes_inactive() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("proof-active", 1, 0)]),
            "t",
        )
        .unwrap();
    engine
        .register(
            make_record("link-2", 1, vec![proof_input("proof-inactive", 1, 0)]),
            "t",
        )
        .unwrap();
    engine
        .invalidate_manual(&LinkageId::new("link-2"), "ops", "t")
        .unwrap();

    let ids = engine.consumed_proof_ids();
    assert_eq!(ids, vec!["proof-active"]);
}

#[test]
fn enrichment_consumed_proof_ids_after_epoch_change_empty() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    engine.on_epoch_change(epoch(2), "t-epoch");
    assert!(engine.consumed_proof_ids().is_empty());
}

#[test]
fn enrichment_consumed_proof_ids_many_duplicates() {
    let mut engine = make_engine();
    for i in 0..5 {
        engine
            .register(
                make_record(
                    &format!("link-{i}"),
                    1,
                    vec![
                        proof_input("shared-proof", 1, 0),
                        proof_input("unique", 1, 0),
                    ],
                ),
                "t",
            )
            .unwrap();
    }
    let ids = engine.consumed_proof_ids();
    // Should be deduplicated
    assert_eq!(ids, vec!["shared-proof", "unique"]);
}

// =========================================================================
// MM. Witness event production with various base_seq
// =========================================================================

#[test]
fn enrichment_produce_witness_events_base_seq_zero() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    let events = engine.produce_witness_events(0, 100);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 0);
    assert_eq!(events[0].timestamp_tick, 100);
}

#[test]
fn enrichment_produce_witness_events_base_seq_large() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    engine
        .register(make_record("link-2", 1, vec![proof_input("p2", 1, 0)]), "t")
        .unwrap();
    let events = engine.produce_witness_events(u64::MAX - 5, 999);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, u64::MAX - 5);
    assert_eq!(events[1].seq, u64::MAX - 4);
}

#[test]
fn enrichment_produce_witness_events_all_capability_checked() {
    use frankenengine_engine::ir_contract::WitnessEventKind;
    let mut engine = make_engine();
    for i in 0..3 {
        engine
            .register(
                make_record(
                    &format!("link-{i}"),
                    1,
                    vec![proof_input(&format!("p{i}"), 1, 0)],
                ),
                "t",
            )
            .unwrap();
    }
    let events = engine.produce_witness_events(0, 0);
    for ev in &events {
        assert_eq!(ev.kind, WitnessEventKind::CapabilityChecked);
        assert_eq!(ev.instruction_index, 0);
    }
}

#[test]
fn enrichment_produce_witness_events_empty_after_full_invalidation() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    engine.on_epoch_change(epoch(2), "t-epoch");
    let events = engine.produce_witness_events(0, 0);
    assert!(events.is_empty());
}

// =========================================================================
// NN. Epoch change determinism across independent runs
// =========================================================================

#[test]
fn enrichment_epoch_change_determinism_two_runs() {
    let run = || {
        let mut eng = LinkageEngine::new("pol-det", epoch(1));
        for i in 0..5 {
            eng.register(
                make_record(
                    &format!("link-{i}"),
                    1,
                    vec![proof_input(&format!("p{i}"), 1, 0)],
                ),
                "t",
            )
            .unwrap();
        }
        let rollbacks = eng.on_epoch_change(epoch(2), "t-e");
        let ids: Vec<String> = rollbacks
            .iter()
            .map(|(id, _)| id.as_str().to_string())
            .collect();
        ids
    };
    let run1 = run();
    let run2 = run();
    assert_eq!(run1, run2);
}

#[test]
fn enrichment_epoch_change_preserves_matching_linkages() {
    let mut engine = make_engine();
    // Register one at epoch 1 (will be invalidated) and one at epoch 2 (will survive)
    engine
        .register(
            make_record("link-old", 1, vec![proof_input("p1", 1, 0)]),
            "t",
        )
        .unwrap();
    engine
        .register(
            make_record("link-new", 2, vec![proof_input("p2", 2, 0)]),
            "t",
        )
        .unwrap();

    let rollbacks = engine.on_epoch_change(epoch(2), "t-e");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].0, LinkageId::new("link-old"));
    assert!(engine.get(&LinkageId::new("link-new")).unwrap().active);
}

// =========================================================================
// OO. Invalidation log accumulation across operations
// =========================================================================

#[test]
fn enrichment_invalidation_log_accumulates_all_causes() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-m", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    engine
        .register(
            make_record("link-p", 1, vec![proof_input("revoke-me", 1, 0)]),
            "t",
        )
        .unwrap();
    engine
        .register(make_record("link-e", 1, vec![proof_input("p3", 1, 0)]), "t")
        .unwrap();

    // Manual
    engine
        .invalidate_manual(&LinkageId::new("link-m"), "ops", "t")
        .unwrap();
    // Proof revocation
    engine.invalidate_by_proof("revoke-me", "t-rev");
    // Epoch change
    engine.on_epoch_change(epoch(2), "t-epoch");

    assert_eq!(engine.invalidations().len(), 3);
    // Check cause types
    assert!(matches!(
        engine.invalidations()[0].1,
        InvalidationCause::ManualInvalidation { .. }
    ));
    assert!(matches!(
        engine.invalidations()[1].1,
        InvalidationCause::ProofRevoked { .. }
    ));
    assert!(matches!(
        engine.invalidations()[2].1,
        InvalidationCause::EpochChange { .. }
    ));
}

#[test]
fn enrichment_invalidation_log_ids_match_linkages() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-x", 1, vec![proof_input("px", 1, 0)]), "t")
        .unwrap();
    engine
        .invalidate_manual(&LinkageId::new("link-x"), "ops", "t")
        .unwrap();

    assert_eq!(engine.invalidations()[0].0, LinkageId::new("link-x"));
}

// =========================================================================
// PP. Event audit trail completeness
// =========================================================================

#[test]
fn enrichment_events_all_have_component_set() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-1"), &mut ir3, "t")
        .unwrap();
    let mut ir4 = blank_ir4();
    engine
        .record_execution(
            &LinkageId::new("link-1"),
            &mut ir4,
            PerformanceDelta::NEUTRAL,
            "t",
        )
        .unwrap();
    engine.on_epoch_change(epoch(2), "t-e");

    for ev in engine.events() {
        assert_eq!(ev.component, "proof_specialization_linkage");
        assert_eq!(ev.policy_id, "pol-001");
    }
}

#[test]
fn enrichment_events_ok_outcome_for_success_operations() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();

    let last = engine.events().last().unwrap();
    assert_eq!(last.outcome, "ok");
    assert!(last.error_code.is_none());
}

#[test]
fn enrichment_events_rejected_outcome_for_duplicate() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();
    let _ = engine.register(make_record("link-1", 1, vec![proof_input("p2", 1, 0)]), "t");

    let last = engine.events().last().unwrap();
    assert_eq!(last.outcome, "rejected");
    assert_eq!(last.error_code.as_deref(), Some("LINKAGE_DUPLICATE"));
}

#[test]
fn enrichment_events_rejected_outcome_for_empty_proofs() {
    let mut engine = make_engine();
    let mut rec = make_record("link-1", 1, vec![proof_input("p1", 1, 0)]);
    rec.proof_inputs.clear();
    let _ = engine.register(rec, "t");

    let last = engine.events().last().unwrap();
    assert_eq!(last.outcome, "rejected");
    assert_eq!(
        last.error_code.as_deref(),
        Some("LINKAGE_EMPTY_PROOF_INPUTS")
    );
}

// =========================================================================
// QQ. attach_to_ir3 with various optimization classes
// =========================================================================

#[test]
fn enrichment_attach_ir3_hostcall_dispatch_specialization() {
    let mut engine = make_engine();
    let mut rec = make_record("link-hds", 1, vec![proof_input("p1", 1, 0)]);
    rec.optimization_class = OptimizationClass::HostcallDispatchSpecialization;
    engine.register(rec, "t").unwrap();

    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-hds"), &mut ir3, "t")
        .unwrap();
    let spec = ir3.specialization.as_ref().unwrap();
    assert_eq!(spec.optimization_class, "hostcall_dispatch_specialization");
}

#[test]
fn enrichment_attach_ir3_ifc_check_elision() {
    let mut engine = make_engine();
    let mut rec = make_record("link-ice", 1, vec![proof_input("p1", 1, 0)]);
    rec.optimization_class = OptimizationClass::IfcCheckElision;
    engine.register(rec, "t").unwrap();

    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-ice"), &mut ir3, "t")
        .unwrap();
    let spec = ir3.specialization.as_ref().unwrap();
    assert_eq!(spec.optimization_class, "ifc_check_elision");
}

#[test]
fn enrichment_attach_ir3_superinstruction_fusion() {
    let mut engine = make_engine();
    let mut rec = make_record("link-sif", 1, vec![proof_input("p1", 1, 0)]);
    rec.optimization_class = OptimizationClass::SuperinstructionFusion;
    engine.register(rec, "t").unwrap();

    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-sif"), &mut ir3, "t")
        .unwrap();
    let spec = ir3.specialization.as_ref().unwrap();
    assert_eq!(spec.optimization_class, "superinstruction_fusion");
}

#[test]
fn enrichment_attach_ir3_path_elimination() {
    let mut engine = make_engine();
    let mut rec = make_record("link-pe", 1, vec![proof_input("p1", 1, 0)]);
    rec.optimization_class = OptimizationClass::PathElimination;
    engine.register(rec, "t").unwrap();

    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3(&LinkageId::new("link-pe"), &mut ir3, "t")
        .unwrap();
    let spec = ir3.specialization.as_ref().unwrap();
    assert_eq!(spec.optimization_class, "path_elimination");
}

// =========================================================================
// RR. Proof type variants in records
// =========================================================================

#[test]
fn enrichment_proof_type_capability_witness_serde() {
    let input = ProofInputRef {
        proof_id: "cw-1".to_string(),
        proof_type: ProofType::CapabilityWitness,
        proof_epoch: epoch(1),
        validity_window_ticks: 100,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(input.proof_type, restored.proof_type);
}

#[test]
fn enrichment_proof_type_flow_proof_serde() {
    let input = ProofInputRef {
        proof_id: "fp-1".to_string(),
        proof_type: ProofType::FlowProof,
        proof_epoch: epoch(2),
        validity_window_ticks: 200,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(input.proof_type, restored.proof_type);
}

#[test]
fn enrichment_proof_type_replay_motif_serde() {
    let input = ProofInputRef {
        proof_id: "rm-1".to_string(),
        proof_type: ProofType::ReplayMotif,
        proof_epoch: epoch(3),
        validity_window_ticks: 300,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: ProofInputRef = serde_json::from_str(&json).unwrap();
    assert_eq!(input.proof_type, restored.proof_type);
}

#[test]
fn enrichment_mixed_proof_types_in_record() {
    let rec = make_record(
        "link-mixed-types",
        1,
        vec![
            ProofInputRef {
                proof_id: "cw".to_string(),
                proof_type: ProofType::CapabilityWitness,
                proof_epoch: epoch(1),
                validity_window_ticks: 0,
            },
            ProofInputRef {
                proof_id: "fp".to_string(),
                proof_type: ProofType::FlowProof,
                proof_epoch: epoch(1),
                validity_window_ticks: 50,
            },
            ProofInputRef {
                proof_id: "rm".to_string(),
                proof_type: ProofType::ReplayMotif,
                proof_epoch: epoch(1),
                validity_window_ticks: 100,
            },
        ],
    );
    let json = serde_json::to_string(&rec).unwrap();
    let restored: LinkageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
    assert_eq!(restored.proof_inputs.len(), 3);
}

// =========================================================================
// SS. PerformanceDelta field-level assertions
// =========================================================================

#[test]
fn enrichment_performance_delta_extreme_speedup() {
    let pd = PerformanceDelta {
        speedup_millionths: u64::MAX,
        instruction_ratio_millionths: 1,
    };
    let json = serde_json::to_string(&pd).unwrap();
    let restored: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, restored);
}

#[test]
fn enrichment_performance_delta_extreme_instruction_ratio() {
    let pd = PerformanceDelta {
        speedup_millionths: 1,
        instruction_ratio_millionths: u64::MAX,
    };
    let json = serde_json::to_string(&pd).unwrap();
    let restored: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, restored);
}

#[test]
fn enrichment_performance_delta_ordering_by_instruction_ratio() {
    let a = PerformanceDelta {
        speedup_millionths: 1_000_000,
        instruction_ratio_millionths: 500_000,
    };
    let b = PerformanceDelta {
        speedup_millionths: 1_000_000,
        instruction_ratio_millionths: 900_000,
    };
    // Same speedup, ordered by instruction_ratio
    assert!(a < b);
}

// =========================================================================
// TT. RollbackState field coverage
// =========================================================================

#[test]
fn enrichment_rollback_state_different_hashes_not_equal() {
    let a = RollbackState {
        baseline_ir3_hash: hash(b"hash-a"),
        activation_epoch: epoch(1),
        activation_tick: 100,
    };
    let b = RollbackState {
        baseline_ir3_hash: hash(b"hash-b"),
        activation_epoch: epoch(1),
        activation_tick: 100,
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_rollback_state_different_epochs_not_equal() {
    let a = RollbackState {
        baseline_ir3_hash: hash(b"same"),
        activation_epoch: epoch(1),
        activation_tick: 100,
    };
    let b = RollbackState {
        baseline_ir3_hash: hash(b"same"),
        activation_epoch: epoch(2),
        activation_tick: 100,
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_rollback_state_different_ticks_not_equal() {
    let a = RollbackState {
        baseline_ir3_hash: hash(b"same"),
        activation_epoch: epoch(1),
        activation_tick: 100,
    };
    let b = RollbackState {
        baseline_ir3_hash: hash(b"same"),
        activation_epoch: epoch(1),
        activation_tick: 200,
    };
    assert_ne!(a, b);
}

// =========================================================================
// UU. LinkageRecord equality and clone
// =========================================================================

#[test]
fn enrichment_linkage_record_equality() {
    let a = make_record("link-eq", 1, vec![proof_input("p1", 1, 0)]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_linkage_record_inequality_by_id() {
    let a = make_record("link-a", 1, vec![proof_input("p1", 1, 0)]);
    let b = make_record("link-b", 1, vec![proof_input("p1", 1, 0)]);
    assert_ne!(a, b);
}

#[test]
fn enrichment_linkage_record_clone_mutation_independent() {
    let original = make_record("link-orig", 1, vec![proof_input("p1", 1, 0)]);
    let mut cloned = original.clone();
    cloned.execution_count = 100;
    cloned.active = false;
    cloned.performance_delta = Some(PerformanceDelta {
        speedup_millionths: 5_000_000,
        instruction_ratio_millionths: 200_000,
    });
    assert_eq!(original.execution_count, 0);
    assert!(original.active);
    assert!(original.performance_delta.is_none());
}

// =========================================================================
// VV. ExecutionRecord field-level coverage
// =========================================================================

#[test]
fn enrichment_execution_record_zero_instructions() {
    let rec = ExecutionRecord {
        linkage_id: LinkageId::new("exec-zero"),
        witness_hash: hash(b"witness-zero"),
        performance_delta: PerformanceDelta::NEUTRAL,
        instructions_executed: 0,
        duration_ticks: 0,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let restored: ExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
    assert_eq!(restored.instructions_executed, 0);
    assert_eq!(restored.duration_ticks, 0);
}

#[test]
fn enrichment_execution_record_large_values() {
    let rec = ExecutionRecord {
        linkage_id: LinkageId::new("exec-large"),
        witness_hash: hash(b"witness-large"),
        performance_delta: PerformanceDelta {
            speedup_millionths: 10_000_000,
            instruction_ratio_millionths: 100_000,
        },
        instructions_executed: u64::MAX,
        duration_ticks: u64::MAX,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let restored: ExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
}

#[test]
fn enrichment_execution_record_equality() {
    let a = ExecutionRecord {
        linkage_id: LinkageId::new("exec-eq"),
        witness_hash: hash(b"w"),
        performance_delta: PerformanceDelta::NEUTRAL,
        instructions_executed: 42,
        duration_ticks: 7,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// WW. LinkageEvent field-level coverage
// =========================================================================

#[test]
fn enrichment_linkage_event_all_fields_roundtrip() {
    let ev = LinkageEvent {
        trace_id: "trace-abc".to_string(),
        decision_id: "dec-xyz".to_string(),
        policy_id: "pol-123".to_string(),
        component: "proof_specialization_linkage".to_string(),
        event: "register".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: LinkageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

#[test]
fn enrichment_linkage_event_with_error_code_roundtrip() {
    let ev = LinkageEvent {
        trace_id: "t".to_string(),
        decision_id: String::new(),
        policy_id: "pol".to_string(),
        component: "comp".to_string(),
        event: "attach_to_ir3".to_string(),
        outcome: "rejected".to_string(),
        error_code: Some("LINKAGE_EPOCH_MISMATCH".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: LinkageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
    assert_eq!(
        restored.error_code.as_deref(),
        Some("LINKAGE_EPOCH_MISMATCH")
    );
}

#[test]
fn enrichment_linkage_event_clone_independence() {
    let ev = LinkageEvent {
        trace_id: "t-orig".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let mut cloned = ev.clone();
    cloned.trace_id = "t-modified".to_string();
    assert_eq!(ev.trace_id, "t-orig");
}

// =========================================================================
// XX. InvalidationCause Display format validation
// =========================================================================

#[test]
fn enrichment_invalidation_cause_epoch_change_display_format() {
    let cause = InvalidationCause::EpochChange {
        old_epoch: epoch(10),
        new_epoch: epoch(20),
    };
    let s = cause.to_string();
    assert!(s.starts_with("epoch_change("));
    assert!(s.contains("->"));
    assert!(s.ends_with(')'));
}

#[test]
fn enrichment_invalidation_cause_proof_revoked_display_format() {
    let cause = InvalidationCause::ProofRevoked {
        proof_id: "proof-abc-123".to_string(),
    };
    let s = cause.to_string();
    assert!(s.contains("proof_revoked(proof-abc-123)"));
}

#[test]
fn enrichment_invalidation_cause_policy_change_display_format() {
    let cause = InvalidationCause::PolicyChange {
        reason: "reason-with-dashes".to_string(),
    };
    let s = cause.to_string();
    assert!(s.contains("policy_change(reason-with-dashes)"));
}

#[test]
fn enrichment_invalidation_cause_manual_display_format() {
    let cause = InvalidationCause::ManualInvalidation {
        operator_id: "admin-42".to_string(),
    };
    let s = cause.to_string();
    assert!(s.contains("manual_invalidation(admin-42)"));
}

// =========================================================================
// YY. LinkageError Display format validation
// =========================================================================

#[test]
fn enrichment_linkage_error_display_duplicate_format() {
    let err = LinkageError::DuplicateLinkage {
        id: "dup-test".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("duplicate linkage"));
    assert!(s.contains("dup-test"));
}

#[test]
fn enrichment_linkage_error_display_not_found_format() {
    let err = LinkageError::LinkageNotFound {
        id: "nf-test".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("linkage not found"));
    assert!(s.contains("nf-test"));
}

#[test]
fn enrichment_linkage_error_display_already_inactive_format() {
    let err = LinkageError::AlreadyInactive {
        id: "ai-test".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("already inactive"));
    assert!(s.contains("ai-test"));
}

#[test]
fn enrichment_linkage_error_display_empty_proof_format() {
    let err = LinkageError::EmptyProofInputs;
    let s = err.to_string();
    assert!(s.contains("no proof inputs"));
}

#[test]
fn enrichment_linkage_error_display_ir3_specialized_format() {
    let err = LinkageError::Ir3AlreadySpecialized;
    let s = err.to_string();
    assert!(s.contains("already has specialization"));
}

// =========================================================================
// ZZ. Error code stability across all variants
// =========================================================================

#[test]
fn enrichment_error_code_duplicate() {
    assert_eq!(
        error_code(&LinkageError::DuplicateLinkage { id: String::new() }),
        "LINKAGE_DUPLICATE"
    );
}

#[test]
fn enrichment_error_code_not_found() {
    assert_eq!(
        error_code(&LinkageError::LinkageNotFound { id: String::new() }),
        "LINKAGE_NOT_FOUND"
    );
}

#[test]
fn enrichment_error_code_already_inactive() {
    assert_eq!(
        error_code(&LinkageError::AlreadyInactive { id: String::new() }),
        "LINKAGE_ALREADY_INACTIVE"
    );
}

#[test]
fn enrichment_error_code_empty_inputs() {
    assert_eq!(
        error_code(&LinkageError::EmptyProofInputs),
        "LINKAGE_EMPTY_PROOF_INPUTS"
    );
}

#[test]
fn enrichment_error_code_epoch_mismatch() {
    assert_eq!(
        error_code(&LinkageError::EpochMismatch {
            linkage_epoch: epoch(1),
            current_epoch: epoch(2),
        }),
        "LINKAGE_EPOCH_MISMATCH"
    );
}

#[test]
fn enrichment_error_code_ir3_specialized() {
    assert_eq!(
        error_code(&LinkageError::Ir3AlreadySpecialized),
        "LINKAGE_IR3_ALREADY_SPECIALIZED"
    );
}

// =========================================================================
// AAA. Attach at tick with multiple proof windows
// =========================================================================

#[test]
fn enrichment_attach_at_tick_multiple_windows_earliest_expires() {
    let mut engine = make_engine();
    let mut rec = make_record(
        "link-multi-win",
        1,
        vec![
            proof_input("p-short", 1, 20),  // expires at 120
            proof_input("p-medium", 1, 50), // expires at 150
            proof_input("p-long", 1, 100),  // expires at 200
        ],
    );
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t").unwrap();

    // At tick 119, all valid
    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3_at_tick(&LinkageId::new("link-multi-win"), &mut ir3, 119, "t")
        .unwrap();
    assert!(ir3.specialization.is_some());
}

#[test]
fn enrichment_attach_at_tick_multiple_windows_first_expired() {
    let mut engine = make_engine();
    let mut rec = make_record(
        "link-multi-exp",
        1,
        vec![proof_input("p-short", 1, 20), proof_input("p-long", 1, 100)],
    );
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t").unwrap();

    // At tick 120, p-short expires
    let mut ir3 = blank_ir3();
    let err = engine
        .attach_to_ir3_at_tick(&LinkageId::new("link-multi-exp"), &mut ir3, 120, "t")
        .unwrap_err();
    assert!(matches!(err, LinkageError::AlreadyInactive { .. }));
    assert!(ir3.specialization.is_none());
}

// =========================================================================
// BBB. Record execution at tick with multiple proof windows
// =========================================================================

#[test]
fn enrichment_record_exec_at_tick_before_all_windows_ok() {
    let mut engine = make_engine();
    let mut rec = make_record(
        "link-exec-win",
        1,
        vec![proof_input("p1", 1, 50), proof_input("p2", 1, 100)],
    );
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t").unwrap();

    let mut ir4 = blank_ir4();
    ir4.instructions_executed = 42;
    ir4.duration_ticks = 10;
    let exec = engine
        .record_execution_at_tick(
            &LinkageId::new("link-exec-win"),
            &mut ir4,
            PerformanceDelta::NEUTRAL,
            149,
            "t",
        )
        .unwrap();
    assert_eq!(exec.instructions_executed, 42);
}

#[test]
fn enrichment_record_exec_at_tick_after_first_window_fails() {
    let mut engine = make_engine();
    let mut rec = make_record(
        "link-exec-fail",
        1,
        vec![proof_input("p-short", 1, 20), proof_input("p-long", 1, 100)],
    );
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t").unwrap();

    let mut ir4 = blank_ir4();
    let err = engine
        .record_execution_at_tick(
            &LinkageId::new("link-exec-fail"),
            &mut ir4,
            PerformanceDelta::NEUTRAL,
            120,
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, LinkageError::AlreadyInactive { .. }));
}

// =========================================================================
// CCC. Invalidate expired proof windows with mixed windows
// =========================================================================

#[test]
fn enrichment_invalidate_expired_windows_mixed_bounded_unbounded_sweep() {
    let mut engine = make_engine();

    // link-1: bounded, expires at 150
    let mut r1 = make_record("link-1", 1, vec![proof_input("p1", 1, 50)]);
    r1.rollback.activation_tick = 100;
    engine.register(r1, "t").unwrap();

    // link-2: unbounded
    let r2 = make_record("link-2", 1, vec![proof_input("p2", 1, 0)]);
    engine.register(r2, "t").unwrap();

    // link-3: bounded, expires at 200
    let mut r3 = make_record("link-3", 1, vec![proof_input("p3", 1, 100)]);
    r3.rollback.activation_tick = 100;
    engine.register(r3, "t").unwrap();

    // At tick 160: link-1 expired, link-3 not yet
    let rollbacks = engine.invalidate_expired_proof_windows(160, "t");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].0, LinkageId::new("link-1"));
    assert_eq!(engine.active_count(), 2);
}

#[test]
fn enrichment_invalidate_expired_windows_all_expired() {
    let mut engine = make_engine();

    for i in 0..3 {
        let mut rec = make_record(
            &format!("link-{i}"),
            1,
            vec![proof_input(&format!("p{i}"), 1, 10 + i as u64 * 5)],
        );
        rec.rollback.activation_tick = 100;
        engine.register(rec, "t").unwrap();
    }

    // At tick 200, all have expired (max expiry at 100+20=120)
    let rollbacks = engine.invalidate_expired_proof_windows(200, "t");
    assert_eq!(rollbacks.len(), 3);
    assert_eq!(engine.active_count(), 0);
}

// =========================================================================
// DDD. Proof window validity boundary at activation_tick = 0
// =========================================================================

#[test]
fn enrichment_proof_window_activation_tick_zero() {
    let mut rec = make_record("link-zero-act", 1, vec![proof_input("p1", 1, 100)]);
    rec.rollback.activation_tick = 0;
    // Expiry = 0 + 100 = 100
    assert!(rec.proof_windows_valid_at(99));
    assert!(!rec.proof_windows_valid_at(100));
}

#[test]
fn enrichment_proof_window_activation_tick_one() {
    let mut rec = make_record("link-one-act", 1, vec![proof_input("p1", 1, 1)]);
    rec.rollback.activation_tick = 0;
    // Expiry = 0 + 1 = 1
    assert!(rec.proof_windows_valid_at(0));
    assert!(!rec.proof_windows_valid_at(1));
}

// =========================================================================
// EEE. Engine with policy_id check
// =========================================================================

#[test]
fn enrichment_engine_custom_policy_id() {
    let engine = LinkageEngine::new("custom-policy-xyz", epoch(42));
    assert_eq!(engine.policy_id(), "custom-policy-xyz");
    assert_eq!(engine.current_epoch(), epoch(42));
}

#[test]
fn enrichment_engine_empty_policy_id() {
    let engine = LinkageEngine::new("", epoch(0));
    assert_eq!(engine.policy_id(), "");
}

// =========================================================================
// FFF. to_ir3_linkage with many proof inputs
// =========================================================================

#[test]
fn enrichment_to_ir3_linkage_many_proof_inputs() {
    let proofs: Vec<ProofInputRef> = (0..10)
        .map(|i| proof_input(&format!("proof-{i:03}"), 1, 0))
        .collect();
    let rec = make_record("link-many-proofs", 1, proofs);
    let spec = rec.to_ir3_linkage();
    assert_eq!(spec.proof_input_ids.len(), 10);
    for i in 0..10 {
        assert_eq!(spec.proof_input_ids[i], format!("proof-{i:03}"));
    }
}

#[test]
fn enrichment_to_ir3_linkage_single_proof_input() {
    let rec = make_record("link-single", 1, vec![proof_input("only-one", 1, 0)]);
    let spec = rec.to_ir3_linkage();
    assert_eq!(spec.proof_input_ids, vec!["only-one"]);
}

// =========================================================================
// GGG. Engine epoch after multiple changes
// =========================================================================

#[test]
fn enrichment_engine_epoch_tracks_latest() {
    let mut engine = make_engine();
    assert_eq!(engine.current_epoch(), epoch(1));
    engine.on_epoch_change(epoch(5), "t");
    assert_eq!(engine.current_epoch(), epoch(5));
    engine.on_epoch_change(epoch(100), "t");
    assert_eq!(engine.current_epoch(), epoch(100));
    engine.on_epoch_change(epoch(1), "t"); // can go back
    assert_eq!(engine.current_epoch(), epoch(1));
}

// =========================================================================
// HHH. Multiple record executions update performance delta to latest
// =========================================================================

#[test]
fn enrichment_record_execution_overwrites_performance_delta() {
    let mut engine = make_engine();
    engine
        .register(make_record("link-1", 1, vec![proof_input("p1", 1, 0)]), "t")
        .unwrap();

    let lid = LinkageId::new("link-1");
    let perf1 = PerformanceDelta {
        speedup_millionths: 1_200_000,
        instruction_ratio_millionths: 900_000,
    };
    let perf2 = PerformanceDelta {
        speedup_millionths: 2_500_000,
        instruction_ratio_millionths: 400_000,
    };

    let mut ir4 = blank_ir4();
    engine.record_execution(&lid, &mut ir4, perf1, "t").unwrap();
    assert_eq!(
        engine
            .get(&lid)
            .unwrap()
            .performance_delta
            .unwrap()
            .speedup_millionths,
        1_200_000
    );

    engine.record_execution(&lid, &mut ir4, perf2, "t").unwrap();
    assert_eq!(
        engine
            .get(&lid)
            .unwrap()
            .performance_delta
            .unwrap()
            .speedup_millionths,
        2_500_000
    );
    assert_eq!(engine.get(&lid).unwrap().execution_count, 2);
}

// =========================================================================
// III. InvalidationCause serde roundtrip individual variants
// =========================================================================

#[test]
fn enrichment_invalidation_cause_epoch_change_serde() {
    let cause = InvalidationCause::EpochChange {
        old_epoch: epoch(42),
        new_epoch: epoch(99),
    };
    let json = serde_json::to_string(&cause).unwrap();
    let restored: InvalidationCause = serde_json::from_str(&json).unwrap();
    assert_eq!(cause, restored);
}

#[test]
fn enrichment_invalidation_cause_proof_revoked_serde() {
    let cause = InvalidationCause::ProofRevoked {
        proof_id: "proof-revoked-123".to_string(),
    };
    let json = serde_json::to_string(&cause).unwrap();
    let restored: InvalidationCause = serde_json::from_str(&json).unwrap();
    assert_eq!(cause, restored);
}

#[test]
fn enrichment_invalidation_cause_policy_change_serde() {
    let cause = InvalidationCause::PolicyChange {
        reason: "security-policy-update".to_string(),
    };
    let json = serde_json::to_string(&cause).unwrap();
    let restored: InvalidationCause = serde_json::from_str(&json).unwrap();
    assert_eq!(cause, restored);
}

#[test]
fn enrichment_invalidation_cause_manual_serde() {
    let cause = InvalidationCause::ManualInvalidation {
        operator_id: "admin-ops-42".to_string(),
    };
    let json = serde_json::to_string(&cause).unwrap();
    let restored: InvalidationCause = serde_json::from_str(&json).unwrap();
    assert_eq!(cause, restored);
}

// =========================================================================
// JJJ. Debug formatting non-empty
// =========================================================================

#[test]
fn enrichment_debug_linkage_id_nonempty() {
    let id = LinkageId::new("debug-test");
    let dbg = format!("{:?}", id);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("debug-test"));
}

#[test]
fn enrichment_debug_performance_delta_nonempty() {
    let pd = PerformanceDelta {
        speedup_millionths: 1_234_567,
        instruction_ratio_millionths: 7_654_321,
    };
    let dbg = format!("{:?}", pd);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("1234567"));
}

#[test]
fn enrichment_debug_linkage_error_nonempty() {
    let err = LinkageError::DuplicateLinkage {
        id: "debug-err".to_string(),
    };
    let dbg = format!("{:?}", err);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("debug-err"));
}

#[test]
fn enrichment_debug_invalidation_cause_nonempty() {
    let cause = InvalidationCause::ProofRevoked {
        proof_id: "debug-proof".to_string(),
    };
    let dbg = format!("{:?}", cause);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("debug-proof"));
}

#[test]
fn enrichment_debug_execution_record_nonempty() {
    let rec = ExecutionRecord {
        linkage_id: LinkageId::new("debug-exec"),
        witness_hash: hash(b"debug-witness"),
        performance_delta: PerformanceDelta::NEUTRAL,
        instructions_executed: 999,
        duration_ticks: 42,
    };
    let dbg = format!("{:?}", rec);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("debug-exec"));
}

// =========================================================================
// KKK. std::error::Error trait on LinkageError
// =========================================================================

#[test]
fn enrichment_linkage_error_source_is_none() {
    let err = LinkageError::EmptyProofInputs;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(dyn_err.source().is_none());
}

#[test]
fn enrichment_linkage_error_boxed_as_dyn_error() {
    let err = LinkageError::LinkageNotFound {
        id: "box-test".to_string(),
    };
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    assert!(boxed.to_string().contains("box-test"));
}

// =========================================================================
// LLL. Engine get returns None for missing linkage
// =========================================================================

#[test]
fn enrichment_get_missing_returns_none() {
    let engine = make_engine();
    assert!(engine.get(&LinkageId::new("nonexistent")).is_none());
}

#[test]
fn enrichment_get_existing_returns_some() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-exists", 1, vec![proof_input("p1", 1, 0)]),
            "t",
        )
        .unwrap();
    assert!(engine.get(&LinkageId::new("link-exists")).is_some());
}

// =========================================================================
// MMM. Proofs valid at with all same epoch
// =========================================================================

#[test]
fn enrichment_proofs_valid_at_many_same_epoch() {
    let proofs: Vec<ProofInputRef> = (0..10)
        .map(|i| proof_input(&format!("p{i}"), 5, 0))
        .collect();
    let rec = make_record("link-many-same", 5, proofs);
    assert!(rec.proofs_valid_at(epoch(5)));
    assert!(!rec.proofs_valid_at(epoch(6)));
}

#[test]
fn enrichment_proofs_valid_at_one_mismatched() {
    let mut proofs: Vec<ProofInputRef> = (0..5)
        .map(|i| proof_input(&format!("p{i}"), 5, 0))
        .collect();
    proofs.push(proof_input("p-outlier", 3, 0));
    let rec = make_record("link-one-mismatch", 5, proofs);
    // Not all proofs at epoch 5
    assert!(!rec.proofs_valid_at(epoch(5)));
}

// =========================================================================
// NNN. Invalidate by proof with no matching linkages
// =========================================================================

#[test]
fn enrichment_invalidate_by_proof_no_match() {
    let mut engine = make_engine();
    engine
        .register(
            make_record("link-1", 1, vec![proof_input("proof-a", 1, 0)]),
            "t",
        )
        .unwrap();
    let rollbacks = engine.invalidate_by_proof("nonexistent-proof", "t-rev");
    assert!(rollbacks.is_empty());
    assert_eq!(engine.active_count(), 1);
}

// =========================================================================
// OOO. Full lifecycle with record_execution_at_tick
// =========================================================================

#[test]
fn enrichment_full_lifecycle_with_tick_based_execution() {
    let mut engine = make_engine();
    let mut rec = make_record("link-tick-life", 1, vec![proof_input("p1", 1, 200)]);
    rec.rollback.activation_tick = 100;
    engine.register(rec, "t").unwrap();

    // Attach at tick 150 (within window 100+200=300)
    let mut ir3 = blank_ir3();
    engine
        .attach_to_ir3_at_tick(&LinkageId::new("link-tick-life"), &mut ir3, 150, "t")
        .unwrap();
    assert!(ir3.specialization.is_some());

    // Execute at tick 250 (still within window)
    let mut ir4 = blank_ir4();
    ir4.instructions_executed = 77;
    ir4.duration_ticks = 33;
    let exec = engine
        .record_execution_at_tick(
            &LinkageId::new("link-tick-life"),
            &mut ir4,
            PerformanceDelta {
                speedup_millionths: 1_500_000,
                instruction_ratio_millionths: 750_000,
            },
            250,
            "t",
        )
        .unwrap();
    assert_eq!(exec.instructions_executed, 77);
    assert_eq!(exec.duration_ticks, 33);

    // Execute at tick 300 (exactly at expiry = fail closed)
    let mut ir4_2 = blank_ir4();
    let err = engine
        .record_execution_at_tick(
            &LinkageId::new("link-tick-life"),
            &mut ir4_2,
            PerformanceDelta::NEUTRAL,
            300,
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, LinkageError::AlreadyInactive { .. }));
}
