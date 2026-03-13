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
        vec![
            proof_input("p-short", 1, 10),
            proof_input("p-long", 1, 100),
        ],
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
