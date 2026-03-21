//! Integration tests for the `checkpoint` module.
//!
//! Tests cancellation checkpoint contract: density config, cancellation
//! token, checkpoint guard lifecycle, coverage tracking, and serde roundtrips.

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

use frankenengine_engine::checkpoint::{
    CancellationToken, CheckpointAction, CheckpointCoverage, CheckpointEvent, CheckpointGuard,
    CheckpointReason, DensityConfig, LoopSite,
};

// ---------------------------------------------------------------------------
// CheckpointReason display
// ---------------------------------------------------------------------------

#[test]
fn reason_display() {
    assert_eq!(CheckpointReason::Periodic.to_string(), "periodic");
    assert_eq!(
        CheckpointReason::CancelPending.to_string(),
        "cancel_pending"
    );
    assert_eq!(
        CheckpointReason::BudgetExhausted.to_string(),
        "budget_exhausted"
    );
    assert_eq!(CheckpointReason::Explicit.to_string(), "explicit");
}

// ---------------------------------------------------------------------------
// LoopSite display
// ---------------------------------------------------------------------------

#[test]
fn loop_site_display_all_variants() {
    assert_eq!(LoopSite::BytecodeDispatch.to_string(), "bytecode_dispatch");
    assert_eq!(LoopSite::GcScanning.to_string(), "gc_scanning");
    assert_eq!(LoopSite::GcSweep.to_string(), "gc_sweep");
    assert_eq!(LoopSite::PolicyIteration.to_string(), "policy_iteration");
    assert_eq!(
        LoopSite::ContractEvaluation.to_string(),
        "contract_evaluation"
    );
    assert_eq!(LoopSite::ReplayStep.to_string(), "replay_step");
    assert_eq!(LoopSite::ModuleDecode.to_string(), "module_decode");
    assert_eq!(LoopSite::ModuleVerify.to_string(), "module_verify");
    assert_eq!(LoopSite::IrLowering.to_string(), "ir_lowering");
    assert_eq!(LoopSite::IrCompilation.to_string(), "ir_compilation");
    assert_eq!(
        LoopSite::Custom("test".to_string()).to_string(),
        "custom:test"
    );
}

// ---------------------------------------------------------------------------
// DensityConfig
// ---------------------------------------------------------------------------

#[test]
fn density_config_default() {
    let config = DensityConfig::default();
    assert_eq!(config.max_iterations, 1024);
    assert_eq!(config.max_total_iterations, 1_000_000);
}

// ---------------------------------------------------------------------------
// CancellationToken
// ---------------------------------------------------------------------------

#[test]
fn token_starts_not_cancelled() {
    let token = CancellationToken::new();
    assert!(!token.is_cancelled());
}

#[test]
fn token_default_not_cancelled() {
    let token = CancellationToken::default();
    assert!(!token.is_cancelled());
}

#[test]
fn cancel_sets_flag() {
    let token = CancellationToken::new();
    token.cancel();
    assert!(token.is_cancelled());
}

#[test]
fn reset_clears_flag() {
    let token = CancellationToken::new();
    token.cancel();
    token.reset();
    assert!(!token.is_cancelled());
}

#[test]
fn cloned_tokens_share_state() {
    let t1 = CancellationToken::new();
    let t2 = t1.clone();
    t1.cancel();
    assert!(t2.is_cancelled());
}

// ---------------------------------------------------------------------------
// CheckpointGuard — periodic checkpoints
// ---------------------------------------------------------------------------

fn test_guard() -> (CheckpointGuard, CancellationToken) {
    let token = CancellationToken::new();
    let guard = CheckpointGuard::new(
        LoopSite::PolicyIteration,
        "policy",
        "trace-1",
        DensityConfig {
            max_iterations: 10,
            max_total_iterations: 100,
        },
        token.clone(),
    );
    (guard, token)
}

#[test]
fn periodic_checkpoint_at_density_bound() {
    let (mut guard, _) = test_guard();
    for _ in 0..9 {
        guard.tick();
        assert_eq!(guard.check(), CheckpointAction::Continue);
    }
    assert_eq!(guard.event_count(), 0);

    guard.tick();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Continue);
    assert_eq!(guard.event_count(), 1);

    let events = guard.drain_events();
    assert_eq!(events[0].reason, CheckpointReason::Periodic);
    assert_eq!(events[0].iteration_count, 10);
}

#[test]
fn total_iterations_counter() {
    let (mut guard, _) = test_guard();
    for _ in 0..25 {
        guard.tick();
        guard.check();
    }
    assert_eq!(guard.total_iterations(), 25);
}

#[test]
fn virtual_time_counter() {
    let (mut guard, _) = test_guard();
    for _ in 0..5 {
        guard.tick();
    }
    assert_eq!(guard.virtual_time(), 5);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — cancellation
// ---------------------------------------------------------------------------

#[test]
fn cancel_detected_at_next_check() {
    let (mut guard, token) = test_guard();
    guard.tick();
    token.cancel();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Drain);

    let events = guard.drain_events();
    assert_eq!(events[0].reason, CheckpointReason::CancelPending);
}

#[test]
fn cancel_preempts_density() {
    let (mut guard, token) = test_guard();
    for _ in 0..3 {
        guard.tick();
    }
    token.cancel();
    assert_eq!(guard.check(), CheckpointAction::Drain);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — budget exhaustion
// ---------------------------------------------------------------------------

#[test]
fn budget_exhaustion_triggers_abort() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::GcScanning,
        "gc",
        "t",
        DensityConfig {
            max_iterations: 50,
            max_total_iterations: 100,
        },
        token,
    );
    for _ in 0..100 {
        guard.tick();
        guard.check();
    }
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Abort);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — explicit checkpoint
// ---------------------------------------------------------------------------

#[test]
fn explicit_checkpoint_resets_counter() {
    let (mut guard, _) = test_guard();
    for _ in 0..5 {
        guard.tick();
    }
    assert_eq!(guard.explicit_checkpoint(), CheckpointAction::Continue);

    // Counter reset, need another 10 ticks for periodic
    for _ in 0..9 {
        guard.tick();
        guard.check();
    }
    let periodic_count = guard
        .drain_events()
        .iter()
        .filter(|e| e.reason == CheckpointReason::Periodic)
        .count();
    assert_eq!(periodic_count, 0);
}

#[test]
fn explicit_checkpoint_detects_cancel() {
    let (mut guard, token) = test_guard();
    token.cancel();
    assert_eq!(guard.explicit_checkpoint(), CheckpointAction::Drain);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — event structure
// ---------------------------------------------------------------------------

#[test]
fn event_carries_correct_fields() {
    let (mut guard, _) = test_guard();
    for _ in 0..10 {
        guard.tick();
    }
    guard.check();

    let events = guard.drain_events();
    let e = &events[0];
    assert_eq!(e.trace_id, "trace-1");
    assert_eq!(e.component, "policy");
    assert_eq!(e.loop_site, LoopSite::PolicyIteration);
    assert_eq!(e.total_iterations, 10);
    assert_eq!(e.action, CheckpointAction::Continue);
}

// ---------------------------------------------------------------------------
// CheckpointCoverage
// ---------------------------------------------------------------------------

#[test]
fn new_coverage_uncovered() {
    let cov = CheckpointCoverage::new();
    assert!(!cov.all_covered());
    assert_eq!(cov.total(), 10);
    assert_eq!(cov.covered_count(), 0);
}

#[test]
fn default_coverage_matches_mandatory_contract() {
    let cov = CheckpointCoverage::default();
    assert!(!cov.all_covered());
    assert_eq!(cov.total(), 10);
    assert_eq!(cov.covered_count(), 0);
    assert_eq!(cov.uncovered().len(), 10);
}

#[test]
fn register_all_gives_full_coverage() {
    let mut cov = CheckpointCoverage::new();
    let uncov = cov.uncovered();
    for site in &uncov {
        cov.register(site);
    }
    assert!(cov.all_covered());
    assert_eq!(cov.covered_count(), cov.total());
}

#[test]
fn uncovered_returns_missing() {
    let mut cov = CheckpointCoverage::new();
    cov.register("bytecode_dispatch");
    cov.register("gc_scanning");
    let uncov = cov.uncovered();
    assert!(!uncov.contains(&"bytecode_dispatch".to_string()));
    assert!(!uncov.contains(&"gc_scanning".to_string()));
    assert!(uncov.contains(&"gc_sweep".to_string()));
    assert_eq!(cov.covered_count(), 2);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_checkpoint_sequence() {
    let run = |cancel_at: Option<u64>| -> Vec<CheckpointEvent> {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::ReplayStep,
            "replay",
            "t",
            DensityConfig {
                max_iterations: 5,
                max_total_iterations: 50,
            },
            token.clone(),
        );
        for i in 0..25 {
            guard.tick();
            if cancel_at == Some(i) {
                token.cancel();
            }
            let action = guard.check();
            if action == CheckpointAction::Drain || action == CheckpointAction::Abort {
                break;
            }
        }
        guard.drain_events()
    };
    assert_eq!(run(None), run(None));
    assert_eq!(run(Some(12)), run(Some(12)));
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_reason_serde_roundtrip() {
    let reasons = [
        CheckpointReason::Periodic,
        CheckpointReason::CancelPending,
        CheckpointReason::BudgetExhausted,
        CheckpointReason::Explicit,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: CheckpointReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

#[test]
fn checkpoint_action_serde_roundtrip() {
    let actions = [
        CheckpointAction::Continue,
        CheckpointAction::Drain,
        CheckpointAction::Abort,
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let restored: CheckpointAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, restored);
    }
}

#[test]
fn loop_site_serde_roundtrip() {
    let sites = [
        LoopSite::BytecodeDispatch,
        LoopSite::GcScanning,
        LoopSite::GcSweep,
        LoopSite::PolicyIteration,
        LoopSite::Custom("x".to_string()),
    ];
    for s in &sites {
        let json = serde_json::to_string(s).unwrap();
        let restored: LoopSite = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn density_config_serde_roundtrip() {
    let config = DensityConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: DensityConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn checkpoint_event_serde_roundtrip() {
    let event = CheckpointEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        loop_site: LoopSite::BytecodeDispatch,
        iteration_count: 10,
        total_iterations: 100,
        reason: CheckpointReason::Periodic,
        action: CheckpointAction::Continue,
        timestamp_virtual: 42,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CheckpointEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn coverage_serde_roundtrip() {
    let mut cov = CheckpointCoverage::new();
    cov.register("bytecode_dispatch");
    let json = serde_json::to_string(&cov).unwrap();
    let restored: CheckpointCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(cov, restored);
}

#[test]
fn density_config_debug_is_nonempty() {
    let config = DensityConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn cancellation_token_debug_is_nonempty() {
    let token = CancellationToken::default();
    assert!(!format!("{token:?}").is_empty());
}

#[test]
fn checkpoint_coverage_debug_is_nonempty() {
    let cov = CheckpointCoverage::new();
    assert!(!format!("{cov:?}").is_empty());
}

// ---------------------------------------------------------------------------
// CheckpointReason — Ord and Hash
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_reason_ord_is_consistent() {
    use std::cmp::Ordering;
    let a = CheckpointReason::Periodic;
    let b = CheckpointReason::CancelPending;
    let c = CheckpointReason::BudgetExhausted;
    let d = CheckpointReason::Explicit;
    // Ordering must be consistent: Periodic < CancelPending < BudgetExhausted < Explicit
    assert_eq!(a.cmp(&a), Ordering::Equal);
    assert_eq!(a.cmp(&b), Ordering::Less);
    assert_eq!(c.cmp(&b), Ordering::Greater);
    assert_eq!(d.cmp(&a), Ordering::Greater);
}

#[test]
fn checkpoint_reason_hash_determinism() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let compute = |r: &CheckpointReason| {
        let mut h = DefaultHasher::new();
        r.hash(&mut h);
        h.finish()
    };
    // Same variant produces same hash
    assert_eq!(
        compute(&CheckpointReason::Periodic),
        compute(&CheckpointReason::Periodic)
    );
    // Different variants produce different hashes (not guaranteed but overwhelmingly likely)
    assert_ne!(
        compute(&CheckpointReason::Periodic),
        compute(&CheckpointReason::Explicit)
    );
}

#[test]
fn checkpoint_reason_clone_and_copy() {
    let original = CheckpointReason::BudgetExhausted;
    let cloned = original;
    let copied = original;
    assert_eq!(original, cloned);
    assert_eq!(original, copied);
}

// ---------------------------------------------------------------------------
// LoopSite — Ord, Hash, Clone
// ---------------------------------------------------------------------------

#[test]
fn loop_site_ord_among_builtin_variants() {
    // Built-in variants are ordered by definition order
    assert!(LoopSite::BytecodeDispatch < LoopSite::GcScanning);
    assert!(LoopSite::GcScanning < LoopSite::GcSweep);
    assert!(LoopSite::IrCompilation < LoopSite::Custom("z".to_string()));
}

#[test]
fn loop_site_hash_sensitivity() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let compute = |s: &LoopSite| {
        let mut h = DefaultHasher::new();
        s.hash(&mut h);
        h.finish()
    };
    // Two Custom variants with different names produce different hashes
    assert_ne!(
        compute(&LoopSite::Custom("alpha".to_string())),
        compute(&LoopSite::Custom("beta".to_string()))
    );
    // Same custom name produces same hash
    assert_eq!(
        compute(&LoopSite::Custom("x".to_string())),
        compute(&LoopSite::Custom("x".to_string()))
    );
}

#[test]
fn loop_site_clone_custom_is_independent() {
    let original = LoopSite::Custom("deep".to_string());
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // They are equal but independent heap allocations
    assert_eq!(format!("{original}"), format!("{cloned}"));
}

// ---------------------------------------------------------------------------
// CheckpointAction — Clone, Copy, PartialEq
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_action_clone_copy() {
    let a = CheckpointAction::Drain;
    let b = a;
    let c = a; // Copy
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_ne!(CheckpointAction::Continue, CheckpointAction::Abort);
}

// ---------------------------------------------------------------------------
// CheckpointEvent — Clone
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_event_clone_is_deep_equal() {
    let event = CheckpointEvent {
        trace_id: "trace-clone".to_string(),
        component: "comp".to_string(),
        loop_site: LoopSite::Custom("custom_site".to_string()),
        iteration_count: 42,
        total_iterations: 200,
        reason: CheckpointReason::Explicit,
        action: CheckpointAction::Continue,
        timestamp_virtual: 99,
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
    assert_eq!(cloned.trace_id, "trace-clone");
    assert_eq!(cloned.iteration_count, 42);
}

// ---------------------------------------------------------------------------
// DensityConfig — Clone
// ---------------------------------------------------------------------------

#[test]
fn density_config_clone() {
    let cfg = DensityConfig {
        max_iterations: 500,
        max_total_iterations: 5_000_000,
    };
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
    assert_eq!(cloned.max_iterations, 500);
    assert_eq!(cloned.max_total_iterations, 5_000_000);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — drain empties events
// ---------------------------------------------------------------------------

#[test]
fn drain_events_returns_empty_on_second_call() {
    let (mut guard, _) = test_guard();
    for _ in 0..10 {
        guard.tick();
    }
    guard.check(); // produces periodic event
    let first = guard.drain_events();
    assert!(!first.is_empty());
    let second = guard.drain_events();
    assert!(second.is_empty());
}

// ---------------------------------------------------------------------------
// CheckpointGuard — multiple periodic checkpoints accumulate
// ---------------------------------------------------------------------------

#[test]
fn multiple_periodic_checkpoints_accumulate_events() {
    let (mut guard, _) = test_guard();
    // Run 30 ticks with density=10, expect 3 periodic events
    for _ in 0..30 {
        guard.tick();
        guard.check();
    }
    assert_eq!(guard.event_count(), 3);
    let events = guard.drain_events();
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.reason, CheckpointReason::Periodic);
        assert_eq!(e.total_iterations, ((i as u64) + 1) * 10);
    }
}

// ---------------------------------------------------------------------------
// CheckpointGuard — max_iterations=1 fires every tick
// ---------------------------------------------------------------------------

#[test]
fn density_one_fires_every_tick() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ModuleDecode,
        "decoder",
        "t",
        DensityConfig {
            max_iterations: 1,
            max_total_iterations: 100,
        },
        token,
    );
    for _ in 0..5 {
        guard.tick();
        guard.check();
    }
    assert_eq!(guard.event_count(), 5);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — cancel takes priority over budget
// ---------------------------------------------------------------------------

#[test]
fn cancel_takes_priority_over_budget() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::IrLowering,
        "lowering",
        "t",
        DensityConfig {
            max_iterations: 50,
            max_total_iterations: 20,
        },
        token.clone(),
    );
    // Run past budget
    for _ in 0..25 {
        guard.tick();
    }
    // Now both cancel and budget are true
    token.cancel();
    let action = guard.check();
    // Cancel is checked first (priority 1), budget is priority 2
    assert_eq!(action, CheckpointAction::Drain);
    let events = guard.drain_events();
    assert_eq!(
        events.last().unwrap().reason,
        CheckpointReason::CancelPending
    );
}

// ---------------------------------------------------------------------------
// CheckpointGuard — virtual_time equals total_iterations
// ---------------------------------------------------------------------------

#[test]
fn virtual_time_equals_total_iterations() {
    let (mut guard, _) = test_guard();
    for n in 1..=37 {
        guard.tick();
        guard.check();
        assert_eq!(guard.virtual_time(), n);
        assert_eq!(guard.total_iterations(), n);
    }
}

// ---------------------------------------------------------------------------
// CheckpointGuard — explicit checkpoint event fields
// ---------------------------------------------------------------------------

#[test]
fn explicit_checkpoint_event_fields() {
    let (mut guard, _) = test_guard();
    for _ in 0..7 {
        guard.tick();
    }
    guard.explicit_checkpoint();
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.reason, CheckpointReason::Explicit);
    assert_eq!(e.action, CheckpointAction::Continue);
    assert_eq!(e.iteration_count, 7);
    assert_eq!(e.total_iterations, 7);
    assert_eq!(e.timestamp_virtual, 7);
    assert_eq!(e.loop_site, LoopSite::PolicyIteration);
}

// ---------------------------------------------------------------------------
// CheckpointGuard — Custom loop site
// ---------------------------------------------------------------------------

#[test]
fn guard_with_custom_loop_site() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::Custom("my_custom_loop".to_string()),
        "my_component",
        "trace-custom",
        DensityConfig {
            max_iterations: 3,
            max_total_iterations: 100,
        },
        token,
    );
    for _ in 0..3 {
        guard.tick();
    }
    guard.check();
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].loop_site,
        LoopSite::Custom("my_custom_loop".to_string())
    );
    assert_eq!(events[0].component, "my_component");
    assert_eq!(events[0].trace_id, "trace-custom");
}

// ---------------------------------------------------------------------------
// CheckpointCoverage — registering custom (non-mandatory) site
// ---------------------------------------------------------------------------

#[test]
fn coverage_register_custom_site_increases_total() {
    let mut cov = CheckpointCoverage::new();
    let original_total = cov.total();
    cov.register("my_custom_site");
    // Custom site is added as covered
    assert_eq!(cov.total(), original_total + 1);
    assert_eq!(cov.covered_count(), 1);
    // Still not all_covered because mandatory sites remain unregistered
    assert!(!cov.all_covered());
}

// ---------------------------------------------------------------------------
// CheckpointCoverage — double registration is idempotent
// ---------------------------------------------------------------------------

#[test]
fn coverage_double_register_is_idempotent() {
    let mut cov = CheckpointCoverage::new();
    cov.register("bytecode_dispatch");
    assert_eq!(cov.covered_count(), 1);
    cov.register("bytecode_dispatch");
    assert_eq!(cov.covered_count(), 1);
    assert_eq!(cov.total(), 10); // no extra entry created
}

// ---------------------------------------------------------------------------
// CheckpointCoverage — uncovered list is sorted (BTreeMap determinism)
// ---------------------------------------------------------------------------

#[test]
fn coverage_uncovered_is_sorted() {
    let cov = CheckpointCoverage::new();
    let uncov = cov.uncovered();
    let mut sorted = uncov.clone();
    sorted.sort();
    assert_eq!(uncov, sorted);
}

// ---------------------------------------------------------------------------
// Budget exhaustion event carries correct fields
// ---------------------------------------------------------------------------

#[test]
fn budget_exhaustion_event_fields() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::GcSweep,
        "gc_sweep_comp",
        "trace-budget",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 10,
        },
        token,
    );
    for _ in 0..10 {
        guard.tick();
    }
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Abort);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.reason, CheckpointReason::BudgetExhausted);
    assert_eq!(e.action, CheckpointAction::Abort);
    assert_eq!(e.total_iterations, 10);
    assert_eq!(e.loop_site, LoopSite::GcSweep);
    assert_eq!(e.trace_id, "trace-budget");
}

// ---------------------------------------------------------------------------
// New enrichment tests — batch 4
// ---------------------------------------------------------------------------

// Token: multiple independent clones all share the same flag
#[test]
fn test_multiple_token_clones_share_state() {
    let t0 = CancellationToken::new();
    let t1 = t0.clone();
    let t2 = t0.clone();
    let t3 = t1.clone();
    assert!(!t0.is_cancelled());
    assert!(!t1.is_cancelled());
    assert!(!t2.is_cancelled());
    assert!(!t3.is_cancelled());
    t2.cancel();
    assert!(t0.is_cancelled());
    assert!(t1.is_cancelled());
    assert!(t2.is_cancelled());
    assert!(t3.is_cancelled());
}

// Token: cancel/reset cycle is repeatable
#[test]
fn test_token_cancel_reset_cycle_multiple_times() {
    let token = CancellationToken::new();
    for _ in 0..5 {
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        token.reset();
    }
    assert!(!token.is_cancelled());
}

// Guard: periodic event iteration_count resets between consecutive periods
#[test]
fn test_periodic_iteration_count_resets_between_periods() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::BytecodeDispatch,
        "dispatch",
        "trace-period",
        DensityConfig {
            max_iterations: 4,
            max_total_iterations: 1_000,
        },
        token,
    );
    // First period: 4 ticks
    for _ in 0..4 {
        guard.tick();
    }
    guard.check();
    // Second period: 4 more ticks
    for _ in 0..4 {
        guard.tick();
    }
    guard.check();

    let events = guard.drain_events();
    assert_eq!(events.len(), 2);
    // Both periods should report iteration_count of 4
    assert_eq!(events[0].iteration_count, 4);
    assert_eq!(events[1].iteration_count, 4);
    // Total grows cumulatively
    assert_eq!(events[0].total_iterations, 4);
    assert_eq!(events[1].total_iterations, 8);
}

// Guard: interleaved explicit and periodic events preserve ordering
#[test]
fn test_interleaved_explicit_and_periodic_events_ordering() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::IrLowering,
        "lowerer",
        "trace-interleave",
        DensityConfig {
            max_iterations: 5,
            max_total_iterations: 1_000,
        },
        token,
    );
    // 3 ticks, then explicit checkpoint
    for _ in 0..3 {
        guard.tick();
    }
    guard.explicit_checkpoint();
    // 5 more ticks triggers periodic
    for _ in 0..5 {
        guard.tick();
    }
    guard.check();

    let events = guard.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].reason, CheckpointReason::Explicit);
    assert_eq!(events[1].reason, CheckpointReason::Periodic);
    // Explicit fired after 3 ticks; periodic fired after 5 more ticks
    assert_eq!(events[0].iteration_count, 3);
    assert_eq!(events[1].iteration_count, 5);
}

// Guard: explicit_checkpoint on a cancelled guard emits Drain, not Continue
#[test]
fn test_explicit_checkpoint_cancelled_emits_drain_action() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ModuleVerify,
        "verifier",
        "trace-explicit-cancel",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 1_000,
        },
        token.clone(),
    );
    for _ in 0..3 {
        guard.tick();
    }
    token.cancel();
    let action = guard.explicit_checkpoint();
    assert_eq!(action, CheckpointAction::Drain);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::CancelPending);
    assert_eq!(events[0].action, CheckpointAction::Drain);
}

#[test]
fn test_explicit_checkpoint_budget_exhaustion_emits_abort() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::IrCompilation,
        "compiler",
        "trace-explicit-budget",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 3,
        },
        token,
    );
    for _ in 0..3 {
        guard.tick();
    }
    let action = guard.explicit_checkpoint();
    assert_eq!(action, CheckpointAction::Abort);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::BudgetExhausted);
    assert_eq!(events[0].action, CheckpointAction::Abort);
}

// Guard: budget = 0 aborts immediately after first tick
#[test]
fn test_budget_zero_aborts_after_first_tick() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::GcScanning,
        "gc",
        "trace-zero-budget",
        DensityConfig {
            max_iterations: 1_000,
            max_total_iterations: 0,
        },
        token,
    );
    guard.tick();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Abort);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::BudgetExhausted);
}

// Guard: event_count increments correctly with mixed checkpoint types
#[test]
fn test_event_count_increments_for_mixed_checkpoint_types() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::PolicyIteration,
        "policy",
        "trace-mixed",
        DensityConfig {
            max_iterations: 5,
            max_total_iterations: 1_000,
        },
        token,
    );
    // Periodic event
    for _ in 0..5 {
        guard.tick();
    }
    guard.check();
    assert_eq!(guard.event_count(), 1);
    // Explicit event
    guard.explicit_checkpoint();
    assert_eq!(guard.event_count(), 2);
    // Drain clears
    guard.drain_events();
    assert_eq!(guard.event_count(), 0);
}

// Coverage: clone is independent of original
#[test]
fn test_coverage_clone_independence() {
    let mut original = CheckpointCoverage::new();
    original.register("bytecode_dispatch");
    let mut cloned = original.clone();
    // Registering on clone should not affect original
    cloned.register("gc_scanning");
    assert_eq!(original.covered_count(), 1);
    assert_eq!(cloned.covered_count(), 2);
    assert!(!original.coverage_contains("gc_scanning"));
}

// Coverage: all mandatory site names are in the uncovered list initially
#[test]
fn test_coverage_new_uncovered_contains_all_mandatory() {
    let cov = CheckpointCoverage::new();
    let uncov = cov.uncovered();
    let mandatory = [
        "bytecode_dispatch",
        "gc_scanning",
        "gc_sweep",
        "policy_iteration",
        "contract_evaluation",
        "replay_step",
        "module_decode",
        "module_verify",
        "ir_lowering",
        "ir_compilation",
    ];
    for site in &mandatory {
        assert!(uncov.contains(&site.to_string()), "missing: {site}");
    }
}

// Coverage: serde roundtrip on fully covered tracker
#[test]
fn test_coverage_full_serde_roundtrip() {
    let mut cov = CheckpointCoverage::new();
    for site in cov.uncovered() {
        cov.register(&site);
    }
    assert!(cov.all_covered());
    let json = serde_json::to_string(&cov).unwrap();
    let restored: CheckpointCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(cov, restored);
    assert!(restored.all_covered());
    assert_eq!(restored.covered_count(), 10);
}

// LoopSite: custom site with unicode content serializes and displays correctly
#[test]
fn test_loop_site_custom_unicode_serde_and_display() {
    let site = LoopSite::Custom("αβγ_loop".to_string());
    let json = serde_json::to_string(&site).unwrap();
    let restored: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, restored);
    assert_eq!(site.to_string(), "custom:αβγ_loop");
}

// CheckpointEvent: empty trace_id and component round-trip cleanly
#[test]
fn test_checkpoint_event_empty_strings_serde() {
    let event = CheckpointEvent {
        trace_id: String::new(),
        component: String::new(),
        loop_site: LoopSite::GcSweep,
        iteration_count: 0,
        total_iterations: 0,
        reason: CheckpointReason::Explicit,
        action: CheckpointAction::Continue,
        timestamp_virtual: 0,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CheckpointEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
    assert!(restored.trace_id.is_empty());
    assert!(restored.component.is_empty());
}

// DensityConfig: PartialEq distinguishes different configs
#[test]
fn test_density_config_partial_eq_distinguishes_values() {
    let a = DensityConfig {
        max_iterations: 10,
        max_total_iterations: 100,
    };
    let b = DensityConfig {
        max_iterations: 20,
        max_total_iterations: 100,
    };
    let c = DensityConfig {
        max_iterations: 10,
        max_total_iterations: 200,
    };
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    assert_eq!(a, a.clone());
}

// Guard: virtual_time and total_iterations stay in sync across periodic checkpoints
#[test]
fn test_virtual_time_and_total_iterations_in_sync_across_periods() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ContractEvaluation,
        "evaluator",
        "trace-sync",
        DensityConfig {
            max_iterations: 7,
            max_total_iterations: 1_000,
        },
        token,
    );
    for n in 1..=21u64 {
        guard.tick();
        guard.check();
        assert_eq!(guard.virtual_time(), n);
        assert_eq!(guard.total_iterations(), n);
    }
}

// Guard: check() immediately after construction (no ticks) returns Continue
#[test]
fn test_check_immediately_after_construction_returns_continue() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ReplayStep,
        "replay",
        "trace-empty",
        DensityConfig {
            max_iterations: 10,
            max_total_iterations: 100,
        },
        token,
    );
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Continue);
    assert_eq!(guard.event_count(), 0);
    assert_eq!(guard.total_iterations(), 0);
}

// Guard: after cancel+drain, reset token allows normal operation again
#[test]
fn test_guard_continues_after_token_reset_post_cancel() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ModuleDecode,
        "decoder",
        "trace-reset",
        DensityConfig {
            max_iterations: 5,
            max_total_iterations: 1_000,
        },
        token.clone(),
    );
    guard.tick();
    token.cancel();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Drain);
    guard.drain_events();

    // Reset token and continue
    token.reset();
    for _ in 0..5 {
        guard.tick();
    }
    let action2 = guard.check();
    // Periodic checkpoint should fire (5 ticks since last reset of iterations_since_checkpoint)
    assert_eq!(action2, CheckpointAction::Continue);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::Periodic);
}

// CheckpointAction: Debug output contains the variant name
#[test]
fn test_checkpoint_action_debug_contains_variant_name() {
    assert!(format!("{:?}", CheckpointAction::Continue).contains("Continue"));
    assert!(format!("{:?}", CheckpointAction::Drain).contains("Drain"));
    assert!(format!("{:?}", CheckpointAction::Abort).contains("Abort"));
}

// CheckpointReason: sorted order in BTreeSet matches declaration order
#[test]
fn test_checkpoint_reason_btreeset_order() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(CheckpointReason::Explicit);
    set.insert(CheckpointReason::BudgetExhausted);
    set.insert(CheckpointReason::CancelPending);
    set.insert(CheckpointReason::Periodic);
    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered[0], CheckpointReason::Periodic);
    assert_eq!(ordered[1], CheckpointReason::CancelPending);
    assert_eq!(ordered[2], CheckpointReason::BudgetExhausted);
    assert_eq!(ordered[3], CheckpointReason::Explicit);
}

// LoopSite: all non-Custom variants are less than Custom in Ord
#[test]
fn test_loop_site_non_custom_all_less_than_custom() {
    let custom = LoopSite::Custom(String::new());
    let non_custom = [
        LoopSite::BytecodeDispatch,
        LoopSite::GcScanning,
        LoopSite::GcSweep,
        LoopSite::PolicyIteration,
        LoopSite::ContractEvaluation,
        LoopSite::ReplayStep,
        LoopSite::ModuleDecode,
        LoopSite::ModuleVerify,
        LoopSite::IrLowering,
        LoopSite::IrCompilation,
    ];
    for site in &non_custom {
        assert!(site < &custom, "{site} should be less than Custom");
    }
}

// ---------------------------------------------------------------------------
// Helper method added for test_coverage_clone_independence
// (Uses the public API — coverage field is private; use uncovered() proxy)
// ---------------------------------------------------------------------------
trait CoverageExt {
    fn coverage_contains(&self, site: &str) -> bool;
}

impl CoverageExt for CheckpointCoverage {
    fn coverage_contains(&self, site: &str) -> bool {
        // A site is "known covered" if it is NOT in the uncovered list
        // and it IS counted in covered_count
        !self.uncovered().contains(&site.to_string()) && self.covered_count() > 0
    }
}
