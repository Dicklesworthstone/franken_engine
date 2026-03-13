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

// =========================================================================
// A. LoopSite serde for all 11 variants (existing tests cover only 5)
// =========================================================================

#[test]
fn enrichment_loop_site_serde_contract_evaluation() {
    let site = LoopSite::ContractEvaluation;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn enrichment_loop_site_serde_replay_step() {
    let site = LoopSite::ReplayStep;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn enrichment_loop_site_serde_module_decode() {
    let site = LoopSite::ModuleDecode;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn enrichment_loop_site_serde_module_verify() {
    let site = LoopSite::ModuleVerify;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn enrichment_loop_site_serde_ir_lowering() {
    let site = LoopSite::IrLowering;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn enrichment_loop_site_serde_ir_compilation() {
    let site = LoopSite::IrCompilation;
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

// =========================================================================
// B. Guard: check with zero iterations returns Continue, no event
// =========================================================================

#[test]
fn enrichment_guard_check_zero_iterations_no_event() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::BytecodeDispatch,
        "dispatch",
        "t",
        DensityConfig {
            max_iterations: 10,
            max_total_iterations: 100,
        },
        token,
    );
    // check without any tick
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Continue);
    assert_eq!(guard.event_count(), 0);
    assert_eq!(guard.total_iterations(), 0);
    assert_eq!(guard.virtual_time(), 0);
}

// =========================================================================
// C. Guard: budget boundary — exactly at max_total_iterations
// =========================================================================

#[test]
fn enrichment_guard_budget_exact_boundary() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::GcScanning,
        "gc",
        "t",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 5,
        },
        token,
    );
    // 4 ticks — not yet at budget
    for _ in 0..4 {
        guard.tick();
        assert_eq!(guard.check(), CheckpointAction::Continue);
    }
    assert_eq!(guard.event_count(), 0);

    // 5th tick hits budget exactly
    guard.tick();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Abort);
    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::BudgetExhausted);
    assert_eq!(events[0].total_iterations, 5);
}

// =========================================================================
// D. Guard: mixed periodic + explicit events accumulate
// =========================================================================

#[test]
fn enrichment_guard_mixed_periodic_and_explicit_events() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::PolicyIteration,
        "policy",
        "t",
        DensityConfig {
            max_iterations: 5,
            max_total_iterations: 1000,
        },
        token,
    );
    // 5 ticks -> periodic event
    for _ in 0..5 {
        guard.tick();
    }
    guard.check();
    // explicit checkpoint
    guard.tick();
    guard.tick();
    guard.explicit_checkpoint();

    let events = guard.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].reason, CheckpointReason::Periodic);
    assert_eq!(events[1].reason, CheckpointReason::Explicit);
    // Explicit after 2 more ticks, iteration_count should be 2
    assert_eq!(events[1].iteration_count, 2);
}

// =========================================================================
// E. CancellationToken: cancel-reset-cancel cycle
// =========================================================================

#[test]
fn enrichment_token_cancel_reset_cancel_cycle() {
    let token = CancellationToken::new();
    assert!(!token.is_cancelled());

    token.cancel();
    assert!(token.is_cancelled());

    token.reset();
    assert!(!token.is_cancelled());

    token.cancel();
    assert!(token.is_cancelled());
}

#[test]
fn enrichment_token_cancel_idempotent() {
    let token = CancellationToken::new();
    token.cancel();
    token.cancel();
    assert!(token.is_cancelled());
}

#[test]
fn enrichment_token_reset_idempotent() {
    let token = CancellationToken::new();
    token.reset(); // reset when already not cancelled
    assert!(!token.is_cancelled());
}

// =========================================================================
// F. Guard: reset token after drain, then continue executing
// =========================================================================

#[test]
fn enrichment_guard_reset_token_after_drain_resumes() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ReplayStep,
        "replay",
        "t",
        DensityConfig {
            max_iterations: 10,
            max_total_iterations: 1000,
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
    guard.tick();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Continue);
    assert_eq!(guard.event_count(), 0);
}

// =========================================================================
// G. DensityConfig: max_iterations > max_total_iterations
// =========================================================================

#[test]
fn enrichment_density_config_density_larger_than_budget() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::IrCompilation,
        "compiler",
        "t",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 10,
        },
        token,
    );
    // Budget hit before density
    for _ in 0..10 {
        guard.tick();
        let action = guard.check();
        if action == CheckpointAction::Abort {
            break;
        }
    }
    let events = guard.drain_events();
    assert!(
        events
            .iter()
            .any(|e| e.reason == CheckpointReason::BudgetExhausted)
    );
    assert!(
        !events
            .iter()
            .any(|e| e.reason == CheckpointReason::Periodic)
    );
}

// =========================================================================
// H. DensityConfig: very large values serde
// =========================================================================

#[test]
fn enrichment_density_config_large_values_serde() {
    let config = DensityConfig {
        max_iterations: u64::MAX,
        max_total_iterations: u64::MAX,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: DensityConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// =========================================================================
// I. CheckpointEvent: timestamp_virtual increases across events
// =========================================================================

#[test]
fn enrichment_event_timestamps_are_monotonic() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ModuleVerify,
        "verifier",
        "t",
        DensityConfig {
            max_iterations: 3,
            max_total_iterations: 1000,
        },
        token,
    );
    for _ in 0..12 {
        guard.tick();
        guard.check();
    }
    let events = guard.drain_events();
    assert_eq!(events.len(), 4); // at 3, 6, 9, 12
    for pair in events.windows(2) {
        assert!(pair[1].timestamp_virtual > pair[0].timestamp_virtual);
    }
    assert_eq!(events[0].timestamp_virtual, 3);
    assert_eq!(events[1].timestamp_virtual, 6);
    assert_eq!(events[2].timestamp_virtual, 9);
    assert_eq!(events[3].timestamp_virtual, 12);
}

// =========================================================================
// J. BTreeSet of LoopSite for dedup and ordering
// =========================================================================

#[test]
fn enrichment_loop_site_btree_set_dedup() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(LoopSite::BytecodeDispatch);
    set.insert(LoopSite::GcScanning);
    set.insert(LoopSite::BytecodeDispatch); // duplicate
    set.insert(LoopSite::Custom("a".to_string()));
    set.insert(LoopSite::Custom("a".to_string())); // duplicate
    set.insert(LoopSite::Custom("b".to_string()));
    assert_eq!(set.len(), 4);
}

// =========================================================================
// K. BTreeSet of CheckpointReason for dedup
// =========================================================================

#[test]
fn enrichment_checkpoint_reason_btree_set() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(CheckpointReason::Periodic);
    set.insert(CheckpointReason::CancelPending);
    set.insert(CheckpointReason::BudgetExhausted);
    set.insert(CheckpointReason::Explicit);
    set.insert(CheckpointReason::Periodic); // duplicate
    assert_eq!(set.len(), 4);
}

// =========================================================================
// L. Guard: each of the 10 built-in LoopSite variants works
// =========================================================================

#[test]
fn enrichment_guard_all_builtin_loop_sites() {
    let sites = [
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
    for site in &sites {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            site.clone(),
            "comp",
            "t",
            DensityConfig {
                max_iterations: 2,
                max_total_iterations: 100,
            },
            token,
        );
        guard.tick();
        guard.tick();
        guard.check();
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].loop_site, *site);
    }
}

// =========================================================================
// M. Guard: explicit checkpoint while cancelled produces Drain event
// =========================================================================

#[test]
fn enrichment_explicit_checkpoint_while_cancelled_drain_event() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::BytecodeDispatch,
        "dispatch",
        "t",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 1000,
        },
        token.clone(),
    );
    guard.tick();
    token.cancel();
    let action = guard.explicit_checkpoint();
    assert_eq!(action, CheckpointAction::Drain);

    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, CheckpointReason::Explicit);
    assert_eq!(events[0].action, CheckpointAction::Drain);
}

// =========================================================================
// N. CheckpointCoverage: partial coverage count tracking
// =========================================================================

#[test]
fn enrichment_coverage_partial_count_tracking() {
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
    let mut cov = CheckpointCoverage::new();
    for (i, site) in mandatory.iter().enumerate() {
        assert_eq!(cov.covered_count(), i);
        assert_eq!(cov.uncovered().len(), 10 - i);
        cov.register(site);
    }
    assert!(cov.all_covered());
    assert_eq!(cov.covered_count(), 10);
    assert!(cov.uncovered().is_empty());
}

// =========================================================================
// O. CheckpointCoverage: clone independence
// =========================================================================

#[test]
fn enrichment_coverage_clone_independence() {
    let mut cov1 = CheckpointCoverage::new();
    cov1.register("bytecode_dispatch");
    let mut cov2 = cov1.clone();
    assert_eq!(cov1, cov2);

    // Mutate cov2, cov1 unchanged
    cov2.register("gc_scanning");
    assert_ne!(cov1, cov2);
    assert_eq!(cov1.covered_count(), 1);
    assert_eq!(cov2.covered_count(), 2);
}

// =========================================================================
// P. CheckpointEvent with each CheckpointAction variant
// =========================================================================

#[test]
fn enrichment_event_serde_all_action_variants() {
    for action in [
        CheckpointAction::Continue,
        CheckpointAction::Drain,
        CheckpointAction::Abort,
    ] {
        let event = CheckpointEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            loop_site: LoopSite::BytecodeDispatch,
            iteration_count: 1,
            total_iterations: 1,
            reason: CheckpointReason::Periodic,
            action,
            timestamp_virtual: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CheckpointEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

#[test]
fn enrichment_event_serde_all_reason_variants() {
    for reason in [
        CheckpointReason::Periodic,
        CheckpointReason::CancelPending,
        CheckpointReason::BudgetExhausted,
        CheckpointReason::Explicit,
    ] {
        let event = CheckpointEvent {
            trace_id: "trace".to_string(),
            component: "comp".to_string(),
            loop_site: LoopSite::IrLowering,
            iteration_count: 5,
            total_iterations: 50,
            reason,
            action: CheckpointAction::Continue,
            timestamp_virtual: 50,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CheckpointEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

// =========================================================================
// Q. LoopSite Display for remaining untested variants
// =========================================================================

#[test]
fn enrichment_loop_site_display_remaining() {
    assert_eq!(
        LoopSite::ContractEvaluation.to_string(),
        "contract_evaluation"
    );
    assert_eq!(LoopSite::ReplayStep.to_string(), "replay_step");
    assert_eq!(LoopSite::ModuleDecode.to_string(), "module_decode");
    assert_eq!(LoopSite::ModuleVerify.to_string(), "module_verify");
    assert_eq!(LoopSite::IrLowering.to_string(), "ir_lowering");
    assert_eq!(LoopSite::IrCompilation.to_string(), "ir_compilation");
}

// =========================================================================
// R. CheckpointEvent Debug nonempty
// =========================================================================

#[test]
fn enrichment_checkpoint_event_debug_nonempty() {
    let event = CheckpointEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        loop_site: LoopSite::GcSweep,
        iteration_count: 0,
        total_iterations: 0,
        reason: CheckpointReason::Explicit,
        action: CheckpointAction::Continue,
        timestamp_virtual: 0,
    };
    let dbg = format!("{event:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("GcSweep"));
}

// =========================================================================
// S. Guard: density_config=1 with cancellation mid-stream
// =========================================================================

#[test]
fn enrichment_guard_density_one_cancel_mid_stream() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ModuleDecode,
        "decoder",
        "t",
        DensityConfig {
            max_iterations: 1,
            max_total_iterations: 100,
        },
        token.clone(),
    );
    // 3 periodic checkpoints, then cancel
    for _ in 0..3 {
        guard.tick();
        guard.check();
    }
    token.cancel();
    guard.tick();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Drain);

    let events = guard.drain_events();
    assert_eq!(events.len(), 4); // 3 periodic + 1 cancel
    assert_eq!(events[0].reason, CheckpointReason::Periodic);
    assert_eq!(events[1].reason, CheckpointReason::Periodic);
    assert_eq!(events[2].reason, CheckpointReason::Periodic);
    assert_eq!(events[3].reason, CheckpointReason::CancelPending);
}

// =========================================================================
// T. Guard: event_count reflects current undrained events
// =========================================================================

#[test]
fn enrichment_guard_event_count_reflects_undrained() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::IrLowering,
        "lowering",
        "t",
        DensityConfig {
            max_iterations: 2,
            max_total_iterations: 100,
        },
        token,
    );
    assert_eq!(guard.event_count(), 0);

    // 2 ticks -> 1 event
    guard.tick();
    guard.tick();
    guard.check();
    assert_eq!(guard.event_count(), 1);

    // 2 more ticks -> 2 events total
    guard.tick();
    guard.tick();
    guard.check();
    assert_eq!(guard.event_count(), 2);

    // Drain resets
    guard.drain_events();
    assert_eq!(guard.event_count(), 0);
}

// =========================================================================
// U. CheckpointCoverage: JSON structure is deterministic
// =========================================================================

#[test]
fn enrichment_coverage_json_deterministic() {
    let mut cov1 = CheckpointCoverage::new();
    cov1.register("gc_scanning");
    cov1.register("bytecode_dispatch");

    let mut cov2 = CheckpointCoverage::new();
    cov2.register("bytecode_dispatch");
    cov2.register("gc_scanning");

    let json1 = serde_json::to_string(&cov1).unwrap();
    let json2 = serde_json::to_string(&cov2).unwrap();
    assert_eq!(json1, json2); // BTreeMap ensures deterministic serialization
}

// =========================================================================
// V. Guard: multiple explicit checkpoints
// =========================================================================

#[test]
fn enrichment_guard_multiple_explicit_checkpoints() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::ContractEvaluation,
        "contract",
        "t",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 1000,
        },
        token,
    );
    for _ in 0..3 {
        guard.tick();
        guard.tick();
        guard.explicit_checkpoint();
    }
    let events = guard.drain_events();
    assert_eq!(events.len(), 3);
    for e in &events {
        assert_eq!(e.reason, CheckpointReason::Explicit);
        assert_eq!(e.iteration_count, 2);
    }
    // Timestamps should be 2, 4, 6
    assert_eq!(events[0].timestamp_virtual, 2);
    assert_eq!(events[1].timestamp_virtual, 4);
    assert_eq!(events[2].timestamp_virtual, 6);
}

// =========================================================================
// W. LoopSite Custom with empty string
// =========================================================================

#[test]
fn enrichment_loop_site_custom_empty_string() {
    let site = LoopSite::Custom(String::new());
    assert_eq!(site.to_string(), "custom:");
    let json = serde_json::to_string(&site).unwrap();
    let back: LoopSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

// =========================================================================
// X. CheckpointEvent with Custom LoopSite serde
// =========================================================================

#[test]
fn enrichment_event_with_custom_loop_site_serde() {
    let event = CheckpointEvent {
        trace_id: "trace-custom".to_string(),
        component: "my_component".to_string(),
        loop_site: LoopSite::Custom("deep_scanner".to_string()),
        iteration_count: 42,
        total_iterations: 100,
        reason: CheckpointReason::Explicit,
        action: CheckpointAction::Continue,
        timestamp_virtual: 100,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CheckpointEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(json.contains("deep_scanner"));
}

// =========================================================================
// Y. DensityConfig: equality and non-equality
// =========================================================================

#[test]
fn enrichment_density_config_equality() {
    let a = DensityConfig {
        max_iterations: 10,
        max_total_iterations: 100,
    };
    let b = DensityConfig {
        max_iterations: 10,
        max_total_iterations: 100,
    };
    let c = DensityConfig {
        max_iterations: 10,
        max_total_iterations: 200,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// =========================================================================
// Z. Guard: total_iterations persists through periodic resets
// =========================================================================

#[test]
fn enrichment_guard_total_iterations_persists_through_resets() {
    let token = CancellationToken::new();
    let mut guard = CheckpointGuard::new(
        LoopSite::GcSweep,
        "gc",
        "t",
        DensityConfig {
            max_iterations: 3,
            max_total_iterations: 1000,
        },
        token,
    );
    // 9 ticks with density=3 -> 3 periodic events, total_iterations=9
    for _ in 0..9 {
        guard.tick();
        guard.check();
    }
    assert_eq!(guard.total_iterations(), 9);
    assert_eq!(guard.virtual_time(), 9);
    let events = guard.drain_events();
    assert_eq!(events.len(), 3);
    // Each event's total_iterations reflects cumulative count
    assert_eq!(events[0].total_iterations, 3);
    assert_eq!(events[1].total_iterations, 6);
    assert_eq!(events[2].total_iterations, 9);
}

// =========================================================================
// AA. CheckpointAction: Debug nonempty for all variants
// =========================================================================

#[test]
fn enrichment_checkpoint_action_debug_all_variants() {
    assert!(!format!("{:?}", CheckpointAction::Continue).is_empty());
    assert!(!format!("{:?}", CheckpointAction::Drain).is_empty());
    assert!(!format!("{:?}", CheckpointAction::Abort).is_empty());
}

// =========================================================================
// AB. CheckpointReason: Display round-trips through string matching
// =========================================================================

#[test]
fn enrichment_checkpoint_reason_display_strings_distinct() {
    let displays: Vec<String> = [
        CheckpointReason::Periodic,
        CheckpointReason::CancelPending,
        CheckpointReason::BudgetExhausted,
        CheckpointReason::Explicit,
    ]
    .iter()
    .map(|r| r.to_string())
    .collect();
    // All display strings are unique
    for i in 0..displays.len() {
        for j in (i + 1)..displays.len() {
            assert_ne!(displays[i], displays[j]);
        }
    }
}

// =========================================================================
// AC. LoopSite: Display strings for all built-in variants are distinct
// =========================================================================

#[test]
fn enrichment_loop_site_display_strings_distinct() {
    let sites = [
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
    let displays: Vec<String> = sites.iter().map(|s| s.to_string()).collect();
    for i in 0..displays.len() {
        for j in (i + 1)..displays.len() {
            assert_ne!(displays[i], displays[j]);
        }
    }
}

// =========================================================================
// AD. Guard: cloned token cancels guard from outside
// =========================================================================

#[test]
fn enrichment_guard_cloned_token_cancels() {
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let mut guard = CheckpointGuard::new(
        LoopSite::BytecodeDispatch,
        "dispatch",
        "t",
        DensityConfig {
            max_iterations: 100,
            max_total_iterations: 1000,
        },
        token,
    );
    guard.tick();
    // Cancel via clone
    token_clone.cancel();
    let action = guard.check();
    assert_eq!(action, CheckpointAction::Drain);
}

// =========================================================================
// AE. Coverage: serde roundtrip with mixed coverage state
// =========================================================================

#[test]
fn enrichment_coverage_serde_mixed_state() {
    let mut cov = CheckpointCoverage::new();
    cov.register("bytecode_dispatch");
    cov.register("gc_sweep");
    cov.register("ir_compilation");
    // 3 covered, 7 uncovered
    let json = serde_json::to_string(&cov).unwrap();
    let back: CheckpointCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(cov, back);
    assert_eq!(back.covered_count(), 3);
    assert_eq!(back.total(), 10);
    let uncov = back.uncovered();
    assert_eq!(uncov.len(), 7);
    assert!(!uncov.contains(&"bytecode_dispatch".to_string()));
    assert!(uncov.contains(&"gc_scanning".to_string()));
}
