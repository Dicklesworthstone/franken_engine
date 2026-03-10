//! Integration tests for the callback-driven stdlib dispatch module
//! (bd-1lsy.4.9.1 / RGC-311A).
//!
//! Covers: strategy selection, cost estimation, decision building, trace
//! assembly, profile generation, constraint enforcement, manifest generation,
//! serde round-trips, Display formatting, and edge cases.

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

use frankenengine_engine::callback_stdlib_dispatch::{
    BEAD_ID, COMPONENT, CallbackKind, DISPATCH_SCHEMA_VERSION, DispatchConstraints,
    DispatchDecision, DispatchProfile, DispatchStrategy, DispatchTrace, StdlibDispatchError,
    StdlibMethod, batch_cost, build_decision, build_profile, build_trace, constrained_decision,
    deopt_risk_tier, estimate_dispatch_cost, franken_engine_stdlib_dispatch_manifest,
    is_inlineable, optimal_pure_strategy, select_strategy, validate_stack_depth,
    worst_case_strategy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_constraints() -> DispatchConstraints {
    DispatchConstraints::default()
}

fn permissive_constraints() -> DispatchConstraints {
    DispatchConstraints {
        max_deopt_risk_millionths: 1_000_000,
        max_stack_depth: 128,
        allow_mutating_inline: true,
        allow_async_non_promise: true,
        epoch: SecurityEpoch::from_raw(1),
    }
}

// ---------------------------------------------------------------------------
// 1. Constants and enum exhaustiveness
// ---------------------------------------------------------------------------

#[test]
fn test_constants_and_enum_counts() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "callback_stdlib_dispatch");
    assert!(DISPATCH_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(StdlibMethod::ALL.len(), 16);
    assert_eq!(CallbackKind::ALL.len(), 5);
    assert_eq!(DispatchStrategy::ALL.len(), 4);

    // All variants are unique.
    let methods: BTreeSet<_> = StdlibMethod::ALL.iter().collect();
    assert_eq!(methods.len(), 16);
    let kinds: BTreeSet<_> = CallbackKind::ALL.iter().collect();
    assert_eq!(kinds.len(), 5);
}

// ---------------------------------------------------------------------------
// 2. StdlibMethod classification properties
// ---------------------------------------------------------------------------

#[test]
fn test_produces_collection_classification() {
    let producing: BTreeSet<_> = StdlibMethod::ALL
        .iter()
        .filter(|m| m.produces_collection())
        .collect();
    assert_eq!(producing.len(), 7);
    assert!(StdlibMethod::ArrayMap.produces_collection());
    assert!(StdlibMethod::ArrayFilter.produces_collection());
    assert!(StdlibMethod::ArrayFlatMap.produces_collection());
    assert!(StdlibMethod::ArrayFrom.produces_collection());
    assert!(StdlibMethod::ObjectKeys.produces_collection());
    assert!(!StdlibMethod::ArrayForEach.produces_collection());
    assert!(!StdlibMethod::ArrayReduce.produces_collection());
    assert!(!StdlibMethod::SetForEach.produces_collection());
}

#[test]
fn test_short_circuit_comparator_accumulator_async() {
    let short: Vec<_> = StdlibMethod::ALL
        .iter()
        .filter(|m| m.can_short_circuit())
        .collect();
    assert_eq!(short.len(), 4);
    assert!(StdlibMethod::ArrayFind.can_short_circuit());
    assert!(StdlibMethod::ArraySome.can_short_circuit());
    assert!(!StdlibMethod::ArrayMap.can_short_circuit());

    // Comparator: only sort.
    for m in StdlibMethod::ALL {
        assert_eq!(m.requires_comparator(), *m == StdlibMethod::ArraySort);
    }
    // Accumulator: only reduce.
    for m in StdlibMethod::ALL {
        assert_eq!(m.has_accumulator(), *m == StdlibMethod::ArrayReduce);
    }
    // Async dispatch: only PromiseThen.
    for m in StdlibMethod::ALL {
        assert_eq!(m.is_async_dispatch(), *m == StdlibMethod::PromiseThen);
    }
}

#[test]
fn test_method_name_unique_and_display() {
    let names: BTreeSet<_> = StdlibMethod::ALL.iter().map(|m| m.method_name()).collect();
    assert_eq!(names.len(), 16);
    for m in StdlibMethod::ALL {
        assert_eq!(format!("{m}"), m.method_name());
    }
}

// ---------------------------------------------------------------------------
// 3. CallbackKind properties
// ---------------------------------------------------------------------------

#[test]
fn test_callback_deopt_risk_ordering_and_eligibility() {
    let builtin = CallbackKind::BuiltinFunction.deopt_risk_millionths();
    let pure = CallbackKind::PureFunction.deopt_risk_millionths();
    let mutating = CallbackKind::MutatingFunction.deopt_risk_millionths();
    let async_fn = CallbackKind::AsyncFunction.deopt_risk_millionths();
    let generator = CallbackKind::GeneratorFunction.deopt_risk_millionths();
    assert!(builtin < pure && pure < mutating && mutating < async_fn && async_fn < generator);

    // Inlining eligibility: only pure and builtin.
    assert!(CallbackKind::PureFunction.is_inlining_eligible());
    assert!(CallbackKind::BuiltinFunction.is_inlining_eligible());
    assert!(!CallbackKind::MutatingFunction.is_inlining_eligible());
    assert!(!CallbackKind::AsyncFunction.is_inlining_eligible());
    assert!(!CallbackKind::GeneratorFunction.is_inlining_eligible());

    // Only async is async.
    assert!(CallbackKind::AsyncFunction.is_async());
    assert!(!CallbackKind::PureFunction.is_async());
}

#[test]
fn test_callback_kind_display() {
    for kind in CallbackKind::ALL {
        let s = format!("{kind}");
        assert!(s.starts_with("callback:"), "got {s}");
        assert!(s.len() > "callback:".len());
    }
}

// ---------------------------------------------------------------------------
// 4. DispatchStrategy properties
// ---------------------------------------------------------------------------

#[test]
fn test_strategy_cost_ordering_and_flags() {
    let spec = DispatchStrategy::SpecializedBuiltin;
    let inl = DispatchStrategy::InlinedCallback;
    let interp = DispatchStrategy::InterpreterCallback;
    let fall = DispatchStrategy::FallbackSlow;

    assert!(spec.base_cost_millionths() < inl.base_cost_millionths());
    assert!(inl.base_cost_millionths() < interp.base_cost_millionths());
    assert!(interp.base_cost_millionths() < fall.base_cost_millionths());

    assert!(spec.per_element_cost_millionths() < inl.per_element_cost_millionths());
    assert!(inl.per_element_cost_millionths() < interp.per_element_cost_millionths());

    assert!(inl.is_inlined());
    assert!(spec.is_inlined());
    assert!(!interp.is_inlined());
    assert!(!fall.is_inlined());
    assert!(fall.is_fallback());
    assert!(!interp.is_fallback());
}

#[test]
fn test_strategy_display() {
    for s in DispatchStrategy::ALL {
        let d = format!("{s}");
        assert!(d.starts_with("strategy:"));
    }
}

// ---------------------------------------------------------------------------
// 5. select_strategy decision rules
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_strategy_selection() {
    // Builtin on non-async -> SpecializedBuiltin.
    for m in StdlibMethod::ALL {
        if !m.is_async_dispatch() {
            assert_eq!(
                select_strategy(*m, CallbackKind::BuiltinFunction),
                DispatchStrategy::SpecializedBuiltin,
                "builtin on {m}"
            );
        }
    }
    // Builtin on PromiseThen -> Interpreter.
    assert_eq!(
        select_strategy(StdlibMethod::PromiseThen, CallbackKind::BuiltinFunction),
        DispatchStrategy::InterpreterCallback
    );
}

#[test]
fn test_pure_strategy_selection() {
    // Pure on non-sort -> Inlined.
    for m in StdlibMethod::ALL {
        if !m.requires_comparator() {
            assert_eq!(
                select_strategy(*m, CallbackKind::PureFunction),
                DispatchStrategy::InlinedCallback,
                "pure on {m}"
            );
        }
    }
    // Pure on sort -> Interpreter.
    assert_eq!(
        select_strategy(StdlibMethod::ArraySort, CallbackKind::PureFunction),
        DispatchStrategy::InterpreterCallback
    );
}

#[test]
fn test_generator_always_fallback() {
    for m in StdlibMethod::ALL {
        assert_eq!(
            select_strategy(*m, CallbackKind::GeneratorFunction),
            DispatchStrategy::FallbackSlow,
            "generator on {m}"
        );
    }
}

#[test]
fn test_async_and_mutating_strategy_selection() {
    // Async on non-promise -> Fallback; on PromiseThen -> Interpreter.
    assert_eq!(
        select_strategy(StdlibMethod::ArrayMap, CallbackKind::AsyncFunction),
        DispatchStrategy::FallbackSlow
    );
    assert_eq!(
        select_strategy(StdlibMethod::PromiseThen, CallbackKind::AsyncFunction),
        DispatchStrategy::InterpreterCallback
    );

    // Mutating on short-circuit -> Fallback; otherwise -> Interpreter.
    for m in StdlibMethod::ALL {
        let expected = if m.can_short_circuit() {
            DispatchStrategy::FallbackSlow
        } else {
            DispatchStrategy::InterpreterCallback
        };
        assert_eq!(
            select_strategy(*m, CallbackKind::MutatingFunction),
            expected,
            "mutating on {m}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Cost estimation
// ---------------------------------------------------------------------------

#[test]
fn test_cost_base_and_monotonicity() {
    // Zero elements = base cost for 1.0x overhead methods.
    let cost0 = estimate_dispatch_cost(
        StdlibMethod::ArrayMap,
        &DispatchStrategy::InlinedCallback,
        0,
    );
    assert_eq!(
        cost0,
        DispatchStrategy::InlinedCallback.base_cost_millionths()
    );

    // Monotonically increasing.
    let mut prev = 0u64;
    for n in [0, 10, 100, 1_000, 10_000] {
        let cost = estimate_dispatch_cost(
            StdlibMethod::ArrayFilter,
            &DispatchStrategy::InterpreterCallback,
            n,
        );
        assert!(cost >= prev);
        prev = cost;
    }
}

#[test]
fn test_cost_method_overhead_ordering() {
    let strat = DispatchStrategy::InterpreterCallback;
    let map_cost = estimate_dispatch_cost(StdlibMethod::ArrayMap, &strat, 100);
    let reduce_cost = estimate_dispatch_cost(StdlibMethod::ArrayReduce, &strat, 100);
    let flatmap_cost = estimate_dispatch_cost(StdlibMethod::ArrayFlatMap, &strat, 100);
    let sort_cost = estimate_dispatch_cost(StdlibMethod::ArraySort, &strat, 100);
    assert!(map_cost < reduce_cost, "reduce > map");
    assert!(reduce_cost < flatmap_cost, "flatmap > reduce");
    assert!(flatmap_cost < sort_cost, "sort > flatmap");
}

// ---------------------------------------------------------------------------
// 7. build_decision and DispatchDecision
// ---------------------------------------------------------------------------

#[test]
fn test_build_decision_fields_and_paths() {
    let fast = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction);
    assert_eq!(fast.method, StdlibMethod::ArrayFilter);
    assert_eq!(fast.callback_kind, CallbackKind::PureFunction);
    assert_eq!(fast.strategy, DispatchStrategy::InlinedCallback);
    assert!(fast.is_fast_path());
    assert!(!fast.is_slow_path());

    let slow = build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction);
    assert!(slow.is_slow_path());
    assert!(!slow.is_fast_path());
}

#[test]
fn test_build_decision_hash_deterministic_and_varies() {
    let d1 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction);
    let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction);
    assert_eq!(d1.content_hash, d2.content_hash);

    let d3 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d4 = build_decision(StdlibMethod::ArrayMap, CallbackKind::MutatingFunction);
    assert_ne!(d3.content_hash, d4.content_hash);
    assert_ne!(d1.content_hash, d3.content_hash);
}

#[test]
fn test_decision_display() {
    let d = build_decision(StdlibMethod::ArrayReduce, CallbackKind::MutatingFunction);
    let s = format!("{d}");
    assert!(s.contains("Array.prototype.reduce"));
    assert!(s.contains("callback:mutating"));
    assert!(s.contains("strategy:interpreter"));
}

// ---------------------------------------------------------------------------
// 8. is_inlineable
// ---------------------------------------------------------------------------

#[test]
fn test_is_inlineable_matrix() {
    // Pure/builtin inlineable on most methods, not on sort/PromiseThen.
    for m in StdlibMethod::ALL {
        let expected = !m.requires_comparator() && !m.is_async_dispatch();
        assert_eq!(
            is_inlineable(m, &CallbackKind::PureFunction),
            expected,
            "pure on {m}"
        );
        assert_eq!(
            is_inlineable(m, &CallbackKind::BuiltinFunction),
            expected,
            "builtin on {m}"
        );
    }
    // Non-eligible kinds never inlineable.
    for kind in &[
        CallbackKind::MutatingFunction,
        CallbackKind::AsyncFunction,
        CallbackKind::GeneratorFunction,
    ] {
        for m in StdlibMethod::ALL {
            assert!(!is_inlineable(m, kind), "{kind} on {m}");
        }
    }
}

// ---------------------------------------------------------------------------
// 9. Trace building and DispatchTrace methods
// ---------------------------------------------------------------------------

#[test]
fn test_trace_empty() {
    let trace = build_trace(Vec::new());
    assert!(trace.decisions.is_empty());
    assert_eq!(trace.total_cost_millionths, 0);
    assert_eq!(trace.inlined_fraction_millionths(), 0);
    assert_eq!(trace.fallback_fraction_millionths(), 0);
    assert_eq!(trace.average_cost_millionths(), 0);
    assert_eq!(trace.max_deopt_risk_millionths(), 0);
}

#[test]
fn test_trace_mixed_decisions() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayFind, CallbackKind::GeneratorFunction);
    let expected_cost = d1.estimated_cost_millionths + d2.estimated_cost_millionths;
    let trace = build_trace(vec![d1, d2]);

    assert_eq!(trace.decisions.len(), 2);
    assert_eq!(trace.total_cost_millionths, expected_cost);
    assert_eq!(trace.inlined_count, 1);
    assert_eq!(trace.fallback_count, 1);
    assert!(trace.trace_id.starts_with("trace-"));
    // 50% inlined, 50% fallback.
    assert_eq!(trace.inlined_fraction_millionths(), 500_000);
    assert_eq!(trace.fallback_fraction_millionths(), 500_000);
}

#[test]
fn test_trace_all_inlined() {
    let decisions = vec![
        build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
        build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction),
        build_decision(StdlibMethod::ArrayEvery, CallbackKind::BuiltinFunction),
    ];
    let trace = build_trace(decisions);
    assert_eq!(trace.inlined_fraction_millionths(), 1_000_000);
    assert_eq!(trace.fallback_fraction_millionths(), 0);
}

#[test]
fn test_trace_content_hash_deterministic() {
    let mk = || {
        build_trace(vec![
            build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
            build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
        ])
    };
    assert_eq!(mk().trace_content_hash(), mk().trace_content_hash());

    // Different decisions -> different hash.
    let t_other = build_trace(vec![build_decision(
        StdlibMethod::ArrayReduce,
        CallbackKind::MutatingFunction,
    )]);
    assert_ne!(mk().trace_content_hash(), t_other.trace_content_hash());
}

#[test]
fn test_trace_display() {
    let trace = build_trace(vec![
        build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
        build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction),
    ]);
    let s = format!("{trace}");
    assert!(s.starts_with("trace("));
    assert!(s.contains("decisions=2"));
}

// ---------------------------------------------------------------------------
// 10. Constrained decisions
// ---------------------------------------------------------------------------

#[test]
fn test_constrained_stack_overflow() {
    let c = default_constraints();
    assert!(
        constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            &c,
            c.max_stack_depth
        )
        .is_err()
    );
    assert!(
        constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            &c,
            c.max_stack_depth - 1
        )
        .is_ok()
    );
}

#[test]
fn test_constrained_async_non_promise_rejection_and_override() {
    let c = default_constraints();
    let result = constrained_decision(
        StdlibMethod::ArrayFilter,
        CallbackKind::AsyncFunction,
        &c,
        0,
    );
    assert_eq!(result, Err(StdlibDispatchError::CallbackTypeUnsafe));

    // Async on PromiseThen is OK even with default constraints.
    assert!(
        constrained_decision(
            StdlibMethod::PromiseThen,
            CallbackKind::AsyncFunction,
            &c,
            0
        )
        .is_ok()
    );

    // Permissive constraints allow async on non-promise.
    let cp = permissive_constraints();
    assert!(
        constrained_decision(
            StdlibMethod::ArrayFilter,
            CallbackKind::AsyncFunction,
            &cp,
            0
        )
        .is_ok()
    );
}

#[test]
fn test_constrained_low_deopt_ceiling_forces_fallback() {
    let c = DispatchConstraints {
        max_deopt_risk_millionths: 10_000,
        ..default_constraints()
    };
    // PureFunction deopt risk = 50_000 > ceiling 10_000.
    let d =
        constrained_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction, &c, 0).unwrap();
    assert_eq!(d.strategy, DispatchStrategy::FallbackSlow);
}

#[test]
fn test_constrained_normal_path() {
    let c = default_constraints();
    let d =
        constrained_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction, &c, 0).unwrap();
    assert_eq!(d.strategy, DispatchStrategy::InlinedCallback);
}

// ---------------------------------------------------------------------------
// 11. Profile building
// ---------------------------------------------------------------------------

#[test]
fn test_profile_empty_and_populated() {
    let empty_trace = build_trace(Vec::new());
    let p = build_profile(&empty_trace);
    assert_eq!(p.total_decisions, 0);
    assert_eq!(p.distinct_methods, 0);
    assert_eq!(p.average_deopt_risk_millionths, 0);

    let decisions = vec![
        build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
        build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
        build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction),
    ];
    let trace = build_trace(decisions);
    let profile = build_profile(&trace);
    assert_eq!(profile.total_decisions, 3);
    assert_eq!(profile.distinct_methods, 2);
    assert_eq!(profile.distinct_callback_kinds, 3);
    assert_eq!(profile.distinct_strategies, 3);
    assert!(profile.total_cost_millionths > 0);

    let s = format!("{profile}");
    assert!(s.starts_with("profile("));
}

// ---------------------------------------------------------------------------
// 12. deopt_risk_tier boundaries
// ---------------------------------------------------------------------------

#[test]
fn test_deopt_risk_tier_all_boundaries() {
    assert_eq!(deopt_risk_tier(0), "negligible");
    assert_eq!(deopt_risk_tier(99_999), "negligible");
    assert_eq!(deopt_risk_tier(100_000), "low");
    assert_eq!(deopt_risk_tier(299_999), "low");
    assert_eq!(deopt_risk_tier(300_000), "moderate");
    assert_eq!(deopt_risk_tier(599_999), "moderate");
    assert_eq!(deopt_risk_tier(600_000), "high");
    assert_eq!(deopt_risk_tier(799_999), "high");
    assert_eq!(deopt_risk_tier(800_000), "critical");
    assert_eq!(deopt_risk_tier(u64::MAX), "critical");
}

// ---------------------------------------------------------------------------
// 13. batch_cost
// ---------------------------------------------------------------------------

#[test]
fn test_batch_cost_empty_and_additive() {
    assert_eq!(batch_cost(&[]), 0);

    let items = vec![
        (
            StdlibMethod::ArrayMap,
            DispatchStrategy::InlinedCallback,
            50,
        ),
        (
            StdlibMethod::ArrayReduce,
            DispatchStrategy::InterpreterCallback,
            200,
        ),
    ];
    let total = batch_cost(&items);
    let c1 = estimate_dispatch_cost(
        StdlibMethod::ArrayMap,
        &DispatchStrategy::InlinedCallback,
        50,
    );
    let c2 = estimate_dispatch_cost(
        StdlibMethod::ArrayReduce,
        &DispatchStrategy::InterpreterCallback,
        200,
    );
    assert_eq!(total, c1.saturating_add(c2));
}

// ---------------------------------------------------------------------------
// 14. Optimal / worst-case helpers
// ---------------------------------------------------------------------------

#[test]
fn test_optimal_and_worst_case_strategies() {
    for m in StdlibMethod::ALL {
        assert_eq!(
            optimal_pure_strategy(*m),
            select_strategy(*m, CallbackKind::PureFunction)
        );
        assert_eq!(worst_case_strategy(*m), DispatchStrategy::FallbackSlow);
    }
}

// ---------------------------------------------------------------------------
// 15. Manifest generation
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_deterministic_and_correct() {
    let t1 = franken_engine_stdlib_dispatch_manifest();
    let t2 = franken_engine_stdlib_dispatch_manifest();
    assert!(!t1.decisions.is_empty());
    assert_eq!(t1.decisions.len(), t2.decisions.len());
    assert_eq!(t1.total_cost_millionths, t2.total_cost_millionths);
    assert_eq!(t1.trace_content_hash(), t2.trace_content_hash());
    assert!(t1.inlined_count > 0);
    assert!(t1.trace_id.starts_with("trace-"));
}

#[test]
fn test_manifest_no_async_on_non_promise() {
    let trace = franken_engine_stdlib_dispatch_manifest();
    for d in &trace.decisions {
        if d.callback_kind == CallbackKind::AsyncFunction {
            assert!(d.method.is_async_dispatch(), "found async on {}", d.method);
        }
    }
}

// ---------------------------------------------------------------------------
// 16. validate_stack_depth
// ---------------------------------------------------------------------------

#[test]
fn test_validate_stack_depth_custom() {
    let c = DispatchConstraints {
        max_stack_depth: 4,
        ..default_constraints()
    };
    assert!(validate_stack_depth(0, &c).is_ok());
    assert!(validate_stack_depth(3, &c).is_ok());
    assert!(validate_stack_depth(4, &c).is_err());
    assert!(validate_stack_depth(100, &c).is_err());
}

// ---------------------------------------------------------------------------
// 17. DispatchConstraints
// ---------------------------------------------------------------------------

#[test]
fn test_constraints_default_and_display() {
    let c = DispatchConstraints::default();
    assert_eq!(c.max_deopt_risk_millionths, 800_000);
    assert_eq!(c.max_stack_depth, 64);
    assert!(!c.allow_mutating_inline);
    assert!(!c.allow_async_non_promise);
    assert_eq!(c.epoch, SecurityEpoch::from_raw(1));

    let s = format!("{c}");
    assert!(s.contains("max-deopt=800000"));
    assert!(s.contains("max-depth=64"));
}

// ---------------------------------------------------------------------------
// 18. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_serde_roundtrip_all_enums() {
    for m in StdlibMethod::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: StdlibMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
    for k in CallbackKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: CallbackKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
    for s in DispatchStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: DispatchStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_serde_roundtrip_decision_and_trace() {
    let d = build_decision(StdlibMethod::ArrayFlatMap, CallbackKind::PureFunction);
    let json = serde_json::to_string(&d).unwrap();
    let back: DispatchDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);

    let trace = franken_engine_stdlib_dispatch_manifest();
    let json = serde_json::to_string(&trace).unwrap();
    let back: DispatchTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decisions.len(), trace.decisions.len());
    assert_eq!(back.total_cost_millionths, trace.total_cost_millionths);
}

#[test]
fn test_serde_roundtrip_profile_and_constraints() {
    let trace = franken_engine_stdlib_dispatch_manifest();
    let profile = build_profile(&trace);
    let json = serde_json::to_string(&profile).unwrap();
    let back: DispatchProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, profile);

    let c = DispatchConstraints {
        max_deopt_risk_millionths: 500_000,
        max_stack_depth: 32,
        allow_mutating_inline: true,
        allow_async_non_promise: true,
        epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: DispatchConstraints = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn test_serde_roundtrip_error_variants() {
    let errors = vec![
        StdlibDispatchError::UnsupportedMethod,
        StdlibDispatchError::CallbackTypeUnsafe,
        StdlibDispatchError::StackOverflow,
        StdlibDispatchError::InternalError("test msg".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: StdlibDispatchError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, e);
    }
}

// ---------------------------------------------------------------------------
// 19. Error Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_all_variants() {
    assert!(format!("{}", StdlibDispatchError::UnsupportedMethod).contains("unsupported"));
    assert!(format!("{}", StdlibDispatchError::CallbackTypeUnsafe).contains("unsafe"));
    let so = format!("{}", StdlibDispatchError::StackOverflow);
    assert!(so.contains("stack") && so.contains("64"));
    assert!(format!("{}", StdlibDispatchError::InternalError("boom".into())).contains("boom"));
}

// ---------------------------------------------------------------------------
// 20. Cross-cutting: high-deopt-risk flag
// ---------------------------------------------------------------------------

#[test]
fn test_decision_is_high_deopt_risk_flag() {
    // Generator risk = 700_000, threshold = 800_000 -> not high.
    let d_gen = build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction);
    assert!(!d_gen.is_high_deopt_risk());

    // Builtin risk = 20_000 -> not high.
    let d_builtin = build_decision(StdlibMethod::ArrayMap, CallbackKind::BuiltinFunction);
    assert!(!d_builtin.is_high_deopt_risk());

    // Manually verify threshold: 800_000 exactly is "high deopt risk".
    let mut d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    d.deopt_risk_millionths = 800_000;
    assert!(d.is_high_deopt_risk());
    d.deopt_risk_millionths = 799_999;
    assert!(!d.is_high_deopt_risk());
}

// ---------------------------------------------------------------------------
// 21. Trace max_deopt_risk and average_cost
// ---------------------------------------------------------------------------

#[test]
fn test_trace_max_deopt_and_average_cost() {
    let d_pure = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d_mut = build_decision(StdlibMethod::ArrayMap, CallbackKind::MutatingFunction);
    let pure_cost = d_pure.estimated_cost_millionths;
    let mut_cost = d_mut.estimated_cost_millionths;
    let trace = build_trace(vec![d_pure, d_mut]);

    assert_eq!(
        trace.max_deopt_risk_millionths(),
        CallbackKind::MutatingFunction.deopt_risk_millionths()
    );
    assert_eq!(trace.average_cost_millionths(), (pure_cost + mut_cost) / 2);
}
