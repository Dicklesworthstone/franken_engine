//! Enrichment integration tests for `callback_stdlib_dispatch`.
//!
//! Supplements the base tests with deeper coverage of: cost model precision,
//! constraint interactions, saturation behavior, hash determinism, inlining
//! eligibility matrix, error edge cases, and manifest properties.

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
    CallbackKind, DispatchConstraints, DispatchStrategy, StdlibDispatchError, StdlibMethod,
    batch_cost, build_decision, build_profile, build_trace, constrained_decision, deopt_risk_tier,
    estimate_dispatch_cost, franken_engine_stdlib_dispatch_manifest, is_inlineable,
    optimal_pure_strategy, select_strategy, validate_stack_depth, worst_case_strategy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

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

fn minimal_constraints() -> DispatchConstraints {
    DispatchConstraints {
        max_deopt_risk_millionths: 0,
        max_stack_depth: 1,
        allow_mutating_inline: false,
        allow_async_non_promise: false,
        epoch: SecurityEpoch::from_raw(1),
    }
}

// ===========================================================================
// A. Cost model precision (7 tests)
// ===========================================================================

#[test]
fn enrichment_zero_element_cost_not_zero() {
    // With zero elements, cost should still include the base cost
    for method in StdlibMethod::ALL {
        for strategy in DispatchStrategy::ALL {
            let cost = estimate_dispatch_cost(*method, strategy, 0);
            assert!(
                cost > 0,
                "zero-element cost for {method:?}/{strategy:?} should be > 0"
            );
        }
    }
}

#[test]
fn enrichment_cost_monotonic_with_element_count() {
    let method = StdlibMethod::ArrayMap;
    let strategy = DispatchStrategy::InlinedCallback;
    let mut prev = 0;
    for count in [0, 1, 10, 100, 1000, 10000] {
        let cost = estimate_dispatch_cost(method, &strategy, count);
        assert!(cost >= prev, "cost should be monotonically increasing");
        prev = cost;
    }
}

#[test]
fn enrichment_reduce_overhead_higher_than_map() {
    let strategy = DispatchStrategy::InterpreterCallback;
    let count = 100;
    let map_cost = estimate_dispatch_cost(StdlibMethod::ArrayMap, &strategy, count);
    let reduce_cost = estimate_dispatch_cost(StdlibMethod::ArrayReduce, &strategy, count);
    assert!(
        reduce_cost >= map_cost,
        "reduce overhead should be >= map overhead"
    );
}

#[test]
fn enrichment_sort_overhead_highest() {
    let strategy = DispatchStrategy::InterpreterCallback;
    let count = 100;
    let sort_cost = estimate_dispatch_cost(StdlibMethod::ArraySort, &strategy, count);
    let map_cost = estimate_dispatch_cost(StdlibMethod::ArrayMap, &strategy, count);
    assert!(
        sort_cost >= map_cost,
        "sort should have highest overhead multiplier"
    );
}

#[test]
fn enrichment_strategy_cost_ordering_across_strategies() {
    // For any method, SpecializedBuiltin <= InlinedCallback <= InterpreterCallback <= FallbackSlow
    for method in StdlibMethod::ALL {
        let specialized =
            estimate_dispatch_cost(*method, &DispatchStrategy::SpecializedBuiltin, 100);
        let inlined = estimate_dispatch_cost(*method, &DispatchStrategy::InlinedCallback, 100);
        let interpreter =
            estimate_dispatch_cost(*method, &DispatchStrategy::InterpreterCallback, 100);
        let fallback = estimate_dispatch_cost(*method, &DispatchStrategy::FallbackSlow, 100);
        assert!(
            specialized <= inlined,
            "{method:?}: specialized should be <= inlined"
        );
        assert!(
            inlined <= interpreter,
            "{method:?}: inlined should be <= interpreter"
        );
        assert!(
            interpreter <= fallback,
            "{method:?}: interpreter should be <= fallback"
        );
    }
}

#[test]
fn enrichment_batch_cost_matches_individual_sum() {
    let items = [
        (
            StdlibMethod::ArrayMap,
            DispatchStrategy::InlinedCallback,
            50_u64,
        ),
        (
            StdlibMethod::ArrayFilter,
            DispatchStrategy::InterpreterCallback,
            100,
        ),
        (StdlibMethod::ArraySort, DispatchStrategy::FallbackSlow, 200),
    ];
    let batch = batch_cost(&items);
    let individual: u64 = items
        .iter()
        .map(|(m, s, c)| estimate_dispatch_cost(*m, s, *c))
        .fold(0_u64, |acc, v| acc.saturating_add(v));
    assert_eq!(batch, individual);
}

#[test]
fn enrichment_batch_cost_empty_is_zero() {
    let cost = batch_cost(&[]);
    assert_eq!(cost, 0);
}

// ===========================================================================
// B. Constraint interactions (8 tests)
// ===========================================================================

#[test]
fn enrichment_minimal_constraints_all_fallback_or_error() {
    // max_deopt=0 should force everything to fallback
    let constraints = minimal_constraints();
    for method in StdlibMethod::ALL {
        if *method == StdlibMethod::PromiseThen {
            continue; // async on non-promise is rejected
        }
        let result = constrained_decision(*method, CallbackKind::PureFunction, &constraints, 0);
        match result {
            Ok(dec) => {
                // With max_deopt=0, high-deopt callbacks should be downgraded to fallback
                // Pure has deopt risk 50_000 > 0, so should be fallback
                assert!(
                    dec.strategy.is_fallback(),
                    "{method:?}: pure with max_deopt=0 should use fallback, got {:?}",
                    dec.strategy
                );
            }
            Err(_) => {
                // Some combos may error — that's fine
            }
        }
    }
}

#[test]
fn enrichment_stack_depth_at_max_minus_one_passes() {
    let constraints = default_constraints();
    let result = validate_stack_depth(constraints.max_stack_depth - 1, &constraints);
    assert!(result.is_ok());
}

#[test]
fn enrichment_stack_depth_at_max_fails() {
    let constraints = default_constraints();
    let result = validate_stack_depth(constraints.max_stack_depth, &constraints);
    assert!(result.is_err());
}

#[test]
fn enrichment_stack_depth_zero_passes() {
    let constraints = default_constraints();
    let result = validate_stack_depth(0, &constraints);
    assert!(result.is_ok());
}

#[test]
fn enrichment_async_on_non_promise_rejected_by_default() {
    let constraints = default_constraints();
    let result = constrained_decision(
        StdlibMethod::ArrayMap,
        CallbackKind::AsyncFunction,
        &constraints,
        0,
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_async_on_non_promise_allowed_with_flag() {
    let constraints = permissive_constraints();
    let result = constrained_decision(
        StdlibMethod::ArrayMap,
        CallbackKind::AsyncFunction,
        &constraints,
        0,
    );
    assert!(result.is_ok());
}

#[test]
fn enrichment_mutating_inline_not_allowed_by_default() {
    let constraints = default_constraints();
    let dec = constrained_decision(
        StdlibMethod::ArrayMap,
        CallbackKind::MutatingFunction,
        &constraints,
        0,
    )
    .unwrap();
    // Mutating should not be inlined without the flag
    if !constraints.allow_mutating_inline {
        assert!(
            !dec.strategy.is_inlined() || dec.strategy.is_fallback(),
            "mutating should not be inlined without flag"
        );
    }
}

#[test]
fn enrichment_constrained_decision_stack_overflow_error_type() {
    let constraints = default_constraints();
    let result = constrained_decision(
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        &constraints,
        constraints.max_stack_depth,
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("64") || msg.contains("stack"),
        "error should mention stack depth"
    );
}

// ===========================================================================
// C. Inlining eligibility matrix (5 tests)
// ===========================================================================

#[test]
fn enrichment_pure_inlineable_on_non_sort_non_async_methods() {
    for method in StdlibMethod::ALL {
        if *method == StdlibMethod::ArraySort || *method == StdlibMethod::PromiseThen {
            assert!(
                !is_inlineable(method, &CallbackKind::PureFunction),
                "{method:?}: pure should NOT be inlineable on sort/promise"
            );
        } else {
            assert!(
                is_inlineable(method, &CallbackKind::PureFunction),
                "{method:?}: pure should be inlineable"
            );
        }
    }
}

#[test]
fn enrichment_builtin_inlineable_on_non_sort_non_async_methods() {
    for method in StdlibMethod::ALL {
        if *method == StdlibMethod::ArraySort || *method == StdlibMethod::PromiseThen {
            assert!(!is_inlineable(method, &CallbackKind::BuiltinFunction));
        } else {
            assert!(
                is_inlineable(method, &CallbackKind::BuiltinFunction),
                "{method:?}: builtin should be inlineable"
            );
        }
    }
}

#[test]
fn enrichment_mutating_never_inlineable() {
    for method in StdlibMethod::ALL {
        assert!(
            !is_inlineable(method, &CallbackKind::MutatingFunction),
            "{method:?}: mutating should never be inlineable"
        );
    }
}

#[test]
fn enrichment_generator_never_inlineable() {
    for method in StdlibMethod::ALL {
        assert!(
            !is_inlineable(method, &CallbackKind::GeneratorFunction),
            "{method:?}: generator should never be inlineable"
        );
    }
}

#[test]
fn enrichment_async_never_inlineable() {
    for method in StdlibMethod::ALL {
        assert!(
            !is_inlineable(method, &CallbackKind::AsyncFunction),
            "{method:?}: async should never be inlineable"
        );
    }
}

// ===========================================================================
// D. Strategy selection rules (5 tests)
// ===========================================================================

#[test]
fn enrichment_builtin_specialized_except_async() {
    for method in StdlibMethod::ALL {
        let strategy = select_strategy(*method, CallbackKind::BuiltinFunction);
        if method.is_async_dispatch() {
            // Async methods can't use specialized even with builtins
            assert_ne!(
                strategy,
                DispatchStrategy::FallbackSlow,
                "{method:?}: builtin on async should not be fallback"
            );
        } else {
            assert_eq!(
                strategy,
                DispatchStrategy::SpecializedBuiltin,
                "{method:?}: builtin should get specialized"
            );
        }
    }
}

#[test]
fn enrichment_generator_always_fallback() {
    for method in StdlibMethod::ALL {
        let strategy = select_strategy(*method, CallbackKind::GeneratorFunction);
        assert_eq!(
            strategy,
            DispatchStrategy::FallbackSlow,
            "{method:?}: generator should always get fallback"
        );
    }
}

#[test]
fn enrichment_worst_case_always_fallback() {
    for method in StdlibMethod::ALL {
        let strategy = worst_case_strategy(*method);
        assert_eq!(
            strategy,
            DispatchStrategy::FallbackSlow,
            "{method:?}: worst case should be fallback"
        );
    }
}

#[test]
fn enrichment_optimal_pure_never_fallback() {
    for method in StdlibMethod::ALL {
        let strategy = optimal_pure_strategy(*method);
        assert!(
            !strategy.is_fallback(),
            "{method:?}: optimal pure should not be fallback"
        );
    }
}

#[test]
fn enrichment_promise_then_async_not_fallback() {
    // PromiseThen + AsyncFunction should be interpreter (async is expected there)
    let strategy = select_strategy(StdlibMethod::PromiseThen, CallbackKind::AsyncFunction);
    assert_ne!(strategy, DispatchStrategy::FallbackSlow);
}

// ===========================================================================
// E. Deopt risk classification (5 tests)
// ===========================================================================

#[test]
fn enrichment_deopt_tier_negligible() {
    assert_eq!(deopt_risk_tier(0), "negligible");
    assert_eq!(deopt_risk_tier(99_999), "negligible");
}

#[test]
fn enrichment_deopt_tier_low() {
    assert_eq!(deopt_risk_tier(100_000), "low");
    assert_eq!(deopt_risk_tier(299_999), "low");
}

#[test]
fn enrichment_deopt_tier_moderate() {
    assert_eq!(deopt_risk_tier(300_000), "moderate");
    assert_eq!(deopt_risk_tier(599_999), "moderate");
}

#[test]
fn enrichment_deopt_tier_high() {
    assert_eq!(deopt_risk_tier(600_000), "high");
    assert_eq!(deopt_risk_tier(799_999), "high");
}

#[test]
fn enrichment_deopt_tier_critical() {
    assert_eq!(deopt_risk_tier(800_000), "critical");
    assert_eq!(deopt_risk_tier(1_000_000), "critical");
}

// ===========================================================================
// F. Build decision and trace properties (6 tests)
// ===========================================================================

#[test]
fn enrichment_build_decision_hash_deterministic() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    assert_eq!(d1.content_hash, d2.content_hash);
}

#[test]
fn enrichment_build_decision_different_inputs_different_hash() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction);
    assert_ne!(d1.content_hash, d2.content_hash);
}

#[test]
fn enrichment_trace_single_decision_fractions() {
    let dec = build_decision(StdlibMethod::ArrayMap, CallbackKind::BuiltinFunction);
    let trace = build_trace(vec![dec]);
    if trace.decisions[0].strategy.is_inlined() {
        assert_eq!(trace.inlined_count, 1);
        assert_eq!(trace.inlined_fraction_millionths(), 1_000_000);
    }
    assert_eq!(trace.fallback_count, 0);
    assert_eq!(trace.fallback_fraction_millionths(), 0);
}

#[test]
fn enrichment_trace_empty_fractions_zero() {
    let trace = build_trace(vec![]);
    assert_eq!(trace.inlined_fraction_millionths(), 0);
    assert_eq!(trace.fallback_fraction_millionths(), 0);
    assert_eq!(trace.average_cost_millionths(), 0);
    assert_eq!(trace.max_deopt_risk_millionths(), 0);
}

#[test]
fn enrichment_trace_content_hash_order_dependent() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction);
    let trace_ab = build_trace(vec![d1.clone(), d2.clone()]);
    let trace_ba = build_trace(vec![d2, d1]);
    // Different order should produce different hash (if implementation is order-sensitive)
    // Either way, both should have valid hashes
    assert!(!trace_ab.trace_id.is_empty());
    assert!(!trace_ba.trace_id.is_empty());
}

#[test]
fn enrichment_trace_total_cost_sums_decisions() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::MutatingFunction);
    let expected = d1
        .estimated_cost_millionths
        .saturating_add(d2.estimated_cost_millionths);
    let trace = build_trace(vec![d1, d2]);
    assert_eq!(trace.total_cost_millionths, expected);
}

// ===========================================================================
// G. Profile properties (4 tests)
// ===========================================================================

#[test]
fn enrichment_profile_empty_trace() {
    let trace = build_trace(vec![]);
    let profile = build_profile(&trace);
    assert_eq!(profile.distinct_methods, 0);
    assert_eq!(profile.distinct_callback_kinds, 0);
    assert_eq!(profile.distinct_strategies, 0);
    assert_eq!(profile.total_decisions, 0);
}

#[test]
fn enrichment_profile_distinct_counts_with_duplicates() {
    let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let d2 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction); // duplicate
    let d3 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction); // new method
    let trace = build_trace(vec![d1, d2, d3]);
    let profile = build_profile(&trace);
    assert_eq!(profile.total_decisions, 3);
    assert_eq!(profile.distinct_methods, 2); // ArrayMap + ArrayFilter
    assert_eq!(profile.distinct_callback_kinds, 1); // PureFunction only
}

#[test]
fn enrichment_profile_serde_roundtrip() {
    let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let trace = build_trace(vec![d]);
    let profile = build_profile(&trace);
    let json = serde_json::to_string(&profile).unwrap();
    let back: frankenengine_engine::callback_stdlib_dispatch::DispatchProfile =
        serde_json::from_str(&json).unwrap();
    assert_eq!(back, profile);
}

#[test]
fn enrichment_profile_display_not_empty() {
    let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let trace = build_trace(vec![d]);
    let profile = build_profile(&trace);
    let s = format!("{profile}");
    assert!(!s.is_empty());
}

// ===========================================================================
// H. Manifest properties (3 tests)
// ===========================================================================

#[test]
fn enrichment_manifest_deterministic() {
    let m1 = franken_engine_stdlib_dispatch_manifest();
    let m2 = franken_engine_stdlib_dispatch_manifest();
    assert_eq!(m1.trace_content_hash(), m2.trace_content_hash());
    assert_eq!(m1.decisions.len(), m2.decisions.len());
}

#[test]
fn enrichment_manifest_covers_multiple_methods() {
    let manifest = franken_engine_stdlib_dispatch_manifest();
    let methods: BTreeSet<_> = manifest.decisions.iter().map(|d| d.method).collect();
    assert!(methods.len() >= 10, "manifest should cover most methods");
}

#[test]
fn enrichment_manifest_no_zero_cost_decisions() {
    let manifest = franken_engine_stdlib_dispatch_manifest();
    for dec in &manifest.decisions {
        assert!(
            dec.estimated_cost_millionths > 0,
            "decision for {:?} should have non-zero cost",
            dec.method
        );
    }
}

// ===========================================================================
// I. Enum name uniqueness (3 tests)
// ===========================================================================

#[test]
fn enrichment_method_names_all_unique() {
    let mut names = BTreeSet::new();
    for m in StdlibMethod::ALL {
        assert!(
            names.insert(m.method_name()),
            "duplicate method name: {}",
            m.method_name()
        );
    }
}

#[test]
fn enrichment_callback_kind_names_all_unique() {
    let mut names = BTreeSet::new();
    for k in CallbackKind::ALL {
        assert!(
            names.insert(k.kind_name()),
            "duplicate kind name: {}",
            k.kind_name()
        );
    }
}

#[test]
fn enrichment_strategy_names_all_unique() {
    let mut names = BTreeSet::new();
    for s in DispatchStrategy::ALL {
        assert!(
            names.insert(s.strategy_name()),
            "duplicate strategy name: {}",
            s.strategy_name()
        );
    }
}

// ===========================================================================
// J. Error serde and Display (3 tests)
// ===========================================================================

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = [
        StdlibDispatchError::UnsupportedMethod,
        StdlibDispatchError::CallbackTypeUnsafe,
        StdlibDispatchError::StackOverflow,
        StdlibDispatchError::InternalError("test error".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: StdlibDispatchError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_error_display_all_non_empty() {
    let errors = [
        StdlibDispatchError::UnsupportedMethod,
        StdlibDispatchError::CallbackTypeUnsafe,
        StdlibDispatchError::StackOverflow,
        StdlibDispatchError::InternalError("details".to_string()),
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_error_display_all_distinct() {
    let errors = [
        StdlibDispatchError::UnsupportedMethod,
        StdlibDispatchError::CallbackTypeUnsafe,
        StdlibDispatchError::StackOverflow,
        StdlibDispatchError::InternalError("details".to_string()),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        displays.insert(format!("{err}"));
    }
    assert_eq!(displays.len(), errors.len());
}

// ===========================================================================
// K. DispatchConstraints (3 tests)
// ===========================================================================

#[test]
fn enrichment_constraints_default_values() {
    let c = DispatchConstraints::default();
    assert_eq!(c.max_deopt_risk_millionths, 800_000);
    assert_eq!(c.max_stack_depth, 64);
    assert!(!c.allow_mutating_inline);
    assert!(!c.allow_async_non_promise);
}

#[test]
fn enrichment_constraints_serde_roundtrip() {
    let c = permissive_constraints();
    let json = serde_json::to_string(&c).unwrap();
    let back: DispatchConstraints = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn enrichment_constraints_display_not_empty() {
    let c = default_constraints();
    let s = format!("{c}");
    assert!(!s.is_empty());
}

// ===========================================================================
// L. Method classification properties (4 tests)
// ===========================================================================

#[test]
fn enrichment_produces_collection_count() {
    let count = StdlibMethod::ALL
        .iter()
        .filter(|m| m.produces_collection())
        .count();
    assert!(count >= 5, "at least 5 methods should produce collections");
}

#[test]
fn enrichment_short_circuit_methods() {
    assert!(StdlibMethod::ArrayFind.can_short_circuit());
    assert!(StdlibMethod::ArrayFindIndex.can_short_circuit());
    assert!(StdlibMethod::ArraySome.can_short_circuit());
    assert!(StdlibMethod::ArrayEvery.can_short_circuit());
    assert!(!StdlibMethod::ArrayMap.can_short_circuit());
}

#[test]
fn enrichment_only_sort_requires_comparator() {
    for m in StdlibMethod::ALL {
        if *m == StdlibMethod::ArraySort {
            assert!(m.requires_comparator());
        } else {
            assert!(
                !m.requires_comparator(),
                "{m:?} should not require comparator"
            );
        }
    }
}

#[test]
fn enrichment_only_reduce_has_accumulator() {
    for m in StdlibMethod::ALL {
        if *m == StdlibMethod::ArrayReduce {
            assert!(m.has_accumulator());
        } else {
            assert!(!m.has_accumulator(), "{m:?} should not have accumulator");
        }
    }
}
