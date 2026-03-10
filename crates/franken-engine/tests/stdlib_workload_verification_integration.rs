//! Integration tests for `stdlib_workload_verification`.
//!
//! Covers constants, enums, structs, verification functions, suite building,
//! coverage computation, trace verification, and the canonical manifest.

use frankenengine_engine::callback_stdlib_dispatch::{
    CallbackKind, DispatchDecision, DispatchStrategy, StdlibMethod, build_decision, build_trace,
    select_strategy,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::stdlib_workload_verification::{
    COMPONENT, MAX_MUTATION_VIOLATIONS, MIN_PASS_RATE_MILLIONTHS, MutationContract,
    MutationViolation, ScenarioResult, VERIFICATION_BEAD_ID, VERIFICATION_POLICY_ID,
    VERIFICATION_SCHEMA_VERSION, VerificationReport, WorkloadOutcome, WorkloadScenario,
    WorkloadSuite, build_canonical_pure_suite, build_verification_report, check_mutation_contract,
    franken_engine_stdlib_verification_manifest, infer_mutation_contract,
    suite_coverage_millionths, verify_scenario, verify_trace_against_suite,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_scenario(
    id: &str,
    method: StdlibMethod,
    kind: CallbackKind,
    contract: MutationContract,
    strategy: DispatchStrategy,
) -> WorkloadScenario {
    WorkloadScenario::new(
        id,
        method,
        kind,
        contract,
        100,
        strategy,
        format!("test {id}"),
    )
}

fn make_passing_result(id: &str, strategy: DispatchStrategy) -> ScenarioResult {
    let mut r = ScenarioResult {
        scenario_id: id.to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: strategy,
        mutation_honored: true,
        observed_cost_millionths: 100_000,
        observed_deopt_risk_millionths: 50_000,
        details: String::new(),
        content_hash: ContentHash::compute(b""),
    };
    r.seal();
    r
}

fn make_failing_result(id: &str, outcome: WorkloadOutcome) -> ScenarioResult {
    let mut r = ScenarioResult {
        scenario_id: id.to_string(),
        outcome,
        actual_strategy: DispatchStrategy::FallbackSlow,
        mutation_honored: outcome != WorkloadOutcome::MutationViolation,
        observed_cost_millionths: 800_000,
        observed_deopt_risk_millionths: 700_000,
        details: "failure detail".to_string(),
        content_hash: ContentHash::compute(b""),
    };
    r.seal();
    r
}

// ===========================================================================
// 1. Constants (6 tests)
// ===========================================================================

#[test]
fn constant_schema_version_contains_stdlib() {
    assert!(VERIFICATION_SCHEMA_VERSION.contains("stdlib"));
    assert!(VERIFICATION_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn constant_bead_id_has_prefix() {
    assert!(VERIFICATION_BEAD_ID.starts_with("bd-"));
    assert!(!VERIFICATION_BEAD_ID.is_empty());
}

#[test]
fn constant_policy_id_value() {
    assert_eq!(VERIFICATION_POLICY_ID, "RGC-311C");
}

#[test]
fn constant_component_value() {
    assert_eq!(COMPONENT, "stdlib_workload_verification");
}

#[test]
fn constant_min_pass_rate_is_95_percent() {
    assert_eq!(MIN_PASS_RATE_MILLIONTHS, 950_000);
}

#[test]
fn constant_max_mutation_violations_is_zero() {
    assert_eq!(MAX_MUTATION_VIOLATIONS, 0);
}

// ===========================================================================
// 2. MutationContract (5 tests)
// ===========================================================================

#[test]
fn mutation_contract_all_has_four_variants() {
    assert_eq!(MutationContract::ALL.len(), 4);
    assert!(MutationContract::ALL.contains(&MutationContract::ReadOnly));
    assert!(MutationContract::ALL.contains(&MutationContract::MayMutate));
    assert!(MutationContract::ALL.contains(&MutationContract::Accumulator));
    assert!(MutationContract::ALL.contains(&MutationContract::SideEffectOnly));
}

#[test]
fn mutation_contract_display_all_variants() {
    assert_eq!(format!("{}", MutationContract::ReadOnly), "read_only");
    assert_eq!(format!("{}", MutationContract::MayMutate), "may_mutate");
    assert_eq!(format!("{}", MutationContract::Accumulator), "accumulator");
    assert_eq!(
        format!("{}", MutationContract::SideEffectOnly),
        "side_effect_only"
    );
}

#[test]
fn mutation_contract_permits_in_place_mutation() {
    assert!(!MutationContract::ReadOnly.permits_in_place_mutation());
    assert!(MutationContract::MayMutate.permits_in_place_mutation());
    assert!(!MutationContract::Accumulator.permits_in_place_mutation());
    assert!(!MutationContract::SideEffectOnly.permits_in_place_mutation());
}

#[test]
fn mutation_contract_serde_roundtrip() {
    for c in MutationContract::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: MutationContract = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn mutation_contract_exhaustive_all_array() {
    // Verify ALL covers every variant by testing known count.
    let variants = [
        MutationContract::ReadOnly,
        MutationContract::MayMutate,
        MutationContract::Accumulator,
        MutationContract::SideEffectOnly,
    ];
    assert_eq!(MutationContract::ALL.len(), variants.len());
    for v in &variants {
        assert!(MutationContract::ALL.contains(v));
    }
}

// ===========================================================================
// 3. WorkloadOutcome (5 tests)
// ===========================================================================

#[test]
fn workload_outcome_all_has_six_variants() {
    assert_eq!(WorkloadOutcome::ALL.len(), 6);
}

#[test]
fn workload_outcome_is_pass() {
    assert!(WorkloadOutcome::Pass.is_pass());
    for outcome in &WorkloadOutcome::ALL[1..] {
        assert!(!outcome.is_pass(), "{outcome} should not be pass");
    }
}

#[test]
fn workload_outcome_is_violation() {
    assert!(WorkloadOutcome::MutationViolation.is_violation());
    assert!(WorkloadOutcome::Mismatch.is_violation());
    assert!(!WorkloadOutcome::Pass.is_violation());
    assert!(!WorkloadOutcome::Error.is_violation());
    assert!(!WorkloadOutcome::UnexpectedFallback.is_violation());
    assert!(!WorkloadOutcome::Timeout.is_violation());
}

#[test]
fn workload_outcome_display() {
    assert_eq!(format!("{}", WorkloadOutcome::Pass), "pass");
    assert_eq!(format!("{}", WorkloadOutcome::Mismatch), "mismatch");
    assert_eq!(format!("{}", WorkloadOutcome::Error), "error");
    assert_eq!(
        format!("{}", WorkloadOutcome::MutationViolation),
        "mutation_violation"
    );
    assert_eq!(
        format!("{}", WorkloadOutcome::UnexpectedFallback),
        "unexpected_fallback"
    );
    assert_eq!(format!("{}", WorkloadOutcome::Timeout), "timeout");
}

#[test]
fn workload_outcome_serde_roundtrip() {
    for o in WorkloadOutcome::ALL {
        let json = serde_json::to_string(o).unwrap();
        let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ===========================================================================
// 4. infer_mutation_contract (5 tests)
// ===========================================================================

#[test]
fn infer_contract_sort_is_may_mutate() {
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArraySort),
        MutationContract::MayMutate
    );
}

#[test]
fn infer_contract_reduce_is_accumulator() {
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayReduce),
        MutationContract::Accumulator
    );
}

#[test]
fn infer_contract_foreach_is_side_effect_only() {
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayForEach),
        MutationContract::SideEffectOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::SetForEach),
        MutationContract::SideEffectOnly
    );
}

#[test]
fn infer_contract_map_is_read_only() {
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayMap),
        MutationContract::ReadOnly
    );
}

#[test]
fn infer_contract_filter_is_read_only() {
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayFilter),
        MutationContract::ReadOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayFind),
        MutationContract::ReadOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayFindIndex),
        MutationContract::ReadOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayFlatMap),
        MutationContract::ReadOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArraySome),
        MutationContract::ReadOnly
    );
    assert_eq!(
        infer_mutation_contract(StdlibMethod::ArrayEvery),
        MutationContract::ReadOnly
    );
}

// ===========================================================================
// 5. WorkloadScenario (4 tests)
// ===========================================================================

#[test]
fn scenario_new_fields() {
    let s = WorkloadScenario::new(
        "sc-1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        200,
        DispatchStrategy::InlinedCallback,
        "map with pure cb",
    );
    assert_eq!(s.scenario_id, "sc-1");
    assert_eq!(s.method, StdlibMethod::ArrayMap);
    assert_eq!(s.callback_kind, CallbackKind::PureFunction);
    assert_eq!(s.mutation_contract, MutationContract::ReadOnly);
    assert_eq!(s.collection_size, 200);
    assert_eq!(s.expected_strategy, DispatchStrategy::InlinedCallback);
    assert_eq!(s.description, "map with pure cb");
}

#[test]
fn scenario_content_hash_deterministic() {
    let a = make_scenario(
        "det",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    );
    let b = a.clone();
    assert_eq!(a.content_hash(), b.content_hash());
    // Different scenario id produces different hash.
    let c = make_scenario(
        "det2",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    );
    assert_ne!(a.content_hash(), c.content_hash());
}

#[test]
fn scenario_display_contains_id_and_method() {
    let s = make_scenario(
        "disp-1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    );
    let d = format!("{s}");
    assert!(d.contains("disp-1"));
    assert!(d.contains("map"));
    assert!(d.contains("pure"));
}

#[test]
fn scenario_serde_roundtrip() {
    let s = make_scenario(
        "serde-1",
        StdlibMethod::ArrayReduce,
        CallbackKind::MutatingFunction,
        MutationContract::Accumulator,
        DispatchStrategy::InterpreterCallback,
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: WorkloadScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// 6. ScenarioResult (3 tests)
// ===========================================================================

#[test]
fn scenario_result_seal_produces_nonempty_hash() {
    let mut r = ScenarioResult {
        scenario_id: "seal-1".to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: DispatchStrategy::InlinedCallback,
        mutation_honored: true,
        observed_cost_millionths: 100_000,
        observed_deopt_risk_millionths: 50_000,
        details: String::new(),
        content_hash: ContentHash::compute(b""),
    };
    let before = r.content_hash.clone();
    r.seal();
    // seal should compute a different hash from the empty placeholder.
    assert_ne!(r.content_hash, before);
    // Sealing twice produces the same hash.
    let hash1 = r.content_hash.clone();
    r.seal();
    assert_eq!(r.content_hash, hash1);
}

#[test]
fn scenario_result_display() {
    let r = make_passing_result("disp-r1", DispatchStrategy::InlinedCallback);
    let d = format!("{r}");
    assert!(d.contains("disp-r1"));
    assert!(d.contains("pass"));
    assert!(d.contains("inlined"));
}

#[test]
fn scenario_result_serde_roundtrip() {
    let r = make_passing_result("serde-r1", DispatchStrategy::SpecializedBuiltin);
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 7. verify_scenario (4 tests)
// ===========================================================================

#[test]
fn verify_scenario_pass_when_strategy_matches() {
    let expected = select_strategy(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let scenario = make_scenario(
        "vs-pass",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        expected,
    );
    let decision = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(result.outcome, WorkloadOutcome::Pass);
    assert!(result.mutation_honored);
    assert!(result.details.is_empty());
}

#[test]
fn verify_scenario_mismatch_when_different_strategy() {
    // Expect InlinedCallback but provide InterpreterCallback.
    let scenario = make_scenario(
        "vs-mis",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    );
    let decision = DispatchDecision {
        method: StdlibMethod::ArrayMap,
        callback_kind: CallbackKind::PureFunction,
        strategy: DispatchStrategy::InterpreterCallback,
        estimated_cost_millionths: 500_000,
        deopt_risk_millionths: 50_000,
        content_hash: ContentHash::compute(b"test"),
    };
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(result.outcome, WorkloadOutcome::Mismatch);
    assert!(!result.details.is_empty());
}

#[test]
fn verify_scenario_unexpected_fallback() {
    // Expect InlinedCallback but provide FallbackSlow.
    let scenario = make_scenario(
        "vs-fb",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    );
    let decision = DispatchDecision {
        method: StdlibMethod::ArrayFilter,
        callback_kind: CallbackKind::PureFunction,
        strategy: DispatchStrategy::FallbackSlow,
        estimated_cost_millionths: 800_000,
        deopt_risk_millionths: 50_000,
        content_hash: ContentHash::compute(b"fb"),
    };
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(result.outcome, WorkloadOutcome::UnexpectedFallback);
}

#[test]
fn verify_scenario_records_cost_and_deopt_from_decision() {
    let expected = select_strategy(StdlibMethod::ArrayEvery, CallbackKind::PureFunction);
    let scenario = make_scenario(
        "vs-cost",
        StdlibMethod::ArrayEvery,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        expected,
    );
    let decision = build_decision(StdlibMethod::ArrayEvery, CallbackKind::PureFunction);
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(
        result.observed_cost_millionths,
        decision.estimated_cost_millionths
    );
    assert_eq!(
        result.observed_deopt_risk_millionths,
        decision.deopt_risk_millionths
    );
}

// ===========================================================================
// 8. check_mutation_contract (2 tests)
// ===========================================================================

#[test]
fn check_mutation_contract_always_true_for_all_variants() {
    for contract in MutationContract::ALL {
        for strategy in DispatchStrategy::ALL {
            assert!(
                check_mutation_contract(*contract, strategy),
                "contract={contract}, strategy={strategy}"
            );
        }
    }
}

#[test]
fn check_mutation_contract_read_only_with_fallback() {
    assert!(check_mutation_contract(
        MutationContract::ReadOnly,
        &DispatchStrategy::FallbackSlow
    ));
}

// ===========================================================================
// 9. WorkloadSuite (3 tests)
// ===========================================================================

#[test]
fn suite_new_is_empty() {
    let suite = WorkloadSuite::new("s1", "empty suite");
    assert_eq!(suite.suite_id, "s1");
    assert_eq!(suite.scenario_count(), 0);
    assert!(suite.scenarios.is_empty());
    assert_eq!(suite.description, "empty suite");
}

#[test]
fn suite_add_scenario_increments_count() {
    let mut suite = WorkloadSuite::new("s2", "test");
    assert_eq!(suite.scenario_count(), 0);
    suite.add_scenario(make_scenario(
        "a",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    assert_eq!(suite.scenario_count(), 1);
    suite.add_scenario(make_scenario(
        "b",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    assert_eq!(suite.scenario_count(), 2);
}

#[test]
fn suite_scenario_count_matches_scenarios_len() {
    let mut suite = WorkloadSuite::new("s3", "test");
    for i in 0..5 {
        suite.add_scenario(make_scenario(
            &format!("sc-{i}"),
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            DispatchStrategy::InlinedCallback,
        ));
    }
    assert_eq!(suite.scenario_count(), suite.scenarios.len());
    assert_eq!(suite.scenario_count(), 5);
}

// ===========================================================================
// 10. build_verification_report (4 tests)
// ===========================================================================

#[test]
fn report_empty_results_is_healthy_full_pass_rate() {
    let report = build_verification_report("rpt-empty", &test_epoch(), &[]);
    assert_eq!(report.total_scenarios, 0);
    assert_eq!(report.pass_count, 0);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.pass_rate_millionths, 1_000_000);
    assert!(report.is_healthy);
    assert!(report.mutation_violations.is_empty());
}

#[test]
fn report_all_passing_is_healthy() {
    let results: Vec<ScenarioResult> = (0..10)
        .map(|i| make_passing_result(&format!("p{i}"), DispatchStrategy::InlinedCallback))
        .collect();
    let report = build_verification_report("rpt-pass", &test_epoch(), &results);
    assert_eq!(report.total_scenarios, 10);
    assert_eq!(report.pass_count, 10);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.pass_rate_millionths, 1_000_000);
    assert!(report.is_healthy);
    assert_eq!(report.strategy_mismatch_count, 0);
}

#[test]
fn report_with_failures_below_threshold_is_unhealthy() {
    let mut results = Vec::new();
    // 9 pass, 1 mismatch -> 90% pass rate < 95% threshold.
    for i in 0..9 {
        results.push(make_passing_result(
            &format!("m:p{i}"),
            DispatchStrategy::InlinedCallback,
        ));
    }
    results.push(make_failing_result("m:f0", WorkloadOutcome::Mismatch));
    let report = build_verification_report("rpt-fail", &test_epoch(), &results);
    assert_eq!(report.total_scenarios, 10);
    assert_eq!(report.pass_count, 9);
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.pass_rate_millionths, 900_000);
    assert!(!report.is_healthy);
    assert_eq!(report.strategy_mismatch_count, 1);
}

#[test]
fn report_deterministic_content_hash() {
    let results = vec![
        make_passing_result("det:a", DispatchStrategy::InlinedCallback),
        make_passing_result("det:b", DispatchStrategy::SpecializedBuiltin),
    ];
    let a = build_verification_report("rpt-det", &test_epoch(), &results);
    let b = build_verification_report("rpt-det", &test_epoch(), &results);
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.pass_rate_millionths, b.pass_rate_millionths);
}

// ===========================================================================
// 11. build_canonical_pure_suite (2 tests)
// ===========================================================================

#[test]
fn canonical_suite_covers_all_methods() {
    let suite = build_canonical_pure_suite();
    assert_eq!(suite.scenario_count(), StdlibMethod::ALL.len());
    // Each method should appear exactly once.
    for method in StdlibMethod::ALL {
        let count = suite
            .scenarios
            .iter()
            .filter(|s| s.method == *method)
            .count();
        assert_eq!(count, 1, "method {method} should appear once");
    }
}

#[test]
fn canonical_suite_scenarios_have_correct_contracts() {
    let suite = build_canonical_pure_suite();
    for scenario in &suite.scenarios {
        let expected_contract = infer_mutation_contract(scenario.method);
        assert_eq!(
            scenario.mutation_contract, expected_contract,
            "scenario {} should have contract {}",
            scenario.scenario_id, expected_contract
        );
        assert_eq!(scenario.callback_kind, CallbackKind::PureFunction);
        // Expected strategy should match select_strategy for pure callbacks.
        let expected_strat = select_strategy(scenario.method, CallbackKind::PureFunction);
        assert_eq!(
            scenario.expected_strategy, expected_strat,
            "scenario {} strategy mismatch",
            scenario.scenario_id
        );
    }
}

// ===========================================================================
// 12. suite_coverage_millionths (3 tests)
// ===========================================================================

#[test]
fn coverage_empty_suite_is_zero() {
    let suite = WorkloadSuite::new("empty-cov", "empty");
    assert_eq!(suite_coverage_millionths(&suite), 0);
}

#[test]
fn coverage_canonical_suite_is_partial() {
    let suite = build_canonical_pure_suite();
    let cov = suite_coverage_millionths(&suite);
    // Canonical suite covers all methods but only PureFunction kind.
    // Coverage = 16 / (16 * 5) = 0.2 = 200_000 millionths.
    let methods_count = StdlibMethod::ALL.len() as u64;
    let kinds_count = CallbackKind::ALL.len() as u64;
    let expected = methods_count * 1_000_000 / (methods_count * kinds_count);
    assert_eq!(cov, expected);
    assert!(cov > 0);
    assert!(cov < 1_000_000);
}

#[test]
fn coverage_computed_correctly_for_custom_suite() {
    let mut suite = WorkloadSuite::new("custom-cov", "custom");
    // Add two distinct (method, callback) pairs.
    suite.add_scenario(make_scenario(
        "c1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    suite.add_scenario(make_scenario(
        "c2",
        StdlibMethod::ArrayFilter,
        CallbackKind::MutatingFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InterpreterCallback,
    ));
    // Duplicate pair should not increase coverage.
    suite.add_scenario(make_scenario(
        "c3",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    let total_pairs = StdlibMethod::ALL.len() as u64 * CallbackKind::ALL.len() as u64;
    let expected = 2u64 * 1_000_000 / total_pairs;
    assert_eq!(suite_coverage_millionths(&suite), expected);
}

// ===========================================================================
// 13. verify_trace_against_suite (3 tests)
// ===========================================================================

#[test]
fn trace_verification_matching_decisions() {
    let suite = build_canonical_pure_suite();
    // Build decisions for every method with PureFunction.
    let decisions: Vec<DispatchDecision> = StdlibMethod::ALL
        .iter()
        .map(|m| build_decision(*m, CallbackKind::PureFunction))
        .collect();
    let trace = build_trace(decisions);
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    // All should pass because the canonical suite uses the same select_strategy.
    assert_eq!(report.pass_count, report.total_scenarios);
    assert!(report.is_healthy);
    assert_eq!(report.fail_count, 0);
}

#[test]
fn trace_verification_no_matching_decisions() {
    let mut suite = WorkloadSuite::new("no-match", "no matching decisions");
    suite.add_scenario(make_scenario(
        "nm:map:pure",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    // Trace has no ArrayMap+PureFunction decision.
    let decisions = vec![build_decision(
        StdlibMethod::ArraySort,
        CallbackKind::MutatingFunction,
    )];
    let trace = build_trace(decisions);
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    assert_eq!(report.total_scenarios, 1);
    assert_eq!(report.pass_count, 0);
    assert_eq!(report.fail_count, 1);
    assert!(!report.is_healthy);
}

#[test]
fn trace_verification_mixed_results() {
    let mut suite = WorkloadSuite::new("mixed", "mixed results");
    // Scenario 1: ArrayMap + PureFunction -> expects InlinedCallback (will match).
    let strat1 = select_strategy(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    suite.add_scenario(make_scenario(
        "mix:map",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        strat1,
    ));
    // Scenario 2: ArrayForEach + PureFunction -> expects InlinedCallback (will match).
    let strat2 = select_strategy(StdlibMethod::ArrayForEach, CallbackKind::PureFunction);
    suite.add_scenario(make_scenario(
        "mix:forEach",
        StdlibMethod::ArrayForEach,
        CallbackKind::PureFunction,
        MutationContract::SideEffectOnly,
        strat2,
    ));
    // Scenario 3: ArrayReduce + BuiltinFunction -> trace won't have this combo.
    suite.add_scenario(make_scenario(
        "mix:reduce",
        StdlibMethod::ArrayReduce,
        CallbackKind::BuiltinFunction,
        MutationContract::Accumulator,
        DispatchStrategy::SpecializedBuiltin,
    ));

    let decisions = vec![
        build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
        build_decision(StdlibMethod::ArrayForEach, CallbackKind::PureFunction),
        // No ArrayReduce + BuiltinFunction in trace.
    ];
    let trace = build_trace(decisions);
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    assert_eq!(report.total_scenarios, 3);
    assert_eq!(report.pass_count, 2);
    assert_eq!(report.fail_count, 1);
}

// ===========================================================================
// 14. Manifest (2 tests)
// ===========================================================================

#[test]
fn manifest_not_empty_and_healthy() {
    let m = franken_engine_stdlib_verification_manifest();
    assert!(!m.report_id.is_empty());
    assert!(m.report_id.contains(VERIFICATION_BEAD_ID));
    assert!(m.is_healthy);
    assert_eq!(m.total_scenarios, 0);
    assert_eq!(m.pass_rate_millionths, 1_000_000);
}

#[test]
fn manifest_deterministic() {
    let a = franken_engine_stdlib_verification_manifest();
    let b = franken_engine_stdlib_verification_manifest();
    assert_eq!(a.report_id, b.report_id);
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.epoch, b.epoch);
}

// ===========================================================================
// 15. VerificationReport (2 tests)
// ===========================================================================

#[test]
fn report_rehash_produces_deterministic_hash() {
    let results = vec![
        make_passing_result("rh:a", DispatchStrategy::InlinedCallback),
        make_failing_result("rh:b", WorkloadOutcome::Mismatch),
    ];
    let mut report = build_verification_report("rh-test", &test_epoch(), &results);
    let hash1 = report.content_hash.clone();
    report.rehash();
    assert_eq!(report.content_hash, hash1);
}

#[test]
fn report_display_contains_key_info() {
    let results = vec![
        make_passing_result("d:a", DispatchStrategy::InlinedCallback),
        make_passing_result("d:b", DispatchStrategy::SpecializedBuiltin),
    ];
    let report = build_verification_report("disp-rpt", &test_epoch(), &results);
    let d = format!("{report}");
    assert!(d.contains("disp-rpt"));
    assert!(d.contains("2/2"));
    assert!(d.contains("healthy=true"));
}

// ===========================================================================
// Additional edge-case and structural tests
// ===========================================================================

#[test]
fn mutation_violation_display() {
    let v = MutationViolation {
        scenario_id: "mv-1".to_string(),
        contract: MutationContract::ReadOnly,
        observed_mutation: "modified array in place".to_string(),
        severity: 2,
    };
    let d = format!("{v}");
    assert!(d.contains("mv-1"));
    assert!(d.contains("read_only"));
    assert!(d.contains("modified array in place"));
}

#[test]
fn mutation_violation_serde_roundtrip() {
    let v = MutationViolation {
        scenario_id: "mv-serde".to_string(),
        contract: MutationContract::SideEffectOnly,
        observed_mutation: "unexpected write".to_string(),
        severity: 1,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: MutationViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn method_verification_summary_serde_roundtrip() {
    use frankenengine_engine::stdlib_workload_verification::MethodVerificationSummary;
    let mut strategy_counts = std::collections::BTreeMap::new();
    strategy_counts.insert("inlined".to_string(), 5);
    strategy_counts.insert("interpreter".to_string(), 2);
    let mvs = MethodVerificationSummary {
        method_name: "Array.prototype.map".to_string(),
        pass_count: 5,
        fail_count: 2,
        avg_cost_millionths: 120_000,
        max_deopt_risk_millionths: 350_000,
        strategy_counts,
    };
    let json = serde_json::to_string(&mvs).unwrap();
    let back: MethodVerificationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(mvs, back);
}

#[test]
fn report_method_summary_populated() {
    let results = vec![
        make_passing_result("Array.prototype.map:p1", DispatchStrategy::InlinedCallback),
        make_passing_result("Array.prototype.map:p2", DispatchStrategy::InlinedCallback),
        make_failing_result("Array.prototype.filter:f1", WorkloadOutcome::Mismatch),
    ];
    let report = build_verification_report("ms-test", &test_epoch(), &results);
    // Method summary keys are parsed from scenario_id split on ':'.
    assert!(report.method_summary.contains_key("Array.prototype.map"));
    assert!(report.method_summary.contains_key("Array.prototype.filter"));
    let map_summary = &report.method_summary["Array.prototype.map"];
    assert_eq!(map_summary.pass_count, 2);
    assert_eq!(map_summary.fail_count, 0);
    let filter_summary = &report.method_summary["Array.prototype.filter"];
    assert_eq!(filter_summary.pass_count, 0);
    assert_eq!(filter_summary.fail_count, 1);
}

#[test]
fn report_with_mutation_violations_is_unhealthy() {
    // Even with 100% pass rate, mutation violations make it unhealthy.
    // We need to create a scenario result with MutationViolation outcome.
    let mut r = ScenarioResult {
        scenario_id: "mut:v1".to_string(),
        outcome: WorkloadOutcome::MutationViolation,
        actual_strategy: DispatchStrategy::InterpreterCallback,
        mutation_honored: false,
        observed_cost_millionths: 500_000,
        observed_deopt_risk_millionths: 350_000,
        details: "mutation detected".to_string(),
        content_hash: ContentHash::compute(b""),
    };
    r.seal();
    let report = build_verification_report("mut-rpt", &test_epoch(), &[r]);
    assert!(!report.is_healthy);
    assert_eq!(report.mutation_violations.len(), 1);
    assert_eq!(report.mutation_violations[0].severity, 2);
}

#[test]
fn report_strategy_mismatch_count_includes_unexpected_fallback() {
    let results = vec![
        make_failing_result("mc:1", WorkloadOutcome::Mismatch),
        make_failing_result("mc:2", WorkloadOutcome::UnexpectedFallback),
        make_failing_result("mc:3", WorkloadOutcome::Error),
    ];
    let report = build_verification_report("mc-rpt", &test_epoch(), &results);
    // Mismatch + UnexpectedFallback = 2, Error doesn't count.
    assert_eq!(report.strategy_mismatch_count, 2);
}

#[test]
fn workload_suite_serde_roundtrip() {
    let mut suite = WorkloadSuite::new("serde-suite", "roundtrip test");
    suite.add_scenario(make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::InlinedCallback,
    ));
    suite.add_scenario(make_scenario(
        "s2",
        StdlibMethod::ArraySort,
        CallbackKind::MutatingFunction,
        MutationContract::MayMutate,
        DispatchStrategy::InterpreterCallback,
    ));
    let json = serde_json::to_string(&suite).unwrap();
    let back: WorkloadSuite = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, back);
}

#[test]
fn verification_report_serde_roundtrip() {
    let results = vec![
        make_passing_result("sr:a", DispatchStrategy::InlinedCallback),
        make_failing_result("sr:b", WorkloadOutcome::Timeout),
    ];
    let report = build_verification_report("serde-rpt", &test_epoch(), &results);
    let json = serde_json::to_string(&report).unwrap();
    let back: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn infer_contract_all_methods_covered() {
    // Every StdlibMethod should return a valid MutationContract.
    for method in StdlibMethod::ALL {
        let contract = infer_mutation_contract(*method);
        assert!(
            MutationContract::ALL.contains(&contract),
            "method {method} returned unknown contract"
        );
    }
}

#[test]
fn verify_scenario_fallback_slow_strategy_is_fallback() {
    let scenario = make_scenario(
        "fb-check",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        DispatchStrategy::SpecializedBuiltin,
    );
    let decision = DispatchDecision {
        method: StdlibMethod::ArrayMap,
        callback_kind: CallbackKind::PureFunction,
        strategy: DispatchStrategy::FallbackSlow,
        estimated_cost_millionths: 800_000,
        deopt_risk_millionths: 50_000,
        content_hash: ContentHash::compute(b"test"),
    };
    let result = verify_scenario(&scenario, &decision);
    // Expected SpecializedBuiltin, got FallbackSlow -> UnexpectedFallback.
    assert_eq!(result.outcome, WorkloadOutcome::UnexpectedFallback);
    assert_eq!(result.actual_strategy, DispatchStrategy::FallbackSlow);
}
