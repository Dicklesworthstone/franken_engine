//! Enrichment integration tests for `stdlib_workload_verification`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::callback_stdlib_dispatch::{
    CallbackKind, DispatchDecision, DispatchStrategy, DispatchTrace, StdlibMethod, build_decision,
    build_trace,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::stdlib_workload_verification::*;

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
    size: u64,
    strategy: DispatchStrategy,
) -> WorkloadScenario {
    WorkloadScenario::new(
        id,
        method,
        kind,
        contract,
        size,
        strategy,
        format!("test {id}"),
    )
}

fn make_passing_result(scenario_id: &str) -> ScenarioResult {
    let mut r = ScenarioResult {
        scenario_id: scenario_id.to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: DispatchStrategy::InlinedCallback,
        mutation_honored: true,
        observed_cost_millionths: 100_000,
        observed_deopt_risk_millionths: 50_000,
        details: String::new(),
        content_hash: ContentHash::compute(b""),
    };
    r.seal();
    r
}

fn make_failing_result(scenario_id: &str, outcome: WorkloadOutcome) -> ScenarioResult {
    let mut r = ScenarioResult {
        scenario_id: scenario_id.to_string(),
        outcome,
        actual_strategy: DispatchStrategy::FallbackSlow,
        mutation_honored: outcome != WorkloadOutcome::MutationViolation,
        observed_cost_millionths: 800_000,
        observed_deopt_risk_millionths: 700_000,
        details: format!("failure: {outcome}"),
        content_hash: ContentHash::compute(b""),
    };
    r.seal();
    r
}

/// Build a DispatchTrace with decisions for specified method/callback pairs.
fn make_trace(pairs: &[(StdlibMethod, CallbackKind)]) -> DispatchTrace {
    let decisions: Vec<DispatchDecision> =
        pairs.iter().map(|(m, c)| build_decision(*m, *c)).collect();
    build_trace(decisions)
}

// ---------------------------------------------------------------------------
// MutationContract: serde roundtrip for all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_contract_serde_all_variants() {
    for contract in MutationContract::ALL {
        let json = serde_json::to_string(contract).unwrap();
        let back: MutationContract = serde_json::from_str(&json).unwrap();
        assert_eq!(*contract, back);
    }
}

// ---------------------------------------------------------------------------
// MutationContract: Display distinct values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_contract_display_all_distinct() {
    let displays: BTreeSet<String> = MutationContract::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), MutationContract::ALL.len());
}

// ---------------------------------------------------------------------------
// MutationContract: permits_in_place_mutation exhaustive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_contract_permits_in_place_exhaustive() {
    assert!(!MutationContract::ReadOnly.permits_in_place_mutation());
    assert!(MutationContract::MayMutate.permits_in_place_mutation());
    assert!(!MutationContract::Accumulator.permits_in_place_mutation());
    assert!(!MutationContract::SideEffectOnly.permits_in_place_mutation());
}

// ---------------------------------------------------------------------------
// MutationContract: Display matches serde rename
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_contract_display_matches_serde() {
    assert_eq!(MutationContract::ReadOnly.to_string(), "read_only");
    assert_eq!(MutationContract::MayMutate.to_string(), "may_mutate");
    assert_eq!(MutationContract::Accumulator.to_string(), "accumulator");
    assert_eq!(
        MutationContract::SideEffectOnly.to_string(),
        "side_effect_only"
    );
}

// ---------------------------------------------------------------------------
// WorkloadOutcome: serde roundtrip all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_outcome_serde_all_variants() {
    for outcome in WorkloadOutcome::ALL {
        let json = serde_json::to_string(outcome).unwrap();
        let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

// ---------------------------------------------------------------------------
// WorkloadOutcome: Display distinct
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_outcome_display_all_distinct() {
    let displays: BTreeSet<String> = WorkloadOutcome::ALL.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), WorkloadOutcome::ALL.len());
}

// ---------------------------------------------------------------------------
// WorkloadOutcome: is_pass only for Pass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_outcome_is_pass_only_pass() {
    for outcome in WorkloadOutcome::ALL {
        if *outcome == WorkloadOutcome::Pass {
            assert!(outcome.is_pass());
        } else {
            assert!(!outcome.is_pass(), "{outcome} should not be is_pass");
        }
    }
}

// ---------------------------------------------------------------------------
// WorkloadOutcome: is_violation for MutationViolation and Mismatch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_outcome_is_violation_subset() {
    let violations: Vec<&WorkloadOutcome> = WorkloadOutcome::ALL
        .iter()
        .filter(|o| o.is_violation())
        .collect();
    assert_eq!(violations.len(), 2);
    assert!(WorkloadOutcome::MutationViolation.is_violation());
    assert!(WorkloadOutcome::Mismatch.is_violation());
    assert!(!WorkloadOutcome::Error.is_violation());
    assert!(!WorkloadOutcome::UnexpectedFallback.is_violation());
    assert!(!WorkloadOutcome::Timeout.is_violation());
}

// ---------------------------------------------------------------------------
// infer_mutation_contract: exhaustive coverage of all StdlibMethods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_infer_mutation_contract_all_methods() {
    for method in StdlibMethod::ALL {
        let contract = infer_mutation_contract(*method);
        match method {
            StdlibMethod::ArraySort => {
                assert_eq!(contract, MutationContract::MayMutate);
            }
            StdlibMethod::ArrayReduce => {
                assert_eq!(contract, MutationContract::Accumulator);
            }
            StdlibMethod::ArrayForEach | StdlibMethod::SetForEach => {
                assert_eq!(contract, MutationContract::SideEffectOnly);
            }
            _ => {
                assert_eq!(contract, MutationContract::ReadOnly, "method {method}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WorkloadScenario: content_hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_content_hash_deterministic() {
    let s1 = make_scenario(
        "map:pure",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let s2 = s1.clone();
    assert_eq!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// WorkloadScenario: different ids produce different hashes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_content_hash_varies_by_id() {
    let s1 = make_scenario(
        "id-a",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let s2 = make_scenario(
        "id-b",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// WorkloadScenario: different methods produce different hashes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_content_hash_varies_by_method() {
    let s1 = make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let s2 = make_scenario(
        "s1",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// WorkloadScenario: Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_display_format() {
    let s = make_scenario(
        "test-scenario",
        StdlibMethod::ArrayReduce,
        CallbackKind::MutatingFunction,
        MutationContract::Accumulator,
        500,
        DispatchStrategy::InterpreterCallback,
    );
    let display = format!("{s}");
    assert!(display.contains("test-scenario"));
    assert!(display.contains("reduce"));
    assert!(display.contains("mutating"));
    assert!(display.contains("accumulator"));
    assert!(display.contains("500"));
}

// ---------------------------------------------------------------------------
// WorkloadScenario: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_serde_roundtrip() {
    let s = make_scenario(
        "serde-test",
        StdlibMethod::ArrayFlatMap,
        CallbackKind::BuiltinFunction,
        MutationContract::ReadOnly,
        250,
        DispatchStrategy::SpecializedBuiltin,
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: WorkloadScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// ScenarioResult: seal deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_result_seal_deterministic() {
    let r1 = make_passing_result("seal-test");
    let r2 = make_passing_result("seal-test");
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// ScenarioResult: seal changes hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_result_seal_changes_hash() {
    let mut r = ScenarioResult {
        scenario_id: "s1".to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: DispatchStrategy::InlinedCallback,
        mutation_honored: true,
        observed_cost_millionths: 100_000,
        observed_deopt_risk_millionths: 50_000,
        details: String::new(),
        content_hash: ContentHash::compute(b"initial"),
    };
    let before = r.content_hash;
    r.seal();
    // After seal, hash should differ from the arbitrary initial
    assert_ne!(before, r.content_hash);
}

// ---------------------------------------------------------------------------
// ScenarioResult: Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_result_display_format() {
    let r = make_passing_result("display-test");
    let display = format!("{r}");
    assert!(display.contains("display-test"));
    assert!(display.contains("pass"));
    assert!(display.contains("mutation_ok=true"));
}

// ---------------------------------------------------------------------------
// ScenarioResult: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_result_serde_roundtrip() {
    let r = make_passing_result("serde-result");
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// MutationViolation: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_violation_serde_roundtrip() {
    let v = MutationViolation {
        scenario_id: "mv-1".to_string(),
        contract: MutationContract::ReadOnly,
        observed_mutation: "array.splice".to_string(),
        severity: 2,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: MutationViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// MutationViolation: Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_violation_display() {
    let v = MutationViolation {
        scenario_id: "mv-display".to_string(),
        contract: MutationContract::ReadOnly,
        observed_mutation: "push".to_string(),
        severity: 1,
    };
    let display = format!("{v}");
    assert!(display.contains("mv-display"));
    assert!(display.contains("read_only"));
    assert!(display.contains("push"));
}

// ---------------------------------------------------------------------------
// verify_scenario: pass when strategy matches
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_scenario_pass() {
    let scenario = make_scenario(
        "verify-pass",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let decision = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let result = verify_scenario(&scenario, &decision);
    assert!(result.outcome.is_pass());
    assert!(result.mutation_honored);
    assert!(result.details.is_empty());
}

// ---------------------------------------------------------------------------
// verify_scenario: mismatch when strategy differs (non-fallback)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_scenario_mismatch() {
    let scenario = make_scenario(
        "verify-mismatch",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::SpecializedBuiltin,
    );
    let decision = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(result.outcome, WorkloadOutcome::Mismatch);
    assert!(!result.details.is_empty());
}

// ---------------------------------------------------------------------------
// verify_scenario: unexpected fallback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_scenario_unexpected_fallback() {
    let scenario = make_scenario(
        "verify-fallback",
        StdlibMethod::ArrayMap,
        CallbackKind::GeneratorFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let decision = build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction);
    let result = verify_scenario(&scenario, &decision);
    assert_eq!(result.outcome, WorkloadOutcome::UnexpectedFallback);
}

// ---------------------------------------------------------------------------
// check_mutation_contract: always true in current implementation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_check_mutation_contract_all_pass() {
    for contract in MutationContract::ALL {
        for strategy in DispatchStrategy::ALL {
            assert!(
                check_mutation_contract(*contract, strategy),
                "contract={contract}, strategy={strategy}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// build_verification_report: empty results = healthy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_empty_is_healthy() {
    let report = build_verification_report("empty", &test_epoch(), &[]);
    assert!(report.is_healthy);
    assert_eq!(report.total_scenarios, 0);
    assert_eq!(report.pass_count, 0);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.pass_rate_millionths, 1_000_000);
    assert!(report.mutation_violations.is_empty());
}

// ---------------------------------------------------------------------------
// build_verification_report: all passing
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_all_passing() {
    let results: Vec<ScenarioResult> = (0..10)
        .map(|i| make_passing_result(&format!("method:s{i}")))
        .collect();
    let report = build_verification_report("all-pass", &test_epoch(), &results);
    assert_eq!(report.total_scenarios, 10);
    assert_eq!(report.pass_count, 10);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.pass_rate_millionths, 1_000_000);
    assert!(report.is_healthy);
    assert_eq!(report.strategy_mismatch_count, 0);
}

// ---------------------------------------------------------------------------
// build_verification_report: mixed pass/fail
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_mixed_results() {
    let mut results = Vec::new();
    for i in 0..19 {
        results.push(make_passing_result(&format!("method:p{i}")));
    }
    results.push(make_failing_result("method:f0", WorkloadOutcome::Mismatch));

    let report = build_verification_report("mixed", &test_epoch(), &results);
    assert_eq!(report.total_scenarios, 20);
    assert_eq!(report.pass_count, 19);
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.pass_rate_millionths, 950_000);
    assert!(report.is_healthy);
    assert_eq!(report.strategy_mismatch_count, 1);
}

// ---------------------------------------------------------------------------
// build_verification_report: below threshold is unhealthy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_below_threshold_unhealthy() {
    let mut results = Vec::new();
    for i in 0..9 {
        results.push(make_passing_result(&format!("method:p{i}")));
    }
    results.push(make_failing_result("method:f0", WorkloadOutcome::Error));

    let report = build_verification_report("below", &test_epoch(), &results);
    assert_eq!(report.pass_rate_millionths, 900_000);
    assert!(!report.is_healthy);
}

// ---------------------------------------------------------------------------
// build_verification_report: rehash deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_rehash_deterministic() {
    let results = vec![make_passing_result("method:s1")];
    let r1 = build_verification_report("det", &test_epoch(), &results);
    let r2 = build_verification_report("det", &test_epoch(), &results);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// build_verification_report: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_serde_roundtrip() {
    let results = vec![
        make_passing_result("method:s1"),
        make_failing_result("method:f1", WorkloadOutcome::Timeout),
    ];
    let report = build_verification_report("serde", &test_epoch(), &results);
    let json = serde_json::to_string(&report).unwrap();
    let back: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// build_verification_report: Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_display_format() {
    let results = vec![make_passing_result("method:s1")];
    let report = build_verification_report("display-test", &test_epoch(), &results);
    let display = format!("{report}");
    assert!(display.contains("display-test"));
    assert!(display.contains("1/1"));
    assert!(display.contains("healthy=true"));
}

// ---------------------------------------------------------------------------
// build_verification_report: method_summary populated
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_method_summary_populated() {
    let results = vec![
        make_passing_result("map:s1"),
        make_passing_result("map:s2"),
        make_passing_result("filter:s1"),
    ];
    let report = build_verification_report("summary", &test_epoch(), &results);
    assert!(report.method_summary.contains_key("map"));
    assert!(report.method_summary.contains_key("filter"));
    let map_summary = &report.method_summary["map"];
    assert_eq!(map_summary.pass_count, 2);
    assert_eq!(map_summary.fail_count, 0);
}

// ---------------------------------------------------------------------------
// build_verification_report: strategy_mismatch_count
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_strategy_mismatch_counts_correctly() {
    let results = vec![
        make_failing_result("method:m1", WorkloadOutcome::Mismatch),
        make_failing_result("method:m2", WorkloadOutcome::UnexpectedFallback),
        make_failing_result("method:m3", WorkloadOutcome::Error),
        make_failing_result("method:m4", WorkloadOutcome::Timeout),
    ];
    let report = build_verification_report("mismatches", &test_epoch(), &results);
    assert_eq!(report.strategy_mismatch_count, 2);
}

// ---------------------------------------------------------------------------
// WorkloadSuite: new and add_scenario
// ---------------------------------------------------------------------------

#[test]
fn enrichment_suite_add_and_count() {
    let mut suite = WorkloadSuite::new("suite-test", "test suite");
    assert_eq!(suite.scenario_count(), 0);
    for i in 0..5 {
        suite.add_scenario(make_scenario(
            &format!("s{i}"),
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            10,
            DispatchStrategy::InlinedCallback,
        ));
    }
    assert_eq!(suite.scenario_count(), 5);
}

// ---------------------------------------------------------------------------
// WorkloadSuite: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_suite_serde_roundtrip() {
    let mut suite = WorkloadSuite::new("serde-suite", "roundtrip test");
    suite.add_scenario(make_scenario(
        "s1",
        StdlibMethod::ArrayEvery,
        CallbackKind::BuiltinFunction,
        MutationContract::ReadOnly,
        300,
        DispatchStrategy::SpecializedBuiltin,
    ));
    let json = serde_json::to_string(&suite).unwrap();
    let back: WorkloadSuite = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, back);
}

// ---------------------------------------------------------------------------
// build_canonical_pure_suite: covers all StdlibMethod variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_suite_covers_all_methods() {
    let suite = build_canonical_pure_suite();
    assert_eq!(suite.scenario_count(), StdlibMethod::ALL.len());
    let methods: BTreeSet<String> = suite
        .scenarios
        .iter()
        .map(|s| serde_json::to_string(&s.method).unwrap())
        .collect();
    assert_eq!(methods.len(), StdlibMethod::ALL.len());
}

// ---------------------------------------------------------------------------
// build_canonical_pure_suite: all use PureFunction callback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_suite_all_pure_callback() {
    let suite = build_canonical_pure_suite();
    for s in &suite.scenarios {
        assert_eq!(s.callback_kind, CallbackKind::PureFunction);
    }
}

// ---------------------------------------------------------------------------
// build_canonical_pure_suite: scenario IDs are unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_suite_unique_ids() {
    let suite = build_canonical_pure_suite();
    let ids: BTreeSet<&str> = suite
        .scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert_eq!(ids.len(), suite.scenarios.len());
}

// ---------------------------------------------------------------------------
// suite_coverage_millionths: empty suite = 0
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_empty_suite_zero() {
    let suite = WorkloadSuite::new("empty", "empty");
    assert_eq!(suite_coverage_millionths(&suite), 0);
}

// ---------------------------------------------------------------------------
// suite_coverage_millionths: canonical suite partial coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_canonical_partial() {
    let suite = build_canonical_pure_suite();
    let coverage = suite_coverage_millionths(&suite);
    let expected_fraction = 1_000_000 / CallbackKind::ALL.len() as u64;
    assert!(coverage > 0);
    assert!(coverage <= expected_fraction + 1);
}

// ---------------------------------------------------------------------------
// suite_coverage_millionths: full coverage suite
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_full_coverage() {
    let mut suite = WorkloadSuite::new("full", "all pairs");
    for method in StdlibMethod::ALL {
        for kind in CallbackKind::ALL {
            suite.add_scenario(make_scenario(
                &format!("{}:{}", method.method_name(), kind.kind_name()),
                *method,
                *kind,
                infer_mutation_contract(*method),
                100,
                DispatchStrategy::InlinedCallback,
            ));
        }
    }
    let coverage = suite_coverage_millionths(&suite);
    assert_eq!(coverage, 1_000_000);
}

// ---------------------------------------------------------------------------
// verify_trace_against_suite: matching trace produces all-pass report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_trace_matching() {
    let suite = build_canonical_pure_suite();
    let pairs: Vec<(StdlibMethod, CallbackKind)> = StdlibMethod::ALL
        .iter()
        .map(|m| (*m, CallbackKind::PureFunction))
        .collect();
    let trace = make_trace(&pairs);
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    assert_eq!(report.total_scenarios, suite.scenario_count() as u64);
    assert_eq!(report.pass_count, report.total_scenarios);
    assert!(report.is_healthy);
}

// ---------------------------------------------------------------------------
// verify_trace_against_suite: empty trace produces all-error report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_trace_empty_trace() {
    let suite = build_canonical_pure_suite();
    let trace = DispatchTrace {
        trace_id: "empty".to_string(),
        decisions: Vec::new(),
        total_cost_millionths: 0,
        inlined_count: 0,
        fallback_count: 0,
    };
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    assert_eq!(report.total_scenarios, suite.scenario_count() as u64);
    assert_eq!(report.fail_count, report.total_scenarios);
    assert!(!report.is_healthy);
}

// ---------------------------------------------------------------------------
// verify_trace_against_suite: partial trace
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_trace_partial() {
    let mut suite = WorkloadSuite::new("partial", "partial trace test");
    suite.add_scenario(make_scenario(
        "map:pure",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    ));
    suite.add_scenario(make_scenario(
        "filter:pure",
        StdlibMethod::ArrayFilter,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    ));
    let trace = make_trace(&[(StdlibMethod::ArrayMap, CallbackKind::PureFunction)]);
    let report = verify_trace_against_suite(&suite, &trace, &test_epoch());
    assert_eq!(report.total_scenarios, 2);
    assert_eq!(report.pass_count, 1);
    assert_eq!(report.fail_count, 1);
}

// ---------------------------------------------------------------------------
// franken_engine_stdlib_verification_manifest: basic properties
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_basic_properties() {
    let manifest = franken_engine_stdlib_verification_manifest();
    assert!(!manifest.report_id.is_empty());
    assert!(manifest.report_id.contains(VERIFICATION_BEAD_ID));
    assert_eq!(manifest.epoch, SecurityEpoch::from_raw(0));
    assert_eq!(manifest.total_scenarios, 0);
    assert!(manifest.is_healthy);
    assert!(!manifest.method_summary.is_empty());
}

// ---------------------------------------------------------------------------
// franken_engine_stdlib_verification_manifest: deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_deterministic() {
    let m1 = franken_engine_stdlib_verification_manifest();
    let m2 = franken_engine_stdlib_verification_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.report_id, m2.report_id);
}

// ---------------------------------------------------------------------------
// franken_engine_stdlib_verification_manifest: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let m = franken_engine_stdlib_verification_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let back: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// Constants: schema version, bead, policy, component
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_well_formed() {
    assert!(VERIFICATION_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(VERIFICATION_SCHEMA_VERSION.contains("stdlib"));
    assert!(VERIFICATION_BEAD_ID.starts_with("bd-"));
    assert_eq!(VERIFICATION_POLICY_ID, "RGC-311C");
    assert_eq!(COMPONENT, "stdlib_workload_verification");
    assert!(MIN_PASS_RATE_MILLIONTHS > 0);
    assert!(MIN_PASS_RATE_MILLIONTHS <= 1_000_000);
    assert_eq!(MAX_MUTATION_VIOLATIONS, 0);
}

// ---------------------------------------------------------------------------
// MethodVerificationSummary: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_method_summary_serde_roundtrip() {
    let mut strategy_counts = BTreeMap::new();
    strategy_counts.insert("inlined".to_string(), 5);
    strategy_counts.insert("interpreter".to_string(), 3);
    let summary = MethodVerificationSummary {
        method_name: "map".to_string(),
        pass_count: 8,
        fail_count: 0,
        avg_cost_millionths: 120_000,
        max_deopt_risk_millionths: 50_000,
        strategy_counts,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: MethodVerificationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Boundary: single result at exact threshold
// ---------------------------------------------------------------------------

#[test]
fn enrichment_boundary_exact_threshold() {
    let mut results = Vec::new();
    for i in 0..19 {
        results.push(make_passing_result(&format!("method:p{i}")));
    }
    results.push(make_failing_result("method:f0", WorkloadOutcome::Error));
    let report = build_verification_report("threshold", &test_epoch(), &results);
    assert_eq!(report.pass_rate_millionths, 950_000);
    assert!(report.is_healthy);
}

// ---------------------------------------------------------------------------
// Boundary: just below threshold
// ---------------------------------------------------------------------------

#[test]
fn enrichment_boundary_just_below_threshold() {
    let mut results = Vec::new();
    for i in 0..94 {
        results.push(make_passing_result(&format!("method:p{i}")));
    }
    for i in 0..6 {
        results.push(make_failing_result(
            &format!("method:f{i}"),
            WorkloadOutcome::Error,
        ));
    }
    let report = build_verification_report("below", &test_epoch(), &results);
    assert_eq!(report.pass_rate_millionths, 940_000);
    assert!(!report.is_healthy);
}

// ---------------------------------------------------------------------------
// MethodVerificationSummary: avg_cost computation in report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_method_summary_avg_cost() {
    let mut r1 = ScenarioResult {
        scenario_id: "map:s1".to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: DispatchStrategy::InlinedCallback,
        mutation_honored: true,
        observed_cost_millionths: 200_000,
        observed_deopt_risk_millionths: 10_000,
        details: String::new(),
        content_hash: ContentHash::compute(b""),
    };
    r1.seal();
    let mut r2 = ScenarioResult {
        scenario_id: "map:s2".to_string(),
        outcome: WorkloadOutcome::Pass,
        actual_strategy: DispatchStrategy::InlinedCallback,
        mutation_honored: true,
        observed_cost_millionths: 400_000,
        observed_deopt_risk_millionths: 20_000,
        details: String::new(),
        content_hash: ContentHash::compute(b""),
    };
    r2.seal();

    let report = build_verification_report("avg-cost", &test_epoch(), &[r1, r2]);
    let map_summary = &report.method_summary["map"];
    assert_eq!(map_summary.avg_cost_millionths, 300_000);
    assert_eq!(map_summary.max_deopt_risk_millionths, 20_000);
}

// ---------------------------------------------------------------------------
// MethodVerificationSummary: strategy distribution in report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_method_summary_strategy_counts() {
    let mut r1 = make_passing_result("reduce:s1");
    r1.actual_strategy = DispatchStrategy::InterpreterCallback;
    r1.seal();

    let mut r2 = make_passing_result("reduce:s2");
    r2.actual_strategy = DispatchStrategy::InterpreterCallback;
    r2.seal();

    let mut r3 = make_passing_result("reduce:s3");
    r3.actual_strategy = DispatchStrategy::FallbackSlow;
    r3.seal();

    let report = build_verification_report("strat-counts", &test_epoch(), &[r1, r2, r3]);
    let summary = &report.method_summary["reduce"];
    assert_eq!(summary.strategy_counts.get("interpreter"), Some(&2));
    assert_eq!(summary.strategy_counts.get("fallback-slow"), Some(&1));
}

// ---------------------------------------------------------------------------
// Hashing: scenario content hash varies by collection_size
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_hash_varies_by_collection_size() {
    let s1 = make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let s2 = make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        200,
        DispatchStrategy::InlinedCallback,
    );
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// Hashing: scenario content hash varies by callback kind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_hash_varies_by_callback_kind() {
    let s1 = make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    let s2 = make_scenario(
        "s1",
        StdlibMethod::ArrayMap,
        CallbackKind::MutatingFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InlinedCallback,
    );
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// Hashing: scenario content hash varies by mutation contract
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_hash_varies_by_contract() {
    let s1 = make_scenario(
        "s1",
        StdlibMethod::ArraySort,
        CallbackKind::PureFunction,
        MutationContract::MayMutate,
        100,
        DispatchStrategy::InterpreterCallback,
    );
    let s2 = make_scenario(
        "s1",
        StdlibMethod::ArraySort,
        CallbackKind::PureFunction,
        MutationContract::ReadOnly,
        100,
        DispatchStrategy::InterpreterCallback,
    );
    assert_ne!(s1.content_hash(), s2.content_hash());
}
