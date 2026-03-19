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

use frankenengine_engine::callback_stdlib_dispatch::{
    CallbackKind, DispatchStrategy, StdlibMethod,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::stdlib_workload_verification::{
    build_canonical_pure_suite, build_verification_report, check_mutation_contract,
    infer_mutation_contract, suite_coverage_millionths, MutationContract,
    MutationViolation, ScenarioResult, VerificationReport, WorkloadOutcome, WorkloadScenario,
    WorkloadSuite, COMPONENT, MAX_MUTATION_VIOLATIONS, MIN_PASS_RATE_MILLIONTHS,
    VERIFICATION_BEAD_ID, VERIFICATION_POLICY_ID, VERIFICATION_SCHEMA_VERSION,
    franken_engine_stdlib_verification_manifest,
};

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_passing_result(id: &str) -> ScenarioResult {
    let mut r = ScenarioResult {
        scenario_id: id.to_string(),
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

#[test]
fn enrichment_constants_non_empty() {
    assert!(!VERIFICATION_SCHEMA_VERSION.is_empty());
    assert!(!VERIFICATION_BEAD_ID.is_empty());
    assert!(!VERIFICATION_POLICY_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(MIN_PASS_RATE_MILLIONTHS > 0);
    assert_eq!(MAX_MUTATION_VIOLATIONS, 0);
}

#[test]
fn enrichment_mutation_contract_all_variants() {
    assert_eq!(MutationContract::ALL.len(), 4);
}

#[test]
fn enrichment_mutation_contract_display_distinct() {
    let displays: std::collections::BTreeSet<String> =
        MutationContract::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_mutation_contract_permits() {
    assert!(!MutationContract::ReadOnly.permits_in_place_mutation());
    assert!(MutationContract::MayMutate.permits_in_place_mutation());
    assert!(!MutationContract::Accumulator.permits_in_place_mutation());
    assert!(!MutationContract::SideEffectOnly.permits_in_place_mutation());
}

#[test]
fn enrichment_mutation_contract_serde() {
    for c in MutationContract::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: MutationContract = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_workload_outcome_all_variants() {
    assert_eq!(WorkloadOutcome::ALL.len(), 6);
}

#[test]
fn enrichment_workload_outcome_is_pass() {
    assert!(WorkloadOutcome::Pass.is_pass());
    assert!(!WorkloadOutcome::Mismatch.is_pass());
    assert!(!WorkloadOutcome::Error.is_pass());
    assert!(!WorkloadOutcome::Timeout.is_pass());
}

#[test]
fn enrichment_workload_outcome_is_violation() {
    assert!(WorkloadOutcome::MutationViolation.is_violation());
    assert!(WorkloadOutcome::Mismatch.is_violation());
    assert!(!WorkloadOutcome::Pass.is_violation());
}

#[test]
fn enrichment_workload_outcome_serde_all() {
    for o in WorkloadOutcome::ALL {
        let json = serde_json::to_string(o).unwrap();
        let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn enrichment_infer_contract_sort() {
    assert_eq!(infer_mutation_contract(StdlibMethod::ArraySort), MutationContract::MayMutate);
}

#[test]
fn enrichment_infer_contract_reduce() {
    assert_eq!(infer_mutation_contract(StdlibMethod::ArrayReduce), MutationContract::Accumulator);
}

#[test]
fn enrichment_infer_contract_foreach() {
    assert_eq!(infer_mutation_contract(StdlibMethod::ArrayForEach), MutationContract::SideEffectOnly);
}

#[test]
fn enrichment_infer_contract_map() {
    assert_eq!(infer_mutation_contract(StdlibMethod::ArrayMap), MutationContract::ReadOnly);
}

#[test]
fn enrichment_scenario_new_and_display() {
    let s = WorkloadScenario::new(
        "test-1", StdlibMethod::ArrayMap, CallbackKind::PureFunction,
        MutationContract::ReadOnly, 100, DispatchStrategy::InlinedCallback, "test",
    );
    assert_eq!(s.scenario_id, "test-1");
    let d = format!("{s}");
    assert!(d.contains("test-1"));
}

#[test]
fn enrichment_scenario_content_hash_deterministic() {
    let a = WorkloadScenario::new(
        "s1", StdlibMethod::ArrayFilter, CallbackKind::PureFunction,
        MutationContract::ReadOnly, 50, DispatchStrategy::InlinedCallback, "desc",
    );
    let b = a.clone();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_scenario_serde_roundtrip() {
    let s = WorkloadScenario::new(
        "s1", StdlibMethod::ArrayMap, CallbackKind::PureFunction,
        MutationContract::ReadOnly, 100, DispatchStrategy::InlinedCallback, "desc",
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: WorkloadScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_suite_new_empty() {
    let suite = WorkloadSuite::new("suite-1", "test suite");
    assert_eq!(suite.scenario_count(), 0);
}

#[test]
fn enrichment_suite_add_scenario() {
    let mut suite = WorkloadSuite::new("suite-1", "test");
    suite.add_scenario(WorkloadScenario::new(
        "s1", StdlibMethod::ArrayMap, CallbackKind::PureFunction,
        MutationContract::ReadOnly, 10, DispatchStrategy::InlinedCallback, "d",
    ));
    assert_eq!(suite.scenario_count(), 1);
}

#[test]
fn enrichment_canonical_suite_covers_all_methods() {
    let suite = build_canonical_pure_suite();
    assert_eq!(suite.scenario_count(), StdlibMethod::ALL.len());
}

#[test]
fn enrichment_canonical_suite_ids_unique() {
    let suite = build_canonical_pure_suite();
    let ids: std::collections::BTreeSet<&str> = suite.scenarios.iter().map(|s| s.scenario_id.as_str()).collect();
    assert_eq!(ids.len(), suite.scenarios.len());
}

#[test]
fn enrichment_suite_serde_roundtrip() {
    let suite = build_canonical_pure_suite();
    let json = serde_json::to_string(&suite).unwrap();
    let back: WorkloadSuite = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, back);
}

#[test]
fn enrichment_coverage_empty_suite() {
    let suite = WorkloadSuite::new("empty", "empty");
    assert_eq!(suite_coverage_millionths(&suite), 0);
}

#[test]
fn enrichment_coverage_canonical_suite() {
    let suite = build_canonical_pure_suite();
    let coverage = suite_coverage_millionths(&suite);
    assert!(coverage > 0);
    assert!(coverage < 1_000_000);
}

#[test]
fn enrichment_report_empty_results() {
    let report = build_verification_report("r1", &ep(1), &[]);
    assert_eq!(report.total_scenarios, 0);
    assert!(report.is_healthy);
}

#[test]
fn enrichment_report_all_passing() {
    let results = vec![make_passing_result("s1")];
    let report = build_verification_report("r1", &ep(1), &results);
    assert_eq!(report.pass_count, 1);
    assert_eq!(report.fail_count, 0);
    assert!(report.is_healthy);
}

#[test]
fn enrichment_report_deterministic() {
    let results = vec![make_passing_result("s1")];
    let a = build_verification_report("r1", &ep(1), &results);
    let b = build_verification_report("r1", &ep(1), &results);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let report = franken_engine_stdlib_verification_manifest();
    let json = serde_json::to_string(&report).unwrap();
    let back: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_manifest_deterministic() {
    let a = franken_engine_stdlib_verification_manifest();
    let b = franken_engine_stdlib_verification_manifest();
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_scenario_result_seal_deterministic() {
    let r1 = make_passing_result("s1");
    let r2 = make_passing_result("s1");
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_scenario_result_serde_roundtrip() {
    let r = make_passing_result("s1");
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_mutation_violation_serde() {
    let v = MutationViolation {
        scenario_id: "s1".into(),
        contract: MutationContract::ReadOnly,
        observed_mutation: "array.push".into(),
        severity: 2,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: MutationViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_check_mutation_contract_always_true() {
    for contract in MutationContract::ALL {
        assert!(check_mutation_contract(*contract, &DispatchStrategy::InlinedCallback));
    }
}
