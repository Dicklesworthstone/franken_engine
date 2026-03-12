//! Enrichment integration tests for the `test_flake_quarantine_workflow` module.
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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::test_flake_quarantine_workflow::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_run(
    run_id: &str,
    epoch: u32,
    suite_kind: &str,
    scenario_id: &str,
    outcome: &str,
    error_sig: Option<&str>,
    seed: u64,
) -> FlakeRunRecord {
    FlakeRunRecord {
        run_id: run_id.to_string(),
        epoch,
        suite_kind: suite_kind.to_string(),
        scenario_id: scenario_id.to_string(),
        outcome: outcome.to_string(),
        error_signature: error_sig.map(ToString::to_string),
        replay_command_ci: format!("rch exec -- cargo test --test frx_{run_id}"),
        replay_command_local: format!("cargo test --test frx_{run_id}"),
        artifact_bundle_id: format!("bundle-{run_id}"),
        related_unit_suites: vec![format!("unit-{scenario_id}")],
        root_cause_hypothesis_artifacts: vec![format!("hyp-{scenario_id}")],
        seed,
    }
}

fn make_run_bare(
    run_id: &str,
    epoch: u32,
    suite_kind: &str,
    scenario_id: &str,
    outcome: &str,
    error_sig: Option<&str>,
    seed: u64,
) -> FlakeRunRecord {
    FlakeRunRecord {
        run_id: run_id.to_string(),
        epoch,
        suite_kind: suite_kind.to_string(),
        scenario_id: scenario_id.to_string(),
        outcome: outcome.to_string(),
        error_signature: error_sig.map(ToString::to_string),
        replay_command_ci: String::new(),
        replay_command_local: String::new(),
        artifact_bundle_id: format!("bundle-{run_id}"),
        related_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
        seed,
    }
}

fn sensitive_policy() -> FlakePolicy {
    FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 250_000,
        trend_stability_epsilon_millionths: 10_000,
    }
}

fn scenario_runs(
    suite: &str,
    scenario: &str,
    ep: u32,
    n_pass: u32,
    n_fail: u32,
    seed: u64,
) -> Vec<FlakeRunRecord> {
    let mut runs = Vec::new();
    for i in 0..n_pass {
        runs.push(make_run(
            &format!("p-{scenario}-{i}"),
            ep,
            suite,
            scenario,
            "pass",
            None,
            seed,
        ));
    }
    for i in 0..n_fail {
        runs.push(make_run(
            &format!("f-{scenario}-{i}"),
            ep,
            suite,
            scenario,
            "fail",
            Some(&format!("sig-{scenario}")),
            seed,
        ));
    }
    runs
}

fn full_pipeline(
    runs: &[FlakeRunRecord],
    policy: &FlakePolicy,
    owners: &BTreeMap<String, String>,
    current_epoch: u32,
) -> (
    Vec<FlakeClassification>,
    Vec<QuarantineRecord>,
    GateConfidenceReport,
    Vec<FlakeWorkflowEvent>,
) {
    let classifications = classify_flakes(runs, policy);
    let quarantines = build_quarantine_records(&classifications, owners, current_epoch, policy);
    let report = evaluate_gate_confidence(runs, &classifications, policy);
    let events = emit_structured_events(
        "trace-enrich",
        "decision-enrich",
        "policy-enrich-v1",
        &classifications,
        &quarantines,
        &report,
    );
    (classifications, quarantines, report, events)
}

// ===========================================================================
// Section 1: Constants contract
// ===========================================================================

#[test]
fn enrichment_constants_schema_version_contains_module_name() {
    assert!(FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION.contains("flake-quarantine-workflow"));
    assert!(FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.contains("flake-quarantine-workflow"));
}

#[test]
fn enrichment_constants_failure_code_contains_frx_20_5() {
    assert!(FLAKE_WORKFLOW_FAILURE_CODE.contains("FRX-20"));
}

#[test]
fn enrichment_constants_component_is_snake_case() {
    assert!(!FLAKE_WORKFLOW_COMPONENT.contains('-'));
    assert!(FLAKE_WORKFLOW_COMPONENT.contains('_'));
}

#[test]
fn enrichment_constants_are_not_empty() {
    assert!(!FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!FLAKE_WORKFLOW_FAILURE_CODE.is_empty());
    assert!(!FLAKE_WORKFLOW_COMPONENT.is_empty());
}

// ===========================================================================
// Section 2: FlakeSeverity serde and display
// ===========================================================================

#[test]
fn enrichment_flake_severity_clone_eq() {
    let a = FlakeSeverity::Warning;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_flake_severity_debug_format() {
    let dbg = format!("{:?}", FlakeSeverity::High);
    assert!(dbg.contains("High"));
}

#[test]
fn enrichment_flake_severity_serde_roundtrip_all_variants() {
    for severity in [FlakeSeverity::Warning, FlakeSeverity::High] {
        let json = serde_json::to_string(&severity).unwrap();
        let back: FlakeSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(severity, back);
    }
}

#[test]
fn enrichment_flake_severity_serde_json_values() {
    assert_eq!(serde_json::to_string(&FlakeSeverity::Warning).unwrap(), "\"warning\"");
    assert_eq!(serde_json::to_string(&FlakeSeverity::High).unwrap(), "\"high\"");
}

#[test]
fn enrichment_flake_severity_display_matches_as_str() {
    for severity in [FlakeSeverity::Warning, FlakeSeverity::High] {
        assert_eq!(severity.to_string(), severity.as_str());
    }
}

// ===========================================================================
// Section 3: QuarantineAction serde and display
// ===========================================================================

#[test]
fn enrichment_quarantine_action_serde_roundtrip() {
    for action in [QuarantineAction::Observe, QuarantineAction::QuarantineImmediate] {
        let json = serde_json::to_string(&action).unwrap();
        let back: QuarantineAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn enrichment_quarantine_action_kebab_case_serialization() {
    assert_eq!(
        serde_json::to_string(&QuarantineAction::QuarantineImmediate).unwrap(),
        "\"quarantine-immediate\""
    );
}

#[test]
fn enrichment_quarantine_action_display_as_str_consistency() {
    for action in [QuarantineAction::Observe, QuarantineAction::QuarantineImmediate] {
        assert_eq!(action.to_string(), action.as_str());
    }
}

#[test]
fn enrichment_quarantine_action_debug_contains_variant_name() {
    let dbg = format!("{:?}", QuarantineAction::QuarantineImmediate);
    assert!(dbg.contains("QuarantineImmediate"));
}

// ===========================================================================
// Section 4: QuarantineStatus serde
// ===========================================================================

#[test]
fn enrichment_quarantine_status_all_variants_roundtrip() {
    for status in [QuarantineStatus::Active, QuarantineStatus::Expired, QuarantineStatus::Lifted] {
        let json = serde_json::to_string(&status).unwrap();
        let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn enrichment_quarantine_status_snake_case_values() {
    assert_eq!(serde_json::to_string(&QuarantineStatus::Active).unwrap(), "\"active\"");
    assert_eq!(serde_json::to_string(&QuarantineStatus::Expired).unwrap(), "\"expired\"");
    assert_eq!(serde_json::to_string(&QuarantineStatus::Lifted).unwrap(), "\"lifted\"");
}

// ===========================================================================
// Section 5: TrendDirection serde
// ===========================================================================

#[test]
fn enrichment_trend_direction_all_variants_roundtrip() {
    for td in [TrendDirection::Improving, TrendDirection::Stable, TrendDirection::Degrading] {
        let json = serde_json::to_string(&td).unwrap();
        let back: TrendDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(td, back);
    }
}

#[test]
fn enrichment_trend_direction_snake_case_values() {
    assert_eq!(serde_json::to_string(&TrendDirection::Improving).unwrap(), "\"improving\"");
    assert_eq!(serde_json::to_string(&TrendDirection::Stable).unwrap(), "\"stable\"");
    assert_eq!(serde_json::to_string(&TrendDirection::Degrading).unwrap(), "\"degrading\"");
}

// ===========================================================================
// Section 6: FlakePolicy serde and defaults
// ===========================================================================

#[test]
fn enrichment_flake_policy_default_millionths_range() {
    let p = FlakePolicy::default();
    assert!(p.warning_flake_threshold_millionths > 0);
    assert!(p.warning_flake_threshold_millionths < p.high_flake_threshold_millionths);
    assert!(p.high_flake_threshold_millionths <= 1_000_000);
    assert!(p.max_flake_burden_millionths <= 1_000_000);
}

#[test]
fn enrichment_flake_policy_default_ttl_positive() {
    let p = FlakePolicy::default();
    assert!(p.quarantine_ttl_epochs > 0);
}

#[test]
fn enrichment_flake_policy_default_epsilon_positive() {
    let p = FlakePolicy::default();
    assert!(p.trend_stability_epsilon_millionths > 0);
}

#[test]
fn enrichment_flake_policy_serde_roundtrip() {
    let p = FlakePolicy {
        warning_flake_threshold_millionths: 10_000,
        high_flake_threshold_millionths: 200_000,
        quarantine_ttl_epochs: 5,
        max_flake_burden_millionths: 500_000,
        trend_stability_epsilon_millionths: 5_000,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: FlakePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_flake_policy_serde_all_fields_present_in_json() {
    let p = FlakePolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("warning_flake_threshold_millionths"));
    assert!(json.contains("high_flake_threshold_millionths"));
    assert!(json.contains("quarantine_ttl_epochs"));
    assert!(json.contains("max_flake_burden_millionths"));
    assert!(json.contains("trend_stability_epsilon_millionths"));
}

// ===========================================================================
// Section 7: FlakeRunRecord serde
// ===========================================================================

#[test]
fn enrichment_flake_run_record_serde_roundtrip() {
    let rec = make_run("run-serde-1", 3, "e2e", "sc-serde", "pass", None, 77);
    let json = serde_json::to_string(&rec).unwrap();
    let back: FlakeRunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_flake_run_record_with_error_sig_serde() {
    let rec = make_run("run-err", 2, "unit", "sc-err", "fail", Some("panic:oops"), 42);
    let json = serde_json::to_string(&rec).unwrap();
    let back: FlakeRunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec.error_signature, back.error_signature);
}

#[test]
fn enrichment_flake_run_record_none_error_sig_serde() {
    let rec = make_run("run-ok", 1, "e2e", "sc-ok", "pass", None, 10);
    let json = serde_json::to_string(&rec).unwrap();
    assert!(json.contains("null") || json.contains("\"error_signature\":null"));
    let back: FlakeRunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_signature, None);
}

// ===========================================================================
// Section 8: ReproducerBundle serde
// ===========================================================================

#[test]
fn enrichment_reproducer_bundle_serde_roundtrip() {
    let bundle = ReproducerBundle {
        bundle_id: "flake-repro-abc123".to_string(),
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-bundle".to_string(),
        seed: 999,
        replay_command_ci: "rch exec -- cargo test --test frx_bundle".to_string(),
        replay_command_local: "cargo test --test frx_bundle".to_string(),
        artifact_bundle_ids: vec!["art-1".to_string(), "art-2".to_string()],
        run_ids: vec!["r1".to_string(), "r2".to_string()],
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReproducerBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_reproducer_bundle_empty_lists_serde() {
    let bundle = ReproducerBundle {
        bundle_id: "flake-repro-empty".to_string(),
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-empty".to_string(),
        seed: 0,
        replay_command_ci: "rch exec -- cargo test --test frx_empty".to_string(),
        replay_command_local: "cargo test --test frx_empty".to_string(),
        artifact_bundle_ids: vec![],
        run_ids: vec![],
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReproducerBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back.artifact_bundle_ids.len(), 0);
    assert_eq!(back.run_ids.len(), 0);
}

// ===========================================================================
// Section 9: FlakeClassification serde
// ===========================================================================

#[test]
fn enrichment_flake_classification_serde_roundtrip() {
    let runs = scenario_runs("e2e", "sc-cls", 1, 1, 1, 42);
    let policy = sensitive_policy();
    let classifications = classify_flakes(&runs, &policy);
    assert!(!classifications.is_empty());
    let json = serde_json::to_string(&classifications[0]).unwrap();
    let back: FlakeClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classifications[0], back);
}

#[test]
fn enrichment_flake_classification_contains_all_fields_in_json() {
    let runs = scenario_runs("e2e", "sc-fields", 1, 2, 2, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let json = serde_json::to_string(&classifications[0]).unwrap();
    for field in [
        "suite_kind", "scenario_id", "pass_count", "fail_count",
        "flake_rate_millionths", "severity", "quarantine_action",
        "dominant_error_signature", "impacted_unit_suites",
        "root_cause_hypothesis_artifacts", "reproducer_bundle",
    ] {
        assert!(json.contains(field), "missing field {field} in JSON");
    }
}

// ===========================================================================
// Section 10: QuarantineRecord serde
// ===========================================================================

#[test]
fn enrichment_quarantine_record_serde_roundtrip() {
    let rec = QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-qr".to_string(),
        owner: "team-alpha".to_string(),
        owner_bound: true,
        opened_epoch: 10,
        expires_epoch: 13,
        status: QuarantineStatus::Active,
        reason: "high_flake_rate:e2e::sc-qr".to_string(),
        linked_reproducer_bundle_id: "flake-repro-123".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_quarantine_record_expired_status_serde() {
    let rec = QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-exp".to_string(),
        owner: "team-beta".to_string(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 8,
        status: QuarantineStatus::Expired,
        reason: "high_flake_rate:e2e::sc-exp".to_string(),
        linked_reproducer_bundle_id: "flake-repro-456".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, QuarantineStatus::Expired);
}

#[test]
fn enrichment_quarantine_record_lifted_status_serde() {
    let rec = QuarantineRecord {
        suite_kind: "unit".to_string(),
        scenario_id: "sc-lift".to_string(),
        owner: "team-gamma".to_string(),
        owner_bound: true,
        opened_epoch: 1,
        expires_epoch: 4,
        status: QuarantineStatus::Lifted,
        reason: "resolved".to_string(),
        linked_reproducer_bundle_id: "flake-repro-789".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, QuarantineStatus::Lifted);
}

// ===========================================================================
// Section 11: EpochBurdenPoint serde
// ===========================================================================

#[test]
fn enrichment_epoch_burden_point_serde_roundtrip() {
    let point = EpochBurdenPoint {
        epoch: 7,
        total_cases: 20,
        flaky_cases: 4,
        high_severity_cases: 2,
        flake_burden_millionths: 200_000,
        high_severity_burden_millionths: 100_000,
    };
    let json = serde_json::to_string(&point).unwrap();
    let back: EpochBurdenPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(point, back);
}

#[test]
fn enrichment_epoch_burden_point_zero_cases_serde() {
    let point = EpochBurdenPoint {
        epoch: 0,
        total_cases: 0,
        flaky_cases: 0,
        high_severity_cases: 0,
        flake_burden_millionths: 0,
        high_severity_burden_millionths: 0,
    };
    let json = serde_json::to_string(&point).unwrap();
    let back: EpochBurdenPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.flake_burden_millionths, 0);
}

// ===========================================================================
// Section 12: GateConfidenceReport serde
// ===========================================================================

#[test]
fn enrichment_gate_confidence_report_serde_roundtrip() {
    let report = GateConfidenceReport {
        latest_epoch: 10,
        flake_burden_millionths: 150_000,
        high_severity_flake_count: 1,
        trend_direction: TrendDirection::Improving,
        trend_delta_millionths: -50_000,
        per_epoch_burden: vec![
            EpochBurdenPoint {
                epoch: 9,
                total_cases: 10,
                flaky_cases: 3,
                high_severity_cases: 1,
                flake_burden_millionths: 300_000,
                high_severity_burden_millionths: 100_000,
            },
            EpochBurdenPoint {
                epoch: 10,
                total_cases: 10,
                flaky_cases: 2,
                high_severity_cases: 1,
                flake_burden_millionths: 200_000,
                high_severity_burden_millionths: 100_000,
            },
        ],
        promotion_outcome: "hold".to_string(),
        blockers: vec!["high_flake_rate:e2e::sc-x".to_string()],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateConfidenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_gate_confidence_report_promote_serde() {
    let report = GateConfidenceReport {
        latest_epoch: 5,
        flake_burden_millionths: 0,
        high_severity_flake_count: 0,
        trend_direction: TrendDirection::Stable,
        trend_delta_millionths: 0,
        per_epoch_burden: vec![],
        promotion_outcome: "promote".to_string(),
        blockers: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateConfidenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.promotion_outcome, "promote");
    assert!(back.blockers.is_empty());
}

// ===========================================================================
// Section 13: FlakeWorkflowEvent serde
// ===========================================================================

#[test]
fn enrichment_flake_workflow_event_serde_roundtrip() {
    let evt = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-serde".to_string(),
        decision_id: "dec-serde".to_string(),
        policy_id: "pol-serde".to_string(),
        component: FLAKE_WORKFLOW_COMPONENT.to_string(),
        event: "flake_classified".to_string(),
        outcome: "high".to_string(),
        error_code: Some(FLAKE_WORKFLOW_FAILURE_CODE.to_string()),
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-serde".to_string(),
        flake_rate_millionths: Some(500_000),
        replay_command_ci: "rch exec -- cargo test --test frx_serde".to_string(),
        replay_command_local: "cargo test --test frx_serde".to_string(),
        quarantine_owner: Some("team-serde".to_string()),
        quarantine_expires_epoch: Some(15),
        impacted_unit_suites: vec!["unit-serde".to_string()],
        root_cause_hypothesis_artifacts: vec!["hyp-serde".to_string()],
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: FlakeWorkflowEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn enrichment_flake_workflow_event_none_optionals_serde() {
    let evt = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-none".to_string(),
        decision_id: "dec-none".to_string(),
        policy_id: "pol-none".to_string(),
        component: FLAKE_WORKFLOW_COMPONENT.to_string(),
        event: "gate_confidence_evaluated".to_string(),
        outcome: "promote".to_string(),
        error_code: None,
        suite_kind: "gate".to_string(),
        scenario_id: "__gate__".to_string(),
        flake_rate_millionths: None,
        replay_command_ci: "scripts/run_frx_flake_quarantine_workflow_suite.sh ci".to_string(),
        replay_command_local: "scripts/e2e/frx_flake_quarantine_workflow_replay.sh".to_string(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: FlakeWorkflowEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, None);
    assert_eq!(back.quarantine_owner, None);
    assert_eq!(back.quarantine_expires_epoch, None);
}

// ===========================================================================
// Section 14: classify_flakes edge cases
// ===========================================================================

#[test]
fn enrichment_classify_flakes_empty_returns_empty() {
    let result = classify_flakes(&[], &FlakePolicy::default());
    assert!(result.is_empty());
}

#[test]
fn enrichment_classify_flakes_single_pass_no_flake() {
    let runs = vec![make_run("p1", 1, "e2e", "sc-only-pass", "pass", None, 1)];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert!(result.is_empty());
}

#[test]
fn enrichment_classify_flakes_single_fail_no_flake() {
    let runs = vec![make_run("f1", 1, "e2e", "sc-only-fail", "fail", Some("err"), 1)];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert!(result.is_empty());
}

#[test]
fn enrichment_classify_flakes_equal_pass_fail_high_rate() {
    // 1 pass + 1 fail => flake_rate = min(1,1)*1M/2 = 500_000
    let runs = scenario_runs("e2e", "sc-equal", 1, 1, 1, 42);
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].flake_rate_millionths, 500_000);
    assert_eq!(result[0].severity, FlakeSeverity::High);
}

#[test]
fn enrichment_classify_flakes_many_pass_one_fail_below_warning() {
    // 99 pass + 1 fail => rate = 1*1M/100 = 10_000 => below default warning 50_000
    let runs = scenario_runs("e2e", "sc-low", 1, 99, 1, 7);
    let result = classify_flakes(&runs, &FlakePolicy::default());
    assert!(result.is_empty());
}

#[test]
fn enrichment_classify_flakes_exactly_at_warning_threshold() {
    // 19 pass + 1 fail => rate = 1*1M/20 = 50_000 => exactly at default warning threshold
    let runs = scenario_runs("e2e", "sc-boundary", 1, 19, 1, 7);
    let result = classify_flakes(&runs, &FlakePolicy::default());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].flake_rate_millionths, 50_000);
    assert_eq!(result[0].severity, FlakeSeverity::Warning);
}

#[test]
fn enrichment_classify_flakes_just_below_warning_threshold() {
    // Need rate < 50_000. 20 pass + 1 fail => rate = 1*1M/21 = 47_619 => below
    let runs = scenario_runs("e2e", "sc-below", 1, 20, 1, 7);
    let result = classify_flakes(&runs, &FlakePolicy::default());
    assert!(result.is_empty());
}

#[test]
fn enrichment_classify_flakes_deterministic_across_multiple_calls() {
    let runs = scenario_runs("e2e", "sc-det", 1, 3, 3, 42);
    let policy = sensitive_policy();
    let r1 = classify_flakes(&runs, &policy);
    let r2 = classify_flakes(&runs, &policy);
    let r3 = classify_flakes(&runs, &policy);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

#[test]
fn enrichment_classify_flakes_multiple_scenarios_independent() {
    let mut runs = scenario_runs("e2e", "sc-alpha", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-beta", 1, 2, 2, 43));
    runs.extend(scenario_runs("e2e", "sc-gamma", 1, 3, 3, 44));
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result.len(), 3);
    let ids: BTreeSet<&str> = result.iter().map(|c| c.scenario_id.as_str()).collect();
    assert!(ids.contains("sc-alpha"));
    assert!(ids.contains("sc-beta"));
    assert!(ids.contains("sc-gamma"));
}

#[test]
fn enrichment_classify_flakes_same_scenario_different_suites() {
    let mut runs = scenario_runs("e2e", "sc-shared", 1, 1, 1, 42);
    runs.extend(scenario_runs("unit", "sc-shared", 1, 1, 1, 43));
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result.len(), 2);
    let suites: BTreeSet<&str> = result.iter().map(|c| c.suite_kind.as_str()).collect();
    assert!(suites.contains("e2e"));
    assert!(suites.contains("unit"));
}

#[test]
fn enrichment_classify_flakes_warning_severity_observe_action() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 600_000,
        ..FlakePolicy::default()
    };
    // 1 pass + 1 fail => rate = 500_000 => Warning (< 600k)
    let runs = scenario_runs("e2e", "sc-warn", 1, 1, 1, 10);
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result[0].severity, FlakeSeverity::Warning);
    assert_eq!(result[0].quarantine_action, QuarantineAction::Observe);
}

#[test]
fn enrichment_classify_flakes_high_severity_quarantine_immediate() {
    let policy = sensitive_policy();
    // 1 pass + 1 fail => rate = 500_000 => High (>= 100_000)
    let runs = scenario_runs("e2e", "sc-high", 1, 1, 1, 10);
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result[0].severity, FlakeSeverity::High);
    assert_eq!(result[0].quarantine_action, QuarantineAction::QuarantineImmediate);
}

#[test]
fn enrichment_classify_flakes_reproducer_bundle_populated() {
    let runs = scenario_runs("e2e", "sc-repro", 1, 2, 2, 55);
    let result = classify_flakes(&runs, &sensitive_policy());
    let bundle = &result[0].reproducer_bundle;
    assert!(bundle.bundle_id.starts_with("flake-repro-"));
    assert_eq!(bundle.suite_kind, "e2e");
    assert_eq!(bundle.scenario_id, "sc-repro");
    assert_eq!(bundle.seed, 55);
    assert!(!bundle.run_ids.is_empty());
    assert!(!bundle.artifact_bundle_ids.is_empty());
}

#[test]
fn enrichment_classify_flakes_reproducer_bundle_id_deterministic() {
    let runs = scenario_runs("e2e", "sc-det-id", 1, 2, 2, 55);
    let r1 = classify_flakes(&runs, &sensitive_policy());
    let r2 = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(r1[0].reproducer_bundle.bundle_id, r2[0].reproducer_bundle.bundle_id);
}

#[test]
fn enrichment_classify_flakes_dominant_error_sig_most_frequent() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-dsig", "pass", None, 1),
        make_run("f1", 1, "e2e", "sc-dsig", "fail", Some("sig-A"), 1),
        make_run("f2", 1, "e2e", "sc-dsig", "fail", Some("sig-A"), 1),
        make_run("f3", 1, "e2e", "sc-dsig", "fail", Some("sig-B"), 1),
    ];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result[0].dominant_error_signature, "sig-A");
}

#[test]
fn enrichment_classify_flakes_dominant_error_sig_none_when_no_sigs() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-nosig", "pass", None, 1),
        make_run("f1", 1, "e2e", "sc-nosig", "fail", None, 1),
    ];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result[0].dominant_error_signature, "none");
}

#[test]
fn enrichment_classify_flakes_impacted_suites_deduped_sorted() {
    let mut r1 = make_run("p1", 1, "e2e", "sc-dup-imp", "pass", None, 1);
    r1.related_unit_suites = vec!["unit-z".to_string(), "unit-a".to_string()];
    let mut r2 = make_run("f1", 1, "e2e", "sc-dup-imp", "fail", Some("e"), 1);
    r2.related_unit_suites = vec!["unit-a".to_string(), "unit-m".to_string()];
    let result = classify_flakes(&[r1, r2], &sensitive_policy());
    assert_eq!(result[0].impacted_unit_suites, vec!["unit-a", "unit-m", "unit-z"]);
}

#[test]
fn enrichment_classify_flakes_root_cause_artifacts_deduped() {
    let mut r1 = make_run("p1", 1, "e2e", "sc-rc-dup", "pass", None, 1);
    r1.root_cause_hypothesis_artifacts = vec!["hyp-x".to_string()];
    let mut r2 = make_run("f1", 1, "e2e", "sc-rc-dup", "fail", Some("e"), 1);
    r2.root_cause_hypothesis_artifacts = vec!["hyp-x".to_string(), "hyp-y".to_string()];
    let result = classify_flakes(&[r1, r2], &sensitive_policy());
    assert_eq!(result[0].root_cause_hypothesis_artifacts, vec!["hyp-x", "hyp-y"]);
}

#[test]
fn enrichment_classify_flakes_across_epochs_aggregated() {
    // Runs in epoch 1 and epoch 2 for the same scenario
    let mut runs = scenario_runs("e2e", "sc-cross", 1, 2, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-cross", 2, 3, 2, 42));
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result.len(), 1);
    // Total: 5 pass + 3 fail => rate = min(5,3)*1M/8 = 375_000
    assert_eq!(result[0].pass_count, 5);
    assert_eq!(result[0].fail_count, 3);
}

#[test]
fn enrichment_classify_flakes_uses_min_of_pass_fail_for_rate() {
    // 10 pass + 2 fail => rate = min(10,2)*1M/12 = 166_666
    let runs = scenario_runs("e2e", "sc-min-rate", 1, 10, 2, 42);
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result[0].flake_rate_millionths, 2 * 1_000_000 / 12);
}

#[test]
fn enrichment_classify_flakes_skips_non_pass_non_fail_outcomes() {
    // Unknown outcomes are neither pass nor fail, so they don't trigger flake
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-skip", "pass", None, 1),
        make_run("s1", 1, "e2e", "sc-skip", "skipped", None, 1),
    ];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert!(result.is_empty());
}

// ===========================================================================
// Section 15: build_quarantine_records
// ===========================================================================

#[test]
fn enrichment_build_quarantine_only_for_high_severity() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 600_000,
        ..FlakePolicy::default()
    };
    // rate = 500_000 => Warning (< 600_000)
    let runs = scenario_runs("e2e", "sc-warn-q", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert!(quarantines.is_empty());
}

#[test]
fn enrichment_build_quarantine_high_severity_creates_record() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-hq", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert_eq!(quarantines.len(), 1);
    assert_eq!(quarantines[0].opened_epoch, 5);
    assert_eq!(quarantines[0].expires_epoch, 8); // 5 + 3
    assert_eq!(quarantines[0].status, QuarantineStatus::Active);
}

#[test]
fn enrichment_build_quarantine_owner_from_case_key() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-own", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-own".to_string(), "team-alpha".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    assert_eq!(quarantines[0].owner, "team-alpha");
    assert!(quarantines[0].owner_bound);
}

#[test]
fn enrichment_build_quarantine_owner_from_scenario_id_fallback() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-fallback", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("sc-fallback".to_string(), "team-beta".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    assert_eq!(quarantines[0].owner, "team-beta");
    assert!(quarantines[0].owner_bound);
}

#[test]
fn enrichment_build_quarantine_unassigned_owner_when_missing() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-unassigned", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert_eq!(quarantines[0].owner, "unassigned");
    assert!(!quarantines[0].owner_bound);
}

#[test]
fn enrichment_build_quarantine_ttl_clamped_to_min_one() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        quarantine_ttl_epochs: 0, // would be zero, but clamped to 1
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-ttl0", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 10, &policy);
    assert_eq!(quarantines[0].expires_epoch, 11); // 10 + max(0,1) = 11
}

#[test]
fn enrichment_build_quarantine_reason_format() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-reason", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert!(quarantines[0].reason.starts_with("high_flake_rate:"));
    assert!(quarantines[0].reason.contains("e2e::sc-reason"));
}

#[test]
fn enrichment_build_quarantine_linked_reproducer_bundle_id() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-link", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert!(quarantines[0].linked_reproducer_bundle_id.starts_with("flake-repro-"));
    assert_eq!(
        quarantines[0].linked_reproducer_bundle_id,
        classifications[0].reproducer_bundle.bundle_id
    );
}

#[test]
fn enrichment_build_quarantine_multiple_high_severity() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-m1", 1, 1, 1, 10);
    runs.extend(scenario_runs("e2e", "sc-m2", 1, 1, 1, 11));
    runs.extend(scenario_runs("e2e", "sc-m3", 1, 1, 1, 12));
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert_eq!(quarantines.len(), 3);
}

// ===========================================================================
// Section 16: validate_quarantine_records
// ===========================================================================

#[test]
fn enrichment_validate_quarantine_valid_passes() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-valid".to_string(),
        owner: "team-a".to_string(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 8,
        status: QuarantineStatus::Active,
        reason: "flaky".to_string(),
        linked_reproducer_bundle_id: "b1".to_string(),
    }];
    let violations = validate_quarantine_records(&records, 6);
    assert!(violations.is_empty());
}

#[test]
fn enrichment_validate_quarantine_missing_owner_binding() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-no-owner".to_string(),
        owner: "unassigned".to_string(),
        owner_bound: false,
        opened_epoch: 5,
        expires_epoch: 8,
        status: QuarantineStatus::Active,
        reason: "flaky".to_string(),
        linked_reproducer_bundle_id: "b1".to_string(),
    }];
    let violations = validate_quarantine_records(&records, 6);
    assert!(violations.iter().any(|v| v.contains("missing_owner_binding")));
}

#[test]
fn enrichment_validate_quarantine_non_expiring() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-no-exp".to_string(),
        owner: "team-a".to_string(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 5,
        status: QuarantineStatus::Active,
        reason: "flaky".to_string(),
        linked_reproducer_bundle_id: "b1".to_string(),
    }];
    let violations = validate_quarantine_records(&records, 3);
    assert!(violations.iter().any(|v| v.contains("non_expiring_quarantine")));
}

#[test]
fn enrichment_validate_quarantine_expired_active() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-exp-act".to_string(),
        owner: "team-a".to_string(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 8,
        status: QuarantineStatus::Active,
        reason: "flaky".to_string(),
        linked_reproducer_bundle_id: "b1".to_string(),
    }];
    // current_epoch 10 > expires_epoch 8, but status is Active
    let violations = validate_quarantine_records(&records, 10);
    assert!(violations.iter().any(|v| v.contains("expired_active_quarantine")));
}

#[test]
fn enrichment_validate_quarantine_expired_status_no_expired_active_violation() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".to_string(),
        scenario_id: "sc-expired".to_string(),
        owner: "team-a".to_string(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 8,
        status: QuarantineStatus::Expired,
        reason: "flaky".to_string(),
        linked_reproducer_bundle_id: "b1".to_string(),
    }];
    let violations = validate_quarantine_records(&records, 10);
    assert!(!violations.iter().any(|v| v.contains("expired_active_quarantine")));
}

#[test]
fn enrichment_validate_quarantine_multiple_violations() {
    let records = vec![
        QuarantineRecord {
            suite_kind: "e2e".to_string(),
            scenario_id: "sc-v1".to_string(),
            owner: String::new(),
            owner_bound: false,
            opened_epoch: 5,
            expires_epoch: 8,
            status: QuarantineStatus::Active,
            reason: "flaky".to_string(),
            linked_reproducer_bundle_id: "b1".to_string(),
        },
        QuarantineRecord {
            suite_kind: "e2e".to_string(),
            scenario_id: "sc-v2".to_string(),
            owner: "team-a".to_string(),
            owner_bound: true,
            opened_epoch: 5,
            expires_epoch: 5,
            status: QuarantineStatus::Active,
            reason: "flaky".to_string(),
            linked_reproducer_bundle_id: "b2".to_string(),
        },
    ];
    let violations = validate_quarantine_records(&records, 3);
    assert!(violations.len() >= 2);
}

#[test]
fn enrichment_validate_quarantine_empty_records_no_violations() {
    let violations = validate_quarantine_records(&[], 10);
    assert!(violations.is_empty());
}

// ===========================================================================
// Section 17: validate_reproducer_replay_commands
// ===========================================================================

#[test]
fn enrichment_validate_reproducer_valid_replay_commands_pass() {
    let runs = scenario_runs("e2e", "sc-replay-ok", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.is_empty());
}

#[test]
fn enrichment_validate_reproducer_missing_ci_command() {
    let runs = scenario_runs("e2e", "sc-no-ci", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.replay_command_ci = String::new();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_ci_replay_command:")));
}

#[test]
fn enrichment_validate_reproducer_missing_local_command() {
    let runs = scenario_runs("e2e", "sc-no-local", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.replay_command_local = String::new();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_local_replay_command:")));
}

#[test]
fn enrichment_validate_reproducer_invalid_ci_no_rch_exec() {
    let runs = scenario_runs("e2e", "sc-bad-ci", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.replay_command_ci =
        "cargo test --test frx_bad_ci".to_string();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("invalid_ci_replay_command:")));
}

#[test]
fn enrichment_validate_reproducer_invalid_local_has_rch_exec() {
    let runs = scenario_runs("e2e", "sc-bad-local", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.replay_command_local =
        "rch exec -- cargo test --test frx_bad_local".to_string();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("invalid_local_replay_command:")));
}

#[test]
fn enrichment_validate_reproducer_missing_run_ids() {
    let runs = scenario_runs("e2e", "sc-no-rids", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.run_ids.clear();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_reproducer_run_ids:")));
}

#[test]
fn enrichment_validate_reproducer_missing_artifact_ids() {
    let runs = scenario_runs("e2e", "sc-no-aids", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].reproducer_bundle.artifact_bundle_ids.clear();
    let violations = validate_reproducer_replay_commands(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_reproducer_artifact_ids:")));
}

#[test]
fn enrichment_validate_reproducer_empty_classifications_no_violations() {
    let violations = validate_reproducer_replay_commands(&[]);
    assert!(violations.is_empty());
}

// ===========================================================================
// Section 18: validate_flake_linkage
// ===========================================================================

#[test]
fn enrichment_validate_linkage_valid_passes() {
    let runs = scenario_runs("e2e", "sc-link-ok", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let violations = validate_flake_linkage(&classifications);
    assert!(violations.is_empty());
}

#[test]
fn enrichment_validate_linkage_missing_impacted_suites() {
    let runs = scenario_runs("e2e", "sc-no-imp", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].impacted_unit_suites.clear();
    let violations = validate_flake_linkage(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_impacted_unit_suite_links:")));
}

#[test]
fn enrichment_validate_linkage_missing_root_cause_artifacts() {
    let runs = scenario_runs("e2e", "sc-no-rca", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].root_cause_hypothesis_artifacts.clear();
    let violations = validate_flake_linkage(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("missing_root_cause_hypothesis_artifacts:")));
}

#[test]
fn enrichment_validate_linkage_duplicate_impacted_suites() {
    let runs = scenario_runs("e2e", "sc-dup-imp", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].impacted_unit_suites =
        vec!["unit-a".to_string(), "unit-a".to_string()];
    let violations = validate_flake_linkage(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("duplicate_impacted_unit_suite_links:")));
}

#[test]
fn enrichment_validate_linkage_duplicate_root_cause_artifacts() {
    let runs = scenario_runs("e2e", "sc-dup-rca", 1, 1, 1, 42);
    let mut classifications = classify_flakes(&runs, &sensitive_policy());
    classifications[0].root_cause_hypothesis_artifacts =
        vec!["hyp-x".to_string(), "hyp-x".to_string()];
    let violations = validate_flake_linkage(&classifications);
    assert!(violations.iter().any(|v| v.starts_with("duplicate_root_cause_hypothesis_artifacts:")));
}

#[test]
fn enrichment_validate_linkage_empty_classifications_no_violations() {
    let violations = validate_flake_linkage(&[]);
    assert!(violations.is_empty());
}

// ===========================================================================
// Section 19: validate_structured_event_contract
// ===========================================================================

#[test]
fn enrichment_validate_event_contract_well_formed_pass() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-evt-ok", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-evt-ok".to_string(), "team-ok".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace-evt", "decision-evt", "policy-evt-v1",
        &classifications, &quarantines, &report,
    );
    let violations = validate_structured_event_contract(&events);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn enrichment_validate_event_contract_missing_trace_id() {
    let mut evt = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "   ".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: FLAKE_WORKFLOW_COMPONENT.to_string(),
        event: "gate_confidence_evaluated".to_string(),
        outcome: "promote".to_string(),
        error_code: None,
        suite_kind: "gate".to_string(),
        scenario_id: "__gate__".to_string(),
        flake_rate_millionths: Some(0),
        replay_command_ci: "scripts/run_frx_flake_quarantine_workflow_suite.sh ci".to_string(),
        replay_command_local: "scripts/e2e/frx_flake_quarantine_workflow_replay.sh".to_string(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
    };
    let violations = validate_structured_event_contract(&[evt.clone()]);
    assert!(violations.iter().any(|v| v.contains("missing_trace_id")));

    // Fix trace_id but break decision_id
    evt.trace_id = "trace-1".to_string();
    evt.decision_id = "".to_string();
    let violations = validate_structured_event_contract(&[evt.clone()]);
    assert!(violations.iter().any(|v| v.contains("missing_decision_id")));

    // Fix decision_id but break policy_id
    evt.decision_id = "d1".to_string();
    evt.policy_id = "".to_string();
    let violations = validate_structured_event_contract(&[evt]);
    assert!(violations.iter().any(|v| v.contains("missing_policy_id")));
}

#[test]
fn enrichment_validate_event_contract_missing_component() {
    let evt = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "".to_string(),
        event: "gate_confidence_evaluated".to_string(),
        outcome: "promote".to_string(),
        error_code: None,
        suite_kind: "gate".to_string(),
        scenario_id: "__gate__".to_string(),
        flake_rate_millionths: Some(0),
        replay_command_ci: "scripts/run_frx_flake_quarantine_workflow_suite.sh ci".to_string(),
        replay_command_local: "scripts/e2e/frx_flake_quarantine_workflow_replay.sh".to_string(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
    };
    let violations = validate_structured_event_contract(&[evt]);
    assert!(violations.iter().any(|v| v.contains("missing_component")));
}

#[test]
fn enrichment_validate_event_contract_wrong_schema_version() {
    let evt = FlakeWorkflowEvent {
        schema_version: "wrong-version".to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: FLAKE_WORKFLOW_COMPONENT.to_string(),
        event: "gate_confidence_evaluated".to_string(),
        outcome: "promote".to_string(),
        error_code: None,
        suite_kind: "gate".to_string(),
        scenario_id: "__gate__".to_string(),
        flake_rate_millionths: Some(0),
        replay_command_ci: "scripts/run_frx_flake_quarantine_workflow_suite.sh ci".to_string(),
        replay_command_local: "scripts/e2e/frx_flake_quarantine_workflow_replay.sh".to_string(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
    };
    let violations = validate_structured_event_contract(&[evt]);
    assert!(violations.iter().any(|v| v.contains("invalid_event_schema_version")));
}

#[test]
fn enrichment_validate_event_contract_invalid_ci_replay() {
    let runs = scenario_runs("e2e", "sc-bad-evt", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let report = evaluate_gate_confidence(&runs, &classifications, &sensitive_policy());
    let mut events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let evt = events.iter_mut().find(|e| e.event == "flake_classified").unwrap();
    evt.replay_command_ci = "cargo test --test frx_bad".to_string();
    let violations = validate_structured_event_contract(&events);
    assert!(violations.iter().any(|v| v.starts_with("invalid_event_replay_command_ci:")));
}

#[test]
fn enrichment_validate_event_contract_invalid_local_replay() {
    let runs = scenario_runs("e2e", "sc-bad-loc-evt", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let report = evaluate_gate_confidence(&runs, &classifications, &sensitive_policy());
    let mut events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let evt = events.iter_mut().find(|e| e.event == "flake_classified").unwrap();
    evt.replay_command_local = "rch exec -- cargo test --test frx_bad_local".to_string();
    let violations = validate_structured_event_contract(&events);
    assert!(violations.iter().any(|v| v.starts_with("invalid_event_replay_command_local:")));
}

#[test]
fn enrichment_validate_event_contract_flake_classified_missing_linkage() {
    let runs = scenario_runs("e2e", "sc-no-link-evt", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &sensitive_policy());
    let report = evaluate_gate_confidence(&runs, &classifications, &sensitive_policy());
    let mut events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let evt = events.iter_mut().find(|e| e.event == "flake_classified").unwrap();
    evt.impacted_unit_suites.clear();
    evt.root_cause_hypothesis_artifacts.clear();
    let violations = validate_structured_event_contract(&events);
    assert!(violations.iter().any(|v| v.contains("missing_event_impacted_unit_suite_links")));
    assert!(violations.iter().any(|v| v.contains("missing_event_root_cause_hypothesis_artifacts")));
}

#[test]
fn enrichment_validate_event_contract_empty_events_no_violations() {
    let violations = validate_structured_event_contract(&[]);
    assert!(violations.is_empty());
}

// ===========================================================================
// Section 20: evaluate_gate_confidence
// ===========================================================================

#[test]
fn enrichment_gate_confidence_empty_inputs_promotes() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    assert_eq!(report.latest_epoch, 0);
    assert_eq!(report.promotion_outcome, "promote");
    assert!(report.blockers.is_empty());
    assert!(report.per_epoch_burden.is_empty());
}

#[test]
fn enrichment_gate_confidence_no_flakes_promotes() {
    let runs = scenario_runs("e2e", "sc-all-pass", 1, 10, 0, 42);
    let report = evaluate_gate_confidence(&runs, &[], &FlakePolicy::default());
    assert_eq!(report.promotion_outcome, "promote");
}

#[test]
fn enrichment_gate_confidence_high_severity_blocks() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-block", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");
    assert!(report.blockers.iter().any(|b| b.contains("high_flake_rate")));
}

#[test]
fn enrichment_gate_confidence_burden_exceeds_budget_blocks() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 900_000, // high threshold so nothing is "High"
        max_flake_burden_millionths: 1, // very low budget
        ..FlakePolicy::default()
    };
    // 5 pass + 5 fail => rate = 500_000 => Warning (< 900_000)
    let runs = scenario_runs("e2e", "sc-budget", 1, 5, 5, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");
    assert!(report.blockers.iter().any(|b| b.contains("flake_burden_exceeds_budget")));
}

#[test]
fn enrichment_gate_confidence_per_epoch_burden_populated() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-ep1", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-ep2", 2, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert!(report.per_epoch_burden.len() >= 2);
    let epochs: Vec<u32> = report.per_epoch_burden.iter().map(|p| p.epoch).collect();
    assert!(epochs.contains(&1));
    assert!(epochs.contains(&2));
}

#[test]
fn enrichment_gate_confidence_trend_stable_when_same_burden() {
    // Single epoch => previous = latest => delta = 0 => Stable
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-stable", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.trend_direction, TrendDirection::Stable);
    assert_eq!(report.trend_delta_millionths, 0);
}

#[test]
fn enrichment_gate_confidence_trend_improving_when_burden_decreases() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        trend_stability_epsilon_millionths: 1,
        ..FlakePolicy::default()
    };
    // Epoch 1: 1 scenario flaky (1 pass + 1 fail) out of 1 scenario = 1_000_000
    // Epoch 2: 0 flaky (only passes) out of 1 scenario = 0
    let mut runs = scenario_runs("e2e", "sc-imp", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-imp-clean", 2, 5, 0, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    // Epoch 1 burden = 1_000_000, Epoch 2 burden = 0 => delta < 0 => Improving
    assert_eq!(report.trend_direction, TrendDirection::Improving);
    assert!(report.trend_delta_millionths < 0);
}

#[test]
fn enrichment_gate_confidence_trend_degrading_when_burden_increases() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        trend_stability_epsilon_millionths: 1,
        ..FlakePolicy::default()
    };
    // Epoch 1: 0 flaky (only passes) out of 1 scenario = 0
    // Epoch 2: 1 scenario flaky out of 1 scenario = 1_000_000
    let mut runs = scenario_runs("e2e", "sc-deg-clean", 1, 5, 0, 42);
    runs.extend(scenario_runs("e2e", "sc-deg", 2, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.trend_direction, TrendDirection::Degrading);
    assert!(report.trend_delta_millionths > 0);
}

#[test]
fn enrichment_gate_confidence_high_severity_count() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-hc1", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-hc2", 1, 1, 1, 43));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.high_severity_flake_count, 2);
}

#[test]
fn enrichment_gate_confidence_latest_epoch_matches_last_run() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-le1", 5, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-le2", 10, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.latest_epoch, 10);
}

// ===========================================================================
// Section 21: emit_structured_events
// ===========================================================================

#[test]
fn enrichment_emit_events_includes_flake_classified_and_gate_event() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-emit", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let event_names: BTreeSet<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains("flake_classified"));
    assert!(event_names.contains("gate_confidence_evaluated"));
}

#[test]
fn enrichment_emit_events_gate_event_always_last() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-last", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    assert_eq!(events.last().unwrap().event, "gate_confidence_evaluated");
}

#[test]
fn enrichment_emit_events_gate_suite_kind_is_gate() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-gk", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(gate_evt.suite_kind, "gate");
    assert_eq!(gate_evt.scenario_id, "__gate__");
}

#[test]
fn enrichment_emit_events_schema_version_set() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-sv", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    for evt in &events {
        assert_eq!(evt.schema_version, FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION);
    }
}

#[test]
fn enrichment_emit_events_component_set() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-comp", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    for evt in &events {
        assert_eq!(evt.component, FLAKE_WORKFLOW_COMPONENT);
    }
}

#[test]
fn enrichment_emit_events_trace_id_propagated() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-tid", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace-unique-42", "decision", "policy",
        &classifications, &[], &report,
    );
    for evt in &events {
        assert_eq!(evt.trace_id, "trace-unique-42");
    }
}

#[test]
fn enrichment_emit_events_policy_id_propagated() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-pid", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy-xyz-99",
        &classifications, &[], &report,
    );
    for evt in &events {
        assert_eq!(evt.policy_id, "policy-xyz-99");
    }
}

#[test]
fn enrichment_emit_events_high_severity_has_error_code() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-ec", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::High);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(flake_evt.error_code.as_deref(), Some(FLAKE_WORKFLOW_FAILURE_CODE));
}

#[test]
fn enrichment_emit_events_warning_severity_no_error_code() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 600_000,
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-warn-evt", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(flake_evt.error_code, None);
}

#[test]
fn enrichment_emit_events_quarantine_owner_populated_when_present() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-qo", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-qo".to_string(), "team-quarantine".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &quarantines, &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(flake_evt.quarantine_owner.as_deref(), Some("team-quarantine"));
    assert!(flake_evt.quarantine_expires_epoch.is_some());
}

#[test]
fn enrichment_emit_events_quarantine_none_when_no_quarantine() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-noq", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(flake_evt.quarantine_owner, None);
    assert_eq!(flake_evt.quarantine_expires_epoch, None);
}

#[test]
fn enrichment_emit_events_hold_gate_has_error_code() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-hold", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(gate_evt.error_code.as_deref(), Some(FLAKE_WORKFLOW_FAILURE_CODE));
}

#[test]
fn enrichment_emit_events_promote_gate_no_error_code() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    assert_eq!(report.promotion_outcome, "promote");
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &[], &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(gate_evt.error_code, None);
}

#[test]
fn enrichment_emit_events_gate_blockers_in_root_cause_artifacts() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-blockers", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert!(!report.blockers.is_empty());
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(gate_evt.root_cause_hypothesis_artifacts, report.blockers);
}

// ===========================================================================
// Section 22: Full pipeline integration
// ===========================================================================

#[test]
fn enrichment_full_pipeline_single_high_flake_hold() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-full", 1, 1, 1, 42);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-full".to_string(), "team-full".to_string());
    let (cls, qrs, rpt, evts) = full_pipeline(&runs, &policy, &owners, 5);
    assert_eq!(cls.len(), 1);
    assert_eq!(qrs.len(), 1);
    assert_eq!(rpt.promotion_outcome, "hold");
    // flake_classified + gate_confidence_evaluated
    assert_eq!(evts.len(), 2);
    let violations = validate_structured_event_contract(&evts);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn enrichment_full_pipeline_no_flakes_promote() {
    let policy = FlakePolicy::default();
    let runs = scenario_runs("e2e", "sc-nf", 1, 10, 0, 42);
    let (cls, qrs, rpt, evts) = full_pipeline(&runs, &policy, &BTreeMap::new(), 5);
    assert!(cls.is_empty());
    assert!(qrs.is_empty());
    assert_eq!(rpt.promotion_outcome, "promote");
    // Only gate event
    assert_eq!(evts.len(), 1);
}

#[test]
fn enrichment_full_pipeline_multiple_scenarios() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-a", 1, 1, 1, 10);
    runs.extend(scenario_runs("e2e", "sc-b", 1, 1, 1, 11));
    runs.extend(scenario_runs("unit", "sc-c", 1, 1, 1, 12));
    let (cls, qrs, rpt, evts) = full_pipeline(&runs, &policy, &BTreeMap::new(), 5);
    assert_eq!(cls.len(), 3);
    assert_eq!(qrs.len(), 3);
    assert_eq!(rpt.promotion_outcome, "hold");
    assert_eq!(rpt.high_severity_flake_count, 3);
    // 3 flake_classified + 1 gate
    assert_eq!(evts.len(), 4);
}

#[test]
fn enrichment_full_pipeline_validators_all_pass() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-val", 1, 2, 2, 42);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-val".to_string(), "team-val".to_string());
    let (cls, qrs, rpt, evts) = full_pipeline(&runs, &policy, &owners, 5);

    assert!(validate_reproducer_replay_commands(&cls).is_empty());
    assert!(validate_flake_linkage(&cls).is_empty());
    assert!(validate_quarantine_records(&qrs, 5).is_empty());
    assert!(validate_structured_event_contract(&evts).is_empty());

    // Verify report fields
    assert!(rpt.latest_epoch > 0);
    assert!(rpt.flake_burden_millionths > 0);
}

#[test]
fn enrichment_full_pipeline_decision_id_per_flake_unique() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-d1", 1, 1, 1, 10);
    runs.extend(scenario_runs("e2e", "sc-d2", 1, 1, 1, 11));
    let (_, _, _, evts) = full_pipeline(&runs, &policy, &BTreeMap::new(), 5);
    let flake_evts: Vec<&FlakeWorkflowEvent> =
        evts.iter().filter(|e| e.event == "flake_classified").collect();
    assert_eq!(flake_evts.len(), 2);
    assert_ne!(flake_evts[0].decision_id, flake_evts[1].decision_id);
}

#[test]
fn enrichment_full_pipeline_serde_roundtrip_all_events() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-serde-pipe", 1, 1, 1, 42);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-serde-pipe".to_string(), "team-serde".to_string());
    let (_, _, _, evts) = full_pipeline(&runs, &policy, &owners, 5);
    for evt in &evts {
        let json = serde_json::to_string(evt).unwrap();
        let back: FlakeWorkflowEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, &back);
    }
}

#[test]
fn enrichment_full_pipeline_serde_roundtrip_classifications() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-serde-cls", 1, 2, 2, 42);
    let (cls, _, _, _) = full_pipeline(&runs, &policy, &BTreeMap::new(), 5);
    for c in &cls {
        let json = serde_json::to_string(c).unwrap();
        let back: FlakeClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(c, &back);
    }
}

#[test]
fn enrichment_full_pipeline_serde_roundtrip_quarantine_records() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-serde-qr", 1, 1, 1, 42);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-serde-qr".to_string(), "team-qr".to_string());
    let (_, qrs, _, _) = full_pipeline(&runs, &policy, &owners, 5);
    for qr in &qrs {
        let json = serde_json::to_string(qr).unwrap();
        let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(qr, &back);
    }
}

#[test]
fn enrichment_full_pipeline_serde_roundtrip_gate_report() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-serde-rpt", 1, 1, 1, 42);
    let (_, _, rpt, _) = full_pipeline(&runs, &policy, &BTreeMap::new(), 5);
    let json = serde_json::to_string(&rpt).unwrap();
    let back: GateConfidenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(rpt, back);
}

// ===========================================================================
// Section 23: Edge cases and boundary conditions
// ===========================================================================

#[test]
fn enrichment_flake_rate_calculation_symmetry() {
    // 3 pass + 7 fail same as 7 pass + 3 fail (min is 3 in both)
    let runs_a = scenario_runs("e2e", "sc-sym-a", 1, 3, 7, 42);
    let runs_b = scenario_runs("e2e", "sc-sym-b", 1, 7, 3, 42);
    let policy = sensitive_policy();
    let cls_a = classify_flakes(&runs_a, &policy);
    let cls_b = classify_flakes(&runs_b, &policy);
    assert_eq!(cls_a[0].flake_rate_millionths, cls_b[0].flake_rate_millionths);
}

#[test]
fn enrichment_large_run_count_no_overflow() {
    // Large counts should not overflow thanks to saturating arithmetic
    let runs = scenario_runs("e2e", "sc-large", 1, 500, 500, 42);
    let policy = sensitive_policy();
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].flake_rate_millionths, 500_000);
}

#[test]
fn enrichment_quarantine_ttl_large_value() {
    let policy = FlakePolicy {
        quarantine_ttl_epochs: u32::MAX,
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-ttl-max", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 0, &policy);
    // saturating_add should prevent overflow
    assert_eq!(quarantines[0].expires_epoch, u32::MAX);
}

#[test]
fn enrichment_empty_owner_is_not_bound() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-empty-own", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-empty-own".to_string(), "   ".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    // Trimmed "   " is empty => "unassigned" behavior but owner is ""
    // Actually the code trims and checks empty, so owner would be "" and owner_bound false
    assert!(!quarantines[0].owner_bound);
}

#[test]
fn enrichment_classify_flakes_preserves_seed_in_bundle() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-seed", "pass", None, 100),
        make_run("f1", 1, "e2e", "sc-seed", "fail", Some("e"), 200),
    ];
    let result = classify_flakes(&runs, &sensitive_policy());
    // Bundle seed is min of all seeds
    assert_eq!(result[0].reproducer_bundle.seed, 100);
}

#[test]
fn enrichment_classify_flakes_bundle_seed_uses_minimum() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-min-seed", "pass", None, 999),
        make_run("f1", 1, "e2e", "sc-min-seed", "fail", Some("e"), 1),
    ];
    let result = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(result[0].reproducer_bundle.seed, 1);
}

#[test]
fn enrichment_gate_confidence_epoch_burden_total_cases_counts_unique_scenarios() {
    let policy = sensitive_policy();
    // Two different scenarios in same epoch
    let mut runs = scenario_runs("e2e", "sc-tc1", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-tc2", 1, 1, 1, 43));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert!(!report.per_epoch_burden.is_empty());
    let epoch_1 = report.per_epoch_burden.iter().find(|p| p.epoch == 1).unwrap();
    assert_eq!(epoch_1.total_cases, 2);
}

#[test]
fn enrichment_gate_confidence_blockers_sorted_deduped() {
    let policy = sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-sort1", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-sort2", 1, 1, 1, 43));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let sorted = {
        let mut b = report.blockers.clone();
        b.sort();
        b.dedup();
        b
    };
    assert_eq!(report.blockers, sorted);
}

#[test]
fn enrichment_gate_confidence_burden_millionths_fixed_point_scale() {
    let policy = sensitive_policy();
    // 1 flaky scenario out of 1 total => burden = 1_000_000
    let runs = scenario_runs("e2e", "sc-fp", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let epoch_1 = report.per_epoch_burden.iter().find(|p| p.epoch == 1).unwrap();
    assert_eq!(epoch_1.flake_burden_millionths, 1_000_000);
}

#[test]
fn enrichment_emit_events_flake_rate_in_event_matches_classification() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-rate-match", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(
        flake_evt.flake_rate_millionths,
        Some(classifications[0].flake_rate_millionths)
    );
}

#[test]
fn enrichment_emit_events_gate_flake_rate_matches_report_burden() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-gate-rate", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(
        gate_evt.flake_rate_millionths,
        Some(report.flake_burden_millionths)
    );
}

#[test]
fn enrichment_emit_events_flake_outcome_matches_severity_str() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-outcome", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert_eq!(flake_evt.outcome, classifications[0].severity.as_str());
}

#[test]
fn enrichment_emit_events_gate_outcome_matches_report() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-gate-out", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &classifications, &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert_eq!(gate_evt.outcome, report.promotion_outcome);
}

#[test]
fn enrichment_emit_events_gate_replay_ci_is_script() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &[], &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert!(gate_evt.replay_command_ci.ends_with(".sh ci"));
}

#[test]
fn enrichment_emit_events_gate_replay_local_is_script() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &[], &[], &report,
    );
    let gate_evt = events.iter().find(|e| e.event == "gate_confidence_evaluated").unwrap();
    assert!(gate_evt.replay_command_local.ends_with(".sh"));
}

#[test]
fn enrichment_emit_events_no_classifications_still_has_gate() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    let events = emit_structured_events(
        "trace", "decision", "policy",
        &[], &[], &report,
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "gate_confidence_evaluated");
}

#[test]
fn enrichment_emit_events_decision_id_for_gate_is_base_id() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    let events = emit_structured_events(
        "trace", "my-decision", "policy",
        &[], &[], &report,
    );
    assert_eq!(events[0].decision_id, "my-decision");
}

#[test]
fn enrichment_emit_events_decision_id_for_flake_includes_case_key() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-did", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events(
        "trace", "base-decision", "policy",
        &classifications, &[], &report,
    );
    let flake_evt = events.iter().find(|e| e.event == "flake_classified").unwrap();
    assert!(flake_evt.decision_id.starts_with("base-decision-"));
    assert!(flake_evt.decision_id.contains("e2e::sc-did"));
}

// ===========================================================================
// Section 24: Determinism checks
// ===========================================================================

#[test]
fn enrichment_full_pipeline_deterministic() {
    let policy = sensitive_policy();
    let runs = scenario_runs("e2e", "sc-det-full", 1, 3, 3, 42);
    let owners = BTreeMap::new();
    let (cls1, qrs1, rpt1, evts1) = full_pipeline(&runs, &policy, &owners, 5);
    let (cls2, qrs2, rpt2, evts2) = full_pipeline(&runs, &policy, &owners, 5);
    assert_eq!(cls1, cls2);
    assert_eq!(qrs1, qrs2);
    assert_eq!(rpt1, rpt2);
    assert_eq!(evts1, evts2);
}

#[test]
fn enrichment_bundle_id_deterministic_across_calls() {
    let runs = scenario_runs("e2e", "sc-bid", 1, 2, 2, 42);
    let r1 = classify_flakes(&runs, &sensitive_policy());
    let r2 = classify_flakes(&runs, &sensitive_policy());
    assert_eq!(r1[0].reproducer_bundle.bundle_id, r2[0].reproducer_bundle.bundle_id);
}

#[test]
fn enrichment_bundle_id_changes_with_different_runs() {
    let runs_a = scenario_runs("e2e", "sc-diff-a", 1, 2, 2, 42);
    let runs_b = scenario_runs("e2e", "sc-diff-b", 1, 2, 2, 42);
    let r_a = classify_flakes(&runs_a, &sensitive_policy());
    let r_b = classify_flakes(&runs_b, &sensitive_policy());
    assert_ne!(r_a[0].reproducer_bundle.bundle_id, r_b[0].reproducer_bundle.bundle_id);
}
