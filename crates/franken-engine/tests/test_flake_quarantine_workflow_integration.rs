//! Integration tests for the `test_flake_quarantine_workflow` module.
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

use std::collections::BTreeMap;

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
        replay_command_ci: format!("ci-cmd-{run_id}"),
        replay_command_local: format!("local-cmd-{run_id}"),
        artifact_bundle_id: format!("bundle-{run_id}"),
        related_unit_suites: vec![format!("unit-{scenario_id}")],
        root_cause_hypothesis_artifacts: vec![format!("hyp-{scenario_id}")],
        seed,
    }
}

fn default_sensitive_policy() -> FlakePolicy {
    FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 250_000,
        trend_stability_epsilon_millionths: 10_000,
    }
}

/// Build runs producing a known flake rate for a single scenario.
/// `n_pass` pass outcomes and `n_fail` fail outcomes in epoch `ep`.
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

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn constants_schema_versions_are_v1() {
    assert!(FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION.contains("v1"));
    assert!(FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn constants_failure_code_prefix() {
    assert!(FLAKE_WORKFLOW_FAILURE_CODE.starts_with("FE-FRX-"));
}

#[test]
fn constants_component_name() {
    assert_eq!(FLAKE_WORKFLOW_COMPONENT, "frx_flake_quarantine_workflow");
}

// ===========================================================================
// Section 2: FlakeSeverity
// ===========================================================================

#[test]
fn flake_severity_as_str_values() {
    assert_eq!(FlakeSeverity::Warning.as_str(), "warning");
    assert_eq!(FlakeSeverity::High.as_str(), "high");
}

#[test]
fn flake_severity_display_matches_as_str() {
    assert_eq!(
        FlakeSeverity::Warning.to_string(),
        FlakeSeverity::Warning.as_str()
    );
    assert_eq!(
        FlakeSeverity::High.to_string(),
        FlakeSeverity::High.as_str()
    );
}

#[test]
fn flake_severity_serde_roundtrip() {
    for sev in [FlakeSeverity::Warning, FlakeSeverity::High] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: FlakeSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn flake_severity_serde_snake_case_format() {
    assert_eq!(
        serde_json::to_string(&FlakeSeverity::Warning).unwrap(),
        "\"warning\""
    );
    assert_eq!(
        serde_json::to_string(&FlakeSeverity::High).unwrap(),
        "\"high\""
    );
}

// ===========================================================================
// Section 3: QuarantineAction
// ===========================================================================

#[test]
fn quarantine_action_as_str_values() {
    assert_eq!(QuarantineAction::Observe.as_str(), "observe");
    assert_eq!(
        QuarantineAction::QuarantineImmediate.as_str(),
        "quarantine-immediate"
    );
}

#[test]
fn quarantine_action_display_matches_as_str() {
    assert_eq!(QuarantineAction::Observe.to_string(), "observe");
    assert_eq!(
        QuarantineAction::QuarantineImmediate.to_string(),
        "quarantine-immediate"
    );
}

#[test]
fn quarantine_action_serde_kebab_case() {
    assert_eq!(
        serde_json::to_string(&QuarantineAction::Observe).unwrap(),
        "\"observe\""
    );
    assert_eq!(
        serde_json::to_string(&QuarantineAction::QuarantineImmediate).unwrap(),
        "\"quarantine-immediate\""
    );
}

#[test]
fn quarantine_action_serde_roundtrip() {
    for act in [
        QuarantineAction::Observe,
        QuarantineAction::QuarantineImmediate,
    ] {
        let json = serde_json::to_string(&act).unwrap();
        let back: QuarantineAction = serde_json::from_str(&json).unwrap();
        assert_eq!(act, back);
    }
}

// ===========================================================================
// Section 4: QuarantineStatus
// ===========================================================================

#[test]
fn quarantine_status_serde_roundtrip() {
    for st in [
        QuarantineStatus::Active,
        QuarantineStatus::Expired,
        QuarantineStatus::Lifted,
    ] {
        let json = serde_json::to_string(&st).unwrap();
        let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(st, back);
    }
}

#[test]
fn quarantine_status_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&QuarantineStatus::Active).unwrap(),
        "\"active\""
    );
    assert_eq!(
        serde_json::to_string(&QuarantineStatus::Expired).unwrap(),
        "\"expired\""
    );
    assert_eq!(
        serde_json::to_string(&QuarantineStatus::Lifted).unwrap(),
        "\"lifted\""
    );
}

// ===========================================================================
// Section 5: TrendDirection
// ===========================================================================

#[test]
fn trend_direction_serde_roundtrip() {
    for td in [
        TrendDirection::Improving,
        TrendDirection::Stable,
        TrendDirection::Degrading,
    ] {
        let json = serde_json::to_string(&td).unwrap();
        let back: TrendDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(td, back);
    }
}

#[test]
fn trend_direction_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&TrendDirection::Improving).unwrap(),
        "\"improving\""
    );
    assert_eq!(
        serde_json::to_string(&TrendDirection::Stable).unwrap(),
        "\"stable\""
    );
    assert_eq!(
        serde_json::to_string(&TrendDirection::Degrading).unwrap(),
        "\"degrading\""
    );
}

// ===========================================================================
// Section 6: FlakePolicy
// ===========================================================================

#[test]
fn flake_policy_default_values() {
    let p = FlakePolicy::default();
    assert_eq!(p.warning_flake_threshold_millionths, 50_000);
    assert_eq!(p.high_flake_threshold_millionths, 300_000);
    assert_eq!(p.quarantine_ttl_epochs, 3);
    assert_eq!(p.max_flake_burden_millionths, 250_000);
    assert_eq!(p.trend_stability_epsilon_millionths, 10_000);
}

#[test]
fn flake_policy_warning_less_than_high() {
    let p = FlakePolicy::default();
    assert!(p.warning_flake_threshold_millionths < p.high_flake_threshold_millionths);
}

#[test]
fn flake_policy_serde_roundtrip() {
    let p = FlakePolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: FlakePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ===========================================================================
// Section 7: classify_flakes
// ===========================================================================

#[test]
fn classify_flakes_empty_input() {
    let result = classify_flakes(&[], &FlakePolicy::default());
    assert!(result.is_empty());
}

#[test]
fn classify_flakes_all_pass_no_flake() {
    let runs = scenario_runs("e2e", "sc-a", 1, 5, 0, 42);
    let result = classify_flakes(&runs, &default_sensitive_policy());
    assert!(result.is_empty());
}

#[test]
fn classify_flakes_all_fail_no_flake() {
    let runs = scenario_runs("e2e", "sc-a", 1, 0, 5, 42);
    let result = classify_flakes(&runs, &default_sensitive_policy());
    assert!(result.is_empty());
}

#[test]
fn classify_flakes_mixed_produces_flake() {
    // 3 pass + 2 fail => flake_rate = min(3,2)*1M/5 = 400_000
    let runs = scenario_runs("e2e", "sc-mix", 1, 3, 2, 99);
    let policy = default_sensitive_policy();
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].suite_kind, "e2e");
    assert_eq!(result[0].scenario_id, "sc-mix");
    assert_eq!(result[0].pass_count, 3);
    assert_eq!(result[0].fail_count, 2);
    assert_eq!(result[0].flake_rate_millionths, 400_000);
}

#[test]
fn classify_flakes_warning_severity_when_below_high_threshold() {
    // 2 pass + 1 fail => flake_rate = 333_333 => Warning (< 400k high)
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 400_000,
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-w", 1, 2, 1, 10);
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, FlakeSeverity::Warning);
    assert_eq!(result[0].quarantine_action, QuarantineAction::Observe);
}

#[test]
fn classify_flakes_high_severity_at_threshold() {
    // 1 pass + 1 fail => flake_rate = 500_000 => High (>= 100k)
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-h", 1, 1, 1, 10);
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, FlakeSeverity::High);
    assert_eq!(
        result[0].quarantine_action,
        QuarantineAction::QuarantineImmediate
    );
}

#[test]
fn classify_flakes_below_warning_threshold_excluded() {
    // 99 pass + 1 fail => flake_rate = 1*1M/100 = 10_000
    // warning threshold = 50_000 => excluded
    let runs = scenario_runs("e2e", "sc-low", 1, 99, 1, 7);
    let result = classify_flakes(&runs, &FlakePolicy::default());
    assert!(result.is_empty());
}

#[test]
fn classify_flakes_deterministic_repeated_calls() {
    let runs = scenario_runs("e2e", "sc-det", 1, 3, 3, 42);
    let policy = default_sensitive_policy();
    let first = classify_flakes(&runs, &policy);
    let second = classify_flakes(&runs, &policy);
    assert_eq!(first, second);
}

#[test]
fn classify_flakes_multiple_scenarios_independent() {
    let mut runs = scenario_runs("e2e", "sc-alpha", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-beta", 1, 1, 1, 43));
    let policy = default_sensitive_policy();
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 2);
    let ids: Vec<&str> = result.iter().map(|c| c.scenario_id.as_str()).collect();
    assert!(ids.contains(&"sc-alpha"));
    assert!(ids.contains(&"sc-beta"));
}

#[test]
fn classify_flakes_multiple_suite_kinds_separate() {
    let mut runs = scenario_runs("e2e", "sc-same", 1, 1, 1, 42);
    runs.extend(scenario_runs("unit", "sc-same", 1, 1, 1, 43));
    let policy = default_sensitive_policy();
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 2);
}

#[test]
fn classify_flakes_reproducer_bundle_fields() {
    let runs = scenario_runs("e2e", "sc-rb", 1, 2, 2, 55);
    let policy = default_sensitive_policy();
    let result = classify_flakes(&runs, &policy);
    assert_eq!(result.len(), 1);
    let bundle = &result[0].reproducer_bundle;
    assert!(bundle.bundle_id.starts_with("flake-repro-"));
    assert_eq!(bundle.suite_kind, "e2e");
    assert_eq!(bundle.scenario_id, "sc-rb");
    assert_eq!(bundle.seed, 55);
    assert!(!bundle.run_ids.is_empty());
    assert!(!bundle.artifact_bundle_ids.is_empty());
    assert!(!bundle.replay_command_ci.is_empty());
    assert!(!bundle.replay_command_local.is_empty());
}

#[test]
fn classify_flakes_dominant_error_signature_most_frequent() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-sig", "pass", None, 1),
        make_run("f1", 1, "e2e", "sc-sig", "fail", Some("sig-A"), 1),
        make_run("f2", 1, "e2e", "sc-sig", "fail", Some("sig-A"), 1),
        make_run("f3", 1, "e2e", "sc-sig", "fail", Some("sig-B"), 1),
    ];
    let result = classify_flakes(&runs, &default_sensitive_policy());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].dominant_error_signature, "sig-A");
}

#[test]
fn classify_flakes_dominant_error_signature_none_when_no_error_sigs() {
    let runs = vec![
        make_run("p1", 1, "e2e", "sc-no", "pass", None, 1),
        make_run("f1", 1, "e2e", "sc-no", "fail", None, 1),
    ];
    let result = classify_flakes(&runs, &default_sensitive_policy());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].dominant_error_signature, "none");
}

#[test]
fn classify_flakes_impacted_suites_deduplicated_and_sorted() {
    let mut r1 = make_run("p1", 1, "e2e", "sc-dup", "pass", None, 1);
    r1.related_unit_suites = vec!["unit-z".to_string(), "unit-a".to_string()];
    let mut r2 = make_run("f1", 1, "e2e", "sc-dup", "fail", Some("e"), 1);
    r2.related_unit_suites = vec!["unit-a".to_string(), "unit-m".to_string()];
    let result = classify_flakes(&[r1, r2], &default_sensitive_policy());
    assert_eq!(
        result[0].impacted_unit_suites,
        vec!["unit-a", "unit-m", "unit-z"]
    );
}

#[test]
fn classify_flakes_root_cause_artifacts_deduplicated() {
    let mut r1 = make_run("p1", 1, "e2e", "sc-rc", "pass", None, 1);
    r1.root_cause_hypothesis_artifacts = vec!["hyp-x".to_string()];
    let mut r2 = make_run("f1", 1, "e2e", "sc-rc", "fail", Some("e"), 1);
    r2.root_cause_hypothesis_artifacts = vec!["hyp-x".to_string(), "hyp-y".to_string()];
    let result = classify_flakes(&[r1, r2], &default_sensitive_policy());
    assert_eq!(
        result[0].root_cause_hypothesis_artifacts,
        vec!["hyp-x", "hyp-y"]
    );
}

// ===========================================================================
// Section 8: build_quarantine_records
// ===========================================================================

#[test]
fn build_quarantine_only_high_severity() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 400_000,
        ..FlakePolicy::default()
    };
    // 2 pass, 1 fail => rate=333_333 => Warning
    let runs = scenario_runs("e2e", "sc-w", 1, 2, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert!(
        quarantines.is_empty(),
        "Warning-level should not be quarantined"
    );
}

#[test]
fn build_quarantine_high_severity_creates_record() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-h", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert_eq!(quarantines.len(), 1);
    assert_eq!(quarantines[0].opened_epoch, 5);
    assert_eq!(quarantines[0].expires_epoch, 8); // 5 + 3 TTL
    assert_eq!(quarantines[0].status, QuarantineStatus::Active);
}

#[test]
fn build_quarantine_owner_from_case_key() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-own", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-own".to_string(), "quality-oncall".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
    assert_eq!(quarantines[0].owner, "quality-oncall");
    assert!(quarantines[0].owner_bound);
}

#[test]
fn build_quarantine_owner_fallback_to_scenario_id() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-fb", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("sc-fb".to_string(), "fallback-team".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
    assert_eq!(quarantines[0].owner, "fallback-team");
    assert!(quarantines[0].owner_bound);
}

#[test]
fn build_quarantine_unassigned_owner() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-un", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert_eq!(quarantines[0].owner, "unassigned");
    assert!(!quarantines[0].owner_bound);
}

#[test]
fn build_quarantine_reason_includes_case_key() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-r", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert!(quarantines[0].reason.contains("e2e::sc-r"));
    assert!(quarantines[0].reason.starts_with("high_flake_rate:"));
}

#[test]
fn build_quarantine_ttl_minimum_one() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 100_000,
        quarantine_ttl_epochs: 0, // min should be 1
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-ttl", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 5, &policy);
    assert_eq!(quarantines[0].expires_epoch, 6); // 5 + max(0,1) = 6
}

#[test]
fn build_quarantine_linked_reproducer_bundle_id() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-link", 1, 1, 1, 10);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert_eq!(
        quarantines[0].linked_reproducer_bundle_id,
        classifications[0].reproducer_bundle.bundle_id
    );
}

// ===========================================================================
// Section 9: validate_quarantine_records
// ===========================================================================

#[test]
fn validate_clean_record_no_violations() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-ok".into(),
        owner: "team-a".into(),
        owner_bound: true,
        opened_epoch: 1,
        expires_epoch: 5,
        status: QuarantineStatus::Active,
        reason: "high_flake_rate:e2e::sc-ok".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 2);
    assert!(violations.is_empty());
}

#[test]
fn validate_missing_owner_binding() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-mo".into(),
        owner: "unassigned".into(),
        owner_bound: false,
        opened_epoch: 1,
        expires_epoch: 5,
        status: QuarantineStatus::Active,
        reason: "test".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 2);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("missing_owner_binding"))
    );
}

#[test]
fn validate_non_expiring_quarantine() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-ne".into(),
        owner: "team-a".into(),
        owner_bound: true,
        opened_epoch: 5,
        expires_epoch: 5, // <= opened_epoch
        status: QuarantineStatus::Active,
        reason: "test".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 3);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("non_expiring_quarantine"))
    );
}

#[test]
fn validate_expired_active_quarantine() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-ea".into(),
        owner: "team-a".into(),
        owner_bound: true,
        opened_epoch: 1,
        expires_epoch: 4,
        status: QuarantineStatus::Active,
        reason: "test".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    // current_epoch 5 > expires_epoch 4 => violation
    let violations = validate_quarantine_records(&records, 5);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("expired_active_quarantine"))
    );
}

#[test]
fn validate_lifted_status_no_expired_active_violation() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-li".into(),
        owner: "team-a".into(),
        owner_bound: true,
        opened_epoch: 1,
        expires_epoch: 4,
        status: QuarantineStatus::Lifted,
        reason: "fixed".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 10);
    assert!(
        !violations
            .iter()
            .any(|v| v.contains("expired_active_quarantine"))
    );
}

#[test]
fn validate_expired_status_no_expired_active_violation() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-ex".into(),
        owner: "team-a".into(),
        owner_bound: true,
        opened_epoch: 1,
        expires_epoch: 4,
        status: QuarantineStatus::Expired,
        reason: "test".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 10);
    assert!(
        !violations
            .iter()
            .any(|v| v.contains("expired_active_quarantine"))
    );
}

#[test]
fn validate_multiple_violations_same_record() {
    let records = vec![QuarantineRecord {
        suite_kind: "e2e".into(),
        scenario_id: "sc-mv".into(),
        owner: String::new(),
        owner_bound: false,
        opened_epoch: 5,
        expires_epoch: 5, // non-expiring
        status: QuarantineStatus::Active,
        reason: "test".into(),
        linked_reproducer_bundle_id: "b1".into(),
    }];
    let violations = validate_quarantine_records(&records, 6);
    // missing_owner_binding, non_expiring_quarantine, expired_active_quarantine
    assert!(violations.len() >= 2);
}

#[test]
fn validate_empty_records() {
    let violations = validate_quarantine_records(&[], 10);
    assert!(violations.is_empty());
}

// ===========================================================================
// Section 10: evaluate_gate_confidence
// ===========================================================================

#[test]
fn gate_confidence_empty_inputs_defaults() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    assert_eq!(report.latest_epoch, 0);
    assert_eq!(report.flake_burden_millionths, 0);
    assert_eq!(report.high_severity_flake_count, 0);
    assert_eq!(report.promotion_outcome, "promote");
    assert!(report.blockers.is_empty());
    assert!(report.per_epoch_burden.is_empty());
}

#[test]
fn gate_confidence_no_flakes_promotes() {
    let runs = scenario_runs("e2e", "sc-clean", 1, 10, 0, 42);
    let report = evaluate_gate_confidence(&runs, &[], &FlakePolicy::default());
    assert_eq!(report.promotion_outcome, "promote");
}

#[test]
fn gate_confidence_high_flakes_block() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-block", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.contains("high_flake_rate"))
    );
}

#[test]
fn gate_confidence_burden_exceeds_budget_blocks() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 900_000,
        max_flake_burden_millionths: 0, // any burden blocks
        ..FlakePolicy::default()
    };
    let runs = scenario_runs("e2e", "sc-bud", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.contains("flake_burden_exceeds_budget"))
    );
    assert_eq!(report.promotion_outcome, "hold");
}

#[test]
fn gate_confidence_per_epoch_burden_ordered() {
    let policy = default_sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-ep", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-ep", 3, 1, 1, 42));
    runs.extend(scenario_runs("e2e", "sc-ep", 2, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.per_epoch_burden.len(), 3);
    assert_eq!(report.per_epoch_burden[0].epoch, 1);
    assert_eq!(report.per_epoch_burden[1].epoch, 2);
    assert_eq!(report.per_epoch_burden[2].epoch, 3);
}

#[test]
fn gate_confidence_latest_epoch_from_last_burden_point() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-le", 7, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.latest_epoch, 7);
}

#[test]
fn gate_confidence_trend_stable_identical_epochs() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 900_000,
        trend_stability_epsilon_millionths: 10_000,
        ..FlakePolicy::default()
    };
    // Same flake composition in both epochs => stable
    let mut runs = scenario_runs("e2e", "sc-ts", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-ts", 2, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.trend_direction, TrendDirection::Stable);
}

#[test]
fn gate_confidence_trend_improving() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 900_000,
        trend_stability_epsilon_millionths: 10_000,
        ..FlakePolicy::default()
    };
    // Epoch 1: 1 flaky case out of 1 => burden 1M
    // Epoch 2: 1 flaky case out of 2 => burden 500k
    let mut runs = scenario_runs("e2e", "sc-imp", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-imp", 2, 1, 1, 42));
    // Add a clean scenario in epoch 2 only
    runs.extend(scenario_runs("e2e", "sc-clean2", 2, 5, 0, 43));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.trend_direction, TrendDirection::Improving);
}

#[test]
fn gate_confidence_trend_degrading() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 1,
        high_flake_threshold_millionths: 900_000,
        trend_stability_epsilon_millionths: 10_000,
        ..FlakePolicy::default()
    };
    // Epoch 1: 1 flaky out of 2 => burden 500k
    // Epoch 2: 1 flaky out of 1 => burden 1M (degraded)
    let mut runs = scenario_runs("e2e", "sc-deg", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-clean3", 1, 5, 0, 43));
    runs.extend(scenario_runs("e2e", "sc-deg", 2, 1, 1, 42));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.trend_direction, TrendDirection::Degrading);
}

#[test]
fn gate_confidence_high_severity_count() {
    let policy = default_sensitive_policy();
    let mut runs = scenario_runs("e2e", "sc-hs1", 1, 1, 1, 42);
    runs.extend(scenario_runs("e2e", "sc-hs2", 1, 1, 1, 43));
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.high_severity_flake_count, 2);
}

#[test]
fn gate_confidence_single_epoch_stable_trend() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-se", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    // Single epoch: previous_burden = latest_burden => delta=0 => Stable
    assert_eq!(report.trend_direction, TrendDirection::Stable);
}

// ===========================================================================
// Section 11: emit_structured_events
// ===========================================================================

#[test]
fn emit_events_count_is_classifications_plus_one() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-ev", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &quarantines, &report);
    assert_eq!(events.len(), classifications.len() + 1);
}

#[test]
fn emit_events_last_is_gate_confidence_event() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-gate", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &[], &report);
    let gate = events.last().unwrap();
    assert_eq!(gate.event, "gate_confidence_evaluated");
    assert_eq!(gate.suite_kind, "gate");
    assert_eq!(gate.scenario_id, "__gate__");
    assert_eq!(gate.decision_id, "d1");
}

#[test]
fn emit_events_classification_event_fields() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-cf", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-cf".to_string(), "oncall".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 1, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &quarantines, &report);
    let first = &events[0];
    assert_eq!(first.event, "flake_classified");
    assert_eq!(first.schema_version, FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION);
    assert_eq!(first.component, FLAKE_WORKFLOW_COMPONENT);
    assert_eq!(first.trace_id, "t1");
    assert_eq!(first.policy_id, "p1");
    assert!(first.flake_rate_millionths.is_some());
    assert_eq!(
        first.error_code,
        Some(FLAKE_WORKFLOW_FAILURE_CODE.to_string())
    );
    assert_eq!(first.quarantine_owner, Some("oncall".to_string()));
    assert!(first.quarantine_expires_epoch.is_some());
}

#[test]
fn emit_events_warning_has_no_error_code() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 50_000,
        high_flake_threshold_millionths: 900_000,
        ..FlakePolicy::default()
    };
    // 2 pass 1 fail => rate=333_333 => Warning
    let runs = scenario_runs("e2e", "sc-we", 1, 2, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications[0].severity, FlakeSeverity::Warning);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &[], &report);
    assert_eq!(events[0].error_code, None);
}

#[test]
fn emit_events_gate_hold_has_error_code() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-gh", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &[], &report);
    let gate = events.last().unwrap();
    assert_eq!(
        gate.error_code,
        Some(FLAKE_WORKFLOW_FAILURE_CODE.to_string())
    );
}

#[test]
fn emit_events_gate_promote_no_error_code() {
    let report = evaluate_gate_confidence(&[], &[], &FlakePolicy::default());
    assert_eq!(report.promotion_outcome, "promote");
    let events = emit_structured_events("t1", "d1", "p1", &[], &[], &report);
    let gate = events.last().unwrap();
    assert_eq!(gate.error_code, None);
}

#[test]
fn emit_events_no_quarantine_match_yields_none_owner() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-nq", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    // Pass empty quarantines
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &[], &report);
    assert_eq!(events[0].quarantine_owner, None);
    assert_eq!(events[0].quarantine_expires_epoch, None);
}

#[test]
fn emit_events_decision_id_includes_case_key() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-did", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &[], &report);
    assert!(events[0].decision_id.starts_with("d1-"));
    assert!(events[0].decision_id.contains("e2e::sc-did"));
}

// ===========================================================================
// Section 12: Full workflow end-to-end
// ===========================================================================

#[test]
fn full_workflow_end_to_end_promote() {
    let policy = FlakePolicy::default();
    // All pass, no flakes
    let runs = scenario_runs("e2e", "sc-e2e", 1, 10, 0, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert!(classifications.is_empty());
    let quarantines = build_quarantine_records(&classifications, &BTreeMap::new(), 1, &policy);
    assert!(quarantines.is_empty());
    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "promote");
    let events = emit_structured_events("t1", "d1", "p1", &classifications, &quarantines, &report);
    assert_eq!(events.len(), 1); // Only gate event
    assert_eq!(events[0].outcome, "promote");
}

#[test]
fn full_workflow_end_to_end_hold_with_quarantine() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-hold", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    assert_eq!(classifications.len(), 1);
    assert_eq!(classifications[0].severity, FlakeSeverity::High);

    let mut owners = BTreeMap::new();
    owners.insert("e2e::sc-hold".to_string(), "infra-team".to_string());
    let quarantines = build_quarantine_records(&classifications, &owners, 5, &policy);
    assert_eq!(quarantines.len(), 1);
    assert_eq!(quarantines[0].owner, "infra-team");
    assert!(quarantines[0].owner_bound);

    let violations = validate_quarantine_records(&quarantines, 5);
    assert!(violations.is_empty());

    let report = evaluate_gate_confidence(&runs, &classifications, &policy);
    assert_eq!(report.promotion_outcome, "hold");

    let events = emit_structured_events("t1", "d1", "p1", &classifications, &quarantines, &report);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "flake_classified");
    assert_eq!(events[1].event, "gate_confidence_evaluated");
    assert_eq!(events[1].outcome, "hold");
}

// ===========================================================================
// Section 13: Serde roundtrips for structs
// ===========================================================================

#[test]
fn flake_run_record_serde_roundtrip() {
    let rec = make_run("r1", 5, "e2e", "sc-1", "fail", Some("sig"), 42);
    let json = serde_json::to_string(&rec).unwrap();
    let back: FlakeRunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn reproducer_bundle_serde_roundtrip() {
    let bundle = ReproducerBundle {
        bundle_id: "flake-repro-abc".into(),
        suite_kind: "e2e".into(),
        scenario_id: "sc-1".into(),
        seed: 99,
        replay_command_ci: "ci cmd".into(),
        replay_command_local: "local cmd".into(),
        artifact_bundle_ids: vec!["a1".into(), "a2".into()],
        run_ids: vec!["r1".into(), "r2".into()],
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReproducerBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn flake_classification_serde_roundtrip() {
    let policy = default_sensitive_policy();
    let runs = scenario_runs("e2e", "sc-serde", 1, 1, 1, 42);
    let classifications = classify_flakes(&runs, &policy);
    let json = serde_json::to_string(&classifications[0]).unwrap();
    let back: FlakeClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classifications[0], back);
}

#[test]
fn quarantine_record_serde_roundtrip() {
    let rec = QuarantineRecord {
        suite_kind: "unit".into(),
        scenario_id: "sc-q".into(),
        owner: "team-x".into(),
        owner_bound: true,
        opened_epoch: 2,
        expires_epoch: 5,
        status: QuarantineStatus::Active,
        reason: "high_flake_rate:unit::sc-q".into(),
        linked_reproducer_bundle_id: "b1".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn epoch_burden_point_serde_roundtrip() {
    let point = EpochBurdenPoint {
        epoch: 3,
        total_cases: 10,
        flaky_cases: 2,
        high_severity_cases: 1,
        flake_burden_millionths: 200_000,
        high_severity_burden_millionths: 100_000,
    };
    let json = serde_json::to_string(&point).unwrap();
    let back: EpochBurdenPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(point, back);
}

#[test]
fn gate_confidence_report_serde_roundtrip() {
    let report = GateConfidenceReport {
        latest_epoch: 5,
        flake_burden_millionths: 100_000,
        high_severity_flake_count: 2,
        trend_direction: TrendDirection::Degrading,
        trend_delta_millionths: 50_000,
        per_epoch_burden: vec![EpochBurdenPoint {
            epoch: 5,
            total_cases: 10,
            flaky_cases: 3,
            high_severity_cases: 1,
            flake_burden_millionths: 300_000,
            high_severity_burden_millionths: 100_000,
        }],
        promotion_outcome: "hold".into(),
        blockers: vec!["high_flake_rate:e2e::sc-1".into()],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateConfidenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn flake_workflow_event_serde_roundtrip_all_some() {
    let ev = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.into(),
        trace_id: "t2".into(),
        decision_id: "d2".into(),
        policy_id: "p2".into(),
        component: FLAKE_WORKFLOW_COMPONENT.into(),
        event: "flake_classified".into(),
        outcome: "high".into(),
        error_code: Some(FLAKE_WORKFLOW_FAILURE_CODE.into()),
        suite_kind: "unit".into(),
        scenario_id: "sc-2".into(),
        flake_rate_millionths: Some(250_000),
        replay_command_ci: "ci".into(),
        replay_command_local: "local".into(),
        quarantine_owner: Some("team-a".into()),
        quarantine_expires_epoch: Some(5),
        impacted_unit_suites: vec!["suite-a".into()],
        root_cause_hypothesis_artifacts: vec!["art-1".into()],
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: FlakeWorkflowEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn flake_workflow_event_serde_roundtrip_all_none() {
    let ev = FlakeWorkflowEvent {
        schema_version: FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.into(),
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: FLAKE_WORKFLOW_COMPONENT.into(),
        event: "gate_confidence_evaluated".into(),
        outcome: "promote".into(),
        error_code: None,
        suite_kind: "gate".into(),
        scenario_id: "__gate__".into(),
        flake_rate_millionths: None,
        replay_command_ci: "ci".into(),
        replay_command_local: "local".into(),
        quarantine_owner: None,
        quarantine_expires_epoch: None,
        impacted_unit_suites: vec![],
        root_cause_hypothesis_artifacts: vec![],
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: FlakeWorkflowEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}
