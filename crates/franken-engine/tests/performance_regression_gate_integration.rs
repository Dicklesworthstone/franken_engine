//! Integration tests for the performance regression gate (RGC-703).
//!
//! Covers: severity classification, waiver lifecycle, culprit ranking,
//! deterministic ordering, fail-closed semantics, and serde round-trips.

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

use frankenengine_engine::performance_regression_gate::{
    CulpritCandidate, PERFORMANCE_REGRESSION_GATE_COMPONENT,
    PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION, RegressionFinding, RegressionGateError,
    RegressionGateInput, RegressionGateLogEvent, RegressionGatePolicy, RegressionGateReport,
    RegressionObservation, RegressionSeverity, RegressionStatus, RegressionWaiver,
    evaluate_performance_regression_gate, write_regression_report,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_policy() -> RegressionGatePolicy {
    RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 40_000,
        critical_regression_millionths: 90_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    }
}

fn mk_obs(workload: &str, baseline: u64, observed: u64, p_value: u32) -> RegressionObservation {
    RegressionObservation::new(
        workload,
        "scenario",
        "sha256:meta",
        baseline,
        observed,
        p_value,
        Some(format!("commit-{workload}")),
    )
}

fn mk_input(
    observations: Vec<RegressionObservation>,
    waivers: Vec<RegressionWaiver>,
) -> RegressionGateInput {
    RegressionGateInput::new(
        "trace-test",
        "decision-test",
        "policy-test",
        1_700_000_000,
        observations,
        waivers,
    )
}

// ---------------------------------------------------------------------------
// No regressions
// ---------------------------------------------------------------------------

#[test]
fn no_regressions_non_blocking() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 100_000, 5_000),
            mk_obs("w-b", 100_000, 99_000, 6_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert!(!report.is_blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::None);
    assert_eq!(report.severity, RegressionSeverity::None);
    assert!(report.regressions.is_empty());
    assert!(report.culprit_ranking.is_empty());
}

#[test]
fn improvement_does_not_trigger_findings() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 80_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert!(report.regressions.is_empty());
}

// ---------------------------------------------------------------------------
// Warning severity
// ---------------------------------------------------------------------------

#[test]
fn warning_regression_does_not_block() {
    // +3% regression, above warning (2%) but below fail (4%)
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::Warning);
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Warning);
    assert_eq!(report.regressions[0].status, RegressionStatus::Active);
}

// ---------------------------------------------------------------------------
// High severity (fail threshold)
// ---------------------------------------------------------------------------

#[test]
fn high_regression_blocks() {
    // +6% regression, above fail (4%) but below critical (9%)
    let input = mk_input(vec![mk_obs("w-a", 100_000, 106_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::High);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
}

// ---------------------------------------------------------------------------
// Critical severity
// ---------------------------------------------------------------------------

#[test]
fn critical_regression_blocks() {
    // +100% regression, well above critical (9%)
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::Critical);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Critical);
}

// ---------------------------------------------------------------------------
// Zero baseline → Critical
// ---------------------------------------------------------------------------

#[test]
fn zero_baseline_is_critical() {
    let input = mk_input(vec![mk_obs("w-a", 0, 100_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Critical);
    assert!(report.regressions[0].error_code.contains("BASELINE"));
}

// ---------------------------------------------------------------------------
// Missing metadata → High
// ---------------------------------------------------------------------------

#[test]
fn missing_metadata_is_high() {
    let obs = RegressionObservation::new("w-a", "scenario", "", 100_000, 100_000, 10_000, None);
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
    assert!(report.regressions[0].error_code.contains("INTEGRITY"));
}

// ---------------------------------------------------------------------------
// Low confidence → High
// ---------------------------------------------------------------------------

#[test]
fn low_confidence_high_p_value_is_high() {
    // +3% regression with p_value > max (above warning, but p_value too high)
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 80_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
    assert!(report.regressions[0].error_code.contains("SIGNIFICANCE"));
}

// ---------------------------------------------------------------------------
// Waiver lifecycle
// ---------------------------------------------------------------------------

#[test]
fn valid_waiver_suppresses_blocking() {
    let waiver = RegressionWaiver::new(
        "waiver-1",
        "w-a",
        "oncall",
        1_800_000_000,
        "temporary jitter",
    );
    let input = mk_input(vec![mk_obs("w-a", 100_000, 160_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
    assert_eq!(report.regressions[0].waiver_id.as_deref(), Some("waiver-1"));
    assert_eq!(
        report.regressions[0].waiver_owner.as_deref(),
        Some("oncall")
    );
    assert!(report.regressions[0].message.contains("waiver-1"));
    assert!(report.culprit_ranking.is_empty());
}

#[test]
fn expired_waiver_produces_waiver_expired_finding() {
    let waiver = RegressionWaiver::new("waiver-old", "w-a", "oncall", 1_600_000_000, "expired");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 160_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    // Expired waiver creates an additional finding with WAIVER error code
    assert!(
        report
            .regressions
            .iter()
            .any(|f| f.error_code.contains("WAIVER"))
    );
}

#[test]
fn waiver_for_warning_regression_still_waives() {
    let waiver = RegressionWaiver::new("waiver-w", "w-a", "oncall", 1_800_000_000, "known");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
}

#[test]
fn waiver_for_unrelated_workload_has_no_effect() {
    let waiver = RegressionWaiver::new(
        "waiver-other",
        "w-other",
        "oncall",
        1_800_000_000,
        "different workload",
    );
    let input = mk_input(vec![mk_obs("w-a", 100_000, 160_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.regressions[0].status, RegressionStatus::Active);
}

// ---------------------------------------------------------------------------
// Culprit ranking
// ---------------------------------------------------------------------------

#[test]
fn culprit_ranking_sorted_by_score_descending() {
    let input = mk_input(
        vec![
            mk_obs("w-low", 100_000, 103_000, 10_000),
            mk_obs("w-high", 100_000, 200_000, 5_000),
            mk_obs("w-med", 100_000, 160_000, 10_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert_eq!(report.culprit_ranking.len(), 3);
    assert!(report.culprit_ranking[0].score >= report.culprit_ranking[1].score);
    assert!(report.culprit_ranking[1].score >= report.culprit_ranking[2].score);
}

#[test]
fn culprit_ranking_respects_max_culprits() {
    let policy = RegressionGatePolicy {
        max_culprits: 2,
        ..default_policy()
    };
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 200_000, 5_000),
            mk_obs("w-c", 100_000, 200_000, 5_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);

    assert_eq!(report.culprit_ranking.len(), 2);
}

#[test]
fn culprit_ranking_zero_max_produces_empty_list() {
    let policy = RegressionGatePolicy {
        max_culprits: 0,
        ..default_policy()
    };
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &policy);

    assert!(report.culprit_ranking.is_empty());
}

#[test]
fn culprit_ranks_start_at_one() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 160_000, 10_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert_eq!(report.culprit_ranking[0].rank, 1);
    assert_eq!(report.culprit_ranking[1].rank, 2);
}

#[test]
fn culprit_excludes_waived_findings() {
    let waiver = RegressionWaiver::new("waiver-1", "w-a", "oncall", 1_800_000_000, "known");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.culprit_ranking.is_empty());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_output_for_permuted_observations() {
    let policy = default_policy();
    let obs_a = vec![
        mk_obs("w-c", 100_000, 140_000, 12_000),
        mk_obs("w-a", 100_000, 130_000, 10_000),
        mk_obs("w-b", 100_000, 111_000, 20_000),
    ];
    let obs_b = vec![
        mk_obs("w-a", 100_000, 130_000, 10_000),
        mk_obs("w-b", 100_000, 111_000, 20_000),
        mk_obs("w-c", 100_000, 140_000, 12_000),
    ];

    let report_a = evaluate_performance_regression_gate(&mk_input(obs_a, Vec::new()), &policy);
    let report_b = evaluate_performance_regression_gate(&mk_input(obs_b, Vec::new()), &policy);

    assert_eq!(report_a, report_b);
}

#[test]
fn deterministic_across_repeated_runs() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 130_000, 10_000),
        ],
        Vec::new(),
    );
    let policy = default_policy();

    let reports: Vec<_> = (0..3)
        .map(|_| evaluate_performance_regression_gate(&input, &policy))
        .collect();

    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
}

// ---------------------------------------------------------------------------
// Report structure
// ---------------------------------------------------------------------------

#[test]
fn report_has_expected_metadata() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert_eq!(
        report.schema_version,
        PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION
    );
    assert_eq!(report.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
    assert_eq!(report.trace_id, "trace-test");
    assert_eq!(report.decision_id, "decision-test");
    assert_eq!(report.policy_id, "policy-test");
}

#[test]
fn log_events_contain_gate_decision() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.logs.iter().any(|l| l.event == "gate_decision"));
}

#[test]
fn blocking_report_gate_decision_is_hold() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    let gate_log = report
        .logs
        .iter()
        .find(|l| l.event == "gate_decision")
        .unwrap();
    assert_eq!(gate_log.outcome, "hold");
}

#[test]
fn non_blocking_report_gate_decision_is_promote() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    let gate_log = report
        .logs
        .iter()
        .find(|l| l.event == "gate_decision")
        .unwrap();
    assert_eq!(gate_log.outcome, "promote");
}

#[test]
fn finding_with_commit_id_propagated() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert_eq!(
        report.regressions[0].commit_id.as_deref(),
        Some("commit-w-a")
    );
    assert_eq!(
        report.culprit_ranking[0].commit_id.as_deref(),
        Some("commit-w-a")
    );
}

// ---------------------------------------------------------------------------
// Write report
// ---------------------------------------------------------------------------

#[test]
fn write_and_read_back_report() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 160_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    let path = std::env::temp_dir().join("prg_integration_report.json");
    write_regression_report(&report, &path).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let restored: RegressionGateReport = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report, restored);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn write_to_nonexistent_dir_fails() {
    let input = mk_input(vec![], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    let result = write_regression_report(&report, "/nonexistent/dir/report.json");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[test]
fn serialization_error_stable_code() {
    let err = RegressionGateError::Serialization("test".into());
    assert_eq!(err.stable_code(), "FE-RGC-703-SERIALIZATION-0007");
    assert!(err.to_string().contains("serialization failed"));
}

#[test]
fn report_write_error_stable_code() {
    let err = RegressionGateError::ReportWrite {
        path: "/tmp/test".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert_eq!(err.stable_code(), "FE-RGC-703-REPORT-0008");
    assert!(err.to_string().contains("report write failed"));
}

// ---------------------------------------------------------------------------
// Enum Display and ordering
// ---------------------------------------------------------------------------

#[test]
fn severity_display_all_variants() {
    assert_eq!(RegressionSeverity::None.as_str(), "none");
    assert_eq!(RegressionSeverity::Warning.as_str(), "warning");
    assert_eq!(RegressionSeverity::High.as_str(), "high");
    assert_eq!(RegressionSeverity::Critical.as_str(), "critical");
    assert_eq!(format!("{}", RegressionSeverity::Critical), "critical");
}

#[test]
fn severity_ordering() {
    assert!(RegressionSeverity::None < RegressionSeverity::Warning);
    assert!(RegressionSeverity::Warning < RegressionSeverity::High);
    assert!(RegressionSeverity::High < RegressionSeverity::Critical);
}

#[test]
fn status_display_all_variants() {
    assert_eq!(RegressionStatus::Active.as_str(), "active");
    assert_eq!(RegressionStatus::Waived.as_str(), "waived");
    assert_eq!(format!("{}", RegressionStatus::Waived), "waived");
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

#[test]
fn default_policy_has_sensible_thresholds() {
    let policy = RegressionGatePolicy::default();
    assert!(policy.warning_regression_millionths < policy.fail_regression_millionths);
    assert!(policy.fail_regression_millionths < policy.critical_regression_millionths);
    assert!(policy.max_p_value_millionths > 0);
    assert!(policy.max_culprits > 0);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn input_serde_roundtrip() {
    let input = mk_input(
        vec![mk_obs("w-a", 100_000, 160_000, 10_000)],
        vec![RegressionWaiver::new(
            "w-1",
            "w-a",
            "oncall",
            1_800_000_000,
            "test",
        )],
    );
    let json = serde_json::to_string(&input).unwrap();
    let back: RegressionGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn observation_serde_roundtrip() {
    let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
    let json = serde_json::to_string(&obs).unwrap();
    let back: RegressionObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn waiver_serde_roundtrip() {
    let waiver = RegressionWaiver::new("w-1", "w-a", "oncall", 1_800_000_000, "test");
    let json = serde_json::to_string(&waiver).unwrap();
    let back: RegressionWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(waiver, back);
}

#[test]
fn policy_serde_roundtrip() {
    let policy = default_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: RegressionGatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn report_serde_roundtrip() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 103_000, 10_000),
        ],
        vec![RegressionWaiver::new(
            "w-1",
            "w-b",
            "oncall",
            1_800_000_000,
            "test",
        )],
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    let json = serde_json::to_string(&report).unwrap();
    let back: RegressionGateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn finding_serde_roundtrip() {
    let finding = RegressionFinding {
        workload_id: "w-a".to_string(),
        scenario_id: "scenario".to_string(),
        severity: RegressionSeverity::High,
        status: RegressionStatus::Active,
        regression_millionths: 60_000,
        p_value_millionths: 10_000,
        error_code: "FE-RGC-703-REGRESSION-0005".to_string(),
        message: "regression".to_string(),
        waiver_id: None,
        waiver_owner: None,
        waiver_expires_at_unix_seconds: None,
        commit_id: Some("commit-a".to_string()),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: RegressionFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn culprit_candidate_serde_roundtrip() {
    let candidate = CulpritCandidate {
        rank: 1,
        workload_id: "w-a".to_string(),
        severity: RegressionSeverity::Critical,
        score: 3_100_000_000,
        regression_millionths: 100_000,
        p_value_millionths: 5_000,
        error_codes: vec!["FE-RGC-703-REGRESSION-0004".to_string()],
        commit_id: Some("commit-a".to_string()),
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let back: CulpritCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(candidate, back);
}

#[test]
fn log_event_serde_roundtrip() {
    let event = RegressionGateLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: PERFORMANCE_REGRESSION_GATE_COMPONENT.to_string(),
        event: "gate_decision".to_string(),
        outcome: "promote".to_string(),
        error_code: None,
        workload_id: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegressionGateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_observations_non_blocking() {
    let input = mk_input(Vec::new(), Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(!report.blocking);
    assert!(report.regressions.is_empty());
    assert!(report.culprit_ranking.is_empty());
}

#[test]
fn multiple_findings_per_workload_accumulate_in_culprit() {
    // Same workload with two different scenarios
    let obs1 = RegressionObservation::new(
        "w-a",
        "scenario-1",
        "sha256:meta1",
        100_000,
        200_000,
        5_000,
        Some("commit-a".to_string()),
    );
    let obs2 = RegressionObservation::new(
        "w-a",
        "scenario-2",
        "sha256:meta2",
        100_000,
        160_000,
        10_000,
        Some("commit-a".to_string()),
    );
    let input = mk_input(vec![obs1, obs2], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert_eq!(report.regressions.len(), 2);
    // Culprit ranking collapses to one entry for w-a
    assert_eq!(report.culprit_ranking.len(), 1);
    assert_eq!(report.culprit_ranking[0].workload_id, "w-a");
}

#[test]
fn constant_values() {
    assert_eq!(
        PERFORMANCE_REGRESSION_GATE_COMPONENT,
        "performance_regression_gate"
    );
    assert!(PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION.contains("v1"));
}

// ---------------------------------------------------------------------------
// Mixed scenarios
// ---------------------------------------------------------------------------

#[test]
fn mixed_severity_takes_highest() {
    let input = mk_input(
        vec![
            mk_obs("w-warn", 100_000, 103_000, 10_000), // warning
            mk_obs("w-crit", 100_000, 200_000, 5_000),  // critical
            mk_obs("w-pass", 100_000, 100_000, 50_000), // pass
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());

    assert!(report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::Critical);
}
