//! Integration tests for the performance statistical validation pipeline (RGC-702).
//!
//! Validates the full pipeline: input construction → warmup trim → outlier filtering →
//! statistical analysis → verdict/promotion decisions → report serialization.

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

use frankenengine_engine::performance_statistical_validation::{
    ConfidenceIntervalNs, FindingCode, OutlierPolicy, OutlierSummary,
    PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT, SampleStatsNs, StatisticalThresholds,
    StatisticalValidationError, StatisticalValidationInput, StatisticalValidationLogEvent,
    StatisticalValidationPolicy, StatisticalValidationReport, ValidationFinding, WorkloadOutcome,
    WorkloadSamples, WorkloadValidationVerdict, evaluate_statistical_validation,
    write_stats_verdict_report,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn permissive_policy() -> StatisticalValidationPolicy {
    StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 500_000,
            warning_regression_millionths: 100_000,
            fail_regression_millionths: 200_000,
            max_p_value_millionths: 999_999,
            min_effect_size_millionths: 100_000,
            confidence_level_millionths: 950_000,
        },
    }
}

fn strict_policy() -> StatisticalValidationPolicy {
    StatisticalValidationPolicy {
        warmup_drop_samples: 1,
        min_samples_after_filter: 8,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 3_000_000,
            min_retained_samples: 8,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 80_000,
            warning_regression_millionths: 10_000,
            fail_regression_millionths: 25_000,
            max_p_value_millionths: 50_000,
            min_effect_size_millionths: 5_000,
            confidence_level_millionths: 950_000,
        },
    }
}

fn stable_workload() -> WorkloadSamples {
    WorkloadSamples::new(
        "router_hot_path",
        "golden",
        "sha256:router-hot-path-abc123",
        vec![1000, 1002, 998, 1001, 999, 1000, 1001, 999, 1000, 1001],
        vec![1001, 1003, 997, 1000, 1001, 999, 1002, 998, 1001, 1000],
    )
}

fn regressing_workload() -> WorkloadSamples {
    // ~30% regression: baseline ~1000, candidate ~1300
    WorkloadSamples::new(
        "gc_hot_path",
        "regression",
        "sha256:gc-hot-path",
        vec![1000, 1002, 998, 1001, 999, 1000, 1001, 999, 1000, 1001],
        vec![1300, 1302, 1298, 1301, 1299, 1300, 1301, 1299, 1300, 1301],
    )
}

// ---------------------------------------------------------------------------
// Full pipeline
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_single_stable_workload_passes() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new(
        "trace-full-01",
        "decision-full-01",
        "policy-permissive",
        vec![stable_workload()],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
    assert_eq!(report.trace_id, "trace-full-01");
    assert_eq!(report.decision_id, "decision-full-01");
    assert_eq!(report.policy_id, "policy-permissive");
    assert_eq!(
        report.component,
        PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT
    );
    assert_eq!(report.verdicts.len(), 1);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Pass);
    assert!(report.failed_workloads.is_empty());
    assert!(report.quarantined_workloads.is_empty());
}

#[test]
fn full_pipeline_multiple_workloads_all_pass() {
    let policy = permissive_policy();
    let mut w2 = stable_workload();
    w2.workload_id = "scheduler_path".to_string();
    w2.scenario_id = "stable_2".to_string();

    let input = StatisticalValidationInput::new(
        "trace-multi",
        "decision-multi",
        "policy-multi",
        vec![stable_workload(), w2],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
    assert_eq!(report.verdicts.len(), 2);
    assert!(
        report
            .verdicts
            .iter()
            .all(|v| v.outcome == WorkloadOutcome::Pass)
    );
}

#[test]
fn full_pipeline_one_failure_blocks_promotion() {
    let policy = strict_policy();
    let mut bad = stable_workload();
    bad.workload_id = "bad_workload".to_string();
    bad.benchmark_metadata_hash.clear();

    let input = StatisticalValidationInput::new(
        "trace-mixed",
        "decision-mixed",
        "policy-strict",
        vec![stable_workload(), bad],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert!(
        report
            .failed_workloads
            .contains(&"bad_workload".to_string())
    );
}

// ---------------------------------------------------------------------------
// Regression detection
// ---------------------------------------------------------------------------

#[test]
fn regression_above_fail_threshold_fails() {
    let policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 500_000,
            warning_regression_millionths: 10_000,
            fail_regression_millionths: 25_000,
            max_p_value_millionths: 999_999,
            min_effect_size_millionths: 1_000,
            confidence_level_millionths: 950_000,
        },
    };

    let input = StatisticalValidationInput::new(
        "trace-regression",
        "decision-regression",
        "policy-regression",
        vec![regressing_workload()],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    let verdict = &report.verdicts[0];
    assert_eq!(verdict.outcome, WorkloadOutcome::Fail);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.code == FindingCode::RegressionFail)
    );
    assert!(verdict.effect_size_millionths > 0);
}

#[test]
fn regression_above_warn_but_below_fail_warns() {
    // ~2% regression with tight thresholds
    let policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 500_000,
            warning_regression_millionths: 10_000, // 1%
            fail_regression_millionths: 50_000,    // 5%
            max_p_value_millionths: 999_999,
            min_effect_size_millionths: 1_000,
            confidence_level_millionths: 950_000,
        },
    };

    let workload = WorkloadSamples::new(
        "warn_path",
        "warn_scenario",
        "sha256:warn",
        vec![1000, 1002, 998, 1001, 999, 1000, 1001, 999, 1000, 1001],
        vec![1020, 1022, 1018, 1021, 1019, 1020, 1021, 1019, 1020, 1021],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Warn);
    assert!(report.warned_workloads.contains(&"warn_path".to_string()));
    assert!(report.promote_allowed, "warns should not block promotion");
}

// ---------------------------------------------------------------------------
// Variance quarantine
// ---------------------------------------------------------------------------

#[test]
fn high_variance_workload_quarantined() {
    let policy = strict_policy();
    let workload = WorkloadSamples::new(
        "noisy_path",
        "variance_test",
        "sha256:noisy",
        vec![500, 1500, 600, 1400, 700, 1300, 800, 1200, 550, 1450],
        vec![510, 1490, 610, 1390, 710, 1290, 810, 1190, 560, 1440],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Quarantine);
    assert!(
        report
            .quarantined_workloads
            .contains(&"noisy_path".to_string())
    );
    assert!(
        report.verdicts[0]
            .findings
            .iter()
            .any(|f| f.code == FindingCode::VarianceQuarantine)
    );
}

// ---------------------------------------------------------------------------
// Missing metadata
// ---------------------------------------------------------------------------

#[test]
fn empty_metadata_hash_fails_closed() {
    let policy = permissive_policy();
    let mut workload = stable_workload();
    workload.benchmark_metadata_hash = String::new();

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
    assert!(
        report.verdicts[0]
            .findings
            .iter()
            .any(|f| f.code == FindingCode::MissingBenchmarkMetadata)
    );
}

#[test]
fn whitespace_only_metadata_hash_fails_closed() {
    let policy = permissive_policy();
    let mut workload = stable_workload();
    workload.benchmark_metadata_hash = "   ".to_string();

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
}

// ---------------------------------------------------------------------------
// Insufficient samples
// ---------------------------------------------------------------------------

#[test]
fn too_few_samples_fails_closed() {
    let policy = strict_policy();
    let workload = WorkloadSamples::new(
        "tiny",
        "test",
        "sha256:tiny",
        vec![100, 200],
        vec![100, 200],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
    assert!(
        report.verdicts[0]
            .findings
            .iter()
            .any(|f| f.code == FindingCode::InsufficientSamples)
    );
}

// ---------------------------------------------------------------------------
// Outlier filtering
// ---------------------------------------------------------------------------

#[test]
fn single_spike_outlier_removed_from_candidate() {
    let policy = strict_policy();
    let workload = WorkloadSamples::new(
        "outlier_test",
        "spike",
        "sha256:outlier",
        vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 1000, 1001, 1000],
        vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 1000, 1001, 50_000],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(
        report.verdicts[0].outliers.candidate_removed >= 1,
        "spike outlier should be removed from candidate"
    );
    assert_eq!(report.verdicts[0].outliers.method, "mad");
}

// ---------------------------------------------------------------------------
// Workload ordering (deterministic)
// ---------------------------------------------------------------------------

#[test]
fn workloads_sorted_by_id_in_verdicts() {
    let policy = permissive_policy();
    let mut w_z = stable_workload();
    w_z.workload_id = "zzz_last".to_string();
    let mut w_a = stable_workload();
    w_a.workload_id = "aaa_first".to_string();
    let mut w_m = stable_workload();
    w_m.workload_id = "mmm_middle".to_string();

    // Insert out of order
    let input = StatisticalValidationInput::new("t", "d", "p", vec![w_z, w_a, w_m]);
    let report = evaluate_statistical_validation(&input, &policy);

    let ids: Vec<&str> = report
        .verdicts
        .iter()
        .map(|v| v.workload_id.as_str())
        .collect();
    assert_eq!(ids, vec!["aaa_first", "mmm_middle", "zzz_last"]);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_across_repeated_evaluations() {
    let policy = strict_policy();
    let input = StatisticalValidationInput::new(
        "trace-det",
        "decision-det",
        "policy-det",
        vec![stable_workload(), regressing_workload()],
    );

    let reports: Vec<_> = (0..3)
        .map(|_| evaluate_statistical_validation(&input, &policy))
        .collect();

    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
}

// ---------------------------------------------------------------------------
// Log events
// ---------------------------------------------------------------------------

#[test]
fn logs_contain_one_event_per_workload() {
    let policy = permissive_policy();
    let mut w2 = stable_workload();
    w2.workload_id = "second_workload".to_string();

    let input = StatisticalValidationInput::new(
        "trace-logs",
        "decision-logs",
        "policy-logs",
        vec![stable_workload(), w2],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.logs.len(), 2);
    for log in &report.logs {
        assert_eq!(log.event, "workload_evaluated");
        assert_eq!(log.component, PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT);
        assert_eq!(log.trace_id, "trace-logs");
        assert_eq!(log.decision_id, "decision-logs");
        assert_eq!(log.policy_id, "policy-logs");
    }
}

#[test]
fn log_error_code_present_for_failures() {
    let policy = permissive_policy();
    let mut bad = stable_workload();
    bad.benchmark_metadata_hash.clear();

    let input = StatisticalValidationInput::new("t", "d", "p", vec![bad]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.logs[0].error_code.is_some());
}

#[test]
fn log_error_code_absent_for_pass() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.logs[0].error_code.is_none());
}

// ---------------------------------------------------------------------------
// Verdict structure
// ---------------------------------------------------------------------------

#[test]
fn verdict_has_baseline_and_candidate_stats() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let verdict = &report.verdicts[0];
    assert!(verdict.baseline.sample_count > 0);
    assert!(verdict.candidate.sample_count > 0);
    assert!(verdict.baseline.mean_ns > 0);
    assert!(verdict.candidate.mean_ns > 0);
}

#[test]
fn verdict_confidence_interval_well_ordered() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let ci = &report.verdicts[0].confidence_interval_mean_delta_ns;
    assert!(ci.lower_ns <= ci.upper_ns);
}

#[test]
fn verdict_p_value_in_valid_range() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let p = report.verdicts[0].p_value_millionths;
    assert!(p <= 1_000_000, "p-value should be <= 1.0 (in millionths)");
}

// ---------------------------------------------------------------------------
// Write report to disk
// ---------------------------------------------------------------------------

#[test]
fn write_and_read_back_report() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new(
        "trace-disk",
        "decision-disk",
        "policy-disk",
        vec![stable_workload()],
    );
    let report = evaluate_statistical_validation(&input, &policy);

    let temp_path = std::env::temp_dir().join("franken_engine_psv_integration_report.json");

    write_stats_verdict_report(&report, &temp_path).expect("write should succeed");

    let bytes = std::fs::read(&temp_path).expect("file should exist");
    assert!(!bytes.is_empty());

    let restored: StatisticalValidationReport =
        serde_json::from_slice(&bytes).expect("should parse back");
    assert_eq!(restored, report);

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn write_to_nonexistent_directory_fails() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let result =
        write_stats_verdict_report(&report, "/nonexistent/path/that/does/not/exist/report.json");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[test]
fn serialization_error_has_correct_stable_code() {
    let err = StatisticalValidationError::Serialization("test".into());
    assert_eq!(err.stable_code(), "FE-RGC-702-SERIALIZATION-0006");
    assert!(err.to_string().contains("serialization failed"));
}

#[test]
fn report_write_error_has_correct_stable_code() {
    let err = StatisticalValidationError::ReportWrite {
        path: "/tmp/test".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert_eq!(err.stable_code(), "FE-RGC-702-REPORT-0007");
    assert!(err.to_string().contains("report write failed"));
}

// ---------------------------------------------------------------------------
// Enum Display and as_str
// ---------------------------------------------------------------------------

#[test]
fn workload_outcome_display_all_variants() {
    assert_eq!(WorkloadOutcome::Pass.as_str(), "pass");
    assert_eq!(WorkloadOutcome::Warn.as_str(), "warn");
    assert_eq!(WorkloadOutcome::Fail.as_str(), "fail");
    assert_eq!(WorkloadOutcome::Quarantine.as_str(), "quarantine");
    assert_eq!(format!("{}", WorkloadOutcome::Pass), "pass");
    assert_eq!(format!("{}", WorkloadOutcome::Quarantine), "quarantine");
}

#[test]
fn workload_outcome_ordering() {
    assert!(WorkloadOutcome::Pass < WorkloadOutcome::Warn);
    assert!(WorkloadOutcome::Warn < WorkloadOutcome::Fail);
    assert!(WorkloadOutcome::Fail < WorkloadOutcome::Quarantine);
}

#[test]
fn finding_code_stable_codes_are_all_distinct() {
    let codes = [
        FindingCode::MissingBenchmarkMetadata,
        FindingCode::InsufficientSamples,
        FindingCode::VarianceQuarantine,
        FindingCode::ConfidenceQuarantine,
        FindingCode::RegressionFail,
        FindingCode::RegressionWarn,
    ];

    let strings: Vec<&str> = codes.iter().map(|c| c.stable_code()).collect();
    let mut unique = strings.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(strings.len(), unique.len());
}

#[test]
fn finding_code_display_matches_stable_code() {
    let code = FindingCode::InsufficientSamples;
    assert_eq!(format!("{code}"), code.stable_code());
}

// ---------------------------------------------------------------------------
// Serde round-trips (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn input_serde_roundtrip() {
    let input = StatisticalValidationInput::new(
        "trace-serde",
        "decision-serde",
        "policy-serde",
        vec![stable_workload(), regressing_workload()],
    );
    let json = serde_json::to_string(&input).unwrap();
    let back: StatisticalValidationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn workload_samples_serde_roundtrip() {
    let w = stable_workload();
    let json = serde_json::to_string(&w).unwrap();
    let back: WorkloadSamples = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn policy_serde_roundtrip() {
    let policy = strict_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: StatisticalValidationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn outlier_policy_serde_roundtrip() {
    let policy = OutlierPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: OutlierPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn thresholds_serde_roundtrip() {
    let thresholds = StatisticalThresholds::default();
    let json = serde_json::to_string(&thresholds).unwrap();
    let back: StatisticalThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(thresholds, back);
}

#[test]
fn report_serde_roundtrip() {
    let policy = strict_policy();
    let input = StatisticalValidationInput::new(
        "trace-serde",
        "decision-serde",
        "policy-serde",
        vec![stable_workload(), regressing_workload()],
    );
    let report = evaluate_statistical_validation(&input, &policy);
    let json = serde_json::to_string(&report).unwrap();
    let back: StatisticalValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn verdict_serde_roundtrip() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![stable_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let verdict = &report.verdicts[0];
    let json = serde_json::to_string(verdict).unwrap();
    let back: WorkloadValidationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(*verdict, back);
}

#[test]
fn log_event_serde_roundtrip() {
    let event = StatisticalValidationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT.to_string(),
        event: "workload_evaluated".to_string(),
        scenario_id: "s".to_string(),
        workload_id: "w".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StatisticalValidationLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn validation_finding_serde_roundtrip() {
    let finding = ValidationFinding {
        code: FindingCode::RegressionFail,
        message: "regression exceeds threshold".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ValidationFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn sample_stats_serde_roundtrip() {
    let stats = SampleStatsNs {
        sample_count: 10,
        mean_ns: 1000,
        stddev_ns: 5,
        cv_millionths: 5_000,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: SampleStatsNs = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn confidence_interval_serde_roundtrip() {
    let ci = ConfidenceIntervalNs {
        lower_ns: -50,
        upper_ns: 150,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: ConfidenceIntervalNs = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, back);
}

#[test]
fn outlier_summary_serde_roundtrip() {
    let summary = OutlierSummary {
        baseline_removed: 1,
        candidate_removed: 2,
        method: "mad".to_string(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: OutlierSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_workloads_produces_empty_report() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", Vec::new());
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
    assert!(report.verdicts.is_empty());
    assert!(report.logs.is_empty());
    assert!(report.failed_workloads.is_empty());
    assert!(report.quarantined_workloads.is_empty());
}

#[test]
fn warmup_drops_first_samples() {
    // With warmup=3 and only 5 samples, we keep 2. Policy requires 3 → fails.
    let policy = StatisticalValidationPolicy {
        warmup_drop_samples: 3,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds::default(),
    };

    let workload = WorkloadSamples::new(
        "warmup_test",
        "test",
        "sha256:warmup",
        vec![999, 998, 997, 1000, 1001],
        vec![999, 998, 997, 1000, 1001],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert!(
        report.verdicts[0]
            .findings
            .iter()
            .any(|f| f.code == FindingCode::InsufficientSamples)
    );
}

#[test]
fn default_policy_sensible_defaults() {
    let policy = StatisticalValidationPolicy::default();
    assert!(policy.warmup_drop_samples > 0);
    assert!(policy.min_samples_after_filter > 0);
    assert!(policy.thresholds.max_cv_millionths > 0);
    assert!(
        policy.thresholds.fail_regression_millionths
            > policy.thresholds.warning_regression_millionths
    );
    assert!(policy.thresholds.max_p_value_millionths > 0);
    assert!(policy.thresholds.confidence_level_millionths > 500_000);
}

#[test]
fn default_outlier_policy_sensible() {
    let policy = OutlierPolicy::default();
    assert!(policy.mad_multiplier_millionths > 0);
    assert!(policy.min_retained_samples > 0);
}

#[test]
fn component_constant_is_expected_value() {
    assert_eq!(
        PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT,
        "performance_statistical_validation"
    );
}

// ---------------------------------------------------------------------------
// Confidence quarantine (p-value above threshold)
// ---------------------------------------------------------------------------

#[test]
fn low_confidence_regression_quarantined() {
    let policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 5,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 5,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 500_000,
            warning_regression_millionths: 5_000,
            fail_regression_millionths: 200_000,
            max_p_value_millionths: 10_000, // very strict p-value threshold
            min_effect_size_millionths: 1_000,
            confidence_level_millionths: 950_000,
        },
    };

    // Moderate noise with a small shift — produces high p-value
    let workload = WorkloadSamples::new(
        "confidence_test",
        "low_confidence",
        "sha256:confidence",
        vec![980, 1000, 1020, 960, 1040, 1010, 990, 970, 1030],
        vec![990, 1010, 1030, 970, 1050, 1020, 1000, 980, 1040],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Quarantine);
    assert!(
        report.verdicts[0]
            .findings
            .iter()
            .any(|f| f.code == FindingCode::ConfidenceQuarantine)
    );
}

// ---------------------------------------------------------------------------
// Mixed outcomes across multiple workloads
// ---------------------------------------------------------------------------

#[test]
fn mixed_outcomes_report_categorization() {
    let policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 10_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 500_000,
            warning_regression_millionths: 10_000,
            fail_regression_millionths: 25_000,
            max_p_value_millionths: 999_999,
            min_effect_size_millionths: 1_000,
            confidence_level_millionths: 950_000,
        },
    };

    // One stable, one regressing (fails), one missing metadata (fails)
    let mut missing_meta = stable_workload();
    missing_meta.workload_id = "missing_meta".to_string();
    missing_meta.benchmark_metadata_hash.clear();

    let input = StatisticalValidationInput::new(
        "t",
        "d",
        "p",
        vec![stable_workload(), regressing_workload(), missing_meta],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts.len(), 3);
    assert!(report.failed_workloads.len() >= 2);
    assert_eq!(report.logs.len(), 3);
}

// ---------------------------------------------------------------------------
// Effect size accuracy
// ---------------------------------------------------------------------------

#[test]
fn effect_size_positive_for_regression() {
    let policy = permissive_policy();
    let input = StatisticalValidationInput::new("t", "d", "p", vec![regressing_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(
        report.verdicts[0].effect_size_millionths > 0,
        "candidate slower than baseline should show positive regression"
    );
}

#[test]
fn effect_size_near_zero_for_identical_workloads() {
    let policy = permissive_policy();
    let workload = WorkloadSamples::new(
        "identical",
        "test",
        "sha256:identical",
        vec![1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
        vec![1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
    );

    let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].effect_size_millionths, 0);
}
