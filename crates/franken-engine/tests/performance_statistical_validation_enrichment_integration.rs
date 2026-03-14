//! Enrichment integration tests for performance_statistical_validation (RGC-702).
//!
//! Covers: outlier filtering edge cases, confidence interval boundaries,
//! p-value computation edge cases, finding code properties, error types,
//! warmup trim edge cases, regression computation, and cross-type interactions.

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

fn tight_policy() -> StatisticalValidationPolicy {
    StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 3,
        outlier_policy: OutlierPolicy {
            mad_multiplier_millionths: 2_000_000,
            min_retained_samples: 3,
        },
        thresholds: StatisticalThresholds {
            max_cv_millionths: 50_000,
            warning_regression_millionths: 5_000,
            fail_regression_millionths: 15_000,
            max_p_value_millionths: 50_000,
            min_effect_size_millionths: 3_000,
            confidence_level_millionths: 990_000,
        },
    }
}

fn identical_samples_workload() -> WorkloadSamples {
    WorkloadSamples::new(
        "identical_path",
        "deterministic",
        "sha256:identical",
        vec![1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
        vec![1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
    )
}

fn improvement_workload() -> WorkloadSamples {
    // Candidate is faster (lower latency) than baseline
    WorkloadSamples::new(
        "improved_path",
        "improvement",
        "sha256:improved",
        vec![2000, 2001, 1999, 2002, 1998, 2000, 2001, 1999, 2000, 2001],
        vec![1500, 1501, 1499, 1502, 1498, 1500, 1501, 1499, 1500, 1501],
    )
}

fn high_noise_workload() -> WorkloadSamples {
    WorkloadSamples::new(
        "noisy_path",
        "volatile",
        "sha256:noisy",
        vec![100, 500, 200, 800, 150, 600, 250, 700, 300, 400],
        vec![100, 500, 200, 800, 150, 600, 250, 700, 300, 400],
    )
}

fn make_input(workloads: Vec<WorkloadSamples>) -> StatisticalValidationInput {
    StatisticalValidationInput::new(
        "trace-enrich",
        "decision-enrich",
        "policy-enrich",
        workloads,
    )
}

// ---------------------------------------------------------------------------
// Identical samples produce zero effect size
// ---------------------------------------------------------------------------

#[test]
fn identical_samples_yield_zero_effect_size() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
    assert_eq!(report.verdicts.len(), 1);
    assert_eq!(report.verdicts[0].effect_size_millionths, 0);
}

#[test]
fn identical_samples_yield_pass_outcome() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Pass);
    assert!(report.failed_workloads.is_empty());
    assert!(report.quarantined_workloads.is_empty());
    assert!(report.warned_workloads.is_empty());
}

// ---------------------------------------------------------------------------
// Improvement (candidate faster) has negative effect size
// ---------------------------------------------------------------------------

#[test]
fn improvement_yields_negative_effect_size() {
    let policy = tight_policy();
    let input = make_input(vec![improvement_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.verdicts[0].effect_size_millionths < 0);
}

#[test]
fn improvement_passes_regression_gates() {
    let policy = tight_policy();
    let input = make_input(vec![improvement_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    // An improvement (negative effect) should never trigger regression findings
    let has_regression = report.verdicts[0].findings.iter().any(|f| {
        matches!(
            f.code,
            FindingCode::RegressionFail | FindingCode::RegressionWarn
        )
    });
    assert!(!has_regression);
}

// ---------------------------------------------------------------------------
// Warmup trim edge cases
// ---------------------------------------------------------------------------

#[test]
fn warmup_exceeding_sample_count_produces_empty_filtered() {
    let mut policy = tight_policy();
    policy.warmup_drop_samples = 100; // Way more than sample count
    policy.min_samples_after_filter = 0; // Don't fail on insufficient

    let input = make_input(vec![WorkloadSamples::new(
        "warmup_overflow",
        "edge",
        "sha256:warmup",
        vec![1000, 1001, 1002],
        vec![1000, 1001, 1002],
    )]);
    let report = evaluate_statistical_validation(&input, &policy);

    // Should fail due to insufficient samples
    assert_eq!(report.verdicts.len(), 1);
    assert_eq!(report.verdicts[0].baseline.sample_count, 0);
}

#[test]
fn warmup_equal_to_sample_count_produces_empty() {
    let mut policy = tight_policy();
    policy.warmup_drop_samples = 5;
    policy.min_samples_after_filter = 0;

    let input = make_input(vec![WorkloadSamples::new(
        "warmup_exact",
        "edge",
        "sha256:warmup-exact",
        vec![1000, 1001, 1002, 1003, 1004],
        vec![1000, 1001, 1002, 1003, 1004],
    )]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].baseline.sample_count, 0);
}

// ---------------------------------------------------------------------------
// Finding code and outcome enum properties
// ---------------------------------------------------------------------------

#[test]
fn finding_code_all_variants_have_nonempty_stable_codes() {
    let variants = [
        FindingCode::MissingBenchmarkMetadata,
        FindingCode::InsufficientSamples,
        FindingCode::VarianceQuarantine,
        FindingCode::ConfidenceQuarantine,
        FindingCode::RegressionFail,
        FindingCode::RegressionWarn,
    ];
    for variant in &variants {
        let code = variant.stable_code();
        assert!(!code.is_empty(), "stable code empty for {:?}", variant);
        assert!(
            code.starts_with("FE-RGC-702") || code.starts_with("WARN-RGC-702"),
            "unexpected prefix in code '{}' for {:?}",
            code,
            variant
        );
    }
}

#[test]
fn finding_code_display_matches_stable_code_for_all_variants() {
    let variants = [
        FindingCode::MissingBenchmarkMetadata,
        FindingCode::InsufficientSamples,
        FindingCode::VarianceQuarantine,
        FindingCode::ConfidenceQuarantine,
        FindingCode::RegressionFail,
        FindingCode::RegressionWarn,
    ];
    for variant in &variants {
        assert_eq!(
            variant.to_string(),
            variant.stable_code(),
            "Display mismatch for {:?}",
            variant
        );
    }
}

#[test]
fn finding_code_ordering_is_declaration_order() {
    assert!(FindingCode::MissingBenchmarkMetadata < FindingCode::InsufficientSamples);
    assert!(FindingCode::InsufficientSamples < FindingCode::VarianceQuarantine);
    assert!(FindingCode::VarianceQuarantine < FindingCode::ConfidenceQuarantine);
    assert!(FindingCode::ConfidenceQuarantine < FindingCode::RegressionFail);
    assert!(FindingCode::RegressionFail < FindingCode::RegressionWarn);
}

#[test]
fn workload_outcome_as_str_matches_display() {
    let variants = [
        WorkloadOutcome::Pass,
        WorkloadOutcome::Warn,
        WorkloadOutcome::Fail,
        WorkloadOutcome::Quarantine,
    ];
    for variant in &variants {
        assert_eq!(variant.as_str(), variant.to_string());
    }
}

#[test]
fn workload_outcome_ordering_severity() {
    assert!(WorkloadOutcome::Pass < WorkloadOutcome::Warn);
    assert!(WorkloadOutcome::Warn < WorkloadOutcome::Fail);
    assert!(WorkloadOutcome::Fail < WorkloadOutcome::Quarantine);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for composite types
// ---------------------------------------------------------------------------

#[test]
fn finding_code_serde_roundtrip_all_variants() {
    let variants = [
        FindingCode::MissingBenchmarkMetadata,
        FindingCode::InsufficientSamples,
        FindingCode::VarianceQuarantine,
        FindingCode::ConfidenceQuarantine,
        FindingCode::RegressionFail,
        FindingCode::RegressionWarn,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let deser: FindingCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, deser, "roundtrip failed for {:?}", variant);
    }
}

#[test]
fn workload_outcome_serde_roundtrip_all_variants() {
    let variants = [
        WorkloadOutcome::Pass,
        WorkloadOutcome::Warn,
        WorkloadOutcome::Fail,
        WorkloadOutcome::Quarantine,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let deser: WorkloadOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, deser, "roundtrip failed for {:?}", variant);
    }
}

#[test]
fn validation_finding_serde_preserves_code_and_message() {
    let finding = ValidationFinding {
        code: FindingCode::VarianceQuarantine,
        message: "variance exceeds threshold".to_string(),
    };
    let json = serde_json::to_string(&finding).expect("serialize");
    let deser: ValidationFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(finding.code, deser.code);
    assert_eq!(finding.message, deser.message);
}

#[test]
fn confidence_interval_serde_preserves_negative_bounds() {
    let ci = ConfidenceIntervalNs {
        lower_ns: -500,
        upper_ns: 200,
    };
    let json = serde_json::to_string(&ci).expect("serialize");
    let deser: ConfidenceIntervalNs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ci.lower_ns, deser.lower_ns);
    assert_eq!(ci.upper_ns, deser.upper_ns);
}

#[test]
fn sample_stats_ns_serde_preserves_all_fields() {
    let stats = SampleStatsNs {
        sample_count: 42,
        mean_ns: 12345,
        stddev_ns: 678,
        cv_millionths: 54_932,
    };
    let json = serde_json::to_string(&stats).expect("serialize");
    let deser: SampleStatsNs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stats, deser);
}

#[test]
fn outlier_summary_serde_roundtrip() {
    let summary = OutlierSummary {
        baseline_removed: 3,
        candidate_removed: 1,
        method: "mad".to_string(),
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let deser: OutlierSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, deser);
}

// ---------------------------------------------------------------------------
// Error type properties
// ---------------------------------------------------------------------------

#[test]
fn serialization_error_stable_code_prefix() {
    let err = StatisticalValidationError::Serialization("bad data".to_string());
    assert!(
        err.stable_code().starts_with("FE-RGC-702"),
        "got: {}",
        err.stable_code()
    );
}

#[test]
fn serialization_error_display_contains_message() {
    let err = StatisticalValidationError::Serialization("bad data".to_string());
    let display = err.to_string();
    assert!(display.contains("bad data"), "got: {}", display);
    assert!(display.contains("serialization"), "got: {}", display);
}

#[test]
fn report_write_error_stable_code_prefix() {
    let err = StatisticalValidationError::ReportWrite {
        path: "/nonexistent/path".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert!(
        err.stable_code().starts_with("FE-RGC-702"),
        "got: {}",
        err.stable_code()
    );
}

#[test]
fn report_write_error_display_contains_path() {
    let err = StatisticalValidationError::ReportWrite {
        path: "/my/report.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"),
    };
    let display = err.to_string();
    assert!(display.contains("/my/report.json"), "got: {}", display);
}

// ---------------------------------------------------------------------------
// Report metadata propagation
// ---------------------------------------------------------------------------

#[test]
fn report_propagates_trace_and_decision_ids() {
    let policy = tight_policy();
    let input = StatisticalValidationInput::new(
        "trace-propagate-42",
        "decision-propagate-42",
        "policy-propagate-42",
        vec![identical_samples_workload()],
    );
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.trace_id, "trace-propagate-42");
    assert_eq!(report.decision_id, "decision-propagate-42");
    assert_eq!(report.policy_id, "policy-propagate-42");
    assert_eq!(
        report.component,
        PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT
    );
}

#[test]
fn log_events_propagate_metadata_from_input() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.logs.len(), 1);
    let log = &report.logs[0];
    assert_eq!(log.trace_id, "trace-enrich");
    assert_eq!(log.decision_id, "decision-enrich");
    assert_eq!(log.policy_id, "policy-enrich");
    assert_eq!(log.component, PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT);
    assert_eq!(log.event, "workload_evaluated");
}

// ---------------------------------------------------------------------------
// Multiple workloads with mixed outcomes
// ---------------------------------------------------------------------------

#[test]
fn mixed_outcomes_categorize_into_correct_lists() {
    let policy = tight_policy();
    let mut workloads = vec![identical_samples_workload()];

    // Add a workload that will fail (missing metadata)
    workloads.push(WorkloadSamples::new(
        "missing_meta",
        "fail",
        "",
        vec![1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007],
        vec![1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007],
    ));

    let input = make_input(workloads);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert!(
        report
            .failed_workloads
            .contains(&"missing_meta".to_string())
    );
}

#[test]
fn high_noise_quarantines_workload() {
    let mut policy = tight_policy();
    policy.thresholds.max_cv_millionths = 50_000; // 5% max CV

    let input = make_input(vec![high_noise_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    // High-noise workload should have CV exceeding 5%, triggering quarantine
    let verdict = &report.verdicts[0];
    let has_variance_finding = verdict
        .findings
        .iter()
        .any(|f| f.code == FindingCode::VarianceQuarantine);
    assert!(
        has_variance_finding,
        "expected variance quarantine finding, got: {:?}",
        verdict.findings
    );
}

// ---------------------------------------------------------------------------
// Confidence interval properties
// ---------------------------------------------------------------------------

#[test]
fn confidence_interval_lower_le_upper() {
    let policy = tight_policy();
    let input = make_input(vec![improvement_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let ci = &report.verdicts[0].confidence_interval_mean_delta_ns;
    assert!(
        ci.lower_ns <= ci.upper_ns,
        "CI lower ({}) > upper ({})",
        ci.lower_ns,
        ci.upper_ns
    );
}

#[test]
fn identical_samples_have_degenerate_confidence_interval() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let ci = &report.verdicts[0].confidence_interval_mean_delta_ns;
    // With identical samples, stderr is 0 and CI collapses to a point
    assert_eq!(ci.lower_ns, ci.upper_ns);
}

// ---------------------------------------------------------------------------
// P-value properties
// ---------------------------------------------------------------------------

#[test]
fn identical_samples_have_max_p_value() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    // Identical samples → zero effect → p-value = 1.0 (or 1_000_000 millionths)
    assert_eq!(report.verdicts[0].p_value_millionths, 1_000_000);
}

#[test]
fn p_value_in_valid_range_for_improvement() {
    let policy = tight_policy();
    let input = make_input(vec![improvement_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let p = report.verdicts[0].p_value_millionths;
    assert!(p <= 1_000_000, "p-value exceeds 1.0: {}", p);
}

// ---------------------------------------------------------------------------
// Default policy values
// ---------------------------------------------------------------------------

#[test]
fn default_policy_has_one_warmup_drop() {
    let policy = StatisticalValidationPolicy::default();
    assert_eq!(policy.warmup_drop_samples, 1);
}

#[test]
fn default_policy_requires_eight_samples() {
    let policy = StatisticalValidationPolicy::default();
    assert_eq!(policy.min_samples_after_filter, 8);
}

#[test]
fn default_outlier_policy_uses_mad_3_5x() {
    let policy = OutlierPolicy::default();
    assert_eq!(policy.mad_multiplier_millionths, 3_500_000);
}

#[test]
fn default_thresholds_fail_at_25_percent_regression() {
    let thresholds = StatisticalThresholds::default();
    assert_eq!(thresholds.fail_regression_millionths, 25_000);
}

#[test]
fn default_thresholds_warn_at_10_percent_regression() {
    let thresholds = StatisticalThresholds::default();
    assert_eq!(thresholds.warning_regression_millionths, 10_000);
}

#[test]
fn default_thresholds_95_percent_confidence() {
    let thresholds = StatisticalThresholds::default();
    assert_eq!(thresholds.confidence_level_millionths, 950_000);
}

// ---------------------------------------------------------------------------
// Workload samples construction
// ---------------------------------------------------------------------------

#[test]
fn workload_samples_preserves_all_fields() {
    let ws = WorkloadSamples::new(
        "wl-id",
        "sc-id",
        "sha256:meta",
        vec![100, 200],
        vec![300, 400],
    );
    assert_eq!(ws.workload_id, "wl-id");
    assert_eq!(ws.scenario_id, "sc-id");
    assert_eq!(ws.benchmark_metadata_hash, "sha256:meta");
    assert_eq!(ws.baseline_samples_ns, vec![100, 200]);
    assert_eq!(ws.candidate_samples_ns, vec![300, 400]);
}

#[test]
fn validation_input_preserves_all_fields() {
    let input = StatisticalValidationInput::new(
        "tid",
        "did",
        "pid",
        vec![WorkloadSamples::new("w", "s", "h", vec![1], vec![2])],
    );
    assert_eq!(input.trace_id, "tid");
    assert_eq!(input.decision_id, "did");
    assert_eq!(input.policy_id, "pid");
    assert_eq!(input.workloads.len(), 1);
}

// ---------------------------------------------------------------------------
// Verdict outlier summary
// ---------------------------------------------------------------------------

#[test]
fn outlier_method_is_always_mad() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.verdicts[0].outliers.method, "mad");
}

// ---------------------------------------------------------------------------
// Log event properties
// ---------------------------------------------------------------------------

#[test]
fn log_event_for_pass_has_no_error_code() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.logs[0].error_code.is_none());
}

#[test]
fn log_event_for_failure_has_error_code() {
    let policy = tight_policy();
    let input = make_input(vec![WorkloadSamples::new(
        "fail_meta",
        "edge",
        "",
        vec![1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007],
        vec![1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007],
    )]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.logs[0].error_code.is_some());
}

#[test]
fn log_event_workload_id_matches_verdict() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert_eq!(report.logs[0].workload_id, report.verdicts[0].workload_id);
}

// ---------------------------------------------------------------------------
// Promotion logic
// ---------------------------------------------------------------------------

#[test]
fn promotion_allowed_when_all_pass() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
}

#[test]
fn promotion_blocked_when_any_quarantined() {
    let mut policy = tight_policy();
    policy.thresholds.max_cv_millionths = 50_000;

    let input = make_input(vec![high_noise_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    if !report.quarantined_workloads.is_empty() {
        assert!(!report.promote_allowed);
    }
}

#[test]
fn promotion_blocked_when_any_failed() {
    let policy = tight_policy();
    let input = make_input(vec![WorkloadSamples::new(
        "fail_insufficient",
        "edge",
        "sha256:ok",
        vec![1000],
        vec![1000],
    )]);
    let report = evaluate_statistical_validation(&input, &policy);

    if !report.failed_workloads.is_empty() {
        assert!(!report.promote_allowed);
    }
}

// ---------------------------------------------------------------------------
// Report write and serialization
// ---------------------------------------------------------------------------

#[test]
fn report_json_serialization_deterministic() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let json_a = serde_json::to_string(&report).expect("serialize a");
    let json_b = serde_json::to_string(&report).expect("serialize b");
    assert_eq!(json_a, json_b);
}

#[test]
fn full_report_serde_roundtrip() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload(), improvement_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let json = serde_json::to_string(&report).expect("serialize");
    let deser: StatisticalValidationReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, deser);
}

#[test]
fn write_report_to_tempfile_and_read_back() {
    let policy = tight_policy();
    let input = make_input(vec![identical_samples_workload()]);
    let report = evaluate_statistical_validation(&input, &policy);

    let dir = std::env::temp_dir().join("franken_perf_stat_enrichment");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("enrichment_report.json");

    write_stats_verdict_report(&report, &path).expect("write");
    let content = std::fs::read_to_string(&path).expect("read back");
    let deser: StatisticalValidationReport =
        serde_json::from_str(&content).expect("deserialize from file");
    assert_eq!(report, deser);

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Empty workloads edge case
// ---------------------------------------------------------------------------

#[test]
fn empty_workloads_produce_allowed_promotion() {
    let policy = tight_policy();
    let input = make_input(vec![]);
    let report = evaluate_statistical_validation(&input, &policy);

    assert!(report.promote_allowed);
    assert!(report.verdicts.is_empty());
    assert!(report.logs.is_empty());
    assert!(report.failed_workloads.is_empty());
    assert!(report.quarantined_workloads.is_empty());
    assert!(report.warned_workloads.is_empty());
}

// ---------------------------------------------------------------------------
// Component constant
// ---------------------------------------------------------------------------

#[test]
fn component_constant_is_module_name() {
    assert_eq!(
        PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT,
        "performance_statistical_validation"
    );
}

// ---------------------------------------------------------------------------
// LogEvent serde
// ---------------------------------------------------------------------------

#[test]
fn log_event_serde_roundtrip_with_error_code() {
    let event = StatisticalValidationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        scenario_id: "s".to_string(),
        workload_id: "w".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-RGC-702-SAMPLE-0002".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let deser: StatisticalValidationLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, deser);
}

#[test]
fn log_event_serde_roundtrip_without_error_code() {
    let event = StatisticalValidationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        scenario_id: "s".to_string(),
        workload_id: "w".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let deser: StatisticalValidationLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, deser);
}

// ---------------------------------------------------------------------------
// Verdict serde with all fields populated
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde_roundtrip_with_findings() {
    let verdict = WorkloadValidationVerdict {
        workload_id: "wl-1".to_string(),
        scenario_id: "sc-1".to_string(),
        outcome: WorkloadOutcome::Quarantine,
        p_value_millionths: 750_000,
        effect_size_millionths: 15_000,
        confidence_interval_mean_delta_ns: ConfidenceIntervalNs {
            lower_ns: -100,
            upper_ns: 300,
        },
        baseline: SampleStatsNs {
            sample_count: 10,
            mean_ns: 5000,
            stddev_ns: 200,
            cv_millionths: 40_000,
        },
        candidate: SampleStatsNs {
            sample_count: 10,
            mean_ns: 5075,
            stddev_ns: 250,
            cv_millionths: 49_261,
        },
        outliers: OutlierSummary {
            baseline_removed: 1,
            candidate_removed: 2,
            method: "mad".to_string(),
        },
        findings: vec![ValidationFinding {
            code: FindingCode::ConfidenceQuarantine,
            message: "p-value exceeds threshold".to_string(),
        }],
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let deser: WorkloadValidationVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(verdict, deser);
}
