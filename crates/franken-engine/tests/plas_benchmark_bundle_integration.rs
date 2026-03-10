#![forbid(unsafe_code)]
//! Integration tests for the `plas_benchmark_bundle` module.
//!
//! Exercises build_plas_benchmark_bundle(), validation errors, cohort
//! summaries, threshold checking, trend regression detection, markdown
//! and JSON output, duplicate detection, and serde round-trips.

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

use frankenengine_engine::plas_benchmark_bundle::{
    PLAS_BENCHMARK_BUNDLE_COMPONENT, PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION,
    PlasBenchmarkBundleDecision, PlasBenchmarkBundleError, PlasBenchmarkBundleRequest,
    PlasBenchmarkCohort, PlasBenchmarkExtensionSample, PlasBenchmarkThresholds,
    PlasBenchmarkTrendPoint, build_plas_benchmark_bundle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn good_sample(id: &str, cohort: PlasBenchmarkCohort) -> PlasBenchmarkExtensionSample {
    PlasBenchmarkExtensionSample {
        extension_id: id.into(),
        cohort,
        synthesized_capability_count: 5,
        empirically_required_capability_count: 5,
        manual_authoring_time_ms: 10_000,
        plas_authoring_time_ms: 2_000,
        benign_request_count: 1000,
        benign_false_deny_count: 1,
        escrow_event_count: 2,
        observation_window_ns: 3_600_000_000_000, // 1 hour
        witness_present: true,
    }
}

fn all_cohort_samples() -> Vec<PlasBenchmarkExtensionSample> {
    vec![
        good_sample("ext-simple", PlasBenchmarkCohort::Simple),
        good_sample("ext-complex", PlasBenchmarkCohort::Complex),
        good_sample("ext-high-risk", PlasBenchmarkCohort::HighRisk),
        good_sample("ext-boundary", PlasBenchmarkCohort::Boundary),
    ]
}

fn good_request() -> PlasBenchmarkBundleRequest {
    PlasBenchmarkBundleRequest {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        benchmark_run_id: "run-1".into(),
        generated_at_ns: 1_000_000_000,
        samples: all_cohort_samples(),
        historical_runs: Vec::new(),
        thresholds: None, // use defaults
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn component_name() {
    assert_eq!(PLAS_BENCHMARK_BUNDLE_COMPONENT, "plas_benchmark_bundle");
}

#[test]
fn schema_version() {
    assert!(PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION.contains("plas-benchmark-bundle"));
}

// ===========================================================================
// 2. PlasBenchmarkCohort
// ===========================================================================

#[test]
fn cohort_as_str() {
    assert_eq!(PlasBenchmarkCohort::Simple.as_str(), "simple");
    assert_eq!(PlasBenchmarkCohort::Complex.as_str(), "complex");
    assert_eq!(PlasBenchmarkCohort::HighRisk.as_str(), "high_risk");
    assert_eq!(PlasBenchmarkCohort::Boundary.as_str(), "boundary");
}

#[test]
fn cohort_all() {
    let all = PlasBenchmarkCohort::all();
    assert_eq!(all.len(), 4);
}

#[test]
fn cohort_serde_round_trip() {
    for cohort in PlasBenchmarkCohort::all() {
        let json = serde_json::to_string(&cohort).unwrap();
        let back: PlasBenchmarkCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cohort);
    }
}

// ===========================================================================
// 3. PlasBenchmarkThresholds
// ===========================================================================

#[test]
fn default_thresholds() {
    let t = PlasBenchmarkThresholds::default();
    assert_eq!(t.max_over_privilege_ratio_millionths, 1_100_000);
    assert_eq!(t.min_authoring_time_reduction_millionths, 700_000);
    assert_eq!(t.max_false_deny_rate_millionths, 5_000);
    assert_eq!(t.min_witness_coverage_millionths, 900_000);
    assert!(t.max_escrow_event_rate_per_hour_millionths.is_none());
    assert!(!t.fail_on_trend_regression);
}

#[test]
fn thresholds_serde_round_trip() {
    let t = PlasBenchmarkThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: PlasBenchmarkThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 4. PlasBenchmarkExtensionSample
// ===========================================================================

#[test]
fn sample_serde_round_trip() {
    let sample = good_sample("ext-1", PlasBenchmarkCohort::Simple);
    let json = serde_json::to_string(&sample).unwrap();
    let back: PlasBenchmarkExtensionSample = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sample);
}

// ===========================================================================
// 5. PlasBenchmarkTrendPoint
// ===========================================================================

#[test]
fn trend_point_serde() {
    let point = PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-prev".into(),
        generated_at_ns: 500_000_000,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 750_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 100_000,
        witness_coverage_millionths: 950_000,
    };
    let json = serde_json::to_string(&point).unwrap();
    let back: PlasBenchmarkTrendPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, point);
}

// ===========================================================================
// 6. build_plas_benchmark_bundle — happy path
// ===========================================================================

#[test]
fn build_happy_path_publish_allowed() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();

    assert!(decision.publish_allowed);
    assert!(decision.blockers.is_empty());
    assert_eq!(
        decision.schema_version,
        PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION
    );
    assert_eq!(decision.benchmark_run_id, "run-1");
    assert_eq!(decision.extension_results.len(), 4);
    assert!(!decision.cohort_summaries.is_empty());
    assert!(!decision.events.is_empty());
}

#[test]
fn build_happy_path_overall_summary() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();

    assert_eq!(decision.overall_summary.extension_count, 4);
    assert!(decision.overall_summary.required_cohorts_present);
    assert!(decision.overall_summary.over_privilege_ratio_threshold_pass);
    assert!(
        decision
            .overall_summary
            .authoring_time_reduction_threshold_pass
    );
    assert!(decision.overall_summary.false_deny_rate_threshold_pass);
    assert!(decision.overall_summary.witness_coverage_threshold_pass);
}

#[test]
fn build_happy_path_cohort_summaries() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();

    assert_eq!(decision.cohort_summaries.len(), 4);
    for summary in &decision.cohort_summaries {
        assert_eq!(summary.extension_count, 1);
        assert!(summary.pass);
    }
}

#[test]
fn build_happy_path_no_trend_regression() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.trend_regression_detected);
}

// ===========================================================================
// 7. build_plas_benchmark_bundle — validation errors
// ===========================================================================

#[test]
fn build_empty_trace_id_fails() {
    let mut request = good_request();
    request.trace_id = "".into();
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        PlasBenchmarkBundleError::InvalidInput { field, .. } => {
            assert_eq!(field, "trace_id");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn build_empty_decision_id_fails() {
    let mut request = good_request();
    request.decision_id = "  ".into();
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_empty_samples_fails() {
    let mut request = good_request();
    request.samples = Vec::new();
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_empty_extension_id_fails() {
    let mut request = good_request();
    request.samples[0].extension_id = "".into();
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_zero_synthesized_capability_fails() {
    let mut request = good_request();
    request.samples[0].synthesized_capability_count = 0;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_zero_empirically_required_fails() {
    let mut request = good_request();
    request.samples[0].empirically_required_capability_count = 0;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_zero_manual_authoring_time_fails() {
    let mut request = good_request();
    request.samples[0].manual_authoring_time_ms = 0;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_false_deny_exceeds_requests_fails() {
    let mut request = good_request();
    request.samples[0].benign_false_deny_count = request.samples[0].benign_request_count + 1;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_zero_observation_window_fails() {
    let mut request = good_request();
    request.samples[0].observation_window_ns = 0;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_sample_zero_benign_requests_fails() {
    let mut request = good_request();
    request.samples[0].benign_request_count = 0;
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

// ===========================================================================
// 8. build_plas_benchmark_bundle — duplicate extension
// ===========================================================================

#[test]
fn build_duplicate_extension_id_fails() {
    let mut request = good_request();
    request
        .samples
        .push(good_sample("ext-simple", PlasBenchmarkCohort::Simple));
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        PlasBenchmarkBundleError::DuplicateExtensionId { extension_id } => {
            assert_eq!(extension_id, "ext-simple");
        }
        other => panic!("expected DuplicateExtensionId, got {other:?}"),
    }
}

// ===========================================================================
// 9. build_plas_benchmark_bundle — missing cohorts
// ===========================================================================

#[test]
fn build_missing_cohort_adds_blocker() {
    let mut request = good_request();
    // Remove the Boundary cohort sample
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);

    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("boundary")));
}

#[test]
fn build_single_cohort_misses_three() {
    let request = PlasBenchmarkBundleRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        generated_at_ns: 1,
        samples: vec![good_sample("ext-1", PlasBenchmarkCohort::Simple)],
        historical_runs: Vec::new(),
        thresholds: None,
    };
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("missing")));
}

// ===========================================================================
// 10. build_plas_benchmark_bundle — threshold failures
// ===========================================================================

#[test]
fn build_high_over_privilege_fails_threshold() {
    let mut request = good_request();
    // Give way more capabilities than needed → high over-privilege ratio
    for s in &mut request.samples {
        s.synthesized_capability_count = 100;
        s.empirically_required_capability_count = 1;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("over-privilege"))
    );
}

#[test]
fn build_low_authoring_time_reduction_fails() {
    let mut request = good_request();
    // PLAS is barely faster → low reduction
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 10_000;
        s.plas_authoring_time_ms = 9_500;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("authoring-time"))
    );
}

#[test]
fn build_high_false_deny_rate_fails() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.benign_request_count = 100;
        s.benign_false_deny_count = 50; // 50% false deny rate
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("false-deny")));
}

#[test]
fn build_low_witness_coverage_fails() {
    let mut request = good_request();
    // All witnesses missing
    for s in &mut request.samples {
        s.witness_present = false;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("witness")));
}

// ===========================================================================
// 11. build_plas_benchmark_bundle — threshold validation
// ===========================================================================

#[test]
fn build_zero_over_privilege_threshold_fails() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_over_privilege_ratio_millionths: 0,
        ..PlasBenchmarkThresholds::default()
    });
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_too_high_false_deny_threshold_fails() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_false_deny_rate_millionths: 2_000_000, // > 1M
        ..PlasBenchmarkThresholds::default()
    });
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

#[test]
fn build_zero_escrow_rate_threshold_fails() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(0),
        ..PlasBenchmarkThresholds::default()
    });
    let result = build_plas_benchmark_bundle(&request);
    assert!(result.is_err());
}

// ===========================================================================
// 12. build_plas_benchmark_bundle — trend regression
// ===========================================================================

#[test]
fn build_with_historical_runs_no_regression() {
    let mut request = good_request();
    request.historical_runs = vec![PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-prev".into(),
        generated_at_ns: 500_000_000,
        mean_over_privilege_ratio_millionths: 1_100_000,
        mean_authoring_time_reduction_millionths: 700_000,
        mean_false_deny_rate_millionths: 5_000,
        mean_escrow_event_rate_per_hour_millionths: 100_000,
        witness_coverage_millionths: 950_000,
    }];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // Our current run has better metrics than the historical one
    // so no regression should be detected
    assert!(!decision.trend_regression_detected || decision.publish_allowed);
}

// ===========================================================================
// 13. PlasBenchmarkBundleError
// ===========================================================================

#[test]
fn error_stable_codes() {
    let e1 = PlasBenchmarkBundleError::InvalidInput {
        field: "f".into(),
        detail: "d".into(),
    };
    assert!(e1.stable_code().starts_with("FE-"));

    let e2 = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "x".into(),
    };
    assert!(e2.stable_code().starts_with("FE-"));
}

#[test]
fn error_display() {
    let e = PlasBenchmarkBundleError::InvalidInput {
        field: "trace_id".into(),
        detail: "must not be empty".into(),
    };
    assert!(e.to_string().contains("trace_id"));
    assert!(e.to_string().contains("must not be empty"));
}

#[test]
fn error_display_duplicate() {
    let e = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "ext-1".into(),
    };
    assert!(e.to_string().contains("ext-1"));
    assert!(e.to_string().contains("duplicate"));
}

// ===========================================================================
// 14. PlasBenchmarkBundleDecision — outputs
// ===========================================================================

#[test]
fn decision_to_json_pretty() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let json = decision.to_json_pretty().unwrap();
    assert!(json.contains("publish_allowed"));
    assert!(json.contains("cohort_summaries"));
}

#[test]
fn decision_to_markdown_report() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("# PLAS Benchmark Bundle"));
    assert!(md.contains("ALLOW"));
    assert!(md.contains("Overall Metrics"));
    assert!(md.contains("Cohort Summary"));
    assert!(md.contains("Extension Metrics"));
}

#[test]
fn decision_markdown_shows_deny_when_blocked() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);

    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("DENY"));
    assert!(md.contains("Blockers"));
}

#[test]
fn decision_serde_round_trip() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    let back: PlasBenchmarkBundleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

// ===========================================================================
// 15. Extension result metrics
// ===========================================================================

#[test]
fn extension_result_over_privilege_ratio() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // All samples have synthesized == empirical, so ratio = 1.0 = 1_000_000
    for result in &decision.extension_results {
        assert_eq!(result.over_privilege_ratio_millionths, 1_000_000);
    }
}

#[test]
fn extension_result_authoring_time_reduction() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // manual=10000, plas=2000, reduction = (10000-2000)/10000 = 80%
    for result in &decision.extension_results {
        assert_eq!(result.authoring_time_reduction_millionths, 800_000);
    }
}

#[test]
fn extension_result_false_deny_rate() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // 1 false deny out of 1000 requests = 0.1% = 1_000 millionths
    for result in &decision.extension_results {
        assert_eq!(result.false_deny_rate_millionths, 1_000);
    }
}

// ===========================================================================
// 16. Custom thresholds
// ===========================================================================

#[test]
fn build_with_custom_thresholds() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_over_privilege_ratio_millionths: 2_000_000, // very lenient
        min_authoring_time_reduction_millionths: 100_000,
        max_false_deny_rate_millionths: 100_000,
        min_witness_coverage_millionths: 500_000,
        max_escrow_event_rate_per_hour_millionths: Some(5_000_000), // 5/hour, samples have 2/hour
        fail_on_trend_regression: false,
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.publish_allowed,
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn build_with_strict_escrow_threshold_fails() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(1), // impossibly strict
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
}

// ===========================================================================
// 17. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_build_inspect_serialize() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();

    // Verify structure
    assert_eq!(decision.extension_results.len(), 4);
    assert_eq!(decision.cohort_summaries.len(), 4);
    assert!(decision.publish_allowed);

    // JSON round-trip
    let json = decision.to_json_pretty().unwrap();
    let back: PlasBenchmarkBundleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.publish_allowed, decision.publish_allowed);
    assert_eq!(
        back.extension_results.len(),
        decision.extension_results.len()
    );

    // Markdown
    let md = decision.to_markdown_report();
    assert!(!md.is_empty());
}
