//! Enrichment integration tests for `plas_benchmark_bundle`.
//!
//! Supplements base tests with deeper coverage of: trend regression detection,
//! escrow-event rate edge cases, bundle_id determinism, markdown report structure,
//! event emission patterns, per-cohort blocker generation, extreme input values,
//! and threshold boundary conditions.

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

use frankenengine_engine::plas_benchmark_bundle::{
    PLAS_BENCHMARK_BUNDLE_COMPONENT, PlasBenchmarkBundleDecision, PlasBenchmarkBundleError,
    PlasBenchmarkBundleRequest, PlasBenchmarkCohort, PlasBenchmarkExtensionSample,
    PlasBenchmarkThresholds, PlasBenchmarkTrendPoint, build_plas_benchmark_bundle,
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
        thresholds: None,
    }
}

fn trend_point_from_decision(decision: &PlasBenchmarkBundleDecision) -> PlasBenchmarkTrendPoint {
    PlasBenchmarkTrendPoint {
        benchmark_run_id: decision.benchmark_run_id.clone(),
        generated_at_ns: decision.generated_at_ns,
        mean_over_privilege_ratio_millionths: decision
            .overall_summary
            .mean_over_privilege_ratio_millionths,
        mean_authoring_time_reduction_millionths: decision
            .overall_summary
            .mean_authoring_time_reduction_millionths,
        mean_false_deny_rate_millionths: decision.overall_summary.mean_false_deny_rate_millionths,
        mean_escrow_event_rate_per_hour_millionths: decision
            .overall_summary
            .mean_escrow_event_rate_per_hour_millionths,
        witness_coverage_millionths: decision.overall_summary.witness_coverage_millionths,
    }
}

// ===========================================================================
// A. Bundle ID determinism (4 tests)
// ===========================================================================

#[test]
fn enrichment_bundle_id_deterministic_for_same_inputs() {
    let request = good_request();
    let d1 = build_plas_benchmark_bundle(&request).unwrap();
    let d2 = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(d1.bundle_id, d2.bundle_id);
}

#[test]
fn enrichment_bundle_id_has_prefix() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.bundle_id.starts_with("plas-bundle-"),
        "bundle_id should start with 'plas-bundle-': {}",
        decision.bundle_id
    );
}

#[test]
fn enrichment_bundle_id_varies_by_trace_id() {
    let mut r1 = good_request();
    r1.trace_id = "trace-a".into();
    let mut r2 = good_request();
    r2.trace_id = "trace-b".into();
    let d1 = build_plas_benchmark_bundle(&r1).unwrap();
    let d2 = build_plas_benchmark_bundle(&r2).unwrap();
    assert_ne!(d1.bundle_id, d2.bundle_id);
}

#[test]
fn enrichment_bundle_id_varies_by_generated_at_ns() {
    let mut r1 = good_request();
    r1.generated_at_ns = 100;
    let mut r2 = good_request();
    r2.generated_at_ns = 200;
    let d1 = build_plas_benchmark_bundle(&r1).unwrap();
    let d2 = build_plas_benchmark_bundle(&r2).unwrap();
    assert_ne!(d1.bundle_id, d2.bundle_id);
}

// ===========================================================================
// B. Trend regression detection (7 tests)
// ===========================================================================

#[test]
fn enrichment_regression_over_privilege_worse() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    // Make historical better than what the current run will produce
    historical.mean_over_privilege_ratio_millionths = 500_000; // better than current ~1_000_000

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.trend_regression_detected);
}

#[test]
fn enrichment_regression_authoring_reduction_worse() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    // Make historical have better authoring reduction
    historical.mean_authoring_time_reduction_millionths = 900_000; // better than current 800_000

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.trend_regression_detected);
}

#[test]
fn enrichment_regression_false_deny_worse() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    // Make historical have better (lower) false deny rate
    historical.mean_false_deny_rate_millionths = 0;

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // current has 1/1000 = 1_000 millionths > 0, so regression detected
    assert!(decision.trend_regression_detected);
}

#[test]
fn enrichment_regression_witness_coverage_worse() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    // Make historical have better witness coverage
    historical.witness_coverage_millionths = 1_000_001; // > 1_000_000

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.trend_regression_detected);
}

#[test]
fn enrichment_regression_identical_metrics_no_regression() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let historical = trend_point_from_decision(&d_base);

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.trend_regression_detected);
}

#[test]
fn enrichment_regression_fail_on_regression_blocks_publish() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    historical.mean_over_privilege_ratio_millionths = 500_000;

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    request.thresholds = Some(PlasBenchmarkThresholds {
        fail_on_trend_regression: true,
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.trend_regression_detected);
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("trend regression"))
    );
}

#[test]
fn enrichment_regression_no_fail_when_flag_false() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    historical.mean_over_privilege_ratio_millionths = 500_000;

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    request.thresholds = Some(PlasBenchmarkThresholds {
        fail_on_trend_regression: false,
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.trend_regression_detected);
    // Still allowed because fail_on_trend_regression is false
    assert!(
        decision.publish_allowed,
        "should still allow publish: {:?}",
        decision.blockers
    );
}

// ===========================================================================
// C. Event emission patterns (6 tests)
// ===========================================================================

#[test]
fn enrichment_events_contain_started_event() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "plas_benchmark_bundle_started")
    );
}

#[test]
fn enrichment_events_contain_decision_event() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "plas_benchmark_bundle_decision")
    );
}

#[test]
fn enrichment_events_contain_cohort_evaluated() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let cohort_events: Vec<_> = decision
        .events
        .iter()
        .filter(|e| e.event == "cohort_evaluated")
        .collect();
    assert_eq!(
        cohort_events.len(),
        4,
        "should have 4 cohort evaluation events"
    );
}

#[test]
fn enrichment_events_contain_trend_regression_check() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "trend_regression_check")
    );
}

#[test]
fn enrichment_events_all_have_component() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for event in &decision.events {
        assert_eq!(event.component, PLAS_BENCHMARK_BUNDLE_COMPONENT);
    }
}

#[test]
fn enrichment_events_all_have_trace_id() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.decision_id, "dec-1");
        assert_eq!(event.policy_id, "pol-1");
    }
}

// ===========================================================================
// D. Escrow event rate edge cases (4 tests)
// ===========================================================================

#[test]
fn enrichment_zero_escrow_events_gives_zero_rate() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.escrow_event_count = 0;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for result in &decision.extension_results {
        assert_eq!(result.escrow_event_rate_per_hour_millionths, 0);
    }
}

#[test]
fn enrichment_escrow_rate_scales_with_observation_window() {
    let mut request = good_request();
    // 2 events in 1 hour vs 2 events in 2 hours
    request.samples[0].escrow_event_count = 2;
    request.samples[0].observation_window_ns = 3_600_000_000_000; // 1 hour

    let d1 = build_plas_benchmark_bundle(&request).unwrap();
    let rate1 = d1
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap()
        .escrow_event_rate_per_hour_millionths;

    request.samples[0].observation_window_ns = 7_200_000_000_000; // 2 hours
    let d2 = build_plas_benchmark_bundle(&request).unwrap();
    let rate2 = d2
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap()
        .escrow_event_rate_per_hour_millionths;

    assert!(rate1 > rate2, "shorter window should give higher rate");
}

#[test]
fn enrichment_escrow_threshold_none_always_passes() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.escrow_event_count = 1_000_000; // huge
    }
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: None,
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.overall_summary.escrow_event_rate_threshold_pass);
}

#[test]
fn enrichment_escrow_threshold_some_can_fail() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.escrow_event_count = 1_000_000;
    }
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(1),
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.overall_summary.escrow_event_rate_threshold_pass);
}

// ===========================================================================
// E. Markdown report structure (5 tests)
// ===========================================================================

#[test]
fn enrichment_markdown_contains_all_sections() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("# PLAS Benchmark Bundle"));
    assert!(md.contains("## Overall Metrics"));
    assert!(md.contains("## Cohort Summary"));
    assert!(md.contains("## Extension Metrics"));
    assert!(md.contains("## Trend"));
}

#[test]
fn enrichment_markdown_shows_all_cohort_names() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    for cohort in PlasBenchmarkCohort::all() {
        assert!(
            md.contains(cohort.as_str()),
            "missing cohort: {}",
            cohort.as_str()
        );
    }
}

#[test]
fn enrichment_markdown_shows_all_extension_ids() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    for sample in &request.samples {
        assert!(md.contains(&sample.extension_id));
    }
}

#[test]
fn enrichment_markdown_trend_section_has_current_run() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("run-1"));
}

#[test]
fn enrichment_markdown_trend_regression_line() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("Trend regression detected"));
}

// ===========================================================================
// F. Per-cohort blocker generation (5 tests)
// ===========================================================================

#[test]
fn enrichment_cohort_over_privilege_blocker() {
    let mut request = good_request();
    // Make only the simple cohort have bad over-privilege ratio
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::Simple)
        .for_each(|s| {
            s.synthesized_capability_count = 100;
            s.empirically_required_capability_count = 1;
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("simple") && b.contains("over-privilege")),
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_cohort_authoring_time_blocker() {
    let mut request = good_request();
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::Complex)
        .for_each(|s| {
            s.manual_authoring_time_ms = 10_000;
            s.plas_authoring_time_ms = 9_900; // only 1% improvement
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("complex") && b.contains("authoring-time")),
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_cohort_false_deny_blocker() {
    let mut request = good_request();
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::HighRisk)
        .for_each(|s| {
            s.benign_request_count = 10;
            s.benign_false_deny_count = 5; // 50% false deny
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("high_risk") && b.contains("false-deny")),
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_cohort_witness_coverage_blocker() {
    let mut request = good_request();
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::Boundary)
        .for_each(|s| {
            s.witness_present = false;
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("boundary") && b.contains("witness")),
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_cohort_escrow_rate_blocker() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.escrow_event_count = 1_000_000;
    }
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(1), // impossibly strict
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.blockers.iter().any(|b| b.contains("escrow")),
        "blockers: {:?}",
        decision.blockers
    );
}

// ===========================================================================
// G. Cohort summary properties (5 tests)
// ===========================================================================

#[test]
fn enrichment_cohort_summaries_sorted_by_cohort_enum_order() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let cohorts: Vec<_> = decision.cohort_summaries.iter().map(|s| s.cohort).collect();
    let expected = vec![
        PlasBenchmarkCohort::Simple,
        PlasBenchmarkCohort::Complex,
        PlasBenchmarkCohort::HighRisk,
        PlasBenchmarkCohort::Boundary,
    ];
    assert_eq!(cohorts, expected);
}

#[test]
fn enrichment_cohort_summary_witness_coverage_all_present() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for summary in &decision.cohort_summaries {
        assert_eq!(
            summary.witness_coverage_millionths, 1_000_000,
            "all witnesses present → 100%"
        );
    }
}

#[test]
fn enrichment_cohort_summary_pass_when_all_thresholds_met() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for summary in &decision.cohort_summaries {
        assert!(summary.over_privilege_ratio_threshold_pass);
        assert!(summary.authoring_time_reduction_threshold_pass);
        assert!(summary.false_deny_rate_threshold_pass);
        assert!(summary.witness_coverage_threshold_pass);
        assert!(summary.escrow_event_rate_threshold_pass);
        assert!(summary.pass);
    }
}

#[test]
fn enrichment_cohort_summary_extension_count_matches() {
    let mut request = good_request();
    // Add a second simple extension
    request
        .samples
        .push(good_sample("ext-simple-2", PlasBenchmarkCohort::Simple));
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple_summary = decision
        .cohort_summaries
        .iter()
        .find(|s| s.cohort == PlasBenchmarkCohort::Simple)
        .unwrap();
    assert_eq!(simple_summary.extension_count, 2);
}

#[test]
fn enrichment_cohort_summary_not_pass_if_any_threshold_fails() {
    let mut request = good_request();
    // High over-privilege for simple cohort
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::Simple)
        .for_each(|s| {
            s.synthesized_capability_count = 100;
            s.empirically_required_capability_count = 1;
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple_summary = decision
        .cohort_summaries
        .iter()
        .find(|s| s.cohort == PlasBenchmarkCohort::Simple)
        .unwrap();
    assert!(!simple_summary.over_privilege_ratio_threshold_pass);
    assert!(!simple_summary.pass);
}

// ===========================================================================
// H. Extension results sorting (3 tests)
// ===========================================================================

#[test]
fn enrichment_extension_results_sorted_by_id() {
    let mut request = good_request();
    // Add samples in reverse order
    request.samples = vec![
        good_sample("z-ext", PlasBenchmarkCohort::Boundary),
        good_sample("a-ext", PlasBenchmarkCohort::Simple),
        good_sample("m-ext", PlasBenchmarkCohort::Complex),
        good_sample("f-ext", PlasBenchmarkCohort::HighRisk),
    ];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let ids: Vec<_> = decision
        .extension_results
        .iter()
        .map(|r| &r.extension_id)
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        ids, sorted,
        "extension results should be sorted by extension_id"
    );
}

#[test]
fn enrichment_extension_results_count_matches_samples() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.extension_results.len(), request.samples.len());
}

#[test]
fn enrichment_extension_results_all_have_cohort() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let cohorts: BTreeSet<_> = decision
        .extension_results
        .iter()
        .map(|r| r.cohort)
        .collect();
    assert_eq!(cohorts.len(), 4, "should cover all 4 cohorts");
}

// ===========================================================================
// I. Overall summary properties (4 tests)
// ===========================================================================

#[test]
fn enrichment_overall_extension_count() {
    let mut request = good_request();
    request
        .samples
        .push(good_sample("ext-extra", PlasBenchmarkCohort::Simple));
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.overall_summary.extension_count, 5);
}

#[test]
fn enrichment_overall_cohorts_present() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let expected = vec![
        PlasBenchmarkCohort::Simple,
        PlasBenchmarkCohort::Complex,
        PlasBenchmarkCohort::HighRisk,
        PlasBenchmarkCohort::Boundary,
    ];
    assert_eq!(decision.overall_summary.cohorts_present, expected);
}

#[test]
fn enrichment_overall_required_cohorts_false_when_missing() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.overall_summary.required_cohorts_present);
}

#[test]
fn enrichment_overall_mean_over_privilege_expected_value() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // All samples have synth=5, empirical=5 → ratio = 1_000_000
    assert_eq!(
        decision
            .overall_summary
            .mean_over_privilege_ratio_millionths,
        1_000_000
    );
}

// ===========================================================================
// J. Trend array includes current run (3 tests)
// ===========================================================================

#[test]
fn enrichment_trend_includes_current_run() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.trend.len(), 1, "trend should include current run");
    assert_eq!(decision.trend[0].benchmark_run_id, "run-1");
}

#[test]
fn enrichment_trend_historical_plus_current() {
    let mut request = good_request();
    request.historical_runs = vec![PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-prev".into(),
        generated_at_ns: 500,
        mean_over_privilege_ratio_millionths: 1_100_000,
        mean_authoring_time_reduction_millionths: 700_000,
        mean_false_deny_rate_millionths: 5_000,
        mean_escrow_event_rate_per_hour_millionths: 100_000,
        witness_coverage_millionths: 950_000,
    }];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.trend.len(), 2);
    assert_eq!(decision.trend[0].benchmark_run_id, "run-prev");
    assert_eq!(decision.trend[1].benchmark_run_id, "run-1");
}

#[test]
fn enrichment_trend_sorted_by_generated_at_ns() {
    let mut request = good_request();
    request.historical_runs = vec![
        PlasBenchmarkTrendPoint {
            benchmark_run_id: "run-old".into(),
            generated_at_ns: 100,
            mean_over_privilege_ratio_millionths: 1_100_000,
            mean_authoring_time_reduction_millionths: 700_000,
            mean_false_deny_rate_millionths: 5_000,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 900_000,
        },
        PlasBenchmarkTrendPoint {
            benchmark_run_id: "run-mid".into(),
            generated_at_ns: 500,
            mean_over_privilege_ratio_millionths: 1_050_000,
            mean_authoring_time_reduction_millionths: 750_000,
            mean_false_deny_rate_millionths: 3_000,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 950_000,
        },
    ];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.trend.len(), 3);
    for i in 0..decision.trend.len() - 1 {
        assert!(
            decision.trend[i].generated_at_ns <= decision.trend[i + 1].generated_at_ns,
            "trend should be sorted by timestamp"
        );
    }
}

// ===========================================================================
// K. Validation edge cases (6 tests)
// ===========================================================================

#[test]
fn enrichment_whitespace_only_trace_id_fails() {
    let mut request = good_request();
    request.trace_id = "   ".into();
    assert!(build_plas_benchmark_bundle(&request).is_err());
}

#[test]
fn enrichment_whitespace_only_policy_id_fails() {
    let mut request = good_request();
    request.policy_id = "  \t  ".into();
    assert!(build_plas_benchmark_bundle(&request).is_err());
}

#[test]
fn enrichment_whitespace_only_benchmark_run_id_fails() {
    let mut request = good_request();
    request.benchmark_run_id = "  ".into();
    assert!(build_plas_benchmark_bundle(&request).is_err());
}

#[test]
fn enrichment_too_high_witness_coverage_threshold_fails() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        min_witness_coverage_millionths: 1_000_001,
        ..PlasBenchmarkThresholds::default()
    });
    assert!(build_plas_benchmark_bundle(&request).is_err());
}

#[test]
fn enrichment_whitespace_extension_id_in_sample_fails() {
    let mut request = good_request();
    request.samples[0].extension_id = "  ".into();
    assert!(build_plas_benchmark_bundle(&request).is_err());
}

#[test]
fn enrichment_error_stable_code_distinct_per_variant() {
    let e1 = PlasBenchmarkBundleError::InvalidInput {
        field: "f".into(),
        detail: "d".into(),
    };
    let e2 = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "x".into(),
    };
    let e3 = PlasBenchmarkBundleError::SerializationFailure("err".into());
    let codes = [e1.stable_code(), e2.stable_code(), e3.stable_code()];
    // InvalidInput and SerializationFailure share the same code, DuplicateExtensionId is different
    assert_ne!(codes[0], codes[1]);
    assert!(codes[0].starts_with("FE-PLAS-BENCH-"));
    assert!(codes[1].starts_with("FE-PLAS-BENCH-"));
}

// ===========================================================================
// L. Serde roundtrip for full decision with blockers (3 tests)
// ===========================================================================

#[test]
fn enrichment_denied_decision_serde_roundtrip() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);

    let json = serde_json::to_string(&decision).unwrap();
    let back: PlasBenchmarkBundleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

#[test]
fn enrichment_decision_json_pretty_parseable() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let json = decision.to_json_pretty().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_object());
    assert!(parsed["publish_allowed"].as_bool().unwrap());
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let errors = [
        PlasBenchmarkBundleError::InvalidInput {
            field: "f".into(),
            detail: "d".into(),
        },
        PlasBenchmarkBundleError::DuplicateExtensionId {
            extension_id: "x".into(),
        },
        PlasBenchmarkBundleError::SerializationFailure("err".into()),
    ];
    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty());
    }
}

// ===========================================================================
// M. Multi-sample cohort aggregation (8 tests)
// ===========================================================================

#[test]
fn enrichment_multi_sample_same_cohort_mean_over_privilege() {
    let mut request = good_request();
    // Replace Simple sample with two: one with ratio 2.0 and one with ratio 1.0
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Simple);
    let mut s1 = good_sample("ext-s1", PlasBenchmarkCohort::Simple);
    s1.synthesized_capability_count = 10;
    s1.empirically_required_capability_count = 5; // ratio = 2.0
    let mut s2 = good_sample("ext-s2", PlasBenchmarkCohort::Simple);
    s2.synthesized_capability_count = 5;
    s2.empirically_required_capability_count = 5; // ratio = 1.0
    request.samples.push(s1);
    request.samples.push(s2);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::Simple)
        .unwrap();
    // mean of 2_000_000 and 1_000_000 = 1_500_000
    assert_eq!(simple.mean_over_privilege_ratio_millionths, 1_500_000);
}

#[test]
fn enrichment_multi_sample_same_cohort_witness_coverage_partial() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Complex);
    let mut s1 = good_sample("ext-c1", PlasBenchmarkCohort::Complex);
    s1.witness_present = true;
    let mut s2 = good_sample("ext-c2", PlasBenchmarkCohort::Complex);
    s2.witness_present = false;
    request.samples.push(s1);
    request.samples.push(s2);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let complex = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::Complex)
        .unwrap();
    // 1 out of 2 => 500_000 millionths
    assert_eq!(complex.witness_coverage_millionths, 500_000);
}

#[test]
fn enrichment_multi_sample_mean_false_deny() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::HighRisk);
    let mut s1 = good_sample("ext-h1", PlasBenchmarkCohort::HighRisk);
    s1.benign_request_count = 1000;
    s1.benign_false_deny_count = 0; // 0%
    let mut s2 = good_sample("ext-h2", PlasBenchmarkCohort::HighRisk);
    s2.benign_request_count = 1000;
    s2.benign_false_deny_count = 10; // 1% = 10_000 millionths
    request.samples.push(s1);
    request.samples.push(s2);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let hr = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::HighRisk)
        .unwrap();
    // mean of 0 and 10_000 = 5_000
    assert_eq!(hr.mean_false_deny_rate_millionths, 5_000);
}

#[test]
fn enrichment_multi_sample_mean_authoring_reduction() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);
    let mut s1 = good_sample("ext-b1", PlasBenchmarkCohort::Boundary);
    s1.manual_authoring_time_ms = 10_000;
    s1.plas_authoring_time_ms = 2_000; // 80% reduction = 800_000
    let mut s2 = good_sample("ext-b2", PlasBenchmarkCohort::Boundary);
    s2.manual_authoring_time_ms = 10_000;
    s2.plas_authoring_time_ms = 5_000; // 50% reduction = 500_000
    request.samples.push(s1);
    request.samples.push(s2);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let boundary = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::Boundary)
        .unwrap();
    // mean of 800_000 and 500_000 = 650_000
    assert_eq!(boundary.mean_authoring_time_reduction_millionths, 650_000);
}

#[test]
fn enrichment_multi_sample_extension_count_in_summary() {
    let mut request = good_request();
    request
        .samples
        .push(good_sample("ext-simple-2", PlasBenchmarkCohort::Simple));
    request
        .samples
        .push(good_sample("ext-simple-3", PlasBenchmarkCohort::Simple));
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::Simple)
        .unwrap();
    assert_eq!(simple.extension_count, 3);
}

#[test]
fn enrichment_multi_sample_overall_extension_count() {
    let mut request = good_request();
    request
        .samples
        .push(good_sample("ext-simple-2", PlasBenchmarkCohort::Simple));
    request
        .samples
        .push(good_sample("ext-complex-2", PlasBenchmarkCohort::Complex));
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.overall_summary.extension_count, 6);
}

#[test]
fn enrichment_multi_sample_overall_witness_coverage_mixed() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.witness_present = true;
    }
    let mut extra = good_sample("ext-no-witness", PlasBenchmarkCohort::Simple);
    extra.witness_present = false;
    request.samples.push(extra);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // 4 out of 5 witnesses present → 800_000
    assert_eq!(
        decision.overall_summary.witness_coverage_millionths,
        800_000
    );
}

#[test]
fn enrichment_multi_sample_deterministic_ordering() {
    let mut request = good_request();
    request
        .samples
        .push(good_sample("ext-aaa", PlasBenchmarkCohort::Simple));
    request
        .samples
        .push(good_sample("ext-zzz", PlasBenchmarkCohort::Simple));
    let d1 = build_plas_benchmark_bundle(&request).unwrap();
    // Reverse the samples
    request.samples.reverse();
    let d2 = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(d1.bundle_id, d2.bundle_id);
    assert_eq!(d1.extension_results, d2.extension_results);
}

// ===========================================================================
// N. Authoring time edge cases (6 tests)
// ===========================================================================

#[test]
fn enrichment_plas_slower_than_manual_negative_reduction() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 1_000;
        s.plas_authoring_time_ms = 2_000; // plas is slower → negative reduction
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for result in &decision.extension_results {
        assert!(
            result.authoring_time_reduction_millionths < 0,
            "reduction should be negative when plas is slower"
        );
    }
}

#[test]
fn enrichment_plas_equal_to_manual_zero_reduction() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 5_000;
        s.plas_authoring_time_ms = 5_000;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for result in &decision.extension_results {
        assert_eq!(result.authoring_time_reduction_millionths, 0);
    }
}

#[test]
fn enrichment_plas_zero_ms_full_reduction() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 10_000;
        s.plas_authoring_time_ms = 0; // 100% reduction
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for result in &decision.extension_results {
        assert_eq!(result.authoring_time_reduction_millionths, 1_000_000);
    }
}

#[test]
fn enrichment_negative_reduction_denies_publish() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 1_000;
        s.plas_authoring_time_ms = 5_000; // much slower
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("authoring-time")),
        "blockers: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_plas_authoring_just_below_threshold() {
    // Default min_authoring_time_reduction_millionths = 700_000 (70%)
    // If plas_time = 3001 with manual = 10000, reduction = 69.99% < 70%
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 10_000;
        s.plas_authoring_time_ms = 3_001;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("authoring-time")),
        "just below threshold should block: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_plas_authoring_exactly_at_threshold() {
    // Default min_authoring_time_reduction_millionths = 700_000 (70%)
    // plas_time = 3000 with manual = 10000 → reduction = 70% = 700_000
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 10_000;
        s.plas_authoring_time_ms = 3_000;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.publish_allowed,
        "exactly at threshold should pass: blockers = {:?}",
        decision.blockers
    );
}

// ===========================================================================
// O. Threshold boundary conditions (8 tests)
// ===========================================================================

#[test]
fn enrichment_over_privilege_exactly_at_threshold() {
    // Default max_over_privilege_ratio_millionths = 1_100_000 (1.1x)
    // synth=11, empirical=10 → ratio = ceil(11/10 * 1M) = 1_100_000
    let mut request = good_request();
    for s in &mut request.samples {
        s.synthesized_capability_count = 11;
        s.empirically_required_capability_count = 10;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.overall_summary.over_privilege_ratio_threshold_pass,
        "exactly at threshold should pass"
    );
}

#[test]
fn enrichment_over_privilege_just_above_threshold() {
    // synth=12, empirical=10 → ratio = ceil(12/10 * 1M) = 1_200_000 > 1_100_000
    let mut request = good_request();
    for s in &mut request.samples {
        s.synthesized_capability_count = 12;
        s.empirically_required_capability_count = 10;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.overall_summary.over_privilege_ratio_threshold_pass);
}

#[test]
fn enrichment_false_deny_exactly_at_threshold() {
    // Default max = 5_000 (0.5%)
    // 5 false deny out of 1000 = 5_000 millionths
    let mut request = good_request();
    for s in &mut request.samples {
        s.benign_request_count = 1000;
        s.benign_false_deny_count = 5;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.overall_summary.false_deny_rate_threshold_pass,
        "exactly at threshold should pass"
    );
}

#[test]
fn enrichment_false_deny_just_above_threshold() {
    // 6 false deny out of 1000 = 6_000 millionths > 5_000
    let mut request = good_request();
    for s in &mut request.samples {
        s.benign_request_count = 1000;
        s.benign_false_deny_count = 6;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.overall_summary.false_deny_rate_threshold_pass);
}

#[test]
fn enrichment_witness_coverage_exactly_at_threshold() {
    // Default min = 900_000 (90%). 9 out of 10 = 900_000
    let mut request = good_request();
    request.samples.clear();
    for i in 0..10 {
        let cohort = PlasBenchmarkCohort::all()[i % 4];
        let mut s = good_sample(&format!("ext-{i}"), cohort);
        s.witness_present = i < 9; // 9 out of 10
        request.samples.push(s);
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.overall_summary.witness_coverage_threshold_pass,
        "90% coverage should pass 90% threshold"
    );
}

#[test]
fn enrichment_witness_coverage_just_below_threshold() {
    // 8 out of 10 = 800_000 < 900_000
    let mut request = good_request();
    request.samples.clear();
    for i in 0..10 {
        let cohort = PlasBenchmarkCohort::all()[i % 4];
        let mut s = good_sample(&format!("ext-{i}"), cohort);
        s.witness_present = i < 8;
        request.samples.push(s);
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.overall_summary.witness_coverage_threshold_pass);
}

#[test]
fn enrichment_custom_threshold_very_lenient_all_pass() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.synthesized_capability_count = 100;
        s.empirically_required_capability_count = 1;
        s.manual_authoring_time_ms = 10_000;
        s.plas_authoring_time_ms = 9_999;
        s.benign_request_count = 10;
        s.benign_false_deny_count = 5;
        s.witness_present = false;
    }
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_over_privilege_ratio_millionths: u64::MAX,
        min_authoring_time_reduction_millionths: i64::MIN,
        max_false_deny_rate_millionths: 1_000_000,
        min_witness_coverage_millionths: 0,
        max_escrow_event_rate_per_hour_millionths: None,
        fail_on_trend_regression: false,
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.publish_allowed,
        "very lenient thresholds should pass: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_custom_threshold_min_authoring_negative_allows_worse() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.manual_authoring_time_ms = 1_000;
        s.plas_authoring_time_ms = 1_500; // negative 50% reduction
    }
    request.thresholds = Some(PlasBenchmarkThresholds {
        min_authoring_time_reduction_millionths: -1_000_000, // allow negative
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision
            .overall_summary
            .authoring_time_reduction_threshold_pass,
        "negative threshold should allow negative reduction"
    );
}

// ===========================================================================
// P. Multiple historical runs (5 tests)
// ===========================================================================

#[test]
fn enrichment_regression_only_compares_to_latest_historical() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let exact = trend_point_from_decision(&d_base);
    let mut worse = exact.clone();
    worse.mean_over_privilege_ratio_millionths = 2_000_000; // worse than current
    worse.generated_at_ns = 50; // older

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    // The latest historical (by timestamp) has exact same metrics → no regression
    request.historical_runs = vec![
        PlasBenchmarkTrendPoint {
            generated_at_ns: 50,
            benchmark_run_id: "run-old".into(),
            ..worse
        },
        PlasBenchmarkTrendPoint {
            generated_at_ns: 999,
            benchmark_run_id: "run-recent".into(),
            ..exact
        },
    ];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        !decision.trend_regression_detected,
        "should compare to latest (run-recent), not run-old"
    );
}

#[test]
fn enrichment_trend_array_preserves_all_historical_runs() {
    let mut request = good_request();
    for i in 0..5 {
        request.historical_runs.push(PlasBenchmarkTrendPoint {
            benchmark_run_id: format!("run-{i}"),
            generated_at_ns: i as u64 * 100,
            mean_over_privilege_ratio_millionths: 1_000_000,
            mean_authoring_time_reduction_millionths: 800_000,
            mean_false_deny_rate_millionths: 1_000,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 1_000_000,
        });
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.trend.len(), 6, "5 historical + 1 current");
}

#[test]
fn enrichment_trend_last_entry_is_current_run() {
    let mut request = good_request();
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-old".into(),
        generated_at_ns: 500,
        mean_over_privilege_ratio_millionths: 1_000_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 1_000,
        mean_escrow_event_rate_per_hour_millionths: 0,
        witness_coverage_millionths: 1_000_000,
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let last = decision.trend.last().unwrap();
    assert_eq!(last.benchmark_run_id, request.benchmark_run_id);
    assert_eq!(last.generated_at_ns, request.generated_at_ns);
}

#[test]
fn enrichment_empty_historical_runs_no_regression() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.trend_regression_detected);
    assert_eq!(decision.trend.len(), 1);
}

#[test]
fn enrichment_regression_escrow_rate_not_in_regression_check() {
    // The is_regression function checks over_privilege, authoring, false_deny, witness
    // but NOT escrow_event_rate. Verify a worse escrow rate alone does not trigger regression.
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    historical.mean_escrow_event_rate_per_hour_millionths = 0; // better than current

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        !decision.trend_regression_detected,
        "escrow rate alone should not trigger regression"
    );
}

// ===========================================================================
// Q. Extension result computation details (7 tests)
// ===========================================================================

#[test]
fn enrichment_extension_result_escrow_rate_1_event_1_hour() {
    let mut request = good_request();
    request.samples[0].escrow_event_count = 1;
    request.samples[0].observation_window_ns = 3_600_000_000_000; // 1 hour
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert_eq!(result.escrow_event_rate_per_hour_millionths, 1_000_000);
}

#[test]
fn enrichment_extension_result_escrow_rate_2_events_half_hour() {
    let mut request = good_request();
    request.samples[0].escrow_event_count = 2;
    request.samples[0].observation_window_ns = 1_800_000_000_000; // 30 min
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    // 2 events in 30min = 4 events/hour = 4_000_000 millionths
    assert_eq!(result.escrow_event_rate_per_hour_millionths, 4_000_000);
}

#[test]
fn enrichment_extension_result_preserves_cohort() {
    let request = good_request();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for sample in &request.samples {
        let result = decision
            .extension_results
            .iter()
            .find(|r| r.extension_id == sample.extension_id)
            .unwrap();
        assert_eq!(result.cohort, sample.cohort);
    }
}

#[test]
fn enrichment_extension_result_zero_false_deny() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.benign_false_deny_count = 0;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    for result in &decision.extension_results {
        assert_eq!(result.false_deny_rate_millionths, 0);
    }
}

#[test]
fn enrichment_extension_result_ratio_ceil_rounding() {
    // ceil(11 * 1_000_000 / 10) = ceil(1_100_000) = 1_100_000 (exact)
    let mut request = good_request();
    request.samples[0].synthesized_capability_count = 11;
    request.samples[0].empirically_required_capability_count = 10;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert_eq!(result.over_privilege_ratio_millionths, 1_100_000);
}

#[test]
fn enrichment_extension_result_ratio_ceil_non_exact() {
    // ceil(1 * 1_000_000 / 3) = ceil(333333.33) = 333_334
    let mut request = good_request();
    request.samples[0].synthesized_capability_count = 1;
    request.samples[0].empirically_required_capability_count = 3;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert_eq!(result.over_privilege_ratio_millionths, 333_334);
}

#[test]
fn enrichment_extension_result_authoring_50_pct_reduction() {
    let mut request = good_request();
    request.samples[0].manual_authoring_time_ms = 10_000;
    request.samples[0].plas_authoring_time_ms = 5_000;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert_eq!(result.authoring_time_reduction_millionths, 500_000);
}

// ===========================================================================
// R. Decision field completeness (5 tests)
// ===========================================================================

#[test]
fn enrichment_decision_has_schema_version() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    assert_eq!(
        decision.schema_version,
        "franken-engine.plas-benchmark-bundle.v1"
    );
}

#[test]
fn enrichment_decision_benchmark_run_id_matches() {
    let mut request = good_request();
    request.benchmark_run_id = "custom-run-42".into();
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.benchmark_run_id, "custom-run-42");
}

#[test]
fn enrichment_decision_generated_at_ns_matches() {
    let mut request = good_request();
    request.generated_at_ns = 99_999;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.generated_at_ns, 99_999);
}

#[test]
fn enrichment_decision_thresholds_default_when_none() {
    let mut request = good_request();
    request.thresholds = None;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.thresholds, PlasBenchmarkThresholds::default());
}

#[test]
fn enrichment_decision_thresholds_custom_when_set() {
    let mut request = good_request();
    let custom = PlasBenchmarkThresholds {
        max_over_privilege_ratio_millionths: 2_000_000,
        min_authoring_time_reduction_millionths: 100_000,
        max_false_deny_rate_millionths: 100_000,
        min_witness_coverage_millionths: 500_000,
        max_escrow_event_rate_per_hour_millionths: Some(10_000_000),
        fail_on_trend_regression: true,
    };
    request.thresholds = Some(custom.clone());
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.thresholds, custom);
}

// ===========================================================================
// S. Markdown report advanced checks (7 tests)
// ===========================================================================

#[test]
fn enrichment_markdown_denied_with_regression_shows_all() {
    let d_base = build_plas_benchmark_bundle(&good_request()).unwrap();
    let mut historical = trend_point_from_decision(&d_base);
    historical.mean_over_privilege_ratio_millionths = 500_000;

    let mut request = good_request();
    request.benchmark_run_id = "run-2".into();
    request.historical_runs = vec![historical];
    request.thresholds = Some(PlasBenchmarkThresholds {
        fail_on_trend_regression: true,
        ..PlasBenchmarkThresholds::default()
    });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("DENY"));
    assert!(md.contains("Blockers"));
    assert!(md.contains("yes")); // trend regression detected: yes
}

#[test]
fn enrichment_markdown_contains_bundle_id() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains(&decision.bundle_id));
}

#[test]
fn enrichment_markdown_contains_benchmark_run_id() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains(&decision.benchmark_run_id));
}

#[test]
fn enrichment_markdown_contains_generated_at_ns() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains(&decision.generated_at_ns.to_string()));
}

#[test]
fn enrichment_markdown_extension_metrics_table() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("| Extension | Cohort |"));
    for result in &decision.extension_results {
        assert!(md.contains(&result.extension_id));
    }
}

#[test]
fn enrichment_markdown_overall_metrics_table() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let md = decision.to_markdown_report();
    assert!(md.contains("| Over-privilege ratio |"));
    assert!(md.contains("| Authoring-time reduction |"));
    assert!(md.contains("| False-deny rate |"));
    assert!(md.contains("| Witness coverage |"));
}

#[test]
fn enrichment_markdown_no_blockers_section_when_allowed() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    assert!(decision.publish_allowed);
    let md = decision.to_markdown_report();
    assert!(!md.contains("## Blockers"));
}

// ===========================================================================
// T. Event emission advanced patterns (6 tests)
// ===========================================================================

#[test]
fn enrichment_events_count_minimum() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    // started + cohort_coverage + 4 cohort_evaluated + trend_regression_check + decision = 8
    assert!(
        decision.events.len() >= 8,
        "expected at least 8 events, got {}",
        decision.events.len()
    );
}

#[test]
fn enrichment_events_first_is_started() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    assert_eq!(decision.events[0].event, "plas_benchmark_bundle_started");
    assert_eq!(decision.events[0].outcome, "pass");
}

#[test]
fn enrichment_events_last_is_decision() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let last = decision.events.last().unwrap();
    assert_eq!(last.event, "plas_benchmark_bundle_decision");
}

#[test]
fn enrichment_events_decision_allow_when_publish_allowed() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    assert!(decision.publish_allowed);
    let decision_event = decision
        .events
        .iter()
        .find(|e| e.event == "plas_benchmark_bundle_decision")
        .unwrap();
    assert_eq!(decision_event.outcome, "allow");
}

#[test]
fn enrichment_events_decision_deny_when_blocked() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(!decision.publish_allowed);
    let decision_event = decision
        .events
        .iter()
        .find(|e| e.event == "plas_benchmark_bundle_decision")
        .unwrap();
    assert_eq!(decision_event.outcome, "deny");
}

#[test]
fn enrichment_events_cohort_coverage_pass_when_all_present() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let coverage_event = decision
        .events
        .iter()
        .find(|e| e.event == "cohort_coverage")
        .unwrap();
    assert_eq!(coverage_event.outcome, "pass");
    assert!(coverage_event.error_code.is_none());
}

// ===========================================================================
// U. Validation: plas_authoring_time_ms (3 tests)
// ===========================================================================

#[test]
fn enrichment_sample_plas_authoring_time_ms_can_be_zero() {
    let mut request = good_request();
    request.samples[0].plas_authoring_time_ms = 0;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert_eq!(result.authoring_time_reduction_millionths, 1_000_000);
}

#[test]
fn enrichment_sample_plas_authoring_time_large_value() {
    let mut request = good_request();
    request.samples[0].manual_authoring_time_ms = 100;
    request.samples[0].plas_authoring_time_ms = 1_000_000;
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .unwrap();
    assert!(result.authoring_time_reduction_millionths < 0);
}

#[test]
fn enrichment_sample_zero_empirically_required_fails() {
    let mut request = good_request();
    request.samples[0].empirically_required_capability_count = 0;
    let err = build_plas_benchmark_bundle(&request).unwrap_err();
    assert!(
        err.to_string()
            .contains("empirically_required_capability_count")
    );
}

// ===========================================================================
// V. Serde: request, thresholds, event roundtrips (5 tests)
// ===========================================================================

#[test]
fn enrichment_request_serde_roundtrip() {
    let request = good_request();
    let json = serde_json::to_string(&request).unwrap();
    let back: PlasBenchmarkBundleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, request.trace_id);
    assert_eq!(back.samples.len(), request.samples.len());
}

#[test]
fn enrichment_request_with_thresholds_serde_roundtrip() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(5_000_000),
        fail_on_trend_regression: true,
        ..PlasBenchmarkThresholds::default()
    });
    let json = serde_json::to_string(&request).unwrap();
    let back: PlasBenchmarkBundleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.thresholds, request.thresholds);
}

#[test]
fn enrichment_request_with_historical_runs_serde_roundtrip() {
    let mut request = good_request();
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-hist".into(),
        generated_at_ns: 500,
        mean_over_privilege_ratio_millionths: 1_000_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 1_000,
        mean_escrow_event_rate_per_hour_millionths: 0,
        witness_coverage_millionths: 1_000_000,
    });
    let json = serde_json::to_string(&request).unwrap();
    let back: PlasBenchmarkBundleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.historical_runs.len(), 1);
    assert_eq!(back.historical_runs[0].benchmark_run_id, "run-hist");
}

#[test]
fn enrichment_bundle_event_serde_roundtrip() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    for event in &decision.events {
        let json = serde_json::to_string(event).unwrap();
        let back: frankenengine_engine::plas_benchmark_bundle::PlasBenchmarkBundleEvent =
            serde_json::from_str(&json).unwrap();
        assert_eq!(back.event, event.event);
        assert_eq!(back.outcome, event.outcome);
    }
}

#[test]
fn enrichment_thresholds_serde_preserves_none_escrow() {
    let t = PlasBenchmarkThresholds::default();
    assert!(t.max_escrow_event_rate_per_hour_millionths.is_none());
    let json = serde_json::to_string(&t).unwrap();
    let back: PlasBenchmarkThresholds = serde_json::from_str(&json).unwrap();
    assert!(back.max_escrow_event_rate_per_hour_millionths.is_none());
}

// ===========================================================================
// W. Overall summary advanced properties (5 tests)
// ===========================================================================

#[test]
fn enrichment_overall_mean_false_deny_aggregation() {
    let mut request = good_request();
    // 4 samples: false deny counts = 0, 2, 4, 10 out of 1000
    let counts = [0, 2, 4, 10];
    for (s, count) in request.samples.iter_mut().zip(counts.iter()) {
        s.benign_request_count = 1000;
        s.benign_false_deny_count = *count;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    // rates in millionths: 0, 2000, 4000, 10000 → mean = 4000
    assert_eq!(
        decision.overall_summary.mean_false_deny_rate_millionths,
        4_000
    );
}

#[test]
fn enrichment_overall_mean_escrow_rate_zero_events() {
    let mut request = good_request();
    for s in &mut request.samples {
        s.escrow_event_count = 0;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(
        decision
            .overall_summary
            .mean_escrow_event_rate_per_hour_millionths,
        0
    );
}

#[test]
fn enrichment_overall_all_thresholds_pass_when_good() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    assert!(decision.overall_summary.over_privilege_ratio_threshold_pass);
    assert!(
        decision
            .overall_summary
            .authoring_time_reduction_threshold_pass
    );
    assert!(decision.overall_summary.false_deny_rate_threshold_pass);
    assert!(decision.overall_summary.witness_coverage_threshold_pass);
    assert!(decision.overall_summary.escrow_event_rate_threshold_pass);
}

#[test]
fn enrichment_overall_cohorts_present_sorted() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let cohorts = &decision.overall_summary.cohorts_present;
    for i in 0..cohorts.len() - 1 {
        assert!(cohorts[i] < cohorts[i + 1], "cohorts should be sorted");
    }
}

#[test]
fn enrichment_overall_escrow_threshold_pass_when_none() {
    let mut request = good_request();
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: None,
        ..PlasBenchmarkThresholds::default()
    });
    for s in &mut request.samples {
        s.escrow_event_count = 999_999;
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(decision.overall_summary.escrow_event_rate_threshold_pass);
}

// ===========================================================================
// X. Error variant properties (5 tests)
// ===========================================================================

#[test]
fn enrichment_error_invalid_input_stable_code() {
    let e = PlasBenchmarkBundleError::InvalidInput {
        field: "x".into(),
        detail: "y".into(),
    };
    assert_eq!(e.stable_code(), "FE-PLAS-BENCH-2001");
}

#[test]
fn enrichment_error_duplicate_extension_stable_code() {
    let e = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "x".into(),
    };
    assert_eq!(e.stable_code(), "FE-PLAS-BENCH-2002");
}

#[test]
fn enrichment_error_serialization_stable_code() {
    let e = PlasBenchmarkBundleError::SerializationFailure("x".into());
    // SerializationFailure shares the same code as InvalidInput
    assert_eq!(e.stable_code(), "FE-PLAS-BENCH-2001");
}

#[test]
fn enrichment_error_display_contains_field_name() {
    let e = PlasBenchmarkBundleError::InvalidInput {
        field: "observation_window_ns".into(),
        detail: "must be > 0".into(),
    };
    let display = e.to_string();
    assert!(display.contains("observation_window_ns"));
    assert!(display.contains("must be > 0"));
}

#[test]
fn enrichment_error_clone_eq() {
    let e1 = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "ext-1".into(),
    };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

// ===========================================================================
// Y. Cohort coverage event (3 tests)
// ===========================================================================

#[test]
fn enrichment_cohort_coverage_fail_event_when_missing() {
    let mut request = good_request();
    request
        .samples
        .retain(|s| s.cohort != PlasBenchmarkCohort::HighRisk);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let coverage_event = decision
        .events
        .iter()
        .find(|e| e.event == "cohort_coverage")
        .unwrap();
    assert_eq!(coverage_event.outcome, "fail");
    assert!(coverage_event.error_code.is_some());
}

#[test]
fn enrichment_cohort_evaluated_events_have_cohort_field() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    let cohort_events: Vec<_> = decision
        .events
        .iter()
        .filter(|e| e.event == "cohort_evaluated")
        .collect();
    for event in &cohort_events {
        assert!(
            event.cohort.is_some(),
            "cohort_evaluated event should have cohort field"
        );
    }
}

#[test]
fn enrichment_cohort_evaluated_fail_event_has_error_code() {
    let mut request = good_request();
    // Make simple cohort fail by setting very high over-privilege
    request
        .samples
        .iter_mut()
        .filter(|s| s.cohort == PlasBenchmarkCohort::Simple)
        .for_each(|s| {
            s.synthesized_capability_count = 100;
            s.empirically_required_capability_count = 1;
        });
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple_event = decision
        .events
        .iter()
        .find(|e| e.event == "cohort_evaluated" && e.cohort.as_deref() == Some("simple"))
        .unwrap();
    assert_eq!(simple_event.outcome, "fail");
    assert!(simple_event.error_code.is_some());
}

// ===========================================================================
// Z. Bundle ID properties (3 tests)
// ===========================================================================

#[test]
fn enrichment_bundle_id_hex_length() {
    let decision = build_plas_benchmark_bundle(&good_request()).unwrap();
    // "plas-bundle-" prefix + 24 hex chars (12 bytes)
    let hex_part = decision.bundle_id.strip_prefix("plas-bundle-").unwrap();
    assert_eq!(hex_part.len(), 24, "expected 24 hex characters");
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "expected only hex digits: {hex_part}"
    );
}

#[test]
fn enrichment_bundle_id_varies_by_policy_id() {
    let mut r1 = good_request();
    r1.policy_id = "pol-a".into();
    let mut r2 = good_request();
    r2.policy_id = "pol-b".into();
    let d1 = build_plas_benchmark_bundle(&r1).unwrap();
    let d2 = build_plas_benchmark_bundle(&r2).unwrap();
    assert_ne!(d1.bundle_id, d2.bundle_id);
}

#[test]
fn enrichment_bundle_id_varies_by_decision_id() {
    let mut r1 = good_request();
    r1.decision_id = "dec-a".into();
    let mut r2 = good_request();
    r2.decision_id = "dec-b".into();
    let d1 = build_plas_benchmark_bundle(&r1).unwrap();
    let d2 = build_plas_benchmark_bundle(&r2).unwrap();
    assert_ne!(d1.bundle_id, d2.bundle_id);
}

// ===========================================================================
// AA. Large sample set properties (4 tests)
// ===========================================================================

#[test]
fn enrichment_many_samples_per_cohort_produces_correct_summaries() {
    let mut request = good_request();
    request.samples.clear();
    for cohort in PlasBenchmarkCohort::all() {
        for i in 0..10 {
            request
                .samples
                .push(good_sample(&format!("ext-{}-{i}", cohort.as_str()), cohort));
        }
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.extension_results.len(), 40);
    assert_eq!(decision.overall_summary.extension_count, 40);
    for summary in &decision.cohort_summaries {
        assert_eq!(summary.extension_count, 10);
    }
}

#[test]
fn enrichment_many_samples_publish_allowed() {
    let mut request = good_request();
    request.samples.clear();
    for cohort in PlasBenchmarkCohort::all() {
        for i in 0..5 {
            request
                .samples
                .push(good_sample(&format!("ext-{}-{i}", cohort.as_str()), cohort));
        }
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert!(
        decision.publish_allowed,
        "all good samples should pass: {:?}",
        decision.blockers
    );
}

#[test]
fn enrichment_single_bad_sample_among_many_can_still_pass_mean() {
    let mut request = good_request();
    // Add many good simple samples, then one with bad over-privilege
    request
        .samples
        .push(good_sample("ext-simple-2", PlasBenchmarkCohort::Simple));
    request
        .samples
        .push(good_sample("ext-simple-3", PlasBenchmarkCohort::Simple));
    request
        .samples
        .push(good_sample("ext-simple-4", PlasBenchmarkCohort::Simple));
    let mut bad = good_sample("ext-simple-bad", PlasBenchmarkCohort::Simple);
    bad.synthesized_capability_count = 8;
    bad.empirically_required_capability_count = 5; // 1.6x but mean of 5 samples ~1.12x
    request.samples.push(bad);
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    let simple = decision
        .cohort_summaries
        .iter()
        .find(|cs| cs.cohort == PlasBenchmarkCohort::Simple)
        .unwrap();
    // 4 samples at 1.0x + 1 at 1.6x → mean = (4*1_000_000 + 1_600_000)/5 = 1_120_000
    // Threshold = 1_100_000 → should fail
    assert!(!simple.over_privilege_ratio_threshold_pass);
}

#[test]
fn enrichment_many_historical_runs_no_crash() {
    let mut request = good_request();
    for i in 0..50 {
        request.historical_runs.push(PlasBenchmarkTrendPoint {
            benchmark_run_id: format!("run-{i}"),
            generated_at_ns: i as u64 * 1000,
            mean_over_privilege_ratio_millionths: 1_000_000,
            mean_authoring_time_reduction_millionths: 800_000,
            mean_false_deny_rate_millionths: 1_000,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 1_000_000,
        });
    }
    let decision = build_plas_benchmark_bundle(&request).unwrap();
    assert_eq!(decision.trend.len(), 51); // 50 historical + 1 current
}
