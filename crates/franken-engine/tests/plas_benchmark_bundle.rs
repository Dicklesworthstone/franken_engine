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
    PlasBenchmarkBundleDecision, PlasBenchmarkBundleError, PlasBenchmarkBundleEvent,
    PlasBenchmarkBundleRequest, PlasBenchmarkCohort, PlasBenchmarkCohortSummary,
    PlasBenchmarkExtensionResult, PlasBenchmarkExtensionSample, PlasBenchmarkOverallSummary,
    PlasBenchmarkThresholds, PlasBenchmarkTrendPoint, build_plas_benchmark_bundle,
};

fn base_sample(extension_id: &str, cohort: PlasBenchmarkCohort) -> PlasBenchmarkExtensionSample {
    PlasBenchmarkExtensionSample {
        extension_id: extension_id.to_string(),
        cohort,
        synthesized_capability_count: 11,
        empirically_required_capability_count: 10,
        manual_authoring_time_ms: 1_000,
        plas_authoring_time_ms: 250,
        benign_request_count: 10_000,
        benign_false_deny_count: 30,
        escrow_event_count: 4,
        observation_window_ns: 3_600_000_000_000,
        witness_present: true,
    }
}

fn representative_samples() -> Vec<PlasBenchmarkExtensionSample> {
    vec![
        base_sample("ext-simple", PlasBenchmarkCohort::Simple),
        base_sample("ext-complex", PlasBenchmarkCohort::Complex),
        base_sample("ext-high-risk", PlasBenchmarkCohort::HighRisk),
        base_sample("ext-boundary", PlasBenchmarkCohort::Boundary),
    ]
}

fn request_with_samples(samples: Vec<PlasBenchmarkExtensionSample>) -> PlasBenchmarkBundleRequest {
    PlasBenchmarkBundleRequest {
        trace_id: "trace-plas-benchmark".to_string(),
        decision_id: "decision-plas-benchmark".to_string(),
        policy_id: "policy-plas-v1".to_string(),
        benchmark_run_id: "run-001".to_string(),
        generated_at_ns: 1_710_000_000_000_000_000,
        samples,
        historical_runs: Vec::new(),
        thresholds: None,
    }
}

#[test]
fn bundle_allows_publication_when_thresholds_pass_for_all_cohorts() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert_eq!(
        decision.schema_version,
        PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION
    );
    assert!(decision.publish_allowed);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.cohort_summaries.len(), 4);
    assert!(decision.overall_summary.required_cohorts_present);
    assert_eq!(decision.trend.len(), 1);

    let json = decision.to_json_pretty().expect("json should serialize");
    assert!(json.contains("plas-bundle-"));

    let markdown = decision.to_markdown_report();
    assert!(markdown.contains("# PLAS Benchmark Bundle"));
    assert!(markdown.contains("## Cohort Summary"));
}

#[test]
fn bundle_denies_when_false_deny_threshold_exceeded() {
    let mut samples = representative_samples();
    samples[2].benign_false_deny_count = 90; // 0.9%

    let request = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("false-deny"))
    );
    assert!(decision
        .events
        .iter()
        .any(|event| event.event == "plas_benchmark_bundle_decision" && event.outcome == "deny"));
}

#[test]
fn bundle_denies_when_required_cohort_is_missing() {
    let mut samples = representative_samples();
    samples.retain(|sample| sample.cohort != PlasBenchmarkCohort::Boundary);

    let request = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("missing representative cohort coverage"))
    );
}

#[test]
fn trend_regression_is_detected_without_blocking_by_default() {
    let mut request = request_with_samples(representative_samples());
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-000".to_string(),
        generated_at_ns: request.generated_at_ns - 1,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 2_000_000,
        witness_coverage_millionths: 1_000_000,
    });

    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(decision.trend_regression_detected);
    assert!(decision.publish_allowed);
    assert!(
        decision
            .events
            .iter()
            .any(|event| event.event == "trend_regression_check" && event.outcome == "warn")
    );
}

#[test]
fn trend_regression_can_block_when_configured() {
    let mut request = request_with_samples(representative_samples());
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-000".to_string(),
        generated_at_ns: request.generated_at_ns - 1,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 2_000_000,
        witness_coverage_millionths: 1_000_000,
    });

    request.thresholds = Some(PlasBenchmarkThresholds {
        fail_on_trend_regression: true,
        ..PlasBenchmarkThresholds::default()
    });

    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(decision.trend_regression_detected);
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("trend regression detected"))
    );
}

#[test]
fn bundle_id_is_deterministic_for_reordered_samples() {
    let request_a = request_with_samples(representative_samples());

    let mut reordered = representative_samples();
    reordered.reverse();
    let request_b = request_with_samples(reordered);

    let decision_a = build_plas_benchmark_bundle(&request_a).expect("bundle A should build");
    let decision_b = build_plas_benchmark_bundle(&request_b).expect("bundle B should build");

    assert_eq!(decision_a.bundle_id, decision_b.bundle_id);
    assert_eq!(decision_a.extension_results, decision_b.extension_results);
    assert_eq!(decision_a.cohort_summaries, decision_b.cohort_summaries);
    assert_eq!(decision_a.overall_summary, decision_b.overall_summary);
    assert_eq!(decision_a.publish_allowed, decision_b.publish_allowed);
}

// ---------- base_sample helper ----------

#[test]
fn base_sample_sets_correct_fields() {
    let s = base_sample("ext-test", PlasBenchmarkCohort::Simple);
    assert_eq!(s.extension_id, "ext-test");
    assert_eq!(s.cohort, PlasBenchmarkCohort::Simple);
    assert_eq!(s.synthesized_capability_count, 11);
    assert_eq!(s.empirically_required_capability_count, 10);
    assert!(s.witness_present);
}

// ---------- representative_samples ----------

#[test]
fn representative_samples_cover_all_cohorts() {
    let samples = representative_samples();
    assert_eq!(samples.len(), 4);
    let cohorts: Vec<_> = samples.iter().map(|s| s.cohort).collect();
    assert!(cohorts.contains(&PlasBenchmarkCohort::Simple));
    assert!(cohorts.contains(&PlasBenchmarkCohort::Complex));
    assert!(cohorts.contains(&PlasBenchmarkCohort::HighRisk));
    assert!(cohorts.contains(&PlasBenchmarkCohort::Boundary));
}

// ---------- PlasBenchmarkCohort ----------

#[test]
fn plas_benchmark_cohort_serde_roundtrip() {
    for cohort in [
        PlasBenchmarkCohort::Simple,
        PlasBenchmarkCohort::Complex,
        PlasBenchmarkCohort::HighRisk,
        PlasBenchmarkCohort::Boundary,
    ] {
        let json = serde_json::to_string(&cohort).expect("serialize");
        let recovered: PlasBenchmarkCohort = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, cohort);
    }
}

// ---------- PlasBenchmarkExtensionSample ----------

#[test]
fn extension_sample_serde_roundtrip() {
    let s = base_sample("ext-serde", PlasBenchmarkCohort::Complex);
    let json = serde_json::to_string(&s).expect("serialize");
    let recovered: PlasBenchmarkExtensionSample = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.extension_id, "ext-serde");
    assert_eq!(recovered.cohort, PlasBenchmarkCohort::Complex);
}

// ---------- PlasBenchmarkBundleRequest ----------

#[test]
fn request_serde_roundtrip() {
    let req = request_with_samples(representative_samples());
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: PlasBenchmarkBundleRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-plas-benchmark");
    assert_eq!(recovered.samples.len(), 4);
}

// ---------- PlasBenchmarkThresholds ----------

#[test]
fn default_thresholds_do_not_fail_on_trend() {
    let t = PlasBenchmarkThresholds::default();
    assert!(!t.fail_on_trend_regression);
}

// ---------- PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION ----------

#[test]
fn schema_version_constant_is_nonempty() {
    assert!(!PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION.is_empty());
    assert!(PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION.contains("plas"));
}

// ---------- decision events ----------

#[test]
fn decision_events_have_correct_trace_ids() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-plas-benchmark");
        assert_eq!(event.decision_id, "decision-plas-benchmark");
        assert_eq!(event.policy_id, "policy-plas-v1");
    }
}

// ---------- to_markdown_report ----------

#[test]
fn markdown_report_contains_cohort_names() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    let md = decision.to_markdown_report();
    assert!(md.contains("Simple") || md.contains("simple"));
    assert!(md.contains("Complex") || md.contains("complex"));
}

// ---------- PlasBenchmarkTrendPoint ----------

#[test]
fn trend_point_serde_roundtrip() {
    let point = PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-serde".to_string(),
        generated_at_ns: 1_000_000,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 2_000_000,
        witness_coverage_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&point).expect("serialize");
    let recovered: PlasBenchmarkTrendPoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.benchmark_run_id, "run-serde");
}

// ---------- empty samples ----------

#[test]
fn bundle_with_empty_samples_returns_error() {
    let request = request_with_samples(Vec::new());
    let err = build_plas_benchmark_bundle(&request).expect_err("empty samples should be rejected");
    let msg = err.to_string();
    assert!(msg.contains("samples") || msg.contains("empty"));
}

// ---------- bundle_id starts with plas-bundle- ----------

#[test]
fn bundle_id_starts_with_plas_bundle_prefix() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle");
    assert!(
        decision.bundle_id.starts_with("plas-bundle-"),
        "bundle_id should start with 'plas-bundle-', got: {}",
        decision.bundle_id
    );
}

// ---------- witness coverage is tracked ----------

#[test]
fn bundle_tracks_witness_coverage() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle");
    assert!(decision.overall_summary.witness_coverage_millionths > 0);
}

// ---------- bundle denies on missing witness ----------

#[test]
fn bundle_extension_result_reflects_witness_absence() {
    let mut samples = representative_samples();
    samples[0].witness_present = false;
    let request = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&request).expect("bundle");
    let ext_result = decision
        .extension_results
        .iter()
        .find(|r| r.extension_id == "ext-simple")
        .expect("ext-simple result");
    assert!(!ext_result.witness_present);
}

// ---------- to_json_pretty is valid JSON ----------

#[test]
fn bundle_to_json_pretty_is_valid_json() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle");
    let json = decision.to_json_pretty().expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert!(parsed.is_object());
}

// ---------- enrichment: error types ----------

#[test]
fn plas_bundle_error_display_is_nonempty() {
    let err = PlasBenchmarkBundleError::InvalidInput {
        field: "samples".to_string(),
        detail: "must not be empty".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("samples"));
}

#[test]
fn plas_bundle_error_duplicate_extension_display() {
    let err = PlasBenchmarkBundleError::DuplicateExtensionId {
        extension_id: "ext-dup".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-dup"));
}

#[test]
fn plas_bundle_error_stable_codes_are_nonempty() {
    let errors: Vec<PlasBenchmarkBundleError> = vec![
        PlasBenchmarkBundleError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        },
        PlasBenchmarkBundleError::DuplicateExtensionId {
            extension_id: "e".to_string(),
        },
        PlasBenchmarkBundleError::SerializationFailure("s".to_string()),
    ];
    for err in &errors {
        assert!(!err.stable_code().is_empty());
    }
}

#[test]
fn plas_bundle_error_is_std_error() {
    let err = PlasBenchmarkBundleError::SerializationFailure("test".to_string());
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn bundle_denies_duplicate_extension_ids() {
    let mut samples = representative_samples();
    samples.push(base_sample("ext-simple", PlasBenchmarkCohort::Simple));
    let request = request_with_samples(samples);
    let err = build_plas_benchmark_bundle(&request)
        .expect_err("duplicate extension_id should be rejected");
    assert!(err.to_string().contains("ext-simple"));
}

// ---------- enrichment: validation, thresholds, boundary values ----------

#[test]
fn sample_with_zero_synthesized_capability_count_rejected() {
    let mut samples = representative_samples();
    samples[0].synthesized_capability_count = 0;
    let request = request_with_samples(samples);
    let err = build_plas_benchmark_bundle(&request).expect_err("zero capability count");
    let msg = err.to_string();
    assert!(
        msg.contains("synthesized_capability_count"),
        "error should mention the invalid field: {msg}"
    );
}

#[test]
fn custom_thresholds_with_zero_over_privilege_ratio_rejected() {
    let mut request = request_with_samples(representative_samples());
    request.thresholds = Some(PlasBenchmarkThresholds {
        max_over_privilege_ratio_millionths: 0,
        ..PlasBenchmarkThresholds::default()
    });
    let err = build_plas_benchmark_bundle(&request).expect_err("invalid threshold");
    let msg = err.to_string();
    assert!(
        msg.contains("max_over_privilege_ratio_millionths"),
        "error should reference the threshold field: {msg}"
    );
}

#[test]
fn cohort_summary_serde_roundtrip() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle");
    for summary in &decision.cohort_summaries {
        let json = serde_json::to_string(summary).expect("serialize cohort summary");
        let recovered: PlasBenchmarkCohortSummary =
            serde_json::from_str(&json).expect("deserialize cohort summary");
        assert_eq!(*summary, recovered);
    }
}

#[test]
fn sample_with_false_deny_exceeding_benign_requests_rejected() {
    let mut samples = representative_samples();
    samples[1].benign_false_deny_count = samples[1].benign_request_count + 1;
    let request = request_with_samples(samples);
    let err = build_plas_benchmark_bundle(&request).expect_err("false_deny > benign_requests");
    let msg = err.to_string();
    assert!(
        msg.contains("benign_false_deny_count"),
        "error should mention benign_false_deny_count: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Enrichment: untested public API surface
// ---------------------------------------------------------------------------

// ---------- PLAS_BENCHMARK_BUNDLE_COMPONENT ----------

#[test]
fn component_constant_matches_expected_value() {
    assert_eq!(PLAS_BENCHMARK_BUNDLE_COMPONENT, "plas_benchmark_bundle");
}

// ---------- PlasBenchmarkCohort::as_str ----------

#[test]
fn cohort_as_str_covers_all_variants() {
    assert_eq!(PlasBenchmarkCohort::Simple.as_str(), "simple");
    assert_eq!(PlasBenchmarkCohort::Complex.as_str(), "complex");
    assert_eq!(PlasBenchmarkCohort::HighRisk.as_str(), "high_risk");
    assert_eq!(PlasBenchmarkCohort::Boundary.as_str(), "boundary");
}

// ---------- PlasBenchmarkCohort::all ----------

#[test]
fn cohort_all_returns_exactly_four_variants() {
    let all = PlasBenchmarkCohort::all();
    assert_eq!(all.len(), 4);
    let set: std::collections::BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(set.len(), 4, "all() variants must be unique");
}

// ---------- request validation: empty string fields ----------

#[test]
fn empty_trace_id_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.trace_id = String::new();
    let err = build_plas_benchmark_bundle(&req).expect_err("empty trace_id");
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn empty_decision_id_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.decision_id = String::new();
    let err = build_plas_benchmark_bundle(&req).expect_err("empty decision_id");
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn empty_policy_id_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.policy_id = String::new();
    let err = build_plas_benchmark_bundle(&req).expect_err("empty policy_id");
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn empty_benchmark_run_id_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.benchmark_run_id = String::new();
    let err = build_plas_benchmark_bundle(&req).expect_err("empty benchmark_run_id");
    assert!(err.to_string().contains("benchmark_run_id"));
}

// ---------- sample validation: zero fields ----------

#[test]
fn sample_with_empty_extension_id_rejected() {
    let mut samples = representative_samples();
    samples[0].extension_id = String::new();
    let err = build_plas_benchmark_bundle(&request_with_samples(samples))
        .expect_err("empty extension_id");
    assert!(err.to_string().contains("extension_id"));
}

#[test]
fn sample_with_zero_empirically_required_capability_count_rejected() {
    let mut samples = representative_samples();
    samples[0].empirically_required_capability_count = 0;
    let err = build_plas_benchmark_bundle(&request_with_samples(samples))
        .expect_err("zero empirically_required_capability_count");
    assert!(
        err.to_string()
            .contains("empirically_required_capability_count")
    );
}

#[test]
fn sample_with_zero_manual_authoring_time_rejected() {
    let mut samples = representative_samples();
    samples[0].manual_authoring_time_ms = 0;
    let err = build_plas_benchmark_bundle(&request_with_samples(samples))
        .expect_err("zero manual_authoring_time_ms");
    assert!(err.to_string().contains("manual_authoring_time_ms"));
}

#[test]
fn sample_with_zero_benign_request_count_rejected() {
    let mut samples = representative_samples();
    samples[0].benign_request_count = 0;
    let err = build_plas_benchmark_bundle(&request_with_samples(samples))
        .expect_err("zero benign_request_count");
    assert!(err.to_string().contains("benign_request_count"));
}

#[test]
fn sample_with_zero_observation_window_rejected() {
    let mut samples = representative_samples();
    samples[0].observation_window_ns = 0;
    let err = build_plas_benchmark_bundle(&request_with_samples(samples))
        .expect_err("zero observation_window_ns");
    assert!(err.to_string().contains("observation_window_ns"));
}

// ---------- threshold validation edge cases ----------

#[test]
fn threshold_false_deny_rate_exceeding_million_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.thresholds = Some(PlasBenchmarkThresholds {
        max_false_deny_rate_millionths: 1_000_001,
        ..PlasBenchmarkThresholds::default()
    });
    let err = build_plas_benchmark_bundle(&req).expect_err("false deny rate > 1M");
    assert!(err.to_string().contains("max_false_deny_rate_millionths"));
}

#[test]
fn threshold_witness_coverage_exceeding_million_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.thresholds = Some(PlasBenchmarkThresholds {
        min_witness_coverage_millionths: 1_000_001,
        ..PlasBenchmarkThresholds::default()
    });
    assert!(build_plas_benchmark_bundle(&req).is_err());
}

#[test]
fn threshold_zero_escrow_event_rate_rejected() {
    let mut req = request_with_samples(representative_samples());
    req.thresholds = Some(PlasBenchmarkThresholds {
        max_escrow_event_rate_per_hour_millionths: Some(0),
        ..PlasBenchmarkThresholds::default()
    });
    let err = build_plas_benchmark_bundle(&req).expect_err("zero escrow rate");
    assert!(
        err.to_string()
            .contains("max_escrow_event_rate_per_hour_millionths")
    );
}

// ---------- serde roundtrips for output types ----------

#[test]
fn extension_result_serde_roundtrip() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    for result in &decision.extension_results {
        let json = serde_json::to_string(result).expect("serialize");
        let recovered: PlasBenchmarkExtensionResult =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*result, recovered);
    }
}

#[test]
fn overall_summary_serde_roundtrip() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    let json = serde_json::to_string(&decision.overall_summary).expect("serialize");
    let recovered: PlasBenchmarkOverallSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision.overall_summary, recovered);
}

#[test]
fn bundle_decision_serde_roundtrip() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: PlasBenchmarkBundleDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, recovered);
}

#[test]
fn bundle_event_serde_roundtrip() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    assert!(!decision.events.is_empty());
    for event in &decision.events {
        let json = serde_json::to_string(event).expect("serialize");
        let recovered: PlasBenchmarkBundleEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, recovered);
    }
}

// ---------- no trend regression when no history ----------

#[test]
fn no_trend_regression_when_no_historical_runs() {
    let req = request_with_samples(representative_samples());
    assert!(req.historical_runs.is_empty());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    assert!(!decision.trend_regression_detected);
}

// ---------- markdown report with blockers ----------

#[test]
fn markdown_report_with_blockers_contains_blockers_section() {
    let mut samples = representative_samples();
    samples.retain(|s| s.cohort != PlasBenchmarkCohort::Boundary);
    let req = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    assert!(!decision.publish_allowed);
    let md = decision.to_markdown_report();
    assert!(
        md.contains("## Blockers"),
        "markdown must show Blockers section"
    );
    assert!(md.contains("DENY"), "markdown must show DENY gate");
}

// ---------- cohort summary pass flags ----------

#[test]
fn cohort_summaries_all_pass_for_representative_samples() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    for summary in &decision.cohort_summaries {
        assert!(
            summary.pass,
            "cohort {:?} should pass with representative samples",
            summary.cohort
        );
        assert!(summary.over_privilege_ratio_threshold_pass);
        assert!(summary.false_deny_rate_threshold_pass);
        assert!(summary.witness_coverage_threshold_pass);
    }
}

// ---------- overall summary field completeness ----------

#[test]
fn overall_summary_extension_count_matches_samples() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    assert_eq!(decision.overall_summary.extension_count, 4);
    assert_eq!(decision.overall_summary.cohorts_present.len(), 4);
    assert!(decision.overall_summary.required_cohorts_present);
    assert!(decision.overall_summary.over_privilege_ratio_threshold_pass);
    assert!(decision.overall_summary.false_deny_rate_threshold_pass);
    assert!(decision.overall_summary.witness_coverage_threshold_pass);
}

// ---------- events have component field ----------

#[test]
fn all_events_have_component_field_set() {
    let req = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&req).expect("build");
    for event in &decision.events {
        assert_eq!(
            event.component, PLAS_BENCHMARK_BUNDLE_COMPONENT,
            "event component must match PLAS_BENCHMARK_BUNDLE_COMPONENT"
        );
    }
}

// ---------- decision serialization is deterministic ----------

#[test]
fn decision_serialization_is_deterministic() {
    let req = request_with_samples(representative_samples());
    let a = build_plas_benchmark_bundle(&req).expect("build a");
    let b = build_plas_benchmark_bundle(&req).expect("build b");
    let json_a = serde_json::to_string(&a).expect("serialize a");
    let json_b = serde_json::to_string(&b).expect("serialize b");
    assert_eq!(json_a, json_b);
}
