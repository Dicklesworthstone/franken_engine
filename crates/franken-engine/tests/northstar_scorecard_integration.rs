#![forbid(unsafe_code)]

//! Integration tests for `northstar_scorecard` — the North-Star Scorecard
//! objective metric stack covering Milestone, MetricKind, Threshold,
//! MetricSample, MetricSummary, ThresholdResult, ScorecardEvaluation,
//! Scorecard, and the `default_thresholds()` function.

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

use frankenengine_engine::northstar_scorecard::{
    MetricKind, MetricSample, MetricSummary, Milestone, Scorecard, ScorecardEvaluation, Threshold,
    ThresholdResult, default_thresholds,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample(kind: MetricKind, value: i64, ep: u64) -> MetricSample {
    MetricSample {
        kind,
        value,
        epoch: epoch(ep),
    }
}

/// Build a scorecard with all 10 metrics at GA-passing values.
fn ga_passing_scorecard() -> Scorecard {
    let mut sc = Scorecard::new(epoch(1));
    for _ in 0..20 {
        sc.record(sample(MetricKind::CompatibilityPassRate, 999_000, 1));
        sc.record(sample(MetricKind::ResponsivenessP99Us, 1_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
        sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
        sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
        sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
        sc.record(sample(MetricKind::EvidenceCompleteness, 999_000, 1));
    }
    sc
}

/// Build a scorecard with alpha-level data (passes alpha, may fail beta/GA).
fn alpha_passing_scorecard() -> Scorecard {
    let mut sc = Scorecard::new(epoch(1));
    for _ in 0..20 {
        sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
        sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1));
        sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
        sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1));
        sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
    }
    sc
}

// ===========================================================================
// Section 1: Milestone — Display, ordering, serde
// ===========================================================================

#[test]
fn milestone_display_alpha() {
    assert_eq!(format!("{}", Milestone::Alpha), "alpha");
}

#[test]
fn milestone_display_beta() {
    assert_eq!(format!("{}", Milestone::Beta), "beta");
}

#[test]
fn milestone_display_ga() {
    assert_eq!(format!("{}", Milestone::Ga), "ga");
}

#[test]
fn milestone_ordering_alpha_lt_beta_lt_ga() {
    assert!(Milestone::Alpha < Milestone::Beta);
    assert!(Milestone::Beta < Milestone::Ga);
    assert!(Milestone::Alpha < Milestone::Ga);
}

#[test]
fn milestone_clone_eq() {
    let a = Milestone::Alpha;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn milestone_serde_roundtrip_all() {
    for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
        let json = serde_json::to_string(&ms).unwrap();
        let back: Milestone = serde_json::from_str(&json).unwrap();
        assert_eq!(ms, back);
    }
}

#[test]
fn milestone_debug_not_empty() {
    let dbg = format!("{:?}", Milestone::Ga);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Ga"));
}

// ===========================================================================
// Section 2: MetricKind — ALL, Display, higher_is_better, serde
// ===========================================================================

#[test]
fn metric_kind_all_has_ten_entries() {
    assert_eq!(MetricKind::ALL.len(), 10);
}

#[test]
fn metric_kind_all_unique_display() {
    let displays: BTreeSet<String> = MetricKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn metric_kind_display_compatibility() {
    assert_eq!(
        MetricKind::CompatibilityPassRate.to_string(),
        "compatibility_pass_rate"
    );
}

#[test]
fn metric_kind_display_responsiveness() {
    assert_eq!(
        MetricKind::ResponsivenessP99Us.to_string(),
        "responsiveness_p99_us"
    );
}

#[test]
fn metric_kind_display_render_latencies() {
    assert_eq!(
        MetricKind::RenderLatencyP50Us.to_string(),
        "render_latency_p50_us"
    );
    assert_eq!(
        MetricKind::RenderLatencyP95Us.to_string(),
        "render_latency_p95_us"
    );
    assert_eq!(
        MetricKind::RenderLatencyP99Us.to_string(),
        "render_latency_p99_us"
    );
}

#[test]
fn metric_kind_display_size_metrics() {
    assert_eq!(MetricKind::BundleSizeBytes.to_string(), "bundle_size_bytes");
    assert_eq!(
        MetricKind::RuntimeMemoryBytes.to_string(),
        "runtime_memory_bytes"
    );
}

#[test]
fn metric_kind_display_fallback_rollback_evidence() {
    assert_eq!(
        MetricKind::FallbackFrequency.to_string(),
        "fallback_frequency"
    );
    assert_eq!(
        MetricKind::RollbackLatencyP99Us.to_string(),
        "rollback_latency_p99_us"
    );
    assert_eq!(
        MetricKind::EvidenceCompleteness.to_string(),
        "evidence_completeness"
    );
}

#[test]
fn metric_kind_higher_is_better_only_two() {
    let hib: Vec<_> = MetricKind::ALL
        .iter()
        .filter(|k| k.higher_is_better())
        .collect();
    assert_eq!(hib.len(), 2);
    assert!(MetricKind::CompatibilityPassRate.higher_is_better());
    assert!(MetricKind::EvidenceCompleteness.higher_is_better());
}

#[test]
fn metric_kind_lower_is_better_eight() {
    let lib: Vec<_> = MetricKind::ALL
        .iter()
        .filter(|k| !k.higher_is_better())
        .collect();
    assert_eq!(lib.len(), 8);
}

#[test]
fn metric_kind_serde_roundtrip_all() {
    for kind in &MetricKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: MetricKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// Section 3: Threshold and default_thresholds()
// ===========================================================================

#[test]
fn default_thresholds_has_thirty_entries() {
    let th = default_thresholds();
    assert_eq!(th.len(), 30); // 10 metrics * 3 milestones
}

#[test]
fn default_thresholds_cover_all_milestones_equally() {
    let th = default_thresholds();
    for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
        let count = th.iter().filter(|t| t.milestone == ms).count();
        assert_eq!(count, 10, "milestone {ms} should have 10 thresholds");
    }
}

#[test]
fn default_thresholds_cover_all_metrics() {
    let th = default_thresholds();
    for kind in &MetricKind::ALL {
        let count = th.iter().filter(|t| t.metric == *kind).count();
        assert_eq!(count, 3, "metric {kind} should have 3 thresholds");
    }
}

#[test]
fn default_thresholds_stricter_alpha_to_ga_hib() {
    // Higher-is-better: boundary increases from alpha to GA
    let th = default_thresholds();
    let cpr: Vec<_> = th
        .iter()
        .filter(|t| t.metric == MetricKind::CompatibilityPassRate)
        .collect();
    let alpha = cpr
        .iter()
        .find(|t| t.milestone == Milestone::Alpha)
        .unwrap();
    let beta = cpr.iter().find(|t| t.milestone == Milestone::Beta).unwrap();
    let ga = cpr.iter().find(|t| t.milestone == Milestone::Ga).unwrap();
    assert!(alpha.boundary < beta.boundary);
    assert!(beta.boundary < ga.boundary);
}

#[test]
fn default_thresholds_stricter_alpha_to_ga_lib() {
    // Lower-is-better: boundary decreases from alpha to GA
    let th = default_thresholds();
    let resp: Vec<_> = th
        .iter()
        .filter(|t| t.metric == MetricKind::ResponsivenessP99Us)
        .collect();
    let alpha = resp
        .iter()
        .find(|t| t.milestone == Milestone::Alpha)
        .unwrap();
    let beta = resp
        .iter()
        .find(|t| t.milestone == Milestone::Beta)
        .unwrap();
    let ga = resp.iter().find(|t| t.milestone == Milestone::Ga).unwrap();
    assert!(alpha.boundary > beta.boundary);
    assert!(beta.boundary > ga.boundary);
}

#[test]
fn threshold_serde_roundtrip() {
    let t = Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Beta,
        boundary: 5_000_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: Threshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn default_thresholds_serde_roundtrip() {
    let th = default_thresholds();
    let json = serde_json::to_string(&th).unwrap();
    let back: Vec<Threshold> = serde_json::from_str(&json).unwrap();
    assert_eq!(th.len(), back.len());
    for (a, b) in th.iter().zip(back.iter()) {
        assert_eq!(a, b);
    }
}

// ===========================================================================
// Section 4: MetricSample — construct, serde
// ===========================================================================

#[test]
fn metric_sample_construct_and_access() {
    let s = sample(MetricKind::CompatibilityPassRate, 950_000, 42);
    assert_eq!(s.kind, MetricKind::CompatibilityPassRate);
    assert_eq!(s.value, 950_000);
    assert_eq!(s.epoch, epoch(42));
}

#[test]
fn metric_sample_serde_roundtrip() {
    let s = sample(MetricKind::FallbackFrequency, 123_456, 7);
    let json = serde_json::to_string(&s).unwrap();
    let back: MetricSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn metric_sample_debug_not_empty() {
    let s = sample(MetricKind::BundleSizeBytes, 100, 1);
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("BundleSizeBytes"));
}

// ===========================================================================
// Section 5: MetricSummary — serde
// ===========================================================================

#[test]
fn metric_summary_serde_roundtrip() {
    let summary = MetricSummary {
        kind: MetricKind::RenderLatencyP50Us,
        count: 500,
        min: 100,
        max: 9900,
        mean: 5000,
        p50: 5000,
        p95: 9500,
        p99: 9900,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: MetricSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn metric_summary_debug_contains_kind() {
    let summary = MetricSummary {
        kind: MetricKind::BundleSizeBytes,
        count: 1,
        min: 42,
        max: 42,
        mean: 42,
        p50: 42,
        p95: 42,
        p99: 42,
    };
    let dbg = format!("{:?}", summary);
    assert!(dbg.contains("BundleSizeBytes"));
}

// ===========================================================================
// Section 6: ThresholdResult — is_pass, serde, variants
// ===========================================================================

#[test]
fn threshold_result_pass_is_pass() {
    let r = ThresholdResult::Pass {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Alpha,
        value: 900_000,
        threshold: 800_000,
        headroom: 100_000,
    };
    assert!(r.is_pass());
}

#[test]
fn threshold_result_fail_is_not_pass() {
    let r = ThresholdResult::Fail {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Ga,
        value: 5_000_000,
        threshold: 2_000_000,
        shortfall: 3_000_000,
    };
    assert!(!r.is_pass());
}

#[test]
fn threshold_result_insufficient_is_not_pass() {
    let r = ThresholdResult::InsufficientData {
        metric: MetricKind::RuntimeMemoryBytes,
        milestone: Milestone::Beta,
    };
    assert!(!r.is_pass());
}

#[test]
fn threshold_result_serde_roundtrip_all_variants() {
    let variants = vec![
        ThresholdResult::Pass {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            value: 995_000,
            threshold: 990_000,
            headroom: 5_000,
        },
        ThresholdResult::Fail {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Beta,
            value: 60_000,
            threshold: 50_000,
            shortfall: 10_000,
        },
        ThresholdResult::InsufficientData {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Alpha,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ThresholdResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Section 7: ScorecardEvaluation — serde
// ===========================================================================

#[test]
fn scorecard_evaluation_serde_roundtrip_empty() {
    let eval = ScorecardEvaluation {
        milestone: Milestone::Alpha,
        epoch: epoch(1),
        results: vec![],
        overall_pass: false,
        pass_count: 0,
        fail_count: 0,
        pass_rate_millionths: 0,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ScorecardEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn scorecard_evaluation_serde_roundtrip_with_results() {
    let eval = ScorecardEvaluation {
        milestone: Milestone::Ga,
        epoch: epoch(99),
        results: vec![
            ThresholdResult::Pass {
                metric: MetricKind::CompatibilityPassRate,
                milestone: Milestone::Ga,
                value: 999_000,
                threshold: 990_000,
                headroom: 9_000,
            },
            ThresholdResult::Fail {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Ga,
                value: 3_000_000,
                threshold: 2_000_000,
                shortfall: 1_000_000,
            },
        ],
        overall_pass: false,
        pass_count: 1,
        fail_count: 1,
        pass_rate_millionths: 500_000,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ScorecardEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// Section 8: Scorecard — construction, recording, summary
// ===========================================================================

#[test]
fn scorecard_new_empty() {
    let sc = Scorecard::new(epoch(1));
    assert_eq!(sc.total_observations(), 0);
    assert_eq!(sc.thresholds().len(), 30);
}

#[test]
fn scorecard_with_custom_thresholds() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 1_000,
    }];
    let sc = Scorecard::with_thresholds(th.clone(), epoch(5));
    assert_eq!(sc.thresholds().len(), 1);
    assert_eq!(sc.thresholds()[0].boundary, 1_000);
}

#[test]
fn scorecard_record_single_observation() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 4200, 2));
    assert_eq!(sc.observation_count(MetricKind::BundleSizeBytes), 1);
    assert_eq!(sc.total_observations(), 1);
}

#[test]
fn scorecard_record_multiple_same_metric() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..50 {
        sc.record(sample(MetricKind::RenderLatencyP50Us, i * 100, 1));
    }
    assert_eq!(sc.observation_count(MetricKind::RenderLatencyP50Us), 50);
}

#[test]
fn scorecard_record_multiple_different_metrics() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 2000, 1));
    sc.record(sample(MetricKind::FallbackFrequency, 3000, 1));
    assert_eq!(sc.observation_count(MetricKind::BundleSizeBytes), 1);
    assert_eq!(sc.observation_count(MetricKind::RuntimeMemoryBytes), 1);
    assert_eq!(sc.observation_count(MetricKind::FallbackFrequency), 1);
    assert_eq!(sc.total_observations(), 3);
}

#[test]
fn scorecard_no_data_summary_is_none() {
    let sc = Scorecard::new(epoch(1));
    assert!(sc.summary(MetricKind::BundleSizeBytes).is_none());
}

#[test]
fn scorecard_no_data_current_value_is_none() {
    let sc = Scorecard::new(epoch(1));
    assert!(sc.current_value(MetricKind::RenderLatencyP50Us).is_none());
}

#[test]
fn scorecard_summary_single_observation() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::RenderLatencyP50Us, 42, 1));
    let s = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
    assert_eq!(s.count, 1);
    assert_eq!(s.min, 42);
    assert_eq!(s.max, 42);
    assert_eq!(s.mean, 42);
    assert_eq!(s.p50, 42);
    assert_eq!(s.p95, 42);
    assert_eq!(s.p99, 42);
}

#[test]
fn scorecard_summary_two_observations() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 1));
    sc.record(sample(MetricKind::BundleSizeBytes, 200, 1));
    let s = sc.summary(MetricKind::BundleSizeBytes).unwrap();
    assert_eq!(s.count, 2);
    assert_eq!(s.min, 100);
    assert_eq!(s.max, 200);
    assert_eq!(s.mean, 150);
}

#[test]
fn scorecard_summary_hundred_observations() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::RenderLatencyP50Us, i * 100, 1));
    }
    let s = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
    assert_eq!(s.count, 100);
    assert_eq!(s.min, 0);
    assert_eq!(s.max, 9900);
    assert_eq!(s.p50, 5000);
    assert_eq!(s.p95, 9500);
    assert_eq!(s.p99, 9900);
}

// ===========================================================================
// Section 9: current_value — correct quantile/aggregation per MetricKind
// ===========================================================================

#[test]
fn current_value_compatibility_uses_mean() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 1_000_000, 1));
    // mean = 900_000
    assert_eq!(
        sc.current_value(MetricKind::CompatibilityPassRate),
        Some(900_000)
    );
}

#[test]
fn current_value_evidence_completeness_uses_mean() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::EvidenceCompleteness, 800_000, 1));
    sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
    assert_eq!(
        sc.current_value(MetricKind::EvidenceCompleteness),
        Some(700_000)
    );
}

#[test]
fn current_value_fallback_frequency_uses_mean() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
    sc.record(sample(MetricKind::FallbackFrequency, 200_000, 1));
    assert_eq!(
        sc.current_value(MetricKind::FallbackFrequency),
        Some(150_000)
    );
}

#[test]
fn current_value_responsiveness_p99_uses_p99() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::ResponsivenessP99Us, i * 100, 1));
    }
    assert_eq!(
        sc.current_value(MetricKind::ResponsivenessP99Us),
        Some(9900)
    );
}

#[test]
fn current_value_render_p50_uses_p50() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::RenderLatencyP50Us, i, 1));
    }
    assert_eq!(sc.current_value(MetricKind::RenderLatencyP50Us), Some(50));
}

#[test]
fn current_value_render_p95_uses_p95() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::RenderLatencyP95Us, i * 10, 1));
    }
    assert_eq!(sc.current_value(MetricKind::RenderLatencyP95Us), Some(950));
}

#[test]
fn current_value_render_p99_uses_p99() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::RenderLatencyP99Us, i, 1));
    }
    assert_eq!(sc.current_value(MetricKind::RenderLatencyP99Us), Some(99));
}

#[test]
fn current_value_rollback_latency_uses_p99() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..100 {
        sc.record(sample(MetricKind::RollbackLatencyP99Us, i * 1000, 1));
    }
    assert_eq!(
        sc.current_value(MetricKind::RollbackLatencyP99Us),
        Some(99_000)
    );
}

#[test]
fn current_value_bundle_size_uses_max() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 1_000, 1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
    sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
    assert_eq!(sc.current_value(MetricKind::BundleSizeBytes), Some(5_000));
}

#[test]
fn current_value_runtime_memory_uses_max() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000, 1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 50_000, 1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 30_000, 1));
    assert_eq!(
        sc.current_value(MetricKind::RuntimeMemoryBytes),
        Some(50_000)
    );
}

// ===========================================================================
// Section 10: evaluate — alpha, beta, GA, empty thresholds
// ===========================================================================

#[test]
fn evaluate_no_data_all_insufficient() {
    let sc = Scorecard::new(epoch(1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(!eval.overall_pass);
    assert_eq!(eval.pass_count, 0);
    assert_eq!(eval.fail_count, 10);
    for r in &eval.results {
        assert!(matches!(r, ThresholdResult::InsufficientData { .. }));
    }
}

#[test]
fn evaluate_alpha_passes_with_good_data() {
    let sc = alpha_passing_scorecard();
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(eval.overall_pass);
    assert_eq!(eval.pass_count, 10);
    assert_eq!(eval.fail_count, 0);
    assert_eq!(eval.pass_rate_millionths, 1_000_000);
}

#[test]
fn evaluate_ga_passes_with_excellent_data() {
    let sc = ga_passing_scorecard();
    let eval = sc.evaluate(Milestone::Ga);
    assert!(eval.overall_pass);
    assert_eq!(eval.pass_count, 10);
    assert_eq!(eval.fail_count, 0);
}

#[test]
fn evaluate_ga_fails_with_alpha_data() {
    let sc = alpha_passing_scorecard();
    let eval = sc.evaluate(Milestone::Ga);
    assert!(!eval.overall_pass);
    assert!(eval.fail_count > 0);
}

#[test]
fn evaluate_empty_thresholds_not_pass() {
    let sc = Scorecard::with_thresholds(vec![], epoch(1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(!eval.overall_pass);
    assert_eq!(eval.pass_count, 0);
    assert_eq!(eval.fail_count, 0);
    assert_eq!(eval.pass_rate_millionths, 0);
}

#[test]
fn evaluate_custom_threshold_pass() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 10_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(eval.overall_pass);
    assert_eq!(eval.pass_count, 1);
}

#[test]
fn evaluate_custom_threshold_fail() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 100,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(!eval.overall_pass);
    assert_eq!(eval.fail_count, 1);
}

#[test]
fn evaluate_pass_rate_fifty_percent() {
    let th = vec![
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        },
    ];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1)); // pass
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 20_000, 1)); // fail
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.pass_count, 1);
    assert_eq!(eval.fail_count, 1);
    assert_eq!(eval.pass_rate_millionths, 500_000);
    assert!(!eval.overall_pass);
}

#[test]
fn evaluate_pass_rate_hundred_percent() {
    let th = vec![
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        },
    ];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 5_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.pass_rate_millionths, 1_000_000);
    assert!(eval.overall_pass);
}

// ===========================================================================
// Section 11: headroom and shortfall
// ===========================================================================

#[test]
fn headroom_correct_higher_is_better() {
    let th = vec![Threshold {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Alpha,
        boundary: 800_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 950_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
        assert_eq!(*headroom, 150_000);
    } else {
        panic!("expected Pass");
    }
}

#[test]
fn headroom_correct_lower_is_better() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 10_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
        assert_eq!(*headroom, 7_000); // 10_000 - 3_000
    } else {
        panic!("expected Pass");
    }
}

#[test]
fn shortfall_correct_higher_is_better() {
    let th = vec![Threshold {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Alpha,
        boundary: 900_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    if let ThresholdResult::Fail { shortfall, .. } = &eval.results[0] {
        assert_eq!(*shortfall, 100_000);
    } else {
        panic!("expected Fail");
    }
}

#[test]
fn shortfall_correct_lower_is_better() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 1_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    if let ThresholdResult::Fail { shortfall, .. } = &eval.results[0] {
        assert_eq!(*shortfall, 2_000);
    } else {
        panic!("expected Fail");
    }
}

#[test]
fn exact_boundary_passes() {
    // Value exactly at boundary should pass for both higher-is-better and lower-is-better
    let th = vec![
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        },
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 5_000,
        },
    ];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(eval.overall_pass);
    assert_eq!(eval.pass_count, 2);
    // Headroom should be 0 for exact boundary
    for r in &eval.results {
        if let ThresholdResult::Pass { headroom, .. } = r {
            assert_eq!(*headroom, 0);
        }
    }
}

// ===========================================================================
// Section 12: highest_passing_milestone
// ===========================================================================

#[test]
fn highest_passing_milestone_none_when_empty() {
    let sc = Scorecard::new(epoch(1));
    assert_eq!(sc.highest_passing_milestone(), None);
}

#[test]
fn highest_passing_milestone_alpha() {
    let sc = alpha_passing_scorecard();
    assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Alpha));
}

#[test]
fn highest_passing_milestone_ga() {
    let sc = ga_passing_scorecard();
    assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Ga));
}

// ===========================================================================
// Section 13: set_epoch, epoch propagation
// ===========================================================================

#[test]
fn set_epoch_reflected_in_evaluation() {
    let mut sc = Scorecard::new(epoch(1));
    sc.set_epoch(epoch(42));
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.epoch, epoch(42));
}

#[test]
fn record_updates_epoch() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 99));
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.epoch, epoch(99));
}

// ===========================================================================
// Section 14: report() — string output
// ===========================================================================

#[test]
fn report_contains_milestone_name() {
    let sc = Scorecard::new(epoch(1));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("alpha"));
}

#[test]
fn report_insufficient_data_says_insufficient() {
    let sc = Scorecard::new(epoch(1));
    let report = sc.report(Milestone::Beta);
    assert!(report.contains("insufficient"));
    assert!(report.contains("FAIL"));
}

#[test]
fn report_passing_contains_pass() {
    let sc = ga_passing_scorecard();
    let report = sc.report(Milestone::Ga);
    assert!(report.contains("PASS"));
}

#[test]
fn report_contains_epoch() {
    let sc = Scorecard::new(epoch(77));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("77"));
}

#[test]
fn report_failing_metric_shows_fail_tag() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 100,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("[FAIL]"));
    assert!(report.contains("bundle_size_bytes"));
}

#[test]
fn report_passing_metric_shows_pass_tag() {
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 10_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("[PASS]"));
}

// ===========================================================================
// Section 15: Scorecard serde round-trip
// ===========================================================================

#[test]
fn scorecard_serde_roundtrip_empty() {
    let sc = Scorecard::new(epoch(1));
    let json = serde_json::to_string(&sc).unwrap();
    let back: Scorecard = serde_json::from_str(&json).unwrap();
    assert_eq!(sc.total_observations(), back.total_observations());
    assert_eq!(sc.thresholds().len(), back.thresholds().len());
}

#[test]
fn scorecard_serde_roundtrip_with_data() {
    let mut sc = Scorecard::new(epoch(5));
    sc.record(sample(MetricKind::BundleSizeBytes, 1000, 5));
    sc.record(sample(MetricKind::BundleSizeBytes, 2000, 5));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 3000, 5));
    let json = serde_json::to_string(&sc).unwrap();
    let back: Scorecard = serde_json::from_str(&json).unwrap();
    assert_eq!(sc.total_observations(), back.total_observations());
    assert_eq!(
        sc.current_value(MetricKind::BundleSizeBytes),
        back.current_value(MetricKind::BundleSizeBytes)
    );
}

// ===========================================================================
// Section 16: Determinism and edge cases
// ===========================================================================

#[test]
fn deterministic_evaluation_identical_builds() {
    let build = || {
        let mut sc = Scorecard::new(epoch(5));
        for i in 0..50 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 950_000 + i, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 1_000_000 + i * 100, 1));
        }
        sc
    };
    let eval1 = build().evaluate(Milestone::Alpha);
    let eval2 = build().evaluate(Milestone::Alpha);
    assert_eq!(eval1.pass_count, eval2.pass_count);
    assert_eq!(eval1.fail_count, eval2.fail_count);
    assert_eq!(eval1.overall_pass, eval2.overall_pass);
    assert_eq!(eval1.pass_rate_millionths, eval2.pass_rate_millionths);
}

#[test]
fn observation_count_unrecorded_metric_is_zero() {
    let sc = Scorecard::new(epoch(1));
    for kind in &MetricKind::ALL {
        assert_eq!(sc.observation_count(*kind), 0);
    }
}

#[test]
fn scorecard_many_observations_thousand() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..1000 {
        sc.record(sample(MetricKind::RenderLatencyP50Us, i, 1));
    }
    assert_eq!(sc.observation_count(MetricKind::RenderLatencyP50Us), 1000);
    assert_eq!(sc.total_observations(), 1000);
    let s = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
    assert_eq!(s.min, 0);
    assert_eq!(s.max, 999);
}

#[test]
fn evaluate_beta_stricter_than_alpha() {
    let sc = alpha_passing_scorecard();
    let alpha_eval = sc.evaluate(Milestone::Alpha);
    let beta_eval = sc.evaluate(Milestone::Beta);
    // Beta is stricter: at least as many failures as alpha
    assert!(beta_eval.fail_count >= alpha_eval.fail_count);
}

#[test]
fn evaluate_unmatched_milestone_thresholds_ignored() {
    // Only define Alpha thresholds; evaluating Beta should find nothing
    let th = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 10_000,
    }];
    let mut sc = Scorecard::with_thresholds(th, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let eval = sc.evaluate(Milestone::Beta);
    // No thresholds match Beta, so no results
    assert_eq!(eval.results.len(), 0);
    assert!(!eval.overall_pass);
}

#[test]
fn scorecard_debug_not_empty() {
    let sc = Scorecard::new(epoch(1));
    let dbg = format!("{:?}", sc);
    assert!(!dbg.is_empty());
}

#[test]
fn sorted_insertion_order_independent() {
    // Observations should be sorted regardless of insertion order
    let mut sc1 = Scorecard::new(epoch(1));
    sc1.record(sample(MetricKind::BundleSizeBytes, 300, 1));
    sc1.record(sample(MetricKind::BundleSizeBytes, 100, 1));
    sc1.record(sample(MetricKind::BundleSizeBytes, 200, 1));

    let mut sc2 = Scorecard::new(epoch(1));
    sc2.record(sample(MetricKind::BundleSizeBytes, 100, 1));
    sc2.record(sample(MetricKind::BundleSizeBytes, 200, 1));
    sc2.record(sample(MetricKind::BundleSizeBytes, 300, 1));

    let s1 = sc1.summary(MetricKind::BundleSizeBytes).unwrap();
    let s2 = sc2.summary(MetricKind::BundleSizeBytes).unwrap();
    assert_eq!(s1, s2);
}
