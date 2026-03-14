//! Enrichment integration tests for `northstar_scorecard`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, Clone independence, determinism, and
//! cross-cutting invariants NOT already tested in the base integration file.

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

// ===========================================================================
// Milestone enrichment
// ===========================================================================

#[test]
fn enrichment_milestone_copy_semantics() {
    let a = Milestone::Alpha;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_milestone_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
        set.insert(ms);
        set.insert(ms);
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_milestone_debug_all_unique() {
    let debugs: BTreeSet<String> = [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
        .iter()
        .map(|m| format!("{m:?}"))
        .collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_milestone_display_all_unique() {
    let displays: BTreeSet<String> = [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
        .iter()
        .map(|m| m.to_string())
        .collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// MetricKind enrichment
// ===========================================================================

#[test]
fn enrichment_metric_kind_copy_semantics() {
    let a = MetricKind::BundleSizeBytes;
    let b = a;
    assert_eq!(a, b);
    assert!(!b.higher_is_better());
}

#[test]
fn enrichment_metric_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &k in &MetricKind::ALL {
        set.insert(k);
        set.insert(k);
    }
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_metric_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = MetricKind::ALL.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 10);
}

// ===========================================================================
// Threshold enrichment
// ===========================================================================

#[test]
fn enrichment_threshold_clone_independence() {
    let original = Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 10_000,
    };
    let mut cloned = original.clone();
    cloned.boundary = 99_999;
    assert_eq!(original.boundary, 10_000);
    assert_eq!(cloned.boundary, 99_999);
}

#[test]
fn enrichment_threshold_json_field_names() {
    let t = Threshold {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Ga,
        boundary: 990_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"milestone\""));
    assert!(json.contains("\"boundary\""));
}

#[test]
fn enrichment_threshold_debug_nonempty() {
    let t = Threshold {
        metric: MetricKind::FallbackFrequency,
        milestone: Milestone::Beta,
        boundary: 50_000,
    };
    let dbg = format!("{t:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Threshold"));
}

// ===========================================================================
// MetricSample enrichment
// ===========================================================================

#[test]
fn enrichment_metric_sample_clone_independence() {
    let original = sample(MetricKind::BundleSizeBytes, 5000, 1);
    let mut cloned = original.clone();
    cloned.value = 9999;
    assert_eq!(original.value, 5000);
    assert_eq!(cloned.value, 9999);
}

#[test]
fn enrichment_metric_sample_json_field_names() {
    let s = sample(MetricKind::CompatibilityPassRate, 950_000, 42);
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"value\""));
    assert!(json.contains("\"epoch\""));
}

// ===========================================================================
// MetricSummary enrichment
// ===========================================================================

#[test]
fn enrichment_metric_summary_clone_independence() {
    let original = MetricSummary {
        kind: MetricKind::RenderLatencyP50Us,
        count: 100,
        min: 0,
        max: 9900,
        mean: 5000,
        p50: 5000,
        p95: 9500,
        p99: 9900,
    };
    let mut cloned = original.clone();
    cloned.count = 999;
    assert_eq!(original.count, 100);
    assert_eq!(cloned.count, 999);
}

#[test]
fn enrichment_metric_summary_json_field_names() {
    let s = MetricSummary {
        kind: MetricKind::BundleSizeBytes,
        count: 10,
        min: 100,
        max: 1000,
        mean: 500,
        p50: 500,
        p95: 950,
        p99: 990,
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"count\""));
    assert!(json.contains("\"min\""));
    assert!(json.contains("\"max\""));
    assert!(json.contains("\"mean\""));
    assert!(json.contains("\"p50\""));
    assert!(json.contains("\"p95\""));
    assert!(json.contains("\"p99\""));
}

// ===========================================================================
// ThresholdResult enrichment
// ===========================================================================

#[test]
fn enrichment_threshold_result_clone_independence() {
    let original = ThresholdResult::Pass {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Ga,
        value: 995_000,
        threshold: 990_000,
        headroom: 5_000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_threshold_result_debug_all_variants_unique() {
    let variants = vec![
        ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        },
        ThresholdResult::Fail {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Ga,
            value: 5_000_000,
            threshold: 2_000_000,
            shortfall: 3_000_000,
        },
        ThresholdResult::InsufficientData {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Beta,
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_threshold_result_json_field_names_pass() {
    let r = ThresholdResult::Pass {
        metric: MetricKind::EvidenceCompleteness,
        milestone: Milestone::Ga,
        value: 999_000,
        threshold: 990_000,
        headroom: 9_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"milestone\""));
    assert!(json.contains("\"value\""));
    assert!(json.contains("\"threshold\""));
    assert!(json.contains("\"headroom\""));
}

#[test]
fn enrichment_threshold_result_json_field_names_fail() {
    let r = ThresholdResult::Fail {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Beta,
        value: 8_000_000,
        threshold: 5_000_000,
        shortfall: 3_000_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"shortfall\""));
}

// ===========================================================================
// ScorecardEvaluation enrichment
// ===========================================================================

#[test]
fn enrichment_scorecard_evaluation_clone_independence() {
    let original = ScorecardEvaluation {
        milestone: Milestone::Ga,
        epoch: epoch(1),
        results: vec![ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Ga,
            value: 999_000,
            threshold: 990_000,
            headroom: 9_000,
        }],
        overall_pass: true,
        pass_count: 1,
        fail_count: 0,
        pass_rate_millionths: 1_000_000,
    };
    let mut cloned = original.clone();
    cloned.overall_pass = false;
    assert!(original.overall_pass);
    assert!(!cloned.overall_pass);
}

#[test]
fn enrichment_scorecard_evaluation_json_field_names() {
    let eval = ScorecardEvaluation {
        milestone: Milestone::Alpha,
        epoch: epoch(5),
        results: vec![],
        overall_pass: false,
        pass_count: 0,
        fail_count: 0,
        pass_rate_millionths: 0,
    };
    let json = serde_json::to_string(&eval).unwrap();
    assert!(json.contains("\"milestone\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"results\""));
    assert!(json.contains("\"overall_pass\""));
    assert!(json.contains("\"pass_count\""));
    assert!(json.contains("\"fail_count\""));
    assert!(json.contains("\"pass_rate_millionths\""));
}

#[test]
fn enrichment_scorecard_evaluation_debug_nonempty() {
    let eval = ScorecardEvaluation {
        milestone: Milestone::Beta,
        epoch: epoch(1),
        results: vec![],
        overall_pass: false,
        pass_count: 0,
        fail_count: 0,
        pass_rate_millionths: 0,
    };
    let dbg = format!("{eval:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ScorecardEvaluation"));
}

// ===========================================================================
// Scorecard enrichment
// ===========================================================================

#[test]
fn enrichment_scorecard_clone_independence() {
    let mut original = Scorecard::new(epoch(1));
    original.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
    let cloned = original.clone();
    original.record(sample(MetricKind::BundleSizeBytes, 2000, 2));
    assert_eq!(cloned.observation_count(MetricKind::BundleSizeBytes), 1);
    assert_eq!(original.observation_count(MetricKind::BundleSizeBytes), 2);
}

#[test]
fn enrichment_scorecard_evaluate_determinism_five_runs() {
    let build = || {
        let mut sc = Scorecard::new(epoch(5));
        for i in 0..50 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 950_000 + i, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 1_000_000 + i * 100, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 10_000 + i, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 5_000 + i, 1));
        }
        sc
    };
    let first = build().evaluate(Milestone::Alpha);
    for _ in 0..4 {
        let again = build().evaluate(Milestone::Alpha);
        assert_eq!(first.pass_count, again.pass_count);
        assert_eq!(first.fail_count, again.fail_count);
        assert_eq!(first.overall_pass, again.overall_pass);
        assert_eq!(first.pass_rate_millionths, again.pass_rate_millionths);
        assert_eq!(first.results.len(), again.results.len());
    }
}

#[test]
fn enrichment_scorecard_serde_roundtrip_preserves_evaluation() {
    let sc = ga_passing_scorecard();
    let eval_before = sc.evaluate(Milestone::Ga);
    let json = serde_json::to_string(&sc).unwrap();
    let back: Scorecard = serde_json::from_str(&json).unwrap();
    let eval_after = back.evaluate(Milestone::Ga);
    assert_eq!(eval_before.overall_pass, eval_after.overall_pass);
    assert_eq!(eval_before.pass_count, eval_after.pass_count);
    assert_eq!(eval_before.fail_count, eval_after.fail_count);
}

// ===========================================================================
// Cross-cutting: threshold strictness for ALL lower-is-better metrics
// ===========================================================================

#[test]
fn enrichment_all_lower_is_better_thresholds_decrease_alpha_to_ga() {
    let th = default_thresholds();
    let lower_is_better: Vec<MetricKind> = MetricKind::ALL
        .iter()
        .copied()
        .filter(|k| !k.higher_is_better())
        .collect();
    for kind in lower_is_better {
        let alpha = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Alpha)
            .unwrap();
        let beta = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Beta)
            .unwrap();
        let ga = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Ga)
            .unwrap();
        assert!(
            alpha.boundary >= beta.boundary,
            "{kind}: alpha boundary should >= beta"
        );
        assert!(
            beta.boundary >= ga.boundary,
            "{kind}: beta boundary should >= ga"
        );
    }
}

#[test]
fn enrichment_all_higher_is_better_thresholds_increase_alpha_to_ga() {
    let th = default_thresholds();
    let higher_is_better: Vec<MetricKind> = MetricKind::ALL
        .iter()
        .copied()
        .filter(|k| k.higher_is_better())
        .collect();
    for kind in higher_is_better {
        let alpha = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Alpha)
            .unwrap();
        let beta = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Beta)
            .unwrap();
        let ga = th
            .iter()
            .find(|t| t.metric == kind && t.milestone == Milestone::Ga)
            .unwrap();
        assert!(
            alpha.boundary <= beta.boundary,
            "{kind}: alpha boundary should <= beta"
        );
        assert!(
            beta.boundary <= ga.boundary,
            "{kind}: beta boundary should <= ga"
        );
    }
}

// ===========================================================================
// Cross-cutting: report format structure
// ===========================================================================

#[test]
fn enrichment_report_ga_passing_contains_all_metrics() {
    let sc = ga_passing_scorecard();
    let report = sc.report(Milestone::Ga);
    for &kind in &MetricKind::ALL {
        let kind_str = kind.to_string();
        assert!(
            report.contains(&kind_str),
            "report should mention {kind_str}"
        );
    }
}

#[test]
fn enrichment_report_contains_headroom_or_shortfall() {
    let sc = ga_passing_scorecard();
    let report = sc.report(Milestone::Ga);
    assert!(
        report.contains("headroom") || report.contains("shortfall"),
        "report should show headroom or shortfall"
    );
}

// ===========================================================================
// Cross-cutting: evaluation across milestones monotonicity
// ===========================================================================

#[test]
fn enrichment_evaluate_pass_count_monotone_ga_to_alpha() {
    let sc = ga_passing_scorecard();
    let ga_eval = sc.evaluate(Milestone::Ga);
    let beta_eval = sc.evaluate(Milestone::Beta);
    let alpha_eval = sc.evaluate(Milestone::Alpha);
    // GA is strictest, so pass_count for GA <= Beta <= Alpha
    assert!(ga_eval.pass_count <= beta_eval.pass_count);
    assert!(beta_eval.pass_count <= alpha_eval.pass_count);
}

// ===========================================================================
// Cross-cutting: highest_passing_milestone consistency
// ===========================================================================

#[test]
fn enrichment_highest_passing_milestone_consistent_with_evaluate() {
    let sc = ga_passing_scorecard();
    let highest = sc.highest_passing_milestone();
    assert_eq!(highest, Some(Milestone::Ga));
    // If GA passes, then Beta and Alpha must also pass
    assert!(sc.evaluate(Milestone::Beta).overall_pass);
    assert!(sc.evaluate(Milestone::Alpha).overall_pass);
}

// ===========================================================================
// Cross-cutting: default thresholds all positive boundaries
// ===========================================================================

#[test]
fn enrichment_default_thresholds_all_positive_boundaries() {
    for t in &default_thresholds() {
        assert!(
            t.boundary > 0,
            "{:?} should have positive boundary",
            t.metric
        );
    }
}

// ===========================================================================
// Cross-cutting: observation ordering invariant
// ===========================================================================

#[test]
fn enrichment_summary_min_le_p50_le_p95_le_p99_le_max() {
    let mut sc = Scorecard::new(epoch(1));
    for i in 0..200 {
        sc.record(sample(MetricKind::RenderLatencyP50Us, i * 7 % 1000, 1));
    }
    let s = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
    assert!(s.min <= s.p50);
    assert!(s.p50 <= s.p95);
    assert!(s.p95 <= s.p99);
    assert!(s.p99 <= s.max);
}

// ===========================================================================
// Cross-cutting: epoch propagation through record
// ===========================================================================

#[test]
fn enrichment_epoch_advances_with_latest_record() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 5));
    sc.record(sample(MetricKind::BundleSizeBytes, 200, 10));
    sc.record(sample(MetricKind::BundleSizeBytes, 300, 7));
    // Epoch should be from the LAST recorded sample (7), not the max
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.epoch, epoch(7));
}

// ===========================================================================
// Cross-cutting: with_thresholds custom override
// ===========================================================================

#[test]
fn enrichment_with_thresholds_overrides_defaults() {
    let custom = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 42,
    }];
    let sc = Scorecard::with_thresholds(custom, epoch(1));
    assert_eq!(sc.thresholds().len(), 1);
    assert_eq!(sc.thresholds()[0].boundary, 42);
}

// ===========================================================================
// Enrichment batch 2: serde roundtrips for all public types
// ===========================================================================

#[test]
fn enrichment_milestone_serde_roundtrip_alpha() {
    let ms = Milestone::Alpha;
    let json = serde_json::to_string(&ms).unwrap();
    let back: Milestone = serde_json::from_str(&json).unwrap();
    assert_eq!(ms, back);
}

#[test]
fn enrichment_milestone_serde_roundtrip_beta() {
    let ms = Milestone::Beta;
    let json = serde_json::to_string(&ms).unwrap();
    let back: Milestone = serde_json::from_str(&json).unwrap();
    assert_eq!(ms, back);
}

#[test]
fn enrichment_milestone_serde_roundtrip_ga() {
    let ms = Milestone::Ga;
    let json = serde_json::to_string(&ms).unwrap();
    let back: Milestone = serde_json::from_str(&json).unwrap();
    assert_eq!(ms, back);
}

#[test]
fn enrichment_metric_kind_serde_roundtrip_all_ten() {
    for &kind in &MetricKind::ALL {
        let json = serde_json::to_string(&kind).unwrap();
        let back: MetricKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back, "serde roundtrip failed for {kind:?}");
    }
}

#[test]
fn enrichment_threshold_serde_roundtrip_every_milestone() {
    for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
        let t = Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: ms,
            boundary: 42_000,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Threshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn enrichment_metric_sample_serde_roundtrip_all_kinds() {
    for &kind in &MetricKind::ALL {
        let s = MetricSample {
            kind,
            value: 123_456,
            epoch: epoch(99),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MetricSample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back, "MetricSample roundtrip failed for {kind:?}");
    }
}

#[test]
fn enrichment_metric_summary_serde_roundtrip_exact() {
    let s = MetricSummary {
        kind: MetricKind::RollbackLatencyP99Us,
        count: 500,
        min: -10,
        max: 99_000,
        mean: 45_000,
        p50: 44_000,
        p95: 90_000,
        p99: 98_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MetricSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_threshold_result_serde_roundtrip_all_variants() {
    let variants = vec![
        ThresholdResult::Pass {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            value: 995_000,
            threshold: 990_000,
            headroom: 5_000,
        },
        ThresholdResult::Fail {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Beta,
            value: 100_000,
            threshold: 50_000,
            shortfall: 50_000,
        },
        ThresholdResult::InsufficientData {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Alpha,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ThresholdResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back, "ThresholdResult roundtrip failed for {v:?}");
    }
}

#[test]
fn enrichment_scorecard_evaluation_serde_roundtrip_with_results() {
    let eval = ScorecardEvaluation {
        milestone: Milestone::Ga,
        epoch: epoch(77),
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

#[test]
fn enrichment_scorecard_serde_roundtrip_with_multi_metric_data() {
    let mut sc = Scorecard::new(epoch(10));
    for i in 0..50 {
        sc.record(sample(
            MetricKind::CompatibilityPassRate,
            900_000 + i * 100,
            10,
        ));
        sc.record(sample(
            MetricKind::BundleSizeBytes,
            1_000_000 + i * 1000,
            10,
        ));
        sc.record(sample(MetricKind::FallbackFrequency, 5_000 + i, 10));
    }
    let json = serde_json::to_string(&sc).unwrap();
    let back: Scorecard = serde_json::from_str(&json).unwrap();
    assert_eq!(sc.total_observations(), back.total_observations());
    assert_eq!(
        sc.observation_count(MetricKind::CompatibilityPassRate),
        back.observation_count(MetricKind::CompatibilityPassRate)
    );
    assert_eq!(
        sc.observation_count(MetricKind::BundleSizeBytes),
        back.observation_count(MetricKind::BundleSizeBytes)
    );
    // Evaluation should be identical after roundtrip
    let eval_before = sc.evaluate(Milestone::Alpha);
    let eval_after = back.evaluate(Milestone::Alpha);
    assert_eq!(eval_before.pass_count, eval_after.pass_count);
    assert_eq!(eval_before.fail_count, eval_after.fail_count);
    assert_eq!(
        eval_before.pass_rate_millionths,
        eval_after.pass_rate_millionths
    );
}

// ===========================================================================
// Enrichment batch 2: edge cases and boundary values
// ===========================================================================

#[test]
fn enrichment_scorecard_zero_value_observations() {
    let mut sc = Scorecard::new(epoch(1));
    for _ in 0..10 {
        sc.record(sample(MetricKind::BundleSizeBytes, 0, 1));
    }
    let summary = sc.summary(MetricKind::BundleSizeBytes).unwrap();
    assert_eq!(summary.min, 0);
    assert_eq!(summary.max, 0);
    assert_eq!(summary.mean, 0);
    assert_eq!(summary.p50, 0);
}

#[test]
fn enrichment_scorecard_negative_value_observations() {
    let mut sc = Scorecard::new(epoch(1));
    // While unusual, the API accepts i64 so negative values should work
    sc.record(sample(MetricKind::RenderLatencyP50Us, -100, 1));
    sc.record(sample(MetricKind::RenderLatencyP50Us, -50, 1));
    sc.record(sample(MetricKind::RenderLatencyP50Us, 200, 1));
    let summary = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
    assert_eq!(summary.min, -100);
    assert_eq!(summary.max, 200);
    assert_eq!(summary.count, 3);
}

#[test]
fn enrichment_scorecard_single_observation_all_quantiles_equal() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::RenderLatencyP99Us, 777, 1));
    let summary = sc.summary(MetricKind::RenderLatencyP99Us).unwrap();
    assert_eq!(summary.min, 777);
    assert_eq!(summary.max, 777);
    assert_eq!(summary.mean, 777);
    assert_eq!(summary.p50, 777);
    assert_eq!(summary.p95, 777);
    assert_eq!(summary.p99, 777);
}

#[test]
fn enrichment_scorecard_identical_observations_collapsed_quantiles() {
    let mut sc = Scorecard::new(epoch(1));
    for _ in 0..100 {
        sc.record(sample(MetricKind::BundleSizeBytes, 42_000, 1));
    }
    let summary = sc.summary(MetricKind::BundleSizeBytes).unwrap();
    assert_eq!(summary.min, 42_000);
    assert_eq!(summary.max, 42_000);
    assert_eq!(summary.mean, 42_000);
    assert_eq!(summary.p50, 42_000);
    assert_eq!(summary.p95, 42_000);
    assert_eq!(summary.p99, 42_000);
}

#[test]
fn enrichment_scorecard_no_summary_for_unrecorded_metric() {
    let sc = Scorecard::new(epoch(1));
    for &kind in &MetricKind::ALL {
        assert!(
            sc.summary(kind).is_none(),
            "expected None for unrecorded {kind:?}"
        );
    }
}

#[test]
fn enrichment_scorecard_no_current_value_for_unrecorded_metric() {
    let sc = Scorecard::new(epoch(1));
    for &kind in &MetricKind::ALL {
        assert!(
            sc.current_value(kind).is_none(),
            "expected None for unrecorded {kind:?}"
        );
    }
}

#[test]
fn enrichment_evaluate_empty_thresholds_pass_rate_zero() {
    let sc = Scorecard::with_thresholds(vec![], epoch(1));
    let eval = sc.evaluate(Milestone::Ga);
    assert_eq!(eval.pass_rate_millionths, 0);
    assert_eq!(eval.results.len(), 0);
    assert!(!eval.overall_pass);
}

// ===========================================================================
// Enrichment batch 2: Display output exact values
// ===========================================================================

#[test]
fn enrichment_milestone_display_exact_strings() {
    assert_eq!(Milestone::Alpha.to_string(), "alpha");
    assert_eq!(Milestone::Beta.to_string(), "beta");
    assert_eq!(Milestone::Ga.to_string(), "ga");
}

#[test]
fn enrichment_metric_kind_display_exact_all() {
    let expected = [
        (MetricKind::CompatibilityPassRate, "compatibility_pass_rate"),
        (MetricKind::ResponsivenessP99Us, "responsiveness_p99_us"),
        (MetricKind::RenderLatencyP50Us, "render_latency_p50_us"),
        (MetricKind::RenderLatencyP95Us, "render_latency_p95_us"),
        (MetricKind::RenderLatencyP99Us, "render_latency_p99_us"),
        (MetricKind::BundleSizeBytes, "bundle_size_bytes"),
        (MetricKind::RuntimeMemoryBytes, "runtime_memory_bytes"),
        (MetricKind::FallbackFrequency, "fallback_frequency"),
        (MetricKind::RollbackLatencyP99Us, "rollback_latency_p99_us"),
        (MetricKind::EvidenceCompleteness, "evidence_completeness"),
    ];
    for (kind, expected_str) in expected {
        assert_eq!(
            kind.to_string(),
            expected_str,
            "Display mismatch for {kind:?}"
        );
    }
}

// ===========================================================================
// Enrichment batch 2: MetricKind::ALL constant validation
// ===========================================================================

#[test]
fn enrichment_metric_kind_all_has_exactly_ten_elements() {
    assert_eq!(MetricKind::ALL.len(), 10);
}

#[test]
fn enrichment_metric_kind_all_no_duplicates() {
    let set: BTreeSet<MetricKind> = MetricKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), MetricKind::ALL.len());
}

#[test]
fn enrichment_metric_kind_higher_is_better_exactly_two() {
    let hib: Vec<MetricKind> = MetricKind::ALL
        .iter()
        .copied()
        .filter(|k| k.higher_is_better())
        .collect();
    assert_eq!(hib.len(), 2);
    assert!(hib.contains(&MetricKind::CompatibilityPassRate));
    assert!(hib.contains(&MetricKind::EvidenceCompleteness));
}

#[test]
fn enrichment_metric_kind_lower_is_better_exactly_eight() {
    let lib: Vec<MetricKind> = MetricKind::ALL
        .iter()
        .copied()
        .filter(|k| !k.higher_is_better())
        .collect();
    assert_eq!(lib.len(), 8);
}

// ===========================================================================
// Enrichment batch 2: default_thresholds validation
// ===========================================================================

#[test]
fn enrichment_default_thresholds_has_30_entries() {
    assert_eq!(default_thresholds().len(), 30); // 10 metrics * 3 milestones
}

#[test]
fn enrichment_default_thresholds_each_metric_has_three_milestones() {
    let th = default_thresholds();
    for &kind in &MetricKind::ALL {
        let milestones: BTreeSet<Milestone> = th
            .iter()
            .filter(|t| t.metric == kind)
            .map(|t| t.milestone)
            .collect();
        assert_eq!(
            milestones.len(),
            3,
            "metric {kind:?} should have 3 milestone thresholds"
        );
        assert!(milestones.contains(&Milestone::Alpha));
        assert!(milestones.contains(&Milestone::Beta));
        assert!(milestones.contains(&Milestone::Ga));
    }
}

// ===========================================================================
// Enrichment batch 2: ThresholdResult::is_pass coverage
// ===========================================================================

#[test]
fn enrichment_threshold_result_is_pass_pass_variant() {
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
fn enrichment_threshold_result_is_pass_fail_variant() {
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
fn enrichment_threshold_result_is_pass_insufficient_data() {
    let r = ThresholdResult::InsufficientData {
        metric: MetricKind::RuntimeMemoryBytes,
        milestone: Milestone::Beta,
    };
    assert!(!r.is_pass());
}

// ===========================================================================
// Enrichment batch 2: set_epoch
// ===========================================================================

#[test]
fn enrichment_set_epoch_reflected_in_evaluation() {
    let mut sc = Scorecard::new(epoch(1));
    sc.set_epoch(epoch(999));
    let eval = sc.evaluate(Milestone::Alpha);
    assert_eq!(eval.epoch, epoch(999));
}

#[test]
fn enrichment_set_epoch_overridden_by_record() {
    let mut sc = Scorecard::new(epoch(1));
    sc.set_epoch(epoch(50));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 77));
    let eval = sc.evaluate(Milestone::Alpha);
    // record() sets epoch to sample's epoch, overriding set_epoch
    assert_eq!(eval.epoch, epoch(77));
}

// ===========================================================================
// Enrichment batch 2: report format structure deeper checks
// ===========================================================================

#[test]
fn enrichment_report_header_contains_epoch() {
    let mut sc = Scorecard::new(epoch(42));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 42));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("42"), "report should mention epoch 42");
}

#[test]
fn enrichment_report_fail_contains_shortfall_word() {
    // Create a scorecard that will fail at least one metric
    let thresholds = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 100,
    }];
    let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("[FAIL]"), "report should contain [FAIL]");
    assert!(
        report.contains("shortfall"),
        "report should contain shortfall"
    );
}

#[test]
fn enrichment_report_pass_contains_headroom_word() {
    let thresholds = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 1000,
    }];
    let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
    let report = sc.report(Milestone::Alpha);
    assert!(report.contains("[PASS]"), "report should contain [PASS]");
    assert!(
        report.contains("headroom"),
        "report should contain headroom"
    );
}

#[test]
fn enrichment_report_insufficient_data_shows_dashes() {
    let sc = Scorecard::new(epoch(1));
    let report = sc.report(Milestone::Alpha);
    assert!(
        report.contains("[----]"),
        "report should contain [----] for insufficient data"
    );
}

// ===========================================================================
// Enrichment batch 2: Scorecard with_thresholds custom scenarios
// ===========================================================================

#[test]
fn enrichment_with_thresholds_empty_evaluates_to_no_pass() {
    let sc = Scorecard::with_thresholds(vec![], epoch(1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(!eval.overall_pass);
    assert_eq!(eval.pass_count, 0);
    assert_eq!(eval.fail_count, 0);
}

#[test]
fn enrichment_with_thresholds_single_metric_pass() {
    let thresholds = vec![Threshold {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Alpha,
        boundary: 500_000,
    }];
    let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 600_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(eval.overall_pass);
    assert_eq!(eval.pass_count, 1);
    assert_eq!(eval.fail_count, 0);
    assert_eq!(eval.pass_rate_millionths, 1_000_000);
}

// ===========================================================================
// Enrichment batch 2: highest_passing_milestone edge cases
// ===========================================================================

#[test]
fn enrichment_highest_passing_milestone_none_with_empty_scorecard() {
    let sc = Scorecard::new(epoch(1));
    assert_eq!(sc.highest_passing_milestone(), None);
}

#[test]
fn enrichment_highest_passing_milestone_beta_not_ga() {
    // Data good enough for Beta but not GA
    let mut sc = Scorecard::new(epoch(1));
    for _ in 0..20 {
        sc.record(sample(MetricKind::CompatibilityPassRate, 960_000, 1)); // passes beta (950k) but fails ga (990k)
        sc.record(sample(MetricKind::ResponsivenessP99Us, 10_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
        sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
        sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
        sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
        sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
        sc.record(sample(MetricKind::EvidenceCompleteness, 960_000, 1)); // passes beta (900k) but fails ga (990k)
    }
    let highest = sc.highest_passing_milestone();
    assert_eq!(highest, Some(Milestone::Beta));
}

// ===========================================================================
// Enrichment batch 2: observation_count and total_observations
// ===========================================================================

#[test]
fn enrichment_observation_count_zero_for_all_initially() {
    let sc = Scorecard::new(epoch(1));
    for &kind in &MetricKind::ALL {
        assert_eq!(sc.observation_count(kind), 0);
    }
    assert_eq!(sc.total_observations(), 0);
}

#[test]
fn enrichment_total_observations_sums_across_metrics() {
    let mut sc = Scorecard::new(epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 100, 1));
    sc.record(sample(MetricKind::BundleSizeBytes, 200, 1));
    sc.record(sample(MetricKind::RuntimeMemoryBytes, 300, 1));
    sc.record(sample(MetricKind::FallbackFrequency, 400, 1));
    sc.record(sample(MetricKind::FallbackFrequency, 500, 1));
    sc.record(sample(MetricKind::FallbackFrequency, 600, 1));
    assert_eq!(sc.observation_count(MetricKind::BundleSizeBytes), 2);
    assert_eq!(sc.observation_count(MetricKind::RuntimeMemoryBytes), 1);
    assert_eq!(sc.observation_count(MetricKind::FallbackFrequency), 3);
    assert_eq!(sc.total_observations(), 6);
}

// ===========================================================================
// Enrichment batch 2: Milestone Ord correctness
// ===========================================================================

#[test]
fn enrichment_milestone_ord_total_order() {
    let mut milestones = vec![Milestone::Ga, Milestone::Alpha, Milestone::Beta];
    milestones.sort();
    assert_eq!(
        milestones,
        vec![Milestone::Alpha, Milestone::Beta, Milestone::Ga]
    );
}

// ===========================================================================
// Enrichment batch 2: MetricKind Ord ensures stable BTreeMap key ordering
// ===========================================================================

#[test]
fn enrichment_metric_kind_ord_btreemap_iteration_stable() {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    // Insert in reverse order to verify sorting
    for &kind in MetricKind::ALL.iter().rev() {
        map.insert(kind, kind.to_string());
    }
    let keys: Vec<MetricKind> = map.keys().copied().collect();
    // BTreeMap should sort by Ord, and repeated builds give same order
    let mut map2 = BTreeMap::new();
    for &kind in &MetricKind::ALL {
        map2.insert(kind, kind.to_string());
    }
    let keys2: Vec<MetricKind> = map2.keys().copied().collect();
    assert_eq!(keys, keys2);
}

// ===========================================================================
// Enrichment batch 2: Scorecard::new default threshold count
// ===========================================================================

#[test]
fn enrichment_scorecard_new_has_30_default_thresholds() {
    let sc = Scorecard::new(epoch(1));
    assert_eq!(sc.thresholds().len(), 30);
}

// ===========================================================================
// Enrichment batch 2: boundary-exact threshold pass/fail
// ===========================================================================

#[test]
fn enrichment_boundary_exact_value_passes_higher_is_better() {
    // When value == boundary for higher_is_better, it should pass (>=)
    let thresholds = vec![Threshold {
        metric: MetricKind::CompatibilityPassRate,
        milestone: Milestone::Alpha,
        boundary: 800_000,
    }];
    let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
    sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(
        eval.overall_pass,
        "exact boundary should pass for higher_is_better"
    );
    if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
        assert_eq!(*headroom, 0);
    } else {
        panic!("expected pass");
    }
}

#[test]
fn enrichment_boundary_exact_value_passes_lower_is_better() {
    // When value == boundary for lower_is_better, it should pass (<=)
    let thresholds = vec![Threshold {
        metric: MetricKind::BundleSizeBytes,
        milestone: Milestone::Alpha,
        boundary: 5_000,
    }];
    let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
    sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
    let eval = sc.evaluate(Milestone::Alpha);
    assert!(
        eval.overall_pass,
        "exact boundary should pass for lower_is_better"
    );
    if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
        assert_eq!(*headroom, 0);
    } else {
        panic!("expected pass");
    }
}
