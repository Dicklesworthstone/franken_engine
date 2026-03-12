//! Integration tests for `regexp_string_governance` (RGC-312C, bd-1lsy.4.12.3).

use std::collections::BTreeSet;

use frankenengine_engine::regexp_string_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("regexp-string-governance"));
}

#[test]
fn test_schema_version_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "regexp_string_governance");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.4.12.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-312C");
}

#[test]
fn test_millionths_value() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_default_parity_threshold() {
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, 950_000);
}

#[test]
fn test_default_tail_risk_threshold() {
    assert_eq!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS, 50_000);
}

#[test]
fn test_default_unicode_coverage_threshold() {
    assert_eq!(DEFAULT_MIN_UNICODE_COVERAGE_MILLIONTHS, 900_000);
}

#[test]
fn test_default_benchmark_samples() {
    assert_eq!(DEFAULT_MIN_BENCHMARK_SAMPLES, 30);
}

#[test]
fn test_default_speedup_threshold() {
    assert_eq!(DEFAULT_MIN_SPEEDUP_MILLIONTHS, MILLIONTHS);
}

// ============================================================================
// StringLane
// ============================================================================

#[test]
fn test_string_lane_all_count() {
    assert_eq!(StringLane::ALL.len(), 5);
}

#[test]
fn test_string_lane_display_matches_as_str() {
    for lane in StringLane::ALL {
        assert_eq!(format!("{lane}"), lane.as_str());
    }
}

#[test]
fn test_string_lane_ordering() {
    assert!(StringLane::Ascii < StringLane::Rope);
}

#[test]
fn test_string_lane_serde_roundtrip() {
    for lane in StringLane::ALL {
        let json = serde_json::to_string(lane).unwrap();
        let back: StringLane = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, back);
    }
}

// ============================================================================
// RegexpFeature
// ============================================================================

#[test]
fn test_regexp_feature_all_count() {
    assert_eq!(RegexpFeature::ALL.len(), 8);
}

#[test]
fn test_regexp_feature_display_matches_as_str() {
    for f in RegexpFeature::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

#[test]
fn test_regexp_feature_serde_roundtrip() {
    for f in RegexpFeature::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: RegexpFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ============================================================================
// ParityAxis
// ============================================================================

#[test]
fn test_parity_axis_all_count() {
    assert_eq!(ParityAxis::ALL.len(), 5);
}

#[test]
fn test_parity_axis_display_matches_as_str() {
    for a in ParityAxis::ALL {
        assert_eq!(format!("{a}"), a.as_str());
    }
}

#[test]
fn test_parity_axis_ordering() {
    assert!(ParityAxis::Semantic < ParityAxis::ErrorPath);
}

// ============================================================================
// ParitySubject
// ============================================================================

#[test]
fn test_parity_subject_lane_display() {
    let s = ParitySubject::Lane(StringLane::Utf8);
    assert_eq!(format!("{s}"), "lane:utf8");
}

#[test]
fn test_parity_subject_feature_display() {
    let s = ParitySubject::Feature(RegexpFeature::Lookahead);
    assert_eq!(format!("{s}"), "feature:lookahead");
}

// ============================================================================
// ParityResult
// ============================================================================

#[test]
fn test_parity_result_constructor_computes_hash() {
    let r = ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    );
    assert_eq!(r.parity_millionths, 980_000);
    assert_eq!(r.sample_count, 50);
    assert!(r.passes);
    // Evidence hash should be non-trivial
    assert_ne!(r.evidence_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn test_parity_result_deterministic_hash() {
    let r1 = ParityResult::new(
        ParitySubject::Feature(RegexpFeature::DotAll),
        ParityAxis::Performance,
        900_000,
        100,
        true,
    );
    let r2 = ParityResult::new(
        ParitySubject::Feature(RegexpFeature::DotAll),
        ParityAxis::Performance,
        900_000,
        100,
        true,
    );
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
}

// ============================================================================
// UnicodeCoverage
// ============================================================================

#[test]
fn test_unicode_coverage_bmp() {
    let uc = UnicodeCoverage::new(0, 0x0000, 0xFFFF, 950_000, true);
    assert_eq!(uc.plane, 0);
    assert_eq!(uc.range_size(), 0x10000);
    assert!(uc.passes);
}

#[test]
fn test_unicode_coverage_smp() {
    let uc = UnicodeCoverage::new(1, 0x10000, 0x1FFFF, 800_000, false);
    assert_eq!(uc.plane, 1);
    assert_eq!(uc.range_size(), 0x10000);
    assert!(!uc.passes);
}

#[test]
fn test_unicode_coverage_content_hash_deterministic() {
    let a = UnicodeCoverage::new(0, 0, 0xFF, 900_000, true);
    let b = UnicodeCoverage::new(0, 0, 0xFF, 900_000, true);
    assert_eq!(a.content_hash, b.content_hash);
}

// ============================================================================
// BenchmarkCategory
// ============================================================================

#[test]
fn test_benchmark_category_all_count() {
    assert_eq!(BenchmarkCategory::ALL.len(), 2);
}

#[test]
fn test_benchmark_category_display() {
    assert_eq!(format!("{}", BenchmarkCategory::String), "string");
    assert_eq!(format!("{}", BenchmarkCategory::Regexp), "regexp");
}

// ============================================================================
// BenchmarkEntry
// ============================================================================

#[test]
fn test_benchmark_entry_speedup_computed() {
    let e = BenchmarkEntry::new(BenchmarkCategory::String, "concat_10k", 2000, 1000, 50);
    assert_eq!(e.speedup_millionths, 2_000_000);
    assert!(!e.is_regression());
}

#[test]
fn test_benchmark_entry_regression() {
    let e = BenchmarkEntry::new(BenchmarkCategory::Regexp, "email_match", 1000, 2000, 50);
    assert_eq!(e.speedup_millionths, 500_000);
    assert!(e.is_regression());
}

#[test]
fn test_benchmark_entry_zero_optimized_caps() {
    let e = BenchmarkEntry::new(BenchmarkCategory::String, "zero_opt", 1000, 0, 50);
    assert_eq!(e.speedup_millionths, MILLIONTHS * 10);
}

#[test]
fn test_benchmark_entry_content_hash_deterministic() {
    let a = BenchmarkEntry::new(BenchmarkCategory::Regexp, "w1", 500, 250, 30);
    let b = BenchmarkEntry::new(BenchmarkCategory::Regexp, "w1", 500, 250, 30);
    assert_eq!(a.content_hash, b.content_hash);
}

// ============================================================================
// TailRiskEntry
// ============================================================================

#[test]
fn test_tail_risk_entry_ratio() {
    let e = TailRiskEntry::new(ParitySubject::Lane(StringLane::Utf16), 10_000, 5_000);
    assert_eq!(e.tail_ratio_millionths, 2_000_000);
}

#[test]
fn test_tail_risk_entry_zero_median_caps() {
    let e = TailRiskEntry::new(ParitySubject::Lane(StringLane::Ascii), 1000, 0);
    assert_eq!(e.tail_ratio_millionths, MILLIONTHS * 100);
}

// ============================================================================
// GovernanceConfig
// ============================================================================

#[test]
fn test_governance_config_default() {
    let c = GovernanceConfig::default();
    assert_eq!(c.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
    assert_eq!(c.max_tail_risk_millionths, DEFAULT_MAX_TAIL_RISK_MILLIONTHS);
    assert_eq!(
        c.min_unicode_coverage_millionths,
        DEFAULT_MIN_UNICODE_COVERAGE_MILLIONTHS
    );
    assert_eq!(c.min_benchmark_samples, DEFAULT_MIN_BENCHMARK_SAMPLES);
    assert_eq!(c.min_speedup_millionths, DEFAULT_MIN_SPEEDUP_MILLIONTHS);
    assert!(c.fail_closed);
}

#[test]
fn test_governance_config_strict() {
    let c = GovernanceConfig::strict();
    assert_eq!(c.min_parity_millionths, MILLIONTHS);
    assert_eq!(c.min_benchmark_samples, 100);
}

#[test]
fn test_governance_config_permissive() {
    let c = GovernanceConfig::permissive();
    assert_eq!(c.min_parity_millionths, 0);
    assert!(!c.fail_closed);
    assert!(c.required_lanes.is_empty());
    assert!(c.required_features.is_empty());
}

#[test]
fn test_governance_config_builders() {
    let c = GovernanceConfig::default_config()
        .with_min_parity(800_000)
        .with_max_tail_risk(100_000)
        .with_min_unicode_coverage(500_000)
        .with_min_benchmark_samples(10)
        .fail_open();
    assert_eq!(c.min_parity_millionths, 800_000);
    assert_eq!(c.max_tail_risk_millionths, 100_000);
    assert_eq!(c.min_unicode_coverage_millionths, 500_000);
    assert_eq!(c.min_benchmark_samples, 10);
    assert!(!c.fail_closed);
}

#[test]
fn test_governance_config_required_lanes_builder() {
    let lanes: BTreeSet<StringLane> = [StringLane::Ascii, StringLane::Utf8]
        .iter()
        .copied()
        .collect();
    let c = GovernanceConfig::default_config().with_required_lanes(lanes.clone());
    assert_eq!(c.required_lanes, lanes);
}

// ============================================================================
// GovernanceVerdict
// ============================================================================

#[test]
fn test_verdict_approved_is_approved() {
    assert!(GovernanceVerdict::Approved.is_approved());
}

#[test]
fn test_verdict_non_approved_types() {
    assert!(!GovernanceVerdict::ParityViolation.is_approved());
    assert!(!GovernanceVerdict::UnicodeCoverageGap.is_approved());
    assert!(!GovernanceVerdict::BenchmarkInsufficient.is_approved());
    assert!(!GovernanceVerdict::TailRiskExceeded.is_approved());
    assert!(!GovernanceVerdict::MultipleViolations.is_approved());
}

#[test]
fn test_verdict_display_matches_as_str() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::ParityViolation,
        GovernanceVerdict::UnicodeCoverageGap,
        GovernanceVerdict::BenchmarkInsufficient,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

// ============================================================================
// GovernanceEvaluator lifecycle
// ============================================================================

#[test]
fn test_evaluator_new_with_defaults() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    assert_eq!(*ev.epoch(), ep());
    assert_eq!(ev.evaluation_count(), 0);
    assert_eq!(ev.approved_count(), 0);
    assert_eq!(ev.denied_count(), 0);
    assert!(ev.last_receipt().is_none());
    assert!(ev.parity_results().is_empty());
    // Evaluate empty with default (fail_closed) produces violation
    let _r = ev.evaluate();
    assert_eq!(ev.evaluation_count(), 1);
}

#[test]
fn test_evaluator_add_parity_and_evaluate_approved() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let pr = ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    );
    ev.add_parity(pr);
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(ev.approved_count(), 1);
}

#[test]
fn test_evaluator_parity_violation() {
    let cfg = GovernanceConfig::default_config()
        .with_required_lanes(BTreeSet::new())
        .with_required_features(BTreeSet::new());
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let pr = ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        500_000,
        50,
        false,
    );
    ev.add_parity(pr);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
    assert_eq!(ev.denied_count(), 1);
}

#[test]
fn test_evaluator_unicode_coverage_gap() {
    let cfg = GovernanceConfig::permissive().with_min_unicode_coverage(900_000);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let uc = UnicodeCoverage::new(0, 0, 0xFFFF, 500_000, false);
    ev.add_unicode_coverage(uc);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::UnicodeCoverageGap);
}

#[test]
fn test_evaluator_benchmark_insufficient_samples() {
    let cfg = GovernanceConfig::permissive().with_min_benchmark_samples(100);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let be = BenchmarkEntry::new(BenchmarkCategory::String, "w1", 1000, 500, 10);
    ev.add_benchmark(be);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::BenchmarkInsufficient);
}

#[test]
fn test_evaluator_benchmark_regression() {
    let cfg = GovernanceConfig::permissive().with_min_benchmark_samples(1);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let be = BenchmarkEntry::new(BenchmarkCategory::Regexp, "w2", 500, 1000, 50);
    ev.add_benchmark(be);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::BenchmarkInsufficient);
}

#[test]
fn test_evaluator_tail_risk_exceeded() {
    let cfg = GovernanceConfig::permissive().with_max_tail_risk(2_000_000);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let tr = TailRiskEntry::new(ParitySubject::Lane(StringLane::Rope), 100_000, 10);
    ev.add_tail_risk(tr);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
}

#[test]
fn test_evaluator_multiple_violations() {
    let cfg = GovernanceConfig::permissive()
        .with_min_unicode_coverage(900_000)
        .with_min_benchmark_samples(100);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let uc = UnicodeCoverage::new(0, 0, 0xFFFF, 500_000, false);
    ev.add_unicode_coverage(uc);
    let be = BenchmarkEntry::new(BenchmarkCategory::String, "w1", 1000, 500, 10);
    ev.add_benchmark(be);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_clear_resets() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    assert_eq!(ev.parity_results().len(), 1);
    ev.clear();
    assert!(ev.parity_results().is_empty());
    assert!(ev.unicode_coverage().is_empty());
    assert!(ev.benchmark_entries().is_empty());
    assert!(ev.tail_risk_entries().is_empty());
}

#[test]
fn test_evaluator_pass_rate_computation() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let pr = ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    );
    ev.add_parity(pr.clone());
    ev.evaluate();
    ev.clear();
    ev.add_parity(pr);
    ev.evaluate();
    assert_eq!(ev.pass_rate_millionths(), MILLIONTHS);
}

#[test]
fn test_evaluator_summary() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Latin1),
        ParityAxis::Memory,
        980_000,
        50,
        true,
    ));
    ev.add_unicode_coverage(UnicodeCoverage::new(0, 0, 0xFF, 950_000, true));
    ev.add_benchmark(BenchmarkEntry::new(
        BenchmarkCategory::String,
        "x",
        100,
        50,
        50,
    ));
    ev.add_tail_risk(TailRiskEntry::new(
        ParitySubject::Lane(StringLane::Ascii),
        500,
        250,
    ));
    ev.evaluate();
    let s = ev.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.parity_results_count, 1);
    assert_eq!(s.unicode_coverage_count, 1);
    assert_eq!(s.benchmark_count, 1);
    assert_eq!(s.tail_risk_count, 1);
}

// ============================================================================
// Content hash determinism
// ============================================================================

#[test]
fn test_receipt_content_hash_deterministic() {
    let build = || {
        let cfg = GovernanceConfig::permissive();
        let mut ev = GovernanceEvaluator::new(cfg, ep());
        ev.add_parity(ParityResult::new(
            ParitySubject::Lane(StringLane::Ascii),
            ParityAxis::Semantic,
            980_000,
            50,
            true,
        ));
        ev.evaluate()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_content_hash_changes_with_data() {
    let cfg = GovernanceConfig::permissive();
    let mut ev1 = GovernanceEvaluator::new(cfg.clone(), ep());
    ev1.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    let r1 = ev1.evaluate();

    let mut ev2 = GovernanceEvaluator::new(cfg, ep());
    ev2.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Utf8),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    let r2 = ev2.evaluate();
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ============================================================================
// E2E scenarios
// ============================================================================

#[test]
fn test_e2e_full_coverage_approved() {
    let cfg = GovernanceConfig::default_config()
        .with_min_parity(900_000)
        .with_min_benchmark_samples(5);
    let mut ev = GovernanceEvaluator::new(cfg, ep());

    // Parity for all lanes
    for lane in StringLane::ALL {
        ev.add_parity(ParityResult::new(
            ParitySubject::Lane(*lane),
            ParityAxis::Semantic,
            960_000,
            50,
            true,
        ));
    }
    // Parity for all features
    for feat in RegexpFeature::ALL {
        ev.add_parity(ParityResult::new(
            ParitySubject::Feature(*feat),
            ParityAxis::Semantic,
            960_000,
            50,
            true,
        ));
    }
    // Unicode
    ev.add_unicode_coverage(UnicodeCoverage::new(0, 0, 0xFFFF, 950_000, true));
    // Benchmark
    ev.add_benchmark(BenchmarkEntry::new(
        BenchmarkCategory::String,
        "w1",
        1000,
        500,
        50,
    ));
    ev.add_benchmark(BenchmarkEntry::new(
        BenchmarkCategory::Regexp,
        "w2",
        800,
        400,
        50,
    ));

    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn test_e2e_missing_required_lane_fail_closed() {
    let lanes: BTreeSet<StringLane> = StringLane::ALL.iter().copied().collect();
    let cfg = GovernanceConfig::permissive().with_required_lanes(lanes);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    // Only provide one lane
    ev.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    let receipt = ev.evaluate();
    // Should still be approved because permissive has fail_closed = false
    assert!(receipt.is_approved());
}

#[test]
fn test_e2e_missing_required_lane_fail_closed_strict() {
    let lanes: BTreeSet<StringLane> = StringLane::ALL.iter().copied().collect();
    let cfg = GovernanceConfig::default_config()
        .with_required_lanes(lanes)
        .with_required_features(BTreeSet::new())
        .with_min_parity(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    // Only provide one lane
    ev.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
}

#[test]
fn test_e2e_serde_roundtrip_receipt() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        980_000,
        50,
        true,
    ));
    let receipt = ev.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.verdict, back.verdict);
    assert_eq!(receipt.content_hash, back.content_hash);
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn test_e2e_last_receipt_stored() {
    let cfg = GovernanceConfig::permissive();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    assert!(ev.last_receipt().is_none());
    ev.evaluate();
    assert!(ev.last_receipt().is_some());
}
