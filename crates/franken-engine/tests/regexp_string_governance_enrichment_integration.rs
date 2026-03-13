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
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::regexp_string_governance::{
    BenchmarkCategory, BenchmarkEntry, GovernanceConfig, GovernanceEvaluator,
    GovernanceReceipt, GovernanceSummary, GovernanceVerdict, MILLIONTHS, ParityAxis,
    ParityResult, ParitySubject, RegexpFeature, StringLane, TailRiskEntry,
    UnicodeCoverage, Violation, regexp_string_governance_manifest, summarize_receipt,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

// =========================================================================
// A. RegexpFeature ordering
// =========================================================================

#[test]
fn enrichment_regexp_feature_ordering() {
    let mut features: Vec<RegexpFeature> = RegexpFeature::ALL.to_vec();
    features.reverse();
    features.sort();
    assert_eq!(features, RegexpFeature::ALL);
}

// =========================================================================
// B. ParitySubject serde roundtrip
// =========================================================================

#[test]
fn enrichment_parity_subject_lane_serde() {
    let subject = ParitySubject::Lane(StringLane::Utf8);
    let json = serde_json::to_string(&subject).unwrap();
    let back: ParitySubject = serde_json::from_str(&json).unwrap();
    assert_eq!(subject, back);
}

#[test]
fn enrichment_parity_subject_feature_serde() {
    let subject = ParitySubject::Feature(RegexpFeature::Lookahead);
    let json = serde_json::to_string(&subject).unwrap();
    let back: ParitySubject = serde_json::from_str(&json).unwrap();
    assert_eq!(subject, back);
}

#[test]
fn enrichment_parity_subject_ordering() {
    let lane = ParitySubject::Lane(StringLane::Ascii);
    let feature = ParitySubject::Feature(RegexpFeature::Backreferences);
    // Lane < Feature in enum order
    assert!(lane < feature);
}

// =========================================================================
// C. ParityResult serde roundtrip
// =========================================================================

#[test]
fn enrichment_parity_result_serde_roundtrip() {
    let pr = ParityResult::new(
        ParitySubject::Lane(StringLane::Utf16),
        ParityAxis::Semantic,
        960_000,
        50,
        true,
    );
    let json = serde_json::to_string(&pr).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

// =========================================================================
// D. ParityAxis serde roundtrip
// =========================================================================

#[test]
fn enrichment_parity_axis_serde_all() {
    for axis in ParityAxis::ALL {
        let json = serde_json::to_string(axis).unwrap();
        let back: ParityAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*axis, back);
    }
}

// =========================================================================
// E. UnicodeCoverage range_size
// =========================================================================

#[test]
fn enrichment_unicode_coverage_range_size_bmp() {
    let uc = UnicodeCoverage::new(0, 0, 0xFFFF, MILLIONTHS, true);
    assert_eq!(uc.range_size(), 0x10000);
}

#[test]
fn enrichment_unicode_coverage_range_size_single() {
    let uc = UnicodeCoverage::new(0, 0x41, 0x41, MILLIONTHS, true);
    assert_eq!(uc.range_size(), 1);
}

#[test]
fn enrichment_unicode_coverage_serde_roundtrip() {
    let uc = UnicodeCoverage::new(1, 0x10000, 0x1FFFF, 950_000, true);
    let json = serde_json::to_string(&uc).unwrap();
    let back: UnicodeCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(uc, back);
}

// =========================================================================
// F. BenchmarkCategory ordering and serde
// =========================================================================

#[test]
fn enrichment_benchmark_category_ordering() {
    assert!(BenchmarkCategory::String < BenchmarkCategory::Regexp);
}

#[test]
fn enrichment_benchmark_category_serde_all() {
    for cat in BenchmarkCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: BenchmarkCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

// =========================================================================
// G. BenchmarkEntry serde roundtrip
// =========================================================================

#[test]
fn enrichment_benchmark_entry_serde_roundtrip() {
    let entry = BenchmarkEntry::new(BenchmarkCategory::String, "concat_10k", 1000, 500, 50);
    let json = serde_json::to_string(&entry).unwrap();
    let back: BenchmarkEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_benchmark_entry_speedup_is_millionths() {
    let entry = BenchmarkEntry::new(BenchmarkCategory::String, "test", 2000, 1000, 30);
    // 2000/1000 = 2.0x = 2_000_000 millionths
    assert_eq!(entry.speedup_millionths, 2_000_000);
}

#[test]
fn enrichment_benchmark_entry_is_regression() {
    let fast = BenchmarkEntry::new(BenchmarkCategory::String, "fast", 1000, 500, 30);
    let slow = BenchmarkEntry::new(BenchmarkCategory::String, "slow", 500, 1000, 30);
    assert!(!fast.is_regression());
    assert!(slow.is_regression());
}

// =========================================================================
// H. TailRiskEntry serde roundtrip
// =========================================================================

#[test]
fn enrichment_tail_risk_entry_serde_roundtrip() {
    let tr = TailRiskEntry::new(ParitySubject::Lane(StringLane::Ascii), 2000, 1000);
    let json = serde_json::to_string(&tr).unwrap();
    let back: TailRiskEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(tr, back);
}

#[test]
fn enrichment_tail_risk_entry_ratio() {
    let tr = TailRiskEntry::new(ParitySubject::Lane(StringLane::Utf8), 3000, 1000);
    // 3000/1000 = 3.0x = 3_000_000 millionths
    assert_eq!(tr.tail_ratio_millionths, 3_000_000);
}

// =========================================================================
// I. Violation
// =========================================================================

#[test]
fn enrichment_violation_display() {
    let v = Violation::new(
        GovernanceVerdict::ParityViolation,
        "lane:ascii on semantic below threshold",
        800_000,
        950_000,
    );
    let display = v.to_string();
    assert!(display.contains("parity_violation"));
    assert!(display.contains("800000"));
    assert!(display.contains("950000"));
}

#[test]
fn enrichment_violation_serde_roundtrip() {
    let v = Violation::new(
        GovernanceVerdict::TailRiskExceeded,
        "tail risk",
        5_000_000,
        50_000,
    );
    let json = serde_json::to_string(&v).unwrap();
    let back: Violation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// =========================================================================
// J. GovernanceVerdict ordering and serde
// =========================================================================

#[test]
fn enrichment_verdict_ordering() {
    assert!(GovernanceVerdict::Approved < GovernanceVerdict::ParityViolation);
    assert!(GovernanceVerdict::ParityViolation < GovernanceVerdict::MultipleViolations);
}

#[test]
fn enrichment_verdict_serde_all() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::ParityViolation,
        GovernanceVerdict::UnicodeCoverageGap,
        GovernanceVerdict::BenchmarkInsufficient,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// =========================================================================
// K. GovernanceConfig serde roundtrip
// =========================================================================

#[test]
fn enrichment_governance_config_serde_roundtrip() {
    let config = GovernanceConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_governance_config_fail_open_builder() {
    let config = GovernanceConfig::default_config().fail_open();
    assert!(!config.fail_closed);
}

#[test]
fn enrichment_governance_config_with_min_benchmark_samples() {
    let config = GovernanceConfig::default_config().with_min_benchmark_samples(100);
    assert_eq!(config.min_benchmark_samples, 100);
}

#[test]
fn enrichment_governance_config_with_required_features() {
    let mut features = BTreeSet::new();
    features.insert(RegexpFeature::Lookahead);
    let config = GovernanceConfig::default_config().with_required_features(features.clone());
    assert_eq!(config.required_features, features);
}

// =========================================================================
// L. GovernanceReceipt methods
// =========================================================================

#[test]
fn enrichment_receipt_is_approved_and_violation_count() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    let receipt = eval.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn enrichment_receipt_seal_deterministic() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        MILLIONTHS,
        100,
        true,
    ));
    let r1 = eval.evaluate();
    eval.clear();
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        MILLIONTHS,
        100,
        true,
    ));
    let r2 = eval.evaluate();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// =========================================================================
// M. GovernanceEvaluator tracking
// =========================================================================

#[test]
fn enrichment_evaluator_counters_increment() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());

    assert_eq!(eval.evaluation_count(), 0);
    assert_eq!(eval.approved_count(), 0);
    assert_eq!(eval.denied_count(), 0);

    let _ = eval.evaluate(); // approved (permissive)
    assert_eq!(eval.evaluation_count(), 1);
    assert_eq!(eval.approved_count(), 1);
    assert_eq!(eval.denied_count(), 0);
}

#[test]
fn enrichment_evaluator_denied_increments() {
    let config = GovernanceConfig::default_config(); // fail_closed requires evidence
    let mut eval = GovernanceEvaluator::new(config, ep());
    let receipt = eval.evaluate();
    assert!(!receipt.is_approved());
    assert_eq!(eval.denied_count(), 1);
    assert_eq!(eval.approved_count(), 0);
}

#[test]
fn enrichment_evaluator_last_receipt_available() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    assert!(eval.last_receipt().is_none());
    let receipt = eval.evaluate();
    assert!(eval.last_receipt().is_some());
    assert_eq!(eval.last_receipt().unwrap().content_hash, receipt.content_hash);
}

#[test]
fn enrichment_evaluator_pass_rate() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    // 0 evaluations -> 0 pass rate
    assert_eq!(eval.pass_rate_millionths(), 0);
    let _ = eval.evaluate();
    // 1/1 = 100%
    assert_eq!(eval.pass_rate_millionths(), MILLIONTHS);
}

#[test]
fn enrichment_evaluator_accessors() {
    let config = GovernanceConfig::default_config();
    let eval = GovernanceEvaluator::with_defaults(ep());
    assert_eq!(*eval.epoch(), ep());
    assert_eq!(eval.config().min_parity_millionths, config.min_parity_millionths);
    assert!(eval.parity_results().is_empty());
    assert!(eval.unicode_coverage().is_empty());
    assert!(eval.benchmark_entries().is_empty());
    assert!(eval.tail_risk_entries().is_empty());
}

// =========================================================================
// N. GovernanceSummary serde
// =========================================================================

#[test]
fn enrichment_governance_summary_serde_roundtrip() {
    let summary = GovernanceSummary {
        total_evaluations: 10,
        approved_count: 8,
        denied_count: 2,
        parity_results_count: 15,
        unicode_coverage_count: 3,
        benchmark_count: 5,
        tail_risk_count: 2,
        pass_rate_millionths: 800_000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: GovernanceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_evaluator_summary_matches_state() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        MILLIONTHS,
        100,
        true,
    ));
    eval.add_unicode_coverage(UnicodeCoverage::new(0, 0, 0xFFFF, MILLIONTHS, true));
    eval.add_benchmark(BenchmarkEntry::new(
        BenchmarkCategory::String,
        "test",
        1000,
        500,
        50,
    ));
    eval.add_tail_risk(TailRiskEntry::new(
        ParitySubject::Lane(StringLane::Ascii),
        1100,
        1000,
    ));
    let _ = eval.evaluate();
    let summary = eval.summary();
    assert_eq!(summary.total_evaluations, 1);
    assert_eq!(summary.parity_results_count, 1);
    assert_eq!(summary.unicode_coverage_count, 1);
    assert_eq!(summary.benchmark_count, 1);
    assert_eq!(summary.tail_risk_count, 1);
}

// =========================================================================
// O. summarize_receipt
// =========================================================================

#[test]
fn enrichment_summarize_receipt_approved() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    let receipt = eval.evaluate();
    let summary = summarize_receipt(&receipt);
    assert!(summary.contains("approved"));
    assert!(summary.contains("epoch"));
    assert!(summary.contains("violations: 0"));
}

#[test]
fn enrichment_summarize_receipt_with_violations() {
    let config = GovernanceConfig::default_config();
    let mut eval = GovernanceEvaluator::new(config, ep());
    let receipt = eval.evaluate();
    let summary = summarize_receipt(&receipt);
    assert!(!summary.contains("verdict: approved\n"));
    assert!(summary.contains("violation details"));
}

// =========================================================================
// P. regexp_string_governance_manifest
// =========================================================================

#[test]
fn enrichment_manifest_all_zeros() {
    let manifest = regexp_string_governance_manifest();
    assert_eq!(manifest.total_evaluations, 0);
    assert_eq!(manifest.approved_count, 0);
    assert_eq!(manifest.denied_count, 0);
    assert_eq!(manifest.pass_rate_millionths, 0);
}

// =========================================================================
// Q. Edge cases: parity exactly at threshold
// =========================================================================

#[test]
fn enrichment_parity_exactly_at_threshold_passes() {
    let mut config = GovernanceConfig::permissive();
    config.min_parity_millionths = 950_000;
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        950_000, // exactly at threshold
        100,
        true,
    ));
    let receipt = eval.evaluate();
    assert!(receipt.is_approved());
}

#[test]
fn enrichment_parity_one_below_threshold_fails() {
    let mut config = GovernanceConfig::permissive();
    config.min_parity_millionths = 950_000;
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        949_999,
        100,
        false,
    ));
    let receipt = eval.evaluate();
    assert!(!receipt.is_approved());
    assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
}

// =========================================================================
// R. Edge case: tail risk exactly at threshold
// =========================================================================

#[test]
fn enrichment_tail_risk_exactly_at_threshold_passes() {
    let mut config = GovernanceConfig::permissive();
    config.max_tail_risk_millionths = 2_000_000; // 2.0x
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_tail_risk(TailRiskEntry::new(
        ParitySubject::Lane(StringLane::Utf8),
        2000,
        1000, // ratio = 2_000_000 exactly
    ));
    let receipt = eval.evaluate();
    assert!(receipt.is_approved());
}

#[test]
fn enrichment_tail_risk_above_threshold_fails() {
    let mut config = GovernanceConfig::permissive();
    config.max_tail_risk_millionths = 2_000_000;
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_tail_risk(TailRiskEntry::new(
        ParitySubject::Lane(StringLane::Utf8),
        2001,
        1000, // ratio > 2_000_000
    ));
    let receipt = eval.evaluate();
    assert!(!receipt.is_approved());
    assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
}

// =========================================================================
// S. GovernanceEvaluator serde roundtrip
// =========================================================================

#[test]
fn enrichment_evaluator_serde_roundtrip() {
    let config = GovernanceConfig::permissive();
    let eval = GovernanceEvaluator::new(config, ep());
    let json = serde_json::to_string(&eval).unwrap();
    let _back: GovernanceEvaluator = serde_json::from_str(&json).unwrap();
}

// =========================================================================
// T. GovernanceReceipt serde roundtrip
// =========================================================================

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::new(config, ep());
    eval.add_parity(ParityResult::new(
        ParitySubject::Lane(StringLane::Ascii),
        ParityAxis::Semantic,
        MILLIONTHS,
        100,
        true,
    ));
    let receipt = eval.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// =========================================================================
// U. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", StringLane::Ascii).is_empty());
    assert!(!format!("{:?}", RegexpFeature::Lookahead).is_empty());
    assert!(!format!("{:?}", ParityAxis::Semantic).is_empty());
    assert!(!format!("{:?}", ParitySubject::Lane(StringLane::Utf8)).is_empty());
    assert!(!format!("{:?}", BenchmarkCategory::String).is_empty());
    assert!(!format!("{:?}", GovernanceVerdict::Approved).is_empty());
    assert!(!format!("{:?}", GovernanceConfig::default_config()).is_empty());
}
