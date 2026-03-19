//! Enrichment integration tests for the `resource_certificate_governance` module.
//!
//! Covers: enum serde roundtrips, Display uniqueness, struct construction,
//! lifecycle flows, arithmetic edge cases, content hash determinism,
//! violation detail correctness, and multi-workload governance scenarios.

use std::collections::BTreeSet;

use frankenengine_engine::resource_certificate_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(77)
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_resource_dimension_all_roundtrip() {
    for dim in ResourceDimension::all() {
        let json = serde_json::to_string(dim).unwrap();
        let back: ResourceDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back, "roundtrip failed for {dim}");
    }
}

#[test]
fn enrichment_serde_resource_dimension_snake_case_format() {
    // serde(rename_all = "snake_case") means JSON values are snake_case strings.
    let json = serde_json::to_string(&ResourceDimension::CpuTime).unwrap();
    assert_eq!(json, "\"cpu_time\"");
    let json = serde_json::to_string(&ResourceDimension::NetworkBandwidth).unwrap();
    assert_eq!(json, "\"network_bandwidth\"");
}

#[test]
fn enrichment_serde_governance_verdict_all_roundtrip() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::UtilisationExceeded,
        GovernanceVerdict::RegressionDetected,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::InsufficientSamples,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back, "roundtrip failed for {v}");
    }
}

#[test]
fn enrichment_serde_governance_verdict_snake_case_format() {
    let json = serde_json::to_string(&GovernanceVerdict::TailRiskExceeded).unwrap();
    assert_eq!(json, "\"tail_risk_exceeded\"");
    let json = serde_json::to_string(&GovernanceVerdict::MultipleViolations).unwrap();
    assert_eq!(json, "\"multiple_violations\"");
}

#[test]
fn enrichment_serde_publication_policy_strict_roundtrip() {
    let strict = PublicationPolicy::strict();
    let json = serde_json::to_string(&strict).unwrap();
    let back: PublicationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(strict, back);
}

#[test]
fn enrichment_serde_publication_policy_relaxed_roundtrip() {
    let relaxed = PublicationPolicy::relaxed();
    let json = serde_json::to_string(&relaxed).unwrap();
    let back: PublicationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(relaxed, back);
}

#[test]
fn enrichment_serde_certificate_evidence_roundtrip() {
    let ce = CertificateEvidence::new(
        ResourceDimension::IoOperations,
        "serde_wl".into(),
        8000,
        4000,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let json = serde_json::to_string(&ce).unwrap();
    let back: CertificateEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, back);
}

#[test]
fn enrichment_serde_regression_entry_roundtrip() {
    let re = RegressionEntry::new(
        ResourceDimension::StackDepth,
        "regr_wl".into(),
        500,
        510,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    let json = serde_json::to_string(&re).unwrap();
    let back: RegressionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(re, back);
}

#[test]
fn enrichment_serde_tail_risk_entry_roundtrip() {
    let te = TailRiskEntry::new(
        ResourceDimension::GcPause,
        "tail_wl".into(),
        2_200_000,
        2_100_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    let json = serde_json::to_string(&te).unwrap();
    let back: TailRiskEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(te, back);
}

#[test]
fn enrichment_serde_governance_receipt_full_roundtrip() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 2000, 1000, 60);
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 800, 810);
    eval.add_tail_risk(
        ResourceDimension::GcPause,
        "w1".into(),
        2_050_000,
        2_000_000,
    );
    let receipt = eval.evaluate(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_serde_evaluator_roundtrip() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::strict());
    eval.add_certificate(ResourceDimension::WallTime, "ev_rt".into(), 3000, 1000, 200);
    eval.add_regression(ResourceDimension::AllocationCount, "ev_rt".into(), 600, 610);
    let json = serde_json::to_string(&eval).unwrap();
    let back: GovernanceEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ---------------------------------------------------------------------------
// Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_resource_dimension_all_unique() {
    let displays: BTreeSet<String> = ResourceDimension::all()
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(displays.len(), ResourceDimension::all().len());
}

#[test]
fn enrichment_display_governance_verdict_all_unique() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::UtilisationExceeded,
        GovernanceVerdict::RegressionDetected,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::InsufficientSamples,
        GovernanceVerdict::MultipleViolations,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), verdicts.len());
}

#[test]
fn enrichment_display_dimension_matches_serde() {
    // Display and serde should produce the same snake_case string.
    for dim in ResourceDimension::all() {
        let display = dim.to_string();
        let serde_json_str = serde_json::to_string(dim).unwrap();
        // serde wraps in quotes
        let serde_val = serde_json_str.trim_matches('"');
        assert_eq!(display, serde_val, "mismatch for {dim:?}");
    }
}

// ---------------------------------------------------------------------------
// Struct construction and fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_struct_certificate_evidence_fields() {
    let ce = CertificateEvidence::new(
        ResourceDimension::FileDescriptors,
        "fd_workload".into(),
        500,
        250,
        40,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ce.dimension, ResourceDimension::FileDescriptors);
    assert_eq!(ce.workload_id, "fd_workload");
    assert_eq!(ce.certified_budget, 500);
    assert_eq!(ce.measured_usage, 250);
    assert_eq!(ce.sample_count, 40);
    assert_eq!(ce.utilisation_millionths, 500_000);
    assert!(ce.within_budget);
}

#[test]
fn enrichment_struct_regression_entry_fields() {
    let re = RegressionEntry::new(
        ResourceDimension::NetworkBandwidth,
        "net_wl".into(),
        2000,
        2100,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(re.dimension, ResourceDimension::NetworkBandwidth);
    assert_eq!(re.workload_id, "net_wl");
    assert_eq!(re.previous_usage, 2000);
    assert_eq!(re.current_usage, 2100);
    assert_eq!(re.regression_millionths, 50_000); // 5%
    assert!(re.within_budget); // exactly at 50_000 threshold
}

#[test]
fn enrichment_struct_tail_risk_entry_fields() {
    let te = TailRiskEntry::new(
        ResourceDimension::InstructionCount,
        "ic_wl".into(),
        3_000_000,
        2_800_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(te.dimension, ResourceDimension::InstructionCount);
    assert_eq!(te.workload_id, "ic_wl");
    assert_eq!(te.tail_ratio_millionths, 3_000_000);
    assert_eq!(te.baseline_ratio_millionths, 2_800_000);
    assert_eq!(te.drift_millionths, 200_000);
    assert!(!te.within_budget); // 200_000 > 100_000 default
}

#[test]
fn enrichment_struct_violation_detail_construction() {
    let vd = ViolationDetail {
        dimension: ResourceDimension::HeapMemory,
        workload_id: "vd_wl".into(),
        category: GovernanceVerdict::UtilisationExceeded,
        summary: "heap too high".into(),
        measured_millionths: 950_000,
        threshold_millionths: 900_000,
    };
    assert_eq!(vd.dimension, ResourceDimension::HeapMemory);
    assert_eq!(vd.category, GovernanceVerdict::UtilisationExceeded);
    assert_eq!(vd.measured_millionths, 950_000);
}

// ---------------------------------------------------------------------------
// Lifecycle and evaluator flows
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_evaluator_empty_relaxed_approved() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert!(receipt.certificates.is_empty());
    assert!(receipt.regressions.is_empty());
    assert!(receipt.tail_risks.is_empty());
    assert!(receipt.dimensions_evaluated.is_empty());
    assert!(receipt.dimensions_missing.is_empty());
}

#[test]
fn enrichment_lifecycle_strict_all_dimensions_satisfied() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::strict());
    for dim in ResourceDimension::all() {
        eval.add_certificate(*dim, "strict_bench".into(), 10_000, 5_000, 200);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.dimensions_missing.is_empty());
    assert_eq!(receipt.dimensions_evaluated.len(), 10);
    assert_eq!(receipt.certificates.len(), 10);
}

#[test]
fn enrichment_lifecycle_strict_partially_covered() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::strict());
    // Cover only 3 out of 10 required dimensions.
    eval.add_certificate(
        ResourceDimension::CpuTime,
        "partial".into(),
        5000,
        2000,
        200,
    );
    eval.add_certificate(
        ResourceDimension::HeapMemory,
        "partial".into(),
        5000,
        2000,
        200,
    );
    eval.add_certificate(
        ResourceDimension::StackDepth,
        "partial".into(),
        5000,
        2000,
        200,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert_eq!(receipt.dimensions_missing.len(), 7);
    assert_eq!(receipt.dimensions_evaluated.len(), 3);
}

#[test]
fn enrichment_lifecycle_mixed_evidence_types_cover_dimension() {
    // A required dimension can be satisfied by regression or tail-risk evidence,
    // not only certificate evidence.
    let mut policy = PublicationPolicy::relaxed();
    policy
        .required_dimensions
        .insert(ResourceDimension::CpuTime);
    policy
        .required_dimensions
        .insert(ResourceDimension::HeapMemory);
    policy
        .required_dimensions
        .insert(ResourceDimension::GcPause);

    let mut eval = GovernanceEvaluator::new(policy);
    eval.add_certificate(ResourceDimension::CpuTime, "w".into(), 1000, 500, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "w".into(), 1000, 1000);
    eval.add_tail_risk(ResourceDimension::GcPause, "w".into(), 2_000_000, 2_000_000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.dimensions_missing.is_empty());
}

#[test]
fn enrichment_lifecycle_multiple_workloads_per_dimension() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    for i in 0..5 {
        eval.add_certificate(
            ResourceDimension::CpuTime,
            format!("workload_{i}"),
            1000,
            500,
            50,
        );
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.certificates.len(), 5);
    // Even with 5 entries, only 1 dimension is covered.
    assert_eq!(receipt.dimensions_evaluated.len(), 1);
}

// ---------------------------------------------------------------------------
// Arithmetic edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arithmetic_certificate_utilisation_exact_half() {
    let ce = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "half".into(),
        2000,
        1000,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ce.utilisation_millionths, 500_000); // exactly 50%
}

#[test]
fn enrichment_arithmetic_certificate_utilisation_full() {
    let ce = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "full".into(),
        1000,
        1000,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ce.utilisation_millionths, FIXED_ONE); // exactly 100%
    assert!(!ce.within_budget); // 1_000_000 > 900_000
}

#[test]
fn enrichment_arithmetic_certificate_zero_budget_nonzero_usage() {
    // Division by zero case: measured > 0, budget = 0 => FIXED_ONE.
    let ce = CertificateEvidence::new(
        ResourceDimension::WallTime,
        "zero_budget".into(),
        0,
        50,
        30,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ce.utilisation_millionths, FIXED_ONE);
    assert!(!ce.within_budget);
}

#[test]
fn enrichment_arithmetic_certificate_zero_budget_zero_usage() {
    // Both zero: 0 * FIXED_ONE / 0 => checked_div returns None, measured_usage == 0 => 0.
    let ce = CertificateEvidence::new(
        ResourceDimension::WallTime,
        "zero_both".into(),
        0,
        0,
        30,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ce.utilisation_millionths, 0);
    assert!(ce.within_budget);
}

#[test]
fn enrichment_arithmetic_regression_improvement_is_zero() {
    // current < previous => saturating_sub => 0 regression.
    let re = RegressionEntry::new(
        ResourceDimension::HeapMemory,
        "improved".into(),
        1000,
        800,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(re.regression_millionths, 0);
    assert!(re.within_budget);
}

#[test]
fn enrichment_arithmetic_regression_zero_previous_nonzero_current() {
    // previous = 0, current > 0 => division by zero => FIXED_ONE.
    let re = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "from_zero".into(),
        0,
        100,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(re.regression_millionths, FIXED_ONE);
    assert!(!re.within_budget);
}

#[test]
fn enrichment_arithmetic_regression_both_zero() {
    let re = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "both_zero".into(),
        0,
        0,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(re.regression_millionths, 0);
    assert!(re.within_budget);
}

#[test]
fn enrichment_arithmetic_tail_risk_improvement_saturates() {
    // tail < baseline => drift saturates to 0.
    let te = TailRiskEntry::new(
        ResourceDimension::GcPause,
        "improved_tail".into(),
        1_500_000,
        2_000_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(te.drift_millionths, 0);
    assert!(te.within_budget);
}

#[test]
fn enrichment_arithmetic_tail_risk_exact_at_threshold() {
    let te = TailRiskEntry::new(
        ResourceDimension::IoOperations,
        "exact_drift".into(),
        2_100_000,
        2_000_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(te.drift_millionths, 100_000);
    assert!(te.within_budget); // exactly at threshold, <= passes
}

#[test]
fn enrichment_arithmetic_tail_risk_one_over_threshold() {
    let te = TailRiskEntry::new(
        ResourceDimension::IoOperations,
        "one_over".into(),
        2_100_001,
        2_000_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(te.drift_millionths, 100_001);
    assert!(!te.within_budget);
}

#[test]
fn enrichment_arithmetic_large_values_no_panic() {
    // Saturating arithmetic should prevent overflow panics.
    let ce = CertificateEvidence::new(
        ResourceDimension::InstructionCount,
        "huge".into(),
        u64::MAX,
        u64::MAX,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    // Should not panic. Utilisation = MAX * 1_000_000 saturates, then / MAX = something.
    let _ = ce.utilisation_millionths;

    let re = RegressionEntry::new(
        ResourceDimension::InstructionCount,
        "huge_reg".into(),
        1,
        u64::MAX,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    let _ = re.regression_millionths;
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_certificate_deterministic() {
    let a = CertificateEvidence::new(
        ResourceDimension::AllocationCount,
        "det_hash".into(),
        4000,
        2000,
        80,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let b = CertificateEvidence::new(
        ResourceDimension::AllocationCount,
        "det_hash".into(),
        4000,
        2000,
        80,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn enrichment_hash_certificate_differs_by_usage() {
    let a = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w".into(),
        1000,
        500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let b = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w".into(),
        1000,
        501,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn enrichment_hash_regression_deterministic() {
    let a = RegressionEntry::new(
        ResourceDimension::WallTime,
        "rdet".into(),
        800,
        820,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    let b = RegressionEntry::new(
        ResourceDimension::WallTime,
        "rdet".into(),
        800,
        820,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn enrichment_hash_tail_risk_deterministic() {
    let a = TailRiskEntry::new(
        ResourceDimension::GcPause,
        "tdet".into(),
        2_500_000,
        2_300_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    let b = TailRiskEntry::new(
        ResourceDimension::GcPause,
        "tdet".into(),
        2_500_000,
        2_300_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn enrichment_hash_receipt_deterministic_across_evaluations() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "h1".into(), 2000, 1000, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "h1".into(), 500, 510);
    let r1 = eval.evaluate(epoch());
    let r2 = eval.evaluate(epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_hash_receipt_differs_with_additional_certificate() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let r1 = eval.evaluate(epoch());
    eval.add_certificate(ResourceDimension::CpuTime, "extra".into(), 1000, 500, 50);
    let r2 = eval.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_hash_receipt_differs_with_different_epoch() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let r1 = eval.evaluate(SecurityEpoch::from_raw(10));
    let r2 = eval.evaluate(SecurityEpoch::from_raw(11));
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Governance verdict logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_single_utilisation_violation() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "over".into(), 1000, 950, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::UtilisationExceeded);
    assert!(receipt.verdict.blocks_publication());
}

#[test]
fn enrichment_verdict_single_regression_violation() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_regression(
        ResourceDimension::HeapMemory,
        "regressed".into(),
        1000,
        1200,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::RegressionDetected);
}

#[test]
fn enrichment_verdict_single_tail_risk_violation() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_tail_risk(
        ResourceDimension::CpuTime,
        "bad_tail".into(),
        5_000_000,
        2_000_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
}

#[test]
fn enrichment_verdict_insufficient_samples_only() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    // Usage within budget, but only 5 samples (min is 30).
    eval.add_certificate(ResourceDimension::CpuTime, "few".into(), 1000, 500, 5);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientSamples);
    assert_eq!(receipt.violations.len(), 1);
}

#[test]
fn enrichment_verdict_multiple_violations_two_categories() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    // Utilisation exceeded + regression detected => two categories => MultipleViolations.
    eval.add_certificate(ResourceDimension::CpuTime, "w".into(), 1000, 960, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "w".into(), 1000, 1200);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn enrichment_verdict_same_category_multiple_entries_not_multiple_violations() {
    // Multiple utilisation violations of the SAME category => single verdict, not MultipleViolations.
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
    eval.add_certificate(ResourceDimension::HeapMemory, "w2".into(), 1000, 960, 50);
    eval.add_certificate(ResourceDimension::WallTime, "w3".into(), 1000, 970, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::UtilisationExceeded);
    assert_eq!(receipt.violations.len(), 3);
}

#[test]
fn enrichment_verdict_approved_does_not_block() {
    assert!(!GovernanceVerdict::Approved.blocks_publication());
}

#[test]
fn enrichment_verdict_all_non_approved_block() {
    let blocking = [
        GovernanceVerdict::UtilisationExceeded,
        GovernanceVerdict::RegressionDetected,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::InsufficientSamples,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &blocking {
        assert!(v.blocks_publication(), "{v} should block");
    }
}

// ---------------------------------------------------------------------------
// Violation detail correctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_violation_detail_regression_fields() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_regression(
        ResourceDimension::AllocationCount,
        "alloc_wl".into(),
        1000,
        1200,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert_eq!(v.dimension, ResourceDimension::AllocationCount);
    assert_eq!(v.workload_id, "alloc_wl");
    assert_eq!(v.category, GovernanceVerdict::RegressionDetected);
    assert_eq!(v.threshold_millionths, DEFAULT_MAX_REGRESSION_MILLIONTHS);
    assert!(v.measured_millionths > DEFAULT_MAX_REGRESSION_MILLIONTHS);
}

#[test]
fn enrichment_violation_detail_tail_risk_fields() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_tail_risk(
        ResourceDimension::NetworkBandwidth,
        "net_wl".into(),
        4_000_000,
        2_000_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert_eq!(v.dimension, ResourceDimension::NetworkBandwidth);
    assert_eq!(v.category, GovernanceVerdict::TailRiskExceeded);
    assert_eq!(v.threshold_millionths, DEFAULT_MAX_TAIL_RISK_MILLIONTHS);
    assert_eq!(v.measured_millionths, 2_000_000); // drift = 4M - 2M
}

#[test]
fn enrichment_violation_detail_insufficient_coverage_empty_workload() {
    let mut policy = PublicationPolicy::relaxed();
    policy
        .required_dimensions
        .insert(ResourceDimension::StackDepth);
    let eval = GovernanceEvaluator::new(policy);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert!(v.workload_id.is_empty());
    assert_eq!(v.category, GovernanceVerdict::InsufficientCoverage);
}

// ---------------------------------------------------------------------------
// Policy construction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_default_is_relaxed() {
    assert_eq!(PublicationPolicy::default(), PublicationPolicy::relaxed());
}

#[test]
fn enrichment_policy_strict_has_all_required_dimensions() {
    let strict = PublicationPolicy::strict();
    assert_eq!(strict.required_dimensions.len(), 10);
    for dim in ResourceDimension::all() {
        assert!(strict.required_dimensions.contains(dim));
    }
}

#[test]
fn enrichment_policy_relaxed_has_no_required_dimensions() {
    let relaxed = PublicationPolicy::relaxed();
    assert!(relaxed.required_dimensions.is_empty());
}

#[test]
fn enrichment_policy_strict_tighter_on_all_thresholds() {
    let strict = PublicationPolicy::strict();
    let relaxed = PublicationPolicy::relaxed();
    assert!(strict.max_regression_millionths < relaxed.max_regression_millionths);
    assert!(strict.max_tail_risk_millionths < relaxed.max_tail_risk_millionths);
    assert!(strict.max_utilisation_millionths < relaxed.max_utilisation_millionths);
    assert!(strict.min_samples > relaxed.min_samples);
    assert!(strict.min_observability_coverage > relaxed.min_observability_coverage);
}

// ---------------------------------------------------------------------------
// Receipt structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_epoch_preserved() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let custom_epoch = SecurityEpoch::from_raw(12345);
    let receipt = eval.evaluate(custom_epoch);
    assert_eq!(receipt.epoch, custom_epoch);
}

#[test]
fn enrichment_receipt_captures_all_evidence() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "c1".into(), 1000, 500, 50);
    eval.add_certificate(ResourceDimension::WallTime, "c2".into(), 2000, 1000, 60);
    eval.add_regression(ResourceDimension::HeapMemory, "r1".into(), 500, 500);
    eval.add_tail_risk(
        ResourceDimension::GcPause,
        "t1".into(),
        2_000_000,
        2_000_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.certificates.len(), 2);
    assert_eq!(receipt.regressions.len(), 1);
    assert_eq!(receipt.tail_risks.len(), 1);
    assert_eq!(receipt.dimensions_evaluated.len(), 4);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_defaults_are_positive() {
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS > 0);
    assert!(DEFAULT_MIN_SAMPLES > 0);
    assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE > 0);
    assert!(DEFAULT_MAX_UTILISATION_MILLIONTHS > 0);
}

#[test]
fn enrichment_constants_defaults_below_fixed_one() {
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MAX_UTILISATION_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE < FIXED_ONE);
}
