// Integration tests for resource_certificate_governance module.
//
// Covers: constants, type ordering, constructor verification, lifecycle flows,
// verdict determination, content hash determinism, and E2E scenarios.

use frankenengine_engine::resource_certificate_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("resource-certificate-governance"));
}

#[test]
fn test_schema_version_ends_with_v1() {
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "resource_certificate_governance");
}

#[test]
fn test_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(BEAD_ID, "bd-1lsy.7.25.3");
}

#[test]
fn test_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(POLICY_ID, "RGC-625C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_constants_positive() {
    const {
        assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS > 0);
        assert!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS > 0);
        assert!(DEFAULT_MIN_SAMPLES > 0);
        assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE > 0);
        assert!(DEFAULT_MAX_UTILISATION_MILLIONTHS > 0);
    }
}

// ---------------------------------------------------------------------------
// ResourceDimension ordering and display
// ---------------------------------------------------------------------------

#[test]
fn test_resource_dimension_all_returns_ten() {
    assert_eq!(ResourceDimension::all().len(), 10);
}

#[test]
fn test_resource_dimension_ordering_first_last() {
    assert!(ResourceDimension::CpuTime < ResourceDimension::InstructionCount);
}

#[test]
fn test_resource_dimension_ordering_adjacent() {
    let all = ResourceDimension::all();
    for i in 0..all.len() - 1 {
        assert!(
            all[i] < all[i + 1],
            "{:?} should be < {:?}",
            all[i],
            all[i + 1]
        );
    }
}

#[test]
fn test_resource_dimension_display_cpu_time() {
    assert_eq!(ResourceDimension::CpuTime.to_string(), "cpu_time");
}

#[test]
fn test_resource_dimension_display_heap_memory() {
    assert_eq!(ResourceDimension::HeapMemory.to_string(), "heap_memory");
}

#[test]
fn test_resource_dimension_display_gc_pause() {
    assert_eq!(ResourceDimension::GcPause.to_string(), "gc_pause");
}

#[test]
fn test_resource_dimension_all_unique() {
    let all = ResourceDimension::all();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence construction
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_within_budget() {
    let c = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        800,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(c.within_budget);
    assert_eq!(c.utilisation_millionths, 800_000);
}

#[test]
fn test_certificate_over_budget() {
    let c = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        950,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(!c.within_budget);
}

#[test]
fn test_certificate_zero_budget_nonzero_usage() {
    let c = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        0,
        100,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(c.utilisation_millionths, FIXED_ONE);
}

#[test]
fn test_certificate_zero_budget_zero_usage() {
    let c = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        0,
        0,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(c.utilisation_millionths, 0);
}

#[test]
fn test_certificate_exact_budget() {
    let c = CertificateEvidence::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        1000,
        900,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(c.utilisation_millionths, 900_000);
    assert!(c.within_budget);
}

#[test]
fn test_certificate_hash_determinism() {
    let a = CertificateEvidence::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        1000,
        500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let b = CertificateEvidence::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        1000,
        500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_certificate_hash_differs_on_dimension() {
    let a = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let b = CertificateEvidence::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        1000,
        500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

// ---------------------------------------------------------------------------
// RegressionEntry
// ---------------------------------------------------------------------------

#[test]
fn test_regression_within_budget() {
    let r = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        1020,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert!(r.within_budget);
    assert_eq!(r.regression_millionths, 20_000);
}

#[test]
fn test_regression_exceeds_budget() {
    let r = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        1100,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert!(!r.within_budget);
}

#[test]
fn test_regression_improvement_is_zero() {
    let r = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        1000,
        900,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(r.regression_millionths, 0);
    assert!(r.within_budget);
}

#[test]
fn test_regression_zero_previous() {
    let r = RegressionEntry::new(
        ResourceDimension::CpuTime,
        "w1".into(),
        0,
        100,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(r.regression_millionths, FIXED_ONE);
}

#[test]
fn test_regression_hash_determinism() {
    let a = RegressionEntry::new(
        ResourceDimension::WallTime,
        "w1".into(),
        500,
        520,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    let b = RegressionEntry::new(
        ResourceDimension::WallTime,
        "w1".into(),
        500,
        520,
        DEFAULT_MAX_REGRESSION_MILLIONTHS,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

// ---------------------------------------------------------------------------
// TailRiskEntry
// ---------------------------------------------------------------------------

#[test]
fn test_tail_risk_within_budget() {
    let t = TailRiskEntry::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        2_100_000,
        2_050_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert!(t.within_budget);
    assert_eq!(t.drift_millionths, 50_000);
}

#[test]
fn test_tail_risk_exceeds_budget() {
    let t = TailRiskEntry::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        3_000_000,
        2_000_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert!(!t.within_budget);
}

#[test]
fn test_tail_risk_improvement_zero_drift() {
    let t = TailRiskEntry::new(
        ResourceDimension::HeapMemory,
        "w1".into(),
        1_500_000,
        2_000_000,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(t.drift_millionths, 0);
    assert!(t.within_budget);
}

// ---------------------------------------------------------------------------
// PublicationPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_policy_strict_requires_all_dimensions() {
    let p = PublicationPolicy::strict();
    assert_eq!(p.required_dimensions.len(), 10);
    for dim in ResourceDimension::all() {
        assert!(p.required_dimensions.contains(dim));
    }
}

#[test]
fn test_policy_strict_tighter_than_relaxed() {
    let s = PublicationPolicy::strict();
    let r = PublicationPolicy::relaxed();
    assert!(s.max_regression_millionths <= r.max_regression_millionths);
    assert!(s.max_tail_risk_millionths <= r.max_tail_risk_millionths);
    assert!(s.min_samples >= r.min_samples);
}

#[test]
fn test_policy_relaxed_no_required_dimensions() {
    let p = PublicationPolicy::relaxed();
    assert!(p.required_dimensions.is_empty());
}

#[test]
fn test_policy_default_is_relaxed() {
    let d = PublicationPolicy::default();
    let r = PublicationPolicy::relaxed();
    assert_eq!(d, r);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_approved_does_not_block() {
    assert!(!GovernanceVerdict::Approved.blocks_publication());
}

#[test]
fn test_verdict_all_non_approved_block() {
    let blocking = [
        GovernanceVerdict::UtilisationExceeded,
        GovernanceVerdict::RegressionDetected,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::InsufficientSamples,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &blocking {
        assert!(v.blocks_publication(), "{:?} should block", v);
    }
}

#[test]
fn test_verdict_display_approved() {
    assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
}

#[test]
fn test_verdict_display_regression_detected() {
    assert_eq!(
        GovernanceVerdict::RegressionDetected.to_string(),
        "regression_detected"
    );
}

#[test]
fn test_verdict_ordering() {
    assert!(GovernanceVerdict::Approved < GovernanceVerdict::MultipleViolations);
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_empty_relaxed_approved() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
}

#[test]
fn test_evaluator_certificate_pass() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.certificates.len(), 1);
}

#[test]
fn test_evaluator_certificate_fail_utilisation() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::UtilisationExceeded);
}

#[test]
fn test_evaluator_certificate_fail_samples() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 5);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientSamples);
}

#[test]
fn test_evaluator_regression_fail() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1200);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::RegressionDetected);
}

#[test]
fn test_evaluator_tail_risk_fail() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_tail_risk(
        ResourceDimension::CpuTime,
        "w1".into(),
        5_000_000,
        2_000_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
}

#[test]
fn test_evaluator_missing_required_dimension() {
    let mut policy = PublicationPolicy::relaxed();
    policy
        .required_dimensions
        .insert(ResourceDimension::GcPause);
    let eval = GovernanceEvaluator::new(policy);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert!(
        receipt
            .dimensions_missing
            .contains(&ResourceDimension::GcPause)
    );
}

#[test]
fn test_evaluator_multiple_violations_utilisation_and_regression() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1200);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_dimensions_evaluated_tracked() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1000);
    let receipt = eval.evaluate(epoch());
    assert!(
        receipt
            .dimensions_evaluated
            .contains(&ResourceDimension::CpuTime)
    );
    assert!(
        receipt
            .dimensions_evaluated
            .contains(&ResourceDimension::HeapMemory)
    );
}

#[test]
fn test_evaluator_epoch_recorded() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let receipt = eval.evaluate(SecurityEpoch::from_raw(99));
    assert_eq!(receipt.epoch, SecurityEpoch::from_raw(99));
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic_two_evaluations() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    let r1 = eval.evaluate(epoch());
    let r2 = eval.evaluate(epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_when_data_added() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let r1 = eval.evaluate(epoch());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    let r2 = eval.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_with_epoch() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    let r1 = eval.evaluate(SecurityEpoch::from_raw(1));
    let r2 = eval.evaluate(SecurityEpoch::from_raw(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_pass_relaxed() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    eval.add_certificate(ResourceDimension::HeapMemory, "w1".into(), 2000, 1000, 50);
    eval.add_regression(ResourceDimension::CpuTime, "w1".into(), 1000, 1000);
    eval.add_tail_risk(
        ResourceDimension::CpuTime,
        "w1".into(),
        2_100_000,
        2_050_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
}

#[test]
fn test_e2e_strict_empty_fails_coverage() {
    let eval = GovernanceEvaluator::new(PublicationPolicy::strict());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert_eq!(receipt.dimensions_missing.len(), 10);
}

#[test]
fn test_e2e_multiple_dimensions_mixed() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    eval.add_certificate(ResourceDimension::HeapMemory, "w1".into(), 2000, 500, 50);
    eval.add_certificate(ResourceDimension::StackDepth, "w1".into(), 500, 250, 50);
    eval.add_regression(ResourceDimension::CpuTime, "w1".into(), 1000, 1010);
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 2000, 2010);
    eval.add_tail_risk(
        ResourceDimension::CpuTime,
        "w1".into(),
        2_050_000,
        2_050_000,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.dimensions_evaluated.len() >= 3);
}

#[test]
fn test_e2e_three_violation_categories() {
    let mut policy = PublicationPolicy::relaxed();
    policy
        .required_dimensions
        .insert(ResourceDimension::GcPause);
    let mut eval = GovernanceEvaluator::new(policy);
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
    eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1200);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violations.len() >= 3);
}

#[test]
fn test_e2e_regression_pass_no_change() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
    eval.add_regression(ResourceDimension::CpuTime, "w1".into(), 1000, 1000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_e2e_violation_detail_contents() {
    let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
    eval.add_regression(ResourceDimension::IoOperations, "bench".into(), 1000, 1200);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert_eq!(v.category, GovernanceVerdict::RegressionDetected);
    assert_eq!(v.dimension, ResourceDimension::IoOperations);
    assert!(v.measured_millionths > 0);
}
