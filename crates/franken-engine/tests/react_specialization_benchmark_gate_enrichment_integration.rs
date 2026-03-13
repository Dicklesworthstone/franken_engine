//! Enrichment integration tests for `react_specialization_benchmark_gate`.
//!
//! Covers: enum ordering/Copy/Hash for SpecializationDomain, BenchmarkClass,
//! ParityDimension, RegressionSeverity, GateVerdict, GovernanceAction;
//! Display/as_str exhaustiveness; serde roundtrips for all enum types;
//! classify_regression boundary conditions; compute_regression edge cases
//! (zero baseline, equal candidate/baseline, below min_sample_count);
//! evaluate_cell insufficient evidence; parity report coverage math;
//! derive_governance_action all branches; compute_receipt determinism;
//! evaluate_benchmark_matrix overall logic; Debug formatting.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_specialization_benchmark_gate::{
    BenchmarkClass, BenchmarkConfig, BenchmarkSample, DecisionReceipt, GateVerdict,
    GovernanceAction, ParityDimension, ParityFinding,
    RegressionSeverity, SpecializationDomain,
    BEAD_ID, COMPONENT, POLICY_ID, SCHEMA_VERSION,
    build_parity_report, classify_regression, compute_receipt, compute_regression,
    derive_governance_action, evaluate_benchmark_matrix, evaluate_cell,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample(
    domain: SpecializationDomain,
    class: BenchmarkClass,
    baseline: u64,
    candidate: u64,
    count: u64,
) -> BenchmarkSample {
    BenchmarkSample {
        domain,
        benchmark_class: class,
        baseline_value_millionths: baseline,
        candidate_value_millionths: candidate,
        sample_count: count,
        epoch: epoch(1),
        content_hash: ContentHash::compute(b"test-workload"),
    }
}

fn parity_finding(
    dim: ParityDimension,
    domain: SpecializationDomain,
    achieved: bool,
    divergences: u64,
    total: u64,
) -> ParityFinding {
    ParityFinding {
        dimension: dim,
        domain,
        is_parity_achieved: achieved,
        divergence_count: divergences,
        total_comparisons: total,
        detail: if achieved {
            "parity achieved".into()
        } else {
            format!("{divergences} divergences found")
        },
    }
}

// =========================================================================
// A. SpecializationDomain — ordering, Copy, Hash, Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_specialization_domain_ordering() {
    for i in 0..SpecializationDomain::ALL.len() - 1 {
        assert!(
            SpecializationDomain::ALL[i] < SpecializationDomain::ALL[i + 1],
            "{:?} should be < {:?}",
            SpecializationDomain::ALL[i],
            SpecializationDomain::ALL[i + 1]
        );
    }
}

#[test]
fn enrichment_specialization_domain_copy_hash() {
    let d = SpecializationDomain::SSR;
    let d2 = d;
    assert_eq!(d, d2);

    use std::hash::{Hash, Hasher};
    let mut hashes = BTreeSet::new();
    for variant in SpecializationDomain::ALL {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), 6);
}

#[test]
fn enrichment_specialization_domain_display_matches_as_str() {
    for d in SpecializationDomain::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrichment_specialization_domain_as_str_all_distinct() {
    let strings: BTreeSet<&str> = SpecializationDomain::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_specialization_domain_serde_all() {
    for d in SpecializationDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let restored: SpecializationDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, restored);
    }
}

// =========================================================================
// B. BenchmarkClass — ordering, Copy, Hash, Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_benchmark_class_ordering() {
    for i in 0..BenchmarkClass::ALL.len() - 1 {
        assert!(BenchmarkClass::ALL[i] < BenchmarkClass::ALL[i + 1]);
    }
}

#[test]
fn enrichment_benchmark_class_copy_hash() {
    let c = BenchmarkClass::Latency;
    let c2 = c;
    assert_eq!(c, c2);

    use std::hash::{Hash, Hasher};
    let mut hashes = BTreeSet::new();
    for variant in BenchmarkClass::ALL {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), 6);
}

#[test]
fn enrichment_benchmark_class_display_matches_as_str() {
    for c in BenchmarkClass::ALL {
        assert_eq!(c.to_string(), c.as_str());
    }
}

#[test]
fn enrichment_benchmark_class_serde_all() {
    for c in BenchmarkClass::ALL {
        let json = serde_json::to_string(c).unwrap();
        let restored: BenchmarkClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

// =========================================================================
// C. ParityDimension — ordering, Copy, Hash, Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_parity_dimension_ordering() {
    for i in 0..ParityDimension::ALL.len() - 1 {
        assert!(ParityDimension::ALL[i] < ParityDimension::ALL[i + 1]);
    }
}

#[test]
fn enrichment_parity_dimension_display_matches_as_str() {
    for d in ParityDimension::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrichment_parity_dimension_as_str_all_distinct() {
    let strings: BTreeSet<&str> = ParityDimension::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_parity_dimension_serde_all() {
    for d in ParityDimension::ALL {
        let json = serde_json::to_string(d).unwrap();
        let restored: ParityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, restored);
    }
}

// =========================================================================
// D. RegressionSeverity — ordering, serde
// =========================================================================

#[test]
fn enrichment_regression_severity_ordering() {
    assert!(RegressionSeverity::None < RegressionSeverity::Minor);
    assert!(RegressionSeverity::Minor < RegressionSeverity::Moderate);
    assert!(RegressionSeverity::Moderate < RegressionSeverity::Major);
    assert!(RegressionSeverity::Major < RegressionSeverity::Critical);
}

#[test]
fn enrichment_regression_severity_display_matches_as_str() {
    let all = [
        RegressionSeverity::None,
        RegressionSeverity::Minor,
        RegressionSeverity::Moderate,
        RegressionSeverity::Major,
        RegressionSeverity::Critical,
    ];
    for s in all {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrichment_regression_severity_serde_all() {
    let all = [
        RegressionSeverity::None,
        RegressionSeverity::Minor,
        RegressionSeverity::Moderate,
        RegressionSeverity::Major,
        RegressionSeverity::Critical,
    ];
    for s in all {
        let json = serde_json::to_string(&s).unwrap();
        let restored: RegressionSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

// =========================================================================
// E. GateVerdict — ordering, serde, as_str
// =========================================================================

#[test]
fn enrichment_gate_verdict_ordering() {
    assert!(GateVerdict::Pass < GateVerdict::ConditionalPass);
    assert!(GateVerdict::ConditionalPass < GateVerdict::MinorRegression);
    assert!(GateVerdict::MinorRegression < GateVerdict::MajorRegression);
    assert!(GateVerdict::MajorRegression < GateVerdict::Fail);
    assert!(GateVerdict::Fail < GateVerdict::InsufficientEvidence);
}

#[test]
fn enrichment_gate_verdict_as_str_all_distinct() {
    let all = [
        GateVerdict::Pass,
        GateVerdict::ConditionalPass,
        GateVerdict::MinorRegression,
        GateVerdict::MajorRegression,
        GateVerdict::Fail,
        GateVerdict::InsufficientEvidence,
    ];
    let strings: BTreeSet<&str> = all.iter().map(|v| v.as_str()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_gate_verdict_serde_all() {
    let all = [
        GateVerdict::Pass,
        GateVerdict::ConditionalPass,
        GateVerdict::MinorRegression,
        GateVerdict::MajorRegression,
        GateVerdict::Fail,
        GateVerdict::InsufficientEvidence,
    ];
    for v in all {
        let json = serde_json::to_string(&v).unwrap();
        let restored: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// =========================================================================
// F. GovernanceAction — ordering, serde, as_str
// =========================================================================

#[test]
fn enrichment_governance_action_ordering() {
    assert!(GovernanceAction::AllowRollout < GovernanceAction::ConditionalRollout);
    assert!(GovernanceAction::ConditionalRollout < GovernanceAction::BlockRollout);
    assert!(GovernanceAction::BlockRollout < GovernanceAction::RequireFreshBenchmark);
    assert!(GovernanceAction::RequireFreshBenchmark < GovernanceAction::DowngradeSpecialization);
    assert!(GovernanceAction::DowngradeSpecialization < GovernanceAction::RequireManualReview);
}

#[test]
fn enrichment_governance_action_as_str_all_distinct() {
    let all = [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshBenchmark,
        GovernanceAction::DowngradeSpecialization,
        GovernanceAction::RequireManualReview,
    ];
    let strings: BTreeSet<&str> = all.iter().map(|a| a.as_str()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_governance_action_serde_all() {
    let all = [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshBenchmark,
        GovernanceAction::DowngradeSpecialization,
        GovernanceAction::RequireManualReview,
    ];
    for a in all {
        let json = serde_json::to_string(&a).unwrap();
        let restored: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }
}

// =========================================================================
// G. classify_regression — boundary conditions
// =========================================================================

#[test]
fn enrichment_classify_regression_zero_is_none() {
    let cfg = BenchmarkConfig::default();
    assert_eq!(classify_regression(0, &cfg), RegressionSeverity::None);
}

#[test]
fn enrichment_classify_regression_below_minor_threshold() {
    let cfg = BenchmarkConfig::default(); // minor=50_000
    assert_eq!(
        classify_regression(49_999, &cfg),
        RegressionSeverity::Minor
    );
}

#[test]
fn enrichment_classify_regression_at_minor_threshold_is_moderate() {
    let cfg = BenchmarkConfig::default(); // minor=50_000
    assert_eq!(
        classify_regression(50_000, &cfg),
        RegressionSeverity::Moderate
    );
}

#[test]
fn enrichment_classify_regression_below_major_threshold() {
    let cfg = BenchmarkConfig::default(); // major=150_000
    assert_eq!(
        classify_regression(149_999, &cfg),
        RegressionSeverity::Moderate
    );
}

#[test]
fn enrichment_classify_regression_at_major_threshold_is_major() {
    let cfg = BenchmarkConfig::default(); // major=150_000
    assert_eq!(
        classify_regression(150_000, &cfg),
        RegressionSeverity::Major
    );
}

#[test]
fn enrichment_classify_regression_at_2x_major_is_critical() {
    let cfg = BenchmarkConfig::default(); // major=150_000, 2x=300_000
    assert_eq!(
        classify_regression(300_000, &cfg),
        RegressionSeverity::Critical
    );
}

// =========================================================================
// H. compute_regression — edge cases
// =========================================================================

#[test]
fn enrichment_compute_regression_empty_samples() {
    let cfg = BenchmarkConfig::default();
    assert!(compute_regression(&[], &cfg).is_none());
}

#[test]
fn enrichment_compute_regression_below_min_sample_count() {
    let cfg = BenchmarkConfig {
        min_sample_count: 100,
        ..Default::default()
    };
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        2_000_000,
        50, // below min of 100
    )];
    assert!(compute_regression(&samples, &cfg).is_none());
}

#[test]
fn enrichment_compute_regression_candidate_not_worse() {
    let cfg = BenchmarkConfig::default();
    // Candidate <= baseline → no regression.
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000, // improvement
        30,
    )];
    assert!(compute_regression(&samples, &cfg).is_none());
}

#[test]
fn enrichment_compute_regression_candidate_equal() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000, // equal
        30,
    )];
    assert!(compute_regression(&samples, &cfg).is_none());
}

#[test]
fn enrichment_compute_regression_produces_evidence() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Latency,
        1_000_000,
        1_200_000, // 20% regression
        30,
    )];
    let evidence = compute_regression(&samples, &cfg).unwrap();
    assert_eq!(evidence.domain, SpecializationDomain::SSR);
    assert_eq!(evidence.benchmark_class, BenchmarkClass::Latency);
    assert_eq!(evidence.baseline_mean_millionths, 1_000_000);
    assert_eq!(evidence.candidate_mean_millionths, 1_200_000);
    assert_eq!(evidence.delta_millionths, 200_000);
    // relative_delta = 200_000 / 1_000_000 * 1_000_000 = 200_000
    assert_eq!(evidence.relative_delta_millionths, 200_000);
    // 200_000 >= major (150_000), < 2*major (300_000) → Major
    assert_eq!(evidence.severity, RegressionSeverity::Major);
}

// =========================================================================
// I. evaluate_cell — insufficient evidence for no samples
// =========================================================================

#[test]
fn enrichment_evaluate_cell_no_matching_samples() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::Hydration,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000,
        30,
    )];
    // Evaluate for SSR/Latency which has no samples.
    let cell = evaluate_cell(
        SpecializationDomain::SSR,
        BenchmarkClass::Latency,
        &samples,
        &cfg,
    );
    assert_eq!(cell.verdict, GateVerdict::InsufficientEvidence);
    assert!(cell.samples.is_empty());
    assert!(cell.regression.is_none());
}

#[test]
fn enrichment_evaluate_cell_pass_no_regression() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000, // improvement
        30,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        &samples,
        &cfg,
    );
    assert_eq!(cell.verdict, GateVerdict::Pass);
    assert!(cell.regression.is_none());
}

// =========================================================================
// J. build_parity_report — edge cases
// =========================================================================

#[test]
fn enrichment_parity_report_empty_findings() {
    let report = build_parity_report(&[]);
    assert!(report.overall_parity_achieved);
    assert_eq!(report.coverage_millionths, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn enrichment_parity_report_all_achieved() {
    let findings = vec![
        parity_finding(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        ),
        parity_finding(
            ParityDimension::SemanticParity,
            SpecializationDomain::Hydration,
            true,
            0,
            50,
        ),
    ];
    let report = build_parity_report(&findings);
    assert!(report.overall_parity_achieved);
    assert_eq!(report.coverage_millionths, 1_000_000); // 100%
}

#[test]
fn enrichment_parity_report_partial_failure() {
    let findings = vec![
        parity_finding(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        ),
        parity_finding(
            ParityDimension::DiagnosticParity,
            SpecializationDomain::SSR,
            false,
            5,
            100,
        ),
    ];
    let report = build_parity_report(&findings);
    assert!(!report.overall_parity_achieved);
    // coverage = 100 / 200 * 1_000_000 = 500_000
    assert_eq!(report.coverage_millionths, 500_000);
}

// =========================================================================
// K. derive_governance_action — all branches
// =========================================================================

#[test]
fn enrichment_derive_governance_action_critical_overrides() {
    // Critical always → DowngradeSpecialization regardless of verdict.
    let action = derive_governance_action(&GateVerdict::Pass, 1, 0);
    assert_eq!(action, GovernanceAction::DowngradeSpecialization);
}

#[test]
fn enrichment_derive_governance_action_pass() {
    let action = derive_governance_action(&GateVerdict::Pass, 0, 0);
    assert_eq!(action, GovernanceAction::AllowRollout);
}

#[test]
fn enrichment_derive_governance_action_conditional_pass() {
    let action = derive_governance_action(&GateVerdict::ConditionalPass, 0, 0);
    assert_eq!(action, GovernanceAction::ConditionalRollout);
}

#[test]
fn enrichment_derive_governance_action_minor_regression_no_major() {
    let action = derive_governance_action(&GateVerdict::MinorRegression, 0, 0);
    assert_eq!(action, GovernanceAction::ConditionalRollout);
}

#[test]
fn enrichment_derive_governance_action_minor_regression_with_major() {
    let action = derive_governance_action(&GateVerdict::MinorRegression, 0, 1);
    assert_eq!(action, GovernanceAction::RequireManualReview);
}

#[test]
fn enrichment_derive_governance_action_major_regression() {
    let action = derive_governance_action(&GateVerdict::MajorRegression, 0, 2);
    assert_eq!(action, GovernanceAction::BlockRollout);
}

#[test]
fn enrichment_derive_governance_action_fail() {
    let action = derive_governance_action(&GateVerdict::Fail, 0, 0);
    assert_eq!(action, GovernanceAction::DowngradeSpecialization);
}

#[test]
fn enrichment_derive_governance_action_insufficient_evidence() {
    let action = derive_governance_action(&GateVerdict::InsufficientEvidence, 0, 0);
    assert_eq!(action, GovernanceAction::RequireFreshBenchmark);
}

// =========================================================================
// L. compute_receipt — determinism
// =========================================================================

#[test]
fn enrichment_compute_receipt_deterministic() {
    let hash = ContentHash::compute(b"input-data");
    let r1 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
    let r2 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
    assert_eq!(r1.timestamp_micros, r2.timestamp_micros);
}

#[test]
fn enrichment_compute_receipt_different_verdicts_differ() {
    let hash = ContentHash::compute(b"input-data");
    let r1 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
    let r2 = compute_receipt(hash, &GateVerdict::Fail, epoch(1));
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn enrichment_compute_receipt_fields() {
    let hash = ContentHash::compute(b"input-data");
    let receipt = compute_receipt(hash, &GateVerdict::Pass, epoch(5));
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.epoch, epoch(5));
    assert_eq!(receipt.timestamp_micros, 5_000_000);
}

// =========================================================================
// M. evaluate_benchmark_matrix — overall logic
// =========================================================================

#[test]
fn enrichment_evaluate_matrix_pass_no_regressions() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000, // improvement
        30,
    )];
    let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
    assert_eq!(result.overall_verdict, GateVerdict::Pass);
    assert_eq!(result.governance_action, GovernanceAction::AllowRollout);
    assert_eq!(result.critical_regressions, 0);
    assert_eq!(result.major_regressions, 0);
    assert_eq!(result.minor_regressions, 0);
}

#[test]
fn enrichment_evaluate_matrix_parity_failure_downgrades() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000,
        30,
    )];
    let findings = vec![parity_finding(
        ParityDimension::OutputEquivalence,
        SpecializationDomain::SSR,
        false,
        10,
        100,
    )];
    let result = evaluate_benchmark_matrix(&cfg, &samples, &findings, epoch(1));
    // Parity failure → MinorRegression.
    assert_eq!(result.overall_verdict, GateVerdict::MinorRegression);
}

#[test]
fn enrichment_evaluate_matrix_empty_samples_insufficient_evidence() {
    let cfg = BenchmarkConfig::default();
    let result = evaluate_benchmark_matrix(&cfg, &[], &[], epoch(1));
    assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(
        result.governance_action,
        GovernanceAction::RequireFreshBenchmark
    );
}

// =========================================================================
// N. Serde roundtrips for compound types
// =========================================================================

#[test]
fn enrichment_benchmark_sample_serde() {
    let s = sample(
        SpecializationDomain::Hydration,
        BenchmarkClass::MemoryOverhead,
        500_000,
        600_000,
        50,
    );
    let json = serde_json::to_string(&s).unwrap();
    let restored: BenchmarkSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn enrichment_parity_finding_serde() {
    let f = parity_finding(
        ParityDimension::SemanticParity,
        SpecializationDomain::StreamingSSR,
        false,
        3,
        100,
    );
    let json = serde_json::to_string(&f).unwrap();
    let restored: ParityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

#[test]
fn enrichment_benchmark_config_serde() {
    let mut cfg = BenchmarkConfig::default();
    cfg.required_domains.insert(SpecializationDomain::SSR);
    cfg.required_classes.insert(BenchmarkClass::Latency);
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: BenchmarkConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn enrichment_decision_receipt_serde() {
    let hash = ContentHash::compute(b"input-data");
    let receipt = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

#[test]
fn enrichment_gate_result_serde() {
    let cfg = BenchmarkConfig::default();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000,
        30,
    )];
    let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
    let json = serde_json::to_string(&result).unwrap();
    let restored: frankenengine_engine::react_specialization_benchmark_gate::GateResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// O. Debug formatting non-empty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", SpecializationDomain::SSR).is_empty());
    assert!(!format!("{:?}", BenchmarkClass::Throughput).is_empty());
    assert!(!format!("{:?}", ParityDimension::OutputEquivalence).is_empty());
    assert!(!format!("{:?}", RegressionSeverity::None).is_empty());
    assert!(!format!("{:?}", GateVerdict::Pass).is_empty());
    assert!(!format!("{:?}", GovernanceAction::AllowRollout).is_empty());
    assert!(!format!("{:?}", BenchmarkConfig::default()).is_empty());
}

// =========================================================================
// P. BenchmarkConfig default values
// =========================================================================

#[test]
fn enrichment_benchmark_config_default_values() {
    let cfg = BenchmarkConfig::default();
    assert_eq!(cfg.minor_regression_threshold_millionths, 50_000);
    assert_eq!(cfg.major_regression_threshold_millionths, 150_000);
    assert_eq!(cfg.min_sample_count, 30);
    assert_eq!(cfg.min_confidence_millionths, 950_000);
    assert!(cfg.required_domains.is_empty());
    assert!(cfg.required_classes.is_empty());
}
