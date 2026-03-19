//! Enrichment integration tests for `test_depth_gate`.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::test_depth_gate::*;
use frankenengine_engine::test_taxonomy::{TestClass, TestSurface};

const MILLION: i64 = 1_000_000;

fn make_passing_metrics(surface: TestSurface) -> ObservedMetrics {
    let mut coverage = BTreeMap::new();
    coverage.insert(CoverageKind::Statement, 950_000);
    coverage.insert(CoverageKind::Branch, 900_000);
    coverage.insert(CoverageKind::Path, 600_000);

    let obligation = FailureModeObligation::for_surface(surface);
    let mut failure_mode_counts = BTreeMap::new();
    for mode in &obligation.required_modes {
        failure_mode_counts.insert(*mode, 5);
    }

    ObservedMetrics {
        surface,
        coverage,
        mutation_score_millionths: MILLION,
        failure_mode_counts,
        total_tests: 100,
        tests_by_class: BTreeMap::from([
            (TestClass::Core, 50),
            (TestClass::Edge, 20),
            (TestClass::Adversarial, 15),
            (TestClass::Regression, 10),
            (TestClass::FaultInjection, 5),
        ]),
    }
}

// ---------------------------------------------------------------------------
// CoverageKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_kind_statement_as_str() {
    assert_eq!(CoverageKind::Statement.as_str(), "statement");
}

#[test]
fn enrichment_coverage_kind_branch_as_str() {
    assert_eq!(CoverageKind::Branch.as_str(), "branch");
}

#[test]
fn enrichment_coverage_kind_path_as_str() {
    assert_eq!(CoverageKind::Path.as_str(), "path");
}

#[test]
fn enrichment_coverage_kind_all_three() {
    assert_eq!(CoverageKind::ALL.len(), 3);
}

// ---------------------------------------------------------------------------
// CoverageTarget
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_target_is_met_at_boundary() {
    let t = CoverageTarget {
        surface: TestSurface::Runtime,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 850_000,
        hard_gate: true,
    };
    assert!(t.is_met(850_000));
    assert!(!t.is_met(849_999));
}

#[test]
fn enrichment_coverage_target_validate_exactly_100pct() {
    let t = CoverageTarget {
        surface: TestSurface::Security,
        kind: CoverageKind::Statement,
        min_coverage_millionths: MILLION,
        hard_gate: true,
    };
    assert!(t.validate().is_empty());
}

#[test]
fn enrichment_coverage_target_validate_zero() {
    let t = CoverageTarget {
        surface: TestSurface::Parser,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 0,
        hard_gate: false,
    };
    assert!(t.validate().is_empty());
}

// ---------------------------------------------------------------------------
// MutationTier
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_tier_high_threshold() {
    assert_eq!(MutationTier::High.default_threshold_millionths(), 900_000);
}

#[test]
fn enrichment_mutation_tier_standard_threshold() {
    assert_eq!(
        MutationTier::Standard.default_threshold_millionths(),
        750_000
    );
}

#[test]
fn enrichment_mutation_tier_display() {
    assert_eq!(MutationTier::Critical.to_string(), "critical");
    assert_eq!(MutationTier::High.to_string(), "high");
    assert_eq!(MutationTier::Standard.to_string(), "standard");
}

// ---------------------------------------------------------------------------
// MutationPolicy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_policy_is_met_at_boundary() {
    let p = MutationPolicy {
        surface: TestSurface::Compiler,
        tier: MutationTier::High,
        min_score_millionths: 900_000,
        hard_gate: true,
        critical_modules: BTreeSet::new(),
    };
    assert!(p.is_met(900_000));
    assert!(!p.is_met(899_999));
}

#[test]
fn enrichment_mutation_policy_validate_over_100() {
    let p = MutationPolicy {
        surface: TestSurface::Parser,
        tier: MutationTier::Standard,
        min_score_millionths: MILLION + 1,
        hard_gate: false,
        critical_modules: BTreeSet::new(),
    };
    assert!(!p.validate().is_empty());
}

// ---------------------------------------------------------------------------
// FailureMode
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_mode_all_has_8_entries() {
    assert_eq!(FailureMode::ALL.len(), 8);
}

#[test]
fn enrichment_failure_mode_resource_exhaustion_mandatory_for_runtime() {
    assert!(FailureMode::ResourceExhaustion.is_mandatory_for(TestSurface::Runtime));
}

#[test]
fn enrichment_failure_mode_resource_exhaustion_not_mandatory_for_governance() {
    assert!(!FailureMode::ResourceExhaustion.is_mandatory_for(TestSurface::Governance));
}

#[test]
fn enrichment_failure_mode_interference_mandatory_for_parser() {
    assert!(FailureMode::Interference.is_mandatory_for(TestSurface::Parser));
}

#[test]
fn enrichment_failure_mode_fallback_mandatory_for_security() {
    assert!(FailureMode::FallbackTrigger.is_mandatory_for(TestSurface::Security));
}

#[test]
fn enrichment_failure_mode_display() {
    assert_eq!(FailureMode::Timeout.to_string(), "timeout");
    assert_eq!(FailureMode::Rollback.to_string(), "rollback");
}

// ---------------------------------------------------------------------------
// FailureModeObligation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obligation_security_has_rollback() {
    let o = FailureModeObligation::for_surface(TestSurface::Security);
    assert!(o.required_modes.contains(&FailureMode::Rollback));
}

#[test]
fn enrichment_obligation_missing_partial_count() {
    let o = FailureModeObligation::for_surface(TestSurface::Parser);
    let mut observed = BTreeMap::new();
    observed.insert(FailureMode::Timeout, 1);
    let missing = o.missing_modes(&observed);
    assert!(missing.iter().any(|m| m.mode == FailureMode::Timeout && m.observed == 1));
}

// ---------------------------------------------------------------------------
// RegressionPolicy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_strict_check_zero_delta() {
    let p = RegressionPolicy::strict();
    assert!(p.check_coverage_delta(0).is_none());
}

#[test]
fn enrichment_regression_permissive_at_tolerance_boundary() {
    let p = RegressionPolicy::permissive(10_000, 10_000);
    assert!(p.check_coverage_delta(-10_000).is_none());
    assert!(p.check_coverage_delta(-10_001).is_some());
}

#[test]
fn enrichment_regression_classify_delta_positive() {
    assert_eq!(
        RegressionPolicy::classify_delta(100),
        RegressionDirection::Increase
    );
}

// ---------------------------------------------------------------------------
// GateOutcome
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_outcome_pass_not_blocking() {
    assert!(!GateOutcome::Pass.is_blocking());
}

#[test]
fn enrichment_gate_outcome_warn_not_blocking() {
    assert!(!GateOutcome::Warn.is_blocking());
}

#[test]
fn enrichment_gate_outcome_block_is_blocking() {
    assert!(GateOutcome::Block.is_blocking());
}

// ---------------------------------------------------------------------------
// DepthGateConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_depth_gate_config_default_has_regression_policy() {
    let cfg = DepthGateConfig::default_config();
    assert!(cfg.regression_policy.zero_regression);
}

#[test]
fn enrichment_depth_gate_config_default_failure_mode_count() {
    let cfg = DepthGateConfig::default_config();
    assert_eq!(cfg.failure_mode_obligations.len(), 8);
}

#[test]
fn enrichment_evaluate_surface_all_pass_no_regression() {
    let cfg = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Compiler);
    let result = cfg.evaluate_surface(&metrics, None, None);
    assert_eq!(result.outcome, GateOutcome::Pass);
}

#[test]
fn enrichment_evaluate_all_empty_passes() {
    let cfg = DepthGateConfig::default_config();
    let summary = cfg.evaluate_all(&[], &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(summary.overall_outcome, GateOutcome::Pass);
    assert!(summary.promotion_allowed());
}

#[test]
fn enrichment_evaluate_all_single_pass() {
    let cfg = DepthGateConfig::default_config();
    let metrics = vec![make_passing_metrics(TestSurface::Security)];
    let summary = cfg.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(summary.overall_outcome, GateOutcome::Pass);
    assert_eq!(summary.results.len(), 1);
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_result_derive_id_works() {
    let cfg = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Router);
    let result = cfg.evaluate_surface(&metrics, None, None);
    let id = result.derive_id().unwrap();
    let id2 = result.derive_id().unwrap();
    assert_eq!(id, id2);
}

// ---------------------------------------------------------------------------
// DepthGateSummary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_promotion_blocked_when_block() {
    let cfg = DepthGateConfig::default_config();
    let bad = ObservedMetrics {
        surface: TestSurface::Security,
        coverage: BTreeMap::from([
            (CoverageKind::Statement, 100_000),
            (CoverageKind::Branch, 100_000),
            (CoverageKind::Path, 100_000),
        ]),
        mutation_score_millionths: 100_000,
        failure_mode_counts: BTreeMap::new(),
        total_tests: 1,
        tests_by_class: BTreeMap::new(),
    };
    let summary = cfg.evaluate_all(&[bad], &BTreeMap::new(), &BTreeMap::new());
    assert!(!summary.promotion_allowed());
}

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!DEPTH_GATE_SCHEMA_VERSION.is_empty());
}
