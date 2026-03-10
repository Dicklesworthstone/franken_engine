#![forbid(unsafe_code)]
//! Integration tests for the `test_depth_gate` module.
//!
//! Exercises coverage targets, mutation policies, failure mode obligations,
//! regression policies, gate evaluation, and serde round-trips from outside
//! the crate boundary.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::test_depth_gate::{
    CoverageKind, CoverageTarget, DEPTH_GATE_SCHEMA_VERSION, DepthGateConfig, DepthGateSummary,
    FailureMode, FailureModeObligation, GateOutcome, GateResult, MutationPolicy, MutationTier,
    ObservedMetrics, RegressionDirection, RegressionPolicy, default_coverage_targets,
    default_mutation_policies,
};
use frankenengine_engine::test_taxonomy::{TestClass, TestSurface};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_passing_metrics(surface: TestSurface) -> ObservedMetrics {
    let mut coverage = BTreeMap::new();
    // Set coverage high enough to pass all surfaces including Security (900k statement)
    coverage.insert(CoverageKind::Statement, 960_000);
    coverage.insert(CoverageKind::Branch, 920_000);
    coverage.insert(CoverageKind::Path, 600_000);

    let mut failure_mode_counts = BTreeMap::new();
    for mode in FailureMode::ALL {
        failure_mode_counts.insert(*mode, 5);
    }

    let mut tests_by_class = BTreeMap::new();
    for class in TestClass::ALL {
        tests_by_class.insert(*class, 20);
    }

    ObservedMetrics {
        surface,
        coverage,
        // Critical tier requires 1_000_000 — set to pass all tiers
        mutation_score_millionths: 1_000_000,
        failure_mode_counts,
        total_tests: 100,
        tests_by_class,
    }
}

fn make_failing_metrics(surface: TestSurface) -> ObservedMetrics {
    ObservedMetrics {
        surface,
        coverage: BTreeMap::new(), // empty → misses all targets
        mutation_score_millionths: 0,
        failure_mode_counts: BTreeMap::new(),
        total_tests: 0,
        tests_by_class: BTreeMap::new(),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!DEPTH_GATE_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. CoverageKind — as_str, serde
// ===========================================================================

#[test]
fn coverage_kind_all_variants() {
    assert_eq!(CoverageKind::ALL.len(), 3);
    for k in CoverageKind::ALL {
        assert!(!k.as_str().is_empty());
    }
}

#[test]
fn coverage_kind_serde_round_trip() {
    for k in CoverageKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: CoverageKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

// ===========================================================================
// 3. MutationTier — defaults, serde
// ===========================================================================

#[test]
fn mutation_tier_all_variants() {
    assert_eq!(MutationTier::ALL.len(), 3);
    for t in MutationTier::ALL {
        assert!(!t.as_str().is_empty());
        assert!(t.default_threshold_millionths() > 0);
    }
}

#[test]
fn mutation_tier_critical_is_one_million() {
    assert_eq!(
        MutationTier::Critical.default_threshold_millionths(),
        1_000_000
    );
}

#[test]
fn mutation_tier_serde_round_trip() {
    for t in MutationTier::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: MutationTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *t);
    }
}

// ===========================================================================
// 4. FailureMode — mandatory modes, serde
// ===========================================================================

#[test]
fn failure_mode_all_variants() {
    assert_eq!(FailureMode::ALL.len(), 8);
    for m in FailureMode::ALL {
        assert!(!m.as_str().is_empty());
    }
}

#[test]
fn failure_mode_mandatory_varies_by_surface() {
    // Different surfaces have different mandatory failure modes
    let runtime_mandatory: Vec<_> = FailureMode::ALL
        .iter()
        .filter(|m| m.is_mandatory_for(TestSurface::Runtime))
        .collect();
    let parser_mandatory: Vec<_> = FailureMode::ALL
        .iter()
        .filter(|m| m.is_mandatory_for(TestSurface::Parser))
        .collect();
    assert!(!runtime_mandatory.is_empty());
    assert!(!parser_mandatory.is_empty());
}

#[test]
fn failure_mode_serde_round_trip() {
    for m in FailureMode::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: FailureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *m);
    }
}

// ===========================================================================
// 5. CoverageTarget — validation, is_met
// ===========================================================================

#[test]
fn coverage_target_valid() {
    let ct = CoverageTarget {
        surface: TestSurface::Compiler,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 800_000,
        hard_gate: true,
    };
    assert!(ct.validate().is_empty());
}

#[test]
fn coverage_target_negative_coverage_invalid() {
    let ct = CoverageTarget {
        surface: TestSurface::Compiler,
        kind: CoverageKind::Statement,
        min_coverage_millionths: -1,
        hard_gate: true,
    };
    assert!(!ct.validate().is_empty());
}

#[test]
fn coverage_target_is_met() {
    let ct = CoverageTarget {
        surface: TestSurface::Compiler,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 800_000,
        hard_gate: true,
    };
    assert!(ct.is_met(900_000));
    assert!(ct.is_met(800_000));
    assert!(!ct.is_met(799_999));
}

#[test]
fn coverage_target_serde_round_trip() {
    let ct = CoverageTarget {
        surface: TestSurface::Security,
        kind: CoverageKind::Branch,
        min_coverage_millionths: 850_000,
        hard_gate: true,
    };
    let json = serde_json::to_string(&ct).unwrap();
    let back: CoverageTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ct);
}

// ===========================================================================
// 6. MutationPolicy — validation, is_met
// ===========================================================================

#[test]
fn mutation_policy_valid() {
    let mp = MutationPolicy {
        surface: TestSurface::Security,
        tier: MutationTier::Critical,
        min_score_millionths: 1_000_000,
        hard_gate: true,
        critical_modules: BTreeSet::new(),
    };
    assert!(mp.validate().is_empty());
}

#[test]
fn mutation_policy_is_met() {
    let mp = MutationPolicy {
        surface: TestSurface::Runtime,
        tier: MutationTier::High,
        min_score_millionths: 900_000,
        hard_gate: true,
        critical_modules: BTreeSet::new(),
    };
    assert!(mp.is_met(900_000));
    assert!(!mp.is_met(899_999));
}

// ===========================================================================
// 7. FailureModeObligation — for_surface, missing_modes
// ===========================================================================

#[test]
fn failure_mode_obligation_for_surface() {
    let obl = FailureModeObligation::for_surface(TestSurface::Runtime);
    assert!(!obl.required_modes.is_empty());
    assert!(obl.min_tests_per_mode >= 1);
}

#[test]
fn failure_mode_obligation_missing_modes() {
    let obl = FailureModeObligation::for_surface(TestSurface::Runtime);
    // No observed modes → all required modes are missing
    let missing = obl.missing_modes(&BTreeMap::new());
    assert!(!missing.is_empty());
    for m in &missing {
        assert!(obl.required_modes.contains(&m.mode));
    }
}

#[test]
fn failure_mode_obligation_all_met() {
    let obl = FailureModeObligation::for_surface(TestSurface::Runtime);
    let mut observed = BTreeMap::new();
    for mode in &obl.required_modes {
        observed.insert(*mode, obl.min_tests_per_mode + 1);
    }
    let missing = obl.missing_modes(&observed);
    assert!(missing.is_empty());
}

// ===========================================================================
// 8. RegressionPolicy — strict, permissive
// ===========================================================================

#[test]
fn regression_policy_strict_blocks_any_decrease() {
    let policy = RegressionPolicy::strict();
    assert!(policy.zero_regression);
    // Any negative delta should trigger violation
    let viol = policy.check_coverage_delta(-1);
    assert!(viol.is_some());
}

#[test]
fn regression_policy_permissive_allows_tolerance() {
    let policy = RegressionPolicy::permissive(50_000, 50_000);
    assert!(!policy.zero_regression);
    // Small decrease within tolerance → no violation
    let viol = policy.check_coverage_delta(-30_000);
    assert!(viol.is_none());
    // Large decrease beyond tolerance → violation
    let viol = policy.check_coverage_delta(-60_000);
    assert!(viol.is_some());
}

#[test]
fn regression_direction_classify() {
    assert_eq!(
        RegressionPolicy::classify_delta(-1),
        RegressionDirection::Decrease
    );
    assert_eq!(
        RegressionPolicy::classify_delta(0),
        RegressionDirection::Stable
    );
    assert_eq!(
        RegressionPolicy::classify_delta(1),
        RegressionDirection::Increase
    );
}

#[test]
fn regression_direction_serde_round_trip() {
    for d in [
        RegressionDirection::Decrease,
        RegressionDirection::Stable,
        RegressionDirection::Increase,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: RegressionDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

// ===========================================================================
// 9. GateOutcome — as_str, is_blocking
// ===========================================================================

#[test]
fn gate_outcome_properties() {
    assert!(!GateOutcome::Pass.is_blocking());
    assert!(!GateOutcome::Warn.is_blocking());
    assert!(GateOutcome::Block.is_blocking());
    for o in [GateOutcome::Pass, GateOutcome::Warn, GateOutcome::Block] {
        assert!(!o.as_str().is_empty());
    }
}

#[test]
fn gate_outcome_serde_round_trip() {
    for o in [GateOutcome::Pass, GateOutcome::Warn, GateOutcome::Block] {
        let json = serde_json::to_string(&o).unwrap();
        let back: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }
}

// ===========================================================================
// 10. Default configs
// ===========================================================================

#[test]
fn default_coverage_targets_nonempty() {
    let targets = default_coverage_targets();
    assert!(!targets.is_empty());
    for t in &targets {
        assert!(t.validate().is_empty());
    }
}

#[test]
fn default_mutation_policies_nonempty() {
    let policies = default_mutation_policies();
    assert!(!policies.is_empty());
    for p in &policies {
        assert!(p.validate().is_empty());
    }
}

#[test]
fn default_config_valid() {
    let config = DepthGateConfig::default_config();
    assert!(config.validate().is_empty());
    assert!(!config.coverage_targets.is_empty());
    assert!(!config.mutation_policies.is_empty());
    assert!(!config.failure_mode_obligations.is_empty());
}

// ===========================================================================
// 11. DepthGateConfig — evaluate_surface
// ===========================================================================

#[test]
fn evaluate_surface_passing() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Compiler);
    let result = config.evaluate_surface(&metrics, None, None);
    assert_eq!(
        result.outcome,
        GateOutcome::Pass,
        "violations: {:?}, failure_mode_missing: {:?}",
        result.coverage_violations,
        result.failure_mode_missing,
    );
}

#[test]
fn evaluate_surface_failing() {
    let config = DepthGateConfig::default_config();
    let metrics = make_failing_metrics(TestSurface::Security);
    let result = config.evaluate_surface(&metrics, None, None);
    // Security surface with zero coverage → should block
    assert!(result.outcome.is_blocking());
    assert!(!result.coverage_violations.is_empty() || !result.mutation_violations.is_empty());
}

#[test]
fn evaluate_surface_with_regression() {
    let config = DepthGateConfig {
        regression_policy: RegressionPolicy::strict(),
        ..DepthGateConfig::default_config()
    };
    let metrics = make_passing_metrics(TestSurface::Compiler);
    // Previous coverage was higher
    let mut prev_cov = BTreeMap::new();
    prev_cov.insert(CoverageKind::Statement, 980_000);
    prev_cov.insert(CoverageKind::Branch, 960_000);
    prev_cov.insert(CoverageKind::Path, 700_000);
    let prev_mutation = Some(980_000_i64);
    let result =
        config.evaluate_surface(&metrics, Some(&prev_cov), prev_mutation.as_ref().copied());
    // Regression should be detected
    assert!(!result.regression_violations.is_empty());
}

// ===========================================================================
// 12. DepthGateConfig — evaluate_all
// ===========================================================================

#[test]
fn evaluate_all_passing() {
    let config = DepthGateConfig::default_config();
    let all_metrics: Vec<ObservedMetrics> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();
    let summary = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
    assert!(
        summary.promotion_allowed(),
        "overall_outcome: {}, blocking_violations: {}",
        summary.overall_outcome.as_str(),
        summary.blocking_violations,
    );
}

#[test]
fn evaluate_all_one_surface_failing() {
    let config = DepthGateConfig::default_config();
    let mut all_metrics: Vec<ObservedMetrics> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();
    // Replace one with failing metrics for a hard-gated surface
    if let Some(m) = all_metrics
        .iter_mut()
        .find(|m| m.surface == TestSurface::Security)
    {
        *m = make_failing_metrics(TestSurface::Security);
    }
    let summary = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
    assert!(!summary.promotion_allowed());
    assert!(summary.blocking_violations > 0);
}

// ===========================================================================
// 13. GateResult — derive_id, serde
// ===========================================================================

#[test]
fn gate_result_derive_id_deterministic() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Compiler);
    let r1 = config.evaluate_surface(&metrics, None, None);
    let r2 = config.evaluate_surface(&metrics, None, None);
    assert_eq!(r1.derive_id().unwrap(), r2.derive_id().unwrap());
}

#[test]
fn gate_result_serde_round_trip() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Compiler);
    let result = config.evaluate_surface(&metrics, None, None);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 14. DepthGateSummary — serde
// ===========================================================================

#[test]
fn depth_gate_summary_serde_round_trip() {
    let config = DepthGateConfig::default_config();
    let metrics = vec![make_passing_metrics(TestSurface::Compiler)];
    let summary = config.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
    let json = serde_json::to_string(&summary).unwrap();
    let back: DepthGateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ===========================================================================
// 15. DepthGateConfig — serde
// ===========================================================================

#[test]
fn depth_gate_config_serde_round_trip() {
    let config = DepthGateConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: DepthGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 16. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_depth_gate() {
    // 1. Build config
    let config = DepthGateConfig::default_config();
    assert!(config.validate().is_empty());

    // 2. Collect metrics for all surfaces
    let all_metrics: Vec<ObservedMetrics> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();

    // 3. Evaluate
    let summary = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());

    // 4. Check promotion
    assert!(summary.promotion_allowed());
    assert_eq!(summary.schema, DEPTH_GATE_SCHEMA_VERSION);

    // 5. Results per surface
    assert_eq!(summary.results.len(), all_metrics.len());
    for result in &summary.results {
        assert_eq!(result.outcome, GateOutcome::Pass);
    }

    // 6. Serde round-trip
    let json = serde_json::to_string(&summary).unwrap();
    let back: DepthGateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.overall_outcome, summary.overall_outcome);
    assert_eq!(back.results.len(), summary.results.len());
}
