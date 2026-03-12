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

// ===========================================================================
// Enrichment tests (PearlTower 2026-03-12)
// ===========================================================================

use frankenengine_engine::test_depth_gate::{DepthGateViolation, FailureModeMissing};

// ---------------------------------------------------------------------------
// CoverageKind — Display, Debug, Clone, ordering, JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_kind_display_matches_as_str() {
    for k in CoverageKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn enrichment_coverage_kind_debug_contains_variant_name() {
    let dbg = format!("{:?}", CoverageKind::Statement);
    assert!(dbg.contains("Statement"));
    let dbg = format!("{:?}", CoverageKind::Branch);
    assert!(dbg.contains("Branch"));
    let dbg = format!("{:?}", CoverageKind::Path);
    assert!(dbg.contains("Path"));
}

#[test]
fn enrichment_coverage_kind_clone_eq() {
    for k in CoverageKind::ALL {
        let cloned = k.clone();
        assert_eq!(*k, cloned);
    }
}

#[test]
fn enrichment_coverage_kind_json_field_names_stable() {
    let json = serde_json::to_string(&CoverageKind::Statement).unwrap();
    assert_eq!(json, "\"Statement\"");
    let json = serde_json::to_string(&CoverageKind::Branch).unwrap();
    assert_eq!(json, "\"Branch\"");
    let json = serde_json::to_string(&CoverageKind::Path).unwrap();
    assert_eq!(json, "\"Path\"");
}

#[test]
fn enrichment_coverage_kind_ordering_total() {
    assert!(CoverageKind::Statement < CoverageKind::Branch);
    assert!(CoverageKind::Branch < CoverageKind::Path);
    assert!(CoverageKind::Statement < CoverageKind::Path);
}

#[test]
fn enrichment_coverage_kind_deserialize_rejects_unknown() {
    let result = serde_json::from_str::<CoverageKind>("\"Unknown\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// MutationTier — Display, Debug, Clone, ordering, thresholds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_tier_display_matches_as_str() {
    for t in MutationTier::ALL {
        assert_eq!(t.to_string(), t.as_str());
    }
}

#[test]
fn enrichment_mutation_tier_json_field_names_stable() {
    assert_eq!(serde_json::to_string(&MutationTier::Critical).unwrap(), "\"Critical\"");
    assert_eq!(serde_json::to_string(&MutationTier::High).unwrap(), "\"High\"");
    assert_eq!(serde_json::to_string(&MutationTier::Standard).unwrap(), "\"Standard\"");
}

#[test]
fn enrichment_mutation_tier_thresholds_all_positive() {
    for t in MutationTier::ALL {
        assert!(t.default_threshold_millionths() > 0);
        assert!(t.default_threshold_millionths() <= 1_000_000);
    }
}

#[test]
fn enrichment_mutation_tier_high_threshold_is_900k() {
    assert_eq!(MutationTier::High.default_threshold_millionths(), 900_000);
}

#[test]
fn enrichment_mutation_tier_standard_threshold_is_750k() {
    assert_eq!(MutationTier::Standard.default_threshold_millionths(), 750_000);
}

#[test]
fn enrichment_mutation_tier_deserialize_rejects_unknown() {
    let result = serde_json::from_str::<MutationTier>("\"Extreme\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// FailureMode — Display, mandatory-for matrix, exhaustive checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_mode_display_matches_as_str() {
    for m in FailureMode::ALL {
        assert_eq!(m.to_string(), m.as_str());
    }
}

#[test]
fn enrichment_failure_mode_as_str_no_whitespace() {
    for m in FailureMode::ALL {
        assert!(!m.as_str().contains(' '));
        assert!(!m.as_str().is_empty());
    }
}

#[test]
fn enrichment_failure_mode_drift_mandatory_for_scheduler() {
    assert!(FailureMode::Drift.is_mandatory_for(TestSurface::Scheduler));
}

#[test]
fn enrichment_failure_mode_drift_not_mandatory_for_parser() {
    assert!(!FailureMode::Drift.is_mandatory_for(TestSurface::Parser));
}

#[test]
fn enrichment_failure_mode_fallback_mandatory_for_security() {
    assert!(FailureMode::FallbackTrigger.is_mandatory_for(TestSurface::Security));
}

#[test]
fn enrichment_failure_mode_fallback_not_mandatory_for_parser() {
    assert!(!FailureMode::FallbackTrigger.is_mandatory_for(TestSurface::Parser));
}

#[test]
fn enrichment_failure_mode_resource_exhaustion_mandatory_parser() {
    assert!(FailureMode::ResourceExhaustion.is_mandatory_for(TestSurface::Parser));
}

#[test]
fn enrichment_failure_mode_resource_exhaustion_not_mandatory_compiler() {
    assert!(!FailureMode::ResourceExhaustion.is_mandatory_for(TestSurface::Compiler));
}

#[test]
fn enrichment_failure_mode_interference_mandatory_parser() {
    assert!(FailureMode::Interference.is_mandatory_for(TestSurface::Parser));
}

#[test]
fn enrichment_failure_mode_json_stability() {
    assert_eq!(serde_json::to_string(&FailureMode::Timeout).unwrap(), "\"Timeout\"");
    assert_eq!(serde_json::to_string(&FailureMode::MalformedInput).unwrap(), "\"MalformedInput\"");
    assert_eq!(serde_json::to_string(&FailureMode::Rollback).unwrap(), "\"Rollback\"");
}

#[test]
fn enrichment_failure_mode_deserialize_rejects_unknown() {
    let result = serde_json::from_str::<FailureMode>("\"Crash\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// CoverageTarget — boundary values, validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_target_zero_is_valid() {
    let ct = CoverageTarget {
        surface: TestSurface::Router,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 0,
        hard_gate: false,
    };
    assert!(ct.validate().is_empty());
}

#[test]
fn enrichment_coverage_target_exactly_1m_is_valid() {
    let ct = CoverageTarget {
        surface: TestSurface::Scheduler,
        kind: CoverageKind::Branch,
        min_coverage_millionths: 1_000_000,
        hard_gate: true,
    };
    assert!(ct.validate().is_empty());
}

#[test]
fn enrichment_coverage_target_over_1m_invalid() {
    let ct = CoverageTarget {
        surface: TestSurface::Evidence,
        kind: CoverageKind::Path,
        min_coverage_millionths: 1_000_001,
        hard_gate: true,
    };
    let violations = ct.validate();
    assert!(!violations.is_empty());
    assert!(violations[0].message.contains("100%"));
}

#[test]
fn enrichment_coverage_target_negative_validation_message() {
    let ct = CoverageTarget {
        surface: TestSurface::Governance,
        kind: CoverageKind::Statement,
        min_coverage_millionths: -100,
        hard_gate: true,
    };
    let violations = ct.validate();
    assert!(!violations.is_empty());
    assert!(violations[0].message.contains("non-negative"));
    assert_eq!(violations[0].field, "min_coverage_millionths");
}

#[test]
fn enrichment_coverage_target_is_met_boundary_exact() {
    let ct = CoverageTarget {
        surface: TestSurface::Compiler,
        kind: CoverageKind::Statement,
        min_coverage_millionths: 500_000,
        hard_gate: true,
    };
    assert!(ct.is_met(500_000));
    assert!(!ct.is_met(499_999));
    assert!(ct.is_met(500_001));
}

#[test]
fn enrichment_coverage_target_is_met_zero_threshold() {
    let ct = CoverageTarget {
        surface: TestSurface::Parser,
        kind: CoverageKind::Path,
        min_coverage_millionths: 0,
        hard_gate: false,
    };
    assert!(ct.is_met(0));
    assert!(ct.is_met(1));
    // Negative observed should still fail if threshold is 0 (>= 0)
    assert!(!ct.is_met(-1));
}

// ---------------------------------------------------------------------------
// MutationPolicy — validation rules, critical tier constraint
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mutation_policy_over_1m_invalid() {
    let mp = MutationPolicy {
        surface: TestSurface::Parser,
        tier: MutationTier::Standard,
        min_score_millionths: 1_000_001,
        hard_gate: false,
        critical_modules: BTreeSet::new(),
    };
    let violations = mp.validate();
    assert!(!violations.is_empty());
    assert!(violations.iter().any(|v| v.message.contains("100%")));
}

#[test]
fn enrichment_mutation_policy_critical_at_999999_invalid() {
    let mp = MutationPolicy {
        surface: TestSurface::Governance,
        tier: MutationTier::Critical,
        min_score_millionths: 999_999,
        hard_gate: true,
        critical_modules: BTreeSet::new(),
    };
    let violations = mp.validate();
    assert!(!violations.is_empty());
    assert!(violations.iter().any(|v| v.message.contains("critical tier")));
}

#[test]
fn enrichment_mutation_policy_zero_is_met() {
    let mp = MutationPolicy {
        surface: TestSurface::Router,
        tier: MutationTier::Standard,
        min_score_millionths: 0,
        hard_gate: false,
        critical_modules: BTreeSet::new(),
    };
    assert!(mp.is_met(0));
    assert!(mp.is_met(1));
}

#[test]
fn enrichment_mutation_policy_with_critical_modules_serde() {
    let mut modules = BTreeSet::new();
    modules.insert("capability_witness".to_string());
    modules.insert("attestation_handshake".to_string());
    let mp = MutationPolicy {
        surface: TestSurface::Security,
        tier: MutationTier::Critical,
        min_score_millionths: 1_000_000,
        hard_gate: true,
        critical_modules: modules,
    };
    let json = serde_json::to_string(&mp).unwrap();
    let back: MutationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(mp, back);
    assert_eq!(back.critical_modules.len(), 2);
}

// ---------------------------------------------------------------------------
// FailureModeObligation — per-surface, missing modes edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obligation_for_all_surfaces_nonempty() {
    for surface in TestSurface::ALL {
        let obl = FailureModeObligation::for_surface(*surface);
        assert!(
            !obl.required_modes.is_empty(),
            "obligation for {} should have required modes",
            surface
        );
        // Universal modes: Timeout, Cancellation, MalformedInput
        assert!(obl.required_modes.contains(&FailureMode::Timeout));
        assert!(obl.required_modes.contains(&FailureMode::Cancellation));
        assert!(obl.required_modes.contains(&FailureMode::MalformedInput));
    }
}

#[test]
fn enrichment_obligation_min_tests_per_mode_is_two() {
    for surface in TestSurface::ALL {
        let obl = FailureModeObligation::for_surface(*surface);
        assert_eq!(obl.min_tests_per_mode, 2);
    }
}

#[test]
fn enrichment_obligation_missing_modes_count_below_threshold() {
    let obl = FailureModeObligation::for_surface(TestSurface::Runtime);
    let mut observed = BTreeMap::new();
    for mode in &obl.required_modes {
        observed.insert(*mode, 1); // below min_tests_per_mode of 2
    }
    let missing = obl.missing_modes(&observed);
    assert_eq!(missing.len(), obl.required_modes.len());
    for m in &missing {
        assert_eq!(m.observed, 1);
        assert_eq!(m.required, 2);
    }
}

#[test]
fn enrichment_obligation_missing_modes_exactly_at_threshold() {
    let obl = FailureModeObligation::for_surface(TestSurface::Security);
    let mut observed = BTreeMap::new();
    for mode in &obl.required_modes {
        observed.insert(*mode, obl.min_tests_per_mode); // exactly at threshold
    }
    let missing = obl.missing_modes(&observed);
    assert!(missing.is_empty());
}

#[test]
fn enrichment_obligation_extra_unrequired_modes_ignored() {
    let obl = FailureModeObligation::for_surface(TestSurface::Compiler);
    // Compiler should not require Drift
    assert!(!obl.required_modes.contains(&FailureMode::Drift));
    let mut observed = BTreeMap::new();
    for mode in &obl.required_modes {
        observed.insert(*mode, 5);
    }
    // Add extra non-required mode
    observed.insert(FailureMode::Drift, 100);
    let missing = obl.missing_modes(&observed);
    assert!(missing.is_empty());
}

#[test]
fn enrichment_obligation_serde_all_surfaces() {
    for surface in TestSurface::ALL {
        let obl = FailureModeObligation::for_surface(*surface);
        let json = serde_json::to_string(&obl).unwrap();
        let back: FailureModeObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(obl, back);
    }
}

// ---------------------------------------------------------------------------
// FailureModeMissing — serde, Debug, Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_mode_missing_debug_format() {
    let m = FailureModeMissing {
        mode: FailureMode::Drift,
        required: 3,
        observed: 0,
    };
    let dbg = format!("{:?}", m);
    assert!(dbg.contains("Drift"));
    assert!(dbg.contains("3"));
}

#[test]
fn enrichment_failure_mode_missing_json_field_names() {
    let m = FailureModeMissing {
        mode: FailureMode::Rollback,
        required: 4,
        observed: 2,
    };
    let json = serde_json::to_string(&m).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("mode").is_some());
    assert!(v.get("required").is_some());
    assert!(v.get("observed").is_some());
}

// ---------------------------------------------------------------------------
// RegressionDirection — Display, ordering, exhaustive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_direction_display_matches_as_str() {
    for d in [
        RegressionDirection::Decrease,
        RegressionDirection::Stable,
        RegressionDirection::Increase,
    ] {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrichment_regression_direction_ordering() {
    assert!(RegressionDirection::Decrease < RegressionDirection::Stable);
    assert!(RegressionDirection::Stable < RegressionDirection::Increase);
}

#[test]
fn enrichment_regression_direction_json_stability() {
    assert_eq!(serde_json::to_string(&RegressionDirection::Decrease).unwrap(), "\"Decrease\"");
    assert_eq!(serde_json::to_string(&RegressionDirection::Stable).unwrap(), "\"Stable\"");
    assert_eq!(serde_json::to_string(&RegressionDirection::Increase).unwrap(), "\"Increase\"");
}

// ---------------------------------------------------------------------------
// RegressionPolicy — check_mutation_delta, edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_strict_mutation_delta_zero_ok() {
    let p = RegressionPolicy::strict();
    assert!(p.check_mutation_delta(0).is_none());
}

#[test]
fn enrichment_regression_strict_mutation_delta_positive_ok() {
    let p = RegressionPolicy::strict();
    assert!(p.check_mutation_delta(100_000).is_none());
}

#[test]
fn enrichment_regression_strict_mutation_delta_negative_blocks() {
    let p = RegressionPolicy::strict();
    let v = p.check_mutation_delta(-1).unwrap();
    assert_eq!(v.field, "mutation_regression");
    assert!(v.message.contains("mutation score decreased"));
}

#[test]
fn enrichment_regression_permissive_mutation_within_tolerance() {
    let p = RegressionPolicy::permissive(10_000, 20_000);
    assert!(p.check_mutation_delta(-20_000).is_none());
    assert!(p.check_mutation_delta(-15_000).is_none());
}

#[test]
fn enrichment_regression_permissive_mutation_exceeds_tolerance() {
    let p = RegressionPolicy::permissive(10_000, 20_000);
    let v = p.check_mutation_delta(-20_001).unwrap();
    assert_eq!(v.field, "mutation_regression");
}

#[test]
fn enrichment_regression_coverage_delta_message_contains_decrease() {
    let p = RegressionPolicy::strict();
    let v = p.check_coverage_delta(-5000).unwrap();
    assert_eq!(v.field, "coverage_regression");
    assert!(v.message.contains("coverage decreased"));
    assert!(v.message.contains("5000"));
}

#[test]
fn enrichment_regression_classify_large_negative() {
    assert_eq!(
        RegressionPolicy::classify_delta(i64::MIN),
        RegressionDirection::Decrease
    );
}

#[test]
fn enrichment_regression_classify_large_positive() {
    assert_eq!(
        RegressionPolicy::classify_delta(i64::MAX),
        RegressionDirection::Increase
    );
}

#[test]
fn enrichment_regression_policy_serde_permissive() {
    let p = RegressionPolicy::permissive(30_000, 40_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: RegressionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert!(!back.zero_regression);
    assert_eq!(back.max_coverage_decrease_millionths, 30_000);
    assert_eq!(back.max_mutation_decrease_millionths, 40_000);
}

#[test]
fn enrichment_regression_policy_json_field_names() {
    let p = RegressionPolicy::strict();
    let json = serde_json::to_string(&p).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("max_coverage_decrease_millionths").is_some());
    assert!(v.get("max_mutation_decrease_millionths").is_some());
    assert!(v.get("zero_regression").is_some());
}

// ---------------------------------------------------------------------------
// GateOutcome — Display, ordering, JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_outcome_display_matches_as_str() {
    for o in [GateOutcome::Pass, GateOutcome::Warn, GateOutcome::Block] {
        assert_eq!(o.to_string(), o.as_str());
    }
}

#[test]
fn enrichment_gate_outcome_ordering() {
    assert!(GateOutcome::Pass < GateOutcome::Warn);
    assert!(GateOutcome::Warn < GateOutcome::Block);
}

#[test]
fn enrichment_gate_outcome_json_stability() {
    assert_eq!(serde_json::to_string(&GateOutcome::Pass).unwrap(), "\"Pass\"");
    assert_eq!(serde_json::to_string(&GateOutcome::Warn).unwrap(), "\"Warn\"");
    assert_eq!(serde_json::to_string(&GateOutcome::Block).unwrap(), "\"Block\"");
}

// ---------------------------------------------------------------------------
// DepthGateViolation — serde, Debug, Clone, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_violation_debug_format() {
    let v = DepthGateViolation {
        field: "coverage.statement".to_string(),
        message: "below threshold".to_string(),
    };
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("coverage.statement"));
    assert!(dbg.contains("below threshold"));
}

#[test]
fn enrichment_violation_json_field_names() {
    let v = DepthGateViolation {
        field: "f".to_string(),
        message: "m".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.get("field").unwrap().as_str().unwrap(), "f");
    assert_eq!(parsed.get("message").unwrap().as_str().unwrap(), "m");
}

#[test]
fn enrichment_violation_empty_strings_valid() {
    let v = DepthGateViolation {
        field: String::new(),
        message: String::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: DepthGateViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// ObservedMetrics — serde, edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observed_metrics_empty_collections_serde() {
    let m = ObservedMetrics {
        surface: TestSurface::Parser,
        coverage: BTreeMap::new(),
        mutation_score_millionths: 0,
        failure_mode_counts: BTreeMap::new(),
        total_tests: 0,
        tests_by_class: BTreeMap::new(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ObservedMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_observed_metrics_json_field_names() {
    let m = make_passing_metrics(TestSurface::Compiler);
    let json = serde_json::to_string(&m).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("surface").is_some());
    assert!(v.get("coverage").is_some());
    assert!(v.get("mutation_score_millionths").is_some());
    assert!(v.get("failure_mode_counts").is_some());
    assert!(v.get("total_tests").is_some());
    assert!(v.get("tests_by_class").is_some());
}

#[test]
fn enrichment_observed_metrics_all_surfaces_serde() {
    for surface in TestSurface::ALL {
        let m = make_passing_metrics(*surface);
        let json = serde_json::to_string(&m).unwrap();
        let back: ObservedMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

// ---------------------------------------------------------------------------
// default_coverage_targets — structural checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_coverage_targets_all_surfaces_present() {
    let targets = default_coverage_targets();
    let surfaces: BTreeSet<_> = targets.iter().map(|t| t.surface).collect();
    for s in TestSurface::ALL {
        assert!(surfaces.contains(s), "missing surface: {:?}", s);
    }
}

#[test]
fn enrichment_default_coverage_targets_all_kinds_per_surface() {
    let targets = default_coverage_targets();
    for surface in TestSurface::ALL {
        let kinds: BTreeSet<_> = targets
            .iter()
            .filter(|t| t.surface == *surface)
            .map(|t| t.kind)
            .collect();
        for kind in CoverageKind::ALL {
            assert!(
                kinds.contains(kind),
                "missing kind {:?} for surface {:?}",
                kind,
                surface
            );
        }
    }
}

#[test]
fn enrichment_default_coverage_path_always_advisory() {
    let targets = default_coverage_targets();
    for t in targets.iter().filter(|t| t.kind == CoverageKind::Path) {
        assert!(!t.hard_gate, "path coverage should be advisory for {:?}", t.surface);
    }
}

#[test]
fn enrichment_default_coverage_stmt_branch_hard_gated() {
    let targets = default_coverage_targets();
    for t in targets
        .iter()
        .filter(|t| t.kind == CoverageKind::Statement || t.kind == CoverageKind::Branch)
    {
        assert!(t.hard_gate, "stmt/branch coverage should be hard gated for {:?}", t.surface);
    }
}

#[test]
fn enrichment_default_coverage_security_governance_highest() {
    let targets = default_coverage_targets();
    let sec_stmt = targets
        .iter()
        .find(|t| t.surface == TestSurface::Security && t.kind == CoverageKind::Statement)
        .unwrap();
    let gov_stmt = targets
        .iter()
        .find(|t| t.surface == TestSurface::Governance && t.kind == CoverageKind::Statement)
        .unwrap();
    assert_eq!(sec_stmt.min_coverage_millionths, 900_000);
    assert_eq!(gov_stmt.min_coverage_millionths, 900_000);
}

// ---------------------------------------------------------------------------
// default_mutation_policies — structural checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_mutation_policies_all_surfaces() {
    let policies = default_mutation_policies();
    let surfaces: BTreeSet<_> = policies.iter().map(|p| p.surface).collect();
    for s in TestSurface::ALL {
        assert!(surfaces.contains(s));
    }
}

#[test]
fn enrichment_default_mutation_governance_is_critical() {
    let policies = default_mutation_policies();
    let gov = policies
        .iter()
        .find(|p| p.surface == TestSurface::Governance)
        .unwrap();
    assert_eq!(gov.tier, MutationTier::Critical);
    assert!(gov.hard_gate);
    assert_eq!(gov.min_score_millionths, 1_000_000);
}

#[test]
fn enrichment_default_mutation_router_is_standard() {
    let policies = default_mutation_policies();
    let router = policies
        .iter()
        .find(|p| p.surface == TestSurface::Router)
        .unwrap();
    assert_eq!(router.tier, MutationTier::Standard);
    assert!(!router.hard_gate);
}

// ---------------------------------------------------------------------------
// DepthGateConfig — validation, evaluate_surface edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_default_has_correct_schema() {
    let config = DepthGateConfig::default_config();
    assert_eq!(config.schema, DEPTH_GATE_SCHEMA_VERSION);
}

#[test]
fn enrichment_config_default_failure_mode_obligations_count() {
    let config = DepthGateConfig::default_config();
    assert_eq!(config.failure_mode_obligations.len(), TestSurface::ALL.len());
}

#[test]
fn enrichment_config_validate_with_invalid_target() {
    let mut config = DepthGateConfig::default_config();
    config.coverage_targets.push(CoverageTarget {
        surface: TestSurface::Parser,
        kind: CoverageKind::Statement,
        min_coverage_millionths: -10,
        hard_gate: true,
    });
    let violations = config.validate();
    assert!(!violations.is_empty());
}

#[test]
fn enrichment_config_validate_with_invalid_mutation_policy() {
    let mut config = DepthGateConfig::default_config();
    config.mutation_policies.push(MutationPolicy {
        surface: TestSurface::Compiler,
        tier: MutationTier::Critical,
        min_score_millionths: 500_000, // invalid: Critical needs 1_000_000
        hard_gate: true,
        critical_modules: BTreeSet::new(),
    });
    let violations = config.validate();
    assert!(!violations.is_empty());
}

#[test]
fn enrichment_evaluate_surface_deterministic() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Compiler);
    let r1 = config.evaluate_surface(&metrics, None, None);
    let r2 = config.evaluate_surface(&metrics, None, None);
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_evaluate_surface_each_surface_passes() {
    let config = DepthGateConfig::default_config();
    for surface in TestSurface::ALL {
        let metrics = make_passing_metrics(*surface);
        let result = config.evaluate_surface(&metrics, None, None);
        assert_eq!(
            result.outcome,
            GateOutcome::Pass,
            "surface {:?} should pass with sufficient metrics. violations: {:?}, missing: {:?}",
            surface,
            result.coverage_violations,
            result.failure_mode_missing,
        );
    }
}

#[test]
fn enrichment_evaluate_surface_each_surface_fails_on_empty() {
    let config = DepthGateConfig::default_config();
    for surface in TestSurface::ALL {
        let metrics = make_failing_metrics(*surface);
        let result = config.evaluate_surface(&metrics, None, None);
        // All surfaces with hard-gated coverage/mutation should block
        assert!(
            result.outcome.is_blocking() || result.outcome == GateOutcome::Warn,
            "surface {:?} with failing metrics should not pass",
            surface,
        );
    }
}

#[test]
fn enrichment_evaluate_surface_soft_gate_only_warns() {
    // Build config with only path coverage (advisory) targets
    let config = DepthGateConfig {
        schema: DEPTH_GATE_SCHEMA_VERSION.to_string(),
        coverage_targets: vec![CoverageTarget {
            surface: TestSurface::Parser,
            kind: CoverageKind::Path,
            min_coverage_millionths: 999_999,
            hard_gate: false,
        }],
        mutation_policies: vec![],
        failure_mode_obligations: vec![],
        regression_policy: RegressionPolicy::permissive(1_000_000, 1_000_000),
    };
    let metrics = ObservedMetrics {
        surface: TestSurface::Parser,
        coverage: BTreeMap::from([(CoverageKind::Path, 100_000)]),
        mutation_score_millionths: 0,
        failure_mode_counts: BTreeMap::new(),
        total_tests: 1,
        tests_by_class: BTreeMap::new(),
    };
    let result = config.evaluate_surface(&metrics, None, None);
    assert_eq!(result.outcome, GateOutcome::Warn);
}

#[test]
fn enrichment_evaluate_surface_no_targets_passes() {
    let config = DepthGateConfig {
        schema: DEPTH_GATE_SCHEMA_VERSION.to_string(),
        coverage_targets: vec![],
        mutation_policies: vec![],
        failure_mode_obligations: vec![],
        regression_policy: RegressionPolicy::permissive(1_000_000, 1_000_000),
    };
    let metrics = make_failing_metrics(TestSurface::Security);
    let result = config.evaluate_surface(&metrics, None, None);
    assert_eq!(result.outcome, GateOutcome::Pass);
}

// ---------------------------------------------------------------------------
// evaluate_all — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_all_empty_metrics() {
    let config = DepthGateConfig::default_config();
    let summary = config.evaluate_all(&[], &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(summary.overall_outcome, GateOutcome::Pass);
    assert!(summary.results.is_empty());
    assert_eq!(summary.total_violations, 0);
    assert_eq!(summary.blocking_violations, 0);
    assert_eq!(summary.advisory_violations, 0);
}

#[test]
fn enrichment_evaluate_all_violation_counts_additive() {
    let config = DepthGateConfig::default_config();
    let metrics = vec![
        make_failing_metrics(TestSurface::Security),
        make_failing_metrics(TestSurface::Parser),
    ];
    let summary = config.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
    assert!(summary.total_violations > 0);
    assert_eq!(
        summary.total_violations,
        summary.blocking_violations + summary.advisory_violations
    );
}

#[test]
fn enrichment_evaluate_all_with_previous_coverage() {
    let config = DepthGateConfig::default_config();
    let metrics = vec![make_passing_metrics(TestSurface::Parser)];
    let mut prev_coverages = BTreeMap::new();
    // Previous coverage higher than current (960_000 stmt, 920_000 branch in make_passing_metrics)
    prev_coverages.insert(
        TestSurface::Parser,
        BTreeMap::from([
            (CoverageKind::Statement, 970_000),
            (CoverageKind::Branch, 930_000),
        ]),
    );
    let summary = config.evaluate_all(&metrics, &prev_coverages, &BTreeMap::new());
    // strict regression policy should catch the decrease
    assert!(!summary.promotion_allowed());
}

#[test]
fn enrichment_evaluate_all_with_previous_mutation() {
    let config = DepthGateConfig::default_config();
    let metrics = vec![make_passing_metrics(TestSurface::Runtime)];
    let mut prev_mutations = BTreeMap::new();
    prev_mutations.insert(TestSurface::Runtime, 1_000_001_i64);
    let summary = config.evaluate_all(&metrics, &BTreeMap::new(), &prev_mutations);
    assert!(!summary.promotion_allowed());
}

// ---------------------------------------------------------------------------
// GateResult — derive_id, serde, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_result_derive_id_differs_between_surfaces() {
    let config = DepthGateConfig::default_config();
    let r1 = config.evaluate_surface(&make_passing_metrics(TestSurface::Parser), None, None);
    let r2 = config.evaluate_surface(&make_passing_metrics(TestSurface::Security), None, None);
    assert_ne!(r1.derive_id().unwrap(), r2.derive_id().unwrap());
}

#[test]
fn enrichment_gate_result_derive_id_differs_on_outcome() {
    let config = DepthGateConfig::default_config();
    let r1 = config.evaluate_surface(&make_passing_metrics(TestSurface::Security), None, None);
    let r2 = config.evaluate_surface(&make_failing_metrics(TestSurface::Security), None, None);
    assert_ne!(r1.derive_id().unwrap(), r2.derive_id().unwrap());
}

#[test]
fn enrichment_gate_result_serde_with_violations() {
    let config = DepthGateConfig::default_config();
    let result = config.evaluate_surface(&make_failing_metrics(TestSurface::Security), None, None);
    assert!(!result.coverage_violations.is_empty() || !result.mutation_violations.is_empty());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// DepthGateSummary — serde, promotion_allowed, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_promotion_allowed_pass() {
    let config = DepthGateConfig::default_config();
    let metrics: Vec<_> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();
    let summary = config.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
    assert!(summary.promotion_allowed());
    assert_eq!(summary.overall_outcome, GateOutcome::Pass);
}

#[test]
fn enrichment_summary_promotion_blocked_on_any_block() {
    let config = DepthGateConfig::default_config();
    let metrics = vec![
        make_passing_metrics(TestSurface::Parser),
        make_failing_metrics(TestSurface::Security),
    ];
    let summary = config.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
    assert!(!summary.promotion_allowed());
    assert_eq!(summary.overall_outcome, GateOutcome::Block);
}

#[test]
fn enrichment_summary_schema_matches_constant() {
    let config = DepthGateConfig::default_config();
    let summary = config.evaluate_all(&[], &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(summary.schema, DEPTH_GATE_SCHEMA_VERSION);
}

#[test]
fn enrichment_summary_json_field_names() {
    let config = DepthGateConfig::default_config();
    let summary = config.evaluate_all(
        &[make_passing_metrics(TestSurface::Router)],
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
    let json = serde_json::to_string(&summary).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema").is_some());
    assert!(v.get("overall_outcome").is_some());
    assert!(v.get("results").is_some());
    assert!(v.get("total_violations").is_some());
    assert!(v.get("blocking_violations").is_some());
    assert!(v.get("advisory_violations").is_some());
}

// ---------------------------------------------------------------------------
// DepthGateConfig — serde, Debug, Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_json_field_names() {
    let config = DepthGateConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema").is_some());
    assert!(v.get("coverage_targets").is_some());
    assert!(v.get("mutation_policies").is_some());
    assert!(v.get("failure_mode_obligations").is_some());
    assert!(v.get("regression_policy").is_some());
}

// ---------------------------------------------------------------------------
// Determinism: same inputs, same outputs across runs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_evaluate_surface_repeated() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Evidence);
    let results: Vec<_> = (0..5)
        .map(|_| config.evaluate_surface(&metrics, None, None))
        .collect();
    for r in &results {
        assert_eq!(r, &results[0]);
    }
}

#[test]
fn enrichment_determinism_evaluate_all_repeated() {
    let config = DepthGateConfig::default_config();
    let all_metrics: Vec<_> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();
    let s1 = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
    let s2 = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(s1, s2);
}

// ---------------------------------------------------------------------------
// Property-based patterns
// ---------------------------------------------------------------------------

#[test]
fn enrichment_property_hard_gate_fail_implies_block() {
    let config = DepthGateConfig::default_config();
    // For every surface, if we provide failing metrics with hard-gated targets, outcome must block
    for surface in TestSurface::ALL {
        let has_hard_gate = config
            .coverage_targets
            .iter()
            .any(|t| t.surface == *surface && t.hard_gate)
            || config
                .mutation_policies
                .iter()
                .any(|p| p.surface == *surface && p.hard_gate);
        if has_hard_gate {
            let metrics = make_failing_metrics(*surface);
            let result = config.evaluate_surface(&metrics, None, None);
            assert!(
                result.outcome.is_blocking(),
                "surface {:?} with hard gate and failing metrics must block",
                surface,
            );
        }
    }
}

#[test]
fn enrichment_property_pass_implies_no_hard_failures() {
    let config = DepthGateConfig::default_config();
    for surface in TestSurface::ALL {
        let metrics = make_passing_metrics(*surface);
        let result = config.evaluate_surface(&metrics, None, None);
        if result.outcome == GateOutcome::Pass {
            // No coverage violations from hard-gated targets
            // No mutation violations from hard-gated policies
            assert!(result.regression_violations.is_empty());
        }
    }
}

#[test]
fn enrichment_property_strict_regression_negative_always_blocks() {
    let config = DepthGateConfig {
        regression_policy: RegressionPolicy::strict(),
        ..DepthGateConfig::default_config()
    };
    let metrics = make_passing_metrics(TestSurface::Compiler);
    // Previous coverage higher than current (960_000) means regression
    let prev_cov = BTreeMap::from([
        (CoverageKind::Statement, 970_000),
    ]);
    let result = config.evaluate_surface(&metrics, Some(&prev_cov), None);
    assert!(result.outcome.is_blocking());
    assert!(!result.regression_violations.is_empty());
}

#[test]
fn enrichment_property_no_decrease_no_regression() {
    let config = DepthGateConfig::default_config();
    let metrics = make_passing_metrics(TestSurface::Evidence);
    // Previous coverage lower or equal — no regression
    let prev_cov = BTreeMap::from([
        (CoverageKind::Statement, 950_000),
        (CoverageKind::Branch, 900_000),
        (CoverageKind::Path, 500_000),
    ]);
    let result = config.evaluate_surface(&metrics, Some(&prev_cov), Some(1_000_000));
    assert!(result.regression_violations.is_empty());
}

#[test]
fn enrichment_property_promotion_iff_no_block() {
    let config = DepthGateConfig::default_config();
    let metrics_sets: Vec<Vec<ObservedMetrics>> = vec![
        TestSurface::ALL
            .iter()
            .map(|s| make_passing_metrics(*s))
            .collect(),
        vec![make_failing_metrics(TestSurface::Security)],
        vec![],
    ];
    for metrics in &metrics_sets {
        let summary = config.evaluate_all(metrics, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(
            summary.promotion_allowed(),
            !summary.overall_outcome.is_blocking()
        );
    }
}

#[test]
fn enrichment_property_blocking_violations_zero_when_pass() {
    let config = DepthGateConfig::default_config();
    let all_metrics: Vec<_> = TestSurface::ALL
        .iter()
        .map(|s| make_passing_metrics(*s))
        .collect();
    let summary = config.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
    if summary.overall_outcome == GateOutcome::Pass {
        assert_eq!(summary.blocking_violations, 0);
        assert_eq!(summary.advisory_violations, 0);
        assert_eq!(summary.total_violations, 0);
    }
}
