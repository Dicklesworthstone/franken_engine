//! Integration tests for `bounded_regret_safety_case` module.
//!
//! Validates public API, serde contracts, determinism, safety case evaluation,
//! benchmark eligibility, operator overrides, regret accounting, and reports.

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

use frankenengine_engine::bounded_regret_safety_case::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn high_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(500)
}

fn moderate_bound() -> RegretBound {
    RegretBound::moderate(1000)
}

fn conservative_bound() -> RegretBound {
    RegretBound::conservative(500)
}

fn build_clean_accounting(steps: usize, regret_per_step: u64) -> RegretAccounting {
    let mut a = RegretAccounting::new(moderate_bound());
    for _ in 0..steps {
        a.record_step(regret_per_step);
    }
    a
}

fn allow_override() -> OperatorOverride {
    OperatorOverride::new(
        "allow-1",
        OperatorOverrideType::AllowBenchmark,
        epoch(),
        "operator approved",
        None,
    )
}

fn deny_override() -> OperatorOverride {
    OperatorOverride::new(
        "deny-1",
        OperatorOverrideType::DenyBenchmark,
        epoch(),
        "operator denied",
        None,
    )
}

fn disable_override() -> OperatorOverride {
    OperatorOverride::new(
        "dis-1",
        OperatorOverrideType::DisableAdaptation,
        epoch(),
        "adaptation off",
        None,
    )
}

// ---------------------------------------------------------------------------
// 1. Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_schema_version_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn constants_component_name() {
    assert_eq!(COMPONENT, "bounded_regret_safety_case");
}

#[test]
fn constants_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn constants_policy_id() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn constants_defaults_positive() {
    assert!(DEFAULT_CUMULATIVE_BUDGET > 0);
    assert!(DEFAULT_PER_STEP_BUDGET > 0);
    assert!(DEFAULT_DECAY_RATE > 0);
    assert!(DEFAULT_MIN_STABILITY_STEPS > 0);
    assert!(DEFAULT_MAX_ACTIVE_OVERRIDES > 0);
}

// ---------------------------------------------------------------------------
// 2. AdaptivePolicy
// ---------------------------------------------------------------------------

#[test]
fn policy_all_variants_present() {
    assert_eq!(AdaptivePolicy::ALL.len(), 4);
}

#[test]
fn policy_as_str_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for p in AdaptivePolicy::ALL {
        assert!(seen.insert(p.as_str()));
    }
}

#[test]
fn policy_display_equals_as_str() {
    for p in AdaptivePolicy::ALL {
        assert_eq!(format!("{p}"), p.as_str());
    }
}

#[test]
fn policy_serde_all() {
    for p in AdaptivePolicy::ALL {
        let json = serde_json::to_string(p).unwrap();
        let back: AdaptivePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

// ---------------------------------------------------------------------------
// 3. OperatorOverrideType
// ---------------------------------------------------------------------------

#[test]
fn override_type_all_variants() {
    assert_eq!(OperatorOverrideType::ALL.len(), 6);
}

#[test]
fn override_type_as_str_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for t in OperatorOverrideType::ALL {
        assert!(seen.insert(t.as_str()));
    }
}

#[test]
fn override_type_display() {
    for t in OperatorOverrideType::ALL {
        assert_eq!(format!("{t}"), t.as_str());
    }
}

#[test]
fn override_type_serde_roundtrip() {
    for t in OperatorOverrideType::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: OperatorOverrideType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// 4. RegretBound
// ---------------------------------------------------------------------------

#[test]
fn bound_conservative_tighter_than_moderate() {
    let c = RegretBound::conservative(500);
    let m = RegretBound::moderate(500);
    assert!(c.cumulative_budget_millionths < m.cumulative_budget_millionths);
    assert!(c.per_step_budget_millionths < m.per_step_budget_millionths);
}

#[test]
fn bound_aggressive_looser_than_moderate() {
    let a = RegretBound::aggressive(500);
    let m = RegretBound::moderate(500);
    assert!(a.cumulative_budget_millionths > m.cumulative_budget_millionths);
}

#[test]
fn bound_serde() {
    let b = RegretBound::moderate(1000);
    let json = serde_json::to_string(&b).unwrap();
    let back: RegretBound = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn bound_custom_new() {
    let b = RegretBound::new(AdaptivePolicy::Custom, 42, 100_000, 10_000, 5_000);
    assert_eq!(b.policy, AdaptivePolicy::Custom);
    assert_eq!(b.horizon_steps, 42);
}

// ---------------------------------------------------------------------------
// 5. RegretAccounting
// ---------------------------------------------------------------------------

#[test]
fn accounting_fresh_state() {
    let a = RegretAccounting::new(moderate_bound());
    assert_eq!(a.steps, 0);
    assert_eq!(a.cumulative_regret, 0);
    assert_eq!(a.peak_regret, 0);
    assert_eq!(a.violations, 0);
    assert!(a.within_budget());
    assert!(!a.has_violations());
}

#[test]
fn accounting_record_and_count() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(1_000);
    a.record_step(2_000);
    a.record_step(3_000);
    assert_eq!(a.steps, 3);
    assert_eq!(a.entries.len(), 3);
}

#[test]
fn accounting_peak_tracking() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(5_000);
    a.record_step(25_000);
    a.record_step(10_000);
    assert_eq!(a.peak_regret, 25_000);
}

#[test]
fn accounting_violation_tracking() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(DEFAULT_PER_STEP_BUDGET); // at limit, not violation
    a.record_step(DEFAULT_PER_STEP_BUDGET + 1); // violation
    assert_eq!(a.violations, 1);
    assert!(a.entries[0].was_violation == false);
    assert!(a.entries[1].was_violation == true);
}

#[test]
fn accounting_decay_applied() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(20_000);
    let after_first = a.cumulative_regret;
    a.record_step(0);
    // Decay should reduce the cumulative
    assert!(a.cumulative_regret < after_first);
}

#[test]
fn accounting_no_decay_when_zero_rate() {
    let mut a = RegretAccounting::new(RegretBound::new(
        AdaptivePolicy::Custom,
        100,
        1_000_000,
        100_000,
        0,
    ));
    a.record_step(10_000);
    a.record_step(10_000);
    assert_eq!(a.cumulative_regret, 20_000);
}

#[test]
fn accounting_summary_fields() {
    let a = build_clean_accounting(10, 5_000);
    let s = a.summary();
    assert_eq!(s.total_steps, 10);
    assert_eq!(s.mean_regret_millionths, 5_000);
    assert_eq!(s.violations_count, 0);
    assert!(s.within_budget);
}

#[test]
fn accounting_steps_since_violation() {
    let mut a = RegretAccounting::new(moderate_bound());
    for _ in 0..5 {
        a.record_step(1_000);
    }
    a.record_step(60_000); // violation at step 5
    for _ in 0..3 {
        a.record_step(1_000);
    }
    assert_eq!(a.steps_since_last_violation(), 3);
}

#[test]
fn accounting_stable_for_exact_boundary() {
    let mut a = RegretAccounting::new(moderate_bound());
    for _ in 0..100 {
        a.record_step(1_000);
    }
    assert!(a.stable_for(100));
    assert!(!a.stable_for(101));
}

#[test]
fn accounting_serde() {
    let a = build_clean_accounting(5, 3_000);
    let json = serde_json::to_string(&a).unwrap();
    let back: RegretAccounting = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// 6. OperatorOverride
// ---------------------------------------------------------------------------

#[test]
fn override_no_expiry_always_active() {
    let o = OperatorOverride::new(
        "o1",
        OperatorOverrideType::ForcePolicy,
        epoch(),
        "test",
        None,
    );
    assert!(o.is_active_at(0));
    assert!(o.is_active_at(1_000_000));
}

#[test]
fn override_with_expiry_boundary() {
    let o = OperatorOverride::new(
        "o1",
        OperatorOverrideType::CapRegret,
        epoch(),
        "test",
        Some(100),
    );
    assert!(o.is_active_at(99));
    assert!(!o.is_active_at(100));
}

#[test]
fn override_affects_benchmark_positive() {
    for t in [
        OperatorOverrideType::AllowBenchmark,
        OperatorOverrideType::DenyBenchmark,
        OperatorOverrideType::DisableAdaptation,
    ] {
        let o = OperatorOverride::new("x", t, epoch(), "r", None);
        assert!(o.affects_benchmark(), "expected {t} to affect benchmark");
    }
}

#[test]
fn override_affects_benchmark_negative() {
    for t in [
        OperatorOverrideType::ForcePolicy,
        OperatorOverrideType::LockTier,
        OperatorOverrideType::CapRegret,
    ] {
        let o = OperatorOverride::new("x", t, epoch(), "r", None);
        assert!(
            !o.affects_benchmark(),
            "expected {t} not to affect benchmark"
        );
    }
}

#[test]
fn override_serde() {
    let o = OperatorOverride::new(
        "o1",
        OperatorOverrideType::LockTier,
        epoch(),
        "reason",
        Some(50),
    );
    let json = serde_json::to_string(&o).unwrap();
    let back: OperatorOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

// ---------------------------------------------------------------------------
// 7. SafetyCaseError
// ---------------------------------------------------------------------------

#[test]
fn error_tags_distinct() {
    let errors = vec![
        SafetyCaseError::EmptyAccounting,
        SafetyCaseError::BudgetExceeded {
            cumulative: 1,
            budget: 0,
        },
        SafetyCaseError::InvalidConfig {
            field: "x".into(),
            reason: "y".into(),
        },
        SafetyCaseError::OverrideConflict {
            override_a: "a".into(),
            override_b: "b".into(),
            reason: "c".into(),
        },
        SafetyCaseError::StaleEvidence {
            evidence_epoch: 0,
            min_epoch: 1,
        },
    ];
    let tags: std::collections::BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), errors.len());
}

#[test]
fn error_display_empty_accounting() {
    let e = SafetyCaseError::EmptyAccounting;
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_display_budget_exceeded() {
    let e = SafetyCaseError::BudgetExceeded {
        cumulative: 200_000,
        budget: 100_000,
    };
    let s = e.to_string();
    assert!(s.contains("200000"));
    assert!(s.contains("100000"));
}

#[test]
fn error_serde() {
    let e = SafetyCaseError::OverrideConflict {
        override_a: "a".into(),
        override_b: "b".into(),
        reason: "conflict".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: SafetyCaseError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// 8. SafetyCaseVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_pass_properties() {
    let v = SafetyCaseVerdict::Pass {
        regret_summary: RegretSummary {
            total_steps: 5,
            cumulative_regret_millionths: 1_000,
            peak_regret_millionths: 500,
            mean_regret_millionths: 200,
            violations_count: 0,
            within_budget: true,
        },
        overrides_active: 0,
    };
    assert!(v.is_pass());
    assert!(!v.is_fail());
    assert!(!v.is_inconclusive());
    assert_eq!(v.tag(), "pass");
    assert!(v.to_string().contains("PASS"));
}

#[test]
fn verdict_fail_properties() {
    let v = SafetyCaseVerdict::Fail {
        violations: vec!["reason".into()],
    };
    assert!(v.is_fail());
    assert_eq!(v.tag(), "fail");
    assert!(v.to_string().contains("FAIL"));
}

#[test]
fn verdict_inconclusive_properties() {
    let v = SafetyCaseVerdict::Inconclusive {
        reasons: vec!["no data".into()],
    };
    assert!(v.is_inconclusive());
    assert_eq!(v.tag(), "inconclusive");
    assert!(v.to_string().contains("INCONCLUSIVE"));
}

#[test]
fn verdict_serde_all_variants() {
    let variants: Vec<SafetyCaseVerdict> = vec![
        SafetyCaseVerdict::Pass {
            regret_summary: RegretSummary {
                total_steps: 1,
                cumulative_regret_millionths: 0,
                peak_regret_millionths: 0,
                mean_regret_millionths: 0,
                violations_count: 0,
                within_budget: true,
            },
            overrides_active: 0,
        },
        SafetyCaseVerdict::Fail {
            violations: vec!["x".into()],
        },
        SafetyCaseVerdict::Inconclusive {
            reasons: vec!["y".into()],
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SafetyCaseVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// 9. SafetyCaseConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = SafetyCaseConfig::default_config();
    assert_eq!(c.max_cumulative_regret, DEFAULT_CUMULATIVE_BUDGET);
    assert_eq!(c.max_per_step_regret, DEFAULT_PER_STEP_BUDGET);
    assert_eq!(c.min_stability_steps, DEFAULT_MIN_STABILITY_STEPS);
    assert!(c.require_operator_approval_for_benchmark);
}

#[test]
fn config_permissive_values() {
    let c = SafetyCaseConfig::permissive();
    assert_eq!(c.max_cumulative_regret, u64::MAX);
    assert!(!c.require_operator_approval_for_benchmark);
    assert_eq!(c.min_stability_steps, 0);
}

#[test]
fn config_strict_values() {
    let c = SafetyCaseConfig::strict();
    assert!(c.max_cumulative_regret < DEFAULT_CUMULATIVE_BUDGET);
    assert!(c.min_stability_steps > DEFAULT_MIN_STABILITY_STEPS);
    assert!(c.require_operator_approval_for_benchmark);
}

#[test]
fn config_default_trait() {
    let c: SafetyCaseConfig = Default::default();
    assert_eq!(c, SafetyCaseConfig::default_config());
}

#[test]
fn config_serde() {
    let c = SafetyCaseConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: SafetyCaseConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// 10. evaluate_safety_case
// ---------------------------------------------------------------------------

#[test]
fn evaluate_empty_accounting_inconclusive() {
    let a = RegretAccounting::new(moderate_bound());
    let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
    assert!(v.is_inconclusive());
}

#[test]
fn evaluate_clean_passes() {
    let a = build_clean_accounting(200, 500);
    let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
    assert!(v.is_pass());
}

#[test]
fn evaluate_over_cumulative_budget_fails() {
    let mut a = RegretAccounting::new(RegretBound::new(
        AdaptivePolicy::Moderate,
        1000,
        100_000,
        100_000,
        0,
    ));
    for _ in 0..20 {
        a.record_step(10_000);
    }
    let config = SafetyCaseConfig {
        max_cumulative_regret: 100_000,
        ..SafetyCaseConfig::default()
    };
    let v = evaluate_safety_case(&a, &[], &config, epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_peak_regret_exceeds_fails() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(200_000);
    let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_stale_epoch_fails() {
    let a = build_clean_accounting(5, 100);
    let config = SafetyCaseConfig {
        min_verification_epoch: 999,
        ..SafetyCaseConfig::default()
    };
    let v = evaluate_safety_case(&a, &[], &config, epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_fresh_epoch_passes() {
    let a = build_clean_accounting(5, 100);
    let config = SafetyCaseConfig {
        min_verification_epoch: 50,
        ..SafetyCaseConfig::default()
    };
    let v = evaluate_safety_case(&a, &[], &config, high_epoch());
    assert!(v.is_pass());
}

#[test]
fn evaluate_override_conflict_allow_deny() {
    let a = build_clean_accounting(5, 100);
    let overrides = vec![allow_override(), deny_override()];
    let v = evaluate_safety_case(&a, &overrides, &SafetyCaseConfig::default(), epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_override_conflict_disable_force() {
    let a = build_clean_accounting(5, 100);
    let overrides = vec![
        disable_override(),
        OperatorOverride::new(
            "force-1",
            OperatorOverrideType::ForcePolicy,
            epoch(),
            "force it",
            None,
        ),
    ];
    let v = evaluate_safety_case(&a, &overrides, &SafetyCaseConfig::default(), epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_too_many_overrides() {
    let a = build_clean_accounting(5, 100);
    let overrides: Vec<OperatorOverride> = (0..20)
        .map(|i| {
            OperatorOverride::new(
                format!("ovr-{i}"),
                OperatorOverrideType::LockTier,
                epoch(),
                "lock",
                None,
            )
        })
        .collect();
    let config = SafetyCaseConfig {
        max_active_overrides: 5,
        ..SafetyCaseConfig::default()
    };
    let v = evaluate_safety_case(&a, &overrides, &config, epoch());
    assert!(v.is_fail());
}

#[test]
fn evaluate_expired_overrides_not_counted() {
    let a = build_clean_accounting(100, 100);
    let overrides: Vec<OperatorOverride> = (0..20)
        .map(|i| {
            OperatorOverride::new(
                format!("ovr-{i}"),
                OperatorOverrideType::LockTier,
                epoch(),
                "lock",
                Some(10), // all expired before step 100
            )
        })
        .collect();
    let config = SafetyCaseConfig {
        max_active_overrides: 5,
        ..SafetyCaseConfig::default()
    };
    let v = evaluate_safety_case(&a, &overrides, &config, epoch());
    assert!(v.is_pass());
}

// ---------------------------------------------------------------------------
// 11. check_benchmark_eligibility
// ---------------------------------------------------------------------------

#[test]
fn eligibility_all_met() {
    let a = build_clean_accounting(200, 100);
    let config = SafetyCaseConfig::default();
    let e = check_benchmark_eligibility(&a, &[allow_override()], &config);
    assert!(e.eligible);
    assert!(e.regret_within_bound);
    assert!(e.policy_stable);
}

#[test]
fn eligibility_denied_by_operator() {
    let a = build_clean_accounting(200, 100);
    let e = check_benchmark_eligibility(&a, &[deny_override()], &SafetyCaseConfig::default());
    assert!(!e.eligible);
    assert!(e.override_active);
}

#[test]
fn eligibility_disabled_adaptation() {
    let a = build_clean_accounting(200, 100);
    let e = check_benchmark_eligibility(&a, &[disable_override()], &SafetyCaseConfig::default());
    assert!(!e.eligible);
    assert!(e.override_active);
}

#[test]
fn eligibility_no_operator_approval() {
    let a = build_clean_accounting(200, 100);
    let config = SafetyCaseConfig {
        require_operator_approval_for_benchmark: true,
        ..SafetyCaseConfig::default()
    };
    let e = check_benchmark_eligibility(&a, &[], &config);
    assert!(!e.eligible);
}

#[test]
fn eligibility_approval_not_required() {
    let a = build_clean_accounting(200, 100);
    let config = SafetyCaseConfig {
        require_operator_approval_for_benchmark: false,
        ..SafetyCaseConfig::default()
    };
    let e = check_benchmark_eligibility(&a, &[], &config);
    assert!(e.eligible);
}

#[test]
fn eligibility_policy_unstable() {
    let mut a = RegretAccounting::new(moderate_bound());
    for _ in 0..50 {
        a.record_step(100);
    }
    a.record_step(60_000); // violation
    for _ in 0..10 {
        a.record_step(100);
    }
    let config = SafetyCaseConfig {
        min_stability_steps: 50,
        require_operator_approval_for_benchmark: false,
        ..SafetyCaseConfig::default()
    };
    let e = check_benchmark_eligibility(&a, &[], &config);
    assert!(!e.eligible);
    assert!(!e.policy_stable);
}

#[test]
fn eligibility_regret_over_budget() {
    let mut a = RegretAccounting::new(RegretBound::new(
        AdaptivePolicy::Conservative,
        100,
        2_000,
        50_000,
        0,
    ));
    for _ in 0..5 {
        a.record_step(1_000);
    }
    let config = SafetyCaseConfig {
        require_operator_approval_for_benchmark: false,
        min_stability_steps: 0,
        ..SafetyCaseConfig::default()
    };
    let e = check_benchmark_eligibility(&a, &[], &config);
    assert!(!e.eligible);
    assert!(!e.regret_within_bound);
}

// ---------------------------------------------------------------------------
// 12. report
// ---------------------------------------------------------------------------

#[test]
fn report_schema_version() {
    let a = build_clean_accounting(5, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::default(), epoch());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_epoch() {
    let a = build_clean_accounting(5, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::default(), high_epoch());
    assert_eq!(r.epoch, high_epoch());
}

#[test]
fn report_policy_active() {
    let a = build_clean_accounting(5, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::default(), epoch());
    assert_eq!(r.policy_active, AdaptivePolicy::Moderate);
}

#[test]
fn report_hash_deterministic() {
    let a = build_clean_accounting(10, 2_000);
    let config = SafetyCaseConfig::default();
    let r1 = report(&a, &[], &config, epoch());
    let r2 = report(&a, &[], &config, epoch());
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn report_hash_differs_on_epoch() {
    let a = build_clean_accounting(5, 1_000);
    let config = SafetyCaseConfig::default();
    let r1 = report(&a, &[], &config, epoch());
    let r2 = report(&a, &[], &config, high_epoch());
    assert_ne!(r1.report_hash, r2.report_hash);
}

#[test]
fn report_filters_expired_overrides() {
    let a = build_clean_accounting(50, 100);
    let overrides = vec![
        OperatorOverride::new(
            "active",
            OperatorOverrideType::LockTier,
            epoch(),
            "active",
            None,
        ),
        OperatorOverride::new(
            "expired",
            OperatorOverrideType::CapRegret,
            epoch(),
            "expired",
            Some(10),
        ),
    ];
    let r = report(&a, &overrides, &SafetyCaseConfig::default(), epoch());
    assert_eq!(r.overrides.len(), 1);
    assert_eq!(r.overrides[0].override_id, "active");
}

#[test]
fn report_serde_roundtrip() {
    let a = build_clean_accounting(5, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::default(), epoch());
    let json = serde_json::to_string(&r).unwrap();
    let back: SafetyCaseReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn report_includes_verdict_and_eligibility() {
    let a = build_clean_accounting(200, 100);
    let r = report(
        &a,
        &[allow_override()],
        &SafetyCaseConfig::default(),
        epoch(),
    );
    assert!(r.verdict.is_pass());
    assert!(r.benchmark_eligibility.eligible);
}

// ---------------------------------------------------------------------------
// 13. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn zero_regret_always_within_budget() {
    let a = build_clean_accounting(100, 0);
    assert!(a.within_budget());
    assert_eq!(a.cumulative_regret, 0);
    assert_eq!(a.peak_regret, 0);
}

#[test]
fn full_decay_only_last_step_counts() {
    let mut a = RegretAccounting::new(RegretBound::new(
        AdaptivePolicy::Custom,
        100,
        1_000_000,
        100_000,
        1_000_000, // 100% decay
    ));
    a.record_step(50_000);
    a.record_step(10_000);
    assert_eq!(a.cumulative_regret, 10_000);
}

#[test]
fn conservative_bound_fields() {
    let b = conservative_bound();
    assert_eq!(b.policy, AdaptivePolicy::Conservative);
    assert_eq!(b.horizon_steps, 500);
}

#[test]
fn multiple_violations_counted() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(60_000);
    a.record_step(70_000);
    a.record_step(80_000);
    assert_eq!(a.violations, 3);
}

#[test]
fn summary_peak_matches_accounting() {
    let mut a = RegretAccounting::new(moderate_bound());
    a.record_step(10_000);
    a.record_step(40_000);
    a.record_step(20_000);
    let s = a.summary();
    assert_eq!(s.peak_regret_millionths, 40_000);
    assert_eq!(s.peak_regret_millionths, a.peak_regret);
}
