//! Enrichment integration tests for `bounded_regret_safety_case`.
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

use frankenengine_engine::bounded_regret_safety_case::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn build_clean_accounting(steps: usize, regret_per_step: u64) -> RegretAccounting {
    let mut a = RegretAccounting::new(RegretBound::moderate(1000));
    for _ in 0..steps {
        a.record_step(regret_per_step);
    }
    a
}

// ===========================================================================
// AdaptivePolicy enrichment
// ===========================================================================

#[test]
fn enrichment_policy_copy_semantics() {
    let a = AdaptivePolicy::Conservative;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "conservative");
}

#[test]
fn enrichment_policy_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &p in AdaptivePolicy::ALL {
        set.insert(p);
        set.insert(p);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_policy_debug_all_unique() {
    let debugs: BTreeSet<String> = AdaptivePolicy::ALL
        .iter()
        .map(|p| format!("{p:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_policy_display_all_unique() {
    let displays: BTreeSet<String> = AdaptivePolicy::ALL.iter().map(|p| format!("{p}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_policy_as_str_matches_display() {
    for p in AdaptivePolicy::ALL {
        assert_eq!(p.as_str(), format!("{p}"));
    }
}

// ===========================================================================
// OperatorOverrideType enrichment
// ===========================================================================

#[test]
fn enrichment_override_type_copy_semantics() {
    let a = OperatorOverrideType::DenyBenchmark;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "deny_benchmark");
}

#[test]
fn enrichment_override_type_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &t in OperatorOverrideType::ALL {
        set.insert(t);
        set.insert(t);
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_override_type_debug_all_unique() {
    let debugs: BTreeSet<String> = OperatorOverrideType::ALL
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_override_type_display_all_unique() {
    let displays: BTreeSet<String> = OperatorOverrideType::ALL
        .iter()
        .map(|t| format!("{t}"))
        .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_override_type_as_str_matches_display() {
    for t in OperatorOverrideType::ALL {
        assert_eq!(t.as_str(), format!("{t}"));
    }
}

// ===========================================================================
// RegretBound enrichment
// ===========================================================================

#[test]
fn enrichment_bound_clone_independence() {
    let original = RegretBound::moderate(1000);
    let mut cloned = original.clone();
    cloned.horizon_steps = 42;
    assert_eq!(original.horizon_steps, 1000);
    assert_eq!(cloned.horizon_steps, 42);
}

#[test]
fn enrichment_bound_json_field_names() {
    let b = RegretBound::moderate(1000);
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"policy\""));
    assert!(json.contains("\"horizon_steps\""));
    assert!(json.contains("\"cumulative_budget_millionths\""));
    assert!(json.contains("\"per_step_budget_millionths\""));
    assert!(json.contains("\"decay_rate_millionths\""));
}

#[test]
fn enrichment_bound_debug_nonempty() {
    let b = RegretBound::conservative(500);
    let dbg = format!("{b:?}");
    assert!(dbg.contains("RegretBound"));
}

#[test]
fn enrichment_bound_conservative_values() {
    let b = RegretBound::conservative(500);
    assert_eq!(b.policy, AdaptivePolicy::Conservative);
    assert_eq!(b.cumulative_budget_millionths, 50_000);
    assert_eq!(b.per_step_budget_millionths, 20_000);
    assert_eq!(b.decay_rate_millionths, 5_000);
}

#[test]
fn enrichment_bound_aggressive_values() {
    let b = RegretBound::aggressive(500);
    assert_eq!(b.policy, AdaptivePolicy::Aggressive);
    assert_eq!(b.cumulative_budget_millionths, 200_000);
    assert_eq!(b.per_step_budget_millionths, 100_000);
    assert_eq!(b.decay_rate_millionths, 20_000);
}

// ===========================================================================
// RegretEntry enrichment
// ===========================================================================

#[test]
fn enrichment_entry_clone_independence() {
    let original = RegretEntry {
        timestamp_step: 0,
        regret_millionths: 5_000,
        policy_active: AdaptivePolicy::Moderate,
        was_violation: false,
    };
    let mut cloned = original.clone();
    cloned.timestamp_step = 99;
    assert_eq!(original.timestamp_step, 0);
    assert_eq!(cloned.timestamp_step, 99);
}

#[test]
fn enrichment_entry_json_field_names() {
    let e = RegretEntry {
        timestamp_step: 0,
        regret_millionths: 5_000,
        policy_active: AdaptivePolicy::Moderate,
        was_violation: false,
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"timestamp_step\""));
    assert!(json.contains("\"regret_millionths\""));
    assert!(json.contains("\"policy_active\""));
    assert!(json.contains("\"was_violation\""));
}

#[test]
fn enrichment_entry_debug_nonempty() {
    let e = RegretEntry {
        timestamp_step: 0,
        regret_millionths: 5_000,
        policy_active: AdaptivePolicy::Moderate,
        was_violation: false,
    };
    let dbg = format!("{e:?}");
    assert!(dbg.contains("RegretEntry"));
}

// ===========================================================================
// RegretAccounting enrichment
// ===========================================================================

#[test]
fn enrichment_accounting_clone_independence() {
    let original = build_clean_accounting(5, 1_000);
    let mut cloned = original.clone();
    cloned.record_step(50_000);
    assert_eq!(original.steps, 5);
    assert_eq!(cloned.steps, 6);
}

#[test]
fn enrichment_accounting_json_field_names() {
    let a = build_clean_accounting(2, 1_000);
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"bound\""));
    assert!(json.contains("\"steps\""));
    assert!(json.contains("\"cumulative_regret\""));
    assert!(json.contains("\"peak_regret\""));
    assert!(json.contains("\"violations\""));
    assert!(json.contains("\"entries\""));
}

#[test]
fn enrichment_accounting_debug_nonempty() {
    let a = RegretAccounting::new(RegretBound::moderate(100));
    let dbg = format!("{a:?}");
    assert!(dbg.contains("RegretAccounting"));
}

#[test]
fn enrichment_accounting_empty_summary() {
    let a = RegretAccounting::new(RegretBound::moderate(100));
    let s = a.summary();
    assert_eq!(s.total_steps, 0);
    assert_eq!(s.cumulative_regret_millionths, 0);
    assert_eq!(s.peak_regret_millionths, 0);
    assert_eq!(s.mean_regret_millionths, 0);
    assert_eq!(s.violations_count, 0);
    assert!(s.within_budget);
}

#[test]
fn enrichment_accounting_no_violations_stable_for_all() {
    let a = build_clean_accounting(50, 1_000);
    assert!(a.stable_for(50));
    assert!(!a.has_violations());
    assert_eq!(a.steps_since_last_violation(), 50);
}

// ===========================================================================
// RegretSummary enrichment
// ===========================================================================

#[test]
fn enrichment_summary_clone_independence() {
    let a = build_clean_accounting(5, 1_000);
    let original = a.summary();
    let mut cloned = original.clone();
    cloned.total_steps = 999;
    assert_eq!(original.total_steps, 5);
    assert_eq!(cloned.total_steps, 999);
}

#[test]
fn enrichment_summary_json_field_names() {
    let a = build_clean_accounting(5, 1_000);
    let s = a.summary();
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"total_steps\""));
    assert!(json.contains("\"cumulative_regret_millionths\""));
    assert!(json.contains("\"peak_regret_millionths\""));
    assert!(json.contains("\"mean_regret_millionths\""));
    assert!(json.contains("\"violations_count\""));
    assert!(json.contains("\"within_budget\""));
}

#[test]
fn enrichment_summary_debug_nonempty() {
    let a = build_clean_accounting(5, 1_000);
    let s = a.summary();
    let dbg = format!("{s:?}");
    assert!(dbg.contains("RegretSummary"));
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let a = build_clean_accounting(10, 3_000);
    let s = a.summary();
    let json = serde_json::to_string(&s).unwrap();
    let back: RegretSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// OperatorOverride enrichment
// ===========================================================================

#[test]
fn enrichment_override_clone_independence() {
    let original =
        OperatorOverride::new("o1", OperatorOverrideType::ForcePolicy, ep(), "test", None);
    let mut cloned = original.clone();
    cloned.override_id = "o2".to_string();
    assert_eq!(original.override_id, "o1");
    assert_eq!(cloned.override_id, "o2");
}

#[test]
fn enrichment_override_json_field_names() {
    let o = OperatorOverride::new(
        "o1",
        OperatorOverrideType::LockTier,
        ep(),
        "reason",
        Some(50),
    );
    let json = serde_json::to_string(&o).unwrap();
    assert!(json.contains("\"override_id\""));
    assert!(json.contains("\"override_type\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"expiry_step\""));
}

#[test]
fn enrichment_override_debug_nonempty() {
    let o = OperatorOverride::new("o1", OperatorOverrideType::CapRegret, ep(), "test", None);
    let dbg = format!("{o:?}");
    assert!(dbg.contains("OperatorOverride"));
}

// ===========================================================================
// BenchmarkEligibility enrichment
// ===========================================================================

#[test]
fn enrichment_eligibility_clone_independence() {
    let original = BenchmarkEligibility {
        eligible: true,
        reasons: vec!["all criteria met".into()],
        override_active: false,
        regret_within_bound: true,
        policy_stable: true,
    };
    let mut cloned = original.clone();
    cloned.eligible = false;
    assert!(original.eligible);
    assert!(!cloned.eligible);
}

#[test]
fn enrichment_eligibility_json_field_names() {
    let e = BenchmarkEligibility {
        eligible: true,
        reasons: vec!["ok".into()],
        override_active: false,
        regret_within_bound: true,
        policy_stable: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"eligible\""));
    assert!(json.contains("\"reasons\""));
    assert!(json.contains("\"override_active\""));
    assert!(json.contains("\"regret_within_bound\""));
    assert!(json.contains("\"policy_stable\""));
}

#[test]
fn enrichment_eligibility_debug_nonempty() {
    let e = BenchmarkEligibility {
        eligible: true,
        reasons: vec![],
        override_active: false,
        regret_within_bound: true,
        policy_stable: true,
    };
    let dbg = format!("{e:?}");
    assert!(dbg.contains("BenchmarkEligibility"));
}

// ===========================================================================
// SafetyCaseVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_verdict_debug_all_unique() {
    let a = build_clean_accounting(10, 1_000);
    let verdicts = vec![
        SafetyCaseVerdict::Pass {
            regret_summary: a.summary(),
            overrides_active: 0,
        },
        SafetyCaseVerdict::Fail {
            violations: vec!["x".into()],
        },
        SafetyCaseVerdict::Inconclusive {
            reasons: vec!["y".into()],
        },
    ];
    let debugs: BTreeSet<String> = verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_verdict_display_all_unique() {
    let a = build_clean_accounting(10, 1_000);
    let verdicts = vec![
        SafetyCaseVerdict::Pass {
            regret_summary: a.summary(),
            overrides_active: 0,
        },
        SafetyCaseVerdict::Fail {
            violations: vec!["x".into()],
        },
        SafetyCaseVerdict::Inconclusive {
            reasons: vec!["y".into()],
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_verdict_tag_all_unique() {
    let a = build_clean_accounting(10, 1_000);
    let verdicts = vec![
        SafetyCaseVerdict::Pass {
            regret_summary: a.summary(),
            overrides_active: 0,
        },
        SafetyCaseVerdict::Fail { violations: vec![] },
        SafetyCaseVerdict::Inconclusive { reasons: vec![] },
    ];
    let tags: BTreeSet<&str> = verdicts.iter().map(|v| v.tag()).collect();
    assert_eq!(tags.len(), 3);
}

#[test]
fn enrichment_verdict_is_pass_fail_inconclusive() {
    let a = build_clean_accounting(10, 1_000);
    let pass = SafetyCaseVerdict::Pass {
        regret_summary: a.summary(),
        overrides_active: 0,
    };
    assert!(pass.is_pass());
    assert!(!pass.is_fail());
    assert!(!pass.is_inconclusive());

    let fail = SafetyCaseVerdict::Fail {
        violations: vec!["x".into()],
    };
    assert!(!fail.is_pass());
    assert!(fail.is_fail());
    assert!(!fail.is_inconclusive());

    let inc = SafetyCaseVerdict::Inconclusive {
        reasons: vec!["y".into()],
    };
    assert!(!inc.is_pass());
    assert!(!inc.is_fail());
    assert!(inc.is_inconclusive());
}

#[test]
fn enrichment_verdict_display_contains_count() {
    let fail = SafetyCaseVerdict::Fail {
        violations: vec!["a".into(), "b".into()],
    };
    assert!(format!("{fail}").contains("2 violation"));

    let inc = SafetyCaseVerdict::Inconclusive {
        reasons: vec!["r1".into(), "r2".into(), "r3".into()],
    };
    assert!(format!("{inc}").contains("3 reason"));
}

// ===========================================================================
// SafetyCaseConfig enrichment
// ===========================================================================

#[test]
fn enrichment_config_clone_independence() {
    let original = SafetyCaseConfig::default_config();
    let mut cloned = original.clone();
    cloned.min_stability_steps = 999;
    assert_eq!(original.min_stability_steps, DEFAULT_MIN_STABILITY_STEPS);
    assert_eq!(cloned.min_stability_steps, 999);
}

#[test]
fn enrichment_config_json_field_names() {
    let c = SafetyCaseConfig::default_config();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"max_cumulative_regret\""));
    assert!(json.contains("\"max_per_step_regret\""));
    assert!(json.contains("\"min_stability_steps\""));
    assert!(json.contains("\"require_operator_approval_for_benchmark\""));
    assert!(json.contains("\"max_active_overrides\""));
    assert!(json.contains("\"min_verification_epoch\""));
}

#[test]
fn enrichment_config_debug_nonempty() {
    let c = SafetyCaseConfig::default_config();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("SafetyCaseConfig"));
}

#[test]
fn enrichment_config_default_matches_constants() {
    let c = SafetyCaseConfig::default_config();
    assert_eq!(c.max_cumulative_regret, DEFAULT_CUMULATIVE_BUDGET);
    assert_eq!(c.max_per_step_regret, DEFAULT_PER_STEP_BUDGET);
    assert_eq!(c.min_stability_steps, DEFAULT_MIN_STABILITY_STEPS);
    assert_eq!(c.max_active_overrides, DEFAULT_MAX_ACTIVE_OVERRIDES);
    assert_eq!(c.min_verification_epoch, DEFAULT_MIN_VERIFICATION_EPOCH);
}

#[test]
fn enrichment_config_strict_stricter_than_default() {
    let d = SafetyCaseConfig::default_config();
    let s = SafetyCaseConfig::strict();
    assert!(s.max_cumulative_regret <= d.max_cumulative_regret);
    assert!(s.max_per_step_regret <= d.max_per_step_regret);
    assert!(s.min_stability_steps >= d.min_stability_steps);
    assert!(s.max_active_overrides <= d.max_active_overrides);
}

#[test]
fn enrichment_config_permissive_more_lenient() {
    let d = SafetyCaseConfig::default_config();
    let p = SafetyCaseConfig::permissive();
    assert!(p.max_cumulative_regret >= d.max_cumulative_regret);
    assert!(p.max_per_step_regret >= d.max_per_step_regret);
    assert!(p.min_stability_steps <= d.min_stability_steps);
}

#[test]
fn enrichment_config_default_trait_eq_default_config() {
    assert_eq!(
        SafetyCaseConfig::default(),
        SafetyCaseConfig::default_config()
    );
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = SafetyCaseConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: SafetyCaseConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// SafetyCaseError enrichment
// ===========================================================================

#[test]
fn enrichment_error_clone_independence() {
    let original = SafetyCaseError::BudgetExceeded {
        cumulative: 200_000,
        budget: 100_000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_error_debug_all_unique() {
    let errors = vec![
        SafetyCaseError::EmptyAccounting,
        SafetyCaseError::BudgetExceeded {
            cumulative: 200_000,
            budget: 100_000,
        },
        SafetyCaseError::InvalidConfig {
            field: "f".into(),
            reason: "r".into(),
        },
        SafetyCaseError::OverrideConflict {
            override_a: "a".into(),
            override_b: "b".into(),
            reason: "r".into(),
        },
        SafetyCaseError::StaleEvidence {
            evidence_epoch: 0,
            min_epoch: 1,
        },
    ];
    let debugs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors = vec![
        SafetyCaseError::EmptyAccounting,
        SafetyCaseError::BudgetExceeded {
            cumulative: 200_000,
            budget: 100_000,
        },
        SafetyCaseError::InvalidConfig {
            field: "f".into(),
            reason: "r".into(),
        },
        SafetyCaseError::OverrideConflict {
            override_a: "a".into(),
            override_b: "b".into(),
            reason: "r".into(),
        },
        SafetyCaseError::StaleEvidence {
            evidence_epoch: 0,
            min_epoch: 1,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_error_tag_all_unique() {
    let errors = vec![
        SafetyCaseError::EmptyAccounting,
        SafetyCaseError::BudgetExceeded {
            cumulative: 1,
            budget: 1,
        },
        SafetyCaseError::InvalidConfig {
            field: "f".into(),
            reason: "r".into(),
        },
        SafetyCaseError::OverrideConflict {
            override_a: "a".into(),
            override_b: "b".into(),
            reason: "r".into(),
        },
        SafetyCaseError::StaleEvidence {
            evidence_epoch: 0,
            min_epoch: 1,
        },
    ];
    let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), 5);
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = vec![
        SafetyCaseError::EmptyAccounting,
        SafetyCaseError::BudgetExceeded {
            cumulative: 200_000,
            budget: 100_000,
        },
        SafetyCaseError::InvalidConfig {
            field: "f".into(),
            reason: "r".into(),
        },
        SafetyCaseError::OverrideConflict {
            override_a: "a".into(),
            override_b: "b".into(),
            reason: "r".into(),
        },
        SafetyCaseError::StaleEvidence {
            evidence_epoch: 0,
            min_epoch: 1,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: SafetyCaseError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// SafetyCaseReport enrichment
// ===========================================================================

#[test]
fn enrichment_report_clone_independence() {
    let a = build_clean_accounting(10, 1_000);
    let original = report(&a, &[], &SafetyCaseConfig::permissive(), ep());
    let mut cloned = original.clone();
    cloned.schema_version = "mutated".to_string();
    assert_ne!(original.schema_version, "mutated");
    assert_eq!(cloned.schema_version, "mutated");
}

#[test]
fn enrichment_report_json_field_names() {
    let a = build_clean_accounting(10, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::permissive(), ep());
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"policy_active\""));
    assert!(json.contains("\"regret_summary\""));
    assert!(json.contains("\"overrides\""));
    assert!(json.contains("\"benchmark_eligibility\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"report_hash\""));
}

#[test]
fn enrichment_report_debug_nonempty() {
    let a = build_clean_accounting(5, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::permissive(), ep());
    let dbg = format!("{r:?}");
    assert!(dbg.contains("SafetyCaseReport"));
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let a = build_clean_accounting(10, 1_000);
    let r = report(&a, &[], &SafetyCaseConfig::permissive(), ep());
    let json = serde_json::to_string(&r).unwrap();
    let back: SafetyCaseReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// Cross-cutting: evaluate_safety_case
// ===========================================================================

#[test]
fn enrichment_safety_case_empty_accounting_inconclusive() {
    let a = RegretAccounting::new(RegretBound::moderate(100));
    let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default_config(), ep());
    assert!(v.is_inconclusive());
}

#[test]
fn enrichment_safety_case_clean_passes() {
    let a = build_clean_accounting(200, 1_000);
    let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default_config(), ep());
    assert!(v.is_pass());
}

#[test]
fn enrichment_safety_case_too_many_overrides_fails() {
    let a = build_clean_accounting(10, 1_000);
    let overrides: Vec<OperatorOverride> = (0..10)
        .map(|i| {
            OperatorOverride::new(
                format!("o{i}"),
                OperatorOverrideType::LockTier,
                ep(),
                "test",
                None,
            )
        })
        .collect();
    let v = evaluate_safety_case(&a, &overrides, &SafetyCaseConfig::default_config(), ep());
    assert!(v.is_fail());
}

#[test]
fn enrichment_safety_case_stale_epoch_fails() {
    let a = build_clean_accounting(10, 1_000);
    let config = SafetyCaseConfig {
        min_verification_epoch: 200,
        ..SafetyCaseConfig::default_config()
    };
    let v = evaluate_safety_case(&a, &[], &config, SecurityEpoch::from_raw(50));
    assert!(v.is_fail());
}

// ===========================================================================
// Cross-cutting: check_benchmark_eligibility
// ===========================================================================

#[test]
fn enrichment_benchmark_deny_overrides_allow() {
    let a = build_clean_accounting(200, 1_000);
    let overrides = vec![
        OperatorOverride::new(
            "allow",
            OperatorOverrideType::AllowBenchmark,
            ep(),
            "r",
            None,
        ),
        OperatorOverride::new("deny", OperatorOverrideType::DenyBenchmark, ep(), "r", None),
    ];
    let e = check_benchmark_eligibility(&a, &overrides, &SafetyCaseConfig::default_config());
    assert!(!e.eligible);
    assert!(e.override_active);
}

#[test]
fn enrichment_benchmark_disable_adaptation_ineligible() {
    let a = build_clean_accounting(200, 1_000);
    let overrides = vec![OperatorOverride::new(
        "dis",
        OperatorOverrideType::DisableAdaptation,
        ep(),
        "r",
        None,
    )];
    let e = check_benchmark_eligibility(&a, &overrides, &SafetyCaseConfig::default_config());
    assert!(!e.eligible);
}

// ===========================================================================
// Cross-cutting: report determinism (5-run)
// ===========================================================================

#[test]
fn enrichment_report_determinism_five_runs() {
    let a = build_clean_accounting(50, 2_000);
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let r = report(&a, &[], &SafetyCaseConfig::permissive(), ep());
        hashes.insert(r.report_hash);
    }
    assert_eq!(hashes.len(), 1);
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.bounded-regret-safety-case.v1"
    );
    assert_eq!(COMPONENT, "bounded_regret_safety_case");
    assert_eq!(BEAD_ID, "bd-1lsy.7.8.3");
    assert_eq!(POLICY_ID, "RGC-608C");
    assert_eq!(DEFAULT_CUMULATIVE_BUDGET, 100_000);
    assert_eq!(DEFAULT_PER_STEP_BUDGET, 50_000);
    assert_eq!(DEFAULT_DECAY_RATE, 10_000);
    assert_eq!(DEFAULT_MIN_STABILITY_STEPS, 100);
    assert_eq!(DEFAULT_MAX_ACTIVE_OVERRIDES, 8);
    assert_eq!(DEFAULT_MIN_VERIFICATION_EPOCH, 1);
}
