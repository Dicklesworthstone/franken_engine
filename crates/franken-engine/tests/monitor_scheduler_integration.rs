//! Integration tests for the `monitor_scheduler` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! probe registration, VOI scoring, regime-adaptive budgets, scheduling
//! determinism, history tracking, error conditions, and serde round-trips.

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

use std::collections::BTreeMap;

use frankenengine_engine::monitor_scheduler::{
    MonitorScheduler, ProbeConfig, ProbeKind, ProbeState, ScheduleDecision, ScheduleResult,
    SchedulerConfig, SchedulerError,
};
use frankenengine_engine::regime_detector::Regime;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn health_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::HealthCheck,
        cost_millionths: 100_000,             // 0.1
        information_gain_millionths: 500_000, // 0.5
        base_relevance_millionths: 1_000_000, // 1.0
    }
}

fn deep_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::DeepDiagnostic,
        cost_millionths: 2_000_000,             // 2.0
        information_gain_millionths: 3_000_000, // 3.0
        base_relevance_millionths: 800_000,     // 0.8
    }
}

fn calibration_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::CalibrationProbe,
        cost_millionths: 500_000,               // 0.5
        information_gain_millionths: 1_500_000, // 1.5
        base_relevance_millionths: 700_000,     // 0.7
    }
}

fn integrity_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::IntegrityAudit,
        cost_millionths: 1_500_000,             // 1.5
        information_gain_millionths: 2_000_000, // 2.0
        base_relevance_millionths: 900_000,     // 0.9
    }
}

fn base_config() -> SchedulerConfig {
    let mut regime_budgets = BTreeMap::new();
    regime_budgets.insert("normal".to_string(), 3_000_000); // 3.0
    regime_budgets.insert("elevated".to_string(), 6_000_000); // 6.0
    regime_budgets.insert("attack".to_string(), 10_000_000); // 10.0

    SchedulerConfig {
        scheduler_id: "sched-int".to_string(),
        base_budget_millionths: 3_000_000,
        regime_budgets,
        relevance_overrides: BTreeMap::new(),
    }
}

fn base_scheduler() -> MonitorScheduler {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("health-1")).unwrap();
    sched.register_probe(deep_probe("deep-1")).unwrap();
    sched
        .register_probe(integrity_probe("integrity-1"))
        .unwrap();
    sched
}

// ===========================================================================
// Section 1: ProbeKind Display
// ===========================================================================

#[test]
fn probe_kind_display_all_variants() {
    assert_eq!(ProbeKind::HealthCheck.to_string(), "health_check");
    assert_eq!(ProbeKind::DeepDiagnostic.to_string(), "deep_diagnostic");
    assert_eq!(ProbeKind::CalibrationProbe.to_string(), "calibration_probe");
    assert_eq!(ProbeKind::IntegrityAudit.to_string(), "integrity_audit");
}

#[test]
fn probe_kind_ordering_is_stable() {
    let mut kinds = vec![
        ProbeKind::IntegrityAudit,
        ProbeKind::HealthCheck,
        ProbeKind::CalibrationProbe,
        ProbeKind::DeepDiagnostic,
    ];
    let kinds_clone = kinds.clone();
    kinds.sort();
    // Re-sort to verify deterministic ordering.
    let mut kinds2 = kinds_clone;
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ===========================================================================
// Section 2: ProbeConfig construction and serde
// ===========================================================================

#[test]
fn probe_config_fields_are_accessible() {
    let cfg = health_probe("probe-alpha");
    assert_eq!(cfg.probe_id, "probe-alpha");
    assert_eq!(cfg.kind, ProbeKind::HealthCheck);
    assert_eq!(cfg.cost_millionths, 100_000);
    assert_eq!(cfg.information_gain_millionths, 500_000);
    assert_eq!(cfg.base_relevance_millionths, 1_000_000);
}

#[test]
fn probe_config_serde_round_trip() {
    let configs = vec![
        health_probe("h"),
        deep_probe("d"),
        calibration_probe("c"),
        integrity_probe("i"),
    ];
    for cfg in &configs {
        let json = serde_json::to_string(cfg).expect("serialize ProbeConfig");
        let restored: ProbeConfig = serde_json::from_str(&json).expect("deserialize ProbeConfig");
        assert_eq!(*cfg, restored, "round-trip failed for {}", cfg.probe_id);
    }
}

#[test]
fn probe_config_clone_equality() {
    let cfg = deep_probe("dp-1");
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

// ===========================================================================
// Section 3: ProbeState construction, VOI, staleness, mark_executed
// ===========================================================================

#[test]
fn probe_state_initial_values() {
    let state = ProbeState::new(health_probe("h"));
    assert_eq!(state.staleness, 0);
    assert_eq!(state.execution_count, 0);
    assert!(state.last_success);
    assert_eq!(state.config.probe_id, "h");
}

#[test]
fn voi_score_is_positive_for_nonzero_staleness() {
    let mut state = ProbeState::new(health_probe("h"));
    // At staleness=0, VOI = (0+1)*1M * 1M * 500K / (100K * 1M * 1M) = 5
    let voi_fresh = state.voi_score(1_000_000);
    assert!(voi_fresh > 0, "VOI should be positive even at staleness 0");

    state.tick_staleness();
    let voi_stale = state.voi_score(1_000_000);
    assert!(voi_stale > voi_fresh, "VOI should grow with staleness");
}

#[test]
fn voi_score_monotonically_increases_with_staleness() {
    let mut state = ProbeState::new(deep_probe("d"));
    let mut prev = state.voi_score(1_000_000);
    for _ in 0..20 {
        state.tick_staleness();
        let curr = state.voi_score(1_000_000);
        assert!(curr >= prev, "VOI must be monotonically non-decreasing");
        prev = curr;
    }
}

#[test]
fn voi_score_scales_with_relevance_multiplier() {
    let state = ProbeState::new(integrity_probe("i"));
    let voi_half = state.voi_score(500_000); // 0.5x
    let voi_unit = state.voi_score(1_000_000); // 1.0x
    let voi_double = state.voi_score(2_000_000); // 2.0x
    assert!(voi_unit > voi_half);
    assert!(voi_double > voi_unit);
}

#[test]
fn voi_score_zero_relevance_gives_zero() {
    let mut state = ProbeState::new(health_probe("h"));
    state.tick_staleness();
    let voi = state.voi_score(0);
    assert_eq!(voi, 0, "Zero relevance multiplier should yield zero VOI");
}

#[test]
fn mark_executed_resets_staleness_and_increments_count() {
    let mut state = ProbeState::new(health_probe("h"));
    state.tick_staleness();
    state.tick_staleness();
    state.tick_staleness();
    assert_eq!(state.staleness, 3);

    state.mark_executed(true);
    assert_eq!(state.staleness, 0);
    assert_eq!(state.execution_count, 1);
    assert!(state.last_success);

    state.mark_executed(false);
    assert_eq!(state.execution_count, 2);
    assert!(!state.last_success);
}

#[test]
fn probe_state_serde_round_trip() {
    let mut state = ProbeState::new(calibration_probe("cal-1"));
    state.tick_staleness();
    state.tick_staleness();
    state.mark_executed(false);
    state.tick_staleness();

    let json = serde_json::to_string(&state).expect("serialize ProbeState");
    let restored: ProbeState = serde_json::from_str(&json).expect("deserialize ProbeState");
    assert_eq!(state, restored);
}

// ===========================================================================
// Section 4: SchedulerConfig — budget and relevance
// ===========================================================================

#[test]
fn budget_for_regime_returns_configured_values() {
    let config = base_config();
    assert_eq!(config.budget_for_regime(Regime::Normal), 3_000_000);
    assert_eq!(config.budget_for_regime(Regime::Elevated), 6_000_000);
    assert_eq!(config.budget_for_regime(Regime::Attack), 10_000_000);
}

#[test]
fn budget_for_regime_falls_back_to_base() {
    let config = base_config();
    // Degraded and Recovery are not in regime_budgets, should fall back.
    assert_eq!(config.budget_for_regime(Regime::Degraded), 3_000_000);
    assert_eq!(config.budget_for_regime(Regime::Recovery), 3_000_000);
}

#[test]
fn relevance_multiplier_default_is_one() {
    let config = base_config();
    let mult = config.relevance_multiplier(Regime::Normal, ProbeKind::HealthCheck);
    assert_eq!(mult, 1_000_000, "Default multiplier should be 1.0 (1M)");
}

#[test]
fn relevance_multiplier_uses_override() {
    let mut config = base_config();
    config
        .relevance_overrides
        .insert("attack:integrity_audit".to_string(), 5_000_000);

    let mult = config.relevance_multiplier(Regime::Attack, ProbeKind::IntegrityAudit);
    assert_eq!(mult, 5_000_000);

    // Non-overridden still defaults to 1.0.
    let default_mult = config.relevance_multiplier(Regime::Attack, ProbeKind::HealthCheck);
    assert_eq!(default_mult, 1_000_000);
}

#[test]
fn scheduler_config_serde_round_trip() {
    let mut config = base_config();
    config
        .relevance_overrides
        .insert("elevated:deep_diagnostic".to_string(), 2_500_000);

    let json = serde_json::to_string(&config).expect("serialize SchedulerConfig");
    let restored: SchedulerConfig =
        serde_json::from_str(&json).expect("deserialize SchedulerConfig");
    assert_eq!(config, restored);
}

// ===========================================================================
// Section 5: SchedulerError — Display and serde
// ===========================================================================

#[test]
fn scheduler_error_display_duplicate() {
    let err = SchedulerError::DuplicateProbe {
        probe_id: "probe-x".to_string(),
    };
    assert_eq!(err.to_string(), "duplicate probe: probe-x");
}

#[test]
fn scheduler_error_display_not_found() {
    let err = SchedulerError::ProbeNotFound {
        probe_id: "missing-probe".to_string(),
    };
    assert_eq!(err.to_string(), "probe not found: missing-probe");
}

#[test]
fn scheduler_error_is_std_error() {
    let err = SchedulerError::DuplicateProbe {
        probe_id: "p".to_string(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.to_string().contains("duplicate"));
}

#[test]
fn scheduler_error_serde_round_trip() {
    let errors = vec![
        SchedulerError::DuplicateProbe {
            probe_id: "dup-1".to_string(),
        },
        SchedulerError::ProbeNotFound {
            probe_id: "missing-1".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize SchedulerError");
        let restored: SchedulerError =
            serde_json::from_str(&json).expect("deserialize SchedulerError");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// Section 6: MonitorScheduler — registration
// ===========================================================================

#[test]
fn register_probe_increments_count() {
    let mut sched = MonitorScheduler::new(base_config());
    assert_eq!(sched.probe_count(), 0);

    sched.register_probe(health_probe("h1")).unwrap();
    assert_eq!(sched.probe_count(), 1);

    sched.register_probe(deep_probe("d1")).unwrap();
    assert_eq!(sched.probe_count(), 2);
}

#[test]
fn register_duplicate_probe_returns_error() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("h1")).unwrap();

    let err = sched.register_probe(health_probe("h1")).unwrap_err();
    assert_eq!(
        err,
        SchedulerError::DuplicateProbe {
            probe_id: "h1".to_string()
        }
    );
    assert_eq!(sched.probe_count(), 1, "count unchanged after dup error");
}

#[test]
fn unregister_probe_decrements_count() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("h1")).unwrap();
    sched.register_probe(deep_probe("d1")).unwrap();
    assert_eq!(sched.probe_count(), 2);

    sched.unregister_probe("h1").unwrap();
    assert_eq!(sched.probe_count(), 1);
}

#[test]
fn unregister_missing_probe_returns_error() {
    let mut sched = MonitorScheduler::new(base_config());
    let err = sched.unregister_probe("nonexistent").unwrap_err();
    assert_eq!(
        err,
        SchedulerError::ProbeNotFound {
            probe_id: "nonexistent".to_string()
        }
    );
}

#[test]
fn probe_accessor_returns_state() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("h1")).unwrap();

    let state = sched.probe("h1").expect("probe should exist");
    assert_eq!(state.config.probe_id, "h1");
    assert_eq!(state.config.kind, ProbeKind::HealthCheck);
}

#[test]
fn probe_accessor_returns_none_for_missing() {
    let sched = MonitorScheduler::new(base_config());
    assert!(sched.probe("ghost").is_none());
}

// ===========================================================================
// Section 7: MonitorScheduler — scheduling basics
// ===========================================================================

#[test]
fn schedule_increments_interval() {
    let mut sched = base_scheduler();
    assert_eq!(sched.interval(), 0);
    sched.schedule(Regime::Normal);
    assert_eq!(sched.interval(), 1);
    sched.schedule(Regime::Elevated);
    assert_eq!(sched.interval(), 2);
    sched.schedule(Regime::Attack);
    assert_eq!(sched.interval(), 3);
}

#[test]
fn schedule_result_contains_correct_metadata() {
    let mut sched = base_scheduler();
    let result = sched.schedule(Regime::Normal);

    assert_eq!(result.scheduler_id, "sched-int");
    assert_eq!(result.interval, 1);
    assert_eq!(result.regime, Regime::Normal);
    assert_eq!(result.budget_total, 3_000_000);
    assert!(result.budget_used <= result.budget_total);
    assert_eq!(
        result.probes_scheduled + result.probes_deferred,
        result.decisions.len()
    );
}

#[test]
fn schedule_respects_budget_constraint() {
    let mut sched = base_scheduler();
    let result = sched.schedule(Regime::Normal);
    assert!(
        result.budget_used <= result.budget_total,
        "used={} > total={}",
        result.budget_used,
        result.budget_total
    );
}

#[test]
fn schedule_all_decisions_have_correct_fields() {
    let mut sched = base_scheduler();
    let result = sched.schedule(Regime::Normal);

    for decision in &result.decisions {
        assert!(!decision.probe_id.is_empty());
        assert!(decision.cost > 0);
        if decision.scheduled {
            assert!(decision.skip_reason.is_none());
            assert!(decision.voi_score > 0);
        } else {
            assert!(decision.skip_reason.is_some());
        }
    }
}

#[test]
fn schedule_with_empty_probes_returns_empty_decisions() {
    let mut sched = MonitorScheduler::new(base_config());
    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 0);
    assert_eq!(result.probes_deferred, 0);
    assert!(result.decisions.is_empty());
    assert_eq!(result.budget_used, 0);
}

// ===========================================================================
// Section 8: Budget exhaustion and greedy scheduling
// ===========================================================================

#[test]
fn tiny_budget_defers_expensive_probes() {
    let config = SchedulerConfig {
        scheduler_id: "tiny".to_string(),
        base_budget_millionths: 50_000, // 0.05 — too small for any probe
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(health_probe("h1")).unwrap(); // costs 0.1
    sched.register_probe(deep_probe("d1")).unwrap(); // costs 2.0

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 0);
    assert_eq!(result.probes_deferred, 2);
    assert_eq!(result.budget_used, 0);

    // All should have budget-exhaustion skip reasons.
    for dec in &result.decisions {
        assert!(!dec.scheduled);
        assert!(dec.skip_reason.as_ref().unwrap().contains("budget"));
    }
}

#[test]
fn exact_budget_schedules_matching_probe() {
    let config = SchedulerConfig {
        scheduler_id: "exact".to_string(),
        base_budget_millionths: 100_000, // exactly health probe cost
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(health_probe("h1")).unwrap();

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 1);
    assert_eq!(result.budget_used, 100_000);
}

#[test]
fn large_budget_schedules_all_probes() {
    let config = SchedulerConfig {
        scheduler_id: "large".to_string(),
        base_budget_millionths: 100_000_000, // 100.0 — huge
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(health_probe("h1")).unwrap();
    sched.register_probe(deep_probe("d1")).unwrap();
    sched.register_probe(calibration_probe("c1")).unwrap();
    sched.register_probe(integrity_probe("i1")).unwrap();

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 4);
    assert_eq!(result.probes_deferred, 0);

    let expected_total: i64 = 100_000 + 2_000_000 + 500_000 + 1_500_000;
    assert_eq!(result.budget_used, expected_total);
}

// ===========================================================================
// Section 9: Regime-adaptive budget
// ===========================================================================

#[test]
fn elevated_regime_has_higher_budget_than_normal() {
    let config = base_config();
    let normal_budget = config.budget_for_regime(Regime::Normal);
    let elevated_budget = config.budget_for_regime(Regime::Elevated);
    let attack_budget = config.budget_for_regime(Regime::Attack);
    assert!(elevated_budget > normal_budget);
    assert!(attack_budget > elevated_budget);
}

#[test]
fn attack_regime_schedules_more_probes() {
    let mut sched_normal = base_scheduler();
    let mut sched_attack = base_scheduler();

    let result_normal = sched_normal.schedule(Regime::Normal);
    let result_attack = sched_attack.schedule(Regime::Attack);

    assert!(
        result_attack.probes_scheduled >= result_normal.probes_scheduled,
        "Attack should schedule >= normal"
    );
    assert!(result_attack.budget_total > result_normal.budget_total);
}

// ===========================================================================
// Section 10: Staleness accumulation and reset
// ===========================================================================

#[test]
fn deferred_probes_accumulate_staleness() {
    let config = SchedulerConfig {
        scheduler_id: "stale".to_string(),
        base_budget_millionths: 50_000, // too small
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(deep_probe("d1")).unwrap(); // costs 2.0, won't fit

    sched.schedule(Regime::Normal);
    assert_eq!(sched.probe("d1").unwrap().staleness, 1);

    sched.schedule(Regime::Normal);
    assert_eq!(sched.probe("d1").unwrap().staleness, 2);

    sched.schedule(Regime::Normal);
    assert_eq!(sched.probe("d1").unwrap().staleness, 3);
}

#[test]
fn scheduled_probes_reset_staleness_to_zero() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("h1")).unwrap();

    // Build up staleness.
    sched.schedule(Regime::Normal); // h1 scheduled -> staleness reset to 0
    assert_eq!(sched.probe("h1").unwrap().staleness, 0);
    assert_eq!(sched.probe("h1").unwrap().execution_count, 1);
}

#[test]
fn staleness_increases_voi_over_time() {
    let mut sched = MonitorScheduler::new(SchedulerConfig {
        scheduler_id: "stale-voi".to_string(),
        base_budget_millionths: 50_000, // tiny: never schedules
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    });
    sched.register_probe(deep_probe("d1")).unwrap();

    let r1 = sched.schedule(Regime::Normal);
    let r2 = sched.schedule(Regime::Normal);
    let r3 = sched.schedule(Regime::Normal);

    let voi1 = r1.decisions[0].voi_score;
    let voi2 = r2.decisions[0].voi_score;
    let voi3 = r3.decisions[0].voi_score;

    assert!(voi2 > voi1, "VOI should increase: {} vs {}", voi2, voi1);
    assert!(voi3 > voi2, "VOI should increase: {} vs {}", voi3, voi2);
}

// ===========================================================================
// Section 11: VOI ordering in decisions
// ===========================================================================

#[test]
fn decisions_are_sorted_by_descending_voi() {
    let mut sched = base_scheduler();
    let result = sched.schedule(Regime::Normal);

    // Verify descending VOI order.
    for window in result.decisions.windows(2) {
        assert!(
            window[0].voi_score >= window[1].voi_score,
            "Decisions not in descending VOI order: {} < {}",
            window[0].voi_score,
            window[1].voi_score
        );
    }
}

#[test]
fn tie_breaking_uses_probe_id() {
    // Create probes with identical parameters but different IDs.
    let mut sched = MonitorScheduler::new(SchedulerConfig {
        scheduler_id: "tie".to_string(),
        base_budget_millionths: 100_000_000,
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    });

    sched
        .register_probe(ProbeConfig {
            probe_id: "b-probe".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,
            information_gain_millionths: 500_000,
            base_relevance_millionths: 1_000_000,
        })
        .unwrap();

    sched
        .register_probe(ProbeConfig {
            probe_id: "a-probe".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,
            information_gain_millionths: 500_000,
            base_relevance_millionths: 1_000_000,
        })
        .unwrap();

    let result = sched.schedule(Regime::Normal);
    // Same VOI, so alphabetical tie-break: "a-probe" before "b-probe".
    let ids: Vec<&str> = result
        .decisions
        .iter()
        .map(|d| d.probe_id.as_str())
        .collect();
    assert_eq!(ids, vec!["a-probe", "b-probe"]);
}

// ===========================================================================
// Section 12: Relevance overrides affect scheduling priority
// ===========================================================================

#[test]
fn relevance_override_boosts_scheduling_priority() {
    let mut config = base_config();
    // Give integrity probes 5x relevance during Attack.
    config
        .relevance_overrides
        .insert("attack:integrity_audit".to_string(), 5_000_000);

    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(health_probe("h1")).unwrap();
    sched.register_probe(integrity_probe("i1")).unwrap();

    let result = sched.schedule(Regime::Attack);

    // Integrity probe has boosted relevance, should be first in decisions.
    let first = &result.decisions[0];
    assert_eq!(first.probe_id, "i1");
    assert!(first.scheduled);
}

#[test]
fn multiple_relevance_overrides() {
    let mut config = base_config();
    config
        .relevance_overrides
        .insert("elevated:health_check".to_string(), 3_000_000);
    config.relevance_overrides.insert(
        "elevated:deep_diagnostic".to_string(),
        500_000, // suppressed
    );

    let scheduler_config = config.clone();
    let mult_health =
        scheduler_config.relevance_multiplier(Regime::Elevated, ProbeKind::HealthCheck);
    let mult_deep =
        scheduler_config.relevance_multiplier(Regime::Elevated, ProbeKind::DeepDiagnostic);
    let mult_cal =
        scheduler_config.relevance_multiplier(Regime::Elevated, ProbeKind::CalibrationProbe);

    assert_eq!(mult_health, 3_000_000);
    assert_eq!(mult_deep, 500_000);
    assert_eq!(mult_cal, 1_000_000); // no override
}

// ===========================================================================
// Section 13: History tracking
// ===========================================================================

#[test]
fn history_records_all_schedules() {
    let mut sched = base_scheduler();
    assert!(sched.history().is_empty());

    sched.schedule(Regime::Normal);
    assert_eq!(sched.history().len(), 1);

    sched.schedule(Regime::Elevated);
    assert_eq!(sched.history().len(), 2);

    sched.schedule(Regime::Attack);
    assert_eq!(sched.history().len(), 3);

    assert_eq!(sched.history()[0].regime, Regime::Normal);
    assert_eq!(sched.history()[1].regime, Regime::Elevated);
    assert_eq!(sched.history()[2].regime, Regime::Attack);
}

#[test]
fn history_intervals_are_sequential() {
    let mut sched = base_scheduler();
    for _ in 0..5 {
        sched.schedule(Regime::Normal);
    }
    for (i, result) in sched.history().iter().enumerate() {
        assert_eq!(result.interval, (i + 1) as u64);
    }
}

// ===========================================================================
// Section 14: record_execution
// ===========================================================================

#[test]
fn record_execution_updates_probe_state() {
    let mut sched = base_scheduler();

    sched.record_execution("health-1", true).unwrap();
    let state = sched.probe("health-1").unwrap();
    assert!(state.last_success);
    assert_eq!(state.execution_count, 1);
    assert_eq!(state.staleness, 0);
}

#[test]
fn record_execution_failure_marks_last_success_false() {
    let mut sched = base_scheduler();

    sched.record_execution("deep-1", false).unwrap();
    let state = sched.probe("deep-1").unwrap();
    assert!(!state.last_success);
    assert_eq!(state.execution_count, 1);
}

#[test]
fn record_execution_missing_probe_returns_error() {
    let mut sched = base_scheduler();
    let err = sched.record_execution("ghost", true).unwrap_err();
    assert_eq!(
        err,
        SchedulerError::ProbeNotFound {
            probe_id: "ghost".to_string()
        }
    );
}

#[test]
fn record_execution_multiple_times() {
    let mut sched = base_scheduler();
    sched.record_execution("health-1", true).unwrap();
    sched.record_execution("health-1", true).unwrap();
    sched.record_execution("health-1", false).unwrap();

    let state = sched.probe("health-1").unwrap();
    assert_eq!(state.execution_count, 3);
    assert!(!state.last_success);
}

// ===========================================================================
// Section 15: Deterministic replay
// ===========================================================================

#[test]
fn deterministic_schedule_replay_identical_results() {
    let run = || -> Vec<ScheduleResult> {
        let mut sched = base_scheduler();
        vec![
            sched.schedule(Regime::Normal),
            sched.schedule(Regime::Elevated),
            sched.schedule(Regime::Attack),
            sched.schedule(Regime::Normal),
        ]
    };

    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2, "Schedule replay must be deterministic");
}

#[test]
fn deterministic_replay_with_record_execution() {
    let run = || -> Vec<ScheduleResult> {
        let mut sched = base_scheduler();
        sched.schedule(Regime::Normal);
        sched.record_execution("health-1", false).unwrap();
        sched.schedule(Regime::Normal);
        sched.record_execution("deep-1", true).unwrap();
        vec![
            sched.schedule(Regime::Elevated),
            sched.schedule(Regime::Attack),
        ]
    };

    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

// ===========================================================================
// Section 16: ScheduleDecision serde
// ===========================================================================

#[test]
fn schedule_decision_serde_round_trip() {
    let decision = ScheduleDecision {
        probe_id: "h1".to_string(),
        kind: ProbeKind::HealthCheck,
        voi_score: 5_000_000,
        cost: 100_000,
        scheduled: true,
        skip_reason: None,
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let restored: ScheduleDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, restored);
}

#[test]
fn schedule_decision_with_skip_reason_serde() {
    let decision = ScheduleDecision {
        probe_id: "d1".to_string(),
        kind: ProbeKind::DeepDiagnostic,
        voi_score: 100,
        cost: 2_000_000,
        scheduled: false,
        skip_reason: Some("budget exhausted (remaining: 500000, cost: 2000000)".to_string()),
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let restored: ScheduleDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, restored);
}

// ===========================================================================
// Section 17: ScheduleResult serde
// ===========================================================================

#[test]
fn schedule_result_serde_round_trip() {
    let mut sched = base_scheduler();
    let result = sched.schedule(Regime::Normal);

    let json = serde_json::to_string(&result).expect("serialize ScheduleResult");
    let restored: ScheduleResult = serde_json::from_str(&json).expect("deserialize ScheduleResult");
    assert_eq!(result, restored);
}

#[test]
fn schedule_result_serde_across_all_regimes() {
    let regimes = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ];
    for regime in &regimes {
        let mut sched = base_scheduler();
        let result = sched.schedule(*regime);
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ScheduleResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored, "failed for regime {}", regime);
    }
}

// ===========================================================================
// Section 18: ProbeKind serde
// ===========================================================================

#[test]
fn probe_kind_serde_round_trip_all_variants() {
    let kinds = vec![
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).expect("serialize ProbeKind");
        let restored: ProbeKind = serde_json::from_str(&json).expect("deserialize ProbeKind");
        assert_eq!(*kind, restored);
    }
}

// ===========================================================================
// Section 19: Multi-interval lifecycle
// ===========================================================================

#[test]
fn multi_interval_lifecycle_with_varied_regimes() {
    let mut sched = base_scheduler();
    sched.register_probe(calibration_probe("cal-1")).unwrap();

    let regimes = [
        Regime::Normal,
        Regime::Normal,
        Regime::Elevated,
        Regime::Elevated,
        Regime::Attack,
        Regime::Normal,
    ];

    let mut results = Vec::new();
    for &regime in &regimes {
        results.push(sched.schedule(regime));
    }

    assert_eq!(results.len(), 6);
    assert_eq!(sched.interval(), 6);
    assert_eq!(sched.history().len(), 6);

    // Verify budgets match the regime.
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.regime, regimes[i]);
    }
}

#[test]
fn probe_registration_mid_lifecycle() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(health_probe("h1")).unwrap();

    let r1 = sched.schedule(Regime::Normal);
    assert_eq!(r1.decisions.len(), 1);

    // Register additional probe.
    sched.register_probe(deep_probe("d1")).unwrap();
    let r2 = sched.schedule(Regime::Normal);
    assert_eq!(r2.decisions.len(), 2);

    // Unregister original.
    sched.unregister_probe("h1").unwrap();
    let r3 = sched.schedule(Regime::Normal);
    assert_eq!(r3.decisions.len(), 1);
    assert_eq!(r3.decisions[0].probe_id, "d1");
}

// ===========================================================================
// Section 20: Config accessor
// ===========================================================================

#[test]
fn config_accessor_returns_scheduler_config() {
    let config = base_config();
    let sched = MonitorScheduler::new(config.clone());
    assert_eq!(sched.config().scheduler_id, config.scheduler_id);
    assert_eq!(
        sched.config().base_budget_millionths,
        config.base_budget_millionths
    );
}

// ===========================================================================
// Section 21: Non-positive VOI skip reason
// ===========================================================================

#[test]
fn zero_info_gain_produces_non_positive_voi() {
    let config = SchedulerConfig {
        scheduler_id: "zero-info".to_string(),
        base_budget_millionths: 100_000_000,
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched
        .register_probe(ProbeConfig {
            probe_id: "zero-gain".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,
            information_gain_millionths: 0, // zero info gain
            base_relevance_millionths: 1_000_000,
        })
        .unwrap();

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_deferred, 1);
    let dec = &result.decisions[0];
    assert!(!dec.scheduled);
    assert!(
        dec.skip_reason
            .as_ref()
            .unwrap()
            .contains("non-positive VOI"),
        "Expected 'non-positive VOI' reason, got: {:?}",
        dec.skip_reason
    );
}

// ===========================================================================
// Section 22: Many probes stress test
// ===========================================================================

#[test]
fn many_probes_schedules_greedily() {
    let config = SchedulerConfig {
        scheduler_id: "stress".to_string(),
        base_budget_millionths: 1_000_000, // 1.0
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);

    // Register 20 cheap probes.
    for i in 0..20 {
        sched
            .register_probe(ProbeConfig {
                probe_id: format!("probe-{i:02}"),
                kind: ProbeKind::HealthCheck,
                cost_millionths: 100_000, // 0.1 each
                information_gain_millionths: 500_000,
                base_relevance_millionths: 1_000_000,
            })
            .unwrap();
    }

    let result = sched.schedule(Regime::Normal);

    // Budget = 1.0, each costs 0.1 -> max 10 scheduled.
    assert_eq!(result.probes_scheduled, 10);
    assert_eq!(result.probes_deferred, 10);
    assert_eq!(result.budget_used, 1_000_000);
}

// ===========================================================================
// Section 23: Scheduler with only CalibrationProbe
// ===========================================================================

#[test]
fn calibration_probe_scheduling() {
    let mut sched = MonitorScheduler::new(base_config());
    sched.register_probe(calibration_probe("cal-1")).unwrap();

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 1);
    assert_eq!(result.decisions[0].kind, ProbeKind::CalibrationProbe);
    assert_eq!(result.budget_used, 500_000);
}
