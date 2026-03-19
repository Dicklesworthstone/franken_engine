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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
        cost_millionths: 100_000,
        information_gain_millionths: 500_000,
        base_relevance_millionths: 1_000_000,
    }
}

fn deep_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::DeepDiagnostic,
        cost_millionths: 2_000_000,
        information_gain_millionths: 3_000_000,
        base_relevance_millionths: 800_000,
    }
}

fn calibration_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::CalibrationProbe,
        cost_millionths: 500_000,
        information_gain_millionths: 1_500_000,
        base_relevance_millionths: 1_000_000,
    }
}

fn integrity_probe(id: &str) -> ProbeConfig {
    ProbeConfig {
        probe_id: id.to_string(),
        kind: ProbeKind::IntegrityAudit,
        cost_millionths: 1_500_000,
        information_gain_millionths: 2_000_000,
        base_relevance_millionths: 900_000,
    }
}

fn make_config(budget: i64) -> SchedulerConfig {
    let mut regime_budgets = BTreeMap::new();
    regime_budgets.insert("normal".to_string(), budget);
    regime_budgets.insert("elevated".to_string(), budget * 2);
    regime_budgets.insert("attack".to_string(), budget * 3);
    SchedulerConfig {
        scheduler_id: "test-sched".to_string(),
        base_budget_millionths: budget,
        regime_budgets,
        relevance_overrides: BTreeMap::new(),
    }
}

fn make_scheduler_with_all_kinds() -> MonitorScheduler {
    let mut sched = MonitorScheduler::new(make_config(10_000_000));
    sched.register_probe(health_probe("h1")).unwrap();
    sched.register_probe(deep_probe("d1")).unwrap();
    sched.register_probe(calibration_probe("c1")).unwrap();
    sched.register_probe(integrity_probe("i1")).unwrap();
    sched
}

// ---------------------------------------------------------------------------
// ProbeKind Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_probe_kind_display_uniqueness_all_four() {
    let kinds = [
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    let set: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_probe_kind_display_strings_are_snake_case() {
    let kinds = [
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    for kind in &kinds {
        let s = kind.to_string();
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_probe_kind_display_health_check() {
    assert_eq!(ProbeKind::HealthCheck.to_string(), "health_check");
}

#[test]
fn enrichment_probe_kind_display_deep_diagnostic() {
    assert_eq!(ProbeKind::DeepDiagnostic.to_string(), "deep_diagnostic");
}

#[test]
fn enrichment_probe_kind_display_calibration_probe() {
    assert_eq!(ProbeKind::CalibrationProbe.to_string(), "calibration_probe");
}

#[test]
fn enrichment_probe_kind_display_integrity_audit() {
    assert_eq!(ProbeKind::IntegrityAudit.to_string(), "integrity_audit");
}

// ---------------------------------------------------------------------------
// ProbeState::new() defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_probe_state_new_defaults_staleness_zero() {
    let state = ProbeState::new(health_probe("p1"));
    assert_eq!(state.staleness, 0);
}

#[test]
fn enrichment_probe_state_new_defaults_execution_count_zero() {
    let state = ProbeState::new(health_probe("p1"));
    assert_eq!(state.execution_count, 0);
}

#[test]
fn enrichment_probe_state_new_defaults_last_success_true() {
    let state = ProbeState::new(health_probe("p1"));
    assert!(state.last_success);
}

#[test]
fn enrichment_probe_state_new_preserves_config() {
    let cfg = calibration_probe("cal-1");
    let state = ProbeState::new(cfg.clone());
    assert_eq!(state.config.probe_id, "cal-1");
    assert_eq!(state.config.kind, ProbeKind::CalibrationProbe);
    assert_eq!(state.config.cost_millionths, cfg.cost_millionths);
    assert_eq!(
        state.config.information_gain_millionths,
        cfg.information_gain_millionths
    );
}

// ---------------------------------------------------------------------------
// voi_score() calculation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_voi_score_increases_with_staleness() {
    let mut state = ProbeState::new(health_probe("h"));
    let v0 = state.voi_score(1_000_000);
    state.tick_staleness();
    let v1 = state.voi_score(1_000_000);
    state.tick_staleness();
    let v2 = state.voi_score(1_000_000);
    assert!(v1 > v0);
    assert!(v2 > v1);
}

#[test]
fn enrichment_voi_score_scales_with_relevance_multiplier() {
    let state = ProbeState::new(deep_probe("d"));
    let low = state.voi_score(500_000);
    let high = state.voi_score(2_000_000);
    assert!(high > low);
}

#[test]
fn enrichment_voi_score_zero_info_gain_is_zero() {
    let cfg = ProbeConfig {
        probe_id: "zero-info".to_string(),
        kind: ProbeKind::HealthCheck,
        cost_millionths: 100_000,
        information_gain_millionths: 0,
        base_relevance_millionths: 1_000_000,
    };
    let state = ProbeState::new(cfg);
    assert_eq!(state.voi_score(1_000_000), 0);
}

#[test]
fn enrichment_voi_score_zero_cost_clamped_to_one() {
    let cfg = ProbeConfig {
        probe_id: "z".to_string(),
        kind: ProbeKind::HealthCheck,
        cost_millionths: 0,
        information_gain_millionths: 1_000_000,
        base_relevance_millionths: 1_000_000,
    };
    let state = ProbeState::new(cfg);
    let voi = state.voi_score(1_000_000);
    assert!(voi > 0);
}

#[test]
fn enrichment_voi_score_is_deterministic() {
    let state = ProbeState {
        config: integrity_probe("i"),
        staleness: 7,
        execution_count: 3,
        last_success: true,
    };
    let a = state.voi_score(1_500_000);
    let b = state.voi_score(1_500_000);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// mark_executed and tick_staleness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mark_executed_resets_staleness_and_increments_count() {
    let mut state = ProbeState::new(health_probe("h"));
    state.tick_staleness();
    state.tick_staleness();
    state.tick_staleness();
    assert_eq!(state.staleness, 3);
    state.mark_executed(true);
    assert_eq!(state.staleness, 0);
    assert_eq!(state.execution_count, 1);
    assert!(state.last_success);
}

#[test]
fn enrichment_mark_executed_failure_records_false() {
    let mut state = ProbeState::new(health_probe("h"));
    state.mark_executed(false);
    assert!(!state.last_success);
    assert_eq!(state.execution_count, 1);
}

// ---------------------------------------------------------------------------
// MonitorScheduler scheduling behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scheduler_register_and_probe_count() {
    let mut sched = MonitorScheduler::new(make_config(5_000_000));
    assert_eq!(sched.probe_count(), 0);
    sched.register_probe(health_probe("h1")).unwrap();
    assert_eq!(sched.probe_count(), 1);
    sched.register_probe(deep_probe("d1")).unwrap();
    assert_eq!(sched.probe_count(), 2);
}

#[test]
fn enrichment_scheduler_duplicate_probe_rejected() {
    let mut sched = MonitorScheduler::new(make_config(5_000_000));
    sched.register_probe(health_probe("h1")).unwrap();
    let err = sched.register_probe(health_probe("h1")).unwrap_err();
    assert_eq!(
        err,
        SchedulerError::DuplicateProbe {
            probe_id: "h1".to_string()
        }
    );
}

#[test]
fn enrichment_scheduler_unregister_and_reregister() {
    let mut sched = MonitorScheduler::new(make_config(5_000_000));
    sched.register_probe(health_probe("h1")).unwrap();
    sched.unregister_probe("h1").unwrap();
    assert_eq!(sched.probe_count(), 0);
    sched.register_probe(deep_probe("h1")).unwrap();
    assert_eq!(sched.probe_count(), 1);
}

#[test]
fn enrichment_scheduler_unregister_missing_fails() {
    let mut sched = MonitorScheduler::new(make_config(5_000_000));
    let err = sched.unregister_probe("nonexistent").unwrap_err();
    assert_eq!(
        err,
        SchedulerError::ProbeNotFound {
            probe_id: "nonexistent".to_string()
        }
    );
}

#[test]
fn enrichment_scheduler_schedule_respects_budget() {
    let mut sched = make_scheduler_with_all_kinds();
    let result = sched.schedule(Regime::Normal);
    assert!(result.budget_used <= result.budget_total);
}

#[test]
fn enrichment_scheduler_interval_increments() {
    let mut sched = make_scheduler_with_all_kinds();
    assert_eq!(sched.interval(), 0);
    sched.schedule(Regime::Normal);
    assert_eq!(sched.interval(), 1);
    sched.schedule(Regime::Attack);
    assert_eq!(sched.interval(), 2);
}

#[test]
fn enrichment_scheduler_history_accumulates() {
    let mut sched = make_scheduler_with_all_kinds();
    sched.schedule(Regime::Normal);
    sched.schedule(Regime::Elevated);
    sched.schedule(Regime::Attack);
    assert_eq!(sched.history().len(), 3);
    assert_eq!(sched.history()[0].regime, Regime::Normal);
    assert_eq!(sched.history()[1].regime, Regime::Elevated);
    assert_eq!(sched.history()[2].regime, Regime::Attack);
}

#[test]
fn enrichment_scheduler_elevated_regime_more_budget() {
    let config = make_config(3_000_000);
    let normal_budget = config.budget_for_regime(Regime::Normal);
    let elevated_budget = config.budget_for_regime(Regime::Elevated);
    assert!(elevated_budget > normal_budget);
}

#[test]
fn enrichment_scheduler_scheduled_plus_deferred_equals_total() {
    let mut sched = make_scheduler_with_all_kinds();
    let result = sched.schedule(Regime::Normal);
    assert_eq!(
        result.probes_scheduled + result.probes_deferred,
        result.decisions.len()
    );
}

#[test]
fn enrichment_scheduler_zero_budget_defers_all() {
    let config = SchedulerConfig {
        scheduler_id: "s".to_string(),
        base_budget_millionths: 0,
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(health_probe("h1")).unwrap();
    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.probes_scheduled, 0);
    assert_eq!(result.probes_deferred, 1);
}

#[test]
fn enrichment_scheduler_empty_no_decisions() {
    let mut sched = MonitorScheduler::new(make_config(5_000_000));
    let result = sched.schedule(Regime::Normal);
    assert!(result.decisions.is_empty());
    assert_eq!(result.probes_scheduled, 0);
}

#[test]
fn enrichment_scheduler_record_execution_updates_state() {
    let mut sched = make_scheduler_with_all_kinds();
    sched.record_execution("h1", false).unwrap();
    let state = sched.probe("h1").unwrap();
    assert!(!state.last_success);
    assert_eq!(state.execution_count, 1);
}

#[test]
fn enrichment_scheduler_record_execution_missing_fails() {
    let mut sched = make_scheduler_with_all_kinds();
    let err = sched.record_execution("nonexistent", true).unwrap_err();
    assert_eq!(
        err,
        SchedulerError::ProbeNotFound {
            probe_id: "nonexistent".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_probe_kind_serde_roundtrip_all_variants() {
    let kinds = [
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: ProbeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_probe_config_serde_roundtrip() {
    let cfg = calibration_probe("cal-rt");
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ProbeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn enrichment_probe_state_serde_roundtrip() {
    let state = ProbeState {
        config: integrity_probe("i-serde"),
        staleness: 10,
        execution_count: 5,
        last_success: false,
    };
    let json = serde_json::to_string(&state).unwrap();
    let restored: ProbeState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, restored);
}

#[test]
fn enrichment_scheduler_config_serde_roundtrip() {
    let config = make_config(5_000_000);
    let json = serde_json::to_string(&config).unwrap();
    let restored: SchedulerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_schedule_decision_serde_roundtrip() {
    let dec = ScheduleDecision {
        probe_id: "p-1".to_string(),
        kind: ProbeKind::DeepDiagnostic,
        voi_score: 2_500_000,
        cost: 2_000_000,
        scheduled: true,
        skip_reason: None,
    };
    let json = serde_json::to_string(&dec).unwrap();
    let restored: ScheduleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, restored);
}

#[test]
fn enrichment_schedule_decision_with_skip_reason_serde() {
    let dec = ScheduleDecision {
        probe_id: "p-skip".to_string(),
        kind: ProbeKind::IntegrityAudit,
        voi_score: 500_000,
        cost: 3_000_000,
        scheduled: false,
        skip_reason: Some("budget exhausted".to_string()),
    };
    let json = serde_json::to_string(&dec).unwrap();
    let restored: ScheduleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, restored);
}

#[test]
fn enrichment_schedule_result_serde_roundtrip() {
    let mut sched = make_scheduler_with_all_kinds();
    let result = sched.schedule(Regime::Normal);
    let json = serde_json::to_string(&result).unwrap();
    let restored: ScheduleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_scheduler_error_serde_roundtrip() {
    let errors = [
        SchedulerError::DuplicateProbe {
            probe_id: "dup".to_string(),
        },
        SchedulerError::ProbeNotFound {
            probe_id: "missing".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: SchedulerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// ---------------------------------------------------------------------------
// SchedulerError Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scheduler_error_display_uniqueness() {
    let errors = [
        SchedulerError::DuplicateProbe {
            probe_id: "a".to_string(),
        },
        SchedulerError::ProbeNotFound {
            probe_id: "b".to_string(),
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_scheduler_error_display_duplicate_contains_id() {
    let err = SchedulerError::DuplicateProbe {
        probe_id: "my-probe".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("my-probe"));
    assert!(msg.contains("duplicate"));
}

#[test]
fn enrichment_scheduler_error_display_not_found_contains_id() {
    let err = SchedulerError::ProbeNotFound {
        probe_id: "missing-probe".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing-probe"));
    assert!(msg.contains("not found"));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schedule_is_deterministic_across_runs() {
    let run = || -> Vec<ScheduleResult> {
        let mut sched = make_scheduler_with_all_kinds();
        vec![
            sched.schedule(Regime::Normal),
            sched.schedule(Regime::Elevated),
            sched.schedule(Regime::Attack),
        ]
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// Edge cases and additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_relevance_multiplier_default_is_one() {
    let config = make_config(5_000_000);
    let mult = config.relevance_multiplier(Regime::Normal, ProbeKind::HealthCheck);
    assert_eq!(mult, 1_000_000);
}

#[test]
fn enrichment_budget_for_unknown_regime_falls_back() {
    let config = make_config(3_000_000);
    let budget = config.budget_for_regime(Regime::Recovery);
    assert_eq!(budget, config.base_budget_millionths);
}

#[test]
fn enrichment_probe_query_missing_returns_none() {
    let sched = MonitorScheduler::new(make_config(5_000_000));
    assert!(sched.probe("nonexistent").is_none());
}

#[test]
fn enrichment_scheduler_config_accessor() {
    let config = make_config(4_000_000);
    let sched = MonitorScheduler::new(config.clone());
    assert_eq!(sched.config().scheduler_id, config.scheduler_id);
    assert_eq!(
        sched.config().base_budget_millionths,
        config.base_budget_millionths
    );
}

#[test]
fn enrichment_scheduler_staleness_accumulates_for_deferred() {
    let config = SchedulerConfig {
        scheduler_id: "s".to_string(),
        base_budget_millionths: 50_000,
        regime_budgets: BTreeMap::new(),
        relevance_overrides: BTreeMap::new(),
    };
    let mut sched = MonitorScheduler::new(config);
    sched.register_probe(deep_probe("d1")).unwrap();
    for expected in 1..=5u64 {
        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("d1").unwrap().staleness, expected);
    }
}

#[test]
fn enrichment_scheduler_result_scheduler_id_propagated() {
    let mut sched = make_scheduler_with_all_kinds();
    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.scheduler_id, "test-sched");
}
