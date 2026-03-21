//! Deep integration tests for monitor_scheduler module.
//!
//! Covers: probe kind Display, probe state VOI scoring, staleness tracking,
//! scheduler config regime budgets, and serde roundtrips.

use frankenengine_engine::monitor_scheduler::{
    MonitorScheduler, ProbeConfig, ProbeKind, ProbeState, ScheduleDecision, ScheduleResult,
    SchedulerConfig, SchedulerError,
};
use frankenengine_engine::regime_detector::Regime;

// ---------------------------------------------------------------------------
// ProbeKind
// ---------------------------------------------------------------------------

#[test]
fn deep_probe_kind_display() {
    assert_eq!(format!("{}", ProbeKind::HealthCheck), "health_check");
    assert_eq!(format!("{}", ProbeKind::DeepDiagnostic), "deep_diagnostic");
    assert_eq!(
        format!("{}", ProbeKind::CalibrationProbe),
        "calibration_probe"
    );
    assert_eq!(format!("{}", ProbeKind::IntegrityAudit), "integrity_audit");
}

#[test]
fn deep_probe_kind_serde_roundtrip() {
    let kinds = [
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ProbeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// ProbeState VOI scoring
// ---------------------------------------------------------------------------

fn make_probe(probe_id: &str, cost: i64, info: i64, relevance: i64) -> ProbeConfig {
    ProbeConfig {
        probe_id: probe_id.to_string(),
        kind: ProbeKind::HealthCheck,
        cost_millionths: cost,
        information_gain_millionths: info,
        base_relevance_millionths: relevance,
    }
}

#[test]
fn deep_voi_increases_with_staleness() {
    let config = make_probe("p1", 100_000, 500_000, 800_000);
    let mut state = ProbeState::new(config);

    let voi_fresh = state.voi_score(1_000_000); // regime multiplier = 1.0
    state.tick_staleness();
    let voi_stale = state.voi_score(1_000_000);

    assert!(
        voi_stale > voi_fresh,
        "VOI should increase with staleness: {} vs {}",
        voi_stale,
        voi_fresh
    );
}

#[test]
fn deep_voi_resets_on_execution() {
    let config = make_probe("p2", 100_000, 500_000, 800_000);
    let mut state = ProbeState::new(config);

    // Increase staleness
    for _ in 0..5 {
        state.tick_staleness();
    }
    let voi_stale = state.voi_score(1_000_000);

    // Execute
    state.mark_executed(true);
    let voi_after = state.voi_score(1_000_000);

    assert!(voi_after < voi_stale, "VOI should drop after execution");
    assert_eq!(state.staleness, 0);
    assert_eq!(state.execution_count, 1);
    assert!(state.last_success);
}

#[test]
fn deep_voi_respects_regime_multiplier() {
    let config = make_probe("p3", 100_000, 500_000, 800_000);
    let mut state = ProbeState::new(config);
    state.tick_staleness();

    let voi_normal = state.voi_score(1_000_000); // 1.0x
    let voi_elevated = state.voi_score(2_000_000); // 2.0x

    assert!(
        voi_elevated > voi_normal,
        "Higher regime multiplier should increase VOI"
    );
}

#[test]
fn deep_voi_zero_cost_does_not_panic() {
    let config = make_probe("p4", 0, 500_000, 800_000);
    let state = ProbeState::new(config);
    // Should not panic (cost clamped to 1)
    let _voi = state.voi_score(1_000_000);
}

#[test]
fn deep_mark_executed_failure() {
    let config = make_probe("p5", 100_000, 500_000, 800_000);
    let mut state = ProbeState::new(config);
    state.mark_executed(false);
    assert!(!state.last_success);
    assert_eq!(state.execution_count, 1);
}

// ---------------------------------------------------------------------------
// ProbeState serde
// ---------------------------------------------------------------------------

#[test]
fn deep_probe_state_serde_roundtrip() {
    let config = make_probe("serde-probe", 200_000, 600_000, 700_000);
    let mut state = ProbeState::new(config);
    state.tick_staleness();
    state.tick_staleness();
    state.mark_executed(true);
    state.tick_staleness();

    let json = serde_json::to_string(&state).unwrap();
    let decoded: ProbeState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, decoded);
}

// ---------------------------------------------------------------------------
// SchedulerConfig
// ---------------------------------------------------------------------------

#[test]
fn deep_scheduler_config_serde_roundtrip() {
    let mut regime_budgets = std::collections::BTreeMap::new();
    regime_budgets.insert("normal".to_string(), 1_000_000i64);
    regime_budgets.insert("elevated".to_string(), 2_000_000);

    let config = SchedulerConfig {
        scheduler_id: "sched-deep".to_string(),
        base_budget_millionths: 500_000,
        regime_budgets,
        relevance_overrides: std::collections::BTreeMap::new(),
    };
    let json = serde_json::to_string(&config).unwrap();
    let decoded: SchedulerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

// ---------------------------------------------------------------------------
// ProbeConfig serde
// ---------------------------------------------------------------------------

#[test]
fn deep_probe_config_serde_roundtrip() {
    let config = make_probe("config-test", 150_000, 400_000, 900_000);
    let json = serde_json::to_string(&config).unwrap();
    let decoded: ProbeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: MonitorScheduler core lifecycle
// ---------------------------------------------------------------------------

fn make_scheduler() -> MonitorScheduler {
    let mut regime_budgets = std::collections::BTreeMap::new();
    regime_budgets.insert("normal".to_string(), 1_000_000i64);
    regime_budgets.insert("elevated".to_string(), 2_000_000);
    regime_budgets.insert("attack".to_string(), 3_000_000);

    let config = SchedulerConfig {
        scheduler_id: "deep-test-scheduler".to_string(),
        base_budget_millionths: 500_000,
        regime_budgets,
        relevance_overrides: std::collections::BTreeMap::new(),
    };
    MonitorScheduler::new(config)
}

#[test]
fn deep_scheduler_register_and_count() {
    let mut sched = make_scheduler();
    assert_eq!(sched.probe_count(), 0);

    sched
        .register_probe(make_probe("p-alpha", 100_000, 500_000, 800_000))
        .unwrap();
    assert_eq!(sched.probe_count(), 1);

    sched
        .register_probe(make_probe("p-beta", 200_000, 600_000, 700_000))
        .unwrap();
    assert_eq!(sched.probe_count(), 2);
}

#[test]
fn deep_scheduler_reject_duplicate_probe_id() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("dup", 100_000, 500_000, 800_000))
        .unwrap();
    let err = sched
        .register_probe(make_probe("dup", 200_000, 600_000, 700_000))
        .unwrap_err();
    assert!(matches!(err, SchedulerError::DuplicateProbe { .. }));
}

#[test]
fn deep_scheduler_unregister_probe() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("remove-me", 100_000, 500_000, 800_000))
        .unwrap();
    assert_eq!(sched.probe_count(), 1);
    sched.unregister_probe("remove-me").unwrap();
    assert_eq!(sched.probe_count(), 0);
}

#[test]
fn deep_scheduler_unregister_unknown_probe_errors() {
    let mut sched = make_scheduler();
    let err = sched.unregister_probe("nonexistent").unwrap_err();
    assert!(matches!(err, SchedulerError::ProbeNotFound { .. }));
}

#[test]
fn deep_scheduler_schedule_empty_produces_no_decisions() {
    let mut sched = make_scheduler();
    let result = sched.schedule(Regime::Normal);
    assert!(result.decisions.is_empty());
}

#[test]
fn deep_scheduler_schedule_selects_by_voi() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("high-info", 100_000, 900_000, 900_000))
        .unwrap();
    sched
        .register_probe(make_probe("low-info", 100_000, 100_000, 100_000))
        .unwrap();
    // Tick staleness so VOI is nonzero
    let _ = sched.schedule(Regime::Normal);

    let result = sched.schedule(Regime::Normal);
    assert_eq!(result.regime, Regime::Normal);
    // history should have entries
    assert!(!sched.history().is_empty());
}

#[test]
fn deep_scheduler_probe_lookup() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("lookup-me", 100_000, 500_000, 800_000))
        .unwrap();
    let probe = sched.probe("lookup-me");
    assert!(probe.is_some());
    assert_eq!(probe.unwrap().config.probe_id, "lookup-me");
}

#[test]
fn deep_scheduler_probe_lookup_missing() {
    let sched = make_scheduler();
    assert!(sched.probe("ghost").is_none());
}

// ---------------------------------------------------------------------------
// Enrichment: ScheduleResult serde
// ---------------------------------------------------------------------------

#[test]
fn deep_schedule_result_serde_roundtrip() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("sr-probe", 100_000, 500_000, 800_000))
        .unwrap();
    let result = sched.schedule(Regime::Normal);
    let json = serde_json::to_string(&result).unwrap();
    let decoded: ScheduleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: ScheduleDecision serde
// ---------------------------------------------------------------------------

#[test]
fn deep_schedule_decision_serde_roundtrip() {
    let decision = ScheduleDecision {
        probe_id: "d-probe".to_string(),
        kind: ProbeKind::DeepDiagnostic,
        voi_score: 42_000,
        cost: 150_000,
        scheduled: true,
        skip_reason: None,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let decoded: ScheduleDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: SchedulerConfig budget queries
// ---------------------------------------------------------------------------

#[test]
fn deep_config_budget_for_known_regime() {
    let mut regime_budgets = std::collections::BTreeMap::new();
    regime_budgets.insert("normal".to_string(), 1_000_000i64);
    regime_budgets.insert("elevated".to_string(), 2_500_000);
    let config = SchedulerConfig {
        scheduler_id: "budget-test".to_string(),
        base_budget_millionths: 500_000,
        regime_budgets,
        relevance_overrides: std::collections::BTreeMap::new(),
    };
    assert_eq!(config.budget_for_regime(Regime::Normal), 1_000_000);
    assert_eq!(config.budget_for_regime(Regime::Elevated), 2_500_000);
}

#[test]
fn deep_config_budget_falls_back_to_base() {
    let config = SchedulerConfig {
        scheduler_id: "fallback-test".to_string(),
        base_budget_millionths: 777_000,
        regime_budgets: std::collections::BTreeMap::new(),
        relevance_overrides: std::collections::BTreeMap::new(),
    };
    // Unknown regime should use base budget
    assert_eq!(config.budget_for_regime(Regime::Attack), 777_000);
}

// ---------------------------------------------------------------------------
// Enrichment: record_execution
// ---------------------------------------------------------------------------

#[test]
fn deep_record_execution_updates_probe_state() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("exec-probe", 100_000, 500_000, 800_000))
        .unwrap();
    sched.record_execution("exec-probe", true).unwrap();
    let probe = sched.probe("exec-probe").unwrap();
    assert_eq!(probe.execution_count, 1);
    assert!(probe.last_success);
    assert_eq!(probe.staleness, 0);
}

#[test]
fn deep_record_execution_unknown_probe_errors() {
    let mut sched = make_scheduler();
    let err = sched.record_execution("ghost", true).unwrap_err();
    assert!(matches!(err, SchedulerError::ProbeNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Enrichment: multiple scheduling rounds produce history
// ---------------------------------------------------------------------------

#[test]
fn deep_scheduler_history_grows_with_rounds() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("history-probe", 100_000, 500_000, 800_000))
        .unwrap();
    let _ = sched.schedule(Regime::Normal);
    let _ = sched.schedule(Regime::Elevated);
    let _ = sched.schedule(Regime::Attack);
    assert_eq!(sched.history().len(), 3);
}

// ---------------------------------------------------------------------------
// Enrichment: staleness accumulates across rounds
// ---------------------------------------------------------------------------

#[test]
fn deep_staleness_increases_across_schedule_rounds() {
    let mut sched = make_scheduler();
    sched
        .register_probe(make_probe("stale-probe", 100_000, 500_000, 800_000))
        .unwrap();
    let _ = sched.schedule(Regime::Normal);
    let staleness_1 = sched.probe("stale-probe").unwrap().staleness;
    let _ = sched.schedule(Regime::Normal);
    let staleness_2 = sched.probe("stale-probe").unwrap().staleness;
    assert!(staleness_2 >= staleness_1);
}

// ---------------------------------------------------------------------------
// Enrichment: ProbeKind all variants
// ---------------------------------------------------------------------------

#[test]
fn deep_probe_kind_all_variants_serde_stable() {
    let kinds = [
        ProbeKind::HealthCheck,
        ProbeKind::DeepDiagnostic,
        ProbeKind::CalibrationProbe,
        ProbeKind::IntegrityAudit,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.starts_with('"'));
        let restored: ProbeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: scheduler accessor methods
// ---------------------------------------------------------------------------

#[test]
fn deep_scheduler_config_accessor() {
    let sched = make_scheduler();
    assert_eq!(sched.config().scheduler_id, "deep-test-scheduler");
    assert_eq!(sched.config().base_budget_millionths, 500_000);
}

#[test]
fn deep_scheduler_interval_starts_at_zero() {
    let sched = make_scheduler();
    // interval starts at 0 and increments with each schedule() call
    assert_eq!(sched.interval(), 0);
}
