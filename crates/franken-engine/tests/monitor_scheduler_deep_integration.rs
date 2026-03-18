//! Deep integration tests for monitor_scheduler module.
//!
//! Covers: probe kind Display, probe state VOI scoring, staleness tracking,
//! scheduler config regime budgets, and serde roundtrips.

use frankenengine_engine::monitor_scheduler::{
    ProbeConfig, ProbeKind, ProbeState, SchedulerConfig,
};

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
