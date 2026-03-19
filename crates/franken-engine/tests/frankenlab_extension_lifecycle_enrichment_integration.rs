#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `frankenlab_extension_lifecycle`.

use std::collections::BTreeSet;

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::frankenlab_extension_lifecycle::{
    ScenarioAssertion, ScenarioKind, ScenarioResult, ScenarioSuiteResult, run_all_scenarios,
    run_scenario,
};
use frankenengine_engine::lab_runtime::Verdict;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(42), MockBudget::new(budget_ms))
}

const ALL_SCENARIO_KINDS: [ScenarioKind; 7] = [
    ScenarioKind::Startup,
    ScenarioKind::NormalShutdown,
    ScenarioKind::ForcedCancel,
    ScenarioKind::Quarantine,
    ScenarioKind::Revocation,
    ScenarioKind::DegradedMode,
    ScenarioKind::MultiExtension,
];

// ---------------------------------------------------------------------------
// ScenarioKind — serde, display, ordering
// ---------------------------------------------------------------------------

#[test]
fn scenario_kind_serde_roundtrip_all() {
    for k in ALL_SCENARIO_KINDS {
        let json = serde_json::to_string(&k).unwrap();
        let back: ScenarioKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back, "roundtrip failed for {k}");
    }
}

#[test]
fn scenario_kind_display_distinctness() {
    let mut seen = BTreeSet::new();
    for k in ALL_SCENARIO_KINDS {
        assert!(seen.insert(format!("{k}")), "duplicate display for {k}");
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn scenario_kind_display_values() {
    assert_eq!(format!("{}", ScenarioKind::Startup), "startup");
    assert_eq!(format!("{}", ScenarioKind::NormalShutdown), "normal_shutdown");
    assert_eq!(format!("{}", ScenarioKind::ForcedCancel), "forced_cancel");
    assert_eq!(format!("{}", ScenarioKind::Quarantine), "quarantine");
    assert_eq!(format!("{}", ScenarioKind::Revocation), "revocation");
    assert_eq!(format!("{}", ScenarioKind::DegradedMode), "degraded_mode");
    assert_eq!(format!("{}", ScenarioKind::MultiExtension), "multi_extension");
}

#[test]
fn scenario_kind_ordering() {
    for pair in ALL_SCENARIO_KINDS.windows(2) {
        assert!(pair[0] < pair[1], "{} should be < {}", pair[0], pair[1]);
    }
}

#[test]
fn scenario_kind_clone_eq() {
    for k in ALL_SCENARIO_KINDS {
        let cloned = k;
        assert_eq!(k, cloned);
    }
}

// ---------------------------------------------------------------------------
// ScenarioAssertion — serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_assertion_serde_roundtrip_passed() {
    let a = ScenarioAssertion {
        description: "check state".into(),
        passed: true,
        detail: String::new(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn scenario_assertion_serde_roundtrip_failed() {
    let a = ScenarioAssertion {
        description: "check value".into(),
        passed: false,
        detail: "expected 1, got 2".into(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// ScenarioResult — serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_result_serde_roundtrip() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn scenario_result_fields_populated_after_run() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Startup, 42, &mut cx);
    assert_eq!(r.kind, ScenarioKind::Startup);
    assert_eq!(r.seed, 42);
    assert!(!r.assertions.is_empty());
    assert!(r.total_events_emitted > 0);
}

// ---------------------------------------------------------------------------
// ScenarioSuiteResult — serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_suite_result_serde_roundtrip() {
    let mut cx = mock_cx(10_000);
    let suite = run_all_scenarios(99, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    let back: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, back);
}

// ---------------------------------------------------------------------------
// run_scenario — individual scenario paths
// ---------------------------------------------------------------------------

#[test]
fn run_scenario_startup_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(r.passed, "startup scenario should pass");
    assert!(r.assertions.iter().all(|a| a.passed));
}

#[test]
fn run_scenario_normal_shutdown_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::NormalShutdown, 1, &mut cx);
    assert!(r.passed, "normal_shutdown scenario should pass");
}

#[test]
fn run_scenario_forced_cancel_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::ForcedCancel, 1, &mut cx);
    assert!(r.passed, "forced_cancel scenario should pass");
}

#[test]
fn run_scenario_quarantine_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Quarantine, 1, &mut cx);
    assert!(r.passed, "quarantine scenario should pass");
}

#[test]
fn run_scenario_revocation_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Revocation, 1, &mut cx);
    assert!(r.passed, "revocation scenario should pass");
}

#[test]
fn run_scenario_degraded_mode_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::DegradedMode, 1, &mut cx);
    assert!(r.passed, "degraded_mode scenario should pass");
}

#[test]
fn run_scenario_multi_extension_passes() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::MultiExtension, 1, &mut cx);
    assert!(r.passed, "multi_extension scenario should pass");
}

// ---------------------------------------------------------------------------
// run_all_scenarios
// ---------------------------------------------------------------------------

#[test]
fn run_all_scenarios_returns_seven() {
    let mut cx = mock_cx(10_000);
    let suite = run_all_scenarios(42, &mut cx);
    assert_eq!(suite.scenarios.len(), 7);
    assert_eq!(suite.seed, 42);
}

#[test]
fn run_all_scenarios_all_pass() {
    let mut cx = mock_cx(10_000);
    let suite = run_all_scenarios(42, &mut cx);
    assert_eq!(suite.verdict, Verdict::Pass);
    assert_eq!(suite.total_assertions, suite.passed_assertions);
}

#[test]
fn run_all_scenarios_deterministic() {
    let mut cx1 = mock_cx(10_000);
    let mut cx2 = mock_cx(10_000);
    let s1 = run_all_scenarios(99, &mut cx1);
    let s2 = run_all_scenarios(99, &mut cx2);
    assert_eq!(s1, s2, "identical seeds must produce identical results");
}

// ---------------------------------------------------------------------------
// Cross-scenario properties
// ---------------------------------------------------------------------------

#[test]
fn each_scenario_has_nonempty_assertions() {
    let mut cx = mock_cx(10_000);
    for kind in ALL_SCENARIO_KINDS {
        let r = run_scenario(kind, 1, &mut cx);
        assert!(!r.assertions.is_empty(), "{kind} should have at least one assertion");
    }
}

#[test]
fn each_scenario_emits_events() {
    let mut cx = mock_cx(10_000);
    for kind in ALL_SCENARIO_KINDS {
        let r = run_scenario(kind, 1, &mut cx);
        assert!(r.total_events_emitted > 0, "{kind} should emit events");
    }
}

#[test]
fn each_scenario_loads_at_least_one_extension() {
    let mut cx = mock_cx(10_000);
    for kind in ALL_SCENARIO_KINDS {
        let r = run_scenario(kind, 1, &mut cx);
        assert!(!r.extensions_loaded.is_empty(), "{kind} should load at least one extension");
    }
}

#[test]
fn startup_scenario_extension_is_running() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    // After startup scenario, at least one extension should still be marked running
    let has_running = r.final_states.values().any(|v| *v);
    assert!(has_running, "startup scenario should have a running extension");
}

#[test]
fn forced_cancel_scenario_no_running_extensions() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::ForcedCancel, 1, &mut cx);
    let any_running = r.final_states.values().any(|v| *v);
    assert!(!any_running, "forced_cancel should leave no running extensions");
}

#[test]
fn degraded_mode_scenario_no_running_extensions() {
    let mut cx = mock_cx(10_000);
    let r = run_scenario(ScenarioKind::DegradedMode, 1, &mut cx);
    let any_running = r.final_states.values().any(|v| *v);
    assert!(!any_running, "degraded_mode should leave no running extensions");
}

// ---------------------------------------------------------------------------
// Determinism per scenario
// ---------------------------------------------------------------------------

#[test]
fn startup_deterministic() {
    let mut cx1 = mock_cx(10_000);
    let mut cx2 = mock_cx(10_000);
    let r1 = run_scenario(ScenarioKind::Startup, 77, &mut cx1);
    let r2 = run_scenario(ScenarioKind::Startup, 77, &mut cx2);
    assert_eq!(r1, r2);
}

#[test]
fn quarantine_deterministic() {
    let mut cx1 = mock_cx(10_000);
    let mut cx2 = mock_cx(10_000);
    let r1 = run_scenario(ScenarioKind::Quarantine, 77, &mut cx1);
    let r2 = run_scenario(ScenarioKind::Quarantine, 77, &mut cx2);
    assert_eq!(r1, r2);
}
