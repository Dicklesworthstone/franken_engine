#![forbid(unsafe_code)]
//! Integration tests for the frankenlab_extension_lifecycle module.
//!
//! Covers ScenarioKind, ScenarioAssertion, ScenarioResult, ScenarioSuiteResult,
//! run_scenario, run_all_scenarios, extension lifecycle state machine transitions,
//! determinism, error paths, cross-concern integration, and serde round-trips.

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

use frankenengine_engine::cancellation_lifecycle::LifecycleEvent;
use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::extension_host_lifecycle::{
    ExtensionHostLifecycleManager, HostLifecycleError, HostLifecycleEvent,
};
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

// ===========================================================================
// ScenarioKind — Display
// ===========================================================================

#[test]
fn scenario_kind_display_startup() {
    assert_eq!(format!("{}", ScenarioKind::Startup), "startup");
}

#[test]
fn scenario_kind_display_normal_shutdown() {
    assert_eq!(
        format!("{}", ScenarioKind::NormalShutdown),
        "normal_shutdown"
    );
}

#[test]
fn scenario_kind_display_forced_cancel() {
    assert_eq!(format!("{}", ScenarioKind::ForcedCancel), "forced_cancel");
}

#[test]
fn scenario_kind_display_quarantine() {
    assert_eq!(format!("{}", ScenarioKind::Quarantine), "quarantine");
}

#[test]
fn scenario_kind_display_revocation() {
    assert_eq!(format!("{}", ScenarioKind::Revocation), "revocation");
}

#[test]
fn scenario_kind_display_degraded_mode() {
    assert_eq!(format!("{}", ScenarioKind::DegradedMode), "degraded_mode");
}

#[test]
fn scenario_kind_display_multi_extension() {
    assert_eq!(
        format!("{}", ScenarioKind::MultiExtension),
        "multi_extension"
    );
}

// ===========================================================================
// ScenarioKind — Ordering and Equality
// ===========================================================================

#[test]
fn scenario_kind_partial_ord_consistent() {
    // Startup should be less than NormalShutdown based on variant ordering
    assert!(ScenarioKind::Startup < ScenarioKind::NormalShutdown);
    assert!(ScenarioKind::NormalShutdown < ScenarioKind::ForcedCancel);
    assert!(ScenarioKind::ForcedCancel < ScenarioKind::Quarantine);
    assert!(ScenarioKind::Quarantine < ScenarioKind::Revocation);
    assert!(ScenarioKind::Revocation < ScenarioKind::DegradedMode);
    assert!(ScenarioKind::DegradedMode < ScenarioKind::MultiExtension);
}

#[test]
fn scenario_kind_eq_reflexive() {
    for kind in &ALL_SCENARIO_KINDS {
        assert_eq!(kind, kind);
    }
}

#[test]
fn scenario_kind_clone_eq() {
    for kind in &ALL_SCENARIO_KINDS {
        let cloned = *kind;
        assert_eq!(*kind, cloned);
    }
}

#[test]
fn scenario_kind_hash_deterministic() {
    use std::collections::BTreeSet;
    let set: BTreeSet<ScenarioKind> = ALL_SCENARIO_KINDS.iter().copied().collect();
    assert_eq!(set.len(), 7);
}

// ===========================================================================
// ScenarioKind — Serde round-trip
// ===========================================================================

#[test]
fn scenario_kind_serde_round_trip_all_variants() {
    for kind in &ALL_SCENARIO_KINDS {
        let json = serde_json::to_string(kind).unwrap();
        let restored: ScenarioKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn scenario_kind_serde_json_representation_is_string() {
    let json = serde_json::to_string(&ScenarioKind::Startup).unwrap();
    assert!(
        json.starts_with('"'),
        "ScenarioKind JSON should be a quoted string"
    );
    assert!(json.contains("Startup"));
}

// ===========================================================================
// ScenarioAssertion — Construction and Serde
// ===========================================================================

#[test]
fn scenario_assertion_construct_passing() {
    let assertion = ScenarioAssertion {
        description: "something passed".to_string(),
        passed: true,
        detail: String::new(),
    };
    assert!(assertion.passed);
    assert!(assertion.detail.is_empty());
    assert_eq!(assertion.description, "something passed");
}

#[test]
fn scenario_assertion_construct_failing() {
    let assertion = ScenarioAssertion {
        description: "something failed".to_string(),
        passed: false,
        detail: "expected X, got Y".to_string(),
    };
    assert!(!assertion.passed);
    assert!(!assertion.detail.is_empty());
}

#[test]
fn scenario_assertion_serde_round_trip_passing() {
    let assertion = ScenarioAssertion {
        description: "check value".to_string(),
        passed: true,
        detail: String::new(),
    };
    let json = serde_json::to_string(&assertion).unwrap();
    let restored: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(assertion, restored);
}

#[test]
fn scenario_assertion_serde_round_trip_failing() {
    let assertion = ScenarioAssertion {
        description: "check value".to_string(),
        passed: false,
        detail: "mismatch".to_string(),
    };
    let json = serde_json::to_string(&assertion).unwrap();
    let restored: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(assertion, restored);
}

#[test]
fn scenario_assertion_clone_eq() {
    let assertion = ScenarioAssertion {
        description: "test".to_string(),
        passed: true,
        detail: String::new(),
    };
    let cloned = assertion.clone();
    assert_eq!(assertion, cloned);
}

// ===========================================================================
// ScenarioResult — Construction and Fields
// ===========================================================================

#[test]
fn scenario_result_from_startup_has_correct_kind() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert_eq!(result.kind, ScenarioKind::Startup);
    assert_eq!(result.seed, 1);
}

#[test]
fn scenario_result_from_startup_has_assertions() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(
        !result.assertions.is_empty(),
        "startup should produce assertions"
    );
}

#[test]
fn scenario_result_startup_all_assertions_pass() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(result.passed);
    for assertion in &result.assertions {
        assert!(
            assertion.passed,
            "assertion failed: {} — {}",
            assertion.description, assertion.detail
        );
    }
}

#[test]
fn scenario_result_startup_extensions_loaded() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(!result.extensions_loaded.is_empty());
    assert!(
        result
            .extensions_loaded
            .contains(&"ext-startup-1".to_string())
    );
}

#[test]
fn scenario_result_startup_lifecycle_events_present() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(!result.lifecycle_events.is_empty());
    assert!(result.total_events_emitted > 0);
    assert_eq!(result.total_events_emitted, result.lifecycle_events.len());
}

#[test]
fn scenario_result_startup_extension_loaded_event() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(
        result
            .lifecycle_events
            .iter()
            .any(|e| e.event == "extension_loaded"),
        "startup should emit extension_loaded event"
    );
}

#[test]
fn scenario_result_serde_round_trip() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 42, &mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let restored: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// ScenarioResult — Final states
// ===========================================================================

#[test]
fn scenario_result_startup_has_final_states() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    // Startup loads one extension and leaves it running
    assert!(!result.final_states.is_empty());
    assert_eq!(
        result.final_states.get("ext-startup-1"),
        Some(&true),
        "ext-startup-1 should be running"
    );
}

#[test]
fn scenario_result_normal_shutdown_final_states() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
    assert_eq!(
        result.final_states.get("ext-ns-1"),
        Some(&false),
        "ext-ns-1 should be unloaded after shutdown"
    );
}

#[test]
fn scenario_result_multi_extension_final_states() {
    let mut cx = mock_cx(50000);
    let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
    assert_eq!(result.final_states.get("ext-m-0"), Some(&false));
    assert_eq!(result.final_states.get("ext-m-1"), Some(&false));
    assert_eq!(result.final_states.get("ext-m-2"), Some(&false));
    assert_eq!(result.final_states.get("ext-m-3"), Some(&true));
}

// ===========================================================================
// run_scenario — All scenario kinds pass
// ===========================================================================

#[test]
fn run_scenario_startup_passes() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(result.passed, "startup scenario failed: {result:#?}");
}

#[test]
fn run_scenario_normal_shutdown_passes() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
    assert!(
        result.passed,
        "normal_shutdown scenario failed: {result:#?}"
    );
}

#[test]
fn run_scenario_forced_cancel_passes() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
    assert!(result.passed, "forced_cancel scenario failed: {result:#?}");
}

#[test]
fn run_scenario_quarantine_passes() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
    assert!(result.passed, "quarantine scenario failed: {result:#?}");
}

#[test]
fn run_scenario_revocation_passes() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
    assert!(result.passed, "revocation scenario failed: {result:#?}");
}

#[test]
fn run_scenario_degraded_mode_passes() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
    assert!(result.passed, "degraded_mode scenario failed: {result:#?}");
}

#[test]
fn run_scenario_multi_extension_passes() {
    let mut cx = mock_cx(50000);
    let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
    assert!(
        result.passed,
        "multi_extension scenario failed: {result:#?}"
    );
}

// ===========================================================================
// run_scenario — Event content verification
// ===========================================================================

#[test]
fn startup_events_have_trace_id() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    for event in &result.lifecycle_events {
        assert!(
            !event.trace_id.is_empty(),
            "event {} should have non-empty trace_id",
            event.event
        );
    }
}

#[test]
fn normal_shutdown_includes_complete_event_trail() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
    let event_names: Vec<&str> = result
        .lifecycle_events
        .iter()
        .map(|e| e.event.as_str())
        .collect();
    assert!(event_names.contains(&"extension_loaded"));
    assert!(event_names.contains(&"session_created"));
    assert!(event_names.contains(&"session_closed"));
    assert!(event_names.contains(&"extension_unloaded"));
}

#[test]
fn forced_cancel_events_include_extension_loaded() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
    let event_names: Vec<&str> = result
        .lifecycle_events
        .iter()
        .map(|e| e.event.as_str())
        .collect();
    assert!(event_names.contains(&"extension_loaded"));
}

#[test]
fn quarantine_emits_quarantine_event() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
    let quarantine_events: Vec<_> = result
        .lifecycle_events
        .iter()
        .filter(|e| e.event == "extension_quarantine")
        .collect();
    assert!(
        !quarantine_events.is_empty(),
        "quarantine should emit extension_quarantine event"
    );
}

#[test]
fn quarantine_events_all_have_trace_id() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
    for event in &result.lifecycle_events {
        assert!(
            !event.trace_id.is_empty(),
            "quarantine event {} should have non-empty trace_id",
            event.event,
        );
    }
}

#[test]
fn revocation_leaves_zero_sessions() {
    let mut cx = mock_cx(10000);
    let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
    let session_check = result
        .assertions
        .iter()
        .find(|a| a.description.contains("session count"));
    assert!(
        session_check.is_some_and(|a| a.passed),
        "revocation should leave zero sessions"
    );
}

#[test]
fn degraded_mode_rejects_new_loads() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
    let load_rejected = result
        .assertions
        .iter()
        .find(|a| a.description.contains("load rejected"));
    assert!(
        load_rejected.is_some_and(|a| a.passed),
        "degraded mode should reject new loads"
    );
}

#[test]
fn degraded_mode_error_code_is_host_shutting_down() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
    let code_check = result
        .assertions
        .iter()
        .find(|a| a.description.contains("error code"));
    assert!(
        code_check.is_some_and(|a| a.passed),
        "error code should be host_shutting_down"
    );
}

#[test]
fn degraded_mode_all_assertions_pass() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
    for assertion in &result.assertions {
        assert!(
            assertion.passed,
            "degraded mode assertion failed: {} — {}",
            assertion.description, assertion.detail,
        );
    }
}

// ===========================================================================
// run_all_scenarios — Suite-level verification
// ===========================================================================

#[test]
fn full_suite_passes() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    assert_eq!(suite.verdict, Verdict::Pass);
    assert_eq!(suite.scenarios.len(), 7);
    assert_eq!(suite.passed_assertions, suite.total_assertions);
}

#[test]
fn full_suite_seed_is_propagated() {
    let seed = 12345;
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(seed, &mut cx);
    assert_eq!(suite.seed, seed);
    for scenario in &suite.scenarios {
        assert_eq!(scenario.seed, seed);
    }
}

#[test]
fn full_suite_covers_all_scenario_kinds() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    let kinds: Vec<ScenarioKind> = suite.scenarios.iter().map(|s| s.kind).collect();
    for expected in &ALL_SCENARIO_KINDS {
        assert!(
            kinds.contains(expected),
            "suite missing scenario kind: {expected}"
        );
    }
}

#[test]
fn full_suite_total_assertions_nonzero() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    assert!(suite.total_assertions > 0);
}

#[test]
fn full_suite_every_scenario_has_assertions() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    for scenario in &suite.scenarios {
        assert!(
            !scenario.assertions.is_empty(),
            "scenario {:?} has no assertions",
            scenario.kind
        );
    }
}

#[test]
fn full_suite_every_scenario_has_extensions_loaded() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    for scenario in &suite.scenarios {
        assert!(
            !scenario.extensions_loaded.is_empty(),
            "scenario {:?} loaded no extensions",
            scenario.kind
        );
    }
}

#[test]
fn full_suite_every_scenario_emits_lifecycle_events() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    for scenario in &suite.scenarios {
        assert!(
            scenario.total_events_emitted > 0,
            "scenario {:?} emitted no lifecycle events",
            scenario.kind,
        );
    }
}

// ===========================================================================
// ScenarioSuiteResult — Serde round-trip
// ===========================================================================

#[test]
fn scenario_suite_result_serde_round_trip() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    let restored: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, restored);
}

#[test]
fn scenario_suite_result_json_machine_readable() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(42, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["verdict"], "Pass");
    assert!(parsed["total_assertions"].as_u64().unwrap() > 0);
    assert_eq!(parsed["total_assertions"], parsed["passed_assertions"]);
    assert!(parsed["scenarios"].is_array());
    assert_eq!(parsed["scenarios"].as_array().unwrap().len(), 7);
}

#[test]
fn scenario_suite_result_json_contains_seed() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(777, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["seed"].as_u64().unwrap(), 777);
}

// ===========================================================================
// Determinism — Same inputs produce same outputs
// ===========================================================================

#[test]
fn determinism_same_seed_same_results() {
    let mut cx1 = mock_cx(100000);
    let suite1 = run_all_scenarios(99, &mut cx1);

    let mut cx2 = mock_cx(100000);
    let suite2 = run_all_scenarios(99, &mut cx2);

    assert_eq!(suite1.total_assertions, suite2.total_assertions);
    assert_eq!(suite1.passed_assertions, suite2.passed_assertions);
    assert_eq!(suite1.verdict, suite2.verdict);

    for (s1, s2) in suite1.scenarios.iter().zip(suite2.scenarios.iter()) {
        assert_eq!(s1.kind, s2.kind);
        assert_eq!(s1.passed, s2.passed);
        assert_eq!(s1.assertions.len(), s2.assertions.len());
        assert_eq!(s1.total_events_emitted, s2.total_events_emitted);
        assert_eq!(s1.extensions_loaded, s2.extensions_loaded);
    }
}

#[test]
fn determinism_assertions_identical_across_runs() {
    let mut cx1 = mock_cx(100000);
    let suite1 = run_all_scenarios(42, &mut cx1);

    let mut cx2 = mock_cx(100000);
    let suite2 = run_all_scenarios(42, &mut cx2);

    for (s1, s2) in suite1.scenarios.iter().zip(suite2.scenarios.iter()) {
        assert_eq!(
            s1.assertions, s2.assertions,
            "assertions differ for {:?}",
            s1.kind
        );
    }
}

#[test]
fn determinism_repeated_50_times() {
    let mut first_suite = None;
    for _ in 0..50 {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(77, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);

        if let Some(ref first) = first_suite {
            let f: &ScenarioSuiteResult = first;
            assert_eq!(f.total_assertions, suite.total_assertions);
            assert_eq!(f.passed_assertions, suite.passed_assertions);
            for (s1, s2) in f.scenarios.iter().zip(suite.scenarios.iter()) {
                assert_eq!(s1.kind, s2.kind);
                assert_eq!(s1.passed, s2.passed);
                assert_eq!(s1.assertions, s2.assertions);
                assert_eq!(s1.total_events_emitted, s2.total_events_emitted);
            }
        } else {
            first_suite = Some(suite);
        }
    }
}

#[test]
fn determinism_different_seeds_same_verdict() {
    for seed in [1, 42, 99, 255, 1000, 65535] {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(seed, &mut cx);
        assert_eq!(
            suite.verdict,
            Verdict::Pass,
            "suite with seed {seed} should pass"
        );
    }
}

#[test]
fn determinism_individual_scenarios_across_seeds() {
    for seed in [0, 1, u64::MAX] {
        for kind in &ALL_SCENARIO_KINDS {
            let mut cx = mock_cx(100000);
            let result = run_scenario(*kind, seed, &mut cx);
            assert!(
                result.passed,
                "scenario {:?} with seed {seed} should pass",
                kind
            );
        }
    }
}

// ===========================================================================
// Lifecycle state machine — Direct manager interactions
// ===========================================================================

#[test]
fn lifecycle_load_then_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    assert!(mgr.is_extension_running("ext-1"));
    assert_eq!(mgr.loaded_extension_count(), 1);

    let outcome = mgr.unload_extension("ext-1", &mut cx).unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-1"));
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn lifecycle_load_create_session_close_session() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "sess-a", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-1"), 1);

    mgr.close_session("ext-1", "sess-a", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-1"), 0);
}

#[test]
fn lifecycle_terminate_clears_sessions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-1"), 2);

    let outcome = mgr
        .cancel_extension("ext-1", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-1"));
    assert_eq!(mgr.session_count("ext-1"), 0);
}

#[test]
fn lifecycle_quarantine_stops_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s1", &mut cx).unwrap();

    let outcome = mgr
        .cancel_extension("ext-1", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-1"));
}

#[test]
fn lifecycle_revocation_stops_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-1", &mut cx, LifecycleEvent::Revocation)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-1"));
}

#[test]
fn lifecycle_shutdown_cancels_all() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.load_extension("ext-c", &mut cx).unwrap();

    let results = mgr.shutdown(&mut cx);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.is_ok());
    }
    assert!(mgr.is_shutting_down());
    assert_eq!(mgr.loaded_extension_count(), 0);
}

// ===========================================================================
// Error paths — HostLifecycleError coverage
// ===========================================================================

#[test]
fn error_load_duplicate_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    let err = mgr.load_extension("ext-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_already_loaded");
    assert!(err.to_string().contains("ext-1"));
}

#[test]
fn error_unload_missing_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    let err = mgr.unload_extension("missing", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
    assert!(err.to_string().contains("missing"));
}

#[test]
fn error_unload_already_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.unload_extension("ext-1", &mut cx).unwrap();
    let err = mgr.unload_extension("ext-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn error_create_session_on_missing_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    let err = mgr.create_session("missing", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn error_create_session_on_unloaded_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.unload_extension("ext-1", &mut cx).unwrap();
    let err = mgr.create_session("ext-1", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn error_create_duplicate_session() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s1", &mut cx).unwrap();
    let err = mgr.create_session("ext-1", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_session_already_exists");
}

#[test]
fn error_close_missing_session() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    let err = mgr.close_session("ext-1", "missing", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_session_not_found");
}

#[test]
fn error_load_during_shutdown() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.shutdown(&mut cx);

    let err = mgr.load_extension("ext-new", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");
    assert!(err.to_string().contains("shutting down"));
}

#[test]
fn error_create_session_during_shutdown() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.shutdown(&mut cx);

    let err = mgr.create_session("ext-1", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");
}

#[test]
fn error_cancel_missing_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    let err = mgr
        .cancel_extension("missing", &mut cx, LifecycleEvent::Terminate)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn error_cancel_already_unloaded_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.cancel_extension("ext-1", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    let err = mgr
        .cancel_extension("ext-1", &mut cx, LifecycleEvent::Terminate)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

// ===========================================================================
// HostLifecycleError — Display formatting
// ===========================================================================

#[test]
fn host_lifecycle_error_display_extension_already_loaded() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded {
        extension_id: "ext-x".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("already loaded"));
    assert!(display.contains("ext-x"));
}

#[test]
fn host_lifecycle_error_display_extension_not_found() {
    let err = HostLifecycleError::ExtensionNotFound {
        extension_id: "ext-y".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("not found"));
    assert!(display.contains("ext-y"));
}

#[test]
fn host_lifecycle_error_display_host_shutting_down() {
    let err = HostLifecycleError::HostShuttingDown;
    let display = err.to_string();
    assert!(display.contains("shutting down"));
}

#[test]
fn host_lifecycle_error_display_session_already_exists() {
    let err = HostLifecycleError::SessionAlreadyExists {
        extension_id: "ext-1".to_string(),
        session_id: "s1".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("already exists"));
    assert!(display.contains("s1"));
}

#[test]
fn host_lifecycle_error_display_session_not_found() {
    let err = HostLifecycleError::SessionNotFound {
        extension_id: "ext-1".to_string(),
        session_id: "s-missing".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("not found"));
    assert!(display.contains("s-missing"));
}

// ===========================================================================
// HostLifecycleError — Serde round-trip
// ===========================================================================

#[test]
fn host_lifecycle_error_serde_round_trip_all_variants() {
    use frankenengine_engine::region_lifecycle::RegionState;

    let variants: Vec<HostLifecycleError> = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "ext-a".to_string(),
        },
        HostLifecycleError::ExtensionNotFound {
            extension_id: "ext-b".to_string(),
        },
        HostLifecycleError::ExtensionNotRunning {
            extension_id: "ext-c".to_string(),
            state: RegionState::Closed,
        },
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "ext-d".to_string(),
            session_id: "s1".to_string(),
        },
        HostLifecycleError::SessionNotFound {
            extension_id: "ext-e".to_string(),
            session_id: "s2".to_string(),
        },
        HostLifecycleError::CellError {
            extension_id: "ext-f".to_string(),
            error_code: "cell_err".to_string(),
            message: "cell failed".to_string(),
        },
        HostLifecycleError::CancellationError {
            extension_id: "ext-g".to_string(),
            error_code: "cancel_err".to_string(),
            message: "cancel failed".to_string(),
        },
        HostLifecycleError::HostShuttingDown,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: HostLifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

// ===========================================================================
// HostLifecycleEvent — Construction and Serde
// ===========================================================================

#[test]
fn host_lifecycle_event_serde_round_trip() {
    let event = HostLifecycleEvent {
        trace_id: "trace-123".to_string(),
        extension_id: "ext-1".to_string(),
        session_id: Some("sess-1".to_string()),
        component: "extension_host_lifecycle".to_string(),
        event: "session_created".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn host_lifecycle_event_with_error_serde_round_trip() {
    let event = HostLifecycleEvent {
        trace_id: "trace-456".to_string(),
        extension_id: "ext-2".to_string(),
        session_id: None,
        component: "extension_host_lifecycle".to_string(),
        event: "extension_loaded".to_string(),
        outcome: "error".to_string(),
        error_code: Some("cell_err".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// Cross-concern: Evidence and Events
// ===========================================================================

#[test]
fn manager_events_record_load_and_session() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s1", &mut cx).unwrap();

    let events = mgr.events();
    assert!(events.len() >= 2);
    assert_eq!(events[0].event, "extension_loaded");
    assert_eq!(events[1].event, "session_created");
    assert_eq!(events[0].extension_id, "ext-1");
    assert_eq!(events[1].extension_id, "ext-1");
    assert_eq!(events[1].session_id, Some("s1".to_string()));
}

#[test]
fn drain_events_clears_event_list() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    assert!(!mgr.events().is_empty());

    let drained = mgr.drain_events();
    assert!(!drained.is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn manager_extension_record_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    let record = mgr.extension_record("ext-1").unwrap();
    assert!(!record.load_trace_id.is_empty());
    assert!(record.sessions.is_empty());
    assert!(!record.unloaded);
}

#[test]
fn manager_extension_ids_includes_all() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    let ids = mgr.extension_ids();
    assert!(ids.contains(&"ext-a"));
    assert!(ids.contains(&"ext-b"));
    assert_eq!(ids.len(), 2);
}

#[test]
fn manager_active_extension_ids_excludes_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    let active = mgr.active_extension_ids();
    assert!(!active.contains(&"ext-a"));
    assert!(active.contains(&"ext-b"));
    assert_eq!(active.len(), 1);

    // extension_ids still includes unloaded for audit trail
    let all = mgr.extension_ids();
    assert_eq!(all.len(), 2);
}

#[test]
fn manager_default_not_shutting_down() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(!mgr.is_shutting_down());
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn manager_session_count_for_missing_extension_is_zero() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert_eq!(mgr.session_count("nonexistent"), 0);
}

#[test]
fn manager_is_extension_running_false_for_missing() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(!mgr.is_extension_running("nonexistent"));
}

// ===========================================================================
// Cross-concern: Multi-extension isolation
// ===========================================================================

#[test]
fn isolation_cancel_one_does_not_affect_others() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    for i in 0..5 {
        mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
    }
    assert_eq!(mgr.loaded_extension_count(), 5);

    mgr.cancel_extension("ext-2", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();

    assert!(mgr.is_extension_running("ext-0"));
    assert!(mgr.is_extension_running("ext-1"));
    assert!(!mgr.is_extension_running("ext-2"));
    assert!(mgr.is_extension_running("ext-3"));
    assert!(mgr.is_extension_running("ext-4"));
    assert_eq!(mgr.loaded_extension_count(), 4);
}

#[test]
fn isolation_sessions_scoped_to_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    mgr.create_session("ext-b", "s3", &mut cx).unwrap();

    assert_eq!(mgr.session_count("ext-a"), 2);
    assert_eq!(mgr.session_count("ext-b"), 1);

    // Cancelling ext-a should not affect ext-b sessions
    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert_eq!(mgr.session_count("ext-a"), 0);
    assert_eq!(mgr.session_count("ext-b"), 1);
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn seed_zero_works() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(0, &mut cx);
    assert_eq!(suite.verdict, Verdict::Pass);
}

#[test]
fn seed_max_works() {
    let mut cx = mock_cx(100000);
    let suite = run_all_scenarios(u64::MAX, &mut cx);
    assert_eq!(suite.verdict, Verdict::Pass);
}

#[test]
fn individual_scenario_with_seed_zero() {
    for kind in &ALL_SCENARIO_KINDS {
        let mut cx = mock_cx(100000);
        let result = run_scenario(*kind, 0, &mut cx);
        assert!(result.passed, "scenario {:?} with seed 0 should pass", kind);
    }
}

#[test]
fn unload_extension_with_active_sessions_auto_closes_them() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s1", &mut cx).unwrap();
    mgr.create_session("ext-1", "s2", &mut cx).unwrap();
    mgr.create_session("ext-1", "s3", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-1"), 3);

    // Unload should close sessions automatically
    let outcome = mgr.unload_extension("ext-1", &mut cx).unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-1"));
}

#[test]
fn empty_manager_shutdown_returns_empty_results() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    let results = mgr.shutdown(&mut cx);
    assert!(results.is_empty());
    assert!(mgr.is_shutting_down());
}

#[test]
fn scenario_result_btree_map_final_states_ordered() {
    let mut cx = mock_cx(50000);
    let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
    let keys: Vec<&String> = result.final_states.keys().collect();
    // BTreeMap keys should be sorted
    for i in 1..keys.len() {
        assert!(
            keys[i - 1] <= keys[i],
            "final_states keys should be sorted: {} > {}",
            keys[i - 1],
            keys[i]
        );
    }
}

// ===========================================================================
// Verdict — Display
// ===========================================================================

#[test]
fn verdict_pass_display() {
    assert_eq!(format!("{}", Verdict::Pass), "PASS");
}

#[test]
fn verdict_fail_display() {
    let v = Verdict::Fail {
        reason: "2 of 10 assertions failed".to_string(),
    };
    let display = format!("{v}");
    assert!(display.contains("FAIL"));
    assert!(display.contains("2 of 10"));
}

#[test]
fn verdict_serde_round_trip_pass() {
    let v = Verdict::Pass;
    let json = serde_json::to_string(&v).unwrap();
    let restored: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn verdict_serde_round_trip_fail() {
    let v = Verdict::Fail {
        reason: "some reason".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ===========================================================================
// HostLifecycleError — error_code stability
// ===========================================================================

#[test]
fn host_lifecycle_error_code_stable_values() {
    assert_eq!(
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "x".to_string(),
        }
        .error_code(),
        "host_extension_already_loaded"
    );
    assert_eq!(
        HostLifecycleError::ExtensionNotFound {
            extension_id: "x".to_string(),
        }
        .error_code(),
        "host_extension_not_found"
    );
    assert_eq!(
        HostLifecycleError::HostShuttingDown.error_code(),
        "host_shutting_down"
    );
    assert_eq!(
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "x".to_string(),
            session_id: "s".to_string(),
        }
        .error_code(),
        "host_session_already_exists"
    );
    assert_eq!(
        HostLifecycleError::SessionNotFound {
            extension_id: "x".to_string(),
            session_id: "s".to_string(),
        }
        .error_code(),
        "host_session_not_found"
    );
    assert_eq!(
        HostLifecycleError::CellError {
            extension_id: "x".to_string(),
            error_code: "c".to_string(),
            message: "m".to_string(),
        }
        .error_code(),
        "host_cell_error"
    );
    assert_eq!(
        HostLifecycleError::CancellationError {
            extension_id: "x".to_string(),
            error_code: "c".to_string(),
            message: "m".to_string(),
        }
        .error_code(),
        "host_cancellation_error"
    );
}

// ===========================================================================
// Cross-concern: Scenario assertion counts
// ===========================================================================

#[test]
fn startup_scenario_has_at_least_6_assertions() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(
        result.assertions.len() >= 6,
        "startup should have >= 6 assertions, got {}",
        result.assertions.len()
    );
}

#[test]
fn normal_shutdown_scenario_has_at_least_8_assertions() {
    let mut cx = mock_cx(20000);
    let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
    assert!(
        result.assertions.len() >= 8,
        "normal_shutdown should have >= 8 assertions, got {}",
        result.assertions.len()
    );
}

#[test]
fn multi_extension_scenario_has_substantial_assertions() {
    let mut cx = mock_cx(50000);
    let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
    assert!(
        result.assertions.len() >= 10,
        "multi_extension should have >= 10 assertions, got {}",
        result.assertions.len()
    );
}

// ===========================================================================
// Cross-concern: Cancellation events via manager
// ===========================================================================

#[test]
fn manager_drain_cancellation_events() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    mgr.cancel_extension("ext-1", &mut cx, LifecycleEvent::Terminate)
        .unwrap();

    let cancel_events = mgr.drain_cancellation_events();
    assert!(!cancel_events.is_empty(), "cancellation should emit events");
}

#[test]
fn manager_cell_manager_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);

    mgr.load_extension("ext-1", &mut cx).unwrap();
    let cm = mgr.cell_manager();
    assert!(cm.active_count() >= 1);
}

// ===========================================================================
// ScenarioResult — JSON structure verification
// ===========================================================================

#[test]
fn scenario_result_json_has_expected_fields() {
    let mut cx = mock_cx(5000);
    let result = run_scenario(ScenarioKind::Startup, 42, &mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["kind"].is_string());
    assert!(parsed["seed"].is_u64());
    assert!(parsed["passed"].is_boolean());
    assert!(parsed["assertions"].is_array());
    assert!(parsed["lifecycle_events"].is_array());
    assert!(parsed["extensions_loaded"].is_array());
    assert!(parsed["final_states"].is_object());
    assert!(parsed["total_events_emitted"].is_u64());
}

#[test]
fn scenario_assertion_json_has_expected_fields() {
    let assertion = ScenarioAssertion {
        description: "test".to_string(),
        passed: true,
        detail: "".to_string(),
    };
    let json = serde_json::to_string(&assertion).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["description"].is_string());
    assert!(parsed["passed"].is_boolean());
    assert!(parsed["detail"].is_string());
}

// ===========================================================================
// Integration: lifecycle manager Default trait
// ===========================================================================

#[test]
fn extension_host_lifecycle_manager_default_equivalent_to_new() {
    let from_new = ExtensionHostLifecycleManager::new();
    let from_default = ExtensionHostLifecycleManager::default();

    assert!(!from_new.is_shutting_down());
    assert!(!from_default.is_shutting_down());
    assert_eq!(from_new.loaded_extension_count(), 0);
    assert_eq!(from_default.loaded_extension_count(), 0);
    assert!(from_new.events().is_empty());
    assert!(from_default.events().is_empty());
}
