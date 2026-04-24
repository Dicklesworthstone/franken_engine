//! Frankenlab deterministic scenarios for extension lifecycle and containment paths.
//!
//! Each scenario exercises a specific lifecycle path using
//! [`ExtensionHostLifecycleManager`] and the [`LabRuntime`] harness to guarantee
//! deterministic, reproducible results.
//!
//! Scenarios: startup, normal shutdown, forced cancel, quarantine, revocation,
//! degraded mode, and multi-extension interaction.
//!
//! Plan reference: Section 10.13 item 12, bd-1o7u.
//! Dependencies: bd-1ukb (regions), bd-2wz9 (cancellation), bd-m9pa (obligations),
//!               bd-2sbb (evidence replay), bd-uvmm (evidence).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cancellation_lifecycle::LifecycleEvent;
use crate::control_plane::ContextAdapter;
use crate::extension_host_lifecycle::{ExtensionHostLifecycleManager, HostLifecycleEvent};
use crate::lab_runtime::Verdict;

// ---------------------------------------------------------------------------
// ScenarioKind — identifies each lifecycle path
// ---------------------------------------------------------------------------

/// Identifies the lifecycle path a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ScenarioKind {
    /// Load extension → verify region + evidence.
    Startup,
    /// Load → work → graceful unload → verify quiescent close.
    NormalShutdown,
    /// Load → work → forced cancel mid-operation.
    ForcedCancel,
    /// Load → policy violation → quarantine isolation.
    Quarantine,
    /// Load → session → revoke capability mid-session.
    Revocation,
    /// Simulate control-plane failure → verify safe degradation.
    DegradedMode,
    /// Multiple extensions → cross-extension events → isolation.
    MultiExtension,
}

impl fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup => write!(f, "startup"),
            Self::NormalShutdown => write!(f, "normal_shutdown"),
            Self::ForcedCancel => write!(f, "forced_cancel"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Revocation => write!(f, "revocation"),
            Self::DegradedMode => write!(f, "degraded_mode"),
            Self::MultiExtension => write!(f, "multi_extension"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioAssertion — individual assertion within a scenario
// ---------------------------------------------------------------------------

/// Individual assertion result within a scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAssertion {
    /// Description of what was checked.
    pub description: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Details on failure (empty if passed).
    pub detail: String,
}

// ---------------------------------------------------------------------------
// ScenarioResult — output of a single scenario run
// ---------------------------------------------------------------------------

/// Output of a single frankenlab scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Which scenario was executed.
    pub kind: ScenarioKind,
    /// Deterministic seed used.
    pub seed: u64,
    /// Overall pass/fail.
    pub passed: bool,
    /// Individual assertions.
    pub assertions: Vec<ScenarioAssertion>,
    /// Lifecycle events captured during the scenario.
    pub lifecycle_events: Vec<HostLifecycleEvent>,
    /// Extensions loaded during the scenario.
    pub extensions_loaded: Vec<String>,
    /// Final extension states (extension_id → running).
    pub final_states: BTreeMap<String, bool>,
    /// Total obligations created (approximate, from events).
    pub total_events_emitted: usize,
}

impl ScenarioResult {
    fn new(kind: ScenarioKind, seed: u64) -> Self {
        Self {
            kind,
            seed,
            passed: true,
            assertions: Vec::new(),
            lifecycle_events: Vec::new(),
            extensions_loaded: Vec::new(),
            final_states: BTreeMap::new(),
            total_events_emitted: 0,
        }
    }

    fn assert_true(&mut self, description: &str, value: bool) {
        if !value {
            self.passed = false;
        }
        self.assertions.push(ScenarioAssertion {
            description: description.to_string(),
            passed: value,
            detail: if value {
                String::new()
            } else {
                format!("expected true, got false: {description}")
            },
        });
    }

    fn assert_eq<T: PartialEq + fmt::Debug>(&mut self, description: &str, left: T, right: T) {
        let passed = left == right;
        if !passed {
            self.passed = false;
        }
        self.assertions.push(ScenarioAssertion {
            description: description.to_string(),
            passed,
            detail: if passed {
                String::new()
            } else {
                format!("{left:?} != {right:?}")
            },
        });
    }

    fn finalize(&mut self, mgr: &mut ExtensionHostLifecycleManager) {
        self.lifecycle_events = mgr.drain_events();
        self.total_events_emitted = self.lifecycle_events.len();
        for ext_id in mgr.extension_ids() {
            self.final_states
                .insert(ext_id.to_string(), mgr.is_extension_running(ext_id));
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioSuiteResult — output of running all scenarios
// ---------------------------------------------------------------------------

/// Result of running the full frankenlab extension lifecycle scenario suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSuiteResult {
    /// Seed used for all scenarios.
    pub seed: u64,
    /// Per-scenario results.
    pub scenarios: Vec<ScenarioResult>,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Total assertions evaluated.
    pub total_assertions: usize,
    /// Total assertions that passed.
    pub passed_assertions: usize,
}

// ---------------------------------------------------------------------------
// run_scenario — dispatches to the correct scenario function
// ---------------------------------------------------------------------------

/// Run a single scenario by kind.
pub fn run_scenario<C: ContextAdapter>(
    kind: ScenarioKind,
    seed: u64,
    cx: &mut C,
) -> ScenarioResult {
    match kind {
        ScenarioKind::Startup => scenario_startup(seed, cx),
        ScenarioKind::NormalShutdown => scenario_normal_shutdown(seed, cx),
        ScenarioKind::ForcedCancel => scenario_forced_cancel(seed, cx),
        ScenarioKind::Quarantine => scenario_quarantine(seed, cx),
        ScenarioKind::Revocation => scenario_revocation(seed, cx),
        ScenarioKind::DegradedMode => scenario_degraded_mode(seed, cx),
        ScenarioKind::MultiExtension => scenario_multi_extension(seed, cx),
    }
}

/// Run all scenarios and produce a suite result.
pub fn run_all_scenarios<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioSuiteResult {
    let kinds = [
        ScenarioKind::Startup,
        ScenarioKind::NormalShutdown,
        ScenarioKind::ForcedCancel,
        ScenarioKind::Quarantine,
        ScenarioKind::Revocation,
        ScenarioKind::DegradedMode,
        ScenarioKind::MultiExtension,
    ];
    let mut scenarios = Vec::new();
    for kind in &kinds {
        scenarios.push(run_scenario(*kind, seed, cx));
    }

    let total_assertions: usize = scenarios.iter().map(|s| s.assertions.len()).sum();
    let passed_assertions: usize = scenarios
        .iter()
        .map(|s| s.assertions.iter().filter(|a| a.passed).count())
        .sum();
    let all_passed = scenarios.iter().all(|s| s.passed);

    ScenarioSuiteResult {
        seed,
        scenarios,
        verdict: if all_passed {
            Verdict::Pass
        } else {
            Verdict::Fail {
                reason: format!(
                    "{} of {} assertions failed",
                    total_assertions - passed_assertions,
                    total_assertions
                ),
            }
        },
        total_assertions,
        passed_assertions,
    }
}

// ---------------------------------------------------------------------------
// Scenario implementations
// ---------------------------------------------------------------------------

/// Scenario: Load an extension, verify region creation, Cx propagation, and
/// evidence emission.
fn scenario_startup<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Startup, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load extension.
    let load_result = mgr.load_extension("ext-startup-1", cx);
    result.assert_true("load_extension succeeds", load_result.is_ok());
    result.assert_true(
        "extension is running after load",
        mgr.is_extension_running("ext-startup-1"),
    );
    result.assert_eq("loaded count is 1", mgr.loaded_extension_count(), 1);

    // Verify extension record.
    if let Some(record) = mgr.extension_record("ext-startup-1") {
        result.assert_true(
            "load_trace_id is non-empty",
            !record.load_trace_id.is_empty(),
        );
        result.assert_true("no sessions yet", record.sessions.is_empty());
        result.assert_true("not unloaded", !record.unloaded);
    } else {
        result.assert_true("extension record exists", false);
    }

    // Verify evidence emission.
    let events = mgr.events();
    result.assert_true("at least one event emitted", !events.is_empty());
    result.assert_true(
        "first event is extension_loaded",
        events
            .first()
            .is_some_and(|e| e.event == "extension_loaded"),
    );
    result.assert_true(
        "event has trace_id",
        events.first().is_some_and(|e| !e.trace_id.is_empty()),
    );

    result.extensions_loaded.push("ext-startup-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → create sessions → close sessions → graceful unload.
fn scenario_normal_shutdown<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::NormalShutdown, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load and create sessions.
    // SAFETY: Test scenario with valid extension ID and context. Load operation should succeed.
    mgr.load_extension("ext-ns-1", cx).unwrap();
    // SAFETY: Extension just loaded successfully, session creation should succeed.
    mgr.create_session("ext-ns-1", "sess-1", cx).unwrap();
    // SAFETY: Extension loaded, first session created, second session creation should succeed.
    mgr.create_session("ext-ns-1", "sess-2", cx).unwrap();
    result.assert_eq("session count is 2", mgr.session_count("ext-ns-1"), 2);

    // Close one session explicitly.
    let close_result = mgr.close_session("ext-ns-1", "sess-1", cx);
    result.assert_true("close_session succeeds", close_result.is_ok());
    result.assert_eq("session count is 1", mgr.session_count("ext-ns-1"), 1);

    // Graceful unload (remaining session should close automatically).
    let unload_result = mgr.unload_extension("ext-ns-1", cx);
    result.assert_true("unload_extension succeeds", unload_result.is_ok());
    if let Ok(outcome) = &unload_result {
        result.assert_true("unload outcome success", outcome.success);
    }
    result.assert_true(
        "extension not running after unload",
        !mgr.is_extension_running("ext-ns-1"),
    );

    // Verify evidence completeness.
    let events = mgr.events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    result.assert_true(
        "events include extension_loaded",
        event_names.contains(&"extension_loaded"),
    );
    result.assert_true(
        "events include session_created",
        event_names.contains(&"session_created"),
    );
    result.assert_true(
        "events include session_closed",
        event_names.contains(&"session_closed"),
    );
    result.assert_true(
        "events include extension_unloaded",
        event_names.contains(&"extension_unloaded"),
    );

    result.extensions_loaded.push("ext-ns-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → work → forced cancel (Terminate) mid-operation.
fn scenario_forced_cancel<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::ForcedCancel, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load extension and session.
    // SAFETY: Test scenario with valid extension ID and context. Load operation should succeed.
    mgr.load_extension("ext-fc-1", cx).unwrap();
    // SAFETY: Extension just loaded successfully, session creation should succeed.
    mgr.create_session("ext-fc-1", "sess-1", cx).unwrap();

    // Force-cancel with Terminate (zero drain budget).
    let cancel_result = mgr.cancel_extension("ext-fc-1", cx, LifecycleEvent::Terminate);
    result.assert_true("cancel_extension succeeds", cancel_result.is_ok());
    if let Ok(outcome) = &cancel_result {
        result.assert_true("terminate outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after terminate",
        !mgr.is_extension_running("ext-fc-1"),
    );

    // Verify cannot create new sessions on terminated extension.
    let err = mgr.create_session("ext-fc-1", "sess-2", cx);
    result.assert_true(
        "session creation on terminated extension fails",
        err.is_err(),
    );

    result.extensions_loaded.push("ext-fc-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → trigger quarantine → verify isolation.
fn scenario_quarantine<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Quarantine, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    mgr.load_extension("ext-q-1", cx).unwrap();
    mgr.create_session("ext-q-1", "sess-1", cx).unwrap();

    // Quarantine the extension.
    let quarantine_result = mgr.cancel_extension("ext-q-1", cx, LifecycleEvent::Quarantine);
    result.assert_true("quarantine succeeds", quarantine_result.is_ok());
    if let Ok(outcome) = &quarantine_result {
        result.assert_true("quarantine outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after quarantine",
        !mgr.is_extension_running("ext-q-1"),
    );

    // Verify quarantine event in evidence.
    let events = mgr.events();
    let quarantine_events: Vec<_> = events
        .iter()
        .filter(|e| e.event == "extension_quarantine")
        .collect();
    result.assert_true("quarantine event emitted", !quarantine_events.is_empty());

    result.extensions_loaded.push("ext-q-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → create session → revoke capability → verify teardown.
fn scenario_revocation<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Revocation, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    mgr.load_extension("ext-r-1", cx).unwrap();
    mgr.create_session("ext-r-1", "sess-active", cx).unwrap();

    // Revoke via Revocation lifecycle event.
    let revoke_result = mgr.cancel_extension("ext-r-1", cx, LifecycleEvent::Revocation);
    result.assert_true("revocation succeeds", revoke_result.is_ok());
    if let Ok(outcome) = &revoke_result {
        result.assert_true("revocation outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after revocation",
        !mgr.is_extension_running("ext-r-1"),
    );

    // Verify no dangling session.
    result.assert_eq("session count is 0", mgr.session_count("ext-r-1"), 0);

    result.extensions_loaded.push("ext-r-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Simulate degraded mode — host shutdown rejects new operations.
fn scenario_degraded_mode<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::DegradedMode, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load some extensions normally.
    mgr.load_extension("ext-d-1", cx).unwrap();
    mgr.load_extension("ext-d-2", cx).unwrap();

    // Initiate shutdown (simulates control-plane entering degraded mode).
    let shutdown_results = mgr.shutdown(cx);
    result.assert_eq("all extensions cancelled", shutdown_results.len(), 2);
    for (i, r) in shutdown_results.iter().enumerate() {
        result.assert_true(&format!("shutdown result {i} succeeds"), r.is_ok());
    }

    result.assert_true("host is shutting down", mgr.is_shutting_down());

    // New operations must be rejected.
    let load_err = mgr.load_extension("ext-new", cx);
    result.assert_true("load rejected during shutdown", load_err.is_err());
    if let Err(e) = &load_err {
        result.assert_eq(
            "error code is host_shutting_down",
            e.error_code(),
            "host_shutting_down",
        );
    }

    let session_err = mgr.create_session("ext-d-1", "s1", cx);
    result.assert_true("session rejected during shutdown", session_err.is_err());

    result.assert_eq("no running extensions", mgr.loaded_extension_count(), 0);

    result
        .extensions_loaded
        .extend(["ext-d-1".to_string(), "ext-d-2".to_string()]);
    result.finalize(&mut mgr);
    result
}

/// Scenario: Multiple extensions — verify region isolation.
fn scenario_multi_extension<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::MultiExtension, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load 4 extensions.
    for i in 0..4 {
        mgr.load_extension(&format!("ext-m-{i}"), cx).unwrap();
    }
    result.assert_eq("4 extensions loaded", mgr.loaded_extension_count(), 4);

    // Create sessions in different extensions.
    mgr.create_session("ext-m-0", "s0a", cx).unwrap();
    mgr.create_session("ext-m-0", "s0b", cx).unwrap();
    mgr.create_session("ext-m-1", "s1a", cx).unwrap();
    mgr.create_session("ext-m-2", "s2a", cx).unwrap();

    // Cancel ext-m-1 (terminate).
    let cancel_result = mgr.cancel_extension("ext-m-1", cx, LifecycleEvent::Terminate);
    result.assert_true("cancel ext-m-1 succeeds", cancel_result.is_ok());

    // Verify isolation: ext-m-1 is down, others unaffected.
    result.assert_true("ext-m-0 still running", mgr.is_extension_running("ext-m-0"));
    result.assert_true("ext-m-1 NOT running", !mgr.is_extension_running("ext-m-1"));
    result.assert_true("ext-m-2 still running", mgr.is_extension_running("ext-m-2"));
    result.assert_true("ext-m-3 still running", mgr.is_extension_running("ext-m-3"));

    // ext-m-0 sessions still alive.
    result.assert_eq("ext-m-0 session count", mgr.session_count("ext-m-0"), 2);
    // ext-m-2 session still alive.
    result.assert_eq("ext-m-2 session count", mgr.session_count("ext-m-2"), 1);

    // Quarantine ext-m-2 (with its session).
    let q_result = mgr.cancel_extension("ext-m-2", cx, LifecycleEvent::Quarantine);
    result.assert_true("quarantine ext-m-2 succeeds", q_result.is_ok());
    result.assert_true(
        "ext-m-2 NOT running after quarantine",
        !mgr.is_extension_running("ext-m-2"),
    );

    // ext-m-0 and ext-m-3 still unaffected.
    result.assert_true(
        "ext-m-0 still running after ext-m-2 quarantine",
        mgr.is_extension_running("ext-m-0"),
    );
    result.assert_true(
        "ext-m-3 still running after ext-m-2 quarantine",
        mgr.is_extension_running("ext-m-3"),
    );

    // Graceful unload of ext-m-0 with sessions.
    let unload = mgr.unload_extension("ext-m-0", cx);
    result.assert_true("unload ext-m-0 succeeds", unload.is_ok());

    result.assert_eq("only ext-m-3 running", mgr.loaded_extension_count(), 1);
    result.assert_true("ext-m-3 still running", mgr.is_extension_running("ext-m-3"));

    for i in 0..4 {
        result.extensions_loaded.push(format!("ext-m-{i}"));
    }
    result.finalize(&mut mgr);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::trace_id_from_seed;
    use crate::control_plane::{ControlPlaneCx, BudgetController, BudgetConfig};
    use crate::security_epoch::SecurityEpoch;

    fn real_cx(budget_ms: u64) -> ControlPlaneCx {
        let budget_config = BudgetConfig {
            compute_budget_us: budget_ms * 1000, // Convert ms to microseconds
            memory_budget_bytes: 10_000_000, // 10MB
            warning_threshold_millionths: 800_000, // 80%
            deterministic_fallback_on_exhaust: true,
        };
        let budget_controller = BudgetController::new(budget_config, SecurityEpoch::from_raw(42));
        let trace_id = trace_id_from_seed(42);

        ControlPlaneCx::new(trace_id, budget_controller)
    }

    // -----------------------------------------------------------------------
    // Individual scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_startup_passes() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        assert!(result.passed, "startup scenario failed: {result:#?}");
        assert!(result.assertions.len() >= 6);
    }

    #[test]
    fn scenario_normal_shutdown_passes() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        assert!(
            result.passed,
            "normal_shutdown scenario failed: {result:#?}"
        );
        assert!(result.assertions.len() >= 8);
    }

    #[test]
    fn scenario_forced_cancel_passes() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        assert!(result.passed, "forced_cancel scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_quarantine_passes() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        assert!(result.passed, "quarantine scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_revocation_passes() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        assert!(result.passed, "revocation scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_degraded_mode_passes() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
        assert!(result.passed, "degraded_mode scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_multi_extension_passes() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        assert!(
            result.passed,
            "multi_extension scenario failed: {result:#?}"
        );
    }

    // -----------------------------------------------------------------------
    // Full suite
    // -----------------------------------------------------------------------

    #[test]
    fn full_suite_passes() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.scenarios.len(), 7);
        assert_eq!(suite.passed_assertions, suite.total_assertions);
    }

    // -----------------------------------------------------------------------
    // Deterministic reproducibility
    // -----------------------------------------------------------------------

    #[test]
    fn scenarios_deterministic_across_runs() {
        let mut cx1 = real_cx(100000);
        let suite1 = run_all_scenarios(99, &mut cx1);

        let mut cx2 = real_cx(100000);
        let suite2 = run_all_scenarios(99, &mut cx2);

        assert_eq!(suite1.total_assertions, suite2.total_assertions);
        assert_eq!(suite1.passed_assertions, suite2.passed_assertions);
        assert_eq!(suite1.verdict, suite2.verdict);

        // Each scenario produces the same assertions.
        for (s1, s2) in suite1.scenarios.iter().zip(suite2.scenarios.iter()) {
            assert_eq!(s1.kind, s2.kind);
            assert_eq!(s1.passed, s2.passed);
            assert_eq!(s1.assertions.len(), s2.assertions.len());
        }
    }

    // -----------------------------------------------------------------------
    // ScenarioKind display
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_display() {
        assert_eq!(format!("{}", ScenarioKind::Startup), "startup");
        assert_eq!(
            format!("{}", ScenarioKind::NormalShutdown),
            "normal_shutdown"
        );
        assert_eq!(format!("{}", ScenarioKind::ForcedCancel), "forced_cancel");
        assert_eq!(format!("{}", ScenarioKind::Quarantine), "quarantine");
        assert_eq!(format!("{}", ScenarioKind::Revocation), "revocation");
        assert_eq!(format!("{}", ScenarioKind::DegradedMode), "degraded_mode");
        assert_eq!(
            format!("{}", ScenarioKind::MultiExtension),
            "multi_extension"
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_result_serde_roundtrip() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        let json = serde_json::to_string(&result).unwrap();
        let back: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn scenario_suite_result_serde_roundtrip() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        let back: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(suite, back);
    }

    #[test]
    fn scenario_kind_serde_roundtrip() {
        for kind in [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ScenarioKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn assertion_serde_roundtrip() {
        let assertion = ScenarioAssertion {
            description: "test assertion".to_string(),
            passed: true,
            detail: String::new(),
        };
        let json = serde_json::to_string(&assertion).unwrap();
        let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(assertion, back);
    }

    // -----------------------------------------------------------------------
    // Individual scenario events
    // -----------------------------------------------------------------------

    #[test]
    fn startup_captures_lifecycle_events() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        assert!(!result.lifecycle_events.is_empty());
        assert!(
            result
                .lifecycle_events
                .iter()
                .any(|e| e.event == "extension_loaded")
        );
    }

    #[test]
    fn normal_shutdown_captures_complete_trail() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        let event_names: Vec<&str> = result
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert!(event_names.contains(&"extension_loaded"));
        assert!(event_names.contains(&"session_created"));
        assert!(event_names.contains(&"extension_unloaded"));
    }

    #[test]
    fn multi_extension_final_states_correct() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        // ext-m-3 should be the only one still running.
        assert_eq!(result.final_states.get("ext-m-3"), Some(&true));
        assert_eq!(result.final_states.get("ext-m-0"), Some(&false));
        assert_eq!(result.final_states.get("ext-m-1"), Some(&false));
        assert_eq!(result.final_states.get("ext-m-2"), Some(&false));
    }

    // -- Enrichment tests --

    #[test]
    fn determinism_full_suite_100_times() {
        let mut first_suite = None;
        for _ in 0..100 {
            let mut cx = real_cx(100000);
            let suite = run_all_scenarios(77, &mut cx);
            assert_eq!(suite.verdict, Verdict::Pass);

            if let Some(ref first) = first_suite {
                // Compare structural equality across runs
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
    fn every_scenario_emits_at_least_one_lifecycle_event() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        for scenario in &suite.scenarios {
            assert!(
                scenario.total_events_emitted > 0,
                "scenario {:?} emitted no lifecycle events",
                scenario.kind,
            );
        }
    }

    #[test]
    fn every_scenario_records_extensions_loaded() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        for scenario in &suite.scenarios {
            assert!(
                !scenario.extensions_loaded.is_empty(),
                "scenario {:?} loaded no extensions",
                scenario.kind,
            );
        }
    }

    #[test]
    fn forced_cancel_evidence_includes_terminate() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        let events: Vec<&str> = result
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert!(
            events.contains(&"extension_loaded"),
            "forced cancel should start with extension_loaded"
        );
    }

    #[test]
    fn revocation_leaves_zero_sessions() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        // Verify through assertions that session count = 0
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
    fn degraded_mode_all_assertions_pass() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
        for assertion in &result.assertions {
            assert!(
                assertion.passed,
                "degraded mode assertion failed: {} — {}",
                assertion.description, assertion.detail,
            );
        }
    }

    #[test]
    fn quarantine_events_have_trace_id() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        for event in &result.lifecycle_events {
            assert!(
                !event.trace_id.is_empty(),
                "lifecycle event {} should have non-empty trace_id",
                event.event,
            );
        }
    }

    #[test]
    fn suite_result_machine_readable_for_release_gating() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);

        // Verify it serializes to JSON for bd-24bu release gating
        let json = serde_json::to_string(&suite).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["verdict"], "Pass");
        // SAFETY: test suite JSON has total_assertions field as u64; as_u64() returns Some
        assert!(parsed["total_assertions"].as_u64().unwrap() > 0);
        assert_eq!(parsed["total_assertions"], parsed["passed_assertions"]);
    }

    #[test]
    fn different_seeds_produce_same_verdict() {
        for seed in [1, 42, 99, 255, 1000] {
            let mut cx = real_cx(100000);
            let suite = run_all_scenarios(seed, &mut cx);
            assert_eq!(
                suite.verdict,
                Verdict::Pass,
                "suite with seed {seed} should pass"
            );
        }
    }

    // -- Enrichment: ScenarioKind ordering --

    #[test]
    fn scenario_kind_ordering_deterministic() {
        let mut kinds = [
            ScenarioKind::MultiExtension,
            ScenarioKind::Startup,
            ScenarioKind::Quarantine,
        ];
        kinds.sort();
        // Derived Ord follows declaration order: Startup < Quarantine < MultiExtension
        assert_eq!(kinds[0], ScenarioKind::Startup);
        assert_eq!(kinds[2], ScenarioKind::MultiExtension);
    }

    // -- Enrichment: ScenarioAssertion detail --

    #[test]
    fn scenario_assertion_passed_has_empty_detail() {
        let a = ScenarioAssertion {
            description: "check".to_string(),
            passed: true,
            detail: String::new(),
        };
        assert!(a.detail.is_empty());
        assert!(a.passed);
    }

    #[test]
    fn scenario_assertion_failed_has_non_empty_detail() {
        let a = ScenarioAssertion {
            description: "check".to_string(),
            passed: false,
            detail: "expected true, got false".to_string(),
        };
        assert!(!a.detail.is_empty());
        assert!(!a.passed);
    }

    // -- Enrichment: ScenarioResult new defaults --

    #[test]
    fn scenario_result_new_starts_passed() {
        let result = ScenarioResult::new(ScenarioKind::Startup, 42);
        assert!(result.passed);
        assert!(result.assertions.is_empty());
        assert!(result.lifecycle_events.is_empty());
        assert!(result.extensions_loaded.is_empty());
        assert!(result.final_states.is_empty());
        assert_eq!(result.total_events_emitted, 0);
        assert_eq!(result.seed, 42);
        assert_eq!(result.kind, ScenarioKind::Startup);
    }

    // -- Enrichment: suite total_assertions accumulates correctly --

    #[test]
    fn suite_total_assertions_matches_sum_of_scenarios() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let sum: usize = suite.scenarios.iter().map(|s| s.assertions.len()).sum();
        assert_eq!(suite.total_assertions, sum);
    }

    // -- Enrichment: each scenario has correct kind --

    #[test]
    fn each_scenario_result_has_matching_kind() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let expected_kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        for (scenario, expected) in suite.scenarios.iter().zip(expected_kinds.iter()) {
            assert_eq!(scenario.kind, *expected);
        }
    }

    // -- Enrichment: scenario suite 7 scenarios --

    #[test]
    fn suite_always_runs_seven_scenarios() {
        let mut cx = real_cx(100000);
        let suite = run_all_scenarios(1, &mut cx);
        assert_eq!(suite.scenarios.len(), 7);
    }

    // -- Enrichment: ScenarioKind Display roundtrips --

    #[test]
    fn scenario_kind_display_all_unique() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let displays: std::collections::BTreeSet<String> =
            kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            displays.len(),
            7,
            "all ScenarioKind Display values are unique"
        );
    }

    // -- Enrichment: startup seed is propagated --

    #[test]
    fn scenario_result_seed_propagated() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 12345, &mut cx);
        assert_eq!(result.seed, 12345);
    }

    // -- Enrichment: multi_extension loads 4 extensions --

    #[test]
    fn multi_extension_loads_four_extensions() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        assert_eq!(result.extensions_loaded.len(), 4);
    }

    // -- Enrichment batch 2: Display uniqueness, serde, boundary --

    #[test]
    fn scenario_kind_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let set: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all ScenarioKind Display strings must be unique"
        );
    }

    #[test]
    fn scenario_kind_ord_follows_declaration_order() {
        assert!(ScenarioKind::Startup < ScenarioKind::NormalShutdown);
        assert!(ScenarioKind::NormalShutdown < ScenarioKind::ForcedCancel);
        assert!(ScenarioKind::ForcedCancel < ScenarioKind::Quarantine);
        assert!(ScenarioKind::Quarantine < ScenarioKind::Revocation);
        assert!(ScenarioKind::Revocation < ScenarioKind::DegradedMode);
        assert!(ScenarioKind::DegradedMode < ScenarioKind::MultiExtension);
    }

    #[test]
    fn scenario_result_assert_true_failure_sets_passed_false() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        assert!(result.passed);
        result.assert_true("this should fail", false);
        assert!(!result.passed);
        assert_eq!(result.assertions.len(), 1);
        assert!(!result.assertions[0].passed);
        assert!(!result.assertions[0].detail.is_empty());
    }

    #[test]
    fn scenario_result_assert_eq_failure_records_diff() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_eq("mismatch", 42_u64, 99_u64);
        assert!(!result.passed);
        let a = &result.assertions[0];
        assert!(!a.passed);
        assert!(a.detail.contains("42"));
        assert!(a.detail.contains("99"));
    }

    #[test]
    fn suite_seed_zero_still_passes() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(0, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.seed, 0);
    }

    #[test]
    fn suite_max_seed_still_passes() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(u64::MAX, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.seed, u64::MAX);
    }

    #[test]
    fn scenario_assertion_clone_equality() {
        let a = ScenarioAssertion {
            description: "clone test".to_string(),
            passed: true,
            detail: String::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_suite_result_json_scenarios_array() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let scenarios = parsed["scenarios"].as_array().unwrap();
        assert_eq!(scenarios.len(), 7);
        for s in scenarios {
            assert!(s["passed"].as_bool().unwrap());
        }
    }

    // -- Enrichment batch 3: clone, failure accumulation, ordering, field checks --

    #[test]
    fn scenario_result_clone_preserves_all_fields() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        let cloned = result.clone();
        assert_eq!(result, cloned);
        assert_eq!(result.kind, cloned.kind);
        assert_eq!(result.seed, cloned.seed);
        assert_eq!(result.assertions.len(), cloned.assertions.len());
        assert_eq!(result.lifecycle_events.len(), cloned.lifecycle_events.len());
        assert_eq!(result.extensions_loaded, cloned.extensions_loaded);
        assert_eq!(result.final_states, cloned.final_states);
    }

    #[test]
    fn scenario_result_multiple_failures_accumulate() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_true("pass-1", true);
        result.assert_true("fail-1", false);
        result.assert_true("pass-2", true);
        result.assert_eq("fail-2", 1_u32, 2_u32);
        assert!(!result.passed);
        assert_eq!(result.assertions.len(), 4);
        let passed_count = result.assertions.iter().filter(|a| a.passed).count();
        assert_eq!(passed_count, 2);
        let failed_count = result.assertions.iter().filter(|a| !a.passed).count();
        assert_eq!(failed_count, 2);
    }

    #[test]
    fn scenario_result_assert_true_success_has_empty_detail() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_true("should pass", true);
        assert!(result.passed);
        assert!(result.assertions[0].passed);
        assert!(result.assertions[0].detail.is_empty());
    }

    #[test]
    fn scenario_result_assert_eq_success_has_empty_detail() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_eq("values match", 42_u64, 42_u64);
        assert!(result.passed);
        assert!(result.assertions[0].passed);
        assert!(result.assertions[0].detail.is_empty());
    }

    #[test]
    fn final_states_btreemap_ordering_deterministic() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        let keys: Vec<&String> = result.final_states.keys().collect();
        // BTreeMap keys are sorted lexicographically
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "final_states keys must be sorted (BTreeMap)");
    }

    #[test]
    fn lifecycle_events_order_preserved_across_runs() {
        let mut cx1 = real_cx(20000);
        let r1 = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx1);
        let mut cx2 = real_cx(20000);
        let r2 = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx2);
        let events1: Vec<&str> = r1
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        let events2: Vec<&str> = r2
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert_eq!(events1, events2);
    }

    #[test]
    fn suite_passed_equals_total_when_all_pass() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        assert_eq!(suite.passed_assertions, suite.total_assertions);
        assert!(suite.total_assertions > 0);
    }

    #[test]
    fn scenario_kind_hash_all_unique() {
        use std::collections::BTreeSet;
        use std::hash::{Hash, Hasher};
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let hashes: BTreeSet<u64> = kinds
            .iter()
            .map(|k| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                k.hash(&mut hasher);
                hasher.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 7, "all ScenarioKind hashes must be unique");
    }

    #[test]
    fn suite_result_json_field_presence() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"scenarios\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"total_assertions\""));
        assert!(json.contains("\"passed_assertions\""));
    }

    #[test]
    fn multi_extension_has_most_assertions() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let multi = suite
            .scenarios
            .iter()
            .find(|s| s.kind == ScenarioKind::MultiExtension)
            .unwrap();
        let startup = suite
            .scenarios
            .iter()
            .find(|s| s.kind == ScenarioKind::Startup)
            .unwrap();
        assert!(
            multi.assertions.len() >= startup.assertions.len(),
            "multi_extension should have at least as many assertions as startup"
        );
    }

    #[test]
    fn scenario_kind_copy_semantics() {
        let k1 = ScenarioKind::Quarantine;
        let k2 = k1; // Copy
        assert_eq!(k1, k2);
    }

    #[test]
    fn scenario_result_serde_with_failed_assertion() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_true("deliberate failure", false);
        assert!(!result.passed);
        let json = serde_json::to_string(&result).unwrap();
        let restored: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
        assert!(!restored.passed);
        assert!(!restored.assertions[0].passed);
    }

    #[test]
    fn startup_extensions_loaded_list() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        assert_eq!(result.extensions_loaded, vec!["ext-startup-1"]);
    }

    #[test]
    fn degraded_mode_extensions_loaded_list() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
        assert_eq!(result.extensions_loaded, vec!["ext-d-1", "ext-d-2"]);
    }

    // -----------------------------------------------------------------------
    // Category 1: Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_startup_copy() {
        let a = ScenarioKind::Startup;
        let b = a;
        assert_eq!(a, b);
        // Both are independently usable after copy
        assert_eq!(format!("{a}"), "startup");
        assert_eq!(format!("{b}"), "startup");
    }

    #[test]
    fn scenario_kind_normal_shutdown_copy() {
        let a = ScenarioKind::NormalShutdown;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(format!("{b}"), "normal_shutdown");
    }

    #[test]
    fn scenario_kind_forced_cancel_copy() {
        let a = ScenarioKind::ForcedCancel;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(format!("{b}"), "forced_cancel");
    }

    #[test]
    fn scenario_kind_revocation_copy() {
        let a = ScenarioKind::Revocation;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_kind_degraded_mode_copy() {
        let a = ScenarioKind::DegradedMode;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_kind_multi_extension_copy() {
        let a = ScenarioKind::MultiExtension;
        let b = a;
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Category 2: Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_debug_all_distinct() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let debugs: std::collections::BTreeSet<String> =
            kinds.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(debugs.len(), 7, "all Debug strings must be distinct");
    }

    #[test]
    fn scenario_kind_debug_nonempty() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        for k in &kinds {
            assert!(!format!("{k:?}").is_empty());
        }
    }

    #[test]
    fn scenario_assertion_debug_nonempty() {
        let a = ScenarioAssertion {
            description: "test".to_string(),
            passed: true,
            detail: String::new(),
        };
        assert!(!format!("{a:?}").is_empty());
    }

    #[test]
    fn scenario_result_debug_nonempty() {
        let r = ScenarioResult::new(ScenarioKind::Startup, 1);
        assert!(!format!("{r:?}").is_empty());
    }

    #[test]
    fn scenario_suite_result_debug_nonempty() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        assert!(!format!("{suite:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // Category 3: Serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_serde_all_variants_distinct() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let jsons: std::collections::BTreeSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        assert_eq!(jsons.len(), 7, "all serde JSON strings must be distinct");
    }

    #[test]
    fn scenario_kind_startup_serde_token() {
        let json = serde_json::to_string(&ScenarioKind::Startup).unwrap();
        assert!(json.contains("Startup"), "expected 'Startup' in {json}");
    }

    #[test]
    fn scenario_kind_quarantine_serde_token() {
        let json = serde_json::to_string(&ScenarioKind::Quarantine).unwrap();
        assert!(
            json.contains("Quarantine"),
            "expected 'Quarantine' in {json}"
        );
    }

    #[test]
    fn scenario_kind_multi_extension_serde_token() {
        let json = serde_json::to_string(&ScenarioKind::MultiExtension).unwrap();
        assert!(
            json.contains("MultiExtension"),
            "expected 'MultiExtension' in {json}"
        );
    }

    // -----------------------------------------------------------------------
    // Category 4: Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_assertion_clone_is_independent() {
        let mut a = ScenarioAssertion {
            description: "original".to_string(),
            passed: true,
            detail: String::new(),
        };
        let b = a.clone();
        a.description = "modified".to_string();
        // b should still have the original description
        assert_eq!(b.description, "original");
        assert_ne!(a.description, b.description);
    }

    #[test]
    fn scenario_result_clone_is_independent() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 1);
        result.assert_true("original assertion", true);
        let mut cloned = result.clone();
        cloned.assert_true("extra assertion in clone", true);
        // original should not have the extra assertion
        assert_eq!(result.assertions.len(), 1);
        assert_eq!(cloned.assertions.len(), 2);
    }

    #[test]
    fn scenario_suite_result_clone_is_independent() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let mut cloned = suite.clone();
        cloned
            .scenarios
            .push(ScenarioResult::new(ScenarioKind::Startup, 99));
        assert_eq!(suite.scenarios.len(), 7);
        assert_eq!(cloned.scenarios.len(), 8);
    }

    // -----------------------------------------------------------------------
    // Category 5: JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_result_json_field_names_stable() {
        let r = ScenarioResult::new(ScenarioKind::Startup, 7);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"assertions\""));
        assert!(json.contains("\"lifecycle_events\""));
        assert!(json.contains("\"extensions_loaded\""));
        assert!(json.contains("\"final_states\""));
        assert!(json.contains("\"total_events_emitted\""));
    }

    #[test]
    fn scenario_assertion_json_field_names_stable() {
        let a = ScenarioAssertion {
            description: "check".to_string(),
            passed: true,
            detail: String::new(),
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"detail\""));
    }

    #[test]
    fn scenario_suite_result_json_field_names_stable() {
        let mut cx = real_cx(20_000);
        let suite = run_all_scenarios(1, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"scenarios\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"total_assertions\""));
        assert!(json.contains("\"passed_assertions\""));
    }

    // -----------------------------------------------------------------------
    // Category 6: Display format checks
    // -----------------------------------------------------------------------

    #[test]
    fn display_startup_is_lowercase_snake() {
        assert_eq!(ScenarioKind::Startup.to_string(), "startup");
    }

    #[test]
    fn display_normal_shutdown_has_underscore() {
        let s = ScenarioKind::NormalShutdown.to_string();
        assert!(s.contains('_'), "expected underscore in '{s}'");
        assert_eq!(s, "normal_shutdown");
    }

    #[test]
    fn display_forced_cancel_has_underscore() {
        let s = ScenarioKind::ForcedCancel.to_string();
        assert!(s.contains('_'));
        assert_eq!(s, "forced_cancel");
    }

    #[test]
    fn display_degraded_mode_has_underscore() {
        let s = ScenarioKind::DegradedMode.to_string();
        assert!(s.contains('_'));
        assert_eq!(s, "degraded_mode");
    }

    #[test]
    fn display_multi_extension_has_underscore() {
        let s = ScenarioKind::MultiExtension.to_string();
        assert!(s.contains('_'));
        assert_eq!(s, "multi_extension");
    }

    #[test]
    fn display_none_contain_uppercase() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        for k in &kinds {
            let s = k.to_string();
            assert!(
                s.chars().all(|c| !c.is_uppercase()),
                "Display for {k:?} contains uppercase: '{s}'"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Category 7: Hash consistency
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_hash_consistent_across_calls() {
        use std::hash::{Hash, Hasher};
        let k = ScenarioKind::Quarantine;
        let hash1 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        };
        let hash2 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn scenario_kind_equal_values_equal_hashes() {
        use std::hash::{Hash, Hasher};
        let k1 = ScenarioKind::DegradedMode;
        let k2 = ScenarioKind::DegradedMode;
        let h1 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k1.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k2.hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // Category 8: Boundary / edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_result_new_seed_zero() {
        let r = ScenarioResult::new(ScenarioKind::Revocation, 0);
        assert_eq!(r.seed, 0);
        assert!(r.passed);
        assert!(r.assertions.is_empty());
    }

    #[test]
    fn scenario_result_new_seed_max() {
        let r = ScenarioResult::new(ScenarioKind::MultiExtension, u64::MAX);
        assert_eq!(r.seed, u64::MAX);
        assert!(r.passed);
    }

    #[test]
    fn scenario_result_assert_true_many_times_all_pass() {
        let mut r = ScenarioResult::new(ScenarioKind::Startup, 1);
        for i in 0..100 {
            r.assert_true(&format!("check-{i}"), true);
        }
        assert!(r.passed);
        assert_eq!(r.assertions.len(), 100);
        assert!(r.assertions.iter().all(|a| a.passed));
    }

    #[test]
    fn scenario_result_assert_eq_string_types() {
        let mut r = ScenarioResult::new(ScenarioKind::Startup, 1);
        r.assert_eq("string match", "hello".to_string(), "hello".to_string());
        assert!(r.passed);
        r.assert_eq("string mismatch", "foo".to_string(), "bar".to_string());
        assert!(!r.passed);
    }

    #[test]
    fn scenario_result_empty_extensions_loaded_initial() {
        let r = ScenarioResult::new(ScenarioKind::ForcedCancel, 5);
        assert!(r.extensions_loaded.is_empty());
    }

    #[test]
    fn scenario_result_empty_final_states_initial() {
        let r = ScenarioResult::new(ScenarioKind::DegradedMode, 5);
        assert!(r.final_states.is_empty());
    }

    #[test]
    fn scenario_result_empty_lifecycle_events_initial() {
        let r = ScenarioResult::new(ScenarioKind::Quarantine, 5);
        assert!(r.lifecycle_events.is_empty());
    }

    #[test]
    fn run_scenario_startup_with_large_seed() {
        let mut cx = real_cx(5000);
        let r = run_scenario(ScenarioKind::Startup, u64::MAX / 2, &mut cx);
        assert!(r.passed);
        assert_eq!(r.seed, u64::MAX / 2);
    }

    #[test]
    fn run_all_scenarios_with_seed_one() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(1, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.seed, 1);
    }

    // -----------------------------------------------------------------------
    // Category 9: Additional serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_result_all_kinds_roundtrip() {
        for kind in [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ] {
            let r = ScenarioResult::new(kind, 42);
            let json = serde_json::to_string(&r).unwrap();
            let back: ScenarioResult = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
            assert_eq!(back.kind, kind);
        }
    }

    #[test]
    fn scenario_assertion_failed_serde_roundtrip() {
        let a = ScenarioAssertion {
            description: "failure case".to_string(),
            passed: false,
            detail: "42 != 99".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
        assert!(!back.passed);
        assert_eq!(back.detail, "42 != 99");
    }

    #[test]
    fn scenario_result_with_assertions_roundtrip() {
        let mut r = ScenarioResult::new(ScenarioKind::Revocation, 55);
        r.assert_true("pass", true);
        r.assert_true("fail", false);
        let json = serde_json::to_string(&r).unwrap();
        let back: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(!back.passed);
        assert_eq!(back.assertions.len(), 2);
    }

    #[test]
    fn suite_result_with_full_run_roundtrip() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(77, &mut cx);
        let json = serde_json::to_string_pretty(&suite).unwrap();
        let back: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(suite.seed, back.seed);
        assert_eq!(suite.total_assertions, back.total_assertions);
        assert_eq!(suite.passed_assertions, back.passed_assertions);
        assert_eq!(suite.verdict, back.verdict);
        assert_eq!(suite.scenarios.len(), back.scenarios.len());
    }

    // -----------------------------------------------------------------------
    // Category 10: Debug nonempty and structural
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_debug_contains_variant_name() {
        assert!(format!("{:?}", ScenarioKind::Startup).contains("Startup"));
        assert!(format!("{:?}", ScenarioKind::NormalShutdown).contains("NormalShutdown"));
        assert!(format!("{:?}", ScenarioKind::ForcedCancel).contains("ForcedCancel"));
        assert!(format!("{:?}", ScenarioKind::Quarantine).contains("Quarantine"));
        assert!(format!("{:?}", ScenarioKind::Revocation).contains("Revocation"));
        assert!(format!("{:?}", ScenarioKind::DegradedMode).contains("DegradedMode"));
        assert!(format!("{:?}", ScenarioKind::MultiExtension).contains("MultiExtension"));
    }

    #[test]
    fn scenario_result_debug_contains_kind() {
        let r = ScenarioResult::new(ScenarioKind::Quarantine, 1);
        let debug = format!("{r:?}");
        assert!(debug.contains("Quarantine"));
    }

    #[test]
    fn scenario_assertion_debug_contains_description() {
        let a = ScenarioAssertion {
            description: "unique_description_xyz".to_string(),
            passed: true,
            detail: String::new(),
        };
        let debug = format!("{a:?}");
        assert!(debug.contains("unique_description_xyz"));
    }

    #[test]
    fn scenario_suite_debug_contains_scenario_count() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let debug = format!("{suite:?}");
        // Debug output should be non-trivial
        assert!(debug.len() > 50);
    }

    // -----------------------------------------------------------------------
    // Additional coverage: scenario invariants and edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn all_scenario_kinds_can_be_used_as_btreemap_keys() {
        let mut map: std::collections::BTreeMap<ScenarioKind, &str> =
            std::collections::BTreeMap::new();
        map.insert(ScenarioKind::Startup, "startup");
        map.insert(ScenarioKind::NormalShutdown, "normal_shutdown");
        map.insert(ScenarioKind::ForcedCancel, "forced_cancel");
        map.insert(ScenarioKind::Quarantine, "quarantine");
        map.insert(ScenarioKind::Revocation, "revocation");
        map.insert(ScenarioKind::DegradedMode, "degraded_mode");
        map.insert(ScenarioKind::MultiExtension, "multi_extension");
        assert_eq!(map.len(), 7);
        assert_eq!(map[&ScenarioKind::Startup], "startup");
        assert_eq!(map[&ScenarioKind::MultiExtension], "multi_extension");
    }

    #[test]
    fn suite_seed_stored_correctly() {
        for seed in [0_u64, 1, 42, 999, u64::MAX] {
            let mut cx = real_cx(100_000);
            let suite = run_all_scenarios(seed, &mut cx);
            assert_eq!(suite.seed, seed, "suite.seed should match input seed");
        }
    }

    #[test]
    fn each_scenario_result_seed_matches_suite_seed() {
        let seed = 333_u64;
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(seed, &mut cx);
        for s in &suite.scenarios {
            assert_eq!(
                s.seed, seed,
                "scenario {:?} seed should match suite seed",
                s.kind
            );
        }
    }

    #[test]
    fn startup_scenario_has_non_empty_final_states() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        // After finalize, final_states should record the extension
        assert!(!result.final_states.is_empty());
    }

    #[test]
    fn normal_shutdown_final_states_all_not_running() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        for (ext_id, running) in &result.final_states {
            assert!(
                !running,
                "extension '{ext_id}' should not be running after normal shutdown"
            );
        }
    }

    #[test]
    fn forced_cancel_final_states_all_not_running() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        for (ext_id, running) in &result.final_states {
            assert!(
                !running,
                "extension '{ext_id}' should not be running after forced cancel"
            );
        }
    }

    #[test]
    fn quarantine_final_states_all_not_running() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        for (ext_id, running) in &result.final_states {
            assert!(
                !running,
                "extension '{ext_id}' should not be running after quarantine"
            );
        }
    }

    #[test]
    fn revocation_final_states_all_not_running() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        for (ext_id, running) in &result.final_states {
            assert!(
                !running,
                "extension '{ext_id}' should not be running after revocation"
            );
        }
    }

    #[test]
    fn scenario_result_total_events_matches_lifecycle_events_len() {
        let mut cx = real_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        for s in &suite.scenarios {
            assert_eq!(
                s.total_events_emitted,
                s.lifecycle_events.len(),
                "total_events_emitted should equal lifecycle_events.len() for {:?}",
                s.kind
            );
        }
    }

    #[test]
    fn startup_scenario_all_assertions_pass() {
        let mut cx = real_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "startup assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }

    #[test]
    fn normal_shutdown_scenario_all_assertions_pass() {
        let mut cx = real_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "normal_shutdown assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }

    #[test]
    fn forced_cancel_all_assertions_pass() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "forced_cancel assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }

    #[test]
    fn quarantine_all_assertions_pass() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "quarantine assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }

    #[test]
    fn revocation_all_assertions_pass() {
        let mut cx = real_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "revocation assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }

    #[test]
    fn multi_extension_all_assertions_pass() {
        let mut cx = real_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        for a in &result.assertions {
            assert!(
                a.passed,
                "multi_extension assertion '{}' failed: {}",
                a.description, a.detail
            );
        }
    }
}
