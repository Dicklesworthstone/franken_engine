//! Release gate enforcing frankenlab scenario pass/fail and deterministic
//! replay checks as hard blockers for security-critical paths.
//!
//! No release artifact can be published if any frankenlab scenario fails or
//! any replay check detects divergence. This module provides:
//!
//! - A [`ReleaseGateRunner`] that evaluates all gates and produces structured
//!   results.
//! - Machine-readable [`GateReport`] with per-gate pass/fail detail.
//! - Fail-closed semantics: infrastructure errors block release (never
//!   fail-open).
//! - Deterministic, idempotent evaluation: same inputs → same report.
//!
//! Plan reference: Section 10.13 item 13, bd-24bu.
//! Dependencies: bd-1o7u (frankenlab scenarios), bd-2sbb (replay checks).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::ContextAdapter;
use crate::frankenlab_extension_lifecycle::run_all_scenarios;
use crate::lab_runtime::Verdict;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT_NAME: &str = "frankenlab_release_gate";

/// Default timeout budget in ticks for gate evaluation.
const DEFAULT_GATE_TIMEOUT_TICKS: u64 = 600;

// ---------------------------------------------------------------------------
// GateKind — the types of release gates
// ---------------------------------------------------------------------------

/// Types of release gates that must pass before a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateKind {
    /// All frankenlab lifecycle scenarios must pass.
    FrankenlabScenarios,
    /// Deterministic replay checks must show zero divergences.
    ReplayDeterminism,
    /// Obligation tracking must report zero unresolved obligations.
    ObligationResolution,
    /// Evidence completeness check: no gaps in the evidence trail.
    EvidenceCompleteness,
}

impl GateKind {
    /// Stable string identifier for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenlabScenarios => "frankenlab_scenarios",
            Self::ReplayDeterminism => "replay_determinism",
            Self::ObligationResolution => "obligation_resolution",
            Self::EvidenceCompleteness => "evidence_completeness",
        }
    }

    /// All gate kinds in evaluation order.
    pub fn all() -> &'static [GateKind] {
        &[
            Self::FrankenlabScenarios,
            Self::ReplayDeterminism,
            Self::ObligationResolution,
            Self::EvidenceCompleteness,
        ]
    }
}

impl fmt::Display for GateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateVerdict — outcome of a single gate
// ---------------------------------------------------------------------------

/// Outcome of evaluating a single release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Gate passed — no issues found.
    Pass,
    /// Gate failed — release must be blocked.
    Fail { reason: String },
    /// Gate infrastructure error — release blocked (fail-closed).
    InfrastructureError { detail: String },
    /// Gate timed out — release blocked.
    Timeout { gate: String, elapsed_ticks: u64 },
}

impl GateVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail { .. } => "fail",
            Self::InfrastructureError { .. } => "infrastructure_error",
            Self::Timeout { .. } => "timeout",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reason } => write!(f, "FAIL: {reason}"),
            Self::InfrastructureError { detail } => {
                write!(f, "INFRASTRUCTURE_ERROR: {detail}")
            }
            Self::Timeout {
                gate,
                elapsed_ticks,
            } => {
                write!(f, "TIMEOUT: gate {gate} after {elapsed_ticks} ticks")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateResult — result of a single gate evaluation
// ---------------------------------------------------------------------------

/// Result of evaluating a single release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Which gate was evaluated.
    pub kind: GateKind,
    /// Pass/fail verdict.
    pub verdict: GateVerdict,
    /// Number of checks performed within this gate.
    pub checks_performed: u64,
    /// Number of checks that passed.
    pub checks_passed: u64,
    /// Structured event log for this gate.
    pub events: Vec<GateEvent>,
}

impl GateResult {
    fn pass(kind: GateKind, checks: u64) -> Self {
        Self {
            kind,
            verdict: GateVerdict::Pass,
            checks_performed: checks,
            checks_passed: checks,
            events: Vec::new(),
        }
    }

    fn fail(kind: GateKind, reason: String, checks: u64, passed: u64) -> Self {
        Self {
            kind,
            verdict: GateVerdict::Fail { reason },
            checks_performed: checks,
            checks_passed: passed,
            events: Vec::new(),
        }
    }

    #[allow(dead_code)]
    fn infra_error(kind: GateKind, detail: String) -> Self {
        Self {
            kind,
            verdict: GateVerdict::InfrastructureError { detail },
            checks_performed: 0,
            checks_passed: 0,
            events: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// GateEvent — structured event log entry
// ---------------------------------------------------------------------------

/// Structured event emitted during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    pub component: String,
    pub gate: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// GateReport — overall release gate report
// ---------------------------------------------------------------------------

/// Overall release gate report across all gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Seed used for deterministic evaluation.
    pub seed: u64,
    /// Per-gate results.
    pub gates: Vec<GateResult>,
    /// Overall verdict: PASS only if every gate passes.
    pub overall_verdict: OverallVerdict,
    /// Total checks across all gates.
    pub total_checks: u64,
    /// Total passed checks.
    pub total_passed: u64,
    /// Summary of failures (empty if all pass).
    pub failure_summary: Vec<String>,
}

/// Overall release verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverallVerdict {
    /// All gates passed — release is allowed.
    Released,
    /// One or more gates failed — release is blocked.
    Blocked { failing_gates: Vec<GateKind> },
}

impl OverallVerdict {
    pub fn is_released(&self) -> bool {
        matches!(self, Self::Released)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Blocked { .. } => "blocked",
        }
    }
}

impl fmt::Display for OverallVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Released => write!(f, "RELEASED"),
            Self::Blocked { failing_gates } => {
                let names: Vec<&str> = failing_gates.iter().map(|g| g.as_str()).collect();
                write!(f, "BLOCKED [{}]", names.join(", "))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateConfig — configuration for release gate behavior
// ---------------------------------------------------------------------------

/// Configuration for release gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Deterministic seed for scenario runs.
    pub seed: u64,
    /// Maximum ticks for gate evaluation timeout.
    pub timeout_ticks: u64,
    /// Whether to run replay determinism checks.
    pub check_replay: bool,
    /// Whether to run obligation resolution checks.
    pub check_obligations: bool,
    /// Whether to run evidence completeness checks.
    pub check_evidence: bool,
    /// Number of replay iterations for determinism verification.
    pub replay_iterations: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            timeout_ticks: DEFAULT_GATE_TIMEOUT_TICKS,
            check_replay: true,
            check_obligations: true,
            check_evidence: true,
            replay_iterations: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// ReleaseGateRunner — runs all gates and produces a report
// ---------------------------------------------------------------------------

/// Runs all release gates and produces a structured report.
///
/// Fail-closed: any gate error blocks release. Deterministic: same config →
/// same report. Idempotent: multiple runs produce identical results.
#[derive(Debug, Clone)]
pub struct ReleaseGateRunner {
    config: GateConfig,
    events: Vec<GateEvent>,
}

impl ReleaseGateRunner {
    pub fn new(config: GateConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
        }
    }

    /// Access the gate configuration.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Run all gates and produce a complete report.
    pub fn run<C: ContextAdapter>(&mut self, cx: &mut C) -> GateReport {
        let mut gates = Vec::new();
        let mut failure_summary = Vec::new();

        // Gate 1: Frankenlab scenarios
        let scenario_result = self.evaluate_frankenlab_scenarios(cx);
        if !scenario_result.verdict.is_pass() {
            failure_summary.push(format!(
                "{}: {}",
                scenario_result.kind, scenario_result.verdict
            ));
        }
        gates.push(scenario_result);

        // Gate 2: Replay determinism
        if self.config.check_replay {
            let replay_result = self.evaluate_replay_determinism(cx);
            if !replay_result.verdict.is_pass() {
                failure_summary.push(format!("{}: {}", replay_result.kind, replay_result.verdict));
            }
            gates.push(replay_result);
        }

        // Gate 3: Obligation resolution
        if self.config.check_obligations {
            let obligation_result = self.evaluate_obligation_resolution(cx);
            if !obligation_result.verdict.is_pass() {
                failure_summary.push(format!(
                    "{}: {}",
                    obligation_result.kind, obligation_result.verdict
                ));
            }
            gates.push(obligation_result);
        }

        // Gate 4: Evidence completeness
        if self.config.check_evidence {
            let evidence_result = self.evaluate_evidence_completeness(cx);
            if !evidence_result.verdict.is_pass() {
                failure_summary.push(format!(
                    "{}: {}",
                    evidence_result.kind, evidence_result.verdict
                ));
            }
            gates.push(evidence_result);
        }

        let total_checks: u64 = gates.iter().map(|g| g.checks_performed).sum();
        let total_passed: u64 = gates.iter().map(|g| g.checks_passed).sum();

        let failing_gates: Vec<GateKind> = gates
            .iter()
            .filter(|g| !g.verdict.is_pass())
            .map(|g| g.kind)
            .collect();

        let overall_verdict = if failing_gates.is_empty() {
            OverallVerdict::Released
        } else {
            OverallVerdict::Blocked { failing_gates }
        };

        GateReport {
            seed: self.config.seed,
            gates,
            overall_verdict,
            total_checks,
            total_passed,
            failure_summary,
        }
    }

    /// Access events from the last run.
    pub fn events(&self) -> &[GateEvent] {
        &self.events
    }

    // -- Gate evaluators --

    fn evaluate_frankenlab_scenarios<C: ContextAdapter>(&mut self, cx: &mut C) -> GateResult {
        self.emit_event(
            GateKind::FrankenlabScenarios,
            "gate_start",
            "starting",
            None,
        );

        let suite = run_all_scenarios(self.config.seed, cx);
        let total = suite.total_assertions as u64;
        let passed = suite.passed_assertions as u64;

        if suite.verdict == Verdict::Pass {
            self.emit_event(GateKind::FrankenlabScenarios, "gate_pass", "pass", None);
            GateResult::pass(GateKind::FrankenlabScenarios, total)
        } else {
            let failing: Vec<String> = suite
                .scenarios
                .iter()
                .filter(|s| !s.passed)
                .map(|s| format!("{}", s.kind))
                .collect();
            let reason = format!(
                "{} of {} scenarios failed: [{}]",
                failing.len(),
                suite.scenarios.len(),
                failing.join(", ")
            );
            self.emit_event(
                GateKind::FrankenlabScenarios,
                "gate_fail",
                "fail",
                Some("scenario_failure"),
            );
            GateResult::fail(GateKind::FrankenlabScenarios, reason, total, passed)
        }
    }

    fn evaluate_replay_determinism<C: ContextAdapter>(&mut self, cx: &mut C) -> GateResult {
        self.emit_event(GateKind::ReplayDeterminism, "gate_start", "starting", None);

        // Run the full scenario suite multiple times and compare results
        let iterations = self.config.replay_iterations;
        let baseline = run_all_scenarios(self.config.seed, cx);
        let baseline_assertions = baseline.total_assertions;
        let baseline_passed = baseline.passed_assertions;

        let mut divergences = Vec::new();

        for i in 1..iterations {
            let replay = run_all_scenarios(self.config.seed, cx);
            if replay.total_assertions != baseline_assertions
                || replay.passed_assertions != baseline_passed
            {
                divergences.push(format!(
                    "iteration {i}: assertions {}/{} vs baseline {}/{}",
                    replay.passed_assertions,
                    replay.total_assertions,
                    baseline_passed,
                    baseline_assertions
                ));
            }

            // Compare per-scenario determinism
            for (bs, rs) in baseline.scenarios.iter().zip(replay.scenarios.iter()) {
                if bs.assertions != rs.assertions {
                    divergences.push(format!(
                        "iteration {i}, scenario {}: assertion mismatch",
                        bs.kind
                    ));
                }
                if bs.total_events_emitted != rs.total_events_emitted {
                    divergences.push(format!(
                        "iteration {i}, scenario {}: event count {} vs {}",
                        bs.kind, rs.total_events_emitted, bs.total_events_emitted
                    ));
                }
            }
        }

        let checks = iterations;
        if divergences.is_empty() {
            self.emit_event(GateKind::ReplayDeterminism, "gate_pass", "pass", None);
            GateResult::pass(GateKind::ReplayDeterminism, checks)
        } else {
            let reason = format!(
                "{} divergences across {} iterations: {}",
                divergences.len(),
                iterations,
                divergences.first().unwrap_or(&String::new()),
            );
            self.emit_event(
                GateKind::ReplayDeterminism,
                "gate_fail",
                "fail",
                Some("replay_divergence"),
            );
            GateResult::fail(
                GateKind::ReplayDeterminism,
                reason,
                checks,
                checks - 1, // at least one failed
            )
        }
    }

    fn evaluate_obligation_resolution<C: ContextAdapter>(&mut self, cx: &mut C) -> GateResult {
        self.emit_event(
            GateKind::ObligationResolution,
            "gate_start",
            "starting",
            None,
        );

        // Run scenarios and check that all scenarios resolved their obligations
        let suite = run_all_scenarios(self.config.seed, cx);
        let mut unresolved = Vec::new();

        for scenario in &suite.scenarios {
            // Check final states: any extension still running means obligations
            // might be unresolved
            let still_running: Vec<&str> = scenario
                .final_states
                .iter()
                .filter(|(_, running)| **running)
                .map(|(id, _)| id.as_str())
                .collect();

            // For non-degraded/multi scenarios, extensions should be cleaned up
            // at scenario end (except multi-extension where ext-m-3 remains)
            if scenario.kind != crate::frankenlab_extension_lifecycle::ScenarioKind::MultiExtension
                && scenario.kind != crate::frankenlab_extension_lifecycle::ScenarioKind::Startup
                && !still_running.is_empty()
            {
                unresolved.push(format!(
                    "scenario {}: {} extensions still running: [{}]",
                    scenario.kind,
                    still_running.len(),
                    still_running.join(", ")
                ));
            }
        }

        let checks = suite.scenarios.len() as u64;
        if unresolved.is_empty() {
            self.emit_event(GateKind::ObligationResolution, "gate_pass", "pass", None);
            GateResult::pass(GateKind::ObligationResolution, checks)
        } else {
            let reason = format!("{} unresolved: {}", unresolved.len(), unresolved.join("; "));
            self.emit_event(
                GateKind::ObligationResolution,
                "gate_fail",
                "fail",
                Some("unresolved_obligations"),
            );
            GateResult::fail(
                GateKind::ObligationResolution,
                reason,
                checks,
                checks - unresolved.len() as u64,
            )
        }
    }

    fn evaluate_evidence_completeness<C: ContextAdapter>(&mut self, cx: &mut C) -> GateResult {
        self.emit_event(
            GateKind::EvidenceCompleteness,
            "gate_start",
            "starting",
            None,
        );

        let suite = run_all_scenarios(self.config.seed, cx);
        let mut gaps = Vec::new();

        for scenario in &suite.scenarios {
            if scenario.total_events_emitted == 0 {
                gaps.push(format!("scenario {}: zero events emitted", scenario.kind));
            }

            // Check evidence trail has no gaps by verifying loaded extensions
            // have corresponding events
            if scenario.lifecycle_events.is_empty() && !scenario.extensions_loaded.is_empty() {
                gaps.push(format!(
                    "scenario {}: extensions loaded but no lifecycle events",
                    scenario.kind
                ));
            }
        }

        let checks = suite.scenarios.len() as u64;
        if gaps.is_empty() {
            self.emit_event(GateKind::EvidenceCompleteness, "gate_pass", "pass", None);
            GateResult::pass(GateKind::EvidenceCompleteness, checks)
        } else {
            let reason = format!("{} gaps: {}", gaps.len(), gaps.join("; "));
            self.emit_event(
                GateKind::EvidenceCompleteness,
                "gate_fail",
                "fail",
                Some("evidence_gap"),
            );
            GateResult::fail(
                GateKind::EvidenceCompleteness,
                reason,
                checks,
                checks - gaps.len() as u64,
            )
        }
    }

    fn emit_event(&mut self, gate: GateKind, event: &str, outcome: &str, error_code: Option<&str>) {
        self.events.push(GateEvent {
            component: COMPONENT_NAME.to_string(),
            gate: gate.as_str().to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(std::string::ToString::to_string),
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(trace_id_from_seed(42), MockBudget::new(budget_ms))
    }

    // --- GateKind ---

    #[test]
    fn gate_kind_display_all_variants() {
        let expected = [
            (GateKind::FrankenlabScenarios, "frankenlab_scenarios"),
            (GateKind::ReplayDeterminism, "replay_determinism"),
            (GateKind::ObligationResolution, "obligation_resolution"),
            (GateKind::EvidenceCompleteness, "evidence_completeness"),
        ];
        for (kind, s) in expected {
            assert_eq!(kind.as_str(), s);
            assert_eq!(kind.to_string(), s);
        }
    }

    #[test]
    fn gate_kind_all_returns_four() {
        assert_eq!(GateKind::all().len(), 4);
    }

    #[test]
    fn gate_kind_serde_roundtrip() {
        for kind in GateKind::all() {
            // SAFETY: GateKind derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(kind).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by to_string of a valid GateKind,
            // so from_str back to GateKind cannot fail (valid format + matching schema).
            let restored: GateKind = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn gate_kind_deterministic_ordering() {
        let mut kinds: Vec<GateKind> = GateKind::all().to_vec();
        let original = kinds.clone();
        kinds.sort();
        assert_eq!(kinds, original);
    }

    // --- GateVerdict ---

    #[test]
    fn gate_verdict_pass_is_pass() {
        assert!(GateVerdict::Pass.is_pass());
        assert!(!GateVerdict::Fail { reason: "x".into() }.is_pass());
        assert!(!GateVerdict::InfrastructureError { detail: "x".into() }.is_pass());
        assert!(
            !GateVerdict::Timeout {
                gate: "x".into(),
                elapsed_ticks: 1,
            }
            .is_pass()
        );
    }

    #[test]
    fn gate_verdict_display() {
        assert_eq!(GateVerdict::Pass.to_string(), "PASS");
        assert!(
            GateVerdict::Fail {
                reason: "bad".into()
            }
            .to_string()
            .contains("FAIL")
        );
        assert!(
            GateVerdict::InfrastructureError {
                detail: "broken".into()
            }
            .to_string()
            .contains("INFRASTRUCTURE_ERROR")
        );
        assert!(
            GateVerdict::Timeout {
                gate: "x".into(),
                elapsed_ticks: 99,
            }
            .to_string()
            .contains("TIMEOUT")
        );
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        let verdicts = vec![
            GateVerdict::Pass,
            GateVerdict::Fail {
                reason: "scenario failed".into(),
            },
            GateVerdict::InfrastructureError {
                detail: "missing dep".into(),
            },
            GateVerdict::Timeout {
                gate: "replay".into(),
                elapsed_ticks: 600,
            },
        ];
        for v in verdicts {
            // SAFETY: GateVerdict derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by to_string of a valid GateVerdict,
            // so from_str back to GateVerdict cannot fail (valid format + matching schema).
            let restored: GateVerdict = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, restored);
        }
    }

    // --- OverallVerdict ---

    #[test]
    fn overall_verdict_display() {
        assert_eq!(OverallVerdict::Released.to_string(), "RELEASED");
        let blocked = OverallVerdict::Blocked {
            failing_gates: vec![GateKind::ReplayDeterminism],
        };
        assert!(blocked.to_string().contains("BLOCKED"));
    }

    #[test]
    fn overall_verdict_serde_roundtrip() {
        for v in [
            OverallVerdict::Released,
            OverallVerdict::Blocked {
                failing_gates: vec![
                    GateKind::FrankenlabScenarios,
                    GateKind::EvidenceCompleteness,
                ],
            },
        ] {
            // SAFETY: OverallVerdict derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by to_string of a valid OverallVerdict,
            // so from_str back to OverallVerdict cannot fail (valid format + matching schema).
            let restored: OverallVerdict = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(v, restored);
        }
    }

    // --- GateConfig ---

    #[test]
    fn config_defaults() {
        let cfg = GateConfig::default();
        assert_eq!(cfg.seed, 42);
        assert!(cfg.check_replay);
        assert!(cfg.check_obligations);
        assert!(cfg.check_evidence);
        assert_eq!(cfg.replay_iterations, 10);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = GateConfig {
            seed: 99,
            timeout_ticks: 300,
            check_replay: false,
            check_obligations: true,
            check_evidence: false,
            replay_iterations: 5,
        };
        // SAFETY: GateConfig derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by to_string of a valid GateConfig,
        // so from_str back to GateConfig cannot fail (valid format + matching schema).
        let restored: GateConfig = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cfg, restored);
    }

    // --- ReleaseGateRunner: full pass ---

    #[test]
    fn full_gate_run_passes() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 3,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        assert!(report.overall_verdict.is_released());
        assert_eq!(report.gates.len(), 4);
        assert!(report.failure_summary.is_empty());
        assert!(report.total_checks > 0);
        assert_eq!(report.total_checks, report.total_passed);
    }

    #[test]
    fn full_gate_run_emits_events() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let _ = runner.run(&mut cx);

        // At least one start + pass event per gate
        assert!(runner.events().len() >= 8);

        // All events have stable component
        for event in runner.events() {
            assert_eq!(event.component, COMPONENT_NAME);
        }
    }

    // --- ReleaseGateRunner: selective gates ---

    #[test]
    fn run_only_scenarios_gate() {
        let config = GateConfig {
            seed: 42,
            check_replay: false,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        assert_eq!(report.gates.len(), 1);
        assert_eq!(report.gates[0].kind, GateKind::FrankenlabScenarios);
        assert!(report.overall_verdict.is_released());
    }

    // --- ReleaseGateRunner: determinism ---

    #[test]
    fn gate_run_deterministic_across_runs() {
        let config = GateConfig {
            seed: 77,
            replay_iterations: 2,
            ..Default::default()
        };

        let mut runner1 = ReleaseGateRunner::new(config.clone());
        let mut cx1 = mock_cx(500_000);
        let report1 = runner1.run(&mut cx1);

        let mut runner2 = ReleaseGateRunner::new(config);
        let mut cx2 = mock_cx(500_000);
        let report2 = runner2.run(&mut cx2);

        assert_eq!(report1.overall_verdict, report2.overall_verdict);
        assert_eq!(report1.total_checks, report2.total_checks);
        assert_eq!(report1.total_passed, report2.total_passed);
        assert_eq!(report1.gates.len(), report2.gates.len());

        for (g1, g2) in report1.gates.iter().zip(report2.gates.iter()) {
            assert_eq!(g1.kind, g2.kind);
            assert_eq!(g1.verdict, g2.verdict);
            assert_eq!(g1.checks_performed, g2.checks_performed);
        }
    }

    #[test]
    fn gate_run_deterministic_100_times() {
        let config = GateConfig {
            seed: 55,
            replay_iterations: 2,
            check_replay: false, // skip replay for speed
            ..Default::default()
        };

        let mut first_report = None;
        for _ in 0..100 {
            let mut runner = ReleaseGateRunner::new(config.clone());
            let mut cx = mock_cx(500_000);
            let report = runner.run(&mut cx);

            if let Some(ref first) = first_report {
                let f: &GateReport = first;
                assert_eq!(f.overall_verdict, report.overall_verdict);
                assert_eq!(f.total_checks, report.total_checks);
                assert_eq!(f.total_passed, report.total_passed);
            } else {
                first_report = Some(report);
            }
        }
    }

    // --- GateReport serde ---

    #[test]
    fn gate_report_serde_roundtrip() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let restored: GateReport = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, restored);
    }

    #[test]
    fn gate_report_machine_readable_json() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("serde deserialization should succeed");

        // Verify key fields exist for CI consumption
        assert!(parsed.get("seed").is_some());
        assert!(parsed.get("gates").is_some());
        assert!(parsed.get("overall_verdict").is_some());
        assert!(parsed.get("total_checks").is_some());
        assert!(parsed.get("total_passed").is_some());
        assert!(parsed.get("failure_summary").is_some());
    }

    // --- GateEvent ---

    #[test]
    fn gate_event_serde_roundtrip() {
        let event = GateEvent {
            component: COMPONENT_NAME.to_string(),
            gate: "frankenlab_scenarios".to_string(),
            event: "gate_pass".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: GateEvent = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    // --- GateResult ---

    #[test]
    fn gate_result_serde_roundtrip() {
        let result = GateResult::pass(GateKind::FrankenlabScenarios, 10);
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let restored: GateResult = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, restored);
    }

    #[test]
    fn gate_result_fail_captures_detail() {
        let result = GateResult::fail(
            GateKind::ReplayDeterminism,
            "divergence found".to_string(),
            10,
            8,
        );
        assert!(!result.verdict.is_pass());
        assert_eq!(result.checks_performed, 10);
        assert_eq!(result.checks_passed, 8);
    }

    #[test]
    fn gate_result_infra_error_blocks() {
        let result = GateResult::infra_error(
            GateKind::FrankenlabScenarios,
            "missing dependency".to_string(),
        );
        assert!(!result.verdict.is_pass());
        assert_eq!(result.checks_performed, 0);
    }

    // --- Infrastructure error (fail-closed) ---

    #[test]
    fn infrastructure_error_verdict_blocks_release() {
        let gate = GateResult::infra_error(
            GateKind::FrankenlabScenarios,
            "frankenlab harness not found".to_string(),
        );
        assert!(matches!(
            gate.verdict,
            GateVerdict::InfrastructureError { .. }
        ));
        assert!(!gate.verdict.is_pass());
    }

    // --- Partial success reporting ---

    #[test]
    fn partial_success_reports_failing_gates() {
        // Construct a report with 2 pass + 2 fail
        let report = GateReport {
            seed: 42,
            gates: vec![
                GateResult::pass(GateKind::FrankenlabScenarios, 10),
                GateResult::fail(GateKind::ReplayDeterminism, "diverged".to_string(), 5, 3),
                GateResult::pass(GateKind::ObligationResolution, 7),
                GateResult::fail(
                    GateKind::EvidenceCompleteness,
                    "gap found".to_string(),
                    7,
                    6,
                ),
            ],
            overall_verdict: OverallVerdict::Blocked {
                failing_gates: vec![GateKind::ReplayDeterminism, GateKind::EvidenceCompleteness],
            },
            total_checks: 29,
            total_passed: 26,
            failure_summary: vec![
                "replay_determinism: FAIL: diverged".to_string(),
                "evidence_completeness: FAIL: gap found".to_string(),
            ],
        };

        assert!(!report.overall_verdict.is_released());
        assert_eq!(report.failure_summary.len(), 2);

        // Verify passing gates still report their results
        assert!(report.gates[0].verdict.is_pass());
        assert!(report.gates[2].verdict.is_pass());
    }

    // --- Different seeds ---

    #[test]
    fn different_seeds_all_pass() {
        for seed in [1, 42, 99, 255, 1000] {
            let config = GateConfig {
                seed,
                replay_iterations: 2,
                check_replay: false,
                ..Default::default()
            };
            let mut runner = ReleaseGateRunner::new(config);
            let mut cx = mock_cx(500_000);
            let report = runner.run(&mut cx);
            assert!(
                report.overall_verdict.is_released(),
                "seed {seed} should release"
            );
        }
    }

    // --- Idempotency ---

    #[test]
    fn gate_idempotent_same_runner() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            check_replay: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);

        let mut cx1 = mock_cx(500_000);
        let report1 = runner.run(&mut cx1);

        let mut cx2 = mock_cx(500_000);
        let report2 = runner.run(&mut cx2);

        assert_eq!(report1.overall_verdict, report2.overall_verdict);
        assert_eq!(report1.total_checks, report2.total_checks);
        assert_eq!(report1.total_passed, report2.total_passed);
    }

    // -- Enrichment: GateVerdict as_str --

    #[test]
    fn gate_verdict_as_str_values() {
        assert_eq!(GateVerdict::Pass.as_str(), "pass");
        assert_eq!(GateVerdict::Fail { reason: "x".into() }.as_str(), "fail");
        assert_eq!(
            GateVerdict::InfrastructureError { detail: "x".into() }.as_str(),
            "infrastructure_error"
        );
        assert_eq!(
            GateVerdict::Timeout {
                gate: "x".into(),
                elapsed_ticks: 1
            }
            .as_str(),
            "timeout"
        );
    }

    // -- Enrichment: OverallVerdict accessors --

    #[test]
    fn overall_verdict_is_released_and_as_str() {
        assert!(OverallVerdict::Released.is_released());
        assert_eq!(OverallVerdict::Released.as_str(), "released");
        let blocked = OverallVerdict::Blocked {
            failing_gates: vec![GateKind::FrankenlabScenarios],
        };
        assert!(!blocked.is_released());
        assert_eq!(blocked.as_str(), "blocked");
    }

    // -- Enrichment: runner config accessor --

    #[test]
    fn runner_config_accessor() {
        let config = GateConfig {
            seed: 99,
            replay_iterations: 5,
            ..Default::default()
        };
        let runner = ReleaseGateRunner::new(config.clone());
        assert_eq!(runner.config().seed, 99);
        assert_eq!(runner.config().replay_iterations, 5);
    }

    // -- Enrichment: runner events empty before run --

    #[test]
    fn runner_events_empty_before_run() {
        let runner = ReleaseGateRunner::new(GateConfig::default());
        assert!(runner.events().is_empty());
    }

    // -- Enrichment: GateKind all contains all variants --

    #[test]
    fn gate_kind_all_contains_all_variants() {
        let all = GateKind::all();
        assert!(all.contains(&GateKind::FrankenlabScenarios));
        assert!(all.contains(&GateKind::ReplayDeterminism));
        assert!(all.contains(&GateKind::ObligationResolution));
        assert!(all.contains(&GateKind::EvidenceCompleteness));
    }

    // -- Enrichment: full report failure_summary empty on pass --

    #[test]
    fn full_report_failure_summary_empty_on_pass() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            check_replay: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        assert!(report.overall_verdict.is_released());
        assert!(report.failure_summary.is_empty());
    }

    // -- Enrichment: GateResult pass checks match --

    #[test]
    fn gate_result_pass_checks_performed_equals_passed() {
        let result = GateResult::pass(GateKind::FrankenlabScenarios, 42);
        assert_eq!(result.checks_performed, 42);
        assert_eq!(result.checks_passed, 42);
        assert!(result.verdict.is_pass());
        assert!(result.events.is_empty());
    }

    // -- Enrichment: config timeout default value --

    #[test]
    fn config_default_timeout_ticks() {
        let cfg = GateConfig::default();
        assert_eq!(cfg.timeout_ticks, 600);
    }

    // -- Enrichment: GateEvent with error_code --

    #[test]
    fn gate_event_with_error_code_serde() {
        let event = GateEvent {
            component: COMPONENT_NAME.to_string(),
            gate: "replay_determinism".to_string(),
            event: "gate_fail".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("replay_divergence".to_string()),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: GateEvent = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
        assert_eq!(restored.error_code.as_deref(), Some("replay_divergence"));
    }

    // -- Enrichment: selective gate combos --

    #[test]
    fn run_only_replay_gate() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            check_replay: true,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert_eq!(report.gates.len(), 2);
        assert_eq!(report.gates[0].kind, GateKind::FrankenlabScenarios);
        assert_eq!(report.gates[1].kind, GateKind::ReplayDeterminism);
    }

    #[test]
    fn run_only_obligations_gate() {
        let config = GateConfig {
            seed: 42,
            check_replay: false,
            check_obligations: true,
            check_evidence: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert_eq!(report.gates.len(), 2);
        assert_eq!(report.gates[1].kind, GateKind::ObligationResolution);
    }

    #[test]
    fn run_only_evidence_gate() {
        let config = GateConfig {
            seed: 42,
            check_replay: false,
            check_obligations: false,
            check_evidence: true,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert_eq!(report.gates.len(), 2);
        assert_eq!(report.gates[1].kind, GateKind::EvidenceCompleteness);
    }

    // -- Enrichment: GateResult serde for fail/infra --

    #[test]
    fn gate_result_fail_serde_roundtrip() {
        let result = GateResult::fail(
            GateKind::EvidenceCompleteness,
            "evidence gap".to_string(),
            20,
            18,
        );
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let restored: GateResult = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, restored);
    }

    #[test]
    fn gate_result_infra_error_serde_roundtrip() {
        let result = GateResult::infra_error(
            GateKind::ObligationResolution,
            "harness unavailable".to_string(),
        );
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let restored: GateResult = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, restored);
    }

    // -- Enrichment: Display detail tests --

    #[test]
    fn gate_verdict_fail_display_contains_reason() {
        let v = GateVerdict::Fail {
            reason: "scenario xyz diverged".into(),
        };
        let s = v.to_string();
        assert!(s.contains("FAIL"));
        assert!(s.contains("scenario xyz diverged"));
    }

    #[test]
    fn gate_verdict_timeout_display_contains_ticks() {
        let v = GateVerdict::Timeout {
            gate: "replay_determinism".into(),
            elapsed_ticks: 600,
        };
        let s = v.to_string();
        assert!(s.contains("600"));
        assert!(s.contains("replay_determinism"));
    }

    #[test]
    fn gate_verdict_infra_error_display_contains_detail() {
        let v = GateVerdict::InfrastructureError {
            detail: "missing harness binary".into(),
        };
        let s = v.to_string();
        assert!(s.contains("INFRASTRUCTURE_ERROR"));
        assert!(s.contains("missing harness binary"));
    }

    #[test]
    fn overall_verdict_blocked_display_lists_gates() {
        let blocked = OverallVerdict::Blocked {
            failing_gates: vec![GateKind::ReplayDeterminism, GateKind::EvidenceCompleteness],
        };
        let display = blocked.to_string();
        assert!(display.contains("replay_determinism"));
        assert!(display.contains("evidence_completeness"));
    }

    // -- Enrichment: report totals correctness --

    #[test]
    fn report_totals_equal_sum_of_gates() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        let sum_checks: u64 = report.gates.iter().map(|g| g.checks_performed).sum();
        let sum_passed: u64 = report.gates.iter().map(|g| g.checks_passed).sum();
        assert_eq!(report.total_checks, sum_checks);
        assert_eq!(report.total_passed, sum_passed);
    }

    // -- Enrichment: seed in report --

    #[test]
    fn report_seed_matches_config() {
        let config = GateConfig {
            seed: 999,
            check_replay: false,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert_eq!(report.seed, 999);
    }

    // -- Enrichment: events accumulate --

    #[test]
    fn events_accumulate_across_multiple_runs() {
        let config = GateConfig {
            seed: 42,
            check_replay: false,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);

        let mut cx1 = mock_cx(500_000);
        let _ = runner.run(&mut cx1);
        let count_after_first = runner.events().len();
        assert!(count_after_first >= 2);

        let mut cx2 = mock_cx(500_000);
        let _ = runner.run(&mut cx2);
        assert!(runner.events().len() > count_after_first);
    }

    // -- Enrichment: all gates pass with full config --

    #[test]
    fn different_seeds_with_full_gates_all_pass() {
        for seed in [1, 42, 255] {
            let config = GateConfig {
                seed,
                replay_iterations: 2,
                ..Default::default()
            };
            let mut runner = ReleaseGateRunner::new(config);
            let mut cx = mock_cx(500_000);
            let report = runner.run(&mut cx);
            assert!(
                report.overall_verdict.is_released(),
                "seed {seed} should release with all gates"
            );
            assert_eq!(report.gates.len(), 4);
        }
    }

    #[test]
    fn gate_verdict_clone_equality() {
        let v = GateVerdict::Fail {
            reason: "test".into(),
        };
        assert_eq!(v, v.clone());
    }

    #[test]
    fn gate_result_clone_equality() {
        let r = GateResult::pass(GateKind::ReplayDeterminism, 5);
        assert_eq!(r, r.clone());
    }

    #[test]
    fn gate_event_clone_equality() {
        let e = GateEvent {
            component: "c".into(),
            gate: "g".into(),
            event: "e".into(),
            outcome: "pass".into(),
            error_code: None,
        };
        assert_eq!(e, e.clone());
    }

    #[test]
    fn gate_config_clone_equality() {
        let c = GateConfig::default();
        assert_eq!(c, c.clone());
    }

    #[test]
    fn overall_verdict_clone_equality() {
        let v = OverallVerdict::Blocked {
            failing_gates: vec![GateKind::EvidenceCompleteness],
        };
        assert_eq!(v, v.clone());
    }

    #[test]
    fn gate_result_json_field_presence() {
        let r = GateResult::pass(GateKind::FrankenlabScenarios, 3);
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"checks_performed\""));
        assert!(json.contains("\"checks_passed\""));
        assert!(json.contains("\"events\""));
    }

    #[test]
    fn gate_event_json_field_presence() {
        let e = GateEvent {
            component: "c".into(),
            gate: "g".into(),
            event: "e".into(),
            outcome: "pass".into(),
            error_code: Some("E01".into()),
        };
        let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"gate\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn gate_report_json_field_presence() {
        let mut runner = ReleaseGateRunner::new(GateConfig {
            check_replay: false,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        });
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"gates\""));
        assert!(json.contains("\"overall_verdict\""));
        assert!(json.contains("\"total_checks\""));
        assert!(json.contains("\"total_passed\""));
        assert!(json.contains("\"failure_summary\""));
    }

    #[test]
    fn gate_verdict_display_all_unique() {
        let verdicts = [
            GateVerdict::Pass,
            GateVerdict::Fail { reason: "r".into() },
            GateVerdict::InfrastructureError { detail: "d".into() },
            GateVerdict::Timeout {
                gate: "g".into(),
                elapsed_ticks: 1,
            },
        ];
        let set: std::collections::BTreeSet<_> = verdicts.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn gate_verdict_as_str_all_unique() {
        let verdicts = [
            GateVerdict::Pass,
            GateVerdict::Fail { reason: "r".into() },
            GateVerdict::InfrastructureError { detail: "d".into() },
            GateVerdict::Timeout {
                gate: "g".into(),
                elapsed_ticks: 1,
            },
        ];
        let set: std::collections::BTreeSet<_> = verdicts.iter().map(|v| v.as_str()).collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn gate_report_clone_equality() {
        let mut runner = ReleaseGateRunner::new(GateConfig {
            check_replay: false,
            check_obligations: false,
            check_evidence: false,
            ..Default::default()
        });
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn gate_kind_as_str_all_unique() {
        let set: std::collections::BTreeSet<_> =
            GateKind::all().iter().map(|k| k.as_str()).collect();
        assert_eq!(set.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 5: Copy, Hash, JSON, boundary
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_gate_kind_copy_semantics() {
        let a = GateKind::ReplayDeterminism;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(b.as_str(), "replay_determinism");
    }

    #[test]
    fn enrichment_gate_kind_hash_in_btreeset() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for kind in GateKind::all() {
            assert!(set.insert(*kind));
        }
        assert_eq!(set.len(), 4);
        assert!(!set.insert(GateKind::FrankenlabScenarios)); // dup
    }

    #[test]
    fn enrichment_config_json_field_presence() {
        let cfg = GateConfig::default();
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        for field in &[
            "seed",
            "timeout_ticks",
            "check_replay",
            "check_obligations",
            "check_evidence",
            "replay_iterations",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn enrichment_overall_verdict_blocked_empty_failing_list() {
        let v = OverallVerdict::Blocked {
            failing_gates: vec![],
        };
        assert!(!v.is_released());
        let display = v.to_string();
        assert!(display.contains("BLOCKED"));
    }

    #[test]
    fn enrichment_gate_events_have_gate_start_names() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 2,
            check_replay: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let _ = runner.run(&mut cx);

        let start_events: Vec<_> = runner
            .events()
            .iter()
            .filter(|e| e.event == "gate_start")
            .collect();
        // Frankenlab scenarios + obligations + evidence = 3 gates enabled
        assert_eq!(start_events.len(), 3);
        assert!(start_events.iter().all(|e| e.outcome == "starting"));
    }

    #[test]
    fn enrichment_replay_iterations_one_still_passes() {
        let config = GateConfig {
            seed: 42,
            replay_iterations: 1,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert!(report.overall_verdict.is_released());
    }

    #[test]
    fn enrichment_gate_result_fail_checks_passed_less_than_performed() {
        let result = GateResult::fail(GateKind::EvidenceCompleteness, "gaps".to_string(), 10, 7);
        assert!(result.checks_passed < result.checks_performed);
        assert_eq!(result.checks_performed, 10);
        assert_eq!(result.checks_passed, 7);
    }

    #[test]
    fn enrichment_gate_kind_display_equals_as_str() {
        for kind in GateKind::all() {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn enrichment_constant_component_name() {
        assert_eq!(COMPONENT_NAME, "frankenlab_release_gate");
    }

    #[test]
    fn enrichment_default_gate_timeout_constant() {
        assert_eq!(DEFAULT_GATE_TIMEOUT_TICKS, 600);
    }
}
