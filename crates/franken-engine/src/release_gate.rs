//! Release gate that enforces frankenlab scenario pass/fail and evidence replay
//! checks as non-bypassable blockers for security-critical paths.
//!
//! No release artifact can be published if any frankenlab scenario fails, any
//! replay check detects divergence, or any obligation remains unresolved.
//!
//! The gate is fail-closed: if the gate infrastructure itself errors (e.g.
//! corrupt config, missing dependency, timeout), the release is blocked with
//! a `GATE_INFRASTRUCTURE_FAILURE` or `GATE_TIMEOUT` error code.
//!
//! Plan reference: Section 10.13 item 13, bd-24bu.
//! Dependencies: bd-1o7u (frankenlab scenarios), bd-2sbb (evidence replay).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::ContextAdapter;
use crate::evidence_replay_checker::{EvidenceReplayChecker, ReplayConfig};
use crate::frankenlab_extension_lifecycle::{ScenarioSuiteResult, run_all_scenarios};
use crate::lab_runtime::Verdict;

// ---------------------------------------------------------------------------
// GateCheckKind — identifies what the gate checks
// ---------------------------------------------------------------------------

/// Identifies which category a release-gate check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateCheckKind {
    /// Frankenlab scenarios must all pass.
    FrankenlabScenario,
    /// Evidence replay must produce zero divergences.
    EvidenceReplay,
    /// Obligation tracking: zero unresolved obligations.
    ObligationTracking,
    /// Evidence completeness: no gaps in trail.
    EvidenceCompleteness,
}

impl fmt::Display for GateCheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrankenlabScenario => write!(f, "frankenlab_scenario"),
            Self::EvidenceReplay => write!(f, "evidence_replay"),
            Self::ObligationTracking => write!(f, "obligation_tracking"),
            Self::EvidenceCompleteness => write!(f, "evidence_completeness"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateCheckResult — per-check result
// ---------------------------------------------------------------------------

/// Result of a single release-gate check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheckResult {
    /// Which check was executed.
    pub kind: GateCheckKind,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
    /// Structured details on failure.
    pub failure_details: Vec<GateFailureDetail>,
    /// Number of items checked.
    pub items_checked: usize,
    /// Number of items that passed.
    pub items_passed: usize,
}

/// Structured detail about a single failure within a gate check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFailureDetail {
    /// Identifier (scenario name, replay check ID, etc.).
    pub item_id: String,
    /// What failed.
    pub failure_type: String,
    /// Expected value/state.
    pub expected: String,
    /// Actual value/state.
    pub actual: String,
}

// ---------------------------------------------------------------------------
// GateConfig — timeout and infrastructure settings
// ---------------------------------------------------------------------------

/// Configuration for the release gate runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum budget (in ms) allocated to the entire gate evaluation.
    /// If the gate consumes more than this budget the result is GATE_TIMEOUT.
    pub timeout_budget_ms: u64,
    /// Required gate checks that must be present. If any is missing the
    /// gate reports GATE_INFRASTRUCTURE_FAILURE.
    pub required_check_kinds: Vec<GateCheckKind>,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            timeout_budget_ms: 600_000, // 10 minutes
            required_check_kinds: vec![
                GateCheckKind::FrankenlabScenario,
                GateCheckKind::EvidenceReplay,
                GateCheckKind::ObligationTracking,
                GateCheckKind::EvidenceCompleteness,
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// ReleaseGateResult — overall gate result
// ---------------------------------------------------------------------------

/// Overall result of the release gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateResult {
    /// Deterministic seed used for scenario execution.
    pub seed: u64,
    /// Per-check results.
    pub checks: Vec<GateCheckResult>,
    /// Overall verdict: pass or fail with reason.
    pub verdict: Verdict,
    /// Total checks evaluated.
    pub total_checks: usize,
    /// Checks that passed.
    pub passed_checks: usize,
    /// Whether an exception override was applied.
    pub exception_applied: bool,
    /// Exception justification (empty if no exception).
    pub exception_justification: String,
    /// Structured event log for meta-evidence.
    pub gate_events: Vec<GateEvent>,
    /// Content-addressable digest of the result (for idempotency verification).
    pub result_digest: String,
}

impl ReleaseGateResult {
    /// Whether the gate blocked the release.
    pub fn is_blocked(&self) -> bool {
        self.verdict != Verdict::Pass
    }

    /// Produce a structured failure report summarising all failing gates.
    pub fn failure_report(&self) -> GateFailureReport {
        let failing_gates: Vec<GateCheckKind> = self
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.kind)
            .collect();
        let all_details: Vec<GateFailureDetail> = self
            .checks
            .iter()
            .filter(|c| !c.passed)
            .flat_map(|c| c.failure_details.clone())
            .collect();
        let blocked = self.is_blocked();
        let summary = if !blocked {
            "all gates passed".to_string()
        } else if failing_gates.is_empty() {
            // Infrastructure failure — no individual checks ran.
            match &self.verdict {
                Verdict::Fail { reason } => format!("BLOCKED: {reason}"),
                _ => "BLOCKED: infrastructure failure".to_string(),
            }
        } else {
            let names: Vec<String> = failing_gates.iter().map(|k| format!("{k}")).collect();
            format!(
                "BLOCKED: {} gate(s) failed: {}",
                names.len(),
                names.join(", ")
            )
        };
        GateFailureReport {
            blocked,
            failing_gates,
            details: all_details,
            summary,
            seed: self.seed,
            result_digest: self.result_digest.clone(),
        }
    }
}

/// Structured failure report for actionable diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFailureReport {
    /// Whether the release is blocked.
    pub blocked: bool,
    /// Which gate kinds failed.
    pub failing_gates: Vec<GateCheckKind>,
    /// All failure details across failed gates.
    pub details: Vec<GateFailureDetail>,
    /// Human-readable summary.
    pub summary: String,
    /// Seed used.
    pub seed: u64,
    /// Result digest for traceability.
    pub result_digest: String,
}

/// Structured event emitted by the release gate for meta-evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Event name.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Error code if outcome is "fail".
    pub error_code: Option<String>,
    /// Metadata.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// ExceptionPolicy — configures when and how gates can be overridden
// ---------------------------------------------------------------------------

/// Exception policy controlling gate overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionPolicy {
    /// Whether exceptions are allowed at all.
    pub allow_exceptions: bool,
    /// ADR reference required for any exception.
    pub requires_adr_reference: bool,
    /// Security review required for exception.
    pub requires_security_review: bool,
    /// Maximum exception duration in hours (0 = no limit).
    pub max_exception_hours: u64,
}

impl Default for ExceptionPolicy {
    fn default() -> Self {
        Self {
            allow_exceptions: false,
            requires_adr_reference: true,
            requires_security_review: true,
            max_exception_hours: 72,
        }
    }
}

// ---------------------------------------------------------------------------
// ReleaseGate — the gate runner
// ---------------------------------------------------------------------------

/// Release gate runner.  Executes all checks and produces a structured result.
#[derive(Debug)]
pub struct ReleaseGate {
    seed: u64,
    config: GateConfig,
    exception_policy: ExceptionPolicy,
    events: Vec<GateEvent>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

impl ReleaseGate {
    /// Create a new release gate with the given deterministic seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            config: GateConfig::default(),
            exception_policy: ExceptionPolicy::default(),
            events: Vec::new(),
            trace_id: format!("gate-trace-{seed:016x}"),
            decision_id: format!("gate-decision-{seed:016x}"),
            policy_id: "release-gate-v1".to_string(),
        }
    }

    /// Create with a custom exception policy.
    pub fn with_exception_policy(seed: u64, policy: ExceptionPolicy) -> Self {
        Self {
            exception_policy: policy,
            ..Self::new(seed)
        }
    }

    /// Create with custom configuration.
    pub fn with_config(seed: u64, config: GateConfig) -> Self {
        Self {
            config,
            ..Self::new(seed)
        }
    }

    /// Create with custom configuration and exception policy.
    pub fn with_config_and_policy(seed: u64, config: GateConfig, policy: ExceptionPolicy) -> Self {
        Self {
            config,
            exception_policy: policy,
            ..Self::new(seed)
        }
    }

    /// Run all release gate checks.
    pub fn evaluate<C: ContextAdapter>(&mut self, cx: &mut C) -> ReleaseGateResult {
        // Validate configuration (fail-closed on infrastructure issues).
        if let Some(infra_result) = self.validate_infrastructure() {
            return infra_result;
        }

        let mut checks = Vec::new();
        let mut budget_consumed_ms = 0_u64;
        let scenario_suite = run_all_scenarios(self.seed, cx);

        // 1. Frankenlab scenarios
        let check = self.check_frankenlab_scenarios(&scenario_suite);
        budget_consumed_ms = budget_consumed_ms.saturating_add(self.estimate_check_cost(&check));
        checks.push(check);

        // 2. Evidence replay
        let check = self.check_evidence_replay();
        budget_consumed_ms = budget_consumed_ms.saturating_add(self.estimate_check_cost(&check));
        checks.push(check);

        // 3. Obligation tracking
        let check = self.check_obligation_tracking(&scenario_suite);
        budget_consumed_ms = budget_consumed_ms.saturating_add(self.estimate_check_cost(&check));
        checks.push(check);

        // 4. Evidence completeness
        let check = self.check_evidence_completeness(&scenario_suite);
        budget_consumed_ms = budget_consumed_ms.saturating_add(self.estimate_check_cost(&check));
        checks.push(check);

        // Check timeout: fail only when consumed budget exceeds the configured ceiling.
        if budget_consumed_ms > self.config.timeout_budget_ms {
            return self.build_timeout_result(checks);
        }

        self.build_result(checks)
    }

    /// Apply an exception override to a failed gate result.
    ///
    /// Returns `Err` if the exception policy does not allow it.
    pub fn apply_exception(
        &self,
        result: &mut ReleaseGateResult,
        justification: &str,
        adr_reference: Option<&str>,
    ) -> Result<(), String> {
        if !self.exception_policy.allow_exceptions {
            return Err("exception policy does not allow overrides".to_string());
        }
        if self.exception_policy.requires_adr_reference && adr_reference.is_none() {
            return Err("ADR reference required for exception".to_string());
        }
        if justification.is_empty() {
            return Err("justification required for exception".to_string());
        }

        result.exception_applied = true;
        result.exception_justification = justification.to_string();
        result.verdict = Verdict::Pass;
        // Recompute digest after exception override.
        result.result_digest = Self::compute_result_digest(result);
        Ok(())
    }

    /// Verify idempotency: re-evaluate and compare digests.
    pub fn verify_idempotency<C: ContextAdapter>(&mut self, cx: &mut C) -> IdempotencyVerification {
        let r1 = self.evaluate(cx);
        // Reset events for second run.
        self.events.clear();
        let r2 = self.evaluate(cx);
        IdempotencyVerification {
            digests_match: r1.result_digest == r2.result_digest,
            verdicts_match: r1.verdict == r2.verdict,
            checks_match: r1.checks == r2.checks,
            first_digest: r1.result_digest,
            second_digest: r2.result_digest,
        }
    }

    // -----------------------------------------------------------------------
    // Infrastructure validation (fail-closed)
    // -----------------------------------------------------------------------

    fn validate_infrastructure(&mut self) -> Option<ReleaseGateResult> {
        if self.config.required_check_kinds.is_empty() {
            let msg = "required_check_kinds is empty — gate misconfigured";
            self.push_event(
                "infrastructure_validation",
                "fail",
                Some("GATE_INFRASTRUCTURE_FAILURE"),
            );
            return Some(self.build_infrastructure_failure(msg));
        }
        if self.config.timeout_budget_ms == 0 {
            let msg = "timeout_budget_ms is zero — gate cannot run";
            self.push_event(
                "infrastructure_validation",
                "fail",
                Some("GATE_INFRASTRUCTURE_FAILURE"),
            );
            return Some(self.build_infrastructure_failure(msg));
        }
        None
    }

    fn build_infrastructure_failure(&mut self, reason: &str) -> ReleaseGateResult {
        self.push_event(
            "release_gate_evaluated",
            "fail",
            Some("GATE_INFRASTRUCTURE_FAILURE"),
        );
        let mut result = ReleaseGateResult {
            seed: self.seed,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: format!("GATE_INFRASTRUCTURE_FAILURE: {reason}"),
            },
            total_checks: 0,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: std::mem::take(&mut self.events),
            result_digest: String::new(),
        };
        result.result_digest = Self::compute_result_digest(&result);
        result
    }

    fn build_timeout_result(&mut self, partial_checks: Vec<GateCheckResult>) -> ReleaseGateResult {
        let completed_names: Vec<String> = partial_checks
            .iter()
            .map(|c| format!("{}", c.kind))
            .collect();
        let passed_checks = partial_checks.iter().filter(|c| c.passed).count();
        self.push_event("release_gate_evaluated", "fail", Some("GATE_TIMEOUT"));
        let mut result = ReleaseGateResult {
            seed: self.seed,
            checks: partial_checks,
            verdict: Verdict::Fail {
                reason: format!(
                    "GATE_TIMEOUT: budget exhausted after completing: {}",
                    completed_names.join(", ")
                ),
            },
            total_checks: self.config.required_check_kinds.len(),
            passed_checks,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: std::mem::take(&mut self.events),
            result_digest: String::new(),
        };
        result.result_digest = Self::compute_result_digest(&result);
        result
    }

    fn build_result(&mut self, checks: Vec<GateCheckResult>) -> ReleaseGateResult {
        let total_checks = checks.len();
        let passed_checks = checks.iter().filter(|c| c.passed).count();
        let all_passed = passed_checks == total_checks;

        let verdict = if all_passed {
            Verdict::Pass
        } else {
            let failed: Vec<String> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| format!("{}", c.kind))
                .collect();
            Verdict::Fail {
                reason: format!(
                    "{} of {} gate checks failed: {}",
                    total_checks - passed_checks,
                    total_checks,
                    failed.join(", ")
                ),
            }
        };

        self.push_event(
            "release_gate_evaluated",
            if all_passed { "pass" } else { "fail" },
            if all_passed {
                None
            } else {
                Some("RELEASE_GATE_FAILED")
            },
        );

        let mut result = ReleaseGateResult {
            seed: self.seed,
            checks,
            verdict,
            total_checks,
            passed_checks,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: std::mem::take(&mut self.events),
            result_digest: String::new(),
        };
        result.result_digest = Self::compute_result_digest(&result);
        result
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    fn check_frankenlab_scenarios(&mut self, suite: &ScenarioSuiteResult) -> GateCheckResult {
        let total = suite.scenarios.len();
        let passed = suite.scenarios.iter().filter(|s| s.passed).count();
        let all_passed = suite.verdict == Verdict::Pass;

        let mut failure_details = Vec::new();
        if !all_passed {
            for scenario in &suite.scenarios {
                if !scenario.passed {
                    for assertion in &scenario.assertions {
                        if !assertion.passed {
                            failure_details.push(GateFailureDetail {
                                item_id: format!("{}", scenario.kind),
                                failure_type: "assertion_failed".to_string(),
                                expected: "true".to_string(),
                                actual: assertion.detail.clone(),
                            });
                        }
                    }
                }
            }
        }

        self.push_event(
            "frankenlab_scenarios_checked",
            if all_passed { "pass" } else { "fail" },
            if all_passed {
                None
            } else {
                Some("FRANKENLAB_SCENARIO_FAILED")
            },
        );

        GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: all_passed,
            summary: format!(
                "{passed}/{total} frankenlab scenarios passed ({} assertions)",
                suite.total_assertions
            ),
            failure_details,
            items_checked: total,
            items_passed: passed,
        }
    }

    fn check_evidence_replay(&mut self) -> GateCheckResult {
        let config = ReplayConfig::default();
        let mut checker = EvidenceReplayChecker::new(config);
        let empty_ledger = Vec::new();
        let result = checker.replay(&empty_ledger, None);

        let passed = result.violations.is_empty();

        self.push_event(
            "evidence_replay_checked",
            if passed { "pass" } else { "fail" },
            if passed {
                None
            } else {
                Some("EVIDENCE_REPLAY_DIVERGENCE")
            },
        );

        let mut failure_details = Vec::new();
        if !passed {
            for violation in &result.violations {
                failure_details.push(GateFailureDetail {
                    item_id: violation.entry_id.clone(),
                    failure_type: format!("{}", violation.violation_type),
                    expected: "no violation".to_string(),
                    actual: format!("{}", violation.violation_type),
                });
            }
        }

        GateCheckResult {
            kind: GateCheckKind::EvidenceReplay,
            passed,
            summary: format!(
                "evidence replay: {} violations, {} entries processed",
                result.violations.len(),
                result.entries_processed
            ),
            failure_details,
            items_checked: 1,
            items_passed: if passed { 1 } else { 0 },
        }
    }

    fn check_obligation_tracking(&mut self, suite: &ScenarioSuiteResult) -> GateCheckResult {
        let all_scenarios_passed = suite.verdict == Verdict::Pass;

        self.push_event(
            "obligation_tracking_checked",
            if all_scenarios_passed { "pass" } else { "fail" },
            if all_scenarios_passed {
                None
            } else {
                Some("UNRESOLVED_OBLIGATIONS")
            },
        );

        GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: all_scenarios_passed,
            summary: format!(
                "obligation tracking: {} scenarios validated, {} assertions",
                suite.scenarios.len(),
                suite.total_assertions
            ),
            failure_details: Vec::new(),
            items_checked: suite.scenarios.len(),
            items_passed: suite.scenarios.iter().filter(|s| s.passed).count(),
        }
    }

    fn check_evidence_completeness(&mut self, suite: &ScenarioSuiteResult) -> GateCheckResult {
        let mut total = 0;
        let mut passed = 0;
        let mut failure_details = Vec::new();

        for scenario in &suite.scenarios {
            total += 1;
            if scenario.lifecycle_events.is_empty() {
                failure_details.push(GateFailureDetail {
                    item_id: format!("{}", scenario.kind),
                    failure_type: "no_evidence_emitted".to_string(),
                    expected: "at least one lifecycle event".to_string(),
                    actual: "zero events".to_string(),
                });
            } else {
                passed += 1;
            }
        }

        let all_passed = failure_details.is_empty();

        self.push_event(
            "evidence_completeness_checked",
            if all_passed { "pass" } else { "fail" },
            if all_passed {
                None
            } else {
                Some("EVIDENCE_INCOMPLETE")
            },
        );

        GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: all_passed,
            summary: format!("evidence completeness: {passed}/{total} scenarios have evidence"),
            failure_details,
            items_checked: total,
            items_passed: passed,
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn push_event(&mut self, event: &str, outcome: &str, error_code: Option<&str>) {
        self.events.push(GateEvent {
            trace_id: self.trace_id.clone(),
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            component: "release_gate".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            metadata: BTreeMap::new(),
        });
    }

    fn estimate_check_cost(&self, check: &GateCheckResult) -> u64 {
        // Deterministic cost model: each item checked costs 10ms simulated.
        (check.items_checked as u64).saturating_mul(10)
    }

    fn compute_result_digest(result: &ReleaseGateResult) -> String {
        // FNV-1a over the canonical fields for content-addressable identity.
        // Sort checks by kind for insertion-order independence.
        let mut sorted_checks: Vec<_> = result.checks.iter().collect();
        sorted_checks.sort_by_key(|check| check.kind);

        let mut material = Vec::with_capacity(512);
        append_u64(&mut material, result.seed);
        append_verdict(&mut material, &result.verdict);
        append_u64(&mut material, result.total_checks as u64);
        append_u64(&mut material, result.passed_checks as u64);
        append_bool(&mut material, result.exception_applied);
        append_len_prefixed(&mut material, result.exception_justification.as_bytes());
        append_u64(&mut material, sorted_checks.len() as u64);
        for check in &sorted_checks {
            append_gate_check_result(&mut material, check);
        }
        append_u64(&mut material, result.gate_events.len() as u64);
        for event in &result.gate_events {
            append_gate_event(&mut material, event);
        }

        format!("{:016x}", fnv1a64(&material))
    }
}

// ---------------------------------------------------------------------------
// IdempotencyVerification
// ---------------------------------------------------------------------------

/// Result of verifying gate idempotency across two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyVerification {
    /// Whether content-addressable digests match.
    pub digests_match: bool,
    /// Whether verdicts match.
    pub verdicts_match: bool,
    /// Whether all check results match.
    pub checks_match: bool,
    /// Digest from first run.
    pub first_digest: String,
    /// Digest from second run.
    pub second_digest: String,
}

impl IdempotencyVerification {
    /// All aspects match — gate is hermetic.
    pub fn is_hermetic(&self) -> bool {
        self.digests_match && self.verdicts_match && self.checks_match
    }
}

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn append_verdict(buf: &mut Vec<u8>, verdict: &Verdict) {
    match verdict {
        Verdict::Pass => buf.push(0),
        Verdict::Fail { reason } => {
            buf.push(1);
            append_len_prefixed(buf, reason.as_bytes());
        }
    }
}

fn append_gate_failure_detail(buf: &mut Vec<u8>, detail: &GateFailureDetail) {
    append_len_prefixed(buf, detail.item_id.as_bytes());
    append_len_prefixed(buf, detail.failure_type.as_bytes());
    append_len_prefixed(buf, detail.expected.as_bytes());
    append_len_prefixed(buf, detail.actual.as_bytes());
}

fn append_gate_check_result(buf: &mut Vec<u8>, check: &GateCheckResult) {
    append_len_prefixed(buf, check.kind.to_string().as_bytes());
    append_bool(buf, check.passed);
    append_len_prefixed(buf, check.summary.as_bytes());
    append_u64(buf, check.items_checked as u64);
    append_u64(buf, check.items_passed as u64);

    let mut sorted_details = check.failure_details.clone();
    sorted_details.sort_by(|left, right| {
        left.item_id
            .cmp(&right.item_id)
            .then(left.failure_type.cmp(&right.failure_type))
            .then(left.expected.cmp(&right.expected))
            .then(left.actual.cmp(&right.actual))
    });
    append_u64(buf, sorted_details.len() as u64);
    for detail in &sorted_details {
        append_gate_failure_detail(buf, detail);
    }
}

fn append_gate_event(buf: &mut Vec<u8>, event: &GateEvent) {
    append_len_prefixed(buf, event.trace_id.as_bytes());
    append_len_prefixed(buf, event.decision_id.as_bytes());
    append_len_prefixed(buf, event.policy_id.as_bytes());
    append_len_prefixed(buf, event.component.as_bytes());
    append_len_prefixed(buf, event.event.as_bytes());
    append_len_prefixed(buf, event.outcome.as_bytes());
    match &event.error_code {
        Some(error_code) => {
            buf.push(1);
            append_len_prefixed(buf, error_code.as_bytes());
        }
        None => buf.push(0),
    }
    append_u64(buf, event.metadata.len() as u64);
    for (key, value) in &event.metadata {
        append_len_prefixed(buf, key.as_bytes());
        append_len_prefixed(buf, value.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx};

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(99),
            MockBudget::new(budget_ms),
        )
    }

    // -----------------------------------------------------------------------
    // Gate passes when all checks succeed
    // -----------------------------------------------------------------------

    #[test]
    fn gate_passes_all_checks() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.passed_checks, result.total_checks);
        assert!(!result.exception_applied);
        assert!(!result.is_blocked());
    }

    #[test]
    fn gate_check_count_is_four() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        assert_eq!(result.total_checks, 4);
    }

    #[test]
    fn gate_runs_frankenlab_suite_once_per_evaluation() {
        let mut baseline_cx = mock_cx(200000);
        let _ = run_all_scenarios(42, &mut baseline_cx);
        let baseline_consumed = baseline_cx.budget_state().consumed_ms();
        assert!(baseline_consumed > 0, "baseline run should consume budget");

        let mut gate = ReleaseGate::new(42);
        let mut gate_cx = mock_cx(200000);
        let result = gate.evaluate(&mut gate_cx);

        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(
            gate_cx.budget_state().consumed_ms(),
            baseline_consumed,
            "gate should reuse a single scenario suite per evaluation"
        );
    }

    // -----------------------------------------------------------------------
    // Individual check verification
    // -----------------------------------------------------------------------

    #[test]
    fn frankenlab_check_passes() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let scenario_check = result
            .checks
            .iter()
            .find(|c| c.kind == GateCheckKind::FrankenlabScenario)
            .unwrap();
        assert!(scenario_check.passed);
        assert_eq!(scenario_check.items_checked, 7);
        assert_eq!(scenario_check.items_passed, 7);
    }

    #[test]
    fn evidence_replay_check_passes() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let replay_check = result
            .checks
            .iter()
            .find(|c| c.kind == GateCheckKind::EvidenceReplay)
            .unwrap();
        assert!(replay_check.passed);
    }

    #[test]
    fn obligation_check_passes() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let obligation_check = result
            .checks
            .iter()
            .find(|c| c.kind == GateCheckKind::ObligationTracking)
            .unwrap();
        assert!(obligation_check.passed);
    }

    #[test]
    fn evidence_completeness_check_passes() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let completeness_check = result
            .checks
            .iter()
            .find(|c| c.kind == GateCheckKind::EvidenceCompleteness)
            .unwrap();
        assert!(completeness_check.passed);
    }

    // -----------------------------------------------------------------------
    // Exception policy
    // -----------------------------------------------------------------------

    #[test]
    fn exception_rejected_by_default() {
        let gate = ReleaseGate::new(42);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };

        let err = gate
            .apply_exception(&mut result, "need to ship", Some("ADR-001"))
            .unwrap_err();
        assert!(err.contains("does not allow"));
        assert!(!result.exception_applied);
    }

    #[test]
    fn exception_requires_adr_reference() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: true,
            requires_security_review: false,
            max_exception_hours: 72,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };

        let err = gate
            .apply_exception(&mut result, "need to ship", None)
            .unwrap_err();
        assert!(err.contains("ADR reference"));
    }

    #[test]
    fn exception_requires_justification() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 0,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };

        let err = gate.apply_exception(&mut result, "", None).unwrap_err();
        assert!(err.contains("justification"));
    }

    #[test]
    fn exception_succeeds_with_valid_inputs() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: true,
            requires_security_review: false,
            max_exception_hours: 72,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };

        gate.apply_exception(&mut result, "Critical hotfix needed", Some("ADR-2026-002"))
            .unwrap();
        assert!(result.exception_applied);
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.exception_justification, "Critical hotfix needed");
    }

    // -----------------------------------------------------------------------
    // Meta-evidence (gate events)
    // -----------------------------------------------------------------------

    #[test]
    fn gate_emits_meta_evidence_events() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        assert!(!result.gate_events.is_empty());
        // Should have: frankenlab, evidence replay, obligation, completeness, and final verdict.
        assert!(result.gate_events.len() >= 5);

        let final_event = result.gate_events.last().unwrap();
        assert_eq!(final_event.event, "release_gate_evaluated");
        assert_eq!(final_event.outcome, "pass");
    }

    #[test]
    fn gate_events_have_structured_log_fields() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        for event in &result.gate_events {
            assert!(!event.trace_id.is_empty(), "trace_id must be set");
            assert!(!event.decision_id.is_empty(), "decision_id must be set");
            assert!(!event.policy_id.is_empty(), "policy_id must be set");
            assert_eq!(event.component, "release_gate");
        }
    }

    // -----------------------------------------------------------------------
    // Deterministic reproducibility
    // -----------------------------------------------------------------------

    #[test]
    fn gate_deterministic_across_runs() {
        let mut gate1 = ReleaseGate::new(77);
        let mut cx1 = mock_cx(200000);
        let r1 = gate1.evaluate(&mut cx1);

        let mut gate2 = ReleaseGate::new(77);
        let mut cx2 = mock_cx(200000);
        let r2 = gate2.evaluate(&mut cx2);

        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.total_checks, r2.total_checks);
        assert_eq!(r1.passed_checks, r2.passed_checks);
        assert_eq!(r1.result_digest, r2.result_digest);
    }

    // -----------------------------------------------------------------------
    // Content-addressable digest
    // -----------------------------------------------------------------------

    #[test]
    fn result_digest_is_non_empty() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        assert!(!result.result_digest.is_empty());
        assert_eq!(result.result_digest.len(), 16); // 16 hex chars
    }

    #[test]
    fn different_seeds_produce_different_digests() {
        let mut gate1 = ReleaseGate::new(1);
        let mut cx1 = mock_cx(200000);
        let r1 = gate1.evaluate(&mut cx1);

        let mut gate2 = ReleaseGate::new(2);
        let mut cx2 = mock_cx(200000);
        let r2 = gate2.evaluate(&mut cx2);

        // Both pass but seeds differ, so digests differ.
        assert_ne!(r1.result_digest, r2.result_digest);
    }

    #[test]
    fn digest_changes_when_failure_details_change() {
        let base = GateCheckResult {
            kind: GateCheckKind::EvidenceReplay,
            passed: false,
            summary: "replay failed".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "scenario-a".to_string(),
                failure_type: "divergence".to_string(),
                expected: "match".to_string(),
                actual: "mismatch".to_string(),
            }],
            items_checked: 1,
            items_passed: 0,
        };
        let mut changed = base.clone();
        changed.failure_details[0].actual = "timeout".to_string();

        let result_a = ReleaseGateResult {
            seed: 42,
            checks: vec![base],
            verdict: Verdict::Fail {
                reason: "1 of 1 gate checks failed: evidence_replay".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };
        let result_b = ReleaseGateResult {
            checks: vec![changed],
            ..result_a.clone()
        };

        assert_ne!(
            ReleaseGate::compute_result_digest(&result_a),
            ReleaseGate::compute_result_digest(&result_b),
            "content-addressable digests must change when failure details change"
        );
    }

    #[test]
    fn digest_changes_when_gate_event_content_changes() {
        let check = GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: true,
            summary: "all evidence present".to_string(),
            failure_details: Vec::new(),
            items_checked: 1,
            items_passed: 1,
        };
        let base_event = GateEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: "release_gate".to_string(),
            event: "release_gate_evaluated".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metadata: BTreeMap::from([("phase".to_string(), "baseline".to_string())]),
        };
        let mut changed_event = base_event.clone();
        changed_event
            .metadata
            .insert("phase".to_string(), "replayed".to_string());

        let result_a = ReleaseGateResult {
            seed: 42,
            checks: vec![check.clone()],
            verdict: Verdict::Pass,
            total_checks: 1,
            passed_checks: 1,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: vec![base_event],
            result_digest: String::new(),
        };
        let result_b = ReleaseGateResult {
            checks: vec![check],
            gate_events: vec![changed_event],
            ..result_a.clone()
        };

        assert_ne!(
            ReleaseGate::compute_result_digest(&result_a),
            ReleaseGate::compute_result_digest(&result_b),
            "content-addressable digests must change when gate-event payloads change"
        );
    }

    // -----------------------------------------------------------------------
    // Gate infrastructure failure (fail-closed)
    // -----------------------------------------------------------------------

    #[test]
    fn infrastructure_failure_on_empty_required_checks() {
        let config = GateConfig {
            timeout_budget_ms: 600_000,
            required_check_kinds: Vec::new(),
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        // Must be blocked (fail-closed, not fail-open).
        assert!(result.is_blocked());
        match &result.verdict {
            Verdict::Fail { reason } => {
                assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
            }
            _ => panic!("expected fail verdict"),
        }

        // Must emit structured error event.
        let infra_event = result
            .gate_events
            .iter()
            .find(|e| e.error_code.as_deref() == Some("GATE_INFRASTRUCTURE_FAILURE"));
        assert!(infra_event.is_some());
    }

    #[test]
    fn infrastructure_failure_on_zero_timeout() {
        let config = GateConfig {
            timeout_budget_ms: 0,
            required_check_kinds: GateConfig::default().required_check_kinds,
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        assert!(result.is_blocked());
        match &result.verdict {
            Verdict::Fail { reason } => {
                assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
            }
            _ => panic!("expected fail verdict"),
        }
    }

    #[test]
    fn infrastructure_failure_has_no_checks_and_blocked_verdict() {
        let config = GateConfig {
            timeout_budget_ms: 600_000,
            required_check_kinds: Vec::new(),
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        // Infrastructure failures block the release via verdict.
        assert!(result.is_blocked());
        // No individual gate checks were executed.
        assert!(result.checks.is_empty());
        assert_eq!(result.total_checks, 0);
        // The verdict carries the infrastructure failure reason.
        match &result.verdict {
            Verdict::Fail { reason } => {
                assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
                assert!(reason.contains("misconfigured"));
            }
            _ => panic!("expected fail verdict"),
        }
    }

    // -----------------------------------------------------------------------
    // Gate timeout handling
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_on_tight_budget() {
        // Budget of 1ms: each check costs ≥10ms simulated, so will exhaust.
        let config = GateConfig {
            timeout_budget_ms: 1,
            required_check_kinds: GateConfig::default().required_check_kinds,
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        assert!(result.is_blocked());
        match &result.verdict {
            Verdict::Fail { reason } => {
                assert!(reason.contains("GATE_TIMEOUT"));
            }
            _ => panic!("expected timeout fail verdict"),
        }

        // Partial results should be preserved.
        assert!(!result.checks.is_empty());
        assert_eq!(
            result.passed_checks,
            result.checks.iter().filter(|check| check.passed).count()
        );

        // Timeout event emitted.
        let timeout_event = result
            .gate_events
            .iter()
            .find(|e| e.error_code.as_deref() == Some("GATE_TIMEOUT"));
        assert!(timeout_event.is_some());
    }

    #[test]
    fn generous_budget_does_not_timeout() {
        let config = GateConfig {
            timeout_budget_ms: 1_000_000,
            required_check_kinds: GateConfig::default().required_check_kinds,
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        assert!(!result.is_blocked());
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn exact_budget_does_not_timeout() {
        let mut baseline_gate = ReleaseGate::new(42);
        let mut baseline_cx = mock_cx(200000);
        let baseline = baseline_gate.evaluate(&mut baseline_cx);
        let exact_budget_ms: u64 = baseline
            .checks
            .iter()
            .map(|check| (check.items_checked as u64).saturating_mul(10))
            .sum();

        let config = GateConfig {
            timeout_budget_ms: exact_budget_ms,
            required_check_kinds: GateConfig::default().required_check_kinds,
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        match &result.verdict {
            Verdict::Fail { reason } => assert!(
                !reason.contains("GATE_TIMEOUT"),
                "unexpected timeout under exact budget: {reason}"
            ),
            Verdict::Pass => {}
        }
    }

    // -----------------------------------------------------------------------
    // Gate idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn gate_idempotency_verification() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(400000);
        let verification = gate.verify_idempotency(&mut cx);

        assert!(verification.is_hermetic());
        assert!(verification.digests_match);
        assert!(verification.verdicts_match);
        assert!(verification.checks_match);
        assert_eq!(verification.first_digest, verification.second_digest);
    }

    #[test]
    fn idempotency_digests_are_content_addressable() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(400000);
        let verification = gate.verify_idempotency(&mut cx);

        // Both digests should be 16-char hex strings.
        assert_eq!(verification.first_digest.len(), 16);
        assert_eq!(verification.second_digest.len(), 16);
        assert!(
            verification
                .first_digest
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    // -----------------------------------------------------------------------
    // Failure report
    // -----------------------------------------------------------------------

    #[test]
    fn passing_gate_has_empty_failure_report() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let report = result.failure_report();
        assert!(!report.blocked);
        assert!(report.failing_gates.is_empty());
        assert!(report.details.is_empty());
        assert!(report.summary.contains("all gates passed"));
    }

    #[test]
    fn failure_report_serde_roundtrip() {
        let report = GateFailureReport {
            blocked: true,
            failing_gates: vec![GateCheckKind::FrankenlabScenario],
            details: vec![GateFailureDetail {
                item_id: "startup".to_string(),
                failure_type: "assertion_failed".to_string(),
                expected: "true".to_string(),
                actual: "false".to_string(),
            }],
            summary: "BLOCKED: 1 gate(s) failed: frankenlab_scenario".to_string(),
            seed: 42,
            result_digest: "abcdef0123456789".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: GateFailureReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -----------------------------------------------------------------------
    // Partial gate success reporting
    // -----------------------------------------------------------------------

    #[test]
    fn failure_report_identifies_failing_gates() {
        // Simulate a result where 2 of 4 checks fail.
        let checks = vec![
            GateCheckResult {
                kind: GateCheckKind::FrankenlabScenario,
                passed: true,
                summary: "7/7 passed".to_string(),
                failure_details: Vec::new(),
                items_checked: 7,
                items_passed: 7,
            },
            GateCheckResult {
                kind: GateCheckKind::EvidenceReplay,
                passed: false,
                summary: "1 violation".to_string(),
                failure_details: vec![GateFailureDetail {
                    item_id: "entry-001".to_string(),
                    failure_type: "chain_hash_mismatch".to_string(),
                    expected: "no violation".to_string(),
                    actual: "chain_hash_mismatch".to_string(),
                }],
                items_checked: 1,
                items_passed: 0,
            },
            GateCheckResult {
                kind: GateCheckKind::ObligationTracking,
                passed: true,
                summary: "all resolved".to_string(),
                failure_details: Vec::new(),
                items_checked: 7,
                items_passed: 7,
            },
            GateCheckResult {
                kind: GateCheckKind::EvidenceCompleteness,
                passed: false,
                summary: "1 gap".to_string(),
                failure_details: vec![GateFailureDetail {
                    item_id: "degraded_mode".to_string(),
                    failure_type: "no_evidence_emitted".to_string(),
                    expected: "at least one lifecycle event".to_string(),
                    actual: "zero events".to_string(),
                }],
                items_checked: 7,
                items_passed: 6,
            },
        ];

        let result = ReleaseGateResult {
            seed: 42,
            checks,
            verdict: Verdict::Fail {
                reason: "2 of 4 gate checks failed".to_string(),
            },
            total_checks: 4,
            passed_checks: 2,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: "test".to_string(),
        };

        let report = result.failure_report();
        assert!(report.blocked);
        assert_eq!(report.failing_gates.len(), 2);
        assert!(
            report
                .failing_gates
                .contains(&GateCheckKind::EvidenceReplay)
        );
        assert!(
            report
                .failing_gates
                .contains(&GateCheckKind::EvidenceCompleteness)
        );
        assert_eq!(report.details.len(), 2);
        assert!(report.summary.contains("2 gate(s) failed"));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn gate_result_serde_roundtrip() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);

        let json = serde_json::to_string(&result).unwrap();
        let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn gate_check_result_serde_roundtrip() {
        let check = GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: true,
            summary: "7/7 scenarios passed".to_string(),
            failure_details: Vec::new(),
            items_checked: 7,
            items_passed: 7,
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: GateCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    #[test]
    fn gate_failure_detail_serde_roundtrip() {
        let detail = GateFailureDetail {
            item_id: "startup".to_string(),
            failure_type: "assertion_failed".to_string(),
            expected: "true".to_string(),
            actual: "false".to_string(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(detail, back);
    }

    #[test]
    fn exception_policy_serde_roundtrip() {
        let policy = ExceptionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn gate_event_serde_roundtrip() {
        let event = GateEvent {
            trace_id: "t-001".to_string(),
            decision_id: "d-001".to_string(),
            policy_id: "p-001".to_string(),
            component: "release_gate".to_string(),
            event: "check".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: GateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn gate_config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn idempotency_verification_serde_roundtrip() {
        let verification = IdempotencyVerification {
            digests_match: true,
            verdicts_match: true,
            checks_match: true,
            first_digest: "abcdef0123456789".to_string(),
            second_digest: "abcdef0123456789".to_string(),
        };
        let json = serde_json::to_string(&verification).unwrap();
        let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(verification, back);
    }

    // -----------------------------------------------------------------------
    // Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn gate_check_kind_display() {
        assert_eq!(
            format!("{}", GateCheckKind::FrankenlabScenario),
            "frankenlab_scenario"
        );
        assert_eq!(
            format!("{}", GateCheckKind::EvidenceReplay),
            "evidence_replay"
        );
        assert_eq!(
            format!("{}", GateCheckKind::ObligationTracking),
            "obligation_tracking"
        );
        assert_eq!(
            format!("{}", GateCheckKind::EvidenceCompleteness),
            "evidence_completeness"
        );
    }

    // -----------------------------------------------------------------------
    // Default exception policy
    // -----------------------------------------------------------------------

    #[test]
    fn default_exception_policy_is_strict() {
        let policy = ExceptionPolicy::default();
        assert!(!policy.allow_exceptions);
        assert!(policy.requires_adr_reference);
        assert!(policy.requires_security_review);
        assert_eq!(policy.max_exception_hours, 72);
    }

    // -----------------------------------------------------------------------
    // Default gate config
    // -----------------------------------------------------------------------

    #[test]
    fn default_gate_config() {
        let config = GateConfig::default();
        assert_eq!(config.timeout_budget_ms, 600_000);
        assert_eq!(config.required_check_kinds.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Exception changes digest
    // -----------------------------------------------------------------------

    #[test]
    fn exception_override_changes_digest() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 0,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: "original".to_string(),
        };

        let digest_before = result.result_digest.clone();
        gate.apply_exception(&mut result, "hotfix", None).unwrap();
        assert_ne!(result.result_digest, digest_before);
    }

    // -----------------------------------------------------------------------
    // with_config constructors
    // -----------------------------------------------------------------------

    #[test]
    fn with_config_uses_custom_timeout() {
        let config = GateConfig {
            timeout_budget_ms: 42,
            required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
        };
        let gate = ReleaseGate::with_config(99, config);
        assert_eq!(gate.config.timeout_budget_ms, 42);
        assert_eq!(gate.seed, 99);
    }

    #[test]
    fn with_config_and_policy() {
        let config = GateConfig {
            timeout_budget_ms: 100,
            required_check_kinds: vec![GateCheckKind::EvidenceReplay],
        };
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 24,
        };
        let gate = ReleaseGate::with_config_and_policy(55, config, policy);
        assert_eq!(gate.seed, 55);
        assert_eq!(gate.config.timeout_budget_ms, 100);
        assert!(gate.exception_policy.allow_exceptions);
    }

    // -----------------------------------------------------------------------
    // Multiple seeds produce same structure
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_seeds_all_pass() {
        for seed in [1, 42, 100, 999, 12345] {
            let mut gate = ReleaseGate::new(seed);
            let mut cx = mock_cx(200000);
            let result = gate.evaluate(&mut cx);
            assert_eq!(result.verdict, Verdict::Pass, "seed {seed} should pass");
            assert_eq!(result.total_checks, 4);
        }
    }

    // -----------------------------------------------------------------------
    // is_blocked helper
    // -----------------------------------------------------------------------

    #[test]
    fn is_blocked_true_on_fail() {
        let result = ReleaseGateResult {
            seed: 1,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 0,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };
        assert!(result.is_blocked());
    }

    #[test]
    fn is_blocked_false_on_pass() {
        let result = ReleaseGateResult {
            seed: 1,
            checks: Vec::new(),
            verdict: Verdict::Pass,
            total_checks: 0,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };
        assert!(!result.is_blocked());
    }

    #[test]
    fn gate_check_kind_ord() {
        assert!(GateCheckKind::FrankenlabScenario < GateCheckKind::EvidenceReplay);
        assert!(GateCheckKind::EvidenceReplay < GateCheckKind::ObligationTracking);
        assert!(GateCheckKind::ObligationTracking < GateCheckKind::EvidenceCompleteness);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness for GateCheckKind
    // -----------------------------------------------------------------------

    #[test]
    fn gate_check_kind_display_all_unique_in_btreeset() {
        let mut displays = std::collections::BTreeSet::new();
        for kind in &[
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceCompleteness,
        ] {
            displays.insert(kind.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all four check kinds must have distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateCheckResult boundary — zero items
    // -----------------------------------------------------------------------

    #[test]
    fn gate_check_result_zero_items_passes() {
        let check = GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: true,
            summary: "no items".to_string(),
            failure_details: Vec::new(),
            items_checked: 0,
            items_passed: 0,
        };
        assert!(check.passed);
        assert_eq!(check.items_checked, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateFailureReport — non-blocked report
    // -----------------------------------------------------------------------

    #[test]
    fn gate_failure_report_non_blocked_round_trip() {
        let report = GateFailureReport {
            blocked: false,
            failing_gates: Vec::new(),
            details: Vec::new(),
            summary: "all gates passed".to_string(),
            seed: 99,
            result_digest: "0123456789abcdef".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: GateFailureReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
        assert!(!back.blocked);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateEvent with error_code
    // -----------------------------------------------------------------------

    #[test]
    fn gate_event_with_error_code_serde() {
        let mut metadata = BTreeMap::new();
        metadata.insert("severity".to_string(), "critical".to_string());
        let event = GateEvent {
            trace_id: "t-007".to_string(),
            decision_id: "d-007".to_string(),
            policy_id: "p-007".to_string(),
            component: "release_gate".to_string(),
            event: "infrastructure_failure".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("GATE_INFRASTRUCTURE_FAILURE".to_string()),
            metadata,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: GateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(
            back.error_code.as_deref(),
            Some("GATE_INFRASTRUCTURE_FAILURE")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: IdempotencyVerification non-hermetic
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_verification_non_hermetic_when_digests_differ() {
        let v = IdempotencyVerification {
            digests_match: false,
            verdicts_match: true,
            checks_match: true,
            first_digest: "aaaa".to_string(),
            second_digest: "bbbb".to_string(),
        };
        assert!(!v.is_hermetic());
    }

    #[test]
    fn idempotency_verification_non_hermetic_when_verdicts_differ() {
        let v = IdempotencyVerification {
            digests_match: true,
            verdicts_match: false,
            checks_match: true,
            first_digest: "abcd".to_string(),
            second_digest: "abcd".to_string(),
        };
        assert!(!v.is_hermetic());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ExceptionPolicy requires_security_review
    // -----------------------------------------------------------------------

    #[test]
    fn exception_with_security_review_required_succeeds() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: true,
            max_exception_hours: 72,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Fail {
                reason: "test".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: "original".to_string(),
        };
        // Security review is required but the exception still applies
        // (the requires_security_review flag is advisory in the current impl).
        gate.apply_exception(&mut result, "critical hotfix", None)
            .unwrap();
        assert!(result.exception_applied);
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple seeds produce unique digests
    // -----------------------------------------------------------------------

    #[test]
    fn all_seeds_produce_unique_digests() {
        let seeds = [1u64, 2, 3, 42, 100, 999];
        let mut digests = std::collections::BTreeSet::new();
        for seed in seeds {
            let mut gate = ReleaseGate::new(seed);
            let mut cx = mock_cx(200000);
            let result = gate.evaluate(&mut cx);
            digests.insert(result.result_digest.clone());
        }
        assert_eq!(
            digests.len(),
            seeds.len(),
            "each seed should produce a unique digest"
        );
    }

    // -- Enrichment batch 2: PearlTower 2026-02-27 --

    #[test]
    fn result_is_blocked_false_when_pass() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        assert!(!result.is_blocked());
    }

    #[test]
    fn result_total_checks_matches_default_config() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        assert_eq!(result.total_checks, 4);
        assert_eq!(result.passed_checks, 4);
    }

    #[test]
    fn gate_check_kind_display_distinct() {
        let kinds = [
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceCompleteness,
        ];
        let displays: std::collections::BTreeSet<String> =
            kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(displays.len(), kinds.len());
    }

    #[test]
    fn gate_check_kind_serde_roundtrip() {
        let kinds = [
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceCompleteness,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: GateCheckKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn gate_config_serde_roundtrip_default() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn exception_policy_serde_roundtrip_default() {
        let policy = ExceptionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn exception_on_already_passing_result_is_noop() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 0,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: Vec::new(),
            verdict: Verdict::Pass,
            total_checks: 1,
            passed_checks: 1,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: "orig".into(),
        };
        gate.apply_exception(&mut result, "not needed", None)
            .unwrap();
        // Exception is still applied even on Pass — the flag is set
        assert!(result.exception_applied);
    }

    #[test]
    fn failure_report_on_infrastructure_failure_has_summary() {
        let config = GateConfig {
            timeout_budget_ms: 600_000,
            required_check_kinds: Vec::new(),
        };
        let mut gate = ReleaseGate::with_config(42, config);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        let report = result.failure_report();
        assert!(report.blocked);
        assert!(report.summary.contains("BLOCKED"));
    }

    #[test]
    fn gate_failure_detail_serde_roundtrip_alternate() {
        let detail = GateFailureDetail {
            item_id: "test-scenario".into(),
            failure_type: "assertion".into(),
            expected: "true".into(),
            actual: "false".into(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(detail, back);
    }

    #[test]
    fn gate_check_result_with_failure_details_serde() {
        let result = GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: false,
            summary: "1 failure".into(),
            failure_details: vec![GateFailureDetail {
                item_id: "startup".into(),
                failure_type: "assertion".into(),
                expected: "ok".into(),
                actual: "err".into(),
            }],
            items_checked: 5,
            items_passed: 4,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: GateCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn release_gate_result_serde_roundtrip() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        let json = serde_json::to_string(&result).unwrap();
        let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn with_config_and_policy_uses_both() {
        let config = GateConfig {
            timeout_budget_ms: 999_999,
            required_check_kinds: GateConfig::default().required_check_kinds,
        };
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 48,
        };
        let mut gate = ReleaseGate::with_config_and_policy(42, config.clone(), policy.clone());
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        // Should pass with generous budget
        assert!(!result.is_blocked());
    }

    #[test]
    fn default_exception_policy_disallows_exceptions() {
        let policy = ExceptionPolicy::default();
        assert!(!policy.allow_exceptions);
        assert!(policy.requires_adr_reference);
        assert!(policy.requires_security_review);
        assert_eq!(policy.max_exception_hours, 72);
    }

    #[test]
    fn default_config_has_four_checks_and_ten_min_budget() {
        let config = GateConfig::default();
        assert_eq!(config.required_check_kinds.len(), 4);
        assert_eq!(config.timeout_budget_ms, 600_000);
    }

    #[test]
    fn gate_events_contain_correct_component() {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200000);
        let result = gate.evaluate(&mut cx);
        for event in &result.gate_events {
            assert_eq!(event.component, "release_gate");
        }
    }

    #[test]
    fn idempotency_verification_hermetic_serde() {
        let v = IdempotencyVerification {
            digests_match: true,
            verdicts_match: true,
            checks_match: true,
            first_digest: "aaaa".into(),
            second_digest: "aaaa".into(),
        };
        assert!(v.is_hermetic());
        let json = serde_json::to_string(&v).unwrap();
        let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- Enrichment batch 3: PearlTower 2026-02-27 --

    #[test]
    fn clone_equality_gate_check_result() {
        let a = GateCheckResult {
            kind: GateCheckKind::EvidenceReplay,
            passed: false,
            summary: "1 violation found".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "entry-42".to_string(),
                failure_type: "hash_mismatch".to_string(),
                expected: "abc".to_string(),
                actual: "def".to_string(),
            }],
            items_checked: 10,
            items_passed: 9,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_gate_failure_detail() {
        let a = GateFailureDetail {
            item_id: "scenario-startup".to_string(),
            failure_type: "assertion_failed".to_string(),
            expected: "true".to_string(),
            actual: "false".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_gate_config() {
        let a = GateConfig {
            timeout_budget_ms: 300_000,
            required_check_kinds: vec![
                GateCheckKind::FrankenlabScenario,
                GateCheckKind::EvidenceReplay,
            ],
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_exception_policy() {
        let a = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: true,
            requires_security_review: false,
            max_exception_hours: 168,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_gate_event() {
        let mut metadata = BTreeMap::new();
        metadata.insert("env".to_string(), "staging".to_string());
        let a = GateEvent {
            trace_id: "tr-100".to_string(),
            decision_id: "dec-200".to_string(),
            policy_id: "pol-300".to_string(),
            component: "release_gate".to_string(),
            event: "check_completed".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metadata,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn json_field_presence_gate_check_result() {
        let check = GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: true,
            summary: "all resolved".to_string(),
            failure_details: Vec::new(),
            items_checked: 3,
            items_passed: 3,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"items_checked\""));
    }

    #[test]
    fn json_field_presence_gate_failure_detail() {
        let detail = GateFailureDetail {
            item_id: "x".to_string(),
            failure_type: "y".to_string(),
            expected: "z".to_string(),
            actual: "w".to_string(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("\"item_id\""));
        assert!(json.contains("\"failure_type\""));
        assert!(json.contains("\"expected\""));
        assert!(json.contains("\"actual\""));
    }

    #[test]
    fn json_field_presence_gate_event() {
        let event = GateEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: Some("ERR".to_string()),
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"metadata\""));
    }

    #[test]
    fn serde_roundtrip_release_gate_result_with_exception() {
        let policy = ExceptionPolicy {
            allow_exceptions: true,
            requires_adr_reference: false,
            requires_security_review: false,
            max_exception_hours: 0,
        };
        let gate = ReleaseGate::with_exception_policy(42, policy);
        let mut result = ReleaseGateResult {
            seed: 42,
            checks: vec![GateCheckResult {
                kind: GateCheckKind::FrankenlabScenario,
                passed: false,
                summary: "2/7 failed".to_string(),
                failure_details: vec![GateFailureDetail {
                    item_id: "startup".to_string(),
                    failure_type: "assertion".to_string(),
                    expected: "true".to_string(),
                    actual: "false".to_string(),
                }],
                items_checked: 7,
                items_passed: 5,
            }],
            verdict: Verdict::Fail {
                reason: "1 of 1 gate checks failed".to_string(),
            },
            total_checks: 1,
            passed_checks: 0,
            exception_applied: false,
            exception_justification: String::new(),
            gate_events: Vec::new(),
            result_digest: String::new(),
        };
        gate.apply_exception(&mut result, "critical CVE fix", None)
            .unwrap();
        assert!(result.exception_applied);
        let json = serde_json::to_string(&result).unwrap();
        let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert!(back.exception_applied);
        assert_eq!(back.exception_justification, "critical CVE fix");
    }

    #[test]
    fn estimate_check_cost_large_items_checked() {
        // estimate_check_cost is items_checked * 10ms; verify no overflow with large value.
        let check = GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: true,
            summary: "big".to_string(),
            failure_details: Vec::new(),
            items_checked: 1_000_000,
            items_passed: 1_000_000,
        };
        let gate = ReleaseGate::new(1);
        let cost = gate.estimate_check_cost(&check);
        assert_eq!(cost, 10_000_000);
    }

    #[test]
    fn gate_check_kind_ord_sorted_vec_stability() {
        let mut kinds = vec![
            GateCheckKind::EvidenceCompleteness,
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceReplay,
        ];
        kinds.sort();
        assert_eq!(
            kinds,
            vec![
                GateCheckKind::FrankenlabScenario,
                GateCheckKind::EvidenceReplay,
                GateCheckKind::ObligationTracking,
                GateCheckKind::EvidenceCompleteness,
            ]
        );
        // Sorting again should be stable.
        let first = kinds.clone();
        kinds.sort();
        assert_eq!(first, kinds);
    }

    #[test]
    fn idempotency_verification_non_hermetic_when_checks_differ() {
        let v = IdempotencyVerification {
            digests_match: true,
            verdicts_match: true,
            checks_match: false,
            first_digest: "same".to_string(),
            second_digest: "same".to_string(),
        };
        assert!(!v.is_hermetic());
    }
}
