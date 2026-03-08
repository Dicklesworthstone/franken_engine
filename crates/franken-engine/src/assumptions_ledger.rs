//! [FRX-13.3] Assumptions Ledger, Falsification Monitors, and Deterministic Demotion
//!
//! Records assumptions active at compile-time and runtime decision points,
//! detects assumption violations via monitors, triggers deterministic
//! demotion/fallback when assumptions fail, and preserves replayability
//! of assumption state.
//!
//! Key abstractions:
//! - **Assumption**: A falsifiable predicate that a decision was conditioned on.
//! - **AssumptionLedger**: Append-only ledger of active/retired assumptions.
//! - **FalsificationMonitor**: Watches for assumption violations in real-time.
//! - **DemotionController**: Triggers deterministic demotion when assumptions fail.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Assumption Primitives ─────────────────────────────────────────────

/// Unique identifier for an assumption.
pub type AssumptionId = String;

/// Category of an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssumptionCategory {
    /// Statistical: distribution stationarity, calibration validity.
    Statistical,
    /// Behavioral: component compatibility, effect ordering.
    Behavioral,
    /// Resource: budget sufficiency, latency bounds.
    Resource,
    /// Safety: no adversarial presence, bounded nondeterminism.
    Safety,
    /// Structural: DAG topology, no cyclic dependencies.
    Structural,
}

/// When the assumption was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssumptionOrigin {
    /// Made at compile/synthesis time.
    CompileTime,
    /// Made at runtime decision point.
    Runtime,
    /// Inherited from an upstream policy or configuration.
    PolicyInherited,
    /// Inferred from observations (e.g., regime detection).
    Inferred,
}

/// Current status of an assumption.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssumptionStatus {
    /// Active and not yet violated.
    Active,
    /// Violated by monitor detection.
    Violated,
    /// Explicitly retired (no longer needed).
    Retired,
    /// Suspended pending investigation.
    Suspended,
}

/// A falsifiable assumption recorded in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assumption {
    pub id: AssumptionId,
    pub category: AssumptionCategory,
    pub origin: AssumptionOrigin,
    pub status: AssumptionStatus,
    /// Human-readable description of the assumption.
    pub description: String,
    /// The decision ID that introduced this assumption.
    pub decision_id: String,
    /// Epoch when the assumption was recorded.
    pub epoch: u64,
    /// Variables/nodes this assumption depends on.
    pub dependencies: BTreeSet<String>,
    /// Severity of violation: higher means more urgent demotion.
    pub violation_severity: ViolationSeverity,
    /// Content hash of the assumption predicate.
    pub predicate_hash: String,
}

/// Severity level for assumption violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Advisory: log but do not demote.
    Advisory,
    /// Warning: increase monitoring, consider demotion.
    Warning,
    /// Critical: immediate demotion required.
    Critical,
    /// Fatal: halt and enter safe mode.
    Fatal,
}

// ── Falsification Evidence ────────────────────────────────────────────

/// Evidence that an assumption was violated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsificationEvidence {
    pub assumption_id: AssumptionId,
    pub monitor_id: String,
    pub epoch: u64,
    pub tick: u64,
    /// The observed value that falsified the assumption (millionths).
    pub observed_value_millionths: i64,
    /// The threshold that was violated (millionths).
    pub threshold_millionths: i64,
    /// Human-readable explanation.
    pub explanation: String,
    /// Content hash of the evidence.
    pub evidence_hash: String,
}

// ── Falsification Monitor ─────────────────────────────────────────────

/// Type of monitor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MonitorKind {
    /// Threshold check: value must stay below/above a bound.
    Threshold,
    /// Drift check: distribution must remain stationary (KL-divergence).
    Drift,
    /// Coverage check: calibration coverage must hold.
    Coverage,
    /// Invariant check: a boolean predicate must hold.
    Invariant,
    /// Budget check: resource consumption within bounds.
    Budget,
}

/// Comparison operator for threshold monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MonitorOp {
    Le,
    Ge,
    Eq,
}

/// A monitor that watches for assumption violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsificationMonitor {
    pub monitor_id: String,
    pub assumption_id: AssumptionId,
    pub kind: MonitorKind,
    /// Variable being monitored.
    pub variable: String,
    /// Threshold or bound (millionths).
    pub threshold_millionths: i64,
    /// Comparison: the assumption holds while variable op threshold.
    pub op: MonitorOp,
    /// Number of consecutive violations before triggering.
    pub trigger_count: u32,
    /// Current consecutive violation count.
    pub current_violations: u32,
    /// Whether this monitor has triggered.
    pub triggered: bool,
}

impl FalsificationMonitor {
    /// Check a new observation against this monitor.
    /// Returns `Some(evidence)` if the assumption is falsified.
    pub fn check(
        &mut self,
        value_millionths: i64,
        epoch: u64,
        tick: u64,
    ) -> Option<FalsificationEvidence> {
        let holds = match self.op {
            MonitorOp::Le => value_millionths <= self.threshold_millionths,
            MonitorOp::Ge => value_millionths >= self.threshold_millionths,
            MonitorOp::Eq => value_millionths == self.threshold_millionths,
        };

        if holds {
            self.current_violations = 0;
            return None;
        }

        self.current_violations += 1;
        if self.current_violations >= self.trigger_count && !self.triggered {
            self.triggered = true;
            let evidence_hash = simple_hash(&format!(
                "{}_{epoch}_{tick}_{value_millionths}",
                self.monitor_id
            ));
            Some(FalsificationEvidence {
                assumption_id: self.assumption_id.clone(),
                monitor_id: self.monitor_id.clone(),
                epoch,
                tick,
                observed_value_millionths: value_millionths,
                threshold_millionths: self.threshold_millionths,
                explanation: format!(
                    "Monitor {}: observed {} violates {:?} {} (consecutive: {})",
                    self.monitor_id,
                    value_millionths,
                    self.op,
                    self.threshold_millionths,
                    self.current_violations
                ),
                evidence_hash,
            })
        } else {
            None
        }
    }

    /// Reset the monitor (e.g., after recovery).
    pub fn reset(&mut self) {
        self.current_violations = 0;
        self.triggered = false;
    }
}

// ── Demotion Actions ──────────────────────────────────────────────────

/// A demotion action triggered by assumption violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemotionAction {
    /// Switch to safe/fallback mode.
    EnterSafeMode { reason: String },
    /// Demote a specific lane/component.
    DemoteLane { lane_id: String, reason: String },
    /// Suspend adaptive routing, use conservative defaults.
    SuspendAdaptive { reason: String },
    /// Escalate to operator review.
    EscalateToOperator { reason: String },
    /// No action (advisory only).
    NoAction,
}

/// Record of a demotion event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionRecord {
    pub record_id: String,
    pub assumption_id: AssumptionId,
    pub evidence: FalsificationEvidence,
    pub action: DemotionAction,
    pub epoch: u64,
    pub severity: ViolationSeverity,
}

// ── Demotion Controller ───────────────────────────────────────────────

/// Policy for mapping violation severity to demotion actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionPolicy {
    pub advisory_action: DemotionAction,
    pub warning_action: DemotionAction,
    pub critical_action: DemotionAction,
    pub fatal_action: DemotionAction,
}

impl Default for DemotionPolicy {
    fn default() -> Self {
        Self {
            advisory_action: DemotionAction::NoAction,
            warning_action: DemotionAction::SuspendAdaptive {
                reason: "warning-level assumption violation".into(),
            },
            critical_action: DemotionAction::EnterSafeMode {
                reason: "critical assumption violation".into(),
            },
            fatal_action: DemotionAction::EnterSafeMode {
                reason: "fatal assumption violation — immediate safe mode".into(),
            },
        }
    }
}

/// Controller that maps assumption violations to deterministic demotion actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionController {
    policy: DemotionPolicy,
    records: Vec<DemotionRecord>,
    next_record_id: u64,
}

impl DemotionController {
    pub fn new(policy: DemotionPolicy) -> Self {
        Self {
            policy,
            records: Vec::new(),
            next_record_id: 0,
        }
    }

    /// Process a falsification event and return the demotion action.
    pub fn process_violation(
        &mut self,
        assumption: &Assumption,
        evidence: FalsificationEvidence,
    ) -> DemotionAction {
        let action = match assumption.violation_severity {
            ViolationSeverity::Advisory => self.policy.advisory_action.clone(),
            ViolationSeverity::Warning => self.policy.warning_action.clone(),
            ViolationSeverity::Critical => self.policy.critical_action.clone(),
            ViolationSeverity::Fatal => self.policy.fatal_action.clone(),
        };

        let record_id = format!("demotion_{}", self.next_record_id);
        self.next_record_id += 1;

        self.records.push(DemotionRecord {
            record_id,
            assumption_id: assumption.id.clone(),
            evidence,
            action: action.clone(),
            epoch: assumption.epoch,
            severity: assumption.violation_severity,
        });

        action
    }

    /// Get all demotion records.
    pub fn records(&self) -> &[DemotionRecord] {
        &self.records
    }

    /// Count of demotion events.
    pub fn demotion_count(&self) -> usize {
        self.records.len()
    }
}

// ── Assumptions Ledger ────────────────────────────────────────────────

/// Errors from ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    DuplicateAssumption(AssumptionId),
    AssumptionNotFound(AssumptionId),
    MonitorNotFound(String),
    DuplicateMonitor(String),
    InvalidTransition {
        assumption_id: AssumptionId,
        from: AssumptionStatus,
        to: AssumptionStatus,
    },
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateAssumption(id) => write!(f, "duplicate assumption: {id}"),
            Self::AssumptionNotFound(id) => write!(f, "assumption not found: {id}"),
            Self::MonitorNotFound(id) => write!(f, "monitor not found: {id}"),
            Self::DuplicateMonitor(id) => write!(f, "duplicate monitor: {id}"),
            Self::InvalidTransition {
                assumption_id,
                from,
                to,
            } => write!(
                f,
                "invalid transition for {assumption_id}: {from:?} -> {to:?}"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

/// The append-only assumptions ledger with falsification monitors and demotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionLedger {
    assumptions: BTreeMap<AssumptionId, Assumption>,
    monitors: BTreeMap<String, FalsificationMonitor>,
    demotion_controller: DemotionController,
    /// History of all falsification evidence (append-only).
    falsification_history: Vec<FalsificationEvidence>,
    /// Chain hash for tamper-evidence.
    chain_hash: String,
}

impl AssumptionLedger {
    /// Create a new empty ledger.
    pub fn new(demotion_policy: DemotionPolicy) -> Self {
        Self {
            assumptions: BTreeMap::new(),
            monitors: BTreeMap::new(),
            demotion_controller: DemotionController::new(demotion_policy),
            falsification_history: Vec::new(),
            chain_hash: simple_hash("genesis"),
        }
    }

    /// Record a new assumption.
    pub fn record_assumption(&mut self, assumption: Assumption) -> Result<(), LedgerError> {
        if self.assumptions.contains_key(&assumption.id) {
            return Err(LedgerError::DuplicateAssumption(assumption.id));
        }
        self.chain_hash = simple_hash(&format!("{}_{}", self.chain_hash, assumption.id));
        self.assumptions.insert(assumption.id.clone(), assumption);
        Ok(())
    }

    /// Register a falsification monitor for an assumption.
    pub fn register_monitor(&mut self, monitor: FalsificationMonitor) -> Result<(), LedgerError> {
        if !self.assumptions.contains_key(&monitor.assumption_id) {
            return Err(LedgerError::AssumptionNotFound(
                monitor.assumption_id.clone(),
            ));
        }
        if self.monitors.contains_key(&monitor.monitor_id) {
            return Err(LedgerError::DuplicateMonitor(monitor.monitor_id));
        }
        self.monitors.insert(monitor.monitor_id.clone(), monitor);
        Ok(())
    }

    /// Feed an observation to all monitors for a given variable.
    /// Returns demotion actions for any assumptions that were falsified.
    pub fn observe(
        &mut self,
        variable: &str,
        value_millionths: i64,
        epoch: u64,
        tick: u64,
    ) -> Vec<DemotionAction> {
        let mut actions = Vec::new();

        // Collect monitor IDs that match this variable
        let monitor_ids: Vec<String> = self
            .monitors
            .iter()
            .filter(|(_, m)| m.variable == variable && !m.triggered)
            .map(|(id, _)| id.clone())
            .collect();

        for monitor_id in monitor_ids {
            if let Some(monitor) = self.monitors.get_mut(&monitor_id)
                && let Some(evidence) = monitor.check(value_millionths, epoch, tick)
            {
                // Mark assumption as violated
                if let Some(assumption) = self.assumptions.get_mut(&evidence.assumption_id) {
                    assumption.status = AssumptionStatus::Violated;
                    let action = self
                        .demotion_controller
                        .process_violation(assumption, evidence.clone());
                    actions.push(action);
                }
                self.falsification_history.push(evidence);
                self.chain_hash =
                    simple_hash(&format!("{}_{monitor_id}_violated", self.chain_hash));
            }
        }

        actions
    }

    /// Retire an assumption (no longer needed).
    pub fn retire_assumption(&mut self, id: &str) -> Result<(), LedgerError> {
        let assumption = self
            .assumptions
            .get_mut(id)
            .ok_or_else(|| LedgerError::AssumptionNotFound(id.to_string()))?;
        if assumption.status != AssumptionStatus::Active {
            return Err(LedgerError::InvalidTransition {
                assumption_id: id.to_string(),
                from: assumption.status.clone(),
                to: AssumptionStatus::Retired,
            });
        }
        assumption.status = AssumptionStatus::Retired;
        Ok(())
    }

    /// Suspend an assumption pending investigation.
    pub fn suspend_assumption(&mut self, id: &str) -> Result<(), LedgerError> {
        let assumption = self
            .assumptions
            .get_mut(id)
            .ok_or_else(|| LedgerError::AssumptionNotFound(id.to_string()))?;
        if assumption.status != AssumptionStatus::Active {
            return Err(LedgerError::InvalidTransition {
                assumption_id: id.to_string(),
                from: assumption.status.clone(),
                to: AssumptionStatus::Suspended,
            });
        }
        assumption.status = AssumptionStatus::Suspended;
        Ok(())
    }

    /// Get an assumption by ID.
    pub fn assumption(&self, id: &str) -> Option<&Assumption> {
        self.assumptions.get(id)
    }

    /// Get all assumptions.
    pub fn assumptions(&self) -> &BTreeMap<AssumptionId, Assumption> {
        &self.assumptions
    }

    /// Get all active assumptions.
    pub fn active_assumptions(&self) -> Vec<&Assumption> {
        self.assumptions
            .values()
            .filter(|a| a.status == AssumptionStatus::Active)
            .collect()
    }

    /// Get all violated assumptions.
    pub fn violated_assumptions(&self) -> Vec<&Assumption> {
        self.assumptions
            .values()
            .filter(|a| a.status == AssumptionStatus::Violated)
            .collect()
    }

    /// Get all monitors.
    pub fn monitors(&self) -> &BTreeMap<String, FalsificationMonitor> {
        &self.monitors
    }

    /// Get the falsification history.
    pub fn falsification_history(&self) -> &[FalsificationEvidence] {
        &self.falsification_history
    }

    /// Get the demotion controller's records.
    pub fn demotion_records(&self) -> &[DemotionRecord] {
        self.demotion_controller.records()
    }

    /// Get the chain hash for tamper-evidence.
    pub fn chain_hash(&self) -> &str {
        &self.chain_hash
    }

    /// Count of all assumptions.
    pub fn assumption_count(&self) -> usize {
        self.assumptions.len()
    }

    /// Count of active assumptions.
    pub fn active_count(&self) -> usize {
        self.assumptions
            .values()
            .filter(|a| a.status == AssumptionStatus::Active)
            .count()
    }

    /// Count of violated assumptions.
    pub fn violated_count(&self) -> usize {
        self.assumptions
            .values()
            .filter(|a| a.status == AssumptionStatus::Violated)
            .count()
    }

    /// Generate a human-readable report.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Assumptions Ledger Report ===".to_string());
        lines.push(format!("Total assumptions: {}", self.assumption_count()));
        lines.push(format!("Active: {}", self.active_count()));
        lines.push(format!("Violated: {}", self.violated_count()));
        lines.push(format!("Monitors: {}", self.monitors.len()));
        lines.push(format!(
            "Falsifications: {}",
            self.falsification_history.len()
        ));
        lines.push(format!(
            "Demotions: {}",
            self.demotion_controller.demotion_count()
        ));

        if !self.falsification_history.is_empty() {
            lines.push(String::new());
            lines.push("-- Recent Falsifications --".to_string());
            for ev in self.falsification_history.iter().rev().take(5) {
                lines.push(format!(
                    "  [{}] {}: {}",
                    ev.monitor_id, ev.assumption_id, ev.explanation
                ));
            }
        }

        lines.join("\n")
    }
}

// ── Helper ────────────────────────────────────────────────────────────

fn simple_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_assumption(id: &str, severity: ViolationSeverity) -> Assumption {
        Assumption {
            id: id.to_string(),
            category: AssumptionCategory::Statistical,
            origin: AssumptionOrigin::Runtime,
            status: AssumptionStatus::Active,
            description: format!("Test assumption {id}"),
            decision_id: "decision_0".into(),
            epoch: 1,
            dependencies: BTreeSet::from(["risk".to_string()]),
            violation_severity: severity,
            predicate_hash: simple_hash(id),
        }
    }

    fn make_monitor(monitor_id: &str, assumption_id: &str) -> FalsificationMonitor {
        FalsificationMonitor {
            monitor_id: monitor_id.into(),
            assumption_id: assumption_id.into(),
            kind: MonitorKind::Threshold,
            variable: "risk".into(),
            threshold_millionths: 500_000,
            op: MonitorOp::Le,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        }
    }

    fn default_ledger() -> AssumptionLedger {
        AssumptionLedger::new(DemotionPolicy::default())
    }

    #[test]
    fn test_new_ledger_is_empty() {
        let ledger = default_ledger();
        assert_eq!(ledger.assumption_count(), 0);
        assert_eq!(ledger.active_count(), 0);
        assert_eq!(ledger.violated_count(), 0);
        assert!(ledger.falsification_history().is_empty());
    }

    #[test]
    fn test_record_assumption() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        assert_eq!(ledger.assumption_count(), 1);
        assert!(ledger.assumption("a1").is_some());
    }

    #[test]
    fn test_duplicate_assumption_fails() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let err = ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Critical))
            .unwrap_err();
        assert_eq!(err, LedgerError::DuplicateAssumption("a1".into()));
    }

    #[test]
    fn test_register_monitor() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        assert_eq!(ledger.monitors().len(), 1);
    }

    #[test]
    fn test_register_monitor_missing_assumption() {
        let mut ledger = default_ledger();
        let err = ledger
            .register_monitor(make_monitor("m1", "nonexistent"))
            .unwrap_err();
        assert_eq!(err, LedgerError::AssumptionNotFound("nonexistent".into()));
    }

    #[test]
    fn test_register_duplicate_monitor() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let err = ledger
            .register_monitor(make_monitor("m1", "a1"))
            .unwrap_err();
        assert_eq!(err, LedgerError::DuplicateMonitor("m1".into()));
    }

    #[test]
    fn test_observe_no_violation() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        // Value below threshold → no violation
        let actions = ledger.observe("risk", 400_000, 1, 0);
        assert!(actions.is_empty());
        assert_eq!(ledger.violated_count(), 0);
    }

    #[test]
    fn test_observe_violation_triggers_demotion() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        // Value above threshold → violation
        let actions = ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DemotionAction::SuspendAdaptive { .. }));
        assert_eq!(ledger.violated_count(), 1);
    }

    #[test]
    fn test_critical_violation_enters_safe_mode() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Critical))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let actions = ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DemotionAction::EnterSafeMode { .. }));
    }

    #[test]
    fn test_fatal_violation_enters_safe_mode() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Fatal))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let actions = ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DemotionAction::EnterSafeMode { .. }));
    }

    #[test]
    fn test_advisory_violation_no_action() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Advisory))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let actions = ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DemotionAction::NoAction));
    }

    #[test]
    fn test_consecutive_violations_trigger_count() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let mut monitor = make_monitor("m1", "a1");
        monitor.trigger_count = 3; // Require 3 consecutive violations
        ledger.register_monitor(monitor).unwrap();

        // First two violations don't trigger
        assert!(ledger.observe("risk", 600_000, 1, 0).is_empty());
        assert!(ledger.observe("risk", 700_000, 1, 1).is_empty());
        // Third violation triggers
        let actions = ledger.observe("risk", 800_000, 1, 2);
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_consecutive_violations_reset_on_pass() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let mut monitor = make_monitor("m1", "a1");
        monitor.trigger_count = 3;
        ledger.register_monitor(monitor).unwrap();

        // Two violations then a pass
        assert!(ledger.observe("risk", 600_000, 1, 0).is_empty());
        assert!(ledger.observe("risk", 700_000, 1, 1).is_empty());
        assert!(ledger.observe("risk", 400_000, 1, 2).is_empty()); // resets
        // Two more violations still don't trigger
        assert!(ledger.observe("risk", 600_000, 1, 3).is_empty());
        assert!(ledger.observe("risk", 700_000, 1, 4).is_empty());
        // Third consecutive triggers
        let actions = ledger.observe("risk", 800_000, 1, 5);
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_monitor_does_not_double_trigger() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        // First violation triggers
        assert_eq!(ledger.observe("risk", 600_000, 1, 0).len(), 1);
        // Second violation should NOT trigger again (monitor already triggered)
        assert!(ledger.observe("risk", 700_000, 1, 1).is_empty());
    }

    #[test]
    fn test_falsification_history_recorded() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(ledger.falsification_history().len(), 1);
        let ev = &ledger.falsification_history()[0];
        assert_eq!(ev.assumption_id, "a1");
        assert_eq!(ev.observed_value_millionths, 600_000);
    }

    #[test]
    fn test_demotion_records() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Critical))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(ledger.demotion_records().len(), 1);
        assert_eq!(ledger.demotion_records()[0].assumption_id, "a1");
    }

    #[test]
    fn test_retire_assumption() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.retire_assumption("a1").unwrap();
        assert_eq!(
            ledger.assumption("a1").unwrap().status,
            AssumptionStatus::Retired
        );
    }

    #[test]
    fn test_retire_nonexistent_fails() {
        let mut ledger = default_ledger();
        assert!(ledger.retire_assumption("nonexistent").is_err());
    }

    #[test]
    fn test_retire_violated_fails() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        let err = ledger.retire_assumption("a1").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidTransition { .. }));
    }

    #[test]
    fn test_suspend_assumption() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.suspend_assumption("a1").unwrap();
        assert_eq!(
            ledger.assumption("a1").unwrap().status,
            AssumptionStatus::Suspended
        );
    }

    #[test]
    fn test_suspend_violated_fails() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        assert!(ledger.suspend_assumption("a1").is_err());
    }

    #[test]
    fn test_active_assumptions_filter() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger
            .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0); // violates a1
        assert_eq!(ledger.active_assumptions().len(), 1);
        assert_eq!(ledger.active_assumptions()[0].id, "a2");
    }

    #[test]
    fn test_violated_assumptions_filter() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        assert_eq!(ledger.violated_assumptions().len(), 1);
        assert_eq!(ledger.violated_assumptions()[0].id, "a1");
    }

    #[test]
    fn test_chain_hash_changes() {
        let mut ledger = default_ledger();
        let h0 = ledger.chain_hash().to_string();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let h1 = ledger.chain_hash().to_string();
        assert_ne!(h0, h1);
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        let h2 = ledger.chain_hash().to_string();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_observe_wrong_variable_no_effect() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        // Wrong variable → no monitors match
        let actions = ledger.observe("latency", 999_999, 1, 0);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_multiple_monitors_same_assumption() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let mut m2 = make_monitor("m2", "a1");
        m2.threshold_millionths = 700_000; // Higher threshold
        ledger.register_monitor(m2).unwrap();
        // Value 600_000 violates m1 (threshold 500_000) but not m2 (threshold 700_000)
        let actions = ledger.observe("risk", 600_000, 1, 0);
        // m1 triggers; m2 does not because assumption is already violated
        // after m1 triggers, the assumption status is Violated, but m2 hasn't triggered yet
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_monitor_ge_op() {
        let mut monitor = FalsificationMonitor {
            monitor_id: "m1".into(),
            assumption_id: "a1".into(),
            kind: MonitorKind::Budget,
            variable: "budget".into(),
            threshold_millionths: 100_000,
            op: MonitorOp::Ge,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        };
        // Budget above threshold → holds
        assert!(monitor.check(200_000, 1, 0).is_none());
        // Budget below threshold → violation
        assert!(monitor.check(50_000, 1, 1).is_some());
    }

    #[test]
    fn test_monitor_eq_op() {
        let mut monitor = FalsificationMonitor {
            monitor_id: "m1".into(),
            assumption_id: "a1".into(),
            kind: MonitorKind::Invariant,
            variable: "flag".into(),
            threshold_millionths: 1_000_000,
            op: MonitorOp::Eq,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        };
        assert!(monitor.check(1_000_000, 1, 0).is_none());
        assert!(monitor.check(0, 1, 1).is_some());
    }

    #[test]
    fn test_monitor_reset() {
        let mut monitor = make_monitor("m1", "a1");
        monitor.check(600_000, 1, 0); // triggers
        assert!(monitor.triggered);
        monitor.reset();
        assert!(!monitor.triggered);
        assert_eq!(monitor.current_violations, 0);
    }

    #[test]
    fn test_report_content() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let report = ledger.report();
        assert!(report.contains("Assumptions Ledger Report"));
        assert!(report.contains("Total assumptions: 1"));
        assert!(report.contains("Active: 1"));
    }

    #[test]
    fn test_report_with_falsifications() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        let report = ledger.report();
        assert!(report.contains("Falsifications: 1"));
        assert!(report.contains("Recent Falsifications"));
    }

    #[test]
    fn test_serde_roundtrip_assumption() {
        let a = make_assumption("a1", ViolationSeverity::Warning);
        let json = serde_json::to_string(&a).unwrap();
        let back: Assumption = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn test_serde_roundtrip_monitor() {
        let m = make_monitor("m1", "a1");
        let json = serde_json::to_string(&m).unwrap();
        let back: FalsificationMonitor = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn test_serde_roundtrip_evidence() {
        let ev = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m1".into(),
            epoch: 1,
            tick: 0,
            observed_value_millionths: 600_000,
            threshold_millionths: 500_000,
            explanation: "test".into(),
            evidence_hash: "abc".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: FalsificationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn test_serde_roundtrip_demotion_record() {
        let record = DemotionRecord {
            record_id: "d0".into(),
            assumption_id: "a1".into(),
            evidence: FalsificationEvidence {
                assumption_id: "a1".into(),
                monitor_id: "m1".into(),
                epoch: 1,
                tick: 0,
                observed_value_millionths: 600_000,
                threshold_millionths: 500_000,
                explanation: "test".into(),
                evidence_hash: "abc".into(),
            },
            action: DemotionAction::EnterSafeMode {
                reason: "test".into(),
            },
            epoch: 1,
            severity: ViolationSeverity::Critical,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: DemotionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_serde_roundtrip_ledger() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: AssumptionLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn test_serde_roundtrip_ledger_error() {
        let err = LedgerError::DuplicateAssumption("a1".into());
        let json = serde_json::to_string(&err).unwrap();
        let back: LedgerError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            LedgerError::DuplicateAssumption("a1".into()).to_string(),
            "duplicate assumption: a1"
        );
        assert_eq!(
            LedgerError::AssumptionNotFound("a1".into()).to_string(),
            "assumption not found: a1"
        );
        assert_eq!(
            LedgerError::MonitorNotFound("m1".into()).to_string(),
            "monitor not found: m1"
        );
    }

    #[test]
    fn test_assumption_category_ordering() {
        let cats = [
            AssumptionCategory::Statistical,
            AssumptionCategory::Behavioral,
            AssumptionCategory::Resource,
            AssumptionCategory::Safety,
            AssumptionCategory::Structural,
        ];
        let set: BTreeSet<AssumptionCategory> = cats.into_iter().collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_assumption_origin_ordering() {
        let origins = [
            AssumptionOrigin::CompileTime,
            AssumptionOrigin::Runtime,
            AssumptionOrigin::PolicyInherited,
            AssumptionOrigin::Inferred,
        ];
        let set: BTreeSet<AssumptionOrigin> = origins.into_iter().collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_violation_severity_ordering() {
        let sevs = [
            ViolationSeverity::Advisory,
            ViolationSeverity::Warning,
            ViolationSeverity::Critical,
            ViolationSeverity::Fatal,
        ];
        let set: BTreeSet<ViolationSeverity> = sevs.into_iter().collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_monitor_kind_ordering() {
        let kinds = [
            MonitorKind::Threshold,
            MonitorKind::Drift,
            MonitorKind::Coverage,
            MonitorKind::Invariant,
            MonitorKind::Budget,
        ];
        let set: BTreeSet<MonitorKind> = kinds.into_iter().collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_demotion_policy_default() {
        let policy = DemotionPolicy::default();
        assert!(matches!(policy.advisory_action, DemotionAction::NoAction));
        assert!(matches!(
            policy.warning_action,
            DemotionAction::SuspendAdaptive { .. }
        ));
        assert!(matches!(
            policy.critical_action,
            DemotionAction::EnterSafeMode { .. }
        ));
        assert!(matches!(
            policy.fatal_action,
            DemotionAction::EnterSafeMode { .. }
        ));
    }

    #[test]
    fn test_custom_demotion_policy() {
        let policy = DemotionPolicy {
            advisory_action: DemotionAction::NoAction,
            warning_action: DemotionAction::EscalateToOperator {
                reason: "custom".into(),
            },
            critical_action: DemotionAction::DemoteLane {
                lane_id: "js".into(),
                reason: "critical".into(),
            },
            fatal_action: DemotionAction::EnterSafeMode {
                reason: "fatal".into(),
            },
        };
        let mut ledger = AssumptionLedger::new(policy);
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        let actions = ledger.observe("risk", 600_000, 1, 0);
        assert!(matches!(
            actions[0],
            DemotionAction::EscalateToOperator { .. }
        ));
    }

    #[test]
    fn test_demotion_controller_count() {
        let mut ctrl = DemotionController::new(DemotionPolicy::default());
        assert_eq!(ctrl.demotion_count(), 0);
        let a = make_assumption("a1", ViolationSeverity::Warning);
        let ev = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m1".into(),
            epoch: 1,
            tick: 0,
            observed_value_millionths: 600_000,
            threshold_millionths: 500_000,
            explanation: "test".into(),
            evidence_hash: "abc".into(),
        };
        ctrl.process_violation(&a, ev);
        assert_eq!(ctrl.demotion_count(), 1);
    }

    #[test]
    fn test_serde_all_demotion_actions() {
        let actions = [
            DemotionAction::EnterSafeMode {
                reason: "test".into(),
            },
            DemotionAction::DemoteLane {
                lane_id: "js".into(),
                reason: "test".into(),
            },
            DemotionAction::SuspendAdaptive {
                reason: "test".into(),
            },
            DemotionAction::EscalateToOperator {
                reason: "test".into(),
            },
            DemotionAction::NoAction,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let back: DemotionAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn assumption_category_serde_all_variants() {
        let variants = [
            AssumptionCategory::Statistical,
            AssumptionCategory::Behavioral,
            AssumptionCategory::Resource,
            AssumptionCategory::Safety,
            AssumptionCategory::Structural,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AssumptionCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn assumption_origin_serde_all_variants() {
        let variants = [
            AssumptionOrigin::CompileTime,
            AssumptionOrigin::Runtime,
            AssumptionOrigin::PolicyInherited,
            AssumptionOrigin::Inferred,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AssumptionOrigin = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn assumption_status_serde_all_variants() {
        let variants = [
            AssumptionStatus::Active,
            AssumptionStatus::Violated,
            AssumptionStatus::Retired,
            AssumptionStatus::Suspended,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AssumptionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn violation_severity_serde_all_variants() {
        let variants = [
            ViolationSeverity::Advisory,
            ViolationSeverity::Warning,
            ViolationSeverity::Critical,
            ViolationSeverity::Fatal,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn monitor_kind_serde_all_variants() {
        let variants = [
            MonitorKind::Threshold,
            MonitorKind::Drift,
            MonitorKind::Coverage,
            MonitorKind::Invariant,
            MonitorKind::Budget,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: MonitorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn monitor_op_serde_all_variants() {
        let variants = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: MonitorOp = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn ledger_error_serde_all_variants() {
        let variants: [LedgerError; 5] = [
            LedgerError::DuplicateAssumption("a1".into()),
            LedgerError::AssumptionNotFound("a2".into()),
            LedgerError::MonitorNotFound("m1".into()),
            LedgerError::DuplicateMonitor("m2".into()),
            LedgerError::InvalidTransition {
                assumption_id: "a3".into(),
                from: AssumptionStatus::Active,
                to: AssumptionStatus::Violated,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LedgerError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn ledger_error_display_distinct() {
        let variants: [LedgerError; 5] = [
            LedgerError::DuplicateAssumption("x".into()),
            LedgerError::AssumptionNotFound("x".into()),
            LedgerError::MonitorNotFound("x".into()),
            LedgerError::DuplicateMonitor("x".into()),
            LedgerError::InvalidTransition {
                assumption_id: "x".into(),
                from: AssumptionStatus::Active,
                to: AssumptionStatus::Violated,
            },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn ledger_error_is_std_error() {
        let e = LedgerError::DuplicateAssumption("test".into());
        let _: &dyn std::error::Error = &e;
    }

    // ── Enrichment: Copy semantics ──────────────────────────────────

    #[test]
    fn assumption_category_copy_from_array() {
        let arr = [
            AssumptionCategory::Statistical,
            AssumptionCategory::Behavioral,
            AssumptionCategory::Resource,
            AssumptionCategory::Safety,
            AssumptionCategory::Structural,
        ];
        let copied = arr[2];
        assert_eq!(copied, AssumptionCategory::Resource);
        assert_eq!(arr[2], AssumptionCategory::Resource);
    }

    #[test]
    fn assumption_origin_copy_from_array() {
        let arr = [
            AssumptionOrigin::CompileTime,
            AssumptionOrigin::Runtime,
            AssumptionOrigin::PolicyInherited,
            AssumptionOrigin::Inferred,
        ];
        let copied = arr[3];
        assert_eq!(copied, AssumptionOrigin::Inferred);
        assert_eq!(arr[3], AssumptionOrigin::Inferred);
    }

    #[test]
    fn violation_severity_copy_from_array() {
        let arr = [
            ViolationSeverity::Advisory,
            ViolationSeverity::Warning,
            ViolationSeverity::Critical,
            ViolationSeverity::Fatal,
        ];
        let copied = arr[0];
        assert_eq!(copied, ViolationSeverity::Advisory);
        assert_eq!(arr[0], ViolationSeverity::Advisory);
    }

    #[test]
    fn monitor_kind_copy_from_array() {
        let arr = [
            MonitorKind::Threshold,
            MonitorKind::Drift,
            MonitorKind::Coverage,
            MonitorKind::Invariant,
            MonitorKind::Budget,
        ];
        let copied = arr[4];
        assert_eq!(copied, MonitorKind::Budget);
        assert_eq!(arr[4], MonitorKind::Budget);
    }

    #[test]
    fn monitor_op_copy_from_array() {
        let arr = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
        let copied = arr[1];
        assert_eq!(copied, MonitorOp::Ge);
        assert_eq!(arr[1], MonitorOp::Ge);
    }

    // ── Enrichment: Debug distinctness ──────────────────────────────

    #[test]
    fn assumption_category_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            AssumptionCategory::Statistical,
            AssumptionCategory::Behavioral,
            AssumptionCategory::Resource,
            AssumptionCategory::Safety,
            AssumptionCategory::Structural,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 5);
    }

    #[test]
    fn assumption_origin_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            AssumptionOrigin::CompileTime,
            AssumptionOrigin::Runtime,
            AssumptionOrigin::PolicyInherited,
            AssumptionOrigin::Inferred,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 4);
    }

    #[test]
    fn assumption_status_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            AssumptionStatus::Active,
            AssumptionStatus::Violated,
            AssumptionStatus::Retired,
            AssumptionStatus::Suspended,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 4);
    }

    #[test]
    fn violation_severity_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            ViolationSeverity::Advisory,
            ViolationSeverity::Warning,
            ViolationSeverity::Critical,
            ViolationSeverity::Fatal,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 4);
    }

    #[test]
    fn monitor_kind_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            MonitorKind::Threshold,
            MonitorKind::Drift,
            MonitorKind::Coverage,
            MonitorKind::Invariant,
            MonitorKind::Budget,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 5);
    }

    // ── Enrichment: Serde variant distinctness ──────────────────────

    #[test]
    fn assumption_status_serde_variants_distinct() {
        let variants = [
            AssumptionStatus::Active,
            AssumptionStatus::Violated,
            AssumptionStatus::Retired,
            AssumptionStatus::Suspended,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn monitor_op_serde_variants_distinct() {
        let variants = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn demotion_action_serde_variants_distinct() {
        let variants = [
            DemotionAction::EnterSafeMode { reason: "r".into() },
            DemotionAction::DemoteLane {
                lane_id: "l".into(),
                reason: "r".into(),
            },
            DemotionAction::SuspendAdaptive { reason: "r".into() },
            DemotionAction::EscalateToOperator { reason: "r".into() },
            DemotionAction::NoAction,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 5);
    }

    // ── Enrichment: Clone independence ──────────────────────────────

    #[test]
    fn assumption_clone_independence() {
        let mut original = make_assumption("a1", ViolationSeverity::Warning);
        let cloned = original.clone();
        original.status = AssumptionStatus::Violated;
        original.description = "mutated".into();
        assert_eq!(cloned.status, AssumptionStatus::Active);
        assert_eq!(cloned.description, "Test assumption a1");
    }

    #[test]
    fn falsification_evidence_clone_independence() {
        let mut original = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m1".into(),
            epoch: 1,
            tick: 0,
            observed_value_millionths: 600_000,
            threshold_millionths: 500_000,
            explanation: "test".into(),
            evidence_hash: "abc".into(),
        };
        let cloned = original.clone();
        original.explanation = "mutated".into();
        assert_eq!(cloned.explanation, "test");
    }

    #[test]
    fn monitor_clone_independence() {
        let mut original = make_monitor("m1", "a1");
        let cloned = original.clone();
        original.triggered = true;
        original.current_violations = 5;
        assert!(!cloned.triggered);
        assert_eq!(cloned.current_violations, 0);
    }

    #[test]
    fn ledger_clone_independence() {
        let mut original = default_ledger();
        original
            .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        let cloned = original.clone();
        original
            .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
            .unwrap();
        assert_eq!(cloned.assumption_count(), 1);
        assert_eq!(original.assumption_count(), 2);
    }

    // ── Enrichment: JSON field-name stability ───────────────────────

    #[test]
    fn assumption_json_field_names() {
        let a = make_assumption("a1", ViolationSeverity::Warning);
        let val: serde_json::Value = serde_json::to_value(&a).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("category"));
        assert!(obj.contains_key("origin"));
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("description"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("dependencies"));
        assert!(obj.contains_key("violation_severity"));
        assert!(obj.contains_key("predicate_hash"));
        assert_eq!(obj.len(), 10);
    }

    #[test]
    fn falsification_evidence_json_field_names() {
        let ev = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m1".into(),
            epoch: 1,
            tick: 0,
            observed_value_millionths: 600_000,
            threshold_millionths: 500_000,
            explanation: "test".into(),
            evidence_hash: "abc".into(),
        };
        let val: serde_json::Value = serde_json::to_value(&ev).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("assumption_id"));
        assert!(obj.contains_key("monitor_id"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("tick"));
        assert!(obj.contains_key("observed_value_millionths"));
        assert!(obj.contains_key("threshold_millionths"));
        assert!(obj.contains_key("explanation"));
        assert!(obj.contains_key("evidence_hash"));
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn falsification_monitor_json_field_names() {
        let m = make_monitor("m1", "a1");
        let val: serde_json::Value = serde_json::to_value(&m).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("monitor_id"));
        assert!(obj.contains_key("assumption_id"));
        assert!(obj.contains_key("kind"));
        assert!(obj.contains_key("variable"));
        assert!(obj.contains_key("threshold_millionths"));
        assert!(obj.contains_key("op"));
        assert!(obj.contains_key("trigger_count"));
        assert!(obj.contains_key("current_violations"));
        assert!(obj.contains_key("triggered"));
        assert_eq!(obj.len(), 9);
    }

    #[test]
    fn demotion_record_json_field_names() {
        let record = DemotionRecord {
            record_id: "d0".into(),
            assumption_id: "a1".into(),
            evidence: FalsificationEvidence {
                assumption_id: "a1".into(),
                monitor_id: "m1".into(),
                epoch: 1,
                tick: 0,
                observed_value_millionths: 600_000,
                threshold_millionths: 500_000,
                explanation: "test".into(),
                evidence_hash: "abc".into(),
            },
            action: DemotionAction::NoAction,
            epoch: 1,
            severity: ViolationSeverity::Critical,
        };
        let val: serde_json::Value = serde_json::to_value(&record).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("record_id"));
        assert!(obj.contains_key("assumption_id"));
        assert!(obj.contains_key("evidence"));
        assert!(obj.contains_key("action"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("severity"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn demotion_policy_json_field_names() {
        let policy = DemotionPolicy::default();
        let val: serde_json::Value = serde_json::to_value(&policy).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("advisory_action"));
        assert!(obj.contains_key("warning_action"));
        assert!(obj.contains_key("critical_action"));
        assert!(obj.contains_key("fatal_action"));
        assert_eq!(obj.len(), 4);
    }

    // ── Enrichment: Hash consistency ────────────────────────────────

    #[test]
    fn assumption_category_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        AssumptionCategory::Statistical.hash(&mut h1);
        AssumptionCategory::Statistical.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn violation_severity_hash_all_distinct() {
        use std::hash::{Hash, Hasher};
        let variants = [
            ViolationSeverity::Advisory,
            ViolationSeverity::Warning,
            ViolationSeverity::Critical,
            ViolationSeverity::Fatal,
        ];
        let hashes: BTreeSet<u64> = variants
            .iter()
            .map(|v| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                v.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 4);
    }

    // ── Enrichment: Boundary/edge cases ─────────────────────────────

    #[test]
    fn monitor_check_exact_threshold_holds_le() {
        let mut monitor = make_monitor("m1", "a1");
        // Exactly at threshold (500_000) → Le holds
        assert!(monitor.check(500_000, 1, 0).is_none());
    }

    #[test]
    fn monitor_check_one_above_threshold_violates_le() {
        let mut monitor = make_monitor("m1", "a1");
        assert!(monitor.check(500_001, 1, 0).is_some());
    }

    #[test]
    fn monitor_check_exact_threshold_holds_ge() {
        let mut monitor = FalsificationMonitor {
            monitor_id: "m1".into(),
            assumption_id: "a1".into(),
            kind: MonitorKind::Threshold,
            variable: "budget".into(),
            threshold_millionths: 100_000,
            op: MonitorOp::Ge,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        };
        assert!(monitor.check(100_000, 1, 0).is_none());
    }

    #[test]
    fn monitor_check_one_below_threshold_violates_ge() {
        let mut monitor = FalsificationMonitor {
            monitor_id: "m1".into(),
            assumption_id: "a1".into(),
            kind: MonitorKind::Threshold,
            variable: "budget".into(),
            threshold_millionths: 100_000,
            op: MonitorOp::Ge,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        };
        assert!(monitor.check(99_999, 1, 0).is_some());
    }

    #[test]
    fn ledger_many_assumptions_btree_ordered() {
        let mut ledger = default_ledger();
        for i in (0..10).rev() {
            ledger
                .record_assumption(make_assumption(
                    &format!("a{i:02}"),
                    ViolationSeverity::Advisory,
                ))
                .unwrap();
        }
        let keys: Vec<&String> = ledger.assumptions().keys().collect();
        let sorted: Vec<&String> = {
            let mut s = keys.clone();
            s.sort();
            s
        };
        assert_eq!(keys, sorted);
    }

    #[test]
    fn ledger_chain_hash_deterministic() {
        let mut l1 = default_ledger();
        let mut l2 = default_ledger();
        l1.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        l2.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        assert_eq!(l1.chain_hash(), l2.chain_hash());
    }

    #[test]
    fn ledger_chain_hash_differs_for_different_assumptions() {
        let mut l1 = default_ledger();
        let mut l2 = default_ledger();
        l1.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
            .unwrap();
        l2.record_assumption(make_assumption("a2", ViolationSeverity::Warning))
            .unwrap();
        assert_ne!(l1.chain_hash(), l2.chain_hash());
    }

    #[test]
    fn empty_ledger_report_contains_zeros() {
        let ledger = default_ledger();
        let report = ledger.report();
        assert!(report.contains("Total assumptions: 0"));
        assert!(report.contains("Active: 0"));
        assert!(report.contains("Violated: 0"));
        assert!(report.contains("Monitors: 0"));
        assert!(report.contains("Falsifications: 0"));
        assert!(report.contains("Demotions: 0"));
        assert!(!report.contains("Recent Falsifications"));
    }

    #[test]
    fn simple_hash_deterministic() {
        let h1 = simple_hash("hello");
        let h2 = simple_hash("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn simple_hash_differs_for_different_inputs() {
        let h1 = simple_hash("hello");
        let h2 = simple_hash("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn monitor_negative_millionths_check() {
        let mut monitor = FalsificationMonitor {
            monitor_id: "m1".into(),
            assumption_id: "a1".into(),
            kind: MonitorKind::Threshold,
            variable: "temp".into(),
            threshold_millionths: -100_000,
            op: MonitorOp::Ge,
            trigger_count: 1,
            current_violations: 0,
            triggered: false,
        };
        // Value above negative threshold → holds
        assert!(monitor.check(0, 1, 0).is_none());
        // Value below negative threshold → violates
        assert!(monitor.check(-200_000, 1, 1).is_some());
    }

    #[test]
    fn demotion_controller_multiple_records_sequential_ids() {
        let mut ctrl = DemotionController::new(DemotionPolicy::default());
        let a1 = make_assumption("a1", ViolationSeverity::Warning);
        let ev1 = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m1".into(),
            epoch: 1,
            tick: 0,
            observed_value_millionths: 600_000,
            threshold_millionths: 500_000,
            explanation: "first".into(),
            evidence_hash: "h1".into(),
        };
        let ev2 = FalsificationEvidence {
            assumption_id: "a1".into(),
            monitor_id: "m2".into(),
            epoch: 1,
            tick: 1,
            observed_value_millionths: 700_000,
            threshold_millionths: 500_000,
            explanation: "second".into(),
            evidence_hash: "h2".into(),
        };
        ctrl.process_violation(&a1, ev1);
        ctrl.process_violation(&a1, ev2);
        assert_eq!(ctrl.demotion_count(), 2);
        assert_eq!(ctrl.records()[0].record_id, "demotion_0");
        assert_eq!(ctrl.records()[1].record_id, "demotion_1");
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────────

    #[test]
    fn assumption_debug_nonempty() {
        let a = make_assumption("a1", ViolationSeverity::Warning);
        let dbg = format!("{a:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("a1"));
    }

    #[test]
    fn ledger_debug_nonempty() {
        let ledger = default_ledger();
        let dbg = format!("{ledger:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("AssumptionLedger"));
    }

    #[test]
    fn demotion_controller_debug_nonempty() {
        let ctrl = DemotionController::new(DemotionPolicy::default());
        let dbg = format!("{ctrl:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("DemotionController"));
    }

    // ── Enrichment: LedgerError serde roundtrips ────────────────────

    #[test]
    fn ledger_error_serde_all_variants_roundtrip() {
        let variants = [
            LedgerError::DuplicateAssumption("a1".into()),
            LedgerError::AssumptionNotFound("a2".into()),
            LedgerError::MonitorNotFound("m1".into()),
            LedgerError::DuplicateMonitor("m2".into()),
            LedgerError::InvalidTransition {
                assumption_id: "a3".into(),
                from: AssumptionStatus::Active,
                to: AssumptionStatus::Violated,
            },
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 5);
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LedgerError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: Full serde roundtrip with violations ────────────

    #[test]
    fn ledger_serde_roundtrip_with_violations() {
        let mut ledger = default_ledger();
        ledger
            .record_assumption(make_assumption("a1", ViolationSeverity::Critical))
            .unwrap();
        ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
        ledger.observe("risk", 600_000, 1, 0);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: AssumptionLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
        assert_eq!(back.violated_count(), 1);
        assert_eq!(back.demotion_records().len(), 1);
    }
}
