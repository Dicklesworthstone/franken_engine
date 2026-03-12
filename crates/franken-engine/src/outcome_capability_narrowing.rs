//! Four-valued Outcome semantics and capability narrowing across boundaries.
//!
//! Preserves Outcome faithfulness (Success, Failure, Timeout, Cancelled) when
//! results cross orchestration boundaries, and enforces explicit capability
//! narrowing rules so child contexts never silently inherit wider authority
//! than their parent boundary permits.
//!
//! Key invariants:
//! - Outcomes never silently upgrade (Timeout → Success is forbidden)
//! - Capability narrowing is monotonic: children are equal or stricter
//! - Boundary transitions produce auditable narrowing evidence
//! - Unknown/external outcomes map to the fail-closed Failure variant
//!
//! Plan references: Section 10.13X.C2, bd-3nr.1.3.2.
//! Dependencies: control_plane adapter (CapabilitySet, NoCaps),
//!               execution_cell (CellKind), security_epoch.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// BoundaryOutcome — four-valued outcome type
// ---------------------------------------------------------------------------

/// Four-valued outcome at orchestration boundaries.
///
/// Every effectful operation that crosses a boundary MUST produce exactly one
/// of these outcomes. No silent coercion is permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryOutcome {
    /// Operation completed normally with expected results.
    Success,
    /// Operation failed with an explicit error.
    Failure,
    /// Operation exhausted its budget before completing.
    Timeout,
    /// Operation was explicitly cancelled (drain/shutdown).
    Cancelled,
}

impl BoundaryOutcome {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether this outcome represents a non-success state.
    pub fn is_failure_class(self) -> bool {
        !matches!(self, Self::Success)
    }

    /// Whether this outcome indicates budget exhaustion.
    pub fn is_budget_related(self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// The severity ordering (lower = more severe for propagation).
    /// Cancelled > Timeout > Failure > Success in severity.
    pub fn severity(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Timeout => 2,
            Self::Cancelled => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// OutcomePropagationRule
// ---------------------------------------------------------------------------

/// Rule governing how outcomes propagate across a specific boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomePropagationRule {
    /// Preserve the child outcome exactly as-is.
    Preserve,
    /// Map non-success outcomes to Failure (collapse detail).
    CollapseToFailure,
    /// Propagate only if severity >= threshold.
    SeverityThreshold { min_severity: u8 },
    /// Always escalate to the most severe outcome.
    EscalateToMostSevere,
}

impl OutcomePropagationRule {
    /// Apply this rule to transform a child outcome for the parent boundary.
    pub fn apply(
        self,
        child_outcome: BoundaryOutcome,
        parent_current: BoundaryOutcome,
    ) -> BoundaryOutcome {
        match self {
            Self::Preserve => child_outcome,
            Self::CollapseToFailure => {
                if child_outcome.is_failure_class() {
                    BoundaryOutcome::Failure
                } else {
                    child_outcome
                }
            }
            Self::SeverityThreshold { min_severity } => {
                if child_outcome.severity() >= min_severity {
                    child_outcome
                } else {
                    parent_current
                }
            }
            Self::EscalateToMostSevere => {
                if child_outcome.severity() > parent_current.severity() {
                    child_outcome
                } else {
                    parent_current
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityToken — named capability flags
// ---------------------------------------------------------------------------

/// Named capability token for boundary narrowing.
///
/// These tokens represent runtime capabilities that can be granted, narrowed,
/// or revoked at orchestration boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityToken {
    /// Read from the filesystem.
    FileSystemRead,
    /// Write to the filesystem.
    FileSystemWrite,
    /// Open network connections.
    NetworkAccess,
    /// Spawn child processes.
    ProcessSpawn,
    /// Access environment variables.
    EnvironmentRead,
    /// Allocate timers and scheduled callbacks.
    TimerAccess,
    /// Access shared memory regions.
    SharedMemory,
    /// Emit structured telemetry.
    TelemetryEmit,
    /// Invoke hostcall gateway.
    HostcallInvoke,
    /// Create child execution cells.
    CellSpawn,
    /// Access the module loader.
    ModuleLoad,
    /// Access cryptographic primitives.
    CryptoAccess,
}

impl CapabilityToken {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileSystemRead => "fs_read",
            Self::FileSystemWrite => "fs_write",
            Self::NetworkAccess => "network",
            Self::ProcessSpawn => "process_spawn",
            Self::EnvironmentRead => "env_read",
            Self::TimerAccess => "timer",
            Self::SharedMemory => "shared_memory",
            Self::TelemetryEmit => "telemetry",
            Self::HostcallInvoke => "hostcall",
            Self::CellSpawn => "cell_spawn",
            Self::ModuleLoad => "module_load",
            Self::CryptoAccess => "crypto",
        }
    }

    /// All capability tokens.
    pub fn all() -> &'static [CapabilityToken] {
        &[
            Self::FileSystemRead,
            Self::FileSystemWrite,
            Self::NetworkAccess,
            Self::ProcessSpawn,
            Self::EnvironmentRead,
            Self::TimerAccess,
            Self::SharedMemory,
            Self::TelemetryEmit,
            Self::HostcallInvoke,
            Self::CellSpawn,
            Self::ModuleLoad,
            Self::CryptoAccess,
        ]
    }
}

// ---------------------------------------------------------------------------
// CapabilitySet — ordered set of capability tokens
// ---------------------------------------------------------------------------

/// An ordered set of capability tokens granted at a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The granted tokens.
    pub tokens: BTreeSet<CapabilityToken>,
    /// Label for this grant (e.g. "extension-sandbox", "session-minimal").
    pub label: String,
}

impl CapabilityGrant {
    /// Empty capability set (no permissions).
    pub fn none() -> Self {
        Self {
            tokens: BTreeSet::new(),
            label: "none".to_owned(),
        }
    }

    /// Full capability set (all permissions).
    pub fn full() -> Self {
        Self {
            tokens: CapabilityToken::all().iter().copied().collect(),
            label: "full".to_owned(),
        }
    }

    /// Minimal compute-only set (telemetry + timer).
    pub fn compute_only() -> Self {
        let mut tokens = BTreeSet::new();
        tokens.insert(CapabilityToken::TelemetryEmit);
        tokens.insert(CapabilityToken::TimerAccess);
        Self {
            tokens,
            label: "compute_only".to_owned(),
        }
    }

    /// Standard sandbox set.
    pub fn sandbox() -> Self {
        let mut tokens = BTreeSet::new();
        tokens.insert(CapabilityToken::TelemetryEmit);
        tokens.insert(CapabilityToken::TimerAccess);
        tokens.insert(CapabilityToken::HostcallInvoke);
        tokens.insert(CapabilityToken::ModuleLoad);
        Self {
            tokens,
            label: "sandbox".to_owned(),
        }
    }

    /// Whether this grant is a subset of (or equal to) another.
    pub fn is_subset_of(&self, other: &CapabilityGrant) -> bool {
        self.tokens.is_subset(&other.tokens)
    }

    /// Whether this grant contains a specific token.
    pub fn has(&self, token: CapabilityToken) -> bool {
        self.tokens.contains(&token)
    }

    /// Number of granted capabilities.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the grant is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Intersect with another grant (narrowing).
    pub fn intersect(&self, other: &CapabilityGrant) -> CapabilityGrant {
        let tokens: BTreeSet<_> = self.tokens.intersection(&other.tokens).copied().collect();
        CapabilityGrant {
            label: format!("{}∩{}", self.label, other.label),
            tokens,
        }
    }

    /// Tokens present in self but not in other (what was narrowed away).
    pub fn difference(&self, other: &CapabilityGrant) -> BTreeSet<CapabilityToken> {
        self.tokens.difference(&other.tokens).copied().collect()
    }
}

// ---------------------------------------------------------------------------
// NarrowingDirection
// ---------------------------------------------------------------------------

/// Direction of capability change across a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarrowingDirection {
    /// Capabilities were reduced (expected, safe).
    Narrowed,
    /// Capabilities were unchanged.
    Preserved,
    /// Capabilities were widened (violation!).
    Widened,
}

// ---------------------------------------------------------------------------
// BoundaryTransition
// ---------------------------------------------------------------------------

/// A recorded transition across an orchestration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryTransition {
    /// Parent trace ID.
    pub parent_trace_id: String,
    /// Child trace ID.
    pub child_trace_id: String,
    /// Boundary label (e.g. "extension_spawn", "session_create").
    pub boundary_label: String,
    /// Parent capabilities before transition.
    pub parent_capabilities: CapabilityGrant,
    /// Child capabilities after transition.
    pub child_capabilities: CapabilityGrant,
    /// Tokens that were narrowed away.
    pub narrowed_tokens: BTreeSet<CapabilityToken>,
    /// Direction of narrowing.
    pub direction: NarrowingDirection,
    /// Outcome of the child operation.
    pub child_outcome: Option<BoundaryOutcome>,
    /// Outcome propagated to parent.
    pub propagated_outcome: Option<BoundaryOutcome>,
    /// Monotonic sequence number.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// NarrowingViolation
// ---------------------------------------------------------------------------

/// A violation of capability narrowing invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarrowingViolation {
    /// Child capabilities wider than parent.
    CapabilityWidening {
        boundary_label: String,
        widened_tokens: BTreeSet<CapabilityToken>,
    },
    /// Outcome upgraded across boundary (e.g. Timeout → Success).
    OutcomeUpgrade {
        boundary_label: String,
        child_outcome: BoundaryOutcome,
        propagated_outcome: BoundaryOutcome,
    },
    /// Unknown outcome mapped to non-Failure.
    UnknownOutcomeNotFailClosed { boundary_label: String },
}

impl std::fmt::Display for NarrowingViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityWidening {
                boundary_label,
                widened_tokens,
            } => {
                let tokens: Vec<_> = widened_tokens.iter().map(|t| t.as_str()).collect();
                write!(
                    f,
                    "capability widening at {}: [{}]",
                    boundary_label,
                    tokens.join(", ")
                )
            }
            Self::OutcomeUpgrade {
                boundary_label,
                child_outcome,
                propagated_outcome,
            } => write!(
                f,
                "outcome upgrade at {}: {} → {}",
                boundary_label,
                child_outcome.as_str(),
                propagated_outcome.as_str()
            ),
            Self::UnknownOutcomeNotFailClosed { boundary_label } => {
                write!(f, "unknown outcome not fail-closed at {}", boundary_label)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityNarrowingValidator
// ---------------------------------------------------------------------------

/// Validates capability narrowing and outcome propagation across boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityNarrowingValidator {
    /// Outcome propagation rule.
    outcome_rule: OutcomePropagationRule,
    /// Recorded transitions.
    transitions: Vec<BoundaryTransition>,
    /// Recorded violations.
    violations: Vec<NarrowingViolation>,
    /// Event counter for sequencing.
    event_counter: u64,
    /// Security epoch.
    epoch: SecurityEpoch,
}

impl CapabilityNarrowingValidator {
    /// Create a new validator with the given outcome rule.
    pub fn new(outcome_rule: OutcomePropagationRule, epoch: SecurityEpoch) -> Self {
        Self {
            outcome_rule,
            transitions: Vec::new(),
            violations: Vec::new(),
            event_counter: 0,
            epoch,
        }
    }

    /// Create with default settings (Preserve outcome, epoch 1).
    pub fn with_defaults() -> Self {
        Self::new(OutcomePropagationRule::Preserve, SecurityEpoch::from_raw(1))
    }

    /// Validate and record a capability narrowing at a boundary.
    pub fn validate_narrowing(
        &mut self,
        parent_trace_id: &str,
        child_trace_id: &str,
        boundary_label: &str,
        parent_caps: &CapabilityGrant,
        child_caps: &CapabilityGrant,
    ) -> NarrowingDirection {
        let narrowed_tokens = parent_caps.difference(child_caps);
        let widened_tokens: BTreeSet<_> = child_caps
            .tokens
            .difference(&parent_caps.tokens)
            .copied()
            .collect();

        let direction = if !widened_tokens.is_empty() {
            self.violations
                .push(NarrowingViolation::CapabilityWidening {
                    boundary_label: boundary_label.to_owned(),
                    widened_tokens,
                });
            NarrowingDirection::Widened
        } else if narrowed_tokens.is_empty() {
            NarrowingDirection::Preserved
        } else {
            NarrowingDirection::Narrowed
        };

        self.event_counter += 1;
        self.transitions.push(BoundaryTransition {
            parent_trace_id: parent_trace_id.to_owned(),
            child_trace_id: child_trace_id.to_owned(),
            boundary_label: boundary_label.to_owned(),
            parent_capabilities: parent_caps.clone(),
            child_capabilities: child_caps.clone(),
            narrowed_tokens,
            direction,
            child_outcome: None,
            propagated_outcome: None,
            sequence: self.event_counter,
        });

        direction
    }

    /// Record outcome propagation across a boundary.
    pub fn record_outcome_propagation(
        &mut self,
        boundary_label: &str,
        child_outcome: BoundaryOutcome,
        parent_current: BoundaryOutcome,
    ) -> BoundaryOutcome {
        let propagated = self.outcome_rule.apply(child_outcome, parent_current);

        // Check for outcome upgrade violation
        if propagated.severity() < child_outcome.severity() {
            self.violations.push(NarrowingViolation::OutcomeUpgrade {
                boundary_label: boundary_label.to_owned(),
                child_outcome,
                propagated_outcome: propagated,
            });
        }

        // Update the last transition if it matches
        if let Some(last) = self.transitions.last_mut() {
            if last.boundary_label == boundary_label {
                last.child_outcome = Some(child_outcome);
                last.propagated_outcome = Some(propagated);
            }
        }

        propagated
    }

    /// Return all recorded transitions.
    pub fn transitions(&self) -> &[BoundaryTransition] {
        &self.transitions
    }

    /// Return all recorded violations.
    pub fn violations(&self) -> &[NarrowingViolation] {
        &self.violations
    }

    /// Whether any violations were recorded.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Build a summary report.
    pub fn build_report(&self) -> NarrowingReport {
        let mut direction_counts: BTreeMap<String, u64> = BTreeMap::new();
        for t in &self.transitions {
            let key = match t.direction {
                NarrowingDirection::Narrowed => "narrowed",
                NarrowingDirection::Preserved => "preserved",
                NarrowingDirection::Widened => "widened",
            };
            *direction_counts.entry(key.to_owned()).or_insert(0) += 1;
        }

        let mut outcome_counts: BTreeMap<String, u64> = BTreeMap::new();
        for t in &self.transitions {
            if let Some(outcome) = t.child_outcome {
                *outcome_counts
                    .entry(outcome.as_str().to_owned())
                    .or_insert(0) += 1;
            }
        }

        let content = format!(
            "transitions={},violations={},narrowed={},widened={}",
            self.transitions.len(),
            self.violations.len(),
            direction_counts.get("narrowed").copied().unwrap_or(0),
            direction_counts.get("widened").copied().unwrap_or(0),
        );
        let content_hash = ContentHash::compute(content.as_bytes());

        NarrowingReport {
            total_transitions: self.transitions.len() as u64,
            direction_counts,
            outcome_counts,
            violations: self.violations.clone(),
            content_hash,
            epoch: self.epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// NarrowingReport
// ---------------------------------------------------------------------------

/// Summary report of capability narrowing activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NarrowingReport {
    /// Total boundary transitions recorded.
    pub total_transitions: u64,
    /// Counts by narrowing direction.
    pub direction_counts: BTreeMap<String, u64>,
    /// Counts by child outcome.
    pub outcome_counts: BTreeMap<String, u64>,
    /// All violations encountered.
    pub violations: Vec<NarrowingViolation>,
    /// Content hash of the report data.
    pub content_hash: ContentHash,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl NarrowingReport {
    /// Whether the report indicates clean narrowing.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_as_str() {
        assert_eq!(BoundaryOutcome::Success.as_str(), "success");
        assert_eq!(BoundaryOutcome::Failure.as_str(), "failure");
        assert_eq!(BoundaryOutcome::Timeout.as_str(), "timeout");
        assert_eq!(BoundaryOutcome::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn test_outcome_failure_class() {
        assert!(!BoundaryOutcome::Success.is_failure_class());
        assert!(BoundaryOutcome::Failure.is_failure_class());
        assert!(BoundaryOutcome::Timeout.is_failure_class());
        assert!(BoundaryOutcome::Cancelled.is_failure_class());
    }

    #[test]
    fn test_outcome_severity_ordering() {
        assert!(BoundaryOutcome::Success.severity() < BoundaryOutcome::Failure.severity());
        assert!(BoundaryOutcome::Failure.severity() < BoundaryOutcome::Timeout.severity());
        assert!(BoundaryOutcome::Timeout.severity() < BoundaryOutcome::Cancelled.severity());
    }

    #[test]
    fn test_outcome_serde_roundtrip() {
        for outcome in [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let round: BoundaryOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, round);
        }
    }

    #[test]
    fn test_propagation_rule_preserve() {
        let rule = OutcomePropagationRule::Preserve;
        assert_eq!(
            rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success),
            BoundaryOutcome::Timeout
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Failure),
            BoundaryOutcome::Success
        );
    }

    #[test]
    fn test_propagation_rule_collapse_to_failure() {
        let rule = OutcomePropagationRule::CollapseToFailure;
        assert_eq!(
            rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success),
            BoundaryOutcome::Failure
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Cancelled, BoundaryOutcome::Success),
            BoundaryOutcome::Failure
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
    }

    #[test]
    fn test_propagation_rule_severity_threshold() {
        let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 2 };
        // Timeout (2) meets threshold
        assert_eq!(
            rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success),
            BoundaryOutcome::Timeout
        );
        // Failure (1) below threshold
        assert_eq!(
            rule.apply(BoundaryOutcome::Failure, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
    }

    #[test]
    fn test_propagation_rule_escalate() {
        let rule = OutcomePropagationRule::EscalateToMostSevere;
        assert_eq!(
            rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Failure),
            BoundaryOutcome::Timeout
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Failure),
            BoundaryOutcome::Failure
        );
    }

    #[test]
    fn test_capability_token_all() {
        let all = CapabilityToken::all();
        assert_eq!(all.len(), 12);
        for token in all {
            assert!(!token.as_str().is_empty());
        }
    }

    #[test]
    fn test_capability_grant_none() {
        let grant = CapabilityGrant::none();
        assert!(grant.is_empty());
        assert_eq!(grant.len(), 0);
        assert!(!grant.has(CapabilityToken::NetworkAccess));
    }

    #[test]
    fn test_capability_grant_full() {
        let grant = CapabilityGrant::full();
        assert_eq!(grant.len(), 12);
        assert!(grant.has(CapabilityToken::NetworkAccess));
        assert!(grant.has(CapabilityToken::FileSystemWrite));
    }

    #[test]
    fn test_capability_grant_compute_only() {
        let grant = CapabilityGrant::compute_only();
        assert!(grant.has(CapabilityToken::TelemetryEmit));
        assert!(grant.has(CapabilityToken::TimerAccess));
        assert!(!grant.has(CapabilityToken::NetworkAccess));
    }

    #[test]
    fn test_capability_grant_sandbox() {
        let grant = CapabilityGrant::sandbox();
        assert!(grant.has(CapabilityToken::HostcallInvoke));
        assert!(grant.has(CapabilityToken::ModuleLoad));
        assert!(!grant.has(CapabilityToken::FileSystemWrite));
    }

    #[test]
    fn test_subset_relationship() {
        let compute = CapabilityGrant::compute_only();
        let sandbox = CapabilityGrant::sandbox();
        let full = CapabilityGrant::full();

        assert!(compute.is_subset_of(&full));
        assert!(sandbox.is_subset_of(&full));
        assert!(!full.is_subset_of(&compute));
        // compute_only has timer+telemetry, sandbox has timer+telemetry+hostcall+module
        assert!(compute.is_subset_of(&sandbox));
    }

    #[test]
    fn test_intersect_grants() {
        let sandbox = CapabilityGrant::sandbox();
        let mut custom = CapabilityGrant::none();
        custom.tokens.insert(CapabilityToken::HostcallInvoke);
        custom.tokens.insert(CapabilityToken::NetworkAccess);

        let narrowed = sandbox.intersect(&custom);
        assert!(narrowed.has(CapabilityToken::HostcallInvoke));
        assert!(!narrowed.has(CapabilityToken::NetworkAccess)); // sandbox doesn't have network
        assert!(!narrowed.has(CapabilityToken::ModuleLoad)); // custom doesn't have module
    }

    #[test]
    fn test_difference_grants() {
        let full = CapabilityGrant::full();
        let sandbox = CapabilityGrant::sandbox();
        let diff = full.difference(&sandbox);
        assert!(diff.contains(&CapabilityToken::NetworkAccess));
        assert!(diff.contains(&CapabilityToken::FileSystemWrite));
        assert!(!diff.contains(&CapabilityToken::HostcallInvoke));
    }

    #[test]
    fn test_validator_narrowing_success() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        let direction = validator.validate_narrowing(
            "parent-trace",
            "child-trace",
            "spawn_extension",
            &parent,
            &child,
        );

        assert_eq!(direction, NarrowingDirection::Narrowed);
        assert!(!validator.has_violations());
        assert_eq!(validator.transitions().len(), 1);
    }

    #[test]
    fn test_validator_narrowing_preserved() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let caps = CapabilityGrant::sandbox();

        let direction = validator.validate_narrowing(
            "parent-trace",
            "child-trace",
            "same_boundary",
            &caps,
            &caps,
        );

        assert_eq!(direction, NarrowingDirection::Preserved);
        assert!(!validator.has_violations());
    }

    #[test]
    fn test_validator_narrowing_widened_violation() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::sandbox();
        let child = CapabilityGrant::full();

        let direction = validator.validate_narrowing(
            "parent-trace",
            "child-trace",
            "bad_boundary",
            &parent,
            &child,
        );

        assert_eq!(direction, NarrowingDirection::Widened);
        assert!(validator.has_violations());
        assert_eq!(validator.violations().len(), 1);
        match &validator.violations()[0] {
            NarrowingViolation::CapabilityWidening { widened_tokens, .. } => {
                assert!(!widened_tokens.is_empty());
            }
            other => panic!("expected CapabilityWidening, got {:?}", other),
        }
    }

    #[test]
    fn test_validator_outcome_propagation_clean() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let propagated = validator.record_outcome_propagation(
            "boundary_1",
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Success,
        );
        assert_eq!(propagated, BoundaryOutcome::Timeout);
        assert!(!validator.has_violations());
    }

    #[test]
    fn test_validator_outcome_upgrade_violation() {
        let mut validator = CapabilityNarrowingValidator::new(
            OutcomePropagationRule::CollapseToFailure,
            SecurityEpoch::from_raw(1),
        );
        // CollapseToFailure: Timeout → Failure (severity goes from 2 to 1 = upgrade)
        let propagated = validator.record_outcome_propagation(
            "boundary_1",
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Success,
        );
        assert_eq!(propagated, BoundaryOutcome::Failure);
        // This IS an upgrade (severity decreased from 2 to 1)
        assert!(validator.has_violations());
    }

    #[test]
    fn test_validator_escalate_rule() {
        let mut validator = CapabilityNarrowingValidator::new(
            OutcomePropagationRule::EscalateToMostSevere,
            SecurityEpoch::from_raw(1),
        );
        // Start with Success, child returns Timeout → escalates
        let p1 = validator.record_outcome_propagation(
            "b1",
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Success,
        );
        assert_eq!(p1, BoundaryOutcome::Timeout);

        // Then another child returns Failure → stays at Timeout
        let p2 = validator.record_outcome_propagation(
            "b2",
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
        );
        assert_eq!(p2, BoundaryOutcome::Timeout);

        // Then child returns Cancelled → escalates
        let p3 = validator.record_outcome_propagation(
            "b3",
            BoundaryOutcome::Cancelled,
            BoundaryOutcome::Timeout,
        );
        assert_eq!(p3, BoundaryOutcome::Cancelled);
    }

    #[test]
    fn test_validator_combined_narrowing_and_outcome() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent_caps = CapabilityGrant::full();
        let child_caps = CapabilityGrant::sandbox();

        // Step 1: validate narrowing
        let direction =
            validator.validate_narrowing("parent", "child", "spawn", &parent_caps, &child_caps);
        assert_eq!(direction, NarrowingDirection::Narrowed);

        // Step 2: record outcome
        let propagated = validator.record_outcome_propagation(
            "spawn",
            BoundaryOutcome::Failure,
            BoundaryOutcome::Success,
        );
        assert_eq!(propagated, BoundaryOutcome::Failure);

        // Check the transition was updated
        let last = validator.transitions().last().unwrap();
        assert_eq!(last.child_outcome, Some(BoundaryOutcome::Failure));
        assert_eq!(last.propagated_outcome, Some(BoundaryOutcome::Failure));

        assert!(!validator.has_violations());
    }

    #[test]
    fn test_report_clean() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        validator.validate_narrowing("p", "c", "test", &parent, &child);

        let report = validator.build_report();
        assert!(report.is_clean());
        assert_eq!(report.total_transitions, 1);
        assert_eq!(*report.direction_counts.get("narrowed").unwrap_or(&0), 1);
    }

    #[test]
    fn test_report_with_violations() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::sandbox();
        let child = CapabilityGrant::full();

        validator.validate_narrowing("p", "c", "bad", &parent, &child);

        let report = validator.build_report();
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 1);
    }

    #[test]
    fn test_report_content_hash_deterministic() {
        let make_report = || {
            let mut v = CapabilityNarrowingValidator::with_defaults();
            let parent = CapabilityGrant::full();
            let child = CapabilityGrant::sandbox();
            v.validate_narrowing("p", "c", "test", &parent, &child);
            v.build_report()
        };

        let r1 = make_report();
        let r2 = make_report();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();
        validator.validate_narrowing("p", "c", "test", &parent, &child);
        let report = validator.build_report();

        let json = serde_json::to_string(&report).unwrap();
        let round: NarrowingReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn test_capability_grant_serde_roundtrip() {
        for grant in [
            CapabilityGrant::none(),
            CapabilityGrant::full(),
            CapabilityGrant::compute_only(),
            CapabilityGrant::sandbox(),
        ] {
            let json = serde_json::to_string(&grant).unwrap();
            let round: CapabilityGrant = serde_json::from_str(&json).unwrap();
            assert_eq!(grant, round);
        }
    }

    #[test]
    fn test_narrowing_violation_display() {
        let v = NarrowingViolation::CapabilityWidening {
            boundary_label: "test".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        };
        let msg = v.to_string();
        assert!(msg.contains("widening"));
        assert!(msg.contains("network"));
    }

    #[test]
    fn test_boundary_transition_serde_roundtrip() {
        let t = BoundaryTransition {
            parent_trace_id: "parent-123".to_owned(),
            child_trace_id: "child-456".to_owned(),
            boundary_label: "spawn_ext".to_owned(),
            parent_capabilities: CapabilityGrant::full(),
            child_capabilities: CapabilityGrant::sandbox(),
            narrowed_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::FileSystemWrite);
                s
            },
            direction: NarrowingDirection::Narrowed,
            child_outcome: Some(BoundaryOutcome::Success),
            propagated_outcome: Some(BoundaryOutcome::Success),
            sequence: 1,
        };
        let json = serde_json::to_string(&t).unwrap();
        let round: BoundaryTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, round);
    }

    #[test]
    fn test_none_is_subset_of_everything() {
        let none = CapabilityGrant::none();
        assert!(none.is_subset_of(&CapabilityGrant::none()));
        assert!(none.is_subset_of(&CapabilityGrant::compute_only()));
        assert!(none.is_subset_of(&CapabilityGrant::sandbox()));
        assert!(none.is_subset_of(&CapabilityGrant::full()));
    }

    #[test]
    fn test_full_is_superset_of_everything() {
        let full = CapabilityGrant::full();
        assert!(CapabilityGrant::none().is_subset_of(&full));
        assert!(CapabilityGrant::compute_only().is_subset_of(&full));
        assert!(CapabilityGrant::sandbox().is_subset_of(&full));
        assert!(full.is_subset_of(&full));
    }

    #[test]
    fn test_multiple_narrowings_monotonic() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let full = CapabilityGrant::full();
        let sandbox = CapabilityGrant::sandbox();
        let compute = CapabilityGrant::compute_only();

        // full → sandbox → compute: each is strictly narrower
        let d1 = validator.validate_narrowing("p1", "c1", "b1", &full, &sandbox);
        assert_eq!(d1, NarrowingDirection::Narrowed);

        let d2 = validator.validate_narrowing("c1", "c2", "b2", &sandbox, &compute);
        assert_eq!(d2, NarrowingDirection::Narrowed);

        assert!(!validator.has_violations());
        assert_eq!(validator.transitions().len(), 2);
    }

    #[test]
    fn test_outcome_budget_related() {
        assert!(!BoundaryOutcome::Success.is_budget_related());
        assert!(!BoundaryOutcome::Failure.is_budget_related());
        assert!(BoundaryOutcome::Timeout.is_budget_related());
        assert!(!BoundaryOutcome::Cancelled.is_budget_related());
    }
}
