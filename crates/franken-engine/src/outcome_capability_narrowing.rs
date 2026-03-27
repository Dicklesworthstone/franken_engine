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

impl std::fmt::Display for BoundaryOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// Pure computation capability.
    Compute,
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
            Self::Compute => "compute",
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
            Self::Compute,
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
        tokens.insert(CapabilityToken::Compute);
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
        tokens.insert(CapabilityToken::Compute);
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

impl std::fmt::Display for NarrowingDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Narrowed => "narrowed",
            Self::Preserved => "preserved",
            Self::Widened => "widened",
        };
        f.write_str(s)
    }
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
        if let Some(last) = self.transitions.last_mut()
            && last.boundary_label == boundary_label
        {
            last.child_outcome = Some(child_outcome);
            last.propagated_outcome = Some(propagated);
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

        let content = {
            let mut s = format!(
                "transitions={},violations={},epoch={}",
                self.transitions.len(),
                self.violations.len(),
                self.epoch.as_u64(),
            );
            // direction_counts and outcome_counts are BTreeMap — deterministic.
            for (dir, count) in &direction_counts {
                s.push_str(&format!("|dir:{dir}={count}"));
            }
            for (outcome, count) in &outcome_counts {
                s.push_str(&format!("|out:{outcome}={count}"));
            }
            for v in &self.violations {
                s.push_str(&format!("|v:{v}"));
            }
            s
        };
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
        assert_eq!(all.len(), 13);
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
        assert_eq!(grant.len(), 13);
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

    // -----------------------------------------------------------------------
    // Deep tests — enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn test_capability_token_serde_roundtrip_all_variants() {
        for token in CapabilityToken::all() {
            let json = serde_json::to_string(token).unwrap();
            let round: CapabilityToken = serde_json::from_str(&json).unwrap();
            assert_eq!(*token, round, "serde roundtrip failed for {:?}", token);
        }
    }

    #[test]
    fn test_narrowing_direction_serde_roundtrip() {
        for dir in [
            NarrowingDirection::Narrowed,
            NarrowingDirection::Preserved,
            NarrowingDirection::Widened,
        ] {
            let json = serde_json::to_string(&dir).unwrap();
            let round: NarrowingDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(dir, round, "serde roundtrip failed for {:?}", dir);
        }
    }

    #[test]
    fn test_outcome_propagation_rule_serde_roundtrip_all_variants() {
        let rules = [
            OutcomePropagationRule::Preserve,
            OutcomePropagationRule::CollapseToFailure,
            OutcomePropagationRule::SeverityThreshold { min_severity: 0 },
            OutcomePropagationRule::SeverityThreshold { min_severity: 3 },
            OutcomePropagationRule::EscalateToMostSevere,
        ];
        for rule in &rules {
            let json = serde_json::to_string(rule).unwrap();
            let round: OutcomePropagationRule = serde_json::from_str(&json).unwrap();
            assert_eq!(*rule, round, "serde roundtrip failed for {:?}", rule);
        }
    }

    #[test]
    fn test_narrowing_violation_serde_roundtrip_all_variants() {
        let violations = vec![
            NarrowingViolation::CapabilityWidening {
                boundary_label: "b1".to_owned(),
                widened_tokens: {
                    let mut s = BTreeSet::new();
                    s.insert(CapabilityToken::NetworkAccess);
                    s.insert(CapabilityToken::CryptoAccess);
                    s
                },
            },
            NarrowingViolation::OutcomeUpgrade {
                boundary_label: "b2".to_owned(),
                child_outcome: BoundaryOutcome::Cancelled,
                propagated_outcome: BoundaryOutcome::Failure,
            },
            NarrowingViolation::UnknownOutcomeNotFailClosed {
                boundary_label: "b3".to_owned(),
            },
        ];
        for v in &violations {
            let json = serde_json::to_string(v).unwrap();
            let round: NarrowingViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, round, "serde roundtrip failed for {:?}", v);
        }
    }

    // -----------------------------------------------------------------------
    // Deep tests — Display / as_str consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_boundary_outcome_display_matches_as_str() {
        for outcome in [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ] {
            assert_eq!(
                outcome.to_string(),
                outcome.as_str(),
                "Display and as_str disagree for {:?}",
                outcome
            );
        }
    }

    #[test]
    fn test_narrowing_direction_display_values() {
        assert_eq!(NarrowingDirection::Narrowed.to_string(), "narrowed");
        assert_eq!(NarrowingDirection::Preserved.to_string(), "preserved");
        assert_eq!(NarrowingDirection::Widened.to_string(), "widened");
    }

    #[test]
    fn test_capability_token_as_str_unique_per_variant() {
        let all = CapabilityToken::all();
        let labels: BTreeSet<&str> = all.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            labels.len(),
            all.len(),
            "duplicate as_str values among CapabilityToken variants"
        );
    }

    // -----------------------------------------------------------------------
    // Deep tests — error Display formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_outcome_upgrade_violation_display_format() {
        let v = NarrowingViolation::OutcomeUpgrade {
            boundary_label: "spawn_ext".to_owned(),
            child_outcome: BoundaryOutcome::Cancelled,
            propagated_outcome: BoundaryOutcome::Failure,
        };
        let msg = v.to_string();
        assert!(msg.contains("outcome upgrade at spawn_ext"));
        assert!(msg.contains("cancelled"));
        assert!(msg.contains("failure"));
        // Verify arrow separator
        assert!(msg.contains("→"));
    }

    #[test]
    fn test_unknown_outcome_not_fail_closed_display() {
        let v = NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "external_gateway".to_owned(),
        };
        let msg = v.to_string();
        assert_eq!(msg, "unknown outcome not fail-closed at external_gateway");
    }

    #[test]
    fn test_capability_widening_display_multiple_tokens() {
        let mut widened = BTreeSet::new();
        widened.insert(CapabilityToken::FileSystemRead);
        widened.insert(CapabilityToken::FileSystemWrite);
        widened.insert(CapabilityToken::NetworkAccess);
        let v = NarrowingViolation::CapabilityWidening {
            boundary_label: "bad_spawn".to_owned(),
            widened_tokens: widened,
        };
        let msg = v.to_string();
        // BTreeSet ordering: FileSystemRead < FileSystemWrite < NetworkAccess
        assert!(msg.contains("fs_read"));
        assert!(msg.contains("fs_write"));
        assert!(msg.contains("network"));
        assert!(msg.contains("bad_spawn"));
    }

    // -----------------------------------------------------------------------
    // Deep tests — edge cases (empty inputs, boundary values)
    // -----------------------------------------------------------------------

    #[test]
    fn test_intersect_empty_with_full_yields_empty() {
        let empty = CapabilityGrant::none();
        let full = CapabilityGrant::full();
        let result = empty.intersect(&full);
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_intersect_full_with_full_yields_full() {
        let full1 = CapabilityGrant::full();
        let full2 = CapabilityGrant::full();
        let result = full1.intersect(&full2);
        assert_eq!(result.len(), 13);
        assert!(result.is_subset_of(&full1));
    }

    #[test]
    fn test_difference_identical_grants_is_empty() {
        let sandbox = CapabilityGrant::sandbox();
        let diff = sandbox.difference(&sandbox);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_difference_empty_from_anything_is_empty() {
        let empty = CapabilityGrant::none();
        let full = CapabilityGrant::full();
        let diff = empty.difference(&full);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_severity_threshold_zero_passes_everything() {
        let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 0 };
        for outcome in [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ] {
            let result = rule.apply(outcome, BoundaryOutcome::Failure);
            assert_eq!(
                result, outcome,
                "threshold 0 should pass through {:?}",
                outcome
            );
        }
    }

    #[test]
    fn test_severity_threshold_max_blocks_everything_except_cancelled() {
        let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 3 };
        // Only Cancelled (severity 3) meets the threshold
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Failure, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Cancelled, BoundaryOutcome::Success),
            BoundaryOutcome::Cancelled
        );
    }

    #[test]
    fn test_severity_threshold_above_all_blocks_everything() {
        let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 255 };
        for outcome in [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ] {
            let result = rule.apply(outcome, BoundaryOutcome::Success);
            assert_eq!(
                result,
                BoundaryOutcome::Success,
                "threshold 255 should block {:?}",
                outcome
            );
        }
    }

    // -----------------------------------------------------------------------
    // Deep tests — state machine transitions
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_sequence_numbers_increment_monotonically() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        for i in 0..5 {
            validator.validate_narrowing(
                &format!("p{}", i),
                &format!("c{}", i),
                &format!("b{}", i),
                &parent,
                &child,
            );
        }

        let sequences: Vec<u64> = validator.transitions().iter().map(|t| t.sequence).collect();
        assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_outcome_propagation_updates_last_matching_transition() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        validator.validate_narrowing("p1", "c1", "boundary_a", &parent, &child);
        validator.validate_narrowing("p2", "c2", "boundary_b", &parent, &child);

        // Record outcome for boundary_b (last transition)
        validator.record_outcome_propagation(
            "boundary_b",
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Success,
        );

        // boundary_a should NOT have outcome set
        assert_eq!(validator.transitions()[0].child_outcome, None);
        assert_eq!(validator.transitions()[0].propagated_outcome, None);

        // boundary_b should have outcome set
        assert_eq!(
            validator.transitions()[1].child_outcome,
            Some(BoundaryOutcome::Timeout)
        );
        assert_eq!(
            validator.transitions()[1].propagated_outcome,
            Some(BoundaryOutcome::Timeout)
        );
    }

    #[test]
    fn test_outcome_propagation_non_matching_boundary_leaves_transitions_unchanged() {
        let mut validator = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        validator.validate_narrowing("p", "c", "boundary_x", &parent, &child);

        // Record for a different boundary label
        validator.record_outcome_propagation(
            "boundary_y",
            BoundaryOutcome::Failure,
            BoundaryOutcome::Success,
        );

        // The transition should NOT be updated because labels don't match
        let t = &validator.transitions()[0];
        assert_eq!(t.child_outcome, None);
        assert_eq!(t.propagated_outcome, None);
    }

    #[test]
    fn test_escalate_same_severity_keeps_parent() {
        let rule = OutcomePropagationRule::EscalateToMostSevere;
        // When child and parent have the same severity, parent_current wins
        assert_eq!(
            rule.apply(BoundaryOutcome::Failure, BoundaryOutcome::Failure),
            BoundaryOutcome::Failure
        );
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Success),
            BoundaryOutcome::Success
        );
    }

    #[test]
    fn test_collapse_to_failure_preserves_success_exactly() {
        let rule = OutcomePropagationRule::CollapseToFailure;
        assert_eq!(
            rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Cancelled),
            BoundaryOutcome::Success
        );
    }

    // -----------------------------------------------------------------------
    // Deep tests — canonical hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn test_report_content_hash_changes_with_different_transitions() {
        let report_a = {
            let mut v = CapabilityNarrowingValidator::with_defaults();
            v.validate_narrowing(
                "p",
                "c",
                "a",
                &CapabilityGrant::full(),
                &CapabilityGrant::sandbox(),
            );
            v.build_report()
        };

        let report_b = {
            let mut v = CapabilityNarrowingValidator::with_defaults();
            v.validate_narrowing(
                "p",
                "c",
                "a",
                &CapabilityGrant::full(),
                &CapabilityGrant::sandbox(),
            );
            // Add a widening violation to change the violation count
            v.validate_narrowing(
                "p",
                "c",
                "b",
                &CapabilityGrant::sandbox(),
                &CapabilityGrant::full(),
            );
            v.build_report()
        };

        assert_ne!(
            report_a.content_hash, report_b.content_hash,
            "reports with different transitions should have different hashes"
        );
    }

    #[test]
    fn test_report_content_hash_stable_across_repeated_builds() {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            "p",
            "c",
            "test",
            &CapabilityGrant::full(),
            &CapabilityGrant::compute_only(),
        );
        v.record_outcome_propagation("test", BoundaryOutcome::Failure, BoundaryOutcome::Success);

        let r1 = v.build_report();
        let r2 = v.build_report();
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // Deep tests — validator serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_serde_roundtrip_preserves_state() {
        let mut validator = CapabilityNarrowingValidator::new(
            OutcomePropagationRule::EscalateToMostSevere,
            SecurityEpoch::from_raw(42),
        );
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        validator.validate_narrowing("p1", "c1", "b1", &parent, &child);
        validator.record_outcome_propagation(
            "b1",
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Success,
        );

        // Also trigger a widening violation
        validator.validate_narrowing("c1", "c2", "b2", &child, &parent);

        let json = serde_json::to_string(&validator).unwrap();
        let round: CapabilityNarrowingValidator = serde_json::from_str(&json).unwrap();

        assert_eq!(round.transitions().len(), 2);
        assert_eq!(round.violations().len(), 1);
        assert!(round.has_violations());
    }

    // -----------------------------------------------------------------------
    // Deep tests — intersect label composition
    // -----------------------------------------------------------------------

    #[test]
    fn test_intersect_label_composed_from_parents() {
        let sandbox = CapabilityGrant::sandbox();
        let compute = CapabilityGrant::compute_only();
        let result = sandbox.intersect(&compute);
        assert_eq!(result.label, "sandbox∩compute_only");
    }

    // -----------------------------------------------------------------------
    // Deep tests — full outcome severity matrix
    // -----------------------------------------------------------------------

    #[test]
    fn test_escalate_full_severity_matrix() {
        let rule = OutcomePropagationRule::EscalateToMostSevere;
        let outcomes = [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ];

        for &child in &outcomes {
            for &parent in &outcomes {
                let result = rule.apply(child, parent);
                // The result should always be the one with higher severity
                assert!(
                    result.severity() >= child.severity() || result.severity() >= parent.severity()
                );
                // More precisely: result == max(child, parent) by severity
                let expected_severity = std::cmp::max(child.severity(), parent.severity());
                assert_eq!(
                    result.severity(),
                    expected_severity,
                    "escalate({:?}, {:?}) produced {:?} with severity {}, expected severity {}",
                    child,
                    parent,
                    result,
                    result.severity(),
                    expected_severity
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Deep tests — report outcome counts reflect recorded propagations
    // -----------------------------------------------------------------------

    #[test]
    fn test_report_outcome_counts_populated() {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();

        // Transition 1 with outcome
        v.validate_narrowing("p1", "c1", "b1", &parent, &child);
        v.record_outcome_propagation("b1", BoundaryOutcome::Success, BoundaryOutcome::Success);

        // Transition 2 with outcome
        v.validate_narrowing("p2", "c2", "b2", &parent, &child);
        v.record_outcome_propagation("b2", BoundaryOutcome::Failure, BoundaryOutcome::Success);

        // Transition 3 with outcome
        v.validate_narrowing("p3", "c3", "b3", &parent, &child);
        v.record_outcome_propagation("b3", BoundaryOutcome::Failure, BoundaryOutcome::Success);

        let report = v.build_report();
        assert_eq!(report.total_transitions, 3);
        assert_eq!(*report.outcome_counts.get("success").unwrap_or(&0), 1);
        assert_eq!(*report.outcome_counts.get("failure").unwrap_or(&0), 2);
        assert!(report.is_clean());
    }

    // -----------------------------------------------------------------------
    // Deep tests — compute_only is subset of sandbox
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_only_subset_of_sandbox_tokens() {
        let compute = CapabilityGrant::compute_only();
        let sandbox = CapabilityGrant::sandbox();
        // compute_only: Compute, TelemetryEmit, TimerAccess
        // sandbox: Compute, TelemetryEmit, TimerAccess, HostcallInvoke, ModuleLoad
        assert!(compute.is_subset_of(&sandbox));
        assert!(!sandbox.is_subset_of(&compute));
        // sandbox has exactly 2 more tokens
        let extra = sandbox.difference(&compute);
        assert_eq!(extra.len(), 2);
        assert!(extra.contains(&CapabilityToken::HostcallInvoke));
        assert!(extra.contains(&CapabilityToken::ModuleLoad));
    }

    // -----------------------------------------------------------------------
    // Deep tests — empty validator report
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_validator_report() {
        let v = CapabilityNarrowingValidator::with_defaults();
        let report = v.build_report();
        assert!(report.is_clean());
        assert_eq!(report.total_transitions, 0);
        assert!(report.direction_counts.is_empty());
        assert!(report.outcome_counts.is_empty());
        assert!(report.violations.is_empty());
        assert_eq!(report.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn test_outcome_severity_values_are_contiguous() {
        let outcomes = [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ];
        for (i, outcome) in outcomes.iter().enumerate() {
            assert_eq!(
                outcome.severity(),
                i as u8,
                "severity for {:?} should be {}",
                outcome,
                i
            );
        }
    }
}
