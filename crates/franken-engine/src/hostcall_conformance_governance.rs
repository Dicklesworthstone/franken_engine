//! Per-axis conformance governance, replay-drop telemetry, degraded-mode
//! policies, and observability claim deltas for hostcall sessions.
//!
//! Implements [RGC-505C] (bead bd-1lsy.6.5.3): gates the hostcall channel
//! with per-axis conformance vectors, per-category replay-drop budgets,
//! policy-visible degraded-mode rules with auto-recovery semantics, and
//! observability-mode claim deltas with tolerance checking so boundary
//! wins survive the telemetry needed to operate them.
//!
//! This module complements [`hostcall_session_governance_gate`] by
//! providing finer-grained, axis-level governance rather than
//! session-level aggregate gating.
//!
//! # Design
//!
//! - `ConformanceAxis` enumerates the six protocol axes checked.
//! - `ConformanceResult` captures per-axis pass/fail with a ratio.
//! - `ReplayDropCategory` classifies replay-drop root causes.
//! - `ReplayDropEntry` records per-category drop telemetry with budgets.
//! - `DegradedModeKind` classifies degraded-mode flavours.
//! - `DegradedModePolicy` configures per-kind max duration and recovery.
//! - `ObservabilityClaimDelta` measures claim-level instrumentation drift.
//! - `GovernanceConfig` aggregates all thresholds.
//! - `GovernanceVerdict` is the multi-violation-aware decision.
//! - `GovernanceEvaluator` accumulates evidence and produces a receipt.
//! - `GovernanceReceipt` bundles verdict, epoch, violations, and hash.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-505C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.hostcall-conformance-governance.v1";

/// Component name.
pub const COMPONENT: &str = "hostcall_conformance_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.6.5.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-505C";

/// Default minimum per-axis conformance ratio (millionths). 90% = 900_000.
pub const DEFAULT_MIN_CONFORMANCE: u64 = 900_000;

/// Default maximum per-category replay-drop rate (millionths). 5% = 50_000.
pub const DEFAULT_MAX_DROP_RATE: u64 = 50_000;

/// Default maximum degraded-mode duration in nanoseconds (60 seconds).
pub const DEFAULT_MAX_DEGRADED_DURATION_NS: u64 = 60_000_000_000;

/// Default minimum observability-mode claim delta tolerance (millionths).
/// A 5% tolerance = 50_000.
pub const DEFAULT_OBSERVABILITY_TOLERANCE: u64 = 50_000;

/// Minimum number of required axes for sufficient coverage.
pub const DEFAULT_MIN_REQUIRED_AXES: usize = 4;

// ---------------------------------------------------------------------------
// ConformanceAxis
// ---------------------------------------------------------------------------

/// Protocol axis checked for hostcall conformance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceAxis {
    /// Wire protocol framing and message structure.
    Protocol,
    /// Message ordering and sequencing guarantees.
    Ordering,
    /// Payload encoding correctness (serialization round-trips).
    Encoding,
    /// Timeout policy adherence.
    Timeout,
    /// Mutual authentication checks.
    Authentication,
    /// Capability-gated authorization checks.
    Authorization,
}

impl ConformanceAxis {
    pub const ALL: &[Self] = &[
        Self::Protocol,
        Self::Ordering,
        Self::Encoding,
        Self::Timeout,
        Self::Authentication,
        Self::Authorization,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Ordering => "ordering",
            Self::Encoding => "encoding",
            Self::Timeout => "timeout",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
        }
    }
}

impl fmt::Display for ConformanceAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ConformanceResult
// ---------------------------------------------------------------------------

/// Per-axis conformance measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceResult {
    /// Which axis this result covers.
    pub axis: ConformanceAxis,
    /// Number of checks that passed.
    pub pass_count: u64,
    /// Number of checks that failed.
    pub fail_count: u64,
    /// Conformance ratio (millionths, 0-1_000_000).
    pub conformance_ratio_millionths: u64,
    /// Whether this axis passes at the given threshold.
    pub passes: bool,
}

impl ConformanceResult {
    /// Build a result from pass/fail counts and a threshold.
    pub fn new(axis: ConformanceAxis, pass_count: u64, fail_count: u64, threshold: u64) -> Self {
        let total = pass_count.saturating_add(fail_count);
        let conformance_ratio_millionths = pass_count
            .saturating_mul(1_000_000)
            .checked_div(total)
            .unwrap_or(0);
        let passes = conformance_ratio_millionths >= threshold;
        Self {
            axis,
            pass_count,
            fail_count,
            conformance_ratio_millionths,
            passes,
        }
    }

    /// Total checks (pass + fail).
    pub fn total_count(&self) -> u64 {
        self.pass_count.saturating_add(self.fail_count)
    }
}

impl fmt::Display for ConformanceResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance[{}]: {}/{} ({}ppm) {}",
            self.axis,
            self.pass_count,
            self.total_count(),
            self.conformance_ratio_millionths,
            if self.passes { "PASS" } else { "FAIL" },
        )
    }
}

// ---------------------------------------------------------------------------
// ReplayDropCategory
// ---------------------------------------------------------------------------

/// Root-cause category for replay-dropped messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDropCategory {
    /// Replay could not complete within the time budget.
    TimeBudgetExceeded,
    /// Protocol-level mismatch prevented replay.
    ProtocolMismatch,
    /// Encoding error corrupted the replay payload.
    EncodingError,
    /// Authentication failed for the replayed message.
    AuthenticationFailure,
    /// Replay violated an active policy constraint.
    PolicyViolation,
}

impl ReplayDropCategory {
    pub const ALL: &[Self] = &[
        Self::TimeBudgetExceeded,
        Self::ProtocolMismatch,
        Self::EncodingError,
        Self::AuthenticationFailure,
        Self::PolicyViolation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimeBudgetExceeded => "time_budget_exceeded",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::EncodingError => "encoding_error",
            Self::AuthenticationFailure => "authentication_failure",
            Self::PolicyViolation => "policy_violation",
        }
    }

    /// Whether this category is security-sensitive.
    pub const fn is_security_sensitive(self) -> bool {
        matches!(self, Self::AuthenticationFailure | Self::PolicyViolation)
    }
}

impl fmt::Display for ReplayDropCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ReplayDropEntry
// ---------------------------------------------------------------------------

/// Per-category replay-drop telemetry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDropEntry {
    /// Root-cause category.
    pub category: ReplayDropCategory,
    /// Number of messages dropped in this category.
    pub drop_count: u64,
    /// Total replays attempted in this window.
    pub total_replays: u64,
    /// Drop rate (millionths, 0-1_000_000).
    pub drop_rate_millionths: u64,
    /// Whether this entry is within the configured budget.
    pub within_budget: bool,
}

impl ReplayDropEntry {
    /// Build an entry with computed rate and budget check.
    pub fn new(
        category: ReplayDropCategory,
        drop_count: u64,
        total_replays: u64,
        max_rate: u64,
    ) -> Self {
        let drop_rate_millionths = match total_replays {
            0 if drop_count == 0 => 0,
            0 => 1_000_000,
            _ => drop_count
                .saturating_mul(1_000_000)
                .checked_div(total_replays)
                .unwrap_or(1_000_000),
        };
        let within_budget = match total_replays {
            0 => drop_count == 0,
            _ => drop_rate_millionths <= max_rate,
        };
        Self {
            category,
            drop_count,
            total_replays,
            drop_rate_millionths,
            within_budget,
        }
    }
}

impl fmt::Display for ReplayDropEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "replay-drop[{}]: {}/{} ({}ppm) {}",
            self.category,
            self.drop_count,
            self.total_replays,
            self.drop_rate_millionths,
            if self.within_budget {
                "WITHIN_BUDGET"
            } else {
                "OVER_BUDGET"
            },
        )
    }
}

// ---------------------------------------------------------------------------
// DegradedModeKind
// ---------------------------------------------------------------------------

/// Flavour of degraded-mode operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedModeKind {
    /// Bandwidth throttled below nominal capacity.
    ReducedBandwidth,
    /// Latency increased above nominal bounds.
    IncreasedLatency,
    /// Some hostcall operations unavailable.
    PartialFunctionality,
    /// Session restricted to read-only operations.
    ReadOnly,
    /// Session fully disconnected from host.
    Disconnected,
}

impl DegradedModeKind {
    pub const ALL: &[Self] = &[
        Self::ReducedBandwidth,
        Self::IncreasedLatency,
        Self::PartialFunctionality,
        Self::ReadOnly,
        Self::Disconnected,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReducedBandwidth => "reduced_bandwidth",
            Self::IncreasedLatency => "increased_latency",
            Self::PartialFunctionality => "partial_functionality",
            Self::ReadOnly => "read_only",
            Self::Disconnected => "disconnected",
        }
    }

    /// Severity rank (higher = more degraded). Used for tiebreaking.
    pub const fn severity_rank(self) -> u32 {
        match self {
            Self::ReducedBandwidth => 1,
            Self::IncreasedLatency => 2,
            Self::PartialFunctionality => 3,
            Self::ReadOnly => 4,
            Self::Disconnected => 5,
        }
    }

    /// Whether this kind is terminal (cannot auto-recover).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Disconnected)
    }
}

impl fmt::Display for DegradedModeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DegradedModePolicy
// ---------------------------------------------------------------------------

/// Policy governing a degraded-mode episode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModePolicy {
    /// Which degradation kind this policy applies to.
    pub kind: DegradedModeKind,
    /// Maximum allowed duration in nanoseconds before escalation.
    pub max_duration_ns: u64,
    /// Whether an operator acknowledgement is required to continue.
    pub requires_operator_ack: bool,
    /// Whether the session can auto-recover from this state.
    pub auto_recovery: bool,
}

impl DegradedModePolicy {
    /// Create a default policy for a given kind.
    pub fn for_kind(kind: DegradedModeKind) -> Self {
        match kind {
            DegradedModeKind::ReducedBandwidth => Self {
                kind,
                max_duration_ns: DEFAULT_MAX_DEGRADED_DURATION_NS,
                requires_operator_ack: false,
                auto_recovery: true,
            },
            DegradedModeKind::IncreasedLatency => Self {
                kind,
                max_duration_ns: DEFAULT_MAX_DEGRADED_DURATION_NS,
                requires_operator_ack: false,
                auto_recovery: true,
            },
            DegradedModeKind::PartialFunctionality => Self {
                kind,
                max_duration_ns: DEFAULT_MAX_DEGRADED_DURATION_NS * 2,
                requires_operator_ack: true,
                auto_recovery: true,
            },
            DegradedModeKind::ReadOnly => Self {
                kind,
                max_duration_ns: DEFAULT_MAX_DEGRADED_DURATION_NS * 5,
                requires_operator_ack: true,
                auto_recovery: false,
            },
            DegradedModeKind::Disconnected => Self {
                kind,
                max_duration_ns: 0,
                requires_operator_ack: true,
                auto_recovery: false,
            },
        }
    }

    /// Whether the given duration exceeds the policy limit.
    pub fn exceeds_duration(&self, duration_ns: u64) -> bool {
        duration_ns > self.max_duration_ns
    }

    /// Whether auto-recovery is available and the session can heal
    /// without operator intervention.
    pub fn can_auto_recover(&self) -> bool {
        self.auto_recovery && !self.kind.is_terminal()
    }
}

impl fmt::Display for DegradedModePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "degraded-policy[{}]: max_ns={} ack={} auto={}",
            self.kind, self.max_duration_ns, self.requires_operator_ack, self.auto_recovery,
        )
    }
}

// ---------------------------------------------------------------------------
// DegradedModeViolation
// ---------------------------------------------------------------------------

/// A specific violation of a degraded-mode policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeViolation {
    /// The kind that was violated.
    pub kind: DegradedModeKind,
    /// Observed duration in nanoseconds.
    pub observed_duration_ns: u64,
    /// Policy limit in nanoseconds.
    pub max_duration_ns: u64,
    /// Whether operator ack was required but missing.
    pub missing_operator_ack: bool,
}

impl fmt::Display for DegradedModeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "degraded-violation[{}]: observed={}ns max={}ns ack_missing={}",
            self.kind, self.observed_duration_ns, self.max_duration_ns, self.missing_operator_ack,
        )
    }
}

// ---------------------------------------------------------------------------
// ObservabilityClaimDelta
// ---------------------------------------------------------------------------

/// Measures drift between a baseline observability claim and the observed
/// value, with tolerance checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityClaimDelta {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Baseline value (millionths).
    pub baseline_millionths: u64,
    /// Observed value (millionths).
    pub observed_millionths: u64,
    /// Absolute delta (millionths). Always non-negative.
    pub delta_millionths: u64,
    /// Whether the delta is within the configured tolerance.
    pub within_tolerance: bool,
}

impl ObservabilityClaimDelta {
    /// Build a delta from baseline/observed and a tolerance threshold.
    pub fn new(
        claim_id: impl Into<String>,
        baseline_millionths: u64,
        observed_millionths: u64,
        tolerance: u64,
    ) -> Self {
        let delta_millionths = observed_millionths.abs_diff(baseline_millionths);
        let within_tolerance = delta_millionths <= tolerance;
        Self {
            claim_id: claim_id.into(),
            baseline_millionths,
            observed_millionths,
            delta_millionths,
            within_tolerance,
        }
    }

    /// Relative drift as a fraction of the baseline (millionths).
    pub fn relative_drift_millionths(&self) -> u64 {
        if self.baseline_millionths == 0 {
            return if self.delta_millionths == 0 {
                0
            } else {
                1_000_000
            };
        }
        self.delta_millionths
            .saturating_mul(1_000_000)
            .checked_div(self.baseline_millionths)
            .unwrap_or(0)
    }
}

impl fmt::Display for ObservabilityClaimDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim-delta[{}]: baseline={} observed={} delta={} {}",
            self.claim_id,
            self.baseline_millionths,
            self.observed_millionths,
            self.delta_millionths,
            if self.within_tolerance {
                "WITHIN"
            } else {
                "DRIFTED"
            },
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Aggregated configuration for all governance checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum per-axis conformance ratio (millionths).
    pub min_conformance: u64,
    /// Maximum per-category replay-drop rate (millionths).
    pub max_drop_rate: u64,
    /// Maximum degraded-mode duration (nanoseconds).
    pub max_degraded_duration: u64,
    /// Minimum observability-mode delta tolerance (millionths).
    pub min_observability_tolerance: u64,
    /// Minimum number of conformance axes required for coverage.
    pub required_axes: usize,
}

impl GovernanceConfig {
    /// Strict configuration for production.
    pub fn strict() -> Self {
        Self {
            min_conformance: 950_000,
            max_drop_rate: 10_000,
            max_degraded_duration: 30_000_000_000,
            min_observability_tolerance: 20_000,
            required_axes: 6,
        }
    }

    /// Permissive configuration for testing.
    pub fn permissive() -> Self {
        Self {
            min_conformance: 500_000,
            max_drop_rate: 200_000,
            max_degraded_duration: u64::MAX,
            min_observability_tolerance: 500_000,
            required_axes: 1,
        }
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            min_conformance: DEFAULT_MIN_CONFORMANCE,
            max_drop_rate: DEFAULT_MAX_DROP_RATE,
            max_degraded_duration: DEFAULT_MAX_DEGRADED_DURATION_NS,
            min_observability_tolerance: DEFAULT_OBSERVABILITY_TOLERANCE,
            required_axes: DEFAULT_MIN_REQUIRED_AXES,
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Multi-violation-aware governance decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks pass.
    Approved,
    /// One or more conformance axes failed.
    ConformanceViolation,
    /// Replay-drop rate exceeded budget.
    DropRateExceeded,
    /// Degraded-mode policy violated (duration or ack).
    DegradedModePolicyViolation,
    /// Observability claim drift exceeded tolerance.
    ObservabilityDrift,
    /// Not enough conformance axes were tested.
    InsufficientCoverage,
    /// Two or more distinct violation categories detected.
    MultipleViolations,
}

impl GovernanceVerdict {
    pub const ALL: &[Self] = &[
        Self::Approved,
        Self::ConformanceViolation,
        Self::DropRateExceeded,
        Self::DegradedModePolicyViolation,
        Self::ObservabilityDrift,
        Self::InsufficientCoverage,
        Self::MultipleViolations,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ConformanceViolation => "conformance_violation",
            Self::DropRateExceeded => "drop_rate_exceeded",
            Self::DegradedModePolicyViolation => "degraded_mode_policy_violation",
            Self::ObservabilityDrift => "observability_drift",
            Self::InsufficientCoverage => "insufficient_coverage",
            Self::MultipleViolations => "multiple_violations",
        }
    }

    /// Whether this verdict allows the session to proceed.
    pub fn is_approved(self) -> bool {
        self == Self::Approved
    }

    /// Whether this verdict represents a failure.
    pub fn is_failure(self) -> bool {
        self != Self::Approved
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ViolationEntry
// ---------------------------------------------------------------------------

/// A specific violation detected during governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationEntry {
    /// Category of violation.
    pub category: GovernanceVerdict,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for ViolationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.description)
    }
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt from a governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Final verdict.
    pub verdict: GovernanceVerdict,
    /// Security epoch at evaluation time.
    pub epoch: SecurityEpoch,
    /// Number of conformance entries evaluated.
    pub conformance_count: usize,
    /// Number of replay-drop entries evaluated.
    pub drop_entry_count: usize,
    /// Number of degraded-mode policies checked.
    pub degraded_policy_count: usize,
    /// Number of observability claim deltas checked.
    pub claim_delta_count: usize,
    /// All violations detected.
    pub violations: Vec<ViolationEntry>,
    /// Content hash of the receipt.
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    /// Total evidence entries.
    pub fn total_entries(&self) -> usize {
        self.conformance_count
            + self.drop_entry_count
            + self.degraded_policy_count
            + self.claim_delta_count
    }

    /// Whether the evaluation passed.
    pub fn is_approved(&self) -> bool {
        self.verdict.is_approved()
    }

    /// Whether violations were detected.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Number of violations.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

impl fmt::Display for GovernanceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}]: {} at {} entries={} violations={}",
            COMPONENT,
            self.verdict,
            self.epoch,
            self.total_entries(),
            self.violations.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a u64 value to a SHA-256 hasher.
fn append_u64(h: &mut Sha256, value: u64) {
    h.update(value.to_le_bytes());
}

/// Append a string to a SHA-256 hasher.
fn append_str(h: &mut Sha256, s: &str) {
    h.update(s.as_bytes());
}

/// Compute a ContentHash from a finalized SHA-256 digest.
fn compute_digest(h: Sha256) -> ContentHash {
    ContentHash::compute(&h.finalize())
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Accumulates governance evidence and evaluates it against a config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    /// Configuration.
    pub config: GovernanceConfig,
    /// Accumulated conformance results.
    pub conformance_results: Vec<ConformanceResult>,
    /// Accumulated replay-drop entries.
    pub replay_drops: Vec<ReplayDropEntry>,
    /// Degraded-mode episodes with observed durations.
    pub degraded_episodes: Vec<(DegradedModePolicy, u64, bool)>,
    /// Observability claim deltas.
    pub claim_deltas: Vec<ObservabilityClaimDelta>,
}

impl GovernanceEvaluator {
    /// Create a new evaluator with default config.
    pub fn with_defaults() -> Self {
        Self {
            config: GovernanceConfig::default(),
            conformance_results: Vec::new(),
            replay_drops: Vec::new(),
            degraded_episodes: Vec::new(),
            claim_deltas: Vec::new(),
        }
    }

    /// Create a new evaluator with the given config.
    pub fn with_config(config: GovernanceConfig) -> Self {
        Self {
            config,
            conformance_results: Vec::new(),
            replay_drops: Vec::new(),
            degraded_episodes: Vec::new(),
            claim_deltas: Vec::new(),
        }
    }

    /// Add a per-axis conformance result.
    pub fn add_conformance(&mut self, axis: ConformanceAxis, pass_count: u64, fail_count: u64) {
        let result =
            ConformanceResult::new(axis, pass_count, fail_count, self.config.min_conformance);
        self.conformance_results.push(result);
    }

    /// Add a replay-drop entry.
    pub fn add_replay_drop(
        &mut self,
        category: ReplayDropCategory,
        drop_count: u64,
        total_replays: u64,
    ) {
        let entry = ReplayDropEntry::new(
            category,
            drop_count,
            total_replays,
            self.config.max_drop_rate,
        );
        self.replay_drops.push(entry);
    }

    /// Add a degraded-mode episode.
    ///
    /// `observed_duration_ns` is how long the degraded state lasted.
    /// `operator_acked` indicates whether the operator acknowledged.
    pub fn add_degraded_mode(
        &mut self,
        kind: DegradedModeKind,
        observed_duration_ns: u64,
        operator_acked: bool,
    ) {
        let policy = DegradedModePolicy::for_kind(kind);
        self.degraded_episodes
            .push((policy, observed_duration_ns, operator_acked));
    }

    /// Add a degraded-mode episode with a custom policy.
    pub fn add_degraded_mode_with_policy(
        &mut self,
        policy: DegradedModePolicy,
        observed_duration_ns: u64,
        operator_acked: bool,
    ) {
        self.degraded_episodes
            .push((policy, observed_duration_ns, operator_acked));
    }

    /// Add an observability claim delta.
    pub fn add_claim_delta(
        &mut self,
        claim_id: impl Into<String>,
        baseline_millionths: u64,
        observed_millionths: u64,
    ) {
        let delta = ObservabilityClaimDelta::new(
            claim_id,
            baseline_millionths,
            observed_millionths,
            self.config.min_observability_tolerance,
        );
        self.claim_deltas.push(delta);
    }

    /// Evaluate all accumulated evidence and produce a receipt.
    pub fn evaluate(&self, epoch: SecurityEpoch) -> GovernanceReceipt {
        let mut violations = Vec::new();
        let mut violation_categories: BTreeSet<GovernanceVerdict> = BTreeSet::new();

        // 1. Check conformance axis coverage.
        let covered_axes: BTreeSet<ConformanceAxis> =
            self.conformance_results.iter().map(|r| r.axis).collect();
        if covered_axes.len() < self.config.required_axes {
            violation_categories.insert(GovernanceVerdict::InsufficientCoverage);
            violations.push(ViolationEntry {
                category: GovernanceVerdict::InsufficientCoverage,
                description: format!(
                    "only {} axes covered, {} required",
                    covered_axes.len(),
                    self.config.required_axes,
                ),
            });
        }

        // 2. Check per-axis conformance.
        for result in &self.conformance_results {
            if !result.passes {
                violation_categories.insert(GovernanceVerdict::ConformanceViolation);
                violations.push(ViolationEntry {
                    category: GovernanceVerdict::ConformanceViolation,
                    description: format!(
                        "axis {} conformance {}ppm below threshold {}ppm",
                        result.axis,
                        result.conformance_ratio_millionths,
                        self.config.min_conformance,
                    ),
                });
            }
        }

        // 3. Check replay-drop rates.
        for entry in &self.replay_drops {
            if !entry.within_budget {
                violation_categories.insert(GovernanceVerdict::DropRateExceeded);
                violations.push(ViolationEntry {
                    category: GovernanceVerdict::DropRateExceeded,
                    description: format!(
                        "category {} drop rate {}ppm exceeds max {}ppm",
                        entry.category, entry.drop_rate_millionths, self.config.max_drop_rate,
                    ),
                });
            }
        }

        // 4. Check degraded-mode policies.
        for (policy, observed_ns, operator_acked) in &self.degraded_episodes {
            let mut violated = false;
            let mut missing_ack = false;

            if policy.exceeds_duration(*observed_ns) {
                violated = true;
            }
            if policy.requires_operator_ack && !operator_acked {
                violated = true;
                missing_ack = true;
            }

            if violated {
                violation_categories.insert(GovernanceVerdict::DegradedModePolicyViolation);
                let violation = DegradedModeViolation {
                    kind: policy.kind,
                    observed_duration_ns: *observed_ns,
                    max_duration_ns: policy.max_duration_ns,
                    missing_operator_ack: missing_ack,
                };
                violations.push(ViolationEntry {
                    category: GovernanceVerdict::DegradedModePolicyViolation,
                    description: violation.to_string(),
                });
            }
        }

        // 5. Check observability claim deltas.
        for delta in &self.claim_deltas {
            if !delta.within_tolerance {
                violation_categories.insert(GovernanceVerdict::ObservabilityDrift);
                violations.push(ViolationEntry {
                    category: GovernanceVerdict::ObservabilityDrift,
                    description: format!(
                        "claim {} drifted {}ppm (baseline={}, observed={})",
                        delta.claim_id,
                        delta.delta_millionths,
                        delta.baseline_millionths,
                        delta.observed_millionths,
                    ),
                });
            }
        }

        // 6. Determine verdict.
        let verdict = if violation_categories.is_empty() {
            GovernanceVerdict::Approved
        } else if violation_categories.len() > 1 {
            GovernanceVerdict::MultipleViolations
        } else {
            // Exactly one category.
            violation_categories
                .into_iter()
                .next()
                .unwrap_or(GovernanceVerdict::Approved)
        };

        // 7. Compute content hash.
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_str(&mut h, COMPONENT);
        append_u64(&mut h, epoch.as_u64());
        append_u64(&mut h, self.conformance_results.len() as u64);
        for r in &self.conformance_results {
            append_str(&mut h, r.axis.as_str());
            append_u64(&mut h, r.pass_count);
            append_u64(&mut h, r.fail_count);
        }
        append_u64(&mut h, self.replay_drops.len() as u64);
        for d in &self.replay_drops {
            append_str(&mut h, d.category.as_str());
            append_u64(&mut h, d.drop_count);
            append_u64(&mut h, d.total_replays);
        }
        append_u64(&mut h, self.degraded_episodes.len() as u64);
        for (policy, observed_ns, _) in &self.degraded_episodes {
            append_str(&mut h, policy.kind.as_str());
            append_u64(&mut h, *observed_ns);
        }
        append_u64(&mut h, self.claim_deltas.len() as u64);
        for delta in &self.claim_deltas {
            append_str(&mut h, &delta.claim_id);
            append_u64(&mut h, delta.baseline_millionths);
            append_u64(&mut h, delta.observed_millionths);
        }
        append_str(&mut h, verdict.as_str());
        let content_hash = compute_digest(h);

        GovernanceReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            verdict,
            epoch,
            conformance_count: self.conformance_results.len(),
            drop_entry_count: self.replay_drops.len(),
            degraded_policy_count: self.degraded_episodes.len(),
            claim_delta_count: self.claim_deltas.len(),
            violations,
            content_hash,
        }
    }

    /// Convenience: evaluate and return just the verdict.
    pub fn verdict(&self, epoch: SecurityEpoch) -> GovernanceVerdict {
        self.evaluate(epoch).verdict
    }

    /// Number of evidence entries accumulated so far.
    pub fn evidence_count(&self) -> usize {
        self.conformance_results.len()
            + self.replay_drops.len()
            + self.degraded_episodes.len()
            + self.claim_deltas.len()
    }

    /// Reset all accumulated evidence.
    pub fn reset(&mut self) {
        self.conformance_results.clear();
        self.replay_drops.clear();
        self.degraded_episodes.clear();
        self.claim_deltas.clear();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "hostcall_conformance_governance");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
        assert_eq!(BEAD_ID, "bd-1lsy.6.5.3");
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
        assert_eq!(POLICY_ID, "RGC-505C");
    }

    #[test]
    fn default_thresholds_valid() {
        const {
            assert!(DEFAULT_MIN_CONFORMANCE > 0 && DEFAULT_MIN_CONFORMANCE <= 1_000_000);
            assert!(DEFAULT_MAX_DROP_RATE > 0 && DEFAULT_MAX_DROP_RATE <= 1_000_000);
            assert!(DEFAULT_MAX_DEGRADED_DURATION_NS > 0);
            assert!(
                DEFAULT_OBSERVABILITY_TOLERANCE > 0 && DEFAULT_OBSERVABILITY_TOLERANCE <= 1_000_000
            );
        }
        assert!(
            DEFAULT_MIN_REQUIRED_AXES > 0
                && DEFAULT_MIN_REQUIRED_AXES <= ConformanceAxis::ALL.len()
        );
    }

    // --- ConformanceAxis ---

    #[test]
    fn axis_all_length() {
        assert_eq!(ConformanceAxis::ALL.len(), 6);
    }

    #[test]
    fn axis_names_unique() {
        let names: BTreeSet<&str> = ConformanceAxis::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names.len(), ConformanceAxis::ALL.len());
    }

    #[test]
    fn axis_display_matches_as_str() {
        for a in ConformanceAxis::ALL {
            assert_eq!(a.to_string(), a.as_str());
        }
    }

    #[test]
    fn axis_serde_roundtrip() {
        for a in ConformanceAxis::ALL {
            let json = serde_json::to_string(a).unwrap();
            let back: ConformanceAxis = serde_json::from_str(&json).unwrap();
            assert_eq!(*a, back);
        }
    }

    // --- ConformanceResult ---

    #[test]
    fn result_perfect_conformance() {
        let r = ConformanceResult::new(ConformanceAxis::Protocol, 100, 0, 900_000);
        assert_eq!(r.conformance_ratio_millionths, 1_000_000);
        assert!(r.passes);
        assert_eq!(r.total_count(), 100);
    }

    #[test]
    fn result_zero_total() {
        let r = ConformanceResult::new(ConformanceAxis::Encoding, 0, 0, 900_000);
        assert_eq!(r.conformance_ratio_millionths, 0);
        assert!(!r.passes);
    }

    #[test]
    fn result_partial_conformance() {
        let r = ConformanceResult::new(ConformanceAxis::Timeout, 90, 10, 900_000);
        assert_eq!(r.conformance_ratio_millionths, 900_000);
        assert!(r.passes);
    }

    #[test]
    fn result_below_threshold() {
        let r = ConformanceResult::new(ConformanceAxis::Authentication, 80, 20, 900_000);
        assert_eq!(r.conformance_ratio_millionths, 800_000);
        assert!(!r.passes);
    }

    #[test]
    fn result_display() {
        let r = ConformanceResult::new(ConformanceAxis::Protocol, 95, 5, 900_000);
        let s = r.to_string();
        assert!(s.contains("protocol"));
        assert!(s.contains("PASS"));
    }

    #[test]
    fn result_serde() {
        let r = ConformanceResult::new(ConformanceAxis::Ordering, 50, 50, 500_000);
        let json = serde_json::to_string(&r).unwrap();
        let back: ConformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- ReplayDropCategory ---

    #[test]
    fn drop_category_all_length() {
        assert_eq!(ReplayDropCategory::ALL.len(), 5);
    }

    #[test]
    fn drop_category_names_unique() {
        let names: BTreeSet<&str> = ReplayDropCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ReplayDropCategory::ALL.len());
    }

    #[test]
    fn drop_category_security_sensitive() {
        assert!(ReplayDropCategory::AuthenticationFailure.is_security_sensitive());
        assert!(ReplayDropCategory::PolicyViolation.is_security_sensitive());
        assert!(!ReplayDropCategory::TimeBudgetExceeded.is_security_sensitive());
        assert!(!ReplayDropCategory::ProtocolMismatch.is_security_sensitive());
        assert!(!ReplayDropCategory::EncodingError.is_security_sensitive());
    }

    #[test]
    fn drop_category_serde() {
        for c in ReplayDropCategory::ALL {
            let json = serde_json::to_string(c).unwrap();
            let back: ReplayDropCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- ReplayDropEntry ---

    #[test]
    fn drop_entry_within_budget() {
        let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 2, 1000, 50_000);
        assert_eq!(e.drop_rate_millionths, 2_000);
        assert!(e.within_budget);
    }

    #[test]
    fn drop_entry_over_budget() {
        let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 100, 1000, 50_000);
        assert_eq!(e.drop_rate_millionths, 100_000);
        assert!(!e.within_budget);
    }

    #[test]
    fn drop_entry_zero_total() {
        let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 0, 0, 50_000);
        assert_eq!(e.drop_rate_millionths, 0);
        assert!(e.within_budget);
    }

    #[test]
    fn drop_entry_nonzero_drop_zero_total_fails_closed() {
        let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 1, 0, 50_000);
        assert_eq!(e.drop_rate_millionths, 1_000_000);
        assert!(!e.within_budget);
    }

    #[test]
    fn drop_entry_display() {
        let e = ReplayDropEntry::new(ReplayDropCategory::PolicyViolation, 5, 100, 50_000);
        let s = e.to_string();
        assert!(s.contains("policy_violation"));
    }

    #[test]
    fn drop_entry_serde() {
        let e = ReplayDropEntry::new(ReplayDropCategory::AuthenticationFailure, 3, 200, 50_000);
        let json = serde_json::to_string(&e).unwrap();
        let back: ReplayDropEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- DegradedModeKind ---

    #[test]
    fn degraded_kind_all_length() {
        assert_eq!(DegradedModeKind::ALL.len(), 5);
    }

    #[test]
    fn degraded_kind_names_unique() {
        let names: BTreeSet<&str> = DegradedModeKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), DegradedModeKind::ALL.len());
    }

    #[test]
    fn degraded_kind_severity_ordering() {
        let mut prev = 0;
        for kind in DegradedModeKind::ALL {
            let rank = kind.severity_rank();
            assert!(rank > prev, "severity ranks must be strictly increasing");
            prev = rank;
        }
    }

    #[test]
    fn degraded_kind_terminal() {
        assert!(DegradedModeKind::Disconnected.is_terminal());
        assert!(!DegradedModeKind::ReducedBandwidth.is_terminal());
        assert!(!DegradedModeKind::IncreasedLatency.is_terminal());
        assert!(!DegradedModeKind::PartialFunctionality.is_terminal());
        assert!(!DegradedModeKind::ReadOnly.is_terminal());
    }

    #[test]
    fn degraded_kind_serde() {
        for k in DegradedModeKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: DegradedModeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- DegradedModePolicy ---

    #[test]
    fn policy_for_each_kind() {
        for kind in DegradedModeKind::ALL {
            let policy = DegradedModePolicy::for_kind(*kind);
            assert_eq!(policy.kind, *kind);
        }
    }

    #[test]
    fn policy_disconnected_no_auto_recovery() {
        let p = DegradedModePolicy::for_kind(DegradedModeKind::Disconnected);
        assert!(!p.can_auto_recover());
        assert!(p.requires_operator_ack);
        assert_eq!(p.max_duration_ns, 0);
    }

    #[test]
    fn policy_reduced_bandwidth_auto_recovery() {
        let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
        assert!(p.can_auto_recover());
        assert!(!p.requires_operator_ack);
    }

    #[test]
    fn policy_exceeds_duration() {
        let p = DegradedModePolicy::for_kind(DegradedModeKind::IncreasedLatency);
        assert!(!p.exceeds_duration(p.max_duration_ns));
        assert!(p.exceeds_duration(p.max_duration_ns + 1));
    }

    #[test]
    fn policy_display() {
        let p = DegradedModePolicy::for_kind(DegradedModeKind::ReadOnly);
        let s = p.to_string();
        assert!(s.contains("read_only"));
    }

    #[test]
    fn policy_serde() {
        let p = DegradedModePolicy::for_kind(DegradedModeKind::PartialFunctionality);
        let json = serde_json::to_string(&p).unwrap();
        let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // --- ObservabilityClaimDelta ---

    #[test]
    fn claim_delta_within_tolerance() {
        let d = ObservabilityClaimDelta::new("claim-1", 500_000, 520_000, 50_000);
        assert_eq!(d.delta_millionths, 20_000);
        assert!(d.within_tolerance);
    }

    #[test]
    fn claim_delta_exceeds_tolerance() {
        let d = ObservabilityClaimDelta::new("claim-2", 500_000, 600_000, 50_000);
        assert_eq!(d.delta_millionths, 100_000);
        assert!(!d.within_tolerance);
    }

    #[test]
    fn claim_delta_negative_direction() {
        let d = ObservabilityClaimDelta::new("claim-3", 500_000, 400_000, 50_000);
        assert_eq!(d.delta_millionths, 100_000);
        assert!(!d.within_tolerance);
    }

    #[test]
    fn claim_delta_exact_tolerance() {
        let d = ObservabilityClaimDelta::new("claim-4", 500_000, 550_000, 50_000);
        assert_eq!(d.delta_millionths, 50_000);
        assert!(d.within_tolerance);
    }

    #[test]
    fn claim_delta_relative_drift() {
        let d = ObservabilityClaimDelta::new("claim-5", 1_000_000, 1_100_000, 200_000);
        assert_eq!(d.relative_drift_millionths(), 100_000); // 10%
    }

    #[test]
    fn claim_delta_zero_baseline() {
        let d = ObservabilityClaimDelta::new("claim-6", 0, 100_000, 50_000);
        assert_eq!(d.relative_drift_millionths(), 1_000_000);
    }

    #[test]
    fn claim_delta_zero_baseline_zero_delta() {
        let d = ObservabilityClaimDelta::new("claim-6b", 0, 0, 50_000);
        assert_eq!(d.relative_drift_millionths(), 0);
    }

    #[test]
    fn claim_delta_serde() {
        let d = ObservabilityClaimDelta::new("claim-7", 800_000, 810_000, 50_000);
        let json = serde_json::to_string(&d).unwrap();
        let back: ObservabilityClaimDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn claim_delta_display() {
        let d = ObservabilityClaimDelta::new("claim-8", 500_000, 600_000, 50_000);
        let s = d.to_string();
        assert!(s.contains("DRIFTED"));
        assert!(s.contains("claim-8"));
    }

    // --- GovernanceConfig ---

    #[test]
    fn config_default() {
        let c = GovernanceConfig::default();
        assert_eq!(c.min_conformance, DEFAULT_MIN_CONFORMANCE);
        assert_eq!(c.max_drop_rate, DEFAULT_MAX_DROP_RATE);
        assert_eq!(c.max_degraded_duration, DEFAULT_MAX_DEGRADED_DURATION_NS);
        assert_eq!(
            c.min_observability_tolerance,
            DEFAULT_OBSERVABILITY_TOLERANCE
        );
        assert_eq!(c.required_axes, DEFAULT_MIN_REQUIRED_AXES);
    }

    #[test]
    fn config_strict_stricter_than_default() {
        let d = GovernanceConfig::default();
        let s = GovernanceConfig::strict();
        assert!(s.min_conformance >= d.min_conformance);
        assert!(s.max_drop_rate <= d.max_drop_rate);
        assert!(s.required_axes >= d.required_axes);
    }

    #[test]
    fn config_permissive_more_lenient() {
        let d = GovernanceConfig::default();
        let p = GovernanceConfig::permissive();
        assert!(p.min_conformance <= d.min_conformance);
        assert!(p.max_drop_rate >= d.max_drop_rate);
        assert!(p.required_axes <= d.required_axes);
    }

    #[test]
    fn config_serde() {
        let c = GovernanceConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- GovernanceVerdict ---

    #[test]
    fn verdict_all_length() {
        assert_eq!(GovernanceVerdict::ALL.len(), 7);
    }

    #[test]
    fn verdict_names_unique() {
        let names: BTreeSet<&str> = GovernanceVerdict::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(names.len(), GovernanceVerdict::ALL.len());
    }

    #[test]
    fn verdict_approved_is_approved() {
        assert!(GovernanceVerdict::Approved.is_approved());
        assert!(!GovernanceVerdict::Approved.is_failure());
    }

    #[test]
    fn verdict_failures_are_failures() {
        for v in GovernanceVerdict::ALL {
            if *v != GovernanceVerdict::Approved {
                assert!(v.is_failure());
                assert!(!v.is_approved());
            }
        }
    }

    #[test]
    fn verdict_display() {
        assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
        assert_eq!(
            GovernanceVerdict::MultipleViolations.to_string(),
            "multiple_violations",
        );
    }

    #[test]
    fn verdict_serde() {
        for v in GovernanceVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- GovernanceEvaluator ---

    fn all_axes_passing(eval: &mut GovernanceEvaluator) {
        for axis in ConformanceAxis::ALL {
            eval.add_conformance(*axis, 100, 0);
        }
    }

    #[test]
    fn evaluator_empty_insufficient_coverage() {
        let eval = GovernanceEvaluator::with_defaults();
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
        assert!(receipt.has_violations());
    }

    #[test]
    fn evaluator_all_axes_passing_approved() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
        assert!(!receipt.has_violations());
    }

    #[test]
    fn evaluator_one_axis_failing() {
        let mut eval = GovernanceEvaluator::with_defaults();
        // Add 5 passing axes (still enough coverage with required_axes=4).
        for axis in &ConformanceAxis::ALL[..5] {
            eval.add_conformance(*axis, 100, 0);
        }
        // Add 1 failing axis.
        eval.add_conformance(ConformanceAxis::Authorization, 50, 50);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::ConformanceViolation);
        assert_eq!(receipt.violation_count(), 1);
    }

    #[test]
    fn evaluator_drop_rate_exceeded() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 100, 1000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::DropRateExceeded);
    }

    #[test]
    fn evaluator_drop_rate_within_budget() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_replay_drop(ReplayDropCategory::EncodingError, 1, 1000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_degraded_mode_violation() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        // Exceed the duration for ReducedBandwidth.
        eval.add_degraded_mode(
            DegradedModeKind::ReducedBandwidth,
            DEFAULT_MAX_DEGRADED_DURATION_NS + 1,
            false,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(
            receipt.verdict,
            GovernanceVerdict::DegradedModePolicyViolation
        );
    }

    #[test]
    fn evaluator_degraded_mode_within_limits() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 1_000, false);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_degraded_missing_ack() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        // PartialFunctionality requires ack; provide operator_acked=false.
        eval.add_degraded_mode(DegradedModeKind::PartialFunctionality, 1_000, false);
        let receipt = eval.evaluate(epoch());
        assert_eq!(
            receipt.verdict,
            GovernanceVerdict::DegradedModePolicyViolation
        );
    }

    #[test]
    fn evaluator_degraded_with_ack() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_degraded_mode(DegradedModeKind::PartialFunctionality, 1_000, true);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_observability_drift() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_claim_delta("obs-1", 500_000, 700_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::ObservabilityDrift);
    }

    #[test]
    fn evaluator_observability_within_tolerance() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_claim_delta("obs-2", 500_000, 530_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_multiple_violations() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        // Cause two distinct violation categories.
        eval.add_replay_drop(ReplayDropCategory::EncodingError, 200, 1000);
        eval.add_claim_delta("obs-x", 100_000, 500_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
        assert!(receipt.violation_count() >= 2);
    }

    #[test]
    fn evaluator_receipt_hash_deterministic() {
        let mut eval1 = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval1);
        let r1 = eval1.evaluate(epoch());

        let mut eval2 = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval2);
        let r2 = eval2.evaluate(epoch());

        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn evaluator_receipt_hash_differs_on_change() {
        let mut eval1 = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval1);
        let r1 = eval1.evaluate(epoch());

        let mut eval2 = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval2);
        eval2.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
        let r2 = eval2.evaluate(epoch());

        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn evaluator_evidence_count() {
        let mut eval = GovernanceEvaluator::with_defaults();
        assert_eq!(eval.evidence_count(), 0);
        eval.add_conformance(ConformanceAxis::Protocol, 10, 0);
        assert_eq!(eval.evidence_count(), 1);
        eval.add_replay_drop(ReplayDropCategory::EncodingError, 0, 10);
        assert_eq!(eval.evidence_count(), 2);
        eval.add_degraded_mode(DegradedModeKind::ReadOnly, 100, true);
        assert_eq!(eval.evidence_count(), 3);
        eval.add_claim_delta("x", 100, 200);
        assert_eq!(eval.evidence_count(), 4);
    }

    #[test]
    fn evaluator_reset() {
        let mut eval = GovernanceEvaluator::with_defaults();
        eval.add_conformance(ConformanceAxis::Protocol, 10, 0);
        eval.add_replay_drop(ReplayDropCategory::EncodingError, 0, 10);
        eval.reset();
        assert_eq!(eval.evidence_count(), 0);
    }

    #[test]
    fn evaluator_verdict_convenience() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        assert_eq!(eval.verdict(epoch()), GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_custom_config() {
        let config = GovernanceConfig {
            min_conformance: 500_000,
            max_drop_rate: 100_000,
            max_degraded_duration: 1_000_000_000,
            min_observability_tolerance: 100_000,
            required_axes: 2,
        };
        let mut eval = GovernanceEvaluator::with_config(config);
        eval.add_conformance(ConformanceAxis::Protocol, 60, 40);
        eval.add_conformance(ConformanceAxis::Encoding, 55, 45);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_custom_policy() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        let policy = DegradedModePolicy {
            kind: DegradedModeKind::IncreasedLatency,
            max_duration_ns: 1_000,
            requires_operator_ack: false,
            auto_recovery: true,
        };
        eval.add_degraded_mode_with_policy(policy, 500, true);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn receipt_total_entries() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        eval.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 0, 100);
        eval.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 100, false);
        eval.add_claim_delta("obs", 100_000, 110_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.total_entries(), 9); // 6 + 1 + 1 + 1
    }

    #[test]
    fn receipt_serde() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        let receipt = eval.evaluate(epoch());
        let json = serde_json::to_string(&receipt).unwrap();
        let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn receipt_display() {
        let mut eval = GovernanceEvaluator::with_defaults();
        all_axes_passing(&mut eval);
        let receipt = eval.evaluate(epoch());
        let s = receipt.to_string();
        assert!(s.contains("hostcall_conformance_governance"));
        assert!(s.contains("approved"));
    }

    #[test]
    fn violation_entry_display() {
        let v = ViolationEntry {
            category: GovernanceVerdict::ConformanceViolation,
            description: "axis protocol failed".into(),
        };
        let s = v.to_string();
        assert!(s.contains("conformance_violation"));
        assert!(s.contains("axis protocol failed"));
    }

    #[test]
    fn degraded_mode_violation_display() {
        let v = DegradedModeViolation {
            kind: DegradedModeKind::ReadOnly,
            observed_duration_ns: 100_000,
            max_duration_ns: 50_000,
            missing_operator_ack: true,
        };
        let s = v.to_string();
        assert!(s.contains("read_only"));
        assert!(s.contains("ack_missing=true"));
    }

    #[test]
    fn evaluator_permissive_config_allows_more() {
        let mut eval = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
        eval.add_conformance(ConformanceAxis::Protocol, 60, 40);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn evaluator_strict_config_rejects_more() {
        let mut eval = GovernanceEvaluator::with_config(GovernanceConfig::strict());
        // Only 4 axes but strict requires 6.
        for axis in &ConformanceAxis::ALL[..4] {
            eval.add_conformance(*axis, 100, 0);
        }
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    }
}
