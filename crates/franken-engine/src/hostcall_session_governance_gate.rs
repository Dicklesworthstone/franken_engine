#![forbid(unsafe_code)]
//! Hostcall session governance gate for conformance, replay-drop, and
//! degraded-mode enforcement.
//!
//! Implements [RGC-505C] (bead bd-1lsy.6.5.3): gates the hostcall channel
//! with conformance vectors, replay-drop telemetry, policy-visible
//! degraded-mode rules, and observability-mode claim deltas so boundary
//! wins survive the telemetry needed to operate them.
//!
//! # Design
//!
//! - `ConformanceVector` captures protocol conformance per session.
//! - `ReplayDropRecord` tracks replay-dropped messages and their causes.
//! - `DegradedModeRecord` records episodes of degraded operation.
//! - `ObservabilityDelta` measures instrumentation overhead.
//! - `evaluate` combines all evidence into a `GateResult` with a receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-505C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.hostcall-session-governance-gate.v1";

/// Component name.
pub const COMPONENT: &str = "hostcall_session_governance_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.6.5.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-505C";

/// Default minimum conformance fraction (millionths). 90% = 900_000.
pub const DEFAULT_MIN_CONFORMANCE: u64 = 900_000;

/// Default maximum replay-drop rate (millionths). 5% = 50_000.
pub const DEFAULT_MAX_REPLAY_DROP_RATE: u64 = 50_000;

/// Default maximum degraded severity (millionths). 70% = 700_000.
pub const DEFAULT_MAX_DEGRADED_SEVERITY: u64 = 700_000;

/// Default maximum observability overhead (millionths). 10% = 100_000.
pub const DEFAULT_MAX_OBSERVABILITY_OVERHEAD: u64 = 100_000;

/// Default minimum operations tested.
pub const DEFAULT_MIN_OPERATIONS_TESTED: u64 = 10;

// ---------------------------------------------------------------------------
// ConformanceLevel
// ---------------------------------------------------------------------------

/// Level of protocol conformance for a hostcall session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceLevel {
    /// Fully conformant — all operations pass.
    Full,
    /// Partially conformant — most operations pass but some fail.
    Partial,
    /// Degraded — conformance below acceptable threshold.
    Degraded,
    /// Non-conformant — critical failures detected.
    NonConformant,
}

impl ConformanceLevel {
    pub const ALL: &[Self] = &[
        Self::Full,
        Self::Partial,
        Self::Degraded,
        Self::NonConformant,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Degraded => "degraded",
            Self::NonConformant => "non_conformant",
        }
    }

    /// Whether this level is acceptable for gate passage.
    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::Full | Self::Partial)
    }
}

impl fmt::Display for ConformanceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DegradedModeReason
// ---------------------------------------------------------------------------

/// Reason a hostcall session entered degraded mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedModeReason {
    /// Latency exceeded acceptable bounds.
    HighLatency,
    /// Host resource pool exhausted.
    ResourceExhaustion,
    /// Security policy violation detected.
    SecurityViolation,
    /// Messages were dropped due to replay issues.
    ReplayDrop,
    /// Protocol version mismatch between host and guest.
    ProtocolMismatch,
}

impl DegradedModeReason {
    pub const ALL: &[Self] = &[
        Self::HighLatency,
        Self::ResourceExhaustion,
        Self::SecurityViolation,
        Self::ReplayDrop,
        Self::ProtocolMismatch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HighLatency => "high_latency",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::SecurityViolation => "security_violation",
            Self::ReplayDrop => "replay_drop",
            Self::ProtocolMismatch => "protocol_mismatch",
        }
    }

    /// Whether this reason is security-critical (blocks passage).
    pub fn is_security_critical(self) -> bool {
        matches!(self, Self::SecurityViolation)
    }
}

impl fmt::Display for DegradedModeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict from the governance gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// All checks pass — session is fully conformant.
    Pass,
    /// Passes with conditions — minor issues detected.
    ConditionalPass,
    /// Fails — session does not meet governance requirements.
    Fail,
    /// Degraded mode — session is operating but with restrictions.
    DegradedMode,
}

impl GateVerdict {
    pub const ALL: &[Self] = &[
        Self::Pass,
        Self::ConditionalPass,
        Self::Fail,
        Self::DegradedMode,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ConditionalPass => "conditional_pass",
            Self::Fail => "fail",
            Self::DegradedMode => "degraded_mode",
        }
    }

    /// Whether this verdict allows the session to proceed.
    pub fn allows_session(self) -> bool {
        matches!(
            self,
            Self::Pass | Self::ConditionalPass | Self::DegradedMode
        )
    }

    /// Whether this verdict represents a clean pass.
    pub fn is_clean(self) -> bool {
        self == Self::Pass
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ReplayDropKind
// ---------------------------------------------------------------------------

/// Kind of replay drop in a hostcall session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDropKind {
    /// Message timed out before delivery.
    Timeout,
    /// Replay buffer overflowed.
    BufferOverflow,
    /// Message ordering violated protocol invariants.
    OrderingViolation,
    /// Schema changed mid-session, invalidating buffered messages.
    SchemaChange,
    /// Session expired before replay could complete.
    SessionExpiry,
}

impl ReplayDropKind {
    pub const ALL: &[Self] = &[
        Self::Timeout,
        Self::BufferOverflow,
        Self::OrderingViolation,
        Self::SchemaChange,
        Self::SessionExpiry,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::BufferOverflow => "buffer_overflow",
            Self::OrderingViolation => "ordering_violation",
            Self::SchemaChange => "schema_change",
            Self::SessionExpiry => "session_expiry",
        }
    }
}

impl fmt::Display for ReplayDropKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ConformanceVector
// ---------------------------------------------------------------------------

/// Protocol conformance measurement for a hostcall session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    /// Session identifier.
    pub session_id: String,
    /// Protocol version string.
    pub protocol_version: String,
    /// Total operations tested.
    pub operations_tested: u64,
    /// Operations that passed conformance checks.
    pub operations_passed: u64,
    /// Conformance fraction (millionths, 0–1_000_000).
    pub conformance_fraction: u64,
    /// Specific failure descriptions.
    pub failures: Vec<String>,
    /// Security epoch when this vector was computed.
    pub epoch: SecurityEpoch,
}

impl ConformanceVector {
    /// Create a new conformance vector with computed fraction.
    pub fn new(
        session_id: impl Into<String>,
        protocol_version: impl Into<String>,
        operations_tested: u64,
        operations_passed: u64,
        failures: Vec<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        let conformance_fraction = operations_passed
            .saturating_mul(1_000_000)
            .checked_div(operations_tested)
            .unwrap_or(0);
        Self {
            session_id: session_id.into(),
            protocol_version: protocol_version.into(),
            operations_tested,
            operations_passed,
            conformance_fraction,
            failures,
            epoch,
        }
    }

    /// Whether all tested operations passed.
    pub fn is_fully_conformant(&self) -> bool {
        self.operations_passed == self.operations_tested && self.operations_tested > 0
    }
}

impl fmt::Display for ConformanceVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance[{}]: {}/{} ({}‰)",
            self.session_id,
            self.operations_passed,
            self.operations_tested,
            self.conformance_fraction / 1_000,
        )
    }
}

// ---------------------------------------------------------------------------
// ReplayDropRecord
// ---------------------------------------------------------------------------

/// Record of replay-dropped messages in a hostcall session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDropRecord {
    /// Session identifier.
    pub session_id: String,
    /// Kind of replay drop.
    pub drop_kind: ReplayDropKind,
    /// Number of messages dropped.
    pub dropped_count: u64,
    /// Total messages in the window.
    pub total_count: u64,
    /// Drop rate (millionths, 0–1_000_000).
    pub drop_rate: u64,
    /// Security epoch when this record was generated.
    pub epoch: SecurityEpoch,
}

impl ReplayDropRecord {
    /// Create a new record with computed drop rate.
    pub fn new(
        session_id: impl Into<String>,
        drop_kind: ReplayDropKind,
        dropped_count: u64,
        total_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let drop_rate = dropped_count
            .saturating_mul(1_000_000)
            .checked_div(total_count)
            .unwrap_or(0);
        Self {
            session_id: session_id.into(),
            drop_kind,
            dropped_count,
            total_count,
            drop_rate,
            epoch,
        }
    }
}

impl fmt::Display for ReplayDropRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "replay-drop[{}]: {} {}/{} ({}‰)",
            self.session_id,
            self.drop_kind,
            self.dropped_count,
            self.total_count,
            self.drop_rate / 1_000,
        )
    }
}

// ---------------------------------------------------------------------------
// DegradedModeRecord
// ---------------------------------------------------------------------------

/// Record of a degraded-mode episode in a hostcall session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeRecord {
    /// Session identifier.
    pub session_id: String,
    /// Why the session entered degraded mode.
    pub reason: DegradedModeReason,
    /// Severity of the degradation (millionths, 0–1_000_000; higher = worse).
    pub severity: u64,
    /// How many epochs the degradation lasted.
    pub duration_epochs: u64,
    /// Mitigations applied.
    pub mitigations: Vec<String>,
    /// Security epoch when this record was generated.
    pub epoch: SecurityEpoch,
}

impl DegradedModeRecord {
    /// Create a new degraded-mode record.
    pub fn new(
        session_id: impl Into<String>,
        reason: DegradedModeReason,
        severity: u64,
        duration_epochs: u64,
        mitigations: Vec<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            reason,
            severity,
            duration_epochs,
            mitigations,
            epoch,
        }
    }

    /// Whether the degradation is security-critical.
    pub fn is_security_critical(&self) -> bool {
        self.reason.is_security_critical()
    }
}

impl fmt::Display for DegradedModeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "degraded[{}]: {} severity={} epochs={}",
            self.session_id, self.reason, self.severity, self.duration_epochs,
        )
    }
}

// ---------------------------------------------------------------------------
// ObservabilityDelta
// ---------------------------------------------------------------------------

/// Measures instrumentation overhead on hostcall throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityDelta {
    /// Throughput with instrumentation enabled (millionths of ops/sec).
    pub instrumented_throughput: u64,
    /// Throughput without instrumentation (millionths of ops/sec).
    pub uninstrumented_throughput: u64,
    /// Overhead fraction (millionths, 0–1_000_000).
    pub overhead_fraction: u64,
    /// Whether the overhead is acceptable per policy.
    pub acceptable: bool,
}

impl ObservabilityDelta {
    /// Create a new delta with computed overhead fraction.
    pub fn new(instrumented_throughput: u64, uninstrumented_throughput: u64) -> Self {
        // overhead = (uninstrumented - instrumented) / uninstrumented
        let diff = uninstrumented_throughput.saturating_sub(instrumented_throughput);
        let overhead_fraction = diff
            .saturating_mul(1_000_000)
            .checked_div(uninstrumented_throughput)
            .unwrap_or(0);
        Self {
            instrumented_throughput,
            uninstrumented_throughput,
            overhead_fraction,
            acceptable: overhead_fraction <= DEFAULT_MAX_OBSERVABILITY_OVERHEAD,
        }
    }

    /// Create with explicit acceptable flag.
    pub fn with_acceptable(
        instrumented_throughput: u64,
        uninstrumented_throughput: u64,
        max_overhead: u64,
    ) -> Self {
        let diff = uninstrumented_throughput.saturating_sub(instrumented_throughput);
        let overhead_fraction = diff
            .saturating_mul(1_000_000)
            .checked_div(uninstrumented_throughput)
            .unwrap_or(0);
        Self {
            instrumented_throughput,
            uninstrumented_throughput,
            overhead_fraction,
            acceptable: overhead_fraction <= max_overhead,
        }
    }
}

impl fmt::Display for ObservabilityDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "observability: overhead={}‰ acceptable={}",
            self.overhead_fraction / 1_000,
            self.acceptable,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the hostcall session governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum conformance fraction to pass (millionths).
    pub min_conformance_fraction: u64,
    /// Maximum acceptable replay-drop rate (millionths).
    pub max_replay_drop_rate: u64,
    /// Maximum degraded severity before failing (millionths).
    pub max_degraded_severity: u64,
    /// Maximum observability overhead fraction (millionths).
    pub max_observability_overhead: u64,
    /// Minimum number of operations that must be tested.
    pub min_operations_tested: u64,
}

impl GateConfig {
    /// Create a strict configuration.
    pub fn strict() -> Self {
        Self {
            min_conformance_fraction: 950_000,
            max_replay_drop_rate: 10_000,
            max_degraded_severity: 300_000,
            max_observability_overhead: 50_000,
            min_operations_tested: 50,
        }
    }

    /// Create a permissive configuration.
    pub fn permissive() -> Self {
        Self {
            min_conformance_fraction: 500_000,
            max_replay_drop_rate: 200_000,
            max_degraded_severity: 900_000,
            max_observability_overhead: 500_000,
            min_operations_tested: 1,
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_conformance_fraction: DEFAULT_MIN_CONFORMANCE,
            max_replay_drop_rate: DEFAULT_MAX_REPLAY_DROP_RATE,
            max_degraded_severity: DEFAULT_MAX_DEGRADED_SEVERITY,
            max_observability_overhead: DEFAULT_MAX_OBSERVABILITY_OVERHEAD,
            min_operations_tested: DEFAULT_MIN_OPERATIONS_TESTED,
        }
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Result of the governance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Conformance level determined.
    pub conformance_level: ConformanceLevel,
    /// Active degraded-mode reasons (may be empty).
    pub degraded_reasons: Vec<DegradedModeReason>,
    /// Reasons that block passage (empty if passing).
    pub blocking_reasons: Vec<String>,
    /// Advisory recommendations.
    pub recommendations: Vec<String>,
    /// Content hash of the decision receipt.
    pub receipt_hash: ContentHash,
}

impl GateResult {
    /// Whether the gate allows the session to proceed.
    pub fn is_passing(&self) -> bool {
        self.verdict.allows_session()
    }

    /// Whether there are any recommendations.
    pub fn has_recommendations(&self) -> bool {
        !self.recommendations.is_empty()
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gate[{}]: conformance={} blocking={} recommendations={}",
            self.verdict,
            self.conformance_level,
            self.blocking_reasons.len(),
            self.recommendations.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Receipt capturing the gate decision for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
    /// Component that issued the receipt.
    pub component: String,
    /// Security epoch of the decision.
    pub epoch: SecurityEpoch,
    /// Verdict rendered.
    pub verdict: GateVerdict,
    /// Hash of the input evidence.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new receipt with computed hash.
    pub fn new(epoch: SecurityEpoch, verdict: GateVerdict, evidence_hash: ContentHash) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(verdict.as_str().as_bytes());
        h.update(evidence_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());

        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch,
            verdict,
            evidence_hash,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}]: {} at epoch {}",
            self.component,
            self.verdict,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics from multiple gate evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evaluations.
    pub total: u64,
    /// Number that passed.
    pub passed: u64,
    /// Number that conditionally passed.
    pub conditional: u64,
    /// Number that failed.
    pub failed: u64,
    /// Number in degraded mode.
    pub degraded: u64,
    /// Pass rate (millionths, 0–1_000_000). Includes conditional passes.
    pub pass_rate: u64,
}

impl GateSummary {
    /// Build a summary from a slice of gate results.
    pub fn from_results(results: &[GateResult]) -> Self {
        let total = results.len() as u64;
        let mut passed = 0u64;
        let mut conditional = 0u64;
        let mut failed = 0u64;
        let mut degraded = 0u64;

        for r in results {
            match r.verdict {
                GateVerdict::Pass => passed += 1,
                GateVerdict::ConditionalPass => conditional += 1,
                GateVerdict::Fail => failed += 1,
                GateVerdict::DegradedMode => degraded += 1,
            }
        }

        let passing = passed.saturating_add(conditional);
        let pass_rate = passing
            .saturating_mul(1_000_000)
            .checked_div(total)
            .unwrap_or(0);

        Self {
            total,
            passed,
            conditional,
            failed,
            degraded,
            pass_rate,
        }
    }

    /// Whether all evaluations passed or conditionally passed.
    pub fn all_passing(&self) -> bool {
        self.total > 0 && self.failed == 0 && self.degraded == 0
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "summary: {}/{} passed, {} conditional, {} failed, {} degraded ({}‰)",
            self.passed,
            self.total,
            self.conditional,
            self.failed,
            self.degraded,
            self.pass_rate / 1_000,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate a conformance vector against configuration thresholds.
///
/// Returns the conformance level based on the fraction of operations that
/// passed and whether the minimum operations threshold is met.
pub fn evaluate_conformance(vector: &ConformanceVector, config: &GateConfig) -> ConformanceLevel {
    // Not enough data — cannot claim conformance.
    if vector.operations_tested < config.min_operations_tested {
        return ConformanceLevel::NonConformant;
    }

    if vector.conformance_fraction >= config.min_conformance_fraction {
        if vector.is_fully_conformant() {
            ConformanceLevel::Full
        } else {
            ConformanceLevel::Partial
        }
    } else if vector.conformance_fraction >= config.min_conformance_fraction / 2 {
        ConformanceLevel::Degraded
    } else {
        ConformanceLevel::NonConformant
    }
}

/// Evaluate replay-drop records against configuration thresholds.
///
/// Returns `true` if the replay-drop rates are acceptable.
pub fn evaluate_replay_drops(records: &[ReplayDropRecord], config: &GateConfig) -> bool {
    if records.is_empty() {
        return true;
    }
    for record in records {
        if record.drop_rate > config.max_replay_drop_rate {
            return false;
        }
    }
    true
}

/// Evaluate degraded-mode records and return the active degraded reasons
/// whose severity exceeds the configured threshold.
pub fn evaluate_degraded_mode(
    records: &[DegradedModeRecord],
    config: &GateConfig,
) -> Vec<DegradedModeReason> {
    let mut reasons = Vec::new();
    for record in records {
        if (record.severity > config.max_degraded_severity || record.is_security_critical())
            && !reasons.contains(&record.reason)
        {
            reasons.push(record.reason);
        }
    }
    reasons
}

/// Perform the full governance gate evaluation.
///
/// Combines conformance, replay-drop, degraded-mode, and observability
/// evidence into a single `GateResult` with an auditable receipt hash.
pub fn evaluate(
    conformance: &ConformanceVector,
    drops: &[ReplayDropRecord],
    degraded: &[DegradedModeRecord],
    observability: Option<&ObservabilityDelta>,
    config: &GateConfig,
) -> GateResult {
    let mut blocking_reasons: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    // 1. Conformance evaluation.
    let conformance_level = evaluate_conformance(conformance, config);
    match conformance_level {
        ConformanceLevel::Full => {}
        ConformanceLevel::Partial => {
            recommendations.push(format!(
                "conformance partial: {}/{} operations passed",
                conformance.operations_passed, conformance.operations_tested,
            ));
        }
        ConformanceLevel::Degraded => {
            recommendations.push(format!(
                "conformance degraded: fraction {} below threshold {}",
                conformance.conformance_fraction, config.min_conformance_fraction,
            ));
        }
        ConformanceLevel::NonConformant => {
            blocking_reasons.push(format!(
                "non-conformant: fraction {} below threshold {} (tested {})",
                conformance.conformance_fraction,
                config.min_conformance_fraction,
                conformance.operations_tested,
            ));
        }
    }

    // 2. Replay-drop evaluation.
    let drops_acceptable = evaluate_replay_drops(drops, config);
    if !drops_acceptable {
        for record in drops {
            if record.drop_rate > config.max_replay_drop_rate {
                blocking_reasons.push(format!(
                    "replay-drop rate {} exceeds max {} for {} ({})",
                    record.drop_rate,
                    config.max_replay_drop_rate,
                    record.drop_kind,
                    record.session_id,
                ));
            }
        }
    }

    // 3. Degraded-mode evaluation.
    let degraded_reasons = evaluate_degraded_mode(degraded, config);
    for reason in &degraded_reasons {
        if reason.is_security_critical() {
            blocking_reasons.push(format!("security-critical degradation: {}", reason,));
        } else {
            recommendations.push(format!("degraded-mode active: {}", reason,));
        }
    }

    // 4. Observability overhead evaluation.
    if let Some(delta) = observability
        && delta.overhead_fraction > config.max_observability_overhead
    {
        recommendations.push(format!(
            "observability overhead {} exceeds max {}",
            delta.overhead_fraction, config.max_observability_overhead,
        ));
    }

    // Determine overall verdict.
    let verdict = if !blocking_reasons.is_empty() {
        GateVerdict::Fail
    } else if !degraded_reasons.is_empty() {
        GateVerdict::DegradedMode
    } else if !recommendations.is_empty() {
        GateVerdict::ConditionalPass
    } else {
        GateVerdict::Pass
    };

    // Compute receipt hash over all inputs.
    let mut h = Sha256::new();
    h.update(COMPONENT.as_bytes());
    h.update(conformance.session_id.as_bytes());
    h.update(conformance.conformance_fraction.to_le_bytes());
    h.update((drops.len() as u64).to_le_bytes());
    for d in drops {
        h.update(d.drop_rate.to_le_bytes());
    }
    h.update((degraded.len() as u64).to_le_bytes());
    for d in degraded {
        h.update(d.severity.to_le_bytes());
    }
    if let Some(delta) = observability {
        h.update(delta.overhead_fraction.to_le_bytes());
    }
    h.update(verdict.as_str().as_bytes());
    let receipt_hash = ContentHash::compute(&h.finalize());

    GateResult {
        verdict,
        conformance_level,
        degraded_reasons,
        blocking_reasons,
        recommendations,
        receipt_hash,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn good_conformance() -> ConformanceVector {
        ConformanceVector::new("sess-1", "v1.0", 100, 100, Vec::new(), epoch())
    }

    fn partial_conformance() -> ConformanceVector {
        ConformanceVector::new(
            "sess-2",
            "v1.0",
            100,
            95,
            vec!["minor failure".into()],
            epoch(),
        )
    }

    fn bad_conformance() -> ConformanceVector {
        ConformanceVector::new(
            "sess-3",
            "v1.0",
            100,
            30,
            vec!["critical failure".into()],
            epoch(),
        )
    }

    fn low_test_conformance() -> ConformanceVector {
        ConformanceVector::new("sess-4", "v1.0", 3, 3, Vec::new(), epoch())
    }

    fn good_drop_record() -> ReplayDropRecord {
        ReplayDropRecord::new("sess-1", ReplayDropKind::Timeout, 1, 1000, epoch())
    }

    fn bad_drop_record() -> ReplayDropRecord {
        ReplayDropRecord::new("sess-1", ReplayDropKind::BufferOverflow, 200, 1000, epoch())
    }

    fn mild_degraded_record() -> DegradedModeRecord {
        DegradedModeRecord::new(
            "sess-1",
            DegradedModeReason::HighLatency,
            300_000,
            2,
            vec!["throttle applied".into()],
            epoch(),
        )
    }

    fn severe_degraded_record() -> DegradedModeRecord {
        DegradedModeRecord::new(
            "sess-1",
            DegradedModeReason::ResourceExhaustion,
            900_000,
            5,
            Vec::new(),
            epoch(),
        )
    }

    fn security_degraded_record() -> DegradedModeRecord {
        DegradedModeRecord::new(
            "sess-1",
            DegradedModeReason::SecurityViolation,
            500_000,
            1,
            vec!["session quarantined".into()],
            epoch(),
        )
    }

    fn default_config() -> GateConfig {
        GateConfig::default()
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "hostcall_session_governance_gate");
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
        const { assert!(DEFAULT_MIN_CONFORMANCE > 0 && DEFAULT_MIN_CONFORMANCE <= 1_000_000) };
        const { assert!(DEFAULT_MAX_REPLAY_DROP_RATE > 0 && DEFAULT_MAX_REPLAY_DROP_RATE <= 1_000_000) };
        const {
            assert!(DEFAULT_MAX_DEGRADED_SEVERITY > 0 && DEFAULT_MAX_DEGRADED_SEVERITY <= 1_000_000)
        };
        const {
            assert!(
                DEFAULT_MAX_OBSERVABILITY_OVERHEAD > 0
                    && DEFAULT_MAX_OBSERVABILITY_OVERHEAD <= 1_000_000
            )
        };
        const { assert!(DEFAULT_MIN_OPERATIONS_TESTED > 0) };
    }

    // --- ConformanceLevel ---

    #[test]
    fn conformance_level_all_length() {
        assert_eq!(ConformanceLevel::ALL.len(), 4);
    }

    #[test]
    fn conformance_level_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            ConformanceLevel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ConformanceLevel::ALL.len());
    }

    #[test]
    fn conformance_level_display() {
        for c in ConformanceLevel::ALL {
            assert_eq!(c.to_string(), c.as_str());
        }
    }

    #[test]
    fn conformance_level_acceptable() {
        assert!(ConformanceLevel::Full.is_acceptable());
        assert!(ConformanceLevel::Partial.is_acceptable());
        assert!(!ConformanceLevel::Degraded.is_acceptable());
        assert!(!ConformanceLevel::NonConformant.is_acceptable());
    }

    #[test]
    fn conformance_level_serde() {
        for c in ConformanceLevel::ALL {
            let json = serde_json::to_string(c).unwrap();
            let back: ConformanceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- DegradedModeReason ---

    #[test]
    fn degraded_reason_all_length() {
        assert_eq!(DegradedModeReason::ALL.len(), 5);
    }

    #[test]
    fn degraded_reason_security_critical() {
        assert!(DegradedModeReason::SecurityViolation.is_security_critical());
        assert!(!DegradedModeReason::HighLatency.is_security_critical());
        assert!(!DegradedModeReason::ResourceExhaustion.is_security_critical());
    }

    #[test]
    fn degraded_reason_serde() {
        for r in DegradedModeReason::ALL {
            let json = serde_json::to_string(r).unwrap();
            let back: DegradedModeReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // --- GateVerdict ---

    #[test]
    fn gate_verdict_all_length() {
        assert_eq!(GateVerdict::ALL.len(), 4);
    }

    #[test]
    fn gate_verdict_allows_session() {
        assert!(GateVerdict::Pass.allows_session());
        assert!(GateVerdict::ConditionalPass.allows_session());
        assert!(!GateVerdict::Fail.allows_session());
        assert!(GateVerdict::DegradedMode.allows_session());
    }

    #[test]
    fn gate_verdict_is_clean() {
        assert!(GateVerdict::Pass.is_clean());
        assert!(!GateVerdict::ConditionalPass.is_clean());
        assert!(!GateVerdict::Fail.is_clean());
    }

    #[test]
    fn gate_verdict_serde() {
        for v in GateVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- ReplayDropKind ---

    #[test]
    fn replay_drop_kind_all_length() {
        assert_eq!(ReplayDropKind::ALL.len(), 5);
    }

    #[test]
    fn replay_drop_kind_serde() {
        for k in ReplayDropKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ReplayDropKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn replay_drop_kind_display() {
        for k in ReplayDropKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    // --- ConformanceVector ---

    #[test]
    fn conformance_vector_fraction_computed() {
        let v = ConformanceVector::new("s1", "v1", 200, 180, Vec::new(), epoch());
        assert_eq!(v.conformance_fraction, 900_000);
    }

    #[test]
    fn conformance_vector_full_conformance() {
        let v = good_conformance();
        assert!(v.is_fully_conformant());
        assert_eq!(v.conformance_fraction, 1_000_000);
    }

    #[test]
    fn conformance_vector_zero_tested() {
        let v = ConformanceVector::new("s1", "v1", 0, 0, Vec::new(), epoch());
        assert_eq!(v.conformance_fraction, 0);
        assert!(!v.is_fully_conformant());
    }

    #[test]
    fn conformance_vector_display() {
        let v = good_conformance();
        let s = v.to_string();
        assert!(s.contains("conformance[sess-1]"));
        assert!(s.contains("100/100"));
    }

    #[test]
    fn conformance_vector_serde() {
        let v = partial_conformance();
        let json = serde_json::to_string(&v).unwrap();
        let back: ConformanceVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- ReplayDropRecord ---

    #[test]
    fn replay_drop_rate_computed() {
        let r = ReplayDropRecord::new("s1", ReplayDropKind::Timeout, 5, 100, epoch());
        assert_eq!(r.drop_rate, 50_000);
    }

    #[test]
    fn replay_drop_zero_total() {
        let r = ReplayDropRecord::new("s1", ReplayDropKind::Timeout, 0, 0, epoch());
        assert_eq!(r.drop_rate, 0);
    }

    #[test]
    fn replay_drop_display() {
        let r = good_drop_record();
        let s = r.to_string();
        assert!(s.contains("replay-drop"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn replay_drop_serde() {
        let r = bad_drop_record();
        let json = serde_json::to_string(&r).unwrap();
        let back: ReplayDropRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- DegradedModeRecord ---

    #[test]
    fn degraded_record_security_critical() {
        let r = security_degraded_record();
        assert!(r.is_security_critical());
    }

    #[test]
    fn degraded_record_not_security_critical() {
        let r = mild_degraded_record();
        assert!(!r.is_security_critical());
    }

    #[test]
    fn degraded_record_display() {
        let r = severe_degraded_record();
        let s = r.to_string();
        assert!(s.contains("degraded"));
        assert!(s.contains("resource_exhaustion"));
    }

    #[test]
    fn degraded_record_serde() {
        let r = mild_degraded_record();
        let json = serde_json::to_string(&r).unwrap();
        let back: DegradedModeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- ObservabilityDelta ---

    #[test]
    fn observability_delta_overhead_computed() {
        let d = ObservabilityDelta::new(900_000, 1_000_000);
        assert_eq!(d.overhead_fraction, 100_000);
        assert!(d.acceptable);
    }

    #[test]
    fn observability_delta_high_overhead() {
        let d = ObservabilityDelta::new(500_000, 1_000_000);
        assert_eq!(d.overhead_fraction, 500_000);
        assert!(!d.acceptable);
    }

    #[test]
    fn observability_delta_zero_uninstrumented() {
        let d = ObservabilityDelta::new(100, 0);
        assert_eq!(d.overhead_fraction, 0);
    }

    #[test]
    fn observability_delta_display() {
        let d = ObservabilityDelta::new(900_000, 1_000_000);
        let s = d.to_string();
        assert!(s.contains("observability"));
    }

    #[test]
    fn observability_delta_with_custom_threshold() {
        let d = ObservabilityDelta::with_acceptable(800_000, 1_000_000, 250_000);
        assert_eq!(d.overhead_fraction, 200_000);
        assert!(d.acceptable);
    }

    #[test]
    fn observability_delta_serde() {
        let d = ObservabilityDelta::new(900_000, 1_000_000);
        let json = serde_json::to_string(&d).unwrap();
        let back: ObservabilityDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- GateConfig ---

    #[test]
    fn gate_config_default() {
        let c = GateConfig::default();
        assert_eq!(c.min_conformance_fraction, DEFAULT_MIN_CONFORMANCE);
        assert_eq!(c.max_replay_drop_rate, DEFAULT_MAX_REPLAY_DROP_RATE);
    }

    #[test]
    fn gate_config_strict_tighter_than_default() {
        let s = GateConfig::strict();
        let d = GateConfig::default();
        assert!(s.min_conformance_fraction >= d.min_conformance_fraction);
        assert!(s.max_replay_drop_rate <= d.max_replay_drop_rate);
    }

    #[test]
    fn gate_config_permissive_looser_than_default() {
        let p = GateConfig::permissive();
        let d = GateConfig::default();
        assert!(p.min_conformance_fraction <= d.min_conformance_fraction);
        assert!(p.max_replay_drop_rate >= d.max_replay_drop_rate);
    }

    #[test]
    fn gate_config_serde() {
        let c = GateConfig::strict();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- evaluate_conformance ---

    #[test]
    fn eval_conformance_full() {
        let level = evaluate_conformance(&good_conformance(), &default_config());
        assert_eq!(level, ConformanceLevel::Full);
    }

    #[test]
    fn eval_conformance_partial() {
        let level = evaluate_conformance(&partial_conformance(), &default_config());
        assert_eq!(level, ConformanceLevel::Partial);
    }

    #[test]
    fn eval_conformance_non_conformant_low_fraction() {
        let level = evaluate_conformance(&bad_conformance(), &default_config());
        assert_eq!(level, ConformanceLevel::NonConformant);
    }

    #[test]
    fn eval_conformance_non_conformant_too_few_tests() {
        let level = evaluate_conformance(&low_test_conformance(), &default_config());
        assert_eq!(level, ConformanceLevel::NonConformant);
    }

    #[test]
    fn eval_conformance_degraded_boundary() {
        // 60% conformance is above half of 90% threshold (45%) but below 90%.
        let v = ConformanceVector::new("s1", "v1", 100, 60, Vec::new(), epoch());
        let level = evaluate_conformance(&v, &default_config());
        assert_eq!(level, ConformanceLevel::Degraded);
    }

    // --- evaluate_replay_drops ---

    #[test]
    fn eval_drops_empty() {
        assert!(evaluate_replay_drops(&[], &default_config()));
    }

    #[test]
    fn eval_drops_acceptable() {
        assert!(evaluate_replay_drops(
            &[good_drop_record()],
            &default_config()
        ));
    }

    #[test]
    fn eval_drops_unacceptable() {
        assert!(!evaluate_replay_drops(
            &[bad_drop_record()],
            &default_config()
        ));
    }

    // --- evaluate_degraded_mode ---

    #[test]
    fn eval_degraded_empty() {
        let reasons = evaluate_degraded_mode(&[], &default_config());
        assert!(reasons.is_empty());
    }

    #[test]
    fn eval_degraded_mild_under_threshold() {
        let reasons = evaluate_degraded_mode(&[mild_degraded_record()], &default_config());
        assert!(reasons.is_empty());
    }

    #[test]
    fn eval_degraded_severe_over_threshold() {
        let reasons = evaluate_degraded_mode(&[severe_degraded_record()], &default_config());
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0], DegradedModeReason::ResourceExhaustion);
    }

    #[test]
    fn eval_degraded_security_always_flagged() {
        let reasons = evaluate_degraded_mode(&[security_degraded_record()], &default_config());
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0], DegradedModeReason::SecurityViolation);
    }

    #[test]
    fn eval_degraded_deduplicates_reasons() {
        let records = vec![
            severe_degraded_record(),
            DegradedModeRecord::new(
                "sess-2",
                DegradedModeReason::ResourceExhaustion,
                800_000,
                3,
                Vec::new(),
                epoch(),
            ),
        ];
        let reasons = evaluate_degraded_mode(&records, &default_config());
        assert_eq!(reasons.len(), 1);
    }

    // --- evaluate (full) ---

    #[test]
    fn eval_full_clean_pass() {
        let result = evaluate(&good_conformance(), &[], &[], None, &default_config());
        assert_eq!(result.verdict, GateVerdict::Pass);
        assert!(result.is_passing());
        assert!(result.blocking_reasons.is_empty());
    }

    #[test]
    fn eval_full_conditional_pass() {
        let result = evaluate(
            &partial_conformance(),
            &[good_drop_record()],
            &[],
            None,
            &default_config(),
        );
        assert_eq!(result.verdict, GateVerdict::ConditionalPass);
        assert!(result.is_passing());
    }

    #[test]
    fn eval_full_fail_bad_conformance() {
        let result = evaluate(&bad_conformance(), &[], &[], None, &default_config());
        assert_eq!(result.verdict, GateVerdict::Fail);
        assert!(!result.is_passing());
    }

    #[test]
    fn eval_full_fail_bad_drops() {
        let result = evaluate(
            &good_conformance(),
            &[bad_drop_record()],
            &[],
            None,
            &default_config(),
        );
        assert_eq!(result.verdict, GateVerdict::Fail);
    }

    #[test]
    fn eval_full_degraded_mode() {
        let result = evaluate(
            &good_conformance(),
            &[],
            &[severe_degraded_record()],
            None,
            &default_config(),
        );
        assert_eq!(result.verdict, GateVerdict::DegradedMode);
        assert!(result.is_passing());
        assert!(!result.degraded_reasons.is_empty());
    }

    #[test]
    fn eval_full_fail_security_violation() {
        let result = evaluate(
            &good_conformance(),
            &[],
            &[security_degraded_record()],
            None,
            &default_config(),
        );
        assert_eq!(result.verdict, GateVerdict::Fail);
        assert!(!result.is_passing());
    }

    #[test]
    fn eval_full_observability_overhead_recommendation() {
        let delta = ObservabilityDelta::new(500_000, 1_000_000);
        let result = evaluate(
            &good_conformance(),
            &[],
            &[],
            Some(&delta),
            &default_config(),
        );
        // Overhead alone produces a recommendation, not a block.
        assert_eq!(result.verdict, GateVerdict::ConditionalPass);
        assert!(result.has_recommendations());
    }

    #[test]
    fn eval_full_receipt_hash_deterministic() {
        let r1 = evaluate(&good_conformance(), &[], &[], None, &default_config());
        let r2 = evaluate(&good_conformance(), &[], &[], None, &default_config());
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn eval_full_receipt_hash_changes_with_input() {
        let r1 = evaluate(&good_conformance(), &[], &[], None, &default_config());
        let r2 = evaluate(&partial_conformance(), &[], &[], None, &default_config());
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    // --- GateResult ---

    #[test]
    fn gate_result_display() {
        let r = evaluate(&good_conformance(), &[], &[], None, &default_config());
        let s = r.to_string();
        assert!(s.contains("gate[pass]"));
    }

    #[test]
    fn gate_result_serde() {
        let r = evaluate(&good_conformance(), &[], &[], None, &default_config());
        let json = serde_json::to_string(&r).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- DecisionReceipt ---

    #[test]
    fn decision_receipt_new() {
        let evidence_hash = ContentHash::compute(b"evidence");
        let receipt = DecisionReceipt::new(epoch(), GateVerdict::Pass, evidence_hash);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.verdict, GateVerdict::Pass);
    }

    #[test]
    fn decision_receipt_hash_deterministic() {
        let eh = ContentHash::compute(b"test");
        let r1 = DecisionReceipt::new(epoch(), GateVerdict::Pass, eh);
        let r2 = DecisionReceipt::new(epoch(), GateVerdict::Pass, eh);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn decision_receipt_display() {
        let eh = ContentHash::compute(b"test");
        let r = DecisionReceipt::new(epoch(), GateVerdict::Fail, eh);
        let s = r.to_string();
        assert!(s.contains("receipt"));
        assert!(s.contains("fail"));
    }

    #[test]
    fn decision_receipt_serde() {
        let eh = ContentHash::compute(b"test");
        let r = DecisionReceipt::new(epoch(), GateVerdict::ConditionalPass, eh);
        let json = serde_json::to_string(&r).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- GateSummary ---

    #[test]
    fn gate_summary_empty() {
        let s = GateSummary::from_results(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.pass_rate, 0);
        assert!(!s.all_passing());
    }

    #[test]
    fn gate_summary_all_pass() {
        let results = vec![
            evaluate(&good_conformance(), &[], &[], None, &default_config()),
            evaluate(&good_conformance(), &[], &[], None, &default_config()),
        ];
        let s = GateSummary::from_results(&results);
        assert_eq!(s.total, 2);
        assert_eq!(s.passed, 2);
        assert_eq!(s.pass_rate, 1_000_000);
        assert!(s.all_passing());
    }

    #[test]
    fn gate_summary_mixed() {
        let results = vec![
            evaluate(&good_conformance(), &[], &[], None, &default_config()),
            evaluate(&bad_conformance(), &[], &[], None, &default_config()),
        ];
        let s = GateSummary::from_results(&results);
        assert_eq!(s.total, 2);
        assert_eq!(s.passed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.pass_rate, 500_000);
        assert!(!s.all_passing());
    }

    #[test]
    fn gate_summary_display() {
        let s = GateSummary::from_results(&[]);
        let text = s.to_string();
        assert!(text.contains("summary"));
    }

    #[test]
    fn gate_summary_serde() {
        let results = vec![evaluate(
            &good_conformance(),
            &[],
            &[],
            None,
            &default_config(),
        )];
        let s = GateSummary::from_results(&results);
        let json = serde_json::to_string(&s).unwrap();
        let back: GateSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
