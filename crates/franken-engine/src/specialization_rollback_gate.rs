//! Bead: bd-1lsy.7.4.3 [RGC-604C]
//!
//! Rollback, interference, and publication governance for proof-guided
//! specialization.
//!
//! This gate governs aggressive proof-guided specialization so it does not
//! create hidden tail-latency or correctness cliffs:
//!
//! 1. **Interference detection** — tracks when two or more specialization
//!    envelopes overlap on shared state and can produce non-deterministic
//!    execution order.
//! 2. **Rollback governance** — reverts specialization when post-ship metrics
//!    regress beyond configurable thresholds.
//! 3. **Publication rules** — requires parity evidence and budget compliance
//!    before specialization may be published to shipped paths.
//! 4. **Observability** — every decision emits an auditable receipt with
//!    evidence hashes, timing, and affected-site lists.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.specialization-rollback-gate.v1";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.7.4.3";

/// Component name for diagnostics.
pub const COMPONENT: &str = "specialization_rollback_gate";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-604C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default maximum tail-latency regression (millionths). 30_000 = 3%.
pub const DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS: u64 = 30_000;

/// Default maximum interference score (millionths). 100_000 = 10%.
pub const DEFAULT_MAX_INTERFERENCE_MILLIONTHS: u64 = 100_000;

/// Default minimum parity ratio for publication (millionths). 1_000_000 = 100%.
pub const DEFAULT_MIN_PARITY_MILLIONTHS: u64 = 1_000_000;

/// Default minimum sample count for statistical validity.
pub const DEFAULT_MIN_SAMPLES: u64 = 50;

/// Maximum consecutive rollbacks before permanent lockout.
pub const MAX_CONSECUTIVE_ROLLBACKS: u32 = 3;

/// Default cooldown after rollback (nanoseconds). 5 seconds.
pub const DEFAULT_ROLLBACK_COOLDOWN_NS: u64 = 5_000_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// SpecializationKind
// ---------------------------------------------------------------------------

/// Kind of specialization being governed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationKind {
    /// Trace-fused superinstruction.
    TraceFusion,
    /// Capability-pruned dispatch.
    CapabilityPruning,
    /// Guard-elided region.
    GuardElision,
    /// Allocation elision.
    AllocationElision,
    /// Inline cache specialization.
    InlineCache,
    /// Type-specialized arithmetic.
    TypeSpecialization,
}

impl SpecializationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TraceFusion => "trace_fusion",
            Self::CapabilityPruning => "capability_pruning",
            Self::GuardElision => "guard_elision",
            Self::AllocationElision => "allocation_elision",
            Self::InlineCache => "inline_cache",
            Self::TypeSpecialization => "type_specialization",
        }
    }
}

impl fmt::Display for SpecializationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// InterferenceKind
// ---------------------------------------------------------------------------

/// Kind of interference between specialization envelopes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterferenceKind {
    /// Two envelopes read/write the same memory region.
    SharedState,
    /// Two envelopes compete for the same inline cache slot.
    CacheContention,
    /// Guard assumptions in one envelope contradict another.
    GuardConflict,
    /// Capability requirements overlap in incompatible ways.
    CapabilityOverlap,
    /// Type feedback from one invalidates assumptions in another.
    TypeFeedbackConflict,
}

impl fmt::Display for InterferenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedState => f.write_str("shared_state"),
            Self::CacheContention => f.write_str("cache_contention"),
            Self::GuardConflict => f.write_str("guard_conflict"),
            Self::CapabilityOverlap => f.write_str("capability_overlap"),
            Self::TypeFeedbackConflict => f.write_str("type_feedback_conflict"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Overall verdict from the specialization gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Specialization approved for publication.
    Approved,
    /// Specialization denied.
    Denied,
    /// Previously approved but rolled back.
    RolledBack,
    /// Insufficient data to decide.
    Inconclusive,
}

impl GateVerdict {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::RolledBack => "rolled_back",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BlockingReason
// ---------------------------------------------------------------------------

/// Reason the gate denied or rolled back a specialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingReason {
    /// Tail-latency regression exceeds threshold.
    TailLatencyRegression {
        regression_millionths: u64,
        threshold_millionths: u64,
    },
    /// Interference score exceeds threshold.
    InterferenceExceeded {
        interference_millionths: u64,
        threshold_millionths: u64,
    },
    /// Parity ratio below publication requirement.
    ParityInsufficient {
        parity_millionths: u64,
        minimum_millionths: u64,
    },
    /// Budget exceeded for this specialization kind.
    BudgetExceeded {
        kind: SpecializationKind,
        used: u64,
        budget: u64,
    },
    /// Insufficient sample count.
    InsufficientSamples { actual: u64, minimum: u64 },
    /// Rollback lockout active.
    RollbackLockout { consecutive: u32 },
    /// Cooldown period active.
    CooldownActive { remaining_ns: u64 },
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TailLatencyRegression {
                regression_millionths,
                threshold_millionths,
            } => write!(
                f,
                "tail_regression({regression_millionths}>{threshold_millionths})"
            ),
            Self::InterferenceExceeded {
                interference_millionths,
                threshold_millionths,
            } => write!(
                f,
                "interference({interference_millionths}>{threshold_millionths})"
            ),
            Self::ParityInsufficient {
                parity_millionths,
                minimum_millionths,
            } => write!(f, "parity({parity_millionths}<{minimum_millionths})"),
            Self::BudgetExceeded { kind, used, budget } => {
                write!(f, "budget_exceeded({kind}:{used}>{budget})")
            }
            Self::InsufficientSamples { actual, minimum } => {
                write!(f, "insufficient_samples({actual}<{minimum})")
            }
            Self::RollbackLockout { consecutive } => {
                write!(f, "rollback_lockout({consecutive})")
            }
            Self::CooldownActive { remaining_ns } => {
                write!(f, "cooldown({remaining_ns}ns)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InterferenceReport
// ---------------------------------------------------------------------------

/// Report of detected interference between specialization envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceReport {
    /// Identifier for this report.
    pub report_id: String,
    /// First envelope identifier.
    pub envelope_a: String,
    /// Second envelope identifier.
    pub envelope_b: String,
    /// Kind of interference.
    pub kind: InterferenceKind,
    /// Interference severity in millionths (0 = none, 1_000_000 = total).
    pub severity_millionths: u64,
    /// Shared sites (e.g. bytecode offsets, memory regions).
    pub shared_sites: BTreeSet<String>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl InterferenceReport {
    /// Create a new interference report.
    pub fn new(
        report_id: &str,
        envelope_a: &str,
        envelope_b: &str,
        kind: InterferenceKind,
        severity_millionths: u64,
        shared_sites: BTreeSet<String>,
    ) -> Self {
        let mut r = Self {
            report_id: report_id.to_string(),
            envelope_a: envelope_a.to_string(),
            envelope_b: envelope_b.to_string(),
            kind,
            severity_millionths,
            shared_sites,
            content_hash: ContentHash::compute(b""),
        };
        r.seal();
        r
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.report_id);
        append_str(&mut buf, &self.envelope_a);
        append_str(&mut buf, &self.envelope_b);
        append_str(&mut buf, &format!("{}", self.kind));
        append_u64(&mut buf, self.severity_millionths);
        for site in &self.shared_sites {
            append_str(&mut buf, site);
        }
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// SpecializationEvidence
// ---------------------------------------------------------------------------

/// Evidence for a specialization publication candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationEvidence {
    /// Evidence identifier.
    pub evidence_id: String,
    /// Kind of specialization.
    pub kind: SpecializationKind,
    /// Envelope identifier being evaluated.
    pub envelope_id: String,
    /// Number of test sites.
    pub sample_count: u64,
    /// Parity ratio in millionths (specialized vs baseline).
    pub parity_millionths: u64,
    /// Tail-latency regression in millionths (positive = worse).
    pub tail_regression_millionths: u64,
    /// Budget usage in millionths (fraction of allowed budget used).
    pub budget_usage_millionths: u64,
    /// Interference reports.
    pub interference_reports: Vec<InterferenceReport>,
    /// Maximum interference severity across all reports.
    pub max_interference_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SpecializationEvidence {
    /// Create new evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: &str,
        kind: SpecializationKind,
        envelope_id: &str,
        sample_count: u64,
        parity_millionths: u64,
        tail_regression_millionths: u64,
        budget_usage_millionths: u64,
        interference_reports: Vec<InterferenceReport>,
    ) -> Self {
        let max_interference_millionths = interference_reports
            .iter()
            .map(|r| r.severity_millionths)
            .max()
            .unwrap_or(0);

        let mut ev = Self {
            evidence_id: evidence_id.to_string(),
            kind,
            envelope_id: envelope_id.to_string(),
            sample_count,
            parity_millionths,
            tail_regression_millionths,
            budget_usage_millionths,
            interference_reports,
            max_interference_millionths,
            content_hash: ContentHash::compute(b""),
        };
        ev.seal();
        ev
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.evidence_id);
        append_str(&mut buf, self.kind.as_str());
        append_str(&mut buf, &self.envelope_id);
        append_u64(&mut buf, self.sample_count);
        append_u64(&mut buf, self.parity_millionths);
        append_u64(&mut buf, self.tail_regression_millionths);
        append_u64(&mut buf, self.budget_usage_millionths);
        append_u64(&mut buf, self.max_interference_millionths);
        for r in &self.interference_reports {
            buf.extend_from_slice(r.content_hash.as_bytes());
        }
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a specialization rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Record identifier.
    pub record_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Envelope that was rolled back.
    pub envelope_id: String,
    /// Reason for the rollback.
    pub reason: BlockingReason,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl RollbackRecord {
    /// Create a new rollback record.
    pub fn new(
        record_id: &str,
        epoch: SecurityEpoch,
        envelope_id: &str,
        reason: BlockingReason,
        timestamp_ns: u64,
    ) -> Self {
        let mut r = Self {
            record_id: record_id.to_string(),
            epoch,
            envelope_id: envelope_id.to_string(),
            reason,
            timestamp_ns,
            content_hash: ContentHash::compute(b""),
        };
        r.seal();
        r
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.record_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, &self.envelope_id);
        append_str(&mut buf, &format!("{}", self.reason));
        append_u64(&mut buf, self.timestamp_ns);
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Envelope evaluated.
    pub envelope_id: String,
    /// Specialization kind.
    pub kind: SpecializationKind,
    /// Gate verdict.
    pub verdict: GateVerdict,
    /// Blocking reasons (empty if approved).
    pub blocking_reasons: Vec<BlockingReason>,
    /// Evidence hash.
    pub evidence_hash: ContentHash,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl DecisionReceipt {
    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.receipt_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, &self.envelope_id);
        append_str(&mut buf, self.kind.as_str());
        append_str(&mut buf, self.verdict.as_str());
        for reason in &self.blocking_reasons {
            append_str(&mut buf, &format!("{reason}"));
        }
        buf.extend_from_slice(self.evidence_hash.as_bytes());
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the specialization rollback gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum tail-latency regression (millionths).
    pub max_tail_regression_millionths: u64,
    /// Maximum interference score (millionths).
    pub max_interference_millionths: u64,
    /// Minimum parity ratio for publication (millionths).
    pub min_parity_millionths: u64,
    /// Minimum sample count.
    pub min_samples: u64,
    /// Maximum consecutive rollbacks.
    pub max_consecutive_rollbacks: u32,
    /// Rollback cooldown (nanoseconds).
    pub rollback_cooldown_ns: u64,
    /// Per-kind budget limits (millionths).
    pub kind_budgets: BTreeMap<String, u64>,
    /// Whether to fail closed on insufficient data.
    pub fail_closed: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_tail_regression_millionths: DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS,
            max_interference_millionths: DEFAULT_MAX_INTERFERENCE_MILLIONTHS,
            min_parity_millionths: DEFAULT_MIN_PARITY_MILLIONTHS,
            min_samples: DEFAULT_MIN_SAMPLES,
            max_consecutive_rollbacks: MAX_CONSECUTIVE_ROLLBACKS,
            rollback_cooldown_ns: DEFAULT_ROLLBACK_COOLDOWN_NS,
            kind_budgets: BTreeMap::new(),
            fail_closed: true,
        }
    }
}

impl GateConfig {
    /// Set tail regression threshold.
    pub fn with_tail_regression(mut self, threshold: u64) -> Self {
        self.max_tail_regression_millionths = threshold;
        self
    }

    /// Set interference threshold.
    pub fn with_interference_threshold(mut self, threshold: u64) -> Self {
        self.max_interference_millionths = threshold;
        self
    }

    /// Set parity threshold.
    pub fn with_parity_threshold(mut self, threshold: u64) -> Self {
        self.min_parity_millionths = threshold;
        self
    }

    /// Use fail-open semantics.
    pub fn fail_open(mut self) -> Self {
        self.fail_closed = false;
        self
    }

    /// Set a budget for a specific specialization kind.
    pub fn with_kind_budget(mut self, kind: &SpecializationKind, budget: u64) -> Self {
        self.kind_budgets.insert(kind.as_str().to_string(), budget);
        self
    }
}

// ---------------------------------------------------------------------------
// SpecializationRollbackGate — main evaluator
// ---------------------------------------------------------------------------

/// Gate evaluator for specialization rollback governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecializationRollbackGate {
    config: GateConfig,
    epoch: SecurityEpoch,
    evaluation_count: u64,
    approved_count: u64,
    denied_count: u64,
    consecutive_rollbacks: u32,
    last_rollback_ns: u64,
    rollback_history: Vec<RollbackRecord>,
    last_receipt: Option<DecisionReceipt>,
    per_kind_counts: BTreeMap<String, u64>,
}

impl SpecializationRollbackGate {
    /// Create a new gate.
    pub fn new(config: GateConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            epoch,
            evaluation_count: 0,
            approved_count: 0,
            denied_count: 0,
            consecutive_rollbacks: 0,
            last_rollback_ns: 0,
            rollback_history: Vec::new(),
            last_receipt: None,
            per_kind_counts: BTreeMap::new(),
        }
    }

    /// Create with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GateConfig::default(), epoch)
    }

    /// Access config.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Current epoch.
    pub fn epoch(&self) -> &SecurityEpoch {
        &self.epoch
    }

    /// Total evaluations.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Total approvals.
    pub fn approved_count(&self) -> u64 {
        self.approved_count
    }

    /// Total denials.
    pub fn denied_count(&self) -> u64 {
        self.denied_count
    }

    /// Most recent receipt.
    pub fn last_receipt(&self) -> Option<&DecisionReceipt> {
        self.last_receipt.as_ref()
    }

    /// Rollback history.
    pub fn rollback_history(&self) -> &[RollbackRecord] {
        &self.rollback_history
    }

    /// Whether rollback lockout is active.
    pub fn is_locked_out(&self) -> bool {
        self.consecutive_rollbacks >= self.config.max_consecutive_rollbacks
    }

    /// Whether cooldown is active at the given timestamp.
    pub fn is_cooldown_active(&self, current_ns: u64) -> bool {
        if self.last_rollback_ns == 0 {
            return false;
        }
        current_ns.saturating_sub(self.last_rollback_ns) < self.config.rollback_cooldown_ns
    }

    /// Evaluate a specialization for publication.
    pub fn evaluate(
        &mut self,
        receipt_id: &str,
        evidence: &SpecializationEvidence,
        current_ns: u64,
    ) -> GateVerdict {
        self.evaluation_count += 1;
        let mut blocking_reasons = Vec::new();

        // Check rollback lockout
        if self.is_locked_out() {
            blocking_reasons.push(BlockingReason::RollbackLockout {
                consecutive: self.consecutive_rollbacks,
            });
        }

        // Check cooldown
        if self.is_cooldown_active(current_ns) {
            let remaining = self
                .config
                .rollback_cooldown_ns
                .saturating_sub(current_ns.saturating_sub(self.last_rollback_ns));
            blocking_reasons.push(BlockingReason::CooldownActive {
                remaining_ns: remaining,
            });
        }

        // Check sample count
        if evidence.sample_count < self.config.min_samples {
            blocking_reasons.push(BlockingReason::InsufficientSamples {
                actual: evidence.sample_count,
                minimum: self.config.min_samples,
            });
        }

        // Check tail regression
        if evidence.tail_regression_millionths > self.config.max_tail_regression_millionths {
            blocking_reasons.push(BlockingReason::TailLatencyRegression {
                regression_millionths: evidence.tail_regression_millionths,
                threshold_millionths: self.config.max_tail_regression_millionths,
            });
        }

        // Check interference
        if evidence.max_interference_millionths > self.config.max_interference_millionths {
            blocking_reasons.push(BlockingReason::InterferenceExceeded {
                interference_millionths: evidence.max_interference_millionths,
                threshold_millionths: self.config.max_interference_millionths,
            });
        }

        // Check parity
        if evidence.parity_millionths < self.config.min_parity_millionths {
            blocking_reasons.push(BlockingReason::ParityInsufficient {
                parity_millionths: evidence.parity_millionths,
                minimum_millionths: self.config.min_parity_millionths,
            });
        }

        // Check per-kind budget
        let kind_key = evidence.kind.as_str().to_string();
        if let Some(&budget) = self.config.kind_budgets.get(&kind_key)
            && evidence.budget_usage_millionths > budget
        {
            blocking_reasons.push(BlockingReason::BudgetExceeded {
                kind: evidence.kind.clone(),
                used: evidence.budget_usage_millionths,
                budget,
            });
        }

        // Determine verdict
        let verdict = if blocking_reasons.is_empty() {
            GateVerdict::Approved
        } else if self.config.fail_closed
            || blocking_reasons.iter().any(|r| {
                matches!(
                    r,
                    BlockingReason::TailLatencyRegression { .. }
                        | BlockingReason::InterferenceExceeded { .. }
                        | BlockingReason::RollbackLockout { .. }
                )
            })
        {
            GateVerdict::Denied
        } else {
            GateVerdict::Inconclusive
        };

        // Update counters
        match verdict {
            GateVerdict::Approved => {
                self.approved_count += 1;
                self.consecutive_rollbacks = 0;
                *self.per_kind_counts.entry(kind_key).or_insert(0) += 1;
            }
            GateVerdict::Denied | GateVerdict::RolledBack => {
                self.denied_count += 1;
            }
            GateVerdict::Inconclusive => {}
        }

        // Build receipt
        let mut receipt = DecisionReceipt {
            receipt_id: receipt_id.to_string(),
            epoch: self.epoch,
            envelope_id: evidence.envelope_id.clone(),
            kind: evidence.kind.clone(),
            verdict,
            blocking_reasons,
            evidence_hash: evidence.content_hash,
            content_hash: ContentHash::compute(b""),
        };
        receipt.seal();
        self.last_receipt = Some(receipt);

        verdict
    }

    /// Trigger a rollback for a specific envelope.
    pub fn rollback(
        &mut self,
        record_id: &str,
        envelope_id: &str,
        reason: BlockingReason,
        timestamp_ns: u64,
    ) -> &RollbackRecord {
        self.consecutive_rollbacks += 1;
        self.last_rollback_ns = timestamp_ns;

        let record = RollbackRecord::new(record_id, self.epoch, envelope_id, reason, timestamp_ns);
        self.rollback_history.push(record);
        self.rollback_history.last().unwrap()
    }

    /// Reset rollback counter.
    pub fn reset_rollback_counter(&mut self) {
        self.consecutive_rollbacks = 0;
    }

    /// Pass rate in millionths.
    pub fn pass_rate_millionths(&self) -> u64 {
        if self.evaluation_count == 0 {
            return 0;
        }
        self.approved_count
            .saturating_mul(MILLIONTHS)
            .checked_div(self.evaluation_count)
            .unwrap_or(0)
    }

    /// Summary statistics.
    pub fn summary(&self) -> GateSummary {
        GateSummary {
            total_evaluations: self.evaluation_count,
            approved_count: self.approved_count,
            denied_count: self.denied_count,
            rollback_count: self.rollback_history.len() as u64,
            is_locked_out: self.is_locked_out(),
            pass_rate_millionths: self.pass_rate_millionths(),
        }
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    pub total_evaluations: u64,
    pub approved_count: u64,
    pub denied_count: u64,
    pub rollback_count: u64,
    pub is_locked_out: bool,
    pub pass_rate_millionths: u64,
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Default manifest for this module.
pub fn specialization_rollback_gate_manifest() -> GateSummary {
    GateSummary {
        total_evaluations: 0,
        approved_count: 0,
        denied_count: 0,
        rollback_count: 0,
        is_locked_out: false,
        pass_rate_millionths: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn good_evidence() -> SpecializationEvidence {
        SpecializationEvidence::new(
            "ev-001",
            SpecializationKind::TraceFusion,
            "env-001",
            100,        // sample_count
            MILLIONTHS, // parity = 100%
            0,          // no regression
            500_000,    // 50% budget used
            vec![],     // no interference
        )
    }

    fn bad_parity_evidence() -> SpecializationEvidence {
        SpecializationEvidence::new(
            "ev-002",
            SpecializationKind::TraceFusion,
            "env-002",
            100,
            800_000, // parity = 80%, below 100% default
            0,
            500_000,
            vec![],
        )
    }

    fn bad_tail_evidence() -> SpecializationEvidence {
        SpecializationEvidence::new(
            "ev-003",
            SpecializationKind::GuardElision,
            "env-003",
            100,
            MILLIONTHS,
            100_000, // 10% regression, above 3% default threshold
            500_000,
            vec![],
        )
    }

    fn interference_evidence() -> SpecializationEvidence {
        let report = InterferenceReport::new(
            "ir-001",
            "env-a",
            "env-b",
            InterferenceKind::SharedState,
            200_000, // 20% interference
            BTreeSet::from(["site-1".to_string(), "site-2".to_string()]),
        );
        SpecializationEvidence::new(
            "ev-004",
            SpecializationKind::InlineCache,
            "env-004",
            100,
            MILLIONTHS,
            0,
            500_000,
            vec![report],
        )
    }

    fn insufficient_evidence() -> SpecializationEvidence {
        SpecializationEvidence::new(
            "ev-005",
            SpecializationKind::TypeSpecialization,
            "env-005",
            5, // too few samples
            MILLIONTHS,
            0,
            500_000,
            vec![],
        )
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("specialization-rollback-gate"));
    }

    #[test]
    fn test_bead_id() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "specialization_rollback_gate");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-604C");
    }

    #[test]
    fn test_millionths() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // SpecializationKind
    // -----------------------------------------------------------------------

    #[test]
    fn test_specialization_kind_display() {
        assert_eq!(
            format!("{}", SpecializationKind::TraceFusion),
            "trace_fusion"
        );
        assert_eq!(
            format!("{}", SpecializationKind::InlineCache),
            "inline_cache"
        );
    }

    #[test]
    fn test_specialization_kind_serde() {
        let k = SpecializationKind::GuardElision;
        let json = serde_json::to_string(&k).unwrap();
        let back: SpecializationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }

    // -----------------------------------------------------------------------
    // InterferenceKind
    // -----------------------------------------------------------------------

    #[test]
    fn test_interference_kind_display() {
        assert_eq!(format!("{}", InterferenceKind::SharedState), "shared_state");
        assert_eq!(
            format!("{}", InterferenceKind::CacheContention),
            "cache_contention"
        );
    }

    // -----------------------------------------------------------------------
    // GateVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_verdict_approved() {
        assert!(GateVerdict::Approved.is_approved());
        assert!(!GateVerdict::Denied.is_approved());
        assert!(!GateVerdict::RolledBack.is_approved());
        assert!(!GateVerdict::Inconclusive.is_approved());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Denied), "denied");
    }

    // -----------------------------------------------------------------------
    // BlockingReason
    // -----------------------------------------------------------------------

    #[test]
    fn test_blocking_reason_display() {
        let r = BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        };
        let s = format!("{r}");
        assert!(s.contains("100000>30000"));
    }

    #[test]
    fn test_blocking_reason_serde() {
        let r = BlockingReason::BudgetExceeded {
            kind: SpecializationKind::AllocationElision,
            used: 800_000,
            budget: 500_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -----------------------------------------------------------------------
    // InterferenceReport
    // -----------------------------------------------------------------------

    #[test]
    fn test_interference_report_seal() {
        let r = InterferenceReport::new(
            "ir-001",
            "env-a",
            "env-b",
            InterferenceKind::SharedState,
            200_000,
            BTreeSet::from(["s1".to_string()]),
        );
        assert_ne!(r.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn test_interference_report_deterministic() {
        let a = InterferenceReport::new(
            "ir-001",
            "env-a",
            "env-b",
            InterferenceKind::GuardConflict,
            100_000,
            BTreeSet::new(),
        );
        let b = InterferenceReport::new(
            "ir-001",
            "env-a",
            "env-b",
            InterferenceKind::GuardConflict,
            100_000,
            BTreeSet::new(),
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // SpecializationEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn test_evidence_max_interference() {
        let ev = interference_evidence();
        assert_eq!(ev.max_interference_millionths, 200_000);
    }

    #[test]
    fn test_evidence_no_interference() {
        let ev = good_evidence();
        assert_eq!(ev.max_interference_millionths, 0);
    }

    #[test]
    fn test_evidence_seal_deterministic() {
        let a = good_evidence();
        let b = good_evidence();
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // RollbackRecord
    // -----------------------------------------------------------------------

    #[test]
    fn test_rollback_record_seal() {
        let r = RollbackRecord::new(
            "rb-001",
            epoch(),
            "env-001",
            BlockingReason::TailLatencyRegression {
                regression_millionths: 100_000,
                threshold_millionths: 30_000,
            },
            1_000_000_000,
        );
        assert_ne!(r.content_hash, ContentHash::compute(b""));
    }

    // -----------------------------------------------------------------------
    // GateConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let c = GateConfig::default();
        assert_eq!(c.max_tail_regression_millionths, 30_000);
        assert_eq!(c.max_interference_millionths, 100_000);
        assert_eq!(c.min_parity_millionths, MILLIONTHS);
        assert!(c.fail_closed);
    }

    #[test]
    fn test_config_builders() {
        let c = GateConfig::default()
            .with_tail_regression(50_000)
            .with_interference_threshold(200_000)
            .with_parity_threshold(900_000)
            .fail_open();
        assert_eq!(c.max_tail_regression_millionths, 50_000);
        assert_eq!(c.max_interference_millionths, 200_000);
        assert_eq!(c.min_parity_millionths, 900_000);
        assert!(!c.fail_closed);
    }

    #[test]
    fn test_config_kind_budget() {
        let c = GateConfig::default().with_kind_budget(&SpecializationKind::TraceFusion, 800_000);
        assert_eq!(c.kind_budgets.get("trace_fusion"), Some(&800_000));
    }

    #[test]
    fn test_config_serde() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -----------------------------------------------------------------------
    // SpecializationRollbackGate — construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_new() {
        let g = SpecializationRollbackGate::with_defaults(epoch());
        assert_eq!(g.evaluation_count(), 0);
        assert!(!g.is_locked_out());
    }

    #[test]
    fn test_gate_epoch() {
        let g = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(42));
        assert_eq!(g.epoch().as_u64(), 42);
    }

    // -----------------------------------------------------------------------
    // SpecializationRollbackGate — evaluate
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_approve() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        let v = g.evaluate("r-001", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Approved);
        assert_eq!(g.approved_count(), 1);
    }

    #[test]
    fn test_evaluate_deny_parity() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = bad_parity_evidence();
        let v = g.evaluate("r-002", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| { matches!(r, BlockingReason::ParityInsufficient { .. }) })
        );
    }

    #[test]
    fn test_evaluate_deny_tail_regression() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = bad_tail_evidence();
        let v = g.evaluate("r-003", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| { matches!(r, BlockingReason::TailLatencyRegression { .. }) })
        );
    }

    #[test]
    fn test_evaluate_deny_interference() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = interference_evidence();
        let v = g.evaluate("r-004", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Denied);
    }

    #[test]
    fn test_evaluate_deny_insufficient_samples() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = insufficient_evidence();
        let v = g.evaluate("r-005", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Denied);
    }

    #[test]
    fn test_evaluate_budget_exceeded() {
        let config =
            GateConfig::default().with_kind_budget(&SpecializationKind::TraceFusion, 400_000);
        let mut g = SpecializationRollbackGate::new(config, epoch());
        let ev = good_evidence(); // 500_000 budget usage
        let v = g.evaluate("r-006", &ev, 100_000_000);
        assert_eq!(v, GateVerdict::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| { matches!(r, BlockingReason::BudgetExceeded { .. }) })
        );
    }

    // -----------------------------------------------------------------------
    // Rollback
    // -----------------------------------------------------------------------

    #[test]
    fn test_rollback_increments() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            "env-001",
            BlockingReason::TailLatencyRegression {
                regression_millionths: 100_000,
                threshold_millionths: 30_000,
            },
            1_000_000_000,
        );
        assert_eq!(g.consecutive_rollbacks, 1);
        assert_eq!(g.rollback_history().len(), 1);
    }

    #[test]
    fn test_rollback_lockout() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
            g.rollback(
                &format!("rb-{i:03}"),
                "env-001",
                BlockingReason::TailLatencyRegression {
                    regression_millionths: 100_000,
                    threshold_millionths: 30_000,
                },
                (i as u64 + 1) * 1_000_000_000,
            );
        }
        assert!(g.is_locked_out());

        // Now even good evidence should be denied
        let ev = good_evidence();
        let ts = (MAX_CONSECUTIVE_ROLLBACKS as u64 + 100) * 1_000_000_000;
        let v = g.evaluate("r-lockout", &ev, ts);
        assert_eq!(v, GateVerdict::Denied);
    }

    #[test]
    fn test_cooldown() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            "env-001",
            BlockingReason::TailLatencyRegression {
                regression_millionths: 100_000,
                threshold_millionths: 30_000,
            },
            1_000_000_000,
        );
        assert!(g.is_cooldown_active(1_000_000_001));
        assert!(!g.is_cooldown_active(1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1));
    }

    #[test]
    fn test_reset_rollback_counter() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            "env-001",
            BlockingReason::TailLatencyRegression {
                regression_millionths: 100_000,
                threshold_millionths: 30_000,
            },
            1_000_000_000,
        );
        g.reset_rollback_counter();
        assert_eq!(g.consecutive_rollbacks, 0);
    }

    // -----------------------------------------------------------------------
    // Counters
    // -----------------------------------------------------------------------

    #[test]
    fn test_pass_rate_empty() {
        let g = SpecializationRollbackGate::with_defaults(epoch());
        assert_eq!(g.pass_rate_millionths(), 0);
    }

    #[test]
    fn test_pass_rate_all() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        g.evaluate("r-002", &ev, 200_000_000);
        assert_eq!(g.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_pass_rate_half() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let good = good_evidence();
        let bad = bad_tail_evidence();
        g.evaluate("r-001", &good, 100_000_000);
        g.evaluate("r-002", &bad, 200_000_000);
        assert_eq!(g.pass_rate_millionths(), 500_000);
    }

    #[test]
    fn test_summary() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        let s = g.summary();
        assert_eq!(s.total_evaluations, 1);
        assert_eq!(s.approved_count, 1);
    }

    // -----------------------------------------------------------------------
    // Receipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_after_evaluate() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        assert!(g.last_receipt().is_none());
        let ev = good_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        assert!(g.last_receipt().is_some());
    }

    #[test]
    fn test_receipt_approved_no_reasons() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        let receipt = g.last_receipt().unwrap();
        assert!(receipt.blocking_reasons.is_empty());
        assert_eq!(receipt.verdict, GateVerdict::Approved);
    }

    #[test]
    fn test_receipt_denied_has_reasons() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = bad_tail_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        let receipt = g.last_receipt().unwrap();
        assert!(!receipt.blocking_reasons.is_empty());
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut g1 = SpecializationRollbackGate::with_defaults(epoch());
        let mut g2 = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        g1.evaluate("r-001", &ev, 100_000_000);
        g2.evaluate("r-001", &ev, 100_000_000);
        assert_eq!(
            g1.last_receipt().unwrap().content_hash,
            g2.last_receipt().unwrap().content_hash,
        );
    }

    // -----------------------------------------------------------------------
    // Gate serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_serde() {
        let mut g = SpecializationRollbackGate::with_defaults(epoch());
        let ev = good_evidence();
        g.evaluate("r-001", &ev, 100_000_000);
        let json = serde_json::to_string(&g).unwrap();
        let back: SpecializationRollbackGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evaluation_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest() {
        let m = specialization_rollback_gate_manifest();
        assert_eq!(m.total_evaluations, 0);
        assert!(!m.is_locked_out);
    }
}
