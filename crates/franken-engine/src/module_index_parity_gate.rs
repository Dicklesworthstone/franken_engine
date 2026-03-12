//! Bead: bd-1lsy.5.8.3 [RGC-406C]
//!
//! Module-index parity, cold-start, and rollback governance for shipped
//! package cohorts.
//!
//! Gates the ART/MPHF-accelerated module-resolution index on:
//!
//! 1. **Parity** — indexed resolution must match baseline (node_modules walk)
//!    on every exported specifier in the covered package cohort.
//! 2. **Cold-start** — startup latency with the index must not regress beyond
//!    a configurable budget versus no-index baseline.
//! 3. **Rollback** — if parity breaks or cold-start regresses, the gate
//!    reverts to checked mode and emits a rollback receipt.
//! 4. **Observability** — every verdict emits a decision receipt with
//!    evidence hash, timing data, and affected-package list.
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

/// Schema version for module-index parity gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.module-index-parity-gate.v1";

/// Bead originating this module.
pub const BEAD_ID: &str = "bd-1lsy.5.8.3";

/// Component name for structured logging.
pub const COMPONENT: &str = "module_index_parity_gate";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-406C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default parity threshold: 1_000_000 = 100% match required.
pub const DEFAULT_PARITY_THRESHOLD_MILLIONTHS: u64 = 1_000_000;

/// Default cold-start budget (millionths). 50_000 = 5% regression allowed.
pub const DEFAULT_COLD_START_BUDGET_MILLIONTHS: u64 = 50_000;

/// Default minimum specifier sample count for statistical validity.
pub const DEFAULT_MIN_SPECIFIER_COUNT: u64 = 100;

/// Maximum consecutive rollbacks before permanent lockout.
pub const MAX_CONSECUTIVE_ROLLBACKS: u32 = 3;

/// Default rollback cooldown in nanoseconds (10 seconds).
pub const DEFAULT_ROLLBACK_COOLDOWN_NS: u64 = 10_000_000_000;

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
// ParityVerdict
// ---------------------------------------------------------------------------

/// Outcome of module-index parity evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityVerdict {
    /// Full parity: index matches baseline on all covered specifiers.
    FullParity,
    /// Partial parity: below threshold but above zero.
    PartialParity,
    /// No parity: too many mismatches.
    NoParity,
    /// Insufficient data: not enough specifiers sampled.
    InsufficientData,
}

impl ParityVerdict {
    /// Whether this verdict allows the index to be shipped.
    pub fn is_shippable(&self) -> bool {
        matches!(self, Self::FullParity)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullParity => "full_parity",
            Self::PartialParity => "partial_parity",
            Self::NoParity => "no_parity",
            Self::InsufficientData => "insufficient_data",
        }
    }
}

impl fmt::Display for ParityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ColdStartVerdict
// ---------------------------------------------------------------------------

/// Outcome of cold-start evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartVerdict {
    /// Cold-start is within budget.
    WithinBudget,
    /// Cold-start regresses beyond budget.
    Regression,
    /// Insufficient timing samples.
    InsufficientSamples,
}

impl ColdStartVerdict {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::WithinBudget)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WithinBudget => "within_budget",
            Self::Regression => "regression",
            Self::InsufficientSamples => "insufficient_samples",
        }
    }
}

impl fmt::Display for ColdStartVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// Overall gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// Index is approved for shipping.
    Approved,
    /// Index is denied due to parity or cold-start failure.
    Denied,
    /// Index was previously approved but has been rolled back.
    RolledBack,
    /// Evaluation is inconclusive (insufficient data).
    Inconclusive,
}

impl GateDecision {
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

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BlockingReason
// ---------------------------------------------------------------------------

/// Why the gate denied or rolled back a package cohort.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingReason {
    /// Index resolution does not match baseline for some specifiers.
    ParityMismatch {
        /// Number of mismatched specifiers.
        mismatch_count: u64,
        /// Total specifiers tested.
        total_tested: u64,
    },
    /// Cold-start latency exceeds budget.
    ColdStartRegression {
        /// Measured regression in millionths.
        regression_millionths: u64,
        /// Budget in millionths.
        budget_millionths: u64,
    },
    /// Too few specifiers to make a statistical determination.
    InsufficientCoverage {
        /// Number of specifiers sampled.
        sampled: u64,
        /// Minimum required.
        minimum_required: u64,
    },
    /// Maximum rollback count exceeded.
    RollbackLockout {
        /// Number of consecutive rollbacks.
        consecutive_rollbacks: u32,
    },
    /// Cooldown period has not elapsed since last rollback.
    CooldownActive {
        /// Remaining cooldown in nanoseconds.
        remaining_ns: u64,
    },
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParityMismatch {
                mismatch_count,
                total_tested,
            } => {
                write!(f, "parity_mismatch({mismatch_count}/{total_tested})")
            }
            Self::ColdStartRegression {
                regression_millionths,
                budget_millionths,
            } => {
                write!(
                    f,
                    "cold_start_regression({regression_millionths}>{budget_millionths})"
                )
            }
            Self::InsufficientCoverage {
                sampled,
                minimum_required,
            } => {
                write!(f, "insufficient_coverage({sampled}<{minimum_required})")
            }
            Self::RollbackLockout {
                consecutive_rollbacks,
            } => {
                write!(f, "rollback_lockout({consecutive_rollbacks})")
            }
            Self::CooldownActive { remaining_ns } => {
                write!(f, "cooldown_active({remaining_ns}ns)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SpecifierResult
// ---------------------------------------------------------------------------

/// Result of comparing indexed versus baseline resolution for one specifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecifierResult {
    /// The module specifier tested (e.g. "react", "lodash/chunk").
    pub specifier: String,
    /// Whether the indexed resolution matched the baseline.
    pub matches: bool,
    /// Baseline-resolved path (if resolved).
    pub baseline_path: Option<String>,
    /// Index-resolved path (if resolved).
    pub index_path: Option<String>,
}

impl SpecifierResult {
    /// Content hash for this result.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.specifier);
        buf.push(u8::from(self.matches));
        if let Some(ref p) = self.baseline_path {
            append_str(&mut buf, p);
        }
        if let Some(ref p) = self.index_path {
            append_str(&mut buf, p);
        }
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// ParityEvidence
// ---------------------------------------------------------------------------

/// Evidence for a parity evaluation across a package cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidence {
    /// Unique identifier for this evidence set.
    pub evidence_id: String,
    /// Package cohort name.
    pub cohort_name: String,
    /// Individual specifier results.
    pub results: Vec<SpecifierResult>,
    /// Number of matches.
    pub match_count: u64,
    /// Number of mismatches.
    pub mismatch_count: u64,
    /// Total specifiers tested.
    pub total_tested: u64,
    /// Parity ratio in millionths (match_count / total_tested * 1_000_000).
    pub parity_ratio_millionths: u64,
    /// Content hash sealing this evidence.
    pub content_hash: ContentHash,
}

impl ParityEvidence {
    /// Build evidence from specifier results.
    pub fn from_results(
        evidence_id: &str,
        cohort_name: &str,
        results: Vec<SpecifierResult>,
    ) -> Self {
        let match_count = results.iter().filter(|r| r.matches).count() as u64;
        let total_tested = results.len() as u64;
        let mismatch_count = total_tested.saturating_sub(match_count);
        let parity_ratio_millionths = if total_tested > 0 {
            match_count
                .saturating_mul(MILLIONTHS)
                .checked_div(total_tested)
                .unwrap_or(0)
        } else {
            0
        };

        let mut ev = Self {
            evidence_id: evidence_id.to_string(),
            cohort_name: cohort_name.to_string(),
            results,
            match_count,
            mismatch_count,
            total_tested,
            parity_ratio_millionths,
            content_hash: ContentHash::compute(b""),
        };
        ev.seal();
        ev
    }

    /// Recompute and set the content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.evidence_id);
        append_str(&mut buf, &self.cohort_name);
        append_u64(&mut buf, self.match_count);
        append_u64(&mut buf, self.mismatch_count);
        append_u64(&mut buf, self.total_tested);
        append_u64(&mut buf, self.parity_ratio_millionths);
        for r in &self.results {
            buf.extend_from_slice(r.content_hash().as_bytes());
        }
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// ColdStartEvidence
// ---------------------------------------------------------------------------

/// Evidence for cold-start timing evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartEvidence {
    /// Unique identifier for this evidence.
    pub evidence_id: String,
    /// Baseline cold-start latency in nanoseconds.
    pub baseline_latency_ns: u64,
    /// Indexed cold-start latency in nanoseconds.
    pub indexed_latency_ns: u64,
    /// Number of timing samples.
    pub sample_count: u64,
    /// Regression in millionths (positive = slower, 0 = faster or equal).
    pub regression_millionths: u64,
    /// Whether the indexed path is faster.
    pub is_speedup: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ColdStartEvidence {
    /// Build cold-start evidence from timing samples.
    pub fn new(
        evidence_id: &str,
        baseline_latency_ns: u64,
        indexed_latency_ns: u64,
        sample_count: u64,
    ) -> Self {
        let is_speedup = indexed_latency_ns <= baseline_latency_ns;
        let regression_millionths =
            if indexed_latency_ns > baseline_latency_ns && baseline_latency_ns > 0 {
                let diff = indexed_latency_ns.saturating_sub(baseline_latency_ns);
                diff.saturating_mul(MILLIONTHS)
                    .checked_div(baseline_latency_ns)
                    .unwrap_or(0)
            } else {
                0
            };

        let mut ev = Self {
            evidence_id: evidence_id.to_string(),
            baseline_latency_ns,
            indexed_latency_ns,
            sample_count,
            regression_millionths,
            is_speedup,
            content_hash: ContentHash::compute(b""),
        };
        ev.seal();
        ev
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.evidence_id);
        append_u64(&mut buf, self.baseline_latency_ns);
        append_u64(&mut buf, self.indexed_latency_ns);
        append_u64(&mut buf, self.sample_count);
        append_u64(&mut buf, self.regression_millionths);
        buf.push(u8::from(self.is_speedup));
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a rollback event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Unique identifier.
    pub record_id: String,
    /// Epoch at which rollback occurred.
    pub epoch: SecurityEpoch,
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
        reason: BlockingReason,
        timestamp_ns: u64,
    ) -> Self {
        let mut r = Self {
            record_id: record_id.to_string(),
            epoch,
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
        append_str(&mut buf, &format!("{}", self.reason));
        append_u64(&mut buf, self.timestamp_ns);
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Cohort name evaluated.
    pub cohort_name: String,
    /// Overall gate decision.
    pub decision: GateDecision,
    /// Parity verdict.
    pub parity_verdict: ParityVerdict,
    /// Cold-start verdict.
    pub cold_start_verdict: ColdStartVerdict,
    /// Blocking reasons (empty if approved).
    pub blocking_reasons: Vec<BlockingReason>,
    /// Parity evidence hash.
    pub parity_evidence_hash: ContentHash,
    /// Cold-start evidence hash.
    pub cold_start_evidence_hash: ContentHash,
    /// Affected packages.
    pub affected_packages: BTreeSet<String>,
    /// Content hash sealing the receipt.
    pub content_hash: ContentHash,
}

impl DecisionReceipt {
    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.receipt_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, &self.cohort_name);
        append_str(&mut buf, self.decision.as_str());
        append_str(&mut buf, self.parity_verdict.as_str());
        append_str(&mut buf, self.cold_start_verdict.as_str());
        for reason in &self.blocking_reasons {
            append_str(&mut buf, &format!("{reason}"));
        }
        buf.extend_from_slice(self.parity_evidence_hash.as_bytes());
        buf.extend_from_slice(self.cold_start_evidence_hash.as_bytes());
        for pkg in &self.affected_packages {
            append_str(&mut buf, pkg);
        }
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the module-index parity gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum parity ratio in millionths (default: 1_000_000 = 100%).
    pub parity_threshold_millionths: u64,
    /// Maximum cold-start regression in millionths (default: 50_000 = 5%).
    pub cold_start_budget_millionths: u64,
    /// Minimum specifier count for statistical validity.
    pub min_specifier_count: u64,
    /// Maximum consecutive rollbacks before permanent lockout.
    pub max_consecutive_rollbacks: u32,
    /// Cooldown between rollbacks in nanoseconds.
    pub rollback_cooldown_ns: u64,
    /// Whether to fail closed (deny) on insufficient data.
    pub fail_closed: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            parity_threshold_millionths: DEFAULT_PARITY_THRESHOLD_MILLIONTHS,
            cold_start_budget_millionths: DEFAULT_COLD_START_BUDGET_MILLIONTHS,
            min_specifier_count: DEFAULT_MIN_SPECIFIER_COUNT,
            max_consecutive_rollbacks: MAX_CONSECUTIVE_ROLLBACKS,
            rollback_cooldown_ns: DEFAULT_ROLLBACK_COOLDOWN_NS,
            fail_closed: true,
        }
    }
}

impl GateConfig {
    /// Build with custom parity threshold.
    pub fn with_parity_threshold(mut self, threshold: u64) -> Self {
        self.parity_threshold_millionths = threshold;
        self
    }

    /// Build with custom cold-start budget.
    pub fn with_cold_start_budget(mut self, budget: u64) -> Self {
        self.cold_start_budget_millionths = budget;
        self
    }

    /// Build with fail-open semantics.
    pub fn fail_open(mut self) -> Self {
        self.fail_closed = false;
        self
    }
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate — main evaluator
// ---------------------------------------------------------------------------

/// Gate evaluator for module-index parity governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIndexParityGate {
    /// Gate configuration.
    config: GateConfig,
    /// Current security epoch.
    epoch: SecurityEpoch,
    /// Number of evaluations performed.
    evaluation_count: u64,
    /// Number of approvals.
    approved_count: u64,
    /// Number of denials.
    denied_count: u64,
    /// Consecutive rollback count.
    consecutive_rollbacks: u32,
    /// Timestamp of last rollback (nanoseconds).
    last_rollback_ns: u64,
    /// Rollback history.
    rollback_history: Vec<RollbackRecord>,
    /// Most recent receipt.
    last_receipt: Option<DecisionReceipt>,
    /// Per-cohort parity scores (millionths).
    cohort_scores: BTreeMap<String, u64>,
}

impl ModuleIndexParityGate {
    /// Create a new gate with the given configuration and epoch.
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
            cohort_scores: BTreeMap::new(),
        }
    }

    /// Create a gate with default configuration.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GateConfig::default(), epoch)
    }

    /// Get the gate configuration.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> &SecurityEpoch {
        &self.epoch
    }

    /// Total evaluations performed.
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

    /// Get most recent decision receipt.
    pub fn last_receipt(&self) -> Option<&DecisionReceipt> {
        self.last_receipt.as_ref()
    }

    /// Get rollback history.
    pub fn rollback_history(&self) -> &[RollbackRecord] {
        &self.rollback_history
    }

    /// Get per-cohort parity scores.
    pub fn cohort_scores(&self) -> &BTreeMap<String, u64> {
        &self.cohort_scores
    }

    /// Check if rollback lockout is active.
    pub fn is_locked_out(&self) -> bool {
        self.consecutive_rollbacks >= self.config.max_consecutive_rollbacks
    }

    /// Check if cooldown is active at the given timestamp.
    pub fn is_cooldown_active(&self, current_ns: u64) -> bool {
        if self.last_rollback_ns == 0 {
            return false;
        }
        current_ns.saturating_sub(self.last_rollback_ns) < self.config.rollback_cooldown_ns
    }

    /// Evaluate parity evidence and produce a verdict.
    pub fn evaluate_parity(&self, evidence: &ParityEvidence) -> ParityVerdict {
        if evidence.total_tested < self.config.min_specifier_count {
            return ParityVerdict::InsufficientData;
        }
        if evidence.parity_ratio_millionths >= self.config.parity_threshold_millionths {
            ParityVerdict::FullParity
        } else if evidence.parity_ratio_millionths > 0 {
            ParityVerdict::PartialParity
        } else {
            ParityVerdict::NoParity
        }
    }

    /// Evaluate cold-start evidence and produce a verdict.
    pub fn evaluate_cold_start(&self, evidence: &ColdStartEvidence) -> ColdStartVerdict {
        if evidence.sample_count < self.config.min_specifier_count {
            return ColdStartVerdict::InsufficientSamples;
        }
        if evidence.regression_millionths <= self.config.cold_start_budget_millionths {
            ColdStartVerdict::WithinBudget
        } else {
            ColdStartVerdict::Regression
        }
    }

    /// Run the full gate evaluation for a package cohort.
    pub fn evaluate(
        &mut self,
        receipt_id: &str,
        parity_evidence: &ParityEvidence,
        cold_start_evidence: &ColdStartEvidence,
        current_ns: u64,
    ) -> GateDecision {
        self.evaluation_count += 1;

        let mut blocking_reasons = Vec::new();

        // Check rollback lockout
        if self.is_locked_out() {
            blocking_reasons.push(BlockingReason::RollbackLockout {
                consecutive_rollbacks: self.consecutive_rollbacks,
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

        // Evaluate parity
        let parity_verdict = self.evaluate_parity(parity_evidence);
        match parity_verdict {
            ParityVerdict::FullParity => {}
            ParityVerdict::PartialParity | ParityVerdict::NoParity => {
                blocking_reasons.push(BlockingReason::ParityMismatch {
                    mismatch_count: parity_evidence.mismatch_count,
                    total_tested: parity_evidence.total_tested,
                });
            }
            ParityVerdict::InsufficientData => {
                blocking_reasons.push(BlockingReason::InsufficientCoverage {
                    sampled: parity_evidence.total_tested,
                    minimum_required: self.config.min_specifier_count,
                });
            }
        }

        // Evaluate cold-start
        let cold_start_verdict = self.evaluate_cold_start(cold_start_evidence);
        match cold_start_verdict {
            ColdStartVerdict::WithinBudget => {}
            ColdStartVerdict::Regression => {
                blocking_reasons.push(BlockingReason::ColdStartRegression {
                    regression_millionths: cold_start_evidence.regression_millionths,
                    budget_millionths: self.config.cold_start_budget_millionths,
                });
            }
            ColdStartVerdict::InsufficientSamples => {
                if self.config.fail_closed {
                    blocking_reasons.push(BlockingReason::InsufficientCoverage {
                        sampled: cold_start_evidence.sample_count,
                        minimum_required: self.config.min_specifier_count,
                    });
                }
            }
        }

        // Determine decision
        let decision = if blocking_reasons.is_empty() {
            if parity_verdict == ParityVerdict::InsufficientData
                || cold_start_verdict == ColdStartVerdict::InsufficientSamples
            {
                if self.config.fail_closed {
                    GateDecision::Denied
                } else {
                    GateDecision::Inconclusive
                }
            } else {
                GateDecision::Approved
            }
        } else {
            GateDecision::Denied
        };

        // Update counters
        match decision {
            GateDecision::Approved => {
                self.approved_count += 1;
                self.consecutive_rollbacks = 0;
            }
            GateDecision::Denied | GateDecision::RolledBack => {
                self.denied_count += 1;
            }
            GateDecision::Inconclusive => {}
        }

        // Update cohort score
        self.cohort_scores.insert(
            parity_evidence.cohort_name.clone(),
            parity_evidence.parity_ratio_millionths,
        );

        // Build affected packages set
        let affected_packages: BTreeSet<String> = parity_evidence
            .results
            .iter()
            .filter(|r| !r.matches)
            .map(|r| r.specifier.clone())
            .collect();

        // Build receipt
        let mut receipt = DecisionReceipt {
            receipt_id: receipt_id.to_string(),
            epoch: self.epoch,
            cohort_name: parity_evidence.cohort_name.clone(),
            decision,
            parity_verdict,
            cold_start_verdict,
            blocking_reasons,
            parity_evidence_hash: parity_evidence.content_hash,
            cold_start_evidence_hash: cold_start_evidence.content_hash,
            affected_packages,
            content_hash: ContentHash::compute(b""),
        };
        receipt.seal();
        self.last_receipt = Some(receipt);

        decision
    }

    /// Trigger a rollback for a cohort.
    pub fn rollback(
        &mut self,
        record_id: &str,
        reason: BlockingReason,
        timestamp_ns: u64,
    ) -> &RollbackRecord {
        self.consecutive_rollbacks += 1;
        self.last_rollback_ns = timestamp_ns;

        let record = RollbackRecord::new(record_id, self.epoch, reason, timestamp_ns);
        self.rollback_history.push(record);
        self.rollback_history.last().unwrap()
    }

    /// Reset rollback counter (e.g. after a successful evaluation).
    pub fn reset_rollback_counter(&mut self) {
        self.consecutive_rollbacks = 0;
    }

    /// Get pass rate in millionths.
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

/// Summary statistics for the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evaluations.
    pub total_evaluations: u64,
    /// Approved evaluations.
    pub approved_count: u64,
    /// Denied evaluations.
    pub denied_count: u64,
    /// Total rollbacks.
    pub rollback_count: u64,
    /// Whether rollback lockout is active.
    pub is_locked_out: bool,
    /// Pass rate in millionths.
    pub pass_rate_millionths: u64,
}

// ---------------------------------------------------------------------------
// BatchResult
// ---------------------------------------------------------------------------

/// Result of evaluating a batch of cohorts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResult {
    /// Individual receipts.
    pub receipts: Vec<DecisionReceipt>,
    /// Whether all cohorts were approved.
    pub all_approved: bool,
    /// Summary.
    pub summary: GateSummary,
}

/// Evaluate a batch of cohort evidence.
pub fn evaluate_batch(
    gate: &mut ModuleIndexParityGate,
    cohorts: &[(String, ParityEvidence, ColdStartEvidence)],
    current_ns: u64,
) -> BatchResult {
    let mut receipts = Vec::new();
    let mut all_approved = true;

    for (i, (cohort_id, parity, cold_start)) in cohorts.iter().enumerate() {
        let receipt_id = format!("{cohort_id}-{i:04}");
        let decision = gate.evaluate(&receipt_id, parity, cold_start, current_ns);
        if !decision.is_approved() {
            all_approved = false;
        }
        if let Some(receipt) = gate.last_receipt().cloned() {
            receipts.push(receipt);
        }
    }

    BatchResult {
        receipts,
        all_approved,
        summary: gate.summary(),
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Produce a manifest for this module.
pub fn module_index_parity_gate_manifest() -> GateSummary {
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

    fn matching_result(spec: &str) -> SpecifierResult {
        SpecifierResult {
            specifier: spec.to_string(),
            matches: true,
            baseline_path: Some(format!("/node_modules/{spec}/index.js")),
            index_path: Some(format!("/node_modules/{spec}/index.js")),
        }
    }

    fn mismatching_result(spec: &str) -> SpecifierResult {
        SpecifierResult {
            specifier: spec.to_string(),
            matches: false,
            baseline_path: Some(format!("/node_modules/{spec}/index.js")),
            index_path: Some(format!("/node_modules/{spec}/main.js")),
        }
    }

    fn full_parity_evidence(n: u64) -> ParityEvidence {
        let results: Vec<_> = (0..n)
            .map(|i| matching_result(&format!("pkg-{i:04}")))
            .collect();
        ParityEvidence::from_results("ev-parity", "test-cohort", results)
    }

    fn partial_parity_evidence(total: u64, mismatches: u64) -> ParityEvidence {
        let mut results: Vec<_> = (0..total.saturating_sub(mismatches))
            .map(|i| matching_result(&format!("pkg-{i:04}")))
            .collect();
        for i in 0..mismatches {
            results.push(mismatching_result(&format!("bad-{i:04}")));
        }
        ParityEvidence::from_results("ev-parity", "test-cohort", results)
    }

    fn good_cold_start() -> ColdStartEvidence {
        ColdStartEvidence::new("ev-cold", 1_000_000, 950_000, 200)
    }

    fn regressing_cold_start() -> ColdStartEvidence {
        ColdStartEvidence::new("ev-cold", 1_000_000, 1_200_000, 200)
    }

    fn insufficient_cold_start() -> ColdStartEvidence {
        ColdStartEvidence::new("ev-cold", 1_000_000, 950_000, 5)
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("module-index-parity-gate"));
    }

    #[test]
    fn test_bead_id() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "module_index_parity_gate");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-406C");
    }

    #[test]
    fn test_millionths() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // ParityVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_verdict_shippable() {
        assert!(ParityVerdict::FullParity.is_shippable());
        assert!(!ParityVerdict::PartialParity.is_shippable());
        assert!(!ParityVerdict::NoParity.is_shippable());
        assert!(!ParityVerdict::InsufficientData.is_shippable());
    }

    #[test]
    fn test_parity_verdict_display() {
        assert_eq!(format!("{}", ParityVerdict::FullParity), "full_parity");
        assert_eq!(format!("{}", ParityVerdict::NoParity), "no_parity");
    }

    #[test]
    fn test_parity_verdict_serde_roundtrip() {
        let v = ParityVerdict::PartialParity;
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -----------------------------------------------------------------------
    // ColdStartVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_cold_start_verdict_acceptable() {
        assert!(ColdStartVerdict::WithinBudget.is_acceptable());
        assert!(!ColdStartVerdict::Regression.is_acceptable());
        assert!(!ColdStartVerdict::InsufficientSamples.is_acceptable());
    }

    #[test]
    fn test_cold_start_verdict_display() {
        assert_eq!(
            format!("{}", ColdStartVerdict::WithinBudget),
            "within_budget"
        );
    }

    // -----------------------------------------------------------------------
    // GateDecision
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_decision_approved() {
        assert!(GateDecision::Approved.is_approved());
        assert!(!GateDecision::Denied.is_approved());
        assert!(!GateDecision::RolledBack.is_approved());
        assert!(!GateDecision::Inconclusive.is_approved());
    }

    #[test]
    fn test_gate_decision_display() {
        assert_eq!(format!("{}", GateDecision::Denied), "denied");
    }

    // -----------------------------------------------------------------------
    // BlockingReason
    // -----------------------------------------------------------------------

    #[test]
    fn test_blocking_reason_display_parity() {
        let r = BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        };
        assert!(format!("{r}").contains("5/100"));
    }

    #[test]
    fn test_blocking_reason_display_cold_start() {
        let r = BlockingReason::ColdStartRegression {
            regression_millionths: 100_000,
            budget_millionths: 50_000,
        };
        assert!(format!("{r}").contains("100000>50000"));
    }

    #[test]
    fn test_blocking_reason_display_lockout() {
        let r = BlockingReason::RollbackLockout {
            consecutive_rollbacks: 3,
        };
        assert!(format!("{r}").contains("3"));
    }

    #[test]
    fn test_blocking_reason_serde_roundtrip() {
        let r = BlockingReason::CooldownActive { remaining_ns: 5000 };
        let json = serde_json::to_string(&r).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -----------------------------------------------------------------------
    // SpecifierResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_specifier_result_content_hash_deterministic() {
        let a = matching_result("react");
        let b = matching_result("react");
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn test_specifier_result_different_paths_different_hash() {
        let a = matching_result("react");
        let b = mismatching_result("react");
        assert_ne!(a.content_hash(), b.content_hash());
    }

    // -----------------------------------------------------------------------
    // ParityEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_evidence_full_match() {
        let ev = full_parity_evidence(200);
        assert_eq!(ev.match_count, 200);
        assert_eq!(ev.mismatch_count, 0);
        assert_eq!(ev.parity_ratio_millionths, MILLIONTHS);
    }

    #[test]
    fn test_parity_evidence_partial_match() {
        let ev = partial_parity_evidence(200, 10);
        assert_eq!(ev.match_count, 190);
        assert_eq!(ev.mismatch_count, 10);
        assert!(ev.parity_ratio_millionths < MILLIONTHS);
        assert!(ev.parity_ratio_millionths > 0);
    }

    #[test]
    fn test_parity_evidence_empty() {
        let ev = ParityEvidence::from_results("ev", "empty", vec![]);
        assert_eq!(ev.total_tested, 0);
        assert_eq!(ev.parity_ratio_millionths, 0);
    }

    #[test]
    fn test_parity_evidence_seal_deterministic() {
        let a = full_parity_evidence(200);
        let b = full_parity_evidence(200);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // ColdStartEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn test_cold_start_speedup() {
        let ev = ColdStartEvidence::new("ev", 1_000_000, 800_000, 100);
        assert!(ev.is_speedup);
        assert_eq!(ev.regression_millionths, 0);
    }

    #[test]
    fn test_cold_start_regression() {
        let ev = ColdStartEvidence::new("ev", 1_000_000, 1_200_000, 100);
        assert!(!ev.is_speedup);
        assert_eq!(ev.regression_millionths, 200_000);
    }

    #[test]
    fn test_cold_start_equal() {
        let ev = ColdStartEvidence::new("ev", 1_000_000, 1_000_000, 100);
        assert!(ev.is_speedup);
        assert_eq!(ev.regression_millionths, 0);
    }

    #[test]
    fn test_cold_start_seal_deterministic() {
        let a = good_cold_start();
        let b = good_cold_start();
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
            BlockingReason::ParityMismatch {
                mismatch_count: 5,
                total_tested: 100,
            },
            1_000_000_000,
        );
        assert!(!r.record_id.is_empty());
        // Hash should be non-trivial
        assert_ne!(r.content_hash, ContentHash::compute(b""));
    }

    // -----------------------------------------------------------------------
    // GateConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_config_default() {
        let c = GateConfig::default();
        assert_eq!(c.parity_threshold_millionths, MILLIONTHS);
        assert_eq!(c.cold_start_budget_millionths, 50_000);
        assert_eq!(c.min_specifier_count, 100);
        assert!(c.fail_closed);
    }

    #[test]
    fn test_gate_config_builders() {
        let c = GateConfig::default()
            .with_parity_threshold(900_000)
            .with_cold_start_budget(100_000)
            .fail_open();
        assert_eq!(c.parity_threshold_millionths, 900_000);
        assert_eq!(c.cold_start_budget_millionths, 100_000);
        assert!(!c.fail_closed);
    }

    #[test]
    fn test_gate_config_serde_roundtrip() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -----------------------------------------------------------------------
    // ModuleIndexParityGate — basic construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_new() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        assert_eq!(g.evaluation_count(), 0);
        assert_eq!(g.approved_count(), 0);
        assert_eq!(g.denied_count(), 0);
        assert!(!g.is_locked_out());
    }

    #[test]
    fn test_gate_epoch() {
        let g = ModuleIndexParityGate::with_defaults(SecurityEpoch::from_raw(42));
        assert_eq!(g.epoch().as_u64(), 42);
    }

    // -----------------------------------------------------------------------
    // ModuleIndexParityGate — evaluate_parity
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_parity_full() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = full_parity_evidence(200);
        assert_eq!(g.evaluate_parity(&ev), ParityVerdict::FullParity);
    }

    #[test]
    fn test_evaluate_parity_partial() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = partial_parity_evidence(200, 10);
        assert_eq!(g.evaluate_parity(&ev), ParityVerdict::PartialParity);
    }

    #[test]
    fn test_evaluate_parity_insufficient() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = full_parity_evidence(10); // below min_specifier_count=100
        assert_eq!(g.evaluate_parity(&ev), ParityVerdict::InsufficientData);
    }

    // -----------------------------------------------------------------------
    // ModuleIndexParityGate — evaluate_cold_start
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_cold_start_within_budget() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = good_cold_start();
        assert_eq!(g.evaluate_cold_start(&ev), ColdStartVerdict::WithinBudget);
    }

    #[test]
    fn test_evaluate_cold_start_regression() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = regressing_cold_start();
        assert_eq!(g.evaluate_cold_start(&ev), ColdStartVerdict::Regression);
    }

    #[test]
    fn test_evaluate_cold_start_insufficient() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        let ev = insufficient_cold_start();
        assert_eq!(
            g.evaluate_cold_start(&ev),
            ColdStartVerdict::InsufficientSamples
        );
    }

    // -----------------------------------------------------------------------
    // ModuleIndexParityGate — full evaluate
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_approve() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        let d = g.evaluate("r-001", &parity, &cold, 100_000_000);
        assert_eq!(d, GateDecision::Approved);
        assert_eq!(g.approved_count(), 1);
    }

    #[test]
    fn test_evaluate_deny_parity_mismatch() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = partial_parity_evidence(200, 10);
        let cold = good_cold_start();
        let d = g.evaluate("r-002", &parity, &cold, 100_000_000);
        assert_eq!(d, GateDecision::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ParityMismatch { .. }))
        );
    }

    #[test]
    fn test_evaluate_deny_cold_start_regression() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = regressing_cold_start();
        let d = g.evaluate("r-003", &parity, &cold, 100_000_000);
        assert_eq!(d, GateDecision::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ColdStartRegression { .. }))
        );
    }

    #[test]
    fn test_evaluate_deny_insufficient_fail_closed() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(10);
        let cold = good_cold_start();
        let d = g.evaluate("r-004", &parity, &cold, 100_000_000);
        assert_eq!(d, GateDecision::Denied);
    }

    #[test]
    fn test_evaluate_insufficient_fail_open() {
        let config = GateConfig::default().fail_open();
        let mut g = ModuleIndexParityGate::new(config, epoch());
        let parity = full_parity_evidence(200);
        let cold = insufficient_cold_start();
        let d = g.evaluate("r-005", &parity, &cold, 100_000_000);
        // With fail-open and full parity, insufficient cold-start samples
        // should not block
        assert_eq!(d, GateDecision::Approved);
    }

    // -----------------------------------------------------------------------
    // Rollback
    // -----------------------------------------------------------------------

    #[test]
    fn test_rollback_increments_counter() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            BlockingReason::ParityMismatch {
                mismatch_count: 5,
                total_tested: 100,
            },
            1_000_000_000,
        );
        assert_eq!(g.consecutive_rollbacks, 1);
        assert_eq!(g.rollback_history().len(), 1);
    }

    #[test]
    fn test_rollback_lockout() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
            g.rollback(
                &format!("rb-{i:03}"),
                BlockingReason::ParityMismatch {
                    mismatch_count: 1,
                    total_tested: 100,
                },
                (i as u64 + 1) * 1_000_000_000,
            );
        }
        assert!(g.is_locked_out());
    }

    #[test]
    fn test_rollback_lockout_blocks_evaluation() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
            g.rollback(
                &format!("rb-{i:03}"),
                BlockingReason::ParityMismatch {
                    mismatch_count: 1,
                    total_tested: 100,
                },
                (i as u64 + 1) * 1_000_000_000,
            );
        }
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        let ts = (MAX_CONSECUTIVE_ROLLBACKS as u64 + 100) * 1_000_000_000;
        let d = g.evaluate("r-lockout", &parity, &cold, ts);
        assert_eq!(d, GateDecision::Denied);
        let receipt = g.last_receipt().unwrap();
        assert!(
            receipt
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::RollbackLockout { .. }))
        );
    }

    #[test]
    fn test_cooldown_active() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            BlockingReason::ParityMismatch {
                mismatch_count: 1,
                total_tested: 100,
            },
            1_000_000_000,
        );
        assert!(g.is_cooldown_active(1_000_000_001));
        assert!(!g.is_cooldown_active(1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1));
    }

    #[test]
    fn test_reset_rollback_counter() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        g.rollback(
            "rb-001",
            BlockingReason::ParityMismatch {
                mismatch_count: 1,
                total_tested: 100,
            },
            1_000_000_000,
        );
        assert_eq!(g.consecutive_rollbacks, 1);
        g.reset_rollback_counter();
        assert_eq!(g.consecutive_rollbacks, 0);
    }

    // -----------------------------------------------------------------------
    // Counters and summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_pass_rate_empty() {
        let g = ModuleIndexParityGate::with_defaults(epoch());
        assert_eq!(g.pass_rate_millionths(), 0);
    }

    #[test]
    fn test_pass_rate_all_approved() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        g.evaluate("r-002", &parity, &cold, 200_000_000);
        assert_eq!(g.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_pass_rate_half() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let good_parity = full_parity_evidence(200);
        let bad_parity = partial_parity_evidence(200, 10);
        let cold = good_cold_start();
        g.evaluate("r-001", &good_parity, &cold, 100_000_000);
        g.evaluate("r-002", &bad_parity, &cold, 200_000_000);
        assert_eq!(g.pass_rate_millionths(), 500_000);
    }

    #[test]
    fn test_summary() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        let s = g.summary();
        assert_eq!(s.total_evaluations, 1);
        assert_eq!(s.approved_count, 1);
        assert!(!s.is_locked_out);
    }

    // -----------------------------------------------------------------------
    // Cohort scores
    // -----------------------------------------------------------------------

    #[test]
    fn test_cohort_scores_updated() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        assert_eq!(g.cohort_scores().get("test-cohort"), Some(&MILLIONTHS));
    }

    // -----------------------------------------------------------------------
    // DecisionReceipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_present_after_evaluate() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        assert!(g.last_receipt().is_none());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        assert!(g.last_receipt().is_some());
    }

    #[test]
    fn test_receipt_approved_has_no_blocking_reasons() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        let receipt = g.last_receipt().unwrap();
        assert!(receipt.blocking_reasons.is_empty());
        assert_eq!(receipt.decision, GateDecision::Approved);
    }

    #[test]
    fn test_receipt_denied_has_blocking_reasons() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = partial_parity_evidence(200, 10);
        let cold = good_cold_start();
        g.evaluate("r-002", &parity, &cold, 100_000_000);
        let receipt = g.last_receipt().unwrap();
        assert!(!receipt.blocking_reasons.is_empty());
        assert_eq!(receipt.decision, GateDecision::Denied);
    }

    #[test]
    fn test_receipt_affected_packages() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = partial_parity_evidence(200, 5);
        let cold = good_cold_start();
        g.evaluate("r-003", &parity, &cold, 100_000_000);
        let receipt = g.last_receipt().unwrap();
        assert_eq!(receipt.affected_packages.len(), 5);
    }

    #[test]
    fn test_receipt_content_hash_deterministic() {
        let mut g1 = ModuleIndexParityGate::with_defaults(epoch());
        let mut g2 = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g1.evaluate("r-001", &parity, &cold, 100_000_000);
        g2.evaluate("r-001", &parity, &cold, 100_000_000);
        assert_eq!(
            g1.last_receipt().unwrap().content_hash,
            g2.last_receipt().unwrap().content_hash,
        );
    }

    // -----------------------------------------------------------------------
    // Batch evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_all_approved() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let cohorts: Vec<_> = (0..3)
            .map(|i| {
                (
                    format!("cohort-{i}"),
                    full_parity_evidence(200),
                    good_cold_start(),
                )
            })
            .collect();
        let result = evaluate_batch(&mut g, &cohorts, 100_000_000);
        assert!(result.all_approved);
        assert_eq!(result.receipts.len(), 3);
    }

    #[test]
    fn test_batch_partial_denial() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let cohorts = vec![
            (
                "cohort-ok".to_string(),
                full_parity_evidence(200),
                good_cold_start(),
            ),
            (
                "cohort-bad".to_string(),
                partial_parity_evidence(200, 10),
                good_cold_start(),
            ),
        ];
        let result = evaluate_batch(&mut g, &cohorts, 100_000_000);
        assert!(!result.all_approved);
        assert_eq!(result.summary.approved_count, 1);
        assert_eq!(result.summary.denied_count, 1);
    }

    // -----------------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest() {
        let m = module_index_parity_gate_manifest();
        assert_eq!(m.total_evaluations, 0);
        assert!(!m.is_locked_out);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_serde_roundtrip() {
        let mut g = ModuleIndexParityGate::with_defaults(epoch());
        let parity = full_parity_evidence(200);
        let cold = good_cold_start();
        g.evaluate("r-001", &parity, &cold, 100_000_000);
        let json = serde_json::to_string(&g).unwrap();
        let back: ModuleIndexParityGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evaluation_count(), 1);
    }

    #[test]
    fn test_parity_evidence_serde_roundtrip() {
        let ev = full_parity_evidence(200);
        let json = serde_json::to_string(&ev).unwrap();
        let back: ParityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.content_hash, back.content_hash);
    }

    #[test]
    fn test_cold_start_evidence_serde_roundtrip() {
        let ev = good_cold_start();
        let json = serde_json::to_string(&ev).unwrap();
        let back: ColdStartEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.content_hash, back.content_hash);
    }

    #[test]
    fn test_rollback_record_serde_roundtrip() {
        let r = RollbackRecord::new(
            "rb-001",
            epoch(),
            BlockingReason::ParityMismatch {
                mismatch_count: 5,
                total_tested: 100,
            },
            1_000_000_000,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: RollbackRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r.record_id, back.record_id);
    }
}
