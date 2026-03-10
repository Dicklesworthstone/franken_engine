//! Bead: bd-1lsy.7.22.3 [RGC-622C]
//!
//! Allocation-elision governance gate: GC impact, tail-latency, rollback,
//! support-surface, and observability evidence for shipped lanes.
//!
//! Gates allocation elimination on user-visible metrics (GC pause time,
//! tail latency, rollback safety, support-surface coverage, observability
//! health) so lanes win on the metrics that matter rather than only on
//! local throughput microbenches.
//!
//! Key behaviours:
//! - Elision verdicts (approve / deny / conditional) backed by evidence.
//! - GC impact assessment: tracks how elision affects pause times and pressure.
//! - Tail-latency evidence: ensures elision does not worsen p99/p999 latency.
//! - Rollback governance: reverts elision when regressions are detected.
//! - Support-surface tracking: maintains contracts for elision-optimised paths.
//! - Deopt witness integration: handles deoptimisation when assumptions break.
//! - Observability: emits diagnostics about elision health and savings.
//! - Decision receipts for every governance verdict.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for allocation-elision gate artifacts.
pub const ELISION_GATE_SCHEMA_VERSION: &str = "franken-engine.allocation-elision-gate.v1";

/// Bead originating this module.
pub const ELISION_GATE_BEAD_ID: &str = "bd-1lsy.7.22.3";

/// Component name for structured logging.
pub const ELISION_GATE_COMPONENT: &str = "allocation_elision_gate";

/// Fixed-point constant: 1.0 in millionths.
const MILLION: u64 = 1_000_000;

/// Default maximum allowed GC pause regression (millionths).
/// 50_000 = 5% — elision must not increase GC pauses by more than 5%.
pub const DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS: u64 = 50_000;

/// Default maximum allowed tail-latency regression (millionths).
/// 30_000 = 3%.
pub const DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS: u64 = 30_000;

/// Default minimum support-surface coverage (millionths).
/// 950_000 = 95%.
pub const DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS: u64 = 950_000;

/// Default minimum sample count for statistical validity.
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;

/// Default rollback cooldown in nanoseconds (5 seconds).
pub const DEFAULT_ROLLBACK_COOLDOWN_NS: u64 = 5_000_000_000;

/// Maximum number of consecutive rollbacks before permanent denial.
pub const MAX_CONSECUTIVE_ROLLBACKS: u32 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn append_length_prefixed_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_be_bytes());
    buf.extend_from_slice(data);
}

fn append_length_prefixed_str(buf: &mut Vec<u8>, value: &str) {
    append_length_prefixed_bytes(buf, value.as_bytes());
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// ElisionVerdict — the core decision
// ---------------------------------------------------------------------------

/// Outcome of evaluating whether an allocation may be elided.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElisionVerdict {
    /// Allocation elision is approved unconditionally.
    Approved,
    /// Approved with conditions that must remain true at runtime.
    Conditional,
    /// Elision denied — allocation must remain heap-allocated.
    Denied,
    /// Elision was previously approved but has been rolled back.
    RolledBack,
}

impl ElisionVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Conditional => "conditional",
            Self::Denied => "denied",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn is_elision_allowed(&self) -> bool {
        matches!(self, Self::Approved | Self::Conditional)
    }
}

impl fmt::Display for ElisionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DenialReason — why elision was denied
// ---------------------------------------------------------------------------

/// Reason an allocation elision was denied or rolled back.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// GC pause times regressed beyond threshold.
    GcPauseRegression,
    /// Tail latency (p99/p999) regressed beyond threshold.
    TailLatencyRegression,
    /// Support-surface coverage insufficient.
    InsufficientSupportCoverage,
    /// Deoptimisation triggered by broken assumptions.
    DeoptWitnessTriggered,
    /// Rollback limit exceeded — too many consecutive rollbacks.
    RollbackLimitExceeded,
    /// Insufficient sample count for statistical validity.
    InsufficientSamples,
    /// Escape analysis certificate missing or invalid.
    MissingEscapeCertificate,
    /// Observability health check failed.
    ObservabilityUnhealthy,
    /// Operator-initiated denial.
    OperatorDenied,
    /// Epoch mismatch — evidence from wrong security epoch.
    EpochMismatch,
}

impl DenialReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GcPauseRegression => "gc_pause_regression",
            Self::TailLatencyRegression => "tail_latency_regression",
            Self::InsufficientSupportCoverage => "insufficient_support_coverage",
            Self::DeoptWitnessTriggered => "deopt_witness_triggered",
            Self::RollbackLimitExceeded => "rollback_limit_exceeded",
            Self::InsufficientSamples => "insufficient_samples",
            Self::MissingEscapeCertificate => "missing_escape_certificate",
            Self::ObservabilityUnhealthy => "observability_unhealthy",
            Self::OperatorDenied => "operator_denied",
            Self::EpochMismatch => "epoch_mismatch",
        }
    }
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AllocationSiteId
// ---------------------------------------------------------------------------

/// Identifies an allocation site within the compiled program.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AllocationSiteId(pub String);

impl AllocationSiteId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AllocationSiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// LaneId
// ---------------------------------------------------------------------------

/// Identifies an execution lane where elision is being evaluated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LaneId(pub String);

impl LaneId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// GcImpactAssessment
// ---------------------------------------------------------------------------

/// Captures the GC impact of eliding a set of allocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcImpactAssessment {
    /// Baseline GC pause time (p50) in nanoseconds before elision.
    pub baseline_pause_p50_ns: u64,
    /// Baseline GC pause time (p99) in nanoseconds before elision.
    pub baseline_pause_p99_ns: u64,
    /// Post-elision GC pause time (p50) in nanoseconds.
    pub elided_pause_p50_ns: u64,
    /// Post-elision GC pause time (p99) in nanoseconds.
    pub elided_pause_p99_ns: u64,
    /// Baseline GC pressure: allocations per collection cycle.
    pub baseline_allocs_per_cycle: u64,
    /// Post-elision allocations per cycle.
    pub elided_allocs_per_cycle: u64,
    /// Baseline total bytes collected per cycle.
    pub baseline_bytes_per_cycle: u64,
    /// Post-elision bytes per cycle.
    pub elided_bytes_per_cycle: u64,
    /// Number of measurement samples.
    pub sample_count: u64,
    /// Computed regression ratio (millionths). >1_000_000 means regression.
    pub pause_regression_millionths: u64,
}

impl GcImpactAssessment {
    /// Compute the pause regression ratio from the raw data.
    pub fn compute_pause_regression(&self) -> u64 {
        if self.baseline_pause_p99_ns == 0 {
            return 0;
        }
        self.elided_pause_p99_ns
            .saturating_mul(MILLION)
            .checked_div(self.baseline_pause_p99_ns)
            .unwrap_or(0)
    }

    /// Whether GC pause times regressed beyond the given threshold.
    pub fn is_regressed(&self, max_regression_millionths: u64) -> bool {
        let regression = self.compute_pause_regression();
        regression > MILLION.saturating_add(max_regression_millionths)
    }

    /// Net bytes saved per cycle by elision.
    pub fn bytes_saved_per_cycle(&self) -> u64 {
        self.baseline_bytes_per_cycle
            .saturating_sub(self.elided_bytes_per_cycle)
    }

    /// Compute a content hash for this assessment.
    pub fn digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&self.baseline_pause_p50_ns.to_be_bytes());
        buf.extend_from_slice(&self.baseline_pause_p99_ns.to_be_bytes());
        buf.extend_from_slice(&self.elided_pause_p50_ns.to_be_bytes());
        buf.extend_from_slice(&self.elided_pause_p99_ns.to_be_bytes());
        buf.extend_from_slice(&self.baseline_allocs_per_cycle.to_be_bytes());
        buf.extend_from_slice(&self.elided_allocs_per_cycle.to_be_bytes());
        buf.extend_from_slice(&self.sample_count.to_be_bytes());
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// TailLatencyEvidence
// ---------------------------------------------------------------------------

/// Evidence about tail-latency impact of allocation elision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyEvidence {
    /// Baseline p99 latency in nanoseconds.
    pub baseline_p99_ns: u64,
    /// Baseline p999 latency in nanoseconds.
    pub baseline_p999_ns: u64,
    /// Post-elision p99 latency in nanoseconds.
    pub elided_p99_ns: u64,
    /// Post-elision p999 latency in nanoseconds.
    pub elided_p999_ns: u64,
    /// Baseline median latency in nanoseconds.
    pub baseline_p50_ns: u64,
    /// Post-elision median latency in nanoseconds.
    pub elided_p50_ns: u64,
    /// Number of measurement samples.
    pub sample_count: u64,
    /// Workload identifier these measurements were taken from.
    pub workload_id: String,
}

impl TailLatencyEvidence {
    /// Compute the p99 regression ratio in millionths.
    pub fn p99_regression_millionths(&self) -> u64 {
        if self.baseline_p99_ns == 0 {
            return 0;
        }
        self.elided_p99_ns
            .saturating_mul(MILLION)
            .checked_div(self.baseline_p99_ns)
            .unwrap_or(0)
    }

    /// Compute the p999 regression ratio in millionths.
    pub fn p999_regression_millionths(&self) -> u64 {
        if self.baseline_p999_ns == 0 {
            return 0;
        }
        self.elided_p999_ns
            .saturating_mul(MILLION)
            .checked_div(self.baseline_p999_ns)
            .unwrap_or(0)
    }

    /// Whether tail latency regressed beyond threshold.
    pub fn is_regressed(&self, max_regression_millionths: u64) -> bool {
        let p99_reg = self.p99_regression_millionths();
        let p999_reg = self.p999_regression_millionths();
        let limit = MILLION.saturating_add(max_regression_millionths);
        p99_reg > limit || p999_reg > limit
    }

    /// Latency improvement at p50 in nanoseconds (positive = better).
    pub fn p50_improvement_ns(&self) -> i64 {
        self.baseline_p50_ns as i64 - self.elided_p50_ns as i64
    }

    /// Content hash for this evidence.
    pub fn digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.baseline_p99_ns.to_be_bytes());
        buf.extend_from_slice(&self.baseline_p999_ns.to_be_bytes());
        buf.extend_from_slice(&self.elided_p99_ns.to_be_bytes());
        buf.extend_from_slice(&self.elided_p999_ns.to_be_bytes());
        buf.extend_from_slice(&self.sample_count.to_be_bytes());
        append_length_prefixed_str(&mut buf, &self.workload_id);
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

/// What triggered a rollback of a previously approved elision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTrigger {
    /// GC pause regression detected post-deployment.
    GcRegression,
    /// Tail latency regression detected.
    LatencyRegression,
    /// Deoptimisation event fired.
    DeoptEvent,
    /// Support-surface contract violation.
    SupportViolation,
    /// Observability anomaly detected.
    ObservabilityAnomaly,
    /// Operator-initiated rollback.
    OperatorInitiated,
}

impl RollbackTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GcRegression => "gc_regression",
            Self::LatencyRegression => "latency_regression",
            Self::DeoptEvent => "deopt_event",
            Self::SupportViolation => "support_violation",
            Self::ObservabilityAnomaly => "observability_anomaly",
            Self::OperatorInitiated => "operator_initiated",
        }
    }
}

impl fmt::Display for RollbackTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a rollback event for a specific allocation site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Which site was rolled back.
    pub site_id: AllocationSiteId,
    /// Lane where rollback occurred.
    pub lane_id: LaneId,
    /// What triggered the rollback.
    pub trigger: RollbackTrigger,
    /// Monotonic timestamp (nanoseconds) when rollback was initiated.
    pub timestamp_ns: u64,
    /// Epoch at rollback time.
    pub epoch: SecurityEpoch,
    /// Consecutive rollback count for this site.
    pub consecutive_count: u32,
    /// Digest of the evidence that prompted rollback.
    pub evidence_digest: ContentHash,
}

impl RollbackRecord {
    /// Whether this rollback exceeds the maximum consecutive limit.
    pub fn exceeds_limit(&self) -> bool {
        self.consecutive_count >= MAX_CONSECUTIVE_ROLLBACKS
    }

    /// Compute content hash.
    pub fn digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        append_length_prefixed_str(&mut buf, self.site_id.as_str());
        append_length_prefixed_str(&mut buf, self.lane_id.as_str());
        append_length_prefixed_str(&mut buf, self.trigger.as_str());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.consecutive_count.to_be_bytes());
        buf.extend_from_slice(self.evidence_digest.as_bytes());
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// SupportSurfaceContract
// ---------------------------------------------------------------------------

/// Defines the support contract for an elision-optimised code path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportSurfaceContract {
    /// Unique contract identifier.
    pub contract_id: String,
    /// Which allocation sites are covered.
    pub covered_sites: BTreeSet<String>,
    /// Minimum test coverage (millionths). 1_000_000 = 100%.
    pub min_coverage_millionths: u64,
    /// Actual measured coverage (millionths).
    pub actual_coverage_millionths: u64,
    /// Whether a fallback path exists for every elided site.
    pub fallback_paths_verified: bool,
    /// Epoch when this contract was last validated.
    pub validated_epoch: SecurityEpoch,
    /// Human-readable notes.
    pub notes: String,
}

impl SupportSurfaceContract {
    /// Whether the contract meets its coverage requirement.
    pub fn meets_coverage(&self) -> bool {
        self.actual_coverage_millionths >= self.min_coverage_millionths
    }

    /// Whether the contract is fully satisfied.
    pub fn is_satisfied(&self) -> bool {
        self.meets_coverage() && self.fallback_paths_verified
    }

    /// Coverage deficit in millionths (0 if met).
    pub fn coverage_deficit_millionths(&self) -> u64 {
        self.min_coverage_millionths
            .saturating_sub(self.actual_coverage_millionths)
    }

    /// Content hash.
    pub fn digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        append_length_prefixed_str(&mut buf, &self.contract_id);
        buf.extend_from_slice(&self.min_coverage_millionths.to_be_bytes());
        buf.extend_from_slice(&self.actual_coverage_millionths.to_be_bytes());
        buf.push(if self.fallback_paths_verified { 1 } else { 0 });
        buf.extend_from_slice(&self.validated_epoch.as_u64().to_be_bytes());
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// DeoptWitness
// ---------------------------------------------------------------------------

/// Witness recording that a deoptimisation was triggered because an
/// elision assumption was violated at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeoptWitness {
    /// Which allocation site assumption was violated.
    pub site_id: AllocationSiteId,
    /// Lane where deopt occurred.
    pub lane_id: LaneId,
    /// Kind of assumption that broke.
    pub assumption_kind: AssumptionKind,
    /// Monotonic timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Epoch at the time of deopt.
    pub epoch: SecurityEpoch,
    /// Stack depth at deopt point.
    pub stack_depth: u32,
    /// Number of times this deopt has fired for this site.
    pub occurrence_count: u64,
    /// Digest of the original elision approval receipt.
    pub approval_receipt_digest: ContentHash,
}

impl DeoptWitness {
    /// Content hash.
    pub fn digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(96);
        append_length_prefixed_str(&mut buf, self.site_id.as_str());
        append_length_prefixed_str(&mut buf, self.lane_id.as_str());
        append_length_prefixed_str(&mut buf, self.assumption_kind.as_str());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.stack_depth.to_be_bytes());
        buf.extend_from_slice(&self.occurrence_count.to_be_bytes());
        buf.extend_from_slice(self.approval_receipt_digest.as_bytes());
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// AssumptionKind
// ---------------------------------------------------------------------------

/// Kind of runtime assumption that an elision decision depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionKind {
    /// Object does not escape the allocating function.
    NoEscape,
    /// Object is only used as argument (arg-escape).
    ArgEscapeOnly,
    /// No aliasing through external references.
    NoAlias,
    /// Object shape (hidden class) remains stable.
    StableShape,
    /// No dynamic property access (computed keys).
    NoDynamicAccess,
    /// No prototype chain mutation.
    StablePrototype,
    /// Liveness range is bounded and known.
    BoundedLiveness,
    /// No cross-module reference leak.
    NoModuleLeak,
}

impl AssumptionKind {
    pub const ALL: &'static [Self] = &[
        Self::NoEscape,
        Self::ArgEscapeOnly,
        Self::NoAlias,
        Self::StableShape,
        Self::NoDynamicAccess,
        Self::StablePrototype,
        Self::BoundedLiveness,
        Self::NoModuleLeak,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEscape => "no_escape",
            Self::ArgEscapeOnly => "arg_escape_only",
            Self::NoAlias => "no_alias",
            Self::StableShape => "stable_shape",
            Self::NoDynamicAccess => "no_dynamic_access",
            Self::StablePrototype => "stable_prototype",
            Self::BoundedLiveness => "bounded_liveness",
            Self::NoModuleLeak => "no_module_leak",
        }
    }
}

impl fmt::Display for AssumptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ObservabilityHealth
// ---------------------------------------------------------------------------

/// Health status of elision observability for a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityHealth {
    /// Whether GC telemetry is being emitted.
    pub gc_telemetry_active: bool,
    /// Whether tail-latency probes are running.
    pub latency_probes_active: bool,
    /// Whether deopt counters are being tracked.
    pub deopt_counters_active: bool,
    /// Whether support-surface checks are scheduled.
    pub support_checks_scheduled: bool,
    /// Total diagnostic events emitted since last check.
    pub events_since_last_check: u64,
    /// Epoch of this health snapshot.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp.
    pub timestamp_ns: u64,
}

impl ObservabilityHealth {
    /// Whether all observability subsystems are healthy.
    pub fn is_healthy(&self) -> bool {
        self.gc_telemetry_active
            && self.latency_probes_active
            && self.deopt_counters_active
            && self.support_checks_scheduled
    }

    /// Count of unhealthy subsystems.
    pub fn unhealthy_count(&self) -> u32 {
        let mut count = 0u32;
        if !self.gc_telemetry_active {
            count += 1;
        }
        if !self.latency_probes_active {
            count += 1;
        }
        if !self.deopt_counters_active {
            count += 1;
        }
        if !self.support_checks_scheduled {
            count += 1;
        }
        count
    }

    /// Summary of unhealthy subsystems.
    pub fn unhealthy_subsystems(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.gc_telemetry_active {
            out.push("gc_telemetry");
        }
        if !self.latency_probes_active {
            out.push("latency_probes");
        }
        if !self.deopt_counters_active {
            out.push("deopt_counters");
        }
        if !self.support_checks_scheduled {
            out.push("support_checks");
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ElisionDiagnostic
// ---------------------------------------------------------------------------

/// Diagnostic event emitted by the elision gate for observability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionDiagnostic {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Diagnostic kind.
    pub kind: DiagnosticKind,
    /// Site identifier (if site-specific).
    pub site_id: Option<AllocationSiteId>,
    /// Lane identifier.
    pub lane_id: LaneId,
    /// Human-readable message.
    pub message: String,
    /// Epoch at emission time.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp (nanoseconds).
    pub timestamp_ns: u64,
}

/// Kind of diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    /// Elision approved for a site.
    ElisionApproved,
    /// Elision denied for a site.
    ElisionDenied,
    /// Elision rolled back.
    ElisionRolledBack,
    /// GC impact assessment completed.
    GcAssessmentComplete,
    /// Tail-latency evidence collected.
    LatencyEvidenceCollected,
    /// Deopt witness recorded.
    DeoptWitnessRecorded,
    /// Support contract validated.
    SupportContractValidated,
    /// Observability health checked.
    HealthChecked,
    /// Savings report generated.
    SavingsReported,
}

impl DiagnosticKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ElisionApproved => "elision_approved",
            Self::ElisionDenied => "elision_denied",
            Self::ElisionRolledBack => "elision_rolled_back",
            Self::GcAssessmentComplete => "gc_assessment_complete",
            Self::LatencyEvidenceCollected => "latency_evidence_collected",
            Self::DeoptWitnessRecorded => "deopt_witness_recorded",
            Self::SupportContractValidated => "support_contract_validated",
            Self::HealthChecked => "health_checked",
            Self::SavingsReported => "savings_reported",
        }
    }
}

impl fmt::Display for DiagnosticKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ElisionDecisionReceipt
// ---------------------------------------------------------------------------

/// Signed decision receipt for an elision governance verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionDecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Which allocation site this decision applies to.
    pub site_id: AllocationSiteId,
    /// Lane where the decision applies.
    pub lane_id: LaneId,
    /// The verdict.
    pub verdict: ElisionVerdict,
    /// Denial reasons (empty if approved).
    pub denial_reasons: Vec<DenialReason>,
    /// Assumptions required for this verdict to hold.
    pub required_assumptions: BTreeSet<String>,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Digest of the GC impact evidence.
    pub gc_evidence_digest: Option<ContentHash>,
    /// Digest of the tail-latency evidence.
    pub latency_evidence_digest: Option<ContentHash>,
    /// Digest of the support-surface contract.
    pub support_contract_digest: Option<ContentHash>,
    /// Content-addressable digest of this receipt.
    pub receipt_digest: ContentHash,
}

impl ElisionDecisionReceipt {
    /// Compute the receipt digest from all fields (excluding receipt_digest itself).
    pub fn compute_digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        append_length_prefixed_str(&mut buf, &self.schema_version);
        append_length_prefixed_str(&mut buf, &self.receipt_id);
        append_length_prefixed_str(&mut buf, self.site_id.as_str());
        append_length_prefixed_str(&mut buf, self.lane_id.as_str());
        append_length_prefixed_str(&mut buf, self.verdict.as_str());
        for reason in &self.denial_reasons {
            append_length_prefixed_str(&mut buf, reason.as_str());
        }
        for assumption in &self.required_assumptions {
            append_length_prefixed_str(&mut buf, assumption);
        }
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        if let Some(ref d) = self.gc_evidence_digest {
            buf.push(1);
            buf.extend_from_slice(d.as_bytes());
        } else {
            buf.push(0);
        }
        if let Some(ref d) = self.latency_evidence_digest {
            buf.push(1);
            buf.extend_from_slice(d.as_bytes());
        } else {
            buf.push(0);
        }
        if let Some(ref d) = self.support_contract_digest {
            buf.push(1);
            buf.extend_from_slice(d.as_bytes());
        } else {
            buf.push(0);
        }
        compute_digest(&buf)
    }

    /// Verify that the stored digest matches the computed one.
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.compute_digest()
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the allocation-elision governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum GC pause regression allowed (millionths above 1.0).
    pub max_gc_pause_regression_millionths: u64,
    /// Maximum tail-latency regression allowed (millionths above 1.0).
    pub max_tail_latency_regression_millionths: u64,
    /// Minimum support-surface coverage (millionths).
    pub min_support_coverage_millionths: u64,
    /// Minimum sample count for statistical validity.
    pub min_sample_count: u64,
    /// Rollback cooldown period (nanoseconds).
    pub rollback_cooldown_ns: u64,
    /// Maximum consecutive rollbacks before permanent denial.
    pub max_consecutive_rollbacks: u32,
    /// Whether observability must be healthy for approval.
    pub require_observability_health: bool,
    /// Whether escape certificate must be present for approval.
    pub require_escape_certificate: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_gc_pause_regression_millionths: DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS,
            max_tail_latency_regression_millionths: DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS,
            min_support_coverage_millionths: DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
            rollback_cooldown_ns: DEFAULT_ROLLBACK_COOLDOWN_NS,
            max_consecutive_rollbacks: MAX_CONSECUTIVE_ROLLBACKS,
            require_observability_health: true,
            require_escape_certificate: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ElisionSavingsReport
// ---------------------------------------------------------------------------

/// Report summarising the aggregate savings from allocation elision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionSavingsReport {
    /// Lane this report covers.
    pub lane_id: LaneId,
    /// Total allocation sites evaluated.
    pub total_sites_evaluated: u64,
    /// Sites where elision was approved.
    pub sites_approved: u64,
    /// Sites where elision was denied.
    pub sites_denied: u64,
    /// Sites currently rolled back.
    pub sites_rolled_back: u64,
    /// Estimated bytes saved per second from elision.
    pub estimated_bytes_saved_per_sec: u64,
    /// Estimated allocations avoided per second.
    pub estimated_allocs_avoided_per_sec: u64,
    /// GC cycles saved (estimated) per minute.
    pub estimated_gc_cycles_saved_per_min: u64,
    /// Net latency improvement at p50 (nanoseconds, positive = better).
    pub net_p50_improvement_ns: i64,
    /// Net latency improvement at p99 (nanoseconds, positive = better).
    pub net_p99_improvement_ns: i64,
    /// Epoch of this report.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp.
    pub timestamp_ns: u64,
    /// Digest of this report.
    pub report_digest: ContentHash,
}

impl ElisionSavingsReport {
    /// Approval rate in millionths.
    pub fn approval_rate_millionths(&self) -> u64 {
        if self.total_sites_evaluated == 0 {
            return 0;
        }
        self.sites_approved
            .saturating_mul(MILLION)
            .checked_div(self.total_sites_evaluated)
            .unwrap_or(0)
    }

    /// Effective elision rate (approved minus rolled-back, in millionths).
    pub fn effective_elision_rate_millionths(&self) -> u64 {
        if self.total_sites_evaluated == 0 {
            return 0;
        }
        let effective = self.sites_approved.saturating_sub(self.sites_rolled_back);
        effective
            .saturating_mul(MILLION)
            .checked_div(self.total_sites_evaluated)
            .unwrap_or(0)
    }

    /// Compute the content hash for this report.
    pub fn compute_digest(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        append_length_prefixed_str(&mut buf, self.lane_id.as_str());
        buf.extend_from_slice(&self.total_sites_evaluated.to_be_bytes());
        buf.extend_from_slice(&self.sites_approved.to_be_bytes());
        buf.extend_from_slice(&self.sites_denied.to_be_bytes());
        buf.extend_from_slice(&self.sites_rolled_back.to_be_bytes());
        buf.extend_from_slice(&self.estimated_bytes_saved_per_sec.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// SiteElisionState — per-site tracking
// ---------------------------------------------------------------------------

/// Tracks the elision state of a single allocation site within the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteElisionState {
    /// The site identifier.
    pub site_id: AllocationSiteId,
    /// Current verdict.
    pub verdict: ElisionVerdict,
    /// Number of consecutive rollbacks.
    pub consecutive_rollbacks: u32,
    /// Timestamp of last evaluation.
    pub last_evaluated_ns: u64,
    /// Timestamp of last rollback (0 if never rolled back).
    pub last_rollback_ns: u64,
    /// Whether the site is permanently denied.
    pub permanently_denied: bool,
    /// Active assumptions for this site.
    pub active_assumptions: BTreeSet<String>,
    /// Deopt count since last approval.
    pub deopt_count_since_approval: u64,
    /// Epoch of last verdict.
    pub verdict_epoch: SecurityEpoch,
}

impl SiteElisionState {
    /// Create a new site in the initial (denied, unevaluated) state.
    pub fn new(site_id: AllocationSiteId, epoch: SecurityEpoch) -> Self {
        Self {
            site_id,
            verdict: ElisionVerdict::Denied,
            consecutive_rollbacks: 0,
            last_evaluated_ns: 0,
            last_rollback_ns: 0,
            permanently_denied: false,
            active_assumptions: BTreeSet::new(),
            deopt_count_since_approval: 0,
            verdict_epoch: epoch,
        }
    }

    /// Whether this site is eligible for re-evaluation.
    pub fn can_reevaluate(&self, now_ns: u64, cooldown_ns: u64) -> bool {
        if self.permanently_denied {
            return false;
        }
        if self.last_rollback_ns == 0 {
            return true;
        }
        now_ns.saturating_sub(self.last_rollback_ns) >= cooldown_ns
    }

    /// Record a rollback event.
    pub fn record_rollback(&mut self, now_ns: u64, max_consecutive: u32) {
        self.verdict = ElisionVerdict::RolledBack;
        self.consecutive_rollbacks += 1;
        self.last_rollback_ns = now_ns;
        self.deopt_count_since_approval = 0;
        if self.consecutive_rollbacks >= max_consecutive {
            self.permanently_denied = true;
        }
    }

    /// Record an approval.
    pub fn record_approval(
        &mut self,
        verdict: ElisionVerdict,
        assumptions: BTreeSet<String>,
        now_ns: u64,
        epoch: SecurityEpoch,
    ) {
        self.verdict = verdict;
        self.active_assumptions = assumptions;
        self.last_evaluated_ns = now_ns;
        self.deopt_count_since_approval = 0;
        self.verdict_epoch = epoch;
    }

    /// Record a deopt event.
    pub fn record_deopt(&mut self) {
        self.deopt_count_since_approval += 1;
    }
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — the core evaluator
// ---------------------------------------------------------------------------

/// Input bundle for a single site evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionEvalInput {
    /// Which site to evaluate.
    pub site_id: AllocationSiteId,
    /// Lane context.
    pub lane_id: LaneId,
    /// GC impact assessment (required).
    pub gc_assessment: GcImpactAssessment,
    /// Tail-latency evidence (required).
    pub latency_evidence: TailLatencyEvidence,
    /// Support-surface contract (optional; if absent and required, denial).
    pub support_contract: Option<SupportSurfaceContract>,
    /// Observability health snapshot (optional; if absent and required, denial).
    pub observability: Option<ObservabilityHealth>,
    /// Whether an escape certificate exists for this site.
    pub has_escape_certificate: bool,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Current monotonic timestamp.
    pub now_ns: u64,
}

/// Result of a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionEvalResult {
    /// The verdict.
    pub verdict: ElisionVerdict,
    /// Denial reasons (empty if approved).
    pub denial_reasons: Vec<DenialReason>,
    /// Decision receipt.
    pub receipt: ElisionDecisionReceipt,
    /// Diagnostics emitted during evaluation.
    pub diagnostics: Vec<ElisionDiagnostic>,
}

/// Core evaluator for the allocation-elision gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElisionGateEvaluator {
    /// Configuration.
    config: GateConfig,
    /// Per-site state, keyed by site_id string.
    site_states: BTreeMap<String, SiteElisionState>,
    /// Rollback history.
    rollback_history: Vec<RollbackRecord>,
    /// Diagnostic sequence counter.
    diagnostic_seq: u64,
    /// Receipt counter for unique IDs.
    receipt_counter: u64,
}

impl ElisionGateEvaluator {
    /// Create a new evaluator with the given configuration.
    pub fn new(config: GateConfig) -> Self {
        Self {
            config,
            site_states: BTreeMap::new(),
            rollback_history: Vec::new(),
            diagnostic_seq: 0,
            receipt_counter: 0,
        }
    }

    /// Create an evaluator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(GateConfig::default())
    }

    /// Access the configuration.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Access per-site states.
    pub fn site_states(&self) -> &BTreeMap<String, SiteElisionState> {
        &self.site_states
    }

    /// Access rollback history.
    pub fn rollback_history(&self) -> &[RollbackRecord] {
        &self.rollback_history
    }

    /// Number of sites tracked.
    pub fn tracked_site_count(&self) -> usize {
        self.site_states.len()
    }

    /// Number of currently approved sites.
    pub fn approved_site_count(&self) -> usize {
        self.site_states
            .values()
            .filter(|s| s.verdict.is_elision_allowed())
            .count()
    }

    /// Number of permanently denied sites.
    pub fn permanently_denied_count(&self) -> usize {
        self.site_states
            .values()
            .filter(|s| s.permanently_denied)
            .count()
    }

    fn next_diagnostic_seq(&mut self) -> u64 {
        let seq = self.diagnostic_seq;
        self.diagnostic_seq += 1;
        seq
    }

    fn next_receipt_id(&mut self) -> String {
        let id = self.receipt_counter;
        self.receipt_counter += 1;
        format!("elision-receipt-{id}")
    }

    fn emit_diagnostic(
        &mut self,
        kind: DiagnosticKind,
        site_id: Option<AllocationSiteId>,
        lane_id: &LaneId,
        message: String,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> ElisionDiagnostic {
        let seq = self.next_diagnostic_seq();
        ElisionDiagnostic {
            sequence: seq,
            kind,
            site_id,
            lane_id: lane_id.clone(),
            message,
            epoch,
            timestamp_ns,
        }
    }

    /// Evaluate whether an allocation site's elision should be approved.
    pub fn evaluate(&mut self, input: &ElisionEvalInput) -> ElisionEvalResult {
        let site_key = input.site_id.as_str().to_string();
        let mut denial_reasons = Vec::new();
        let mut diagnostics = Vec::new();

        // Ensure site state exists.
        if !self.site_states.contains_key(&site_key) {
            self.site_states.insert(
                site_key.clone(),
                SiteElisionState::new(input.site_id.clone(), input.epoch),
            );
        }

        // Check permanent denial.
        let is_permanently_denied = self
            .site_states
            .get(&site_key)
            .map(|s| s.permanently_denied)
            .unwrap_or(false);
        if is_permanently_denied {
            denial_reasons.push(DenialReason::RollbackLimitExceeded);
        }

        // Check cooldown.
        let can_reevaluate = self
            .site_states
            .get(&site_key)
            .map(|s| s.can_reevaluate(input.now_ns, self.config.rollback_cooldown_ns))
            .unwrap_or(true);
        if !can_reevaluate {
            denial_reasons.push(DenialReason::RollbackLimitExceeded);
        }

        // Check epoch.
        let site_epoch = self
            .site_states
            .get(&site_key)
            .map(|s| s.verdict_epoch)
            .unwrap_or(SecurityEpoch::GENESIS);
        if input.epoch < site_epoch {
            denial_reasons.push(DenialReason::EpochMismatch);
        }

        // Check escape certificate.
        if self.config.require_escape_certificate && !input.has_escape_certificate {
            denial_reasons.push(DenialReason::MissingEscapeCertificate);
        }

        // Check sample counts.
        if input.gc_assessment.sample_count < self.config.min_sample_count {
            denial_reasons.push(DenialReason::InsufficientSamples);
        }
        if input.latency_evidence.sample_count < self.config.min_sample_count
            && !denial_reasons.contains(&DenialReason::InsufficientSamples)
        {
            denial_reasons.push(DenialReason::InsufficientSamples);
        }

        // Check GC impact.
        if input
            .gc_assessment
            .is_regressed(self.config.max_gc_pause_regression_millionths)
        {
            denial_reasons.push(DenialReason::GcPauseRegression);
            let diag = self.emit_diagnostic(
                DiagnosticKind::GcAssessmentComplete,
                Some(input.site_id.clone()),
                &input.lane_id,
                format!(
                    "GC pause regression detected: ratio={}",
                    input.gc_assessment.compute_pause_regression()
                ),
                input.epoch,
                input.now_ns,
            );
            diagnostics.push(diag);
        }

        // Check tail latency.
        if input
            .latency_evidence
            .is_regressed(self.config.max_tail_latency_regression_millionths)
        {
            denial_reasons.push(DenialReason::TailLatencyRegression);
            let diag = self.emit_diagnostic(
                DiagnosticKind::LatencyEvidenceCollected,
                Some(input.site_id.clone()),
                &input.lane_id,
                format!(
                    "Tail latency regression: p99_ratio={}, p999_ratio={}",
                    input.latency_evidence.p99_regression_millionths(),
                    input.latency_evidence.p999_regression_millionths()
                ),
                input.epoch,
                input.now_ns,
            );
            diagnostics.push(diag);
        }

        // Check support contract.
        if let Some(ref contract) = input.support_contract {
            if !contract.meets_coverage() {
                denial_reasons.push(DenialReason::InsufficientSupportCoverage);
            }
        } else if self.config.min_support_coverage_millionths > 0 {
            denial_reasons.push(DenialReason::InsufficientSupportCoverage);
        }

        // Check observability.
        if self.config.require_observability_health {
            match &input.observability {
                Some(health) if !health.is_healthy() => {
                    denial_reasons.push(DenialReason::ObservabilityUnhealthy);
                }
                None => {
                    denial_reasons.push(DenialReason::ObservabilityUnhealthy);
                }
                _ => {}
            }
        }

        // Determine verdict.
        let verdict = if denial_reasons.is_empty() {
            ElisionVerdict::Approved
        } else {
            ElisionVerdict::Denied
        };

        // Build receipt.
        let receipt_id = self.next_receipt_id();
        let mut required_assumptions = BTreeSet::new();
        if verdict.is_elision_allowed() {
            required_assumptions.insert(AssumptionKind::NoEscape.as_str().to_string());
            required_assumptions.insert(AssumptionKind::StableShape.as_str().to_string());
        }

        let gc_evidence_digest = Some(input.gc_assessment.digest());
        let latency_evidence_digest = Some(input.latency_evidence.digest());
        let support_contract_digest = input.support_contract.as_ref().map(|c| c.digest());

        let mut receipt = ElisionDecisionReceipt {
            schema_version: ELISION_GATE_SCHEMA_VERSION.to_string(),
            receipt_id,
            site_id: input.site_id.clone(),
            lane_id: input.lane_id.clone(),
            verdict: verdict.clone(),
            denial_reasons: denial_reasons.clone(),
            required_assumptions: required_assumptions.clone(),
            epoch: input.epoch,
            timestamp_ns: input.now_ns,
            gc_evidence_digest,
            latency_evidence_digest,
            support_contract_digest,
            receipt_digest: ContentHash::compute(b"placeholder"),
        };
        receipt.receipt_digest = receipt.compute_digest();

        // Update site state.
        if let Some(state) = self.site_states.get_mut(&site_key) {
            if verdict.is_elision_allowed() {
                state.record_approval(
                    verdict.clone(),
                    required_assumptions,
                    input.now_ns,
                    input.epoch,
                );
            } else {
                state.verdict = verdict.clone();
                state.last_evaluated_ns = input.now_ns;
                state.verdict_epoch = input.epoch;
            }
        }

        // Emit verdict diagnostic.
        let diag_kind = if verdict.is_elision_allowed() {
            DiagnosticKind::ElisionApproved
        } else {
            DiagnosticKind::ElisionDenied
        };
        let diag = self.emit_diagnostic(
            diag_kind,
            Some(input.site_id.clone()),
            &input.lane_id,
            format!("Elision verdict: {verdict}"),
            input.epoch,
            input.now_ns,
        );
        diagnostics.push(diag);

        ElisionEvalResult {
            verdict,
            denial_reasons,
            receipt,
            diagnostics,
        }
    }

    /// Process a deopt witness, potentially triggering rollback.
    pub fn process_deopt(&mut self, witness: &DeoptWitness) -> Option<RollbackRecord> {
        let site_key = witness.site_id.as_str().to_string();

        let state = self.site_states.get_mut(&site_key)?;
        state.record_deopt();

        // Trigger rollback if the site was approved.
        if state.verdict.is_elision_allowed() {
            state.record_rollback(witness.timestamp_ns, self.config.max_consecutive_rollbacks);

            let record = RollbackRecord {
                site_id: witness.site_id.clone(),
                lane_id: witness.lane_id.clone(),
                trigger: RollbackTrigger::DeoptEvent,
                timestamp_ns: witness.timestamp_ns,
                epoch: witness.epoch,
                consecutive_count: state.consecutive_rollbacks,
                evidence_digest: witness.digest(),
            };
            self.rollback_history.push(record.clone());
            Some(record)
        } else {
            None
        }
    }

    /// Trigger a rollback for a specific site.
    pub fn trigger_rollback(
        &mut self,
        site_id: &AllocationSiteId,
        lane_id: &LaneId,
        trigger: RollbackTrigger,
        evidence_digest: ContentHash,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Option<RollbackRecord> {
        let site_key = site_id.as_str().to_string();
        let state = self.site_states.get_mut(&site_key)?;

        if !state.verdict.is_elision_allowed() {
            return None;
        }

        state.record_rollback(timestamp_ns, self.config.max_consecutive_rollbacks);

        let record = RollbackRecord {
            site_id: site_id.clone(),
            lane_id: lane_id.clone(),
            trigger,
            timestamp_ns,
            epoch,
            consecutive_count: state.consecutive_rollbacks,
            evidence_digest,
        };
        self.rollback_history.push(record.clone());
        Some(record)
    }

    /// Generate a savings report for a lane.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_savings_report(
        &self,
        lane_id: &LaneId,
        estimated_bytes_saved_per_sec: u64,
        estimated_allocs_avoided_per_sec: u64,
        estimated_gc_cycles_saved_per_min: u64,
        net_p50_improvement_ns: i64,
        net_p99_improvement_ns: i64,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> ElisionSavingsReport {
        let total = self.site_states.len() as u64;
        let approved = self
            .site_states
            .values()
            .filter(|s| {
                matches!(
                    s.verdict,
                    ElisionVerdict::Approved | ElisionVerdict::Conditional
                )
            })
            .count() as u64;
        let denied = self
            .site_states
            .values()
            .filter(|s| matches!(s.verdict, ElisionVerdict::Denied))
            .count() as u64;
        let rolled_back = self
            .site_states
            .values()
            .filter(|s| matches!(s.verdict, ElisionVerdict::RolledBack))
            .count() as u64;

        let mut report = ElisionSavingsReport {
            lane_id: lane_id.clone(),
            total_sites_evaluated: total,
            sites_approved: approved,
            sites_denied: denied,
            sites_rolled_back: rolled_back,
            estimated_bytes_saved_per_sec,
            estimated_allocs_avoided_per_sec,
            estimated_gc_cycles_saved_per_min,
            net_p50_improvement_ns,
            net_p99_improvement_ns,
            epoch,
            timestamp_ns,
            report_digest: ContentHash::compute(b"placeholder"),
        };
        report.report_digest = report.compute_digest();
        report
    }

    /// Bulk evaluate multiple sites, returning all results.
    pub fn evaluate_batch(&mut self, inputs: &[ElisionEvalInput]) -> Vec<ElisionEvalResult> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            results.push(self.evaluate(input));
        }
        results
    }

    /// Get the current verdict for a site.
    pub fn site_verdict(&self, site_id: &str) -> Option<&ElisionVerdict> {
        self.site_states.get(site_id).map(|s| &s.verdict)
    }

    /// Check if a site is permanently denied.
    pub fn is_permanently_denied(&self, site_id: &str) -> bool {
        self.site_states
            .get(site_id)
            .map(|s| s.permanently_denied)
            .unwrap_or(false)
    }

    /// Reset a site's rollback counter (operator override).
    pub fn reset_rollback_counter(&mut self, site_id: &str) -> bool {
        if let Some(state) = self.site_states.get_mut(site_id) {
            state.consecutive_rollbacks = 0;
            state.permanently_denied = false;
            state.verdict = ElisionVerdict::Denied;
            true
        } else {
            false
        }
    }

    /// Get rollback records for a specific site.
    pub fn site_rollbacks(&self, site_id: &str) -> Vec<&RollbackRecord> {
        self.rollback_history
            .iter()
            .filter(|r| r.site_id.as_str() == site_id)
            .collect()
    }

    /// Total rollback count.
    pub fn total_rollback_count(&self) -> usize {
        self.rollback_history.len()
    }
}

// ---------------------------------------------------------------------------
// EvidenceBundle — aggregated evidence for audit
// ---------------------------------------------------------------------------

/// Aggregated evidence bundle for external audit of elision decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElisionEvidenceBundle {
    /// Schema version.
    pub schema_version: String,
    /// Lane this bundle covers.
    pub lane_id: LaneId,
    /// All decision receipts in this bundle.
    pub receipts: Vec<ElisionDecisionReceipt>,
    /// All rollback records.
    pub rollback_records: Vec<RollbackRecord>,
    /// All deopt witnesses.
    pub deopt_witnesses: Vec<DeoptWitness>,
    /// Savings report.
    pub savings_report: Option<ElisionSavingsReport>,
    /// Observability health at bundle creation.
    pub observability_health: Option<ObservabilityHealth>,
    /// Security epoch of the bundle.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp of bundle creation.
    pub timestamp_ns: u64,
    /// Content-addressable digest of the bundle.
    pub bundle_digest: ContentHash,
}

impl ElisionEvidenceBundle {
    /// Create a new bundle from components.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        lane_id: LaneId,
        receipts: Vec<ElisionDecisionReceipt>,
        rollback_records: Vec<RollbackRecord>,
        deopt_witnesses: Vec<DeoptWitness>,
        savings_report: Option<ElisionSavingsReport>,
        observability_health: Option<ObservabilityHealth>,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> Self {
        let mut buf = Vec::with_capacity(256);
        append_length_prefixed_str(&mut buf, ELISION_GATE_SCHEMA_VERSION);
        append_length_prefixed_str(&mut buf, lane_id.as_str());
        buf.extend_from_slice(&(receipts.len() as u64).to_be_bytes());
        for r in &receipts {
            buf.extend_from_slice(r.receipt_digest.as_bytes());
        }
        buf.extend_from_slice(&(rollback_records.len() as u64).to_be_bytes());
        for r in &rollback_records {
            buf.extend_from_slice(r.digest().as_bytes());
        }
        buf.extend_from_slice(&(deopt_witnesses.len() as u64).to_be_bytes());
        for w in &deopt_witnesses {
            buf.extend_from_slice(w.digest().as_bytes());
        }
        buf.extend_from_slice(&epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        let bundle_digest = compute_digest(&buf);

        Self {
            schema_version: ELISION_GATE_SCHEMA_VERSION.to_string(),
            lane_id,
            receipts,
            rollback_records,
            deopt_witnesses,
            savings_report,
            observability_health,
            epoch,
            timestamp_ns,
            bundle_digest,
        }
    }

    /// Number of approvals in the bundle.
    pub fn approval_count(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| r.verdict.is_elision_allowed())
            .count()
    }

    /// Number of denials in the bundle.
    pub fn denial_count(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| !r.verdict.is_elision_allowed())
            .count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn site(id: &str) -> AllocationSiteId {
        AllocationSiteId::new(id)
    }

    fn lane(id: &str) -> LaneId {
        LaneId::new(id)
    }

    fn good_gc_assessment() -> GcImpactAssessment {
        GcImpactAssessment {
            baseline_pause_p50_ns: 1_000_000,
            baseline_pause_p99_ns: 5_000_000,
            elided_pause_p50_ns: 900_000,
            elided_pause_p99_ns: 4_800_000,
            baseline_allocs_per_cycle: 1000,
            elided_allocs_per_cycle: 800,
            baseline_bytes_per_cycle: 64_000,
            elided_bytes_per_cycle: 48_000,
            sample_count: 100,
            pause_regression_millionths: 960_000,
        }
    }

    fn bad_gc_assessment() -> GcImpactAssessment {
        GcImpactAssessment {
            baseline_pause_p50_ns: 1_000_000,
            baseline_pause_p99_ns: 5_000_000,
            elided_pause_p50_ns: 1_500_000,
            elided_pause_p99_ns: 8_000_000,
            baseline_allocs_per_cycle: 1000,
            elided_allocs_per_cycle: 800,
            baseline_bytes_per_cycle: 64_000,
            elided_bytes_per_cycle: 48_000,
            sample_count: 100,
            pause_regression_millionths: 1_600_000,
        }
    }

    fn good_latency_evidence() -> TailLatencyEvidence {
        TailLatencyEvidence {
            baseline_p99_ns: 10_000_000,
            baseline_p999_ns: 50_000_000,
            elided_p99_ns: 9_500_000,
            elided_p999_ns: 48_000_000,
            baseline_p50_ns: 1_000_000,
            elided_p50_ns: 900_000,
            sample_count: 100,
            workload_id: "bench-workload-1".to_string(),
        }
    }

    fn bad_latency_evidence() -> TailLatencyEvidence {
        TailLatencyEvidence {
            baseline_p99_ns: 10_000_000,
            baseline_p999_ns: 50_000_000,
            elided_p99_ns: 15_000_000,
            elided_p999_ns: 80_000_000,
            baseline_p50_ns: 1_000_000,
            elided_p50_ns: 1_200_000,
            sample_count: 100,
            workload_id: "bench-workload-1".to_string(),
        }
    }

    fn good_support_contract() -> SupportSurfaceContract {
        SupportSurfaceContract {
            contract_id: "contract-1".to_string(),
            covered_sites: {
                let mut s = BTreeSet::new();
                s.insert("site-a".to_string());
                s
            },
            min_coverage_millionths: 950_000,
            actual_coverage_millionths: 980_000,
            fallback_paths_verified: true,
            validated_epoch: epoch(1),
            notes: String::new(),
        }
    }

    fn bad_support_contract() -> SupportSurfaceContract {
        SupportSurfaceContract {
            contract_id: "contract-2".to_string(),
            covered_sites: BTreeSet::new(),
            min_coverage_millionths: 950_000,
            actual_coverage_millionths: 800_000,
            fallback_paths_verified: false,
            validated_epoch: epoch(1),
            notes: String::new(),
        }
    }

    fn healthy_observability() -> ObservabilityHealth {
        ObservabilityHealth {
            gc_telemetry_active: true,
            latency_probes_active: true,
            deopt_counters_active: true,
            support_checks_scheduled: true,
            events_since_last_check: 42,
            epoch: epoch(1),
            timestamp_ns: 1_000_000,
        }
    }

    fn unhealthy_observability() -> ObservabilityHealth {
        ObservabilityHealth {
            gc_telemetry_active: false,
            latency_probes_active: true,
            deopt_counters_active: true,
            support_checks_scheduled: false,
            events_since_last_check: 0,
            epoch: epoch(1),
            timestamp_ns: 1_000_000,
        }
    }

    fn make_good_input(site_name: &str) -> ElisionEvalInput {
        ElisionEvalInput {
            site_id: site(site_name),
            lane_id: lane("lane-1"),
            gc_assessment: good_gc_assessment(),
            latency_evidence: good_latency_evidence(),
            support_contract: Some(good_support_contract()),
            observability: Some(healthy_observability()),
            has_escape_certificate: true,
            epoch: epoch(1),
            now_ns: 10_000_000,
        }
    }

    // --- ElisionVerdict tests ---

    #[test]
    fn verdict_approved_allows_elision() {
        assert!(ElisionVerdict::Approved.is_elision_allowed());
    }

    #[test]
    fn verdict_conditional_allows_elision() {
        assert!(ElisionVerdict::Conditional.is_elision_allowed());
    }

    #[test]
    fn verdict_denied_disallows_elision() {
        assert!(!ElisionVerdict::Denied.is_elision_allowed());
    }

    #[test]
    fn verdict_rolled_back_disallows_elision() {
        assert!(!ElisionVerdict::RolledBack.is_elision_allowed());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(ElisionVerdict::Approved.to_string(), "approved");
        assert_eq!(ElisionVerdict::Denied.to_string(), "denied");
        assert_eq!(ElisionVerdict::RolledBack.to_string(), "rolled_back");
        assert_eq!(ElisionVerdict::Conditional.to_string(), "conditional");
    }

    // --- DenialReason tests ---

    #[test]
    fn denial_reason_display() {
        assert_eq!(
            DenialReason::GcPauseRegression.to_string(),
            "gc_pause_regression"
        );
        assert_eq!(
            DenialReason::TailLatencyRegression.to_string(),
            "tail_latency_regression"
        );
        assert_eq!(
            DenialReason::DeoptWitnessTriggered.to_string(),
            "deopt_witness_triggered"
        );
    }

    // --- GcImpactAssessment tests ---

    #[test]
    fn gc_no_regression_when_improved() {
        let gc = good_gc_assessment();
        assert!(!gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
    }

    #[test]
    fn gc_regression_when_pauses_worse() {
        let gc = bad_gc_assessment();
        assert!(gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
    }

    #[test]
    fn gc_pause_regression_ratio_computation() {
        let gc = good_gc_assessment();
        let ratio = gc.compute_pause_regression();
        // 4_800_000 / 5_000_000 = 0.96 => 960_000 millionths
        assert_eq!(ratio, 960_000);
    }

    #[test]
    fn gc_zero_baseline_no_panic() {
        let mut gc = good_gc_assessment();
        gc.baseline_pause_p99_ns = 0;
        assert_eq!(gc.compute_pause_regression(), 0);
        assert!(!gc.is_regressed(50_000));
    }

    #[test]
    fn gc_bytes_saved_per_cycle() {
        let gc = good_gc_assessment();
        assert_eq!(gc.bytes_saved_per_cycle(), 16_000);
    }

    #[test]
    fn gc_digest_deterministic() {
        let gc = good_gc_assessment();
        assert_eq!(gc.digest(), gc.digest());
    }

    #[test]
    fn gc_different_data_different_digest() {
        let gc1 = good_gc_assessment();
        let gc2 = bad_gc_assessment();
        assert_ne!(gc1.digest(), gc2.digest());
    }

    // --- TailLatencyEvidence tests ---

    #[test]
    fn latency_no_regression_when_improved() {
        let lat = good_latency_evidence();
        assert!(!lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
    }

    #[test]
    fn latency_regression_detected() {
        let lat = bad_latency_evidence();
        assert!(lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
    }

    #[test]
    fn latency_p99_regression_ratio() {
        let lat = good_latency_evidence();
        let ratio = lat.p99_regression_millionths();
        // 9_500_000 / 10_000_000 = 0.95 => 950_000
        assert_eq!(ratio, 950_000);
    }

    #[test]
    fn latency_p999_regression_ratio() {
        let lat = good_latency_evidence();
        let ratio = lat.p999_regression_millionths();
        // 48_000_000 / 50_000_000 = 0.96 => 960_000
        assert_eq!(ratio, 960_000);
    }

    #[test]
    fn latency_p50_improvement() {
        let lat = good_latency_evidence();
        assert_eq!(lat.p50_improvement_ns(), 100_000);
    }

    #[test]
    fn latency_zero_baseline_no_panic() {
        let mut lat = good_latency_evidence();
        lat.baseline_p99_ns = 0;
        lat.baseline_p999_ns = 0;
        assert_eq!(lat.p99_regression_millionths(), 0);
        assert_eq!(lat.p999_regression_millionths(), 0);
    }

    #[test]
    fn latency_digest_deterministic() {
        let lat = good_latency_evidence();
        assert_eq!(lat.digest(), lat.digest());
    }

    // --- SupportSurfaceContract tests ---

    #[test]
    fn support_contract_met() {
        let c = good_support_contract();
        assert!(c.meets_coverage());
        assert!(c.is_satisfied());
    }

    #[test]
    fn support_contract_not_met() {
        let c = bad_support_contract();
        assert!(!c.meets_coverage());
        assert!(!c.is_satisfied());
    }

    #[test]
    fn support_coverage_deficit() {
        let c = bad_support_contract();
        assert_eq!(c.coverage_deficit_millionths(), 150_000);
    }

    #[test]
    fn support_no_deficit_when_met() {
        let c = good_support_contract();
        assert_eq!(c.coverage_deficit_millionths(), 0);
    }

    #[test]
    fn support_fallback_not_verified() {
        let mut c = good_support_contract();
        c.fallback_paths_verified = false;
        assert!(c.meets_coverage());
        assert!(!c.is_satisfied());
    }

    // --- ObservabilityHealth tests ---

    #[test]
    fn observability_healthy() {
        let h = healthy_observability();
        assert!(h.is_healthy());
        assert_eq!(h.unhealthy_count(), 0);
        assert!(h.unhealthy_subsystems().is_empty());
    }

    #[test]
    fn observability_unhealthy() {
        let h = unhealthy_observability();
        assert!(!h.is_healthy());
        assert_eq!(h.unhealthy_count(), 2);
        let subs = h.unhealthy_subsystems();
        assert!(subs.contains(&"gc_telemetry"));
        assert!(subs.contains(&"support_checks"));
    }

    // --- AssumptionKind tests ---

    #[test]
    fn assumption_kind_all_variants() {
        assert_eq!(AssumptionKind::ALL.len(), 8);
    }

    #[test]
    fn assumption_kind_display() {
        assert_eq!(AssumptionKind::NoEscape.to_string(), "no_escape");
        assert_eq!(AssumptionKind::StableShape.to_string(), "stable_shape");
        assert_eq!(AssumptionKind::NoModuleLeak.to_string(), "no_module_leak");
    }

    // --- RollbackTrigger tests ---

    #[test]
    fn rollback_trigger_display() {
        assert_eq!(RollbackTrigger::GcRegression.to_string(), "gc_regression");
        assert_eq!(RollbackTrigger::DeoptEvent.to_string(), "deopt_event");
        assert_eq!(
            RollbackTrigger::OperatorInitiated.to_string(),
            "operator_initiated"
        );
    }

    // --- DiagnosticKind tests ---

    #[test]
    fn diagnostic_kind_display() {
        assert_eq!(
            DiagnosticKind::ElisionApproved.to_string(),
            "elision_approved"
        );
        assert_eq!(
            DiagnosticKind::ElisionRolledBack.to_string(),
            "elision_rolled_back"
        );
    }

    // --- SiteElisionState tests ---

    #[test]
    fn site_state_new_is_denied() {
        let s = SiteElisionState::new(site("s1"), epoch(1));
        assert_eq!(s.verdict, ElisionVerdict::Denied);
        assert!(!s.permanently_denied);
        assert_eq!(s.consecutive_rollbacks, 0);
    }

    #[test]
    fn site_state_can_reevaluate_initially() {
        let s = SiteElisionState::new(site("s1"), epoch(1));
        assert!(s.can_reevaluate(1_000_000, DEFAULT_ROLLBACK_COOLDOWN_NS));
    }

    #[test]
    fn site_state_cooldown_blocks_reevaluation() {
        let mut s = SiteElisionState::new(site("s1"), epoch(1));
        s.record_rollback(1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
        assert!(!s.can_reevaluate(2_000_000, DEFAULT_ROLLBACK_COOLDOWN_NS));
    }

    #[test]
    fn site_state_cooldown_expires() {
        let mut s = SiteElisionState::new(site("s1"), epoch(1));
        s.record_rollback(1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
        let after_cooldown = 1_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1;
        assert!(s.can_reevaluate(after_cooldown, DEFAULT_ROLLBACK_COOLDOWN_NS));
    }

    #[test]
    fn site_state_permanent_denial_after_max_rollbacks() {
        let mut s = SiteElisionState::new(site("s1"), epoch(1));
        for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
            s.record_rollback(i as u64 * 1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
        }
        assert!(s.permanently_denied);
        assert!(!s.can_reevaluate(u64::MAX, DEFAULT_ROLLBACK_COOLDOWN_NS));
    }

    #[test]
    fn site_state_record_approval() {
        let mut s = SiteElisionState::new(site("s1"), epoch(1));
        let mut assumptions = BTreeSet::new();
        assumptions.insert("no_escape".to_string());
        s.record_approval(
            ElisionVerdict::Approved,
            assumptions.clone(),
            5_000,
            epoch(2),
        );
        assert_eq!(s.verdict, ElisionVerdict::Approved);
        assert_eq!(s.active_assumptions, assumptions);
        assert_eq!(s.verdict_epoch, epoch(2));
    }

    #[test]
    fn site_state_deopt_increments_count() {
        let mut s = SiteElisionState::new(site("s1"), epoch(1));
        assert_eq!(s.deopt_count_since_approval, 0);
        s.record_deopt();
        s.record_deopt();
        assert_eq!(s.deopt_count_since_approval, 2);
    }

    // --- ElisionGateEvaluator tests ---

    #[test]
    fn evaluator_approve_good_input() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-a");
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Approved);
        assert!(result.denial_reasons.is_empty());
    }

    #[test]
    fn evaluator_deny_gc_regression() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-b");
        input.gc_assessment = bad_gc_assessment();
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::GcPauseRegression)
        );
    }

    #[test]
    fn evaluator_deny_latency_regression() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-c");
        input.latency_evidence = bad_latency_evidence();
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::TailLatencyRegression)
        );
    }

    #[test]
    fn evaluator_deny_missing_escape_cert() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-d");
        input.has_escape_certificate = false;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::MissingEscapeCertificate)
        );
    }

    #[test]
    fn evaluator_deny_insufficient_samples() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-e");
        input.gc_assessment.sample_count = 5;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::InsufficientSamples)
        );
    }

    #[test]
    fn evaluator_deny_bad_support_contract() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-f");
        input.support_contract = Some(bad_support_contract());
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::InsufficientSupportCoverage)
        );
    }

    #[test]
    fn evaluator_deny_missing_support_contract() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-g");
        input.support_contract = None;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::InsufficientSupportCoverage)
        );
    }

    #[test]
    fn evaluator_deny_unhealthy_observability() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-h");
        input.observability = Some(unhealthy_observability());
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::ObservabilityUnhealthy)
        );
    }

    #[test]
    fn evaluator_deny_missing_observability() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-i");
        input.observability = None;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(
            result
                .denial_reasons
                .contains(&DenialReason::ObservabilityUnhealthy)
        );
    }

    #[test]
    fn evaluator_receipt_digest_is_valid() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-j");
        let result = ev.evaluate(&input);
        assert!(result.receipt.verify_digest());
    }

    #[test]
    fn evaluator_receipt_has_schema_version() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-k");
        let result = ev.evaluate(&input);
        assert_eq!(result.receipt.schema_version, ELISION_GATE_SCHEMA_VERSION);
    }

    #[test]
    fn evaluator_tracks_site_state() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-l");
        ev.evaluate(&input);
        assert_eq!(ev.tracked_site_count(), 1);
        assert_eq!(ev.approved_site_count(), 1);
    }

    #[test]
    fn evaluator_batch_evaluation() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let inputs = vec![make_good_input("site-m"), make_good_input("site-n")];
        let results = ev.evaluate_batch(&inputs);
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|r| r.verdict == ElisionVerdict::Approved)
        );
        assert_eq!(ev.tracked_site_count(), 2);
    }

    #[test]
    fn evaluator_process_deopt_triggers_rollback() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-o");
        ev.evaluate(&input);
        assert_eq!(ev.approved_site_count(), 1);

        let witness = DeoptWitness {
            site_id: site("site-o"),
            lane_id: lane("lane-1"),
            assumption_kind: AssumptionKind::NoEscape,
            timestamp_ns: 20_000_000,
            epoch: epoch(1),
            stack_depth: 3,
            occurrence_count: 1,
            approval_receipt_digest: ContentHash::compute(b"test"),
        };
        let rollback = ev.process_deopt(&witness);
        assert!(rollback.is_some());
        assert_eq!(ev.approved_site_count(), 0);
        assert_eq!(ev.total_rollback_count(), 1);
    }

    #[test]
    fn evaluator_process_deopt_on_denied_site_no_rollback() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        // Evaluate with bad data so site is denied.
        let mut input = make_good_input("site-p");
        input.gc_assessment = bad_gc_assessment();
        ev.evaluate(&input);

        let witness = DeoptWitness {
            site_id: site("site-p"),
            lane_id: lane("lane-1"),
            assumption_kind: AssumptionKind::StableShape,
            timestamp_ns: 20_000_000,
            epoch: epoch(1),
            stack_depth: 1,
            occurrence_count: 1,
            approval_receipt_digest: ContentHash::compute(b"test"),
        };
        let rollback = ev.process_deopt(&witness);
        assert!(rollback.is_none());
    }

    #[test]
    fn evaluator_trigger_rollback_manually() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-q");
        ev.evaluate(&input);

        let record = ev.trigger_rollback(
            &site("site-q"),
            &lane("lane-1"),
            RollbackTrigger::OperatorInitiated,
            ContentHash::compute(b"evidence"),
            30_000_000,
            epoch(1),
        );
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.trigger, RollbackTrigger::OperatorInitiated);
        assert_eq!(record.consecutive_count, 1);
    }

    #[test]
    fn evaluator_permanent_denial_after_repeated_rollbacks() {
        let mut ev = ElisionGateEvaluator::with_defaults();

        for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
            // Re-approve each time (need to bypass cooldown).
            let mut input = make_good_input("site-r");
            input.now_ns = (i as u64 + 1) * (DEFAULT_ROLLBACK_COOLDOWN_NS + 1_000_000);
            ev.evaluate(&input);

            ev.trigger_rollback(
                &site("site-r"),
                &lane("lane-1"),
                RollbackTrigger::GcRegression,
                ContentHash::compute(format!("evidence-{i}").as_bytes()),
                input.now_ns + 1000,
                epoch(1),
            );
        }

        assert!(ev.is_permanently_denied("site-r"));
        assert_eq!(ev.permanently_denied_count(), 1);
    }

    #[test]
    fn evaluator_reset_rollback_counter() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-s");
        ev.evaluate(&input);
        ev.trigger_rollback(
            &site("site-s"),
            &lane("lane-1"),
            RollbackTrigger::LatencyRegression,
            ContentHash::compute(b"ev"),
            20_000_000,
            epoch(1),
        );

        assert!(ev.reset_rollback_counter("site-s"));
        let state = ev.site_states().get("site-s").unwrap();
        assert_eq!(state.consecutive_rollbacks, 0);
        assert!(!state.permanently_denied);
    }

    #[test]
    fn evaluator_reset_nonexistent_site() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        assert!(!ev.reset_rollback_counter("no-such-site"));
    }

    #[test]
    fn evaluator_site_verdict() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        assert!(ev.site_verdict("site-t").is_none());

        let input = make_good_input("site-t");
        ev.evaluate(&input);
        assert_eq!(ev.site_verdict("site-t"), Some(&ElisionVerdict::Approved));
    }

    #[test]
    fn evaluator_site_rollbacks() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-u");
        ev.evaluate(&input);
        ev.trigger_rollback(
            &site("site-u"),
            &lane("lane-1"),
            RollbackTrigger::SupportViolation,
            ContentHash::compute(b"ev"),
            20_000_000,
            epoch(1),
        );
        let rollbacks = ev.site_rollbacks("site-u");
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].trigger, RollbackTrigger::SupportViolation);
    }

    #[test]
    fn evaluator_diagnostics_emitted_on_approval() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-v");
        let result = ev.evaluate(&input);
        assert!(!result.diagnostics.is_empty());
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.kind == DiagnosticKind::ElisionApproved)
        );
    }

    #[test]
    fn evaluator_diagnostics_emitted_on_denial() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-w");
        input.gc_assessment = bad_gc_assessment();
        let result = ev.evaluate(&input);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.kind == DiagnosticKind::ElisionDenied)
        );
    }

    #[test]
    fn evaluator_savings_report() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        ev.evaluate(&make_good_input("site-x1"));
        ev.evaluate(&make_good_input("site-x2"));
        let mut bad_input = make_good_input("site-x3");
        bad_input.gc_assessment = bad_gc_assessment();
        ev.evaluate(&bad_input);

        let report = ev.generate_savings_report(
            &lane("lane-1"),
            1_000_000,
            500,
            10,
            50_000,
            20_000,
            epoch(1),
            50_000_000,
        );
        assert_eq!(report.total_sites_evaluated, 3);
        assert_eq!(report.sites_approved, 2);
        assert_eq!(report.sites_denied, 1);
        assert_eq!(report.sites_rolled_back, 0);
    }

    #[test]
    fn savings_report_approval_rate() {
        let mut report = ElisionSavingsReport {
            lane_id: lane("l"),
            total_sites_evaluated: 10,
            sites_approved: 7,
            sites_denied: 2,
            sites_rolled_back: 1,
            estimated_bytes_saved_per_sec: 0,
            estimated_allocs_avoided_per_sec: 0,
            estimated_gc_cycles_saved_per_min: 0,
            net_p50_improvement_ns: 0,
            net_p99_improvement_ns: 0,
            epoch: epoch(1),
            timestamp_ns: 0,
            report_digest: ContentHash::compute(b"placeholder"),
        };
        report.report_digest = report.compute_digest();
        assert_eq!(report.approval_rate_millionths(), 700_000);
    }

    #[test]
    fn savings_report_effective_rate() {
        let report = ElisionSavingsReport {
            lane_id: lane("l"),
            total_sites_evaluated: 10,
            sites_approved: 7,
            sites_denied: 2,
            sites_rolled_back: 2,
            estimated_bytes_saved_per_sec: 0,
            estimated_allocs_avoided_per_sec: 0,
            estimated_gc_cycles_saved_per_min: 0,
            net_p50_improvement_ns: 0,
            net_p99_improvement_ns: 0,
            epoch: epoch(1),
            timestamp_ns: 0,
            report_digest: ContentHash::compute(b"x"),
        };
        assert_eq!(report.effective_elision_rate_millionths(), 500_000);
    }

    #[test]
    fn savings_report_zero_sites() {
        let report = ElisionSavingsReport {
            lane_id: lane("l"),
            total_sites_evaluated: 0,
            sites_approved: 0,
            sites_denied: 0,
            sites_rolled_back: 0,
            estimated_bytes_saved_per_sec: 0,
            estimated_allocs_avoided_per_sec: 0,
            estimated_gc_cycles_saved_per_min: 0,
            net_p50_improvement_ns: 0,
            net_p99_improvement_ns: 0,
            epoch: epoch(1),
            timestamp_ns: 0,
            report_digest: ContentHash::compute(b"x"),
        };
        assert_eq!(report.approval_rate_millionths(), 0);
        assert_eq!(report.effective_elision_rate_millionths(), 0);
    }

    // --- RollbackRecord tests ---

    #[test]
    fn rollback_record_exceeds_limit() {
        let r = RollbackRecord {
            site_id: site("s"),
            lane_id: lane("l"),
            trigger: RollbackTrigger::GcRegression,
            timestamp_ns: 1000,
            epoch: epoch(1),
            consecutive_count: MAX_CONSECUTIVE_ROLLBACKS,
            evidence_digest: ContentHash::compute(b"x"),
        };
        assert!(r.exceeds_limit());
    }

    #[test]
    fn rollback_record_under_limit() {
        let r = RollbackRecord {
            site_id: site("s"),
            lane_id: lane("l"),
            trigger: RollbackTrigger::LatencyRegression,
            timestamp_ns: 1000,
            epoch: epoch(1),
            consecutive_count: 1,
            evidence_digest: ContentHash::compute(b"x"),
        };
        assert!(!r.exceeds_limit());
    }

    #[test]
    fn rollback_record_digest_deterministic() {
        let r = RollbackRecord {
            site_id: site("s"),
            lane_id: lane("l"),
            trigger: RollbackTrigger::DeoptEvent,
            timestamp_ns: 1000,
            epoch: epoch(1),
            consecutive_count: 1,
            evidence_digest: ContentHash::compute(b"x"),
        };
        assert_eq!(r.digest(), r.digest());
    }

    // --- DeoptWitness tests ---

    #[test]
    fn deopt_witness_digest_deterministic() {
        let w = DeoptWitness {
            site_id: site("s"),
            lane_id: lane("l"),
            assumption_kind: AssumptionKind::NoEscape,
            timestamp_ns: 1000,
            epoch: epoch(1),
            stack_depth: 5,
            occurrence_count: 1,
            approval_receipt_digest: ContentHash::compute(b"r"),
        };
        assert_eq!(w.digest(), w.digest());
    }

    #[test]
    fn deopt_witness_different_assumption_different_digest() {
        let w1 = DeoptWitness {
            site_id: site("s"),
            lane_id: lane("l"),
            assumption_kind: AssumptionKind::NoEscape,
            timestamp_ns: 1000,
            epoch: epoch(1),
            stack_depth: 5,
            occurrence_count: 1,
            approval_receipt_digest: ContentHash::compute(b"r"),
        };
        let w2 = DeoptWitness {
            site_id: site("s"),
            lane_id: lane("l"),
            assumption_kind: AssumptionKind::StableShape,
            timestamp_ns: 1000,
            epoch: epoch(1),
            stack_depth: 5,
            occurrence_count: 1,
            approval_receipt_digest: ContentHash::compute(b"r"),
        };
        assert_ne!(w1.digest(), w2.digest());
    }

    // --- ElisionEvidenceBundle tests ---

    #[test]
    fn evidence_bundle_creation() {
        let bundle = ElisionEvidenceBundle::create(
            lane("l"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            epoch(1),
            1_000_000,
        );
        assert_eq!(bundle.schema_version, ELISION_GATE_SCHEMA_VERSION);
        assert_eq!(bundle.approval_count(), 0);
        assert_eq!(bundle.denial_count(), 0);
    }

    #[test]
    fn evidence_bundle_counts_approvals() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let r1 = ev.evaluate(&make_good_input("s1"));
        let r2 = ev.evaluate(&make_good_input("s2"));
        let mut bad = make_good_input("s3");
        bad.gc_assessment = bad_gc_assessment();
        let r3 = ev.evaluate(&bad);

        let bundle = ElisionEvidenceBundle::create(
            lane("l"),
            vec![r1.receipt, r2.receipt, r3.receipt],
            Vec::new(),
            Vec::new(),
            None,
            None,
            epoch(1),
            1_000_000,
        );
        assert_eq!(bundle.approval_count(), 2);
        assert_eq!(bundle.denial_count(), 1);
    }

    #[test]
    fn evidence_bundle_digest_deterministic() {
        let b1 = ElisionEvidenceBundle::create(
            lane("l"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            epoch(1),
            1_000_000,
        );
        let b2 = ElisionEvidenceBundle::create(
            lane("l"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            epoch(1),
            1_000_000,
        );
        assert_eq!(b1.bundle_digest, b2.bundle_digest);
    }

    // --- GateConfig tests ---

    #[test]
    fn gate_config_defaults() {
        let cfg = GateConfig::default();
        assert_eq!(
            cfg.max_gc_pause_regression_millionths,
            DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS
        );
        assert_eq!(
            cfg.max_tail_latency_regression_millionths,
            DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS
        );
        assert_eq!(
            cfg.min_support_coverage_millionths,
            DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS
        );
        assert_eq!(cfg.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
        assert!(cfg.require_observability_health);
        assert!(cfg.require_escape_certificate);
    }

    #[test]
    fn gate_config_custom() {
        let cfg = GateConfig {
            max_gc_pause_regression_millionths: 100_000,
            max_tail_latency_regression_millionths: 100_000,
            min_support_coverage_millionths: 0,
            min_sample_count: 10,
            rollback_cooldown_ns: 1_000_000,
            max_consecutive_rollbacks: 5,
            require_observability_health: false,
            require_escape_certificate: false,
        };
        assert!(!cfg.require_observability_health);
        assert!(!cfg.require_escape_certificate);
        assert_eq!(cfg.max_consecutive_rollbacks, 5);
    }

    // --- AllocationSiteId / LaneId tests ---

    #[test]
    fn allocation_site_id_display() {
        let s = site("fn_foo:line_42");
        assert_eq!(s.to_string(), "fn_foo:line_42");
        assert_eq!(s.as_str(), "fn_foo:line_42");
    }

    #[test]
    fn lane_id_display() {
        let l = lane("optimized-lane-7");
        assert_eq!(l.to_string(), "optimized-lane-7");
    }

    // --- Relaxed config tests ---

    #[test]
    fn evaluator_approve_without_observability_when_not_required() {
        let cfg = GateConfig {
            require_observability_health: false,
            ..GateConfig::default()
        };
        let mut ev = ElisionGateEvaluator::new(cfg);
        let mut input = make_good_input("site-relax-obs");
        input.observability = None;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Approved);
    }

    #[test]
    fn evaluator_approve_without_escape_cert_when_not_required() {
        let cfg = GateConfig {
            require_escape_certificate: false,
            ..GateConfig::default()
        };
        let mut ev = ElisionGateEvaluator::new(cfg);
        let mut input = make_good_input("site-relax-cert");
        input.has_escape_certificate = false;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Approved);
    }

    #[test]
    fn evaluator_approve_without_support_when_threshold_zero() {
        let cfg = GateConfig {
            min_support_coverage_millionths: 0,
            ..GateConfig::default()
        };
        let mut ev = ElisionGateEvaluator::new(cfg);
        let mut input = make_good_input("site-relax-support");
        input.support_contract = None;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Approved);
    }

    // --- Multiple denial reasons ---

    #[test]
    fn evaluator_multiple_denial_reasons() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let mut input = make_good_input("site-multi-deny");
        input.gc_assessment = bad_gc_assessment();
        input.latency_evidence = bad_latency_evidence();
        input.has_escape_certificate = false;
        input.observability = None;
        let result = ev.evaluate(&input);
        assert_eq!(result.verdict, ElisionVerdict::Denied);
        assert!(result.denial_reasons.len() >= 4);
    }

    // --- Receipt verification ---

    #[test]
    fn receipt_tampered_digest_fails_verification() {
        let mut ev = ElisionGateEvaluator::with_defaults();
        let input = make_good_input("site-tamper");
        let mut result = ev.evaluate(&input);
        result.receipt.receipt_digest = ContentHash::compute(b"tampered");
        assert!(!result.receipt.verify_digest());
    }

    // --- Concurrent site evaluations ---

    #[test]
    fn evaluator_independent_sites_independent_verdicts() {
        let mut ev = ElisionGateEvaluator::with_defaults();

        let good_result = ev.evaluate(&make_good_input("good-site"));
        assert_eq!(good_result.verdict, ElisionVerdict::Approved);

        let mut bad_input = make_good_input("bad-site");
        bad_input.gc_assessment = bad_gc_assessment();
        let bad_result = ev.evaluate(&bad_input);
        assert_eq!(bad_result.verdict, ElisionVerdict::Denied);

        // Good site unaffected.
        assert_eq!(
            ev.site_verdict("good-site"),
            Some(&ElisionVerdict::Approved)
        );
        assert_eq!(ev.site_verdict("bad-site"), Some(&ElisionVerdict::Denied));
    }

    // --- Hex encode ---

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // --- Constants ---

    #[test]
    fn million_constant_value() {
        assert_eq!(MILLION, 1_000_000);
    }

    #[test]
    fn schema_version_non_empty() {
        assert!(!ELISION_GATE_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(ELISION_GATE_BEAD_ID, "bd-1lsy.7.22.3");
    }

    #[test]
    fn component_name_non_empty() {
        assert!(!ELISION_GATE_COMPONENT.is_empty());
    }
}
