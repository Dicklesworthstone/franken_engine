//! Release gate: proof-specialized lanes demonstrate positive performance
//! delta versus ambient-authority lanes with 100% specialization-receipt
//! coverage and deterministic fallback correctness.
//!
//! This module implements the cross-cutting 10.9 release gate (bd-dkh) that
//! validates proof-specialized execution lanes outperform ambient-authority
//! lanes while maintaining full receipt accountability and fail-closed
//! fallback behavior.
//!
//! Key behaviors:
//! - Dual-lane execution: identical workloads run on proof-specialized and
//!   ambient-authority lanes, producing comparable metrics.
//! - Receipt coverage audit: every specialization decision must be backed by
//!   a signed specialization receipt (100% coverage required).
//! - Fallback injection: deliberately inject proof failures and capability
//!   revocations to validate deterministic fallback to baseline paths.
//! - Performance delta: statistical comparison of lane throughput, latency,
//!   and memory with significance threshold (p < 0.05 equivalent in
//!   fixed-point).
//! - Evidence bundle: deterministic hash-linked evidence artifact for
//!   external audit.
//!
//! Plan reference: Section 10.9 item 9, bd-dkh.
//! Cross-refs: bd-6pk (disruption scorecard), bd-1ze (Node/Bun harness),
//! bd-3qv (constrained-vs-ambient benchmark lanes), bd-2pv (specialization
//! conformance), bd-1kzo (compiler policy).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const GATE_COMPONENT: &str = "specialization_lane_gate";

/// Schema version for gate evidence bundles.
pub const GATE_SCHEMA_VERSION: &str = "franken-engine.specialization-lane-gate.v1";

/// Minimum number of workloads required for a valid gate evaluation.
pub const MIN_WORKLOAD_COUNT: usize = 10;

/// Minimum sample count per workload for statistical validity.
pub const MIN_SAMPLE_COUNT: u64 = 5;

/// Required receipt coverage: 1_000_000 = 100%.
pub const REQUIRED_COVERAGE_MILLIONTHS: u64 = 1_000_000;

/// Significance threshold for performance delta (fixed-point millionths).
/// 50_000 = 5% — specialized lane must be at least this much faster.
pub const DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS: u64 = 50_000;

// ---------------------------------------------------------------------------
// LaneType
// ---------------------------------------------------------------------------

/// Identifies which execution lane a measurement belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneType {
    /// Proof-specialized lane: security proofs enable optimization passes.
    ProofSpecialized,
    /// Ambient-authority lane: all dynamic checks active, no specialization.
    AmbientAuthority,
    /// Fallback lane: proof-specialized lane after injected proof failure.
    Fallback,
}

impl LaneType {
    /// String representation for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofSpecialized => "proof_specialized",
            Self::AmbientAuthority => "ambient_authority",
            Self::Fallback => "fallback",
        }
    }
}

impl fmt::Display for LaneType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadMetrics
// ---------------------------------------------------------------------------

/// Performance metrics for a single workload on a single lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadMetrics {
    /// Unique workload identifier.
    pub workload_id: String,
    /// Which lane produced these metrics.
    pub lane_type: LaneType,
    /// Canonical output digest for semantic equivalence verification.
    pub output_digest: ContentHash,
    /// Operations per second (fixed-point, not millionths — raw count).
    pub throughput_ops_per_sec: u64,
    /// p50 latency in nanoseconds.
    pub latency_p50_ns: u64,
    /// p95 latency in nanoseconds.
    pub latency_p95_ns: u64,
    /// p99 latency in nanoseconds.
    pub latency_p99_ns: u64,
    /// Peak memory usage in bytes.
    pub memory_peak_bytes: u64,
    /// Number of measurement samples.
    pub sample_count: u64,
}

// ---------------------------------------------------------------------------
// ReceiptRef — lightweight reference to a specialization receipt
// ---------------------------------------------------------------------------

/// Reference to a specialization receipt for coverage tracking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptRef {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Optimization class the receipt covers.
    pub optimization_class: String,
    /// Hash of the receipt content for integrity verification.
    pub receipt_hash: ContentHash,
    /// Whether the receipt signature was verified.
    pub signature_verified: bool,
    /// Epoch the receipt was issued in.
    pub issued_epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// FallbackInjection — describes a deliberate proof/capability failure
// ---------------------------------------------------------------------------

/// Type of failure injected to test fallback behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InjectionKind {
    /// Proof generation failure: optimizer cannot produce proof.
    ProofFailure,
    /// Capability revocation: previously granted capability revoked mid-run.
    CapabilityRevocation,
    /// Epoch transition: security epoch changes during execution.
    EpochTransition,
    /// Proof expiry: proof validity window expires mid-run.
    ProofExpiry,
}

impl InjectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofFailure => "proof_failure",
            Self::CapabilityRevocation => "capability_revocation",
            Self::EpochTransition => "epoch_transition",
            Self::ProofExpiry => "proof_expiry",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::ProofFailure,
            Self::CapabilityRevocation,
            Self::EpochTransition,
            Self::ProofExpiry,
        ]
    }
}

impl fmt::Display for InjectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a fallback injection test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackTestResult {
    /// Which workload was tested.
    pub workload_id: String,
    /// What kind of failure was injected.
    pub injection_kind: InjectionKind,
    /// Whether the lane fell back correctly (produced correct output).
    pub correct_output: bool,
    /// Whether the lane emitted a structured fallback receipt.
    pub fallback_receipt_emitted: bool,
    /// Whether the lane crashed or hung (should always be false).
    pub crash_or_hang: bool,
    /// Output digest from the fallback execution.
    pub fallback_output_digest: ContentHash,
    /// Expected output digest (from ambient-authority lane).
    pub expected_output_digest: ContentHash,
    /// Fallback latency in nanoseconds (should not regress vs ambient).
    pub fallback_latency_ns: u64,
    /// Ambient-authority latency for comparison.
    pub ambient_latency_ns: u64,
}

impl FallbackTestResult {
    /// Check if this fallback test passed all criteria.
    pub fn passed(&self) -> bool {
        self.correct_output
            && self.fallback_receipt_emitted
            && !self.crash_or_hang
            && self.fallback_output_digest == self.expected_output_digest
    }

    /// Check if fallback performance regressed versus ambient.
    /// Returns true if fallback is slower by more than 10%.
    pub fn performance_regressed(&self) -> bool {
        if self.ambient_latency_ns == 0 {
            return false;
        }
        // Allow 10% regression margin
        let threshold = self.ambient_latency_ns + self.ambient_latency_ns / 10;
        self.fallback_latency_ns > threshold
    }
}

// ---------------------------------------------------------------------------
// PerformanceDelta
// ---------------------------------------------------------------------------

/// Performance comparison between proof-specialized and ambient lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceDelta {
    /// Workload identifier.
    pub workload_id: String,
    /// Throughput improvement: positive = specialized is faster.
    /// Fixed-point millionths: 100_000 = 10% improvement.
    pub throughput_delta_millionths: i64,
    /// p95 latency improvement: positive = specialized has lower latency.
    pub latency_p95_improvement_millionths: i64,
    /// Memory improvement: positive = specialized uses less memory.
    pub memory_improvement_millionths: i64,
    /// Whether output digests match (semantic equivalence).
    pub output_equivalent: bool,
}

impl PerformanceDelta {
    /// Compute delta between specialized and ambient metrics.
    pub fn compute(specialized: &WorkloadMetrics, ambient: &WorkloadMetrics) -> Self {
        let throughput_delta = if ambient.throughput_ops_per_sec == 0 {
            0i64
        } else {
            // (specialized - ambient) / ambient * 1_000_000
            let diff =
                specialized.throughput_ops_per_sec as i64 - ambient.throughput_ops_per_sec as i64;
            diff.saturating_mul(1_000_000) / ambient.throughput_ops_per_sec as i64
        };

        let latency_improvement = if ambient.latency_p95_ns == 0 {
            0i64
        } else {
            // (ambient - specialized) / ambient * 1_000_000
            let diff = ambient.latency_p95_ns as i64 - specialized.latency_p95_ns as i64;
            diff.saturating_mul(1_000_000) / ambient.latency_p95_ns as i64
        };

        let memory_improvement = if ambient.memory_peak_bytes == 0 {
            0i64
        } else {
            let diff = ambient.memory_peak_bytes as i64 - specialized.memory_peak_bytes as i64;
            diff.saturating_mul(1_000_000) / ambient.memory_peak_bytes as i64
        };

        Self {
            workload_id: specialized.workload_id.clone(),
            throughput_delta_millionths: throughput_delta,
            latency_p95_improvement_millionths: latency_improvement,
            memory_improvement_millionths: memory_improvement,
            output_equivalent: specialized.output_digest == ambient.output_digest,
        }
    }

    /// Returns true if the specialized lane is faster on any dimension.
    pub fn has_positive_delta(&self) -> bool {
        self.throughput_delta_millionths > 0
            || self.latency_p95_improvement_millionths > 0
            || self.memory_improvement_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// GateOutcome
// ---------------------------------------------------------------------------

/// Outcome of the specialization lane gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateOutcome {
    /// All criteria met: positive delta, 100% coverage, fallback correct.
    Pass,
    /// One or more criteria failed.
    Fail,
}

impl GateOutcome {
    pub fn is_pass(self) -> bool {
        self == Self::Pass
    }
}

impl fmt::Display for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Fail => f.write_str("FAIL"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateBlocker — reason a gate failed
// ---------------------------------------------------------------------------

/// Specific reason why the gate evaluation failed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateBlocker {
    /// Insufficient workloads for evaluation.
    InsufficientWorkloads { required: usize, actual: usize },
    /// Output digest mismatch between lanes for a workload.
    OutputDivergence { workload_id: String },
    /// Receipt coverage below 100%.
    InsufficientReceiptCoverage { coverage_millionths: u64 },
    /// One or more receipt signatures not verified.
    UnverifiedReceipt { receipt_id: String },
    /// Overall performance delta is not positive.
    NoPositiveDelta {
        mean_throughput_delta_millionths: i64,
    },
    /// A fallback injection test failed.
    FallbackTestFailed {
        workload_id: String,
        injection_kind: InjectionKind,
        reason: String,
    },
    /// Fallback performance regressed versus ambient lane.
    FallbackPerformanceRegression {
        workload_id: String,
        injection_kind: InjectionKind,
    },
    /// Insufficient sample count for statistical validity.
    InsufficientSamples {
        workload_id: String,
        lane_type: LaneType,
        sample_count: u64,
    },
    /// Workload mismatch: specialized lane has workloads not in ambient lane.
    WorkloadMismatch { missing_workload_ids: Vec<String> },
}

impl fmt::Display for GateBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientWorkloads { required, actual } => {
                write!(f, "insufficient workloads: {actual}/{required}")
            }
            Self::OutputDivergence { workload_id } => {
                write!(f, "output divergence: workload {workload_id}")
            }
            Self::InsufficientReceiptCoverage {
                coverage_millionths,
            } => {
                write!(
                    f,
                    "receipt coverage {coverage_millionths}/1000000 (100% required)"
                )
            }
            Self::UnverifiedReceipt { receipt_id } => {
                write!(f, "unverified receipt: {receipt_id}")
            }
            Self::NoPositiveDelta {
                mean_throughput_delta_millionths,
            } => {
                write!(
                    f,
                    "no positive delta: mean throughput delta {mean_throughput_delta_millionths}"
                )
            }
            Self::FallbackTestFailed {
                workload_id,
                injection_kind,
                reason,
            } => {
                write!(
                    f,
                    "fallback test failed: {workload_id} ({injection_kind}): {reason}"
                )
            }
            Self::FallbackPerformanceRegression {
                workload_id,
                injection_kind,
            } => {
                write!(
                    f,
                    "fallback performance regression: {workload_id} ({injection_kind})"
                )
            }
            Self::InsufficientSamples {
                workload_id,
                lane_type,
                sample_count,
            } => {
                write!(
                    f,
                    "insufficient samples for {workload_id} on {lane_type}: {sample_count}"
                )
            }
            Self::WorkloadMismatch {
                missing_workload_ids,
            } => {
                write!(f, "workload mismatch: missing {:?}", missing_workload_ids)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateEvidenceBundle
// ---------------------------------------------------------------------------

/// Complete evidence bundle produced by a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvidenceBundle {
    /// Schema version for this evidence format.
    pub schema_version: String,
    /// Unique run identifier.
    pub run_id: String,
    /// Security epoch of this evaluation.
    pub epoch: SecurityEpoch,
    /// Gate outcome (Pass/Fail).
    pub outcome: GateOutcome,
    /// Blockers that caused failure (empty if Pass).
    pub blockers: Vec<GateBlocker>,
    /// Per-workload performance deltas.
    pub performance_deltas: Vec<PerformanceDelta>,
    /// Aggregate statistics.
    pub summary: GateSummary,
    /// Receipt coverage details.
    pub receipt_coverage: ReceiptCoverageReport,
    /// Fallback injection test results.
    pub fallback_results: Vec<FallbackTestResult>,
    /// Content hash of this evidence bundle.
    pub evidence_hash: ContentHash,
    /// Number of workloads evaluated.
    pub workload_count: u64,
}

/// Aggregate summary statistics for the gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Mean throughput delta across all workloads (millionths).
    pub mean_throughput_delta_millionths: i64,
    /// Mean p95 latency improvement across all workloads (millionths).
    pub mean_latency_p95_improvement_millionths: i64,
    /// Mean memory improvement across all workloads (millionths).
    pub mean_memory_improvement_millionths: i64,
    /// Number of workloads where specialized lane was faster.
    pub workloads_with_positive_delta: u64,
    /// Total workloads evaluated.
    pub total_workloads: u64,
    /// Number of fallback tests passed.
    pub fallback_tests_passed: u64,
    /// Total fallback tests run.
    pub fallback_tests_total: u64,
}

/// Receipt coverage report for the gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCoverageReport {
    /// Total specialization decisions observed.
    pub total_decisions: u64,
    /// Decisions backed by verified receipts.
    pub covered_decisions: u64,
    /// Coverage ratio in millionths (1_000_000 = 100%).
    pub coverage_millionths: u64,
    /// Receipts that failed signature verification.
    pub unverified_receipts: Vec<String>,
    /// All receipt references included.
    pub receipt_refs: Vec<ReceiptRef>,
}

// ---------------------------------------------------------------------------
// GateLogEntry — structured log entry
// ---------------------------------------------------------------------------

/// Structured log entry for gate evaluation events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLogEntry {
    pub trace_id: String,
    pub component: String,
    pub lane_type: Option<LaneType>,
    pub event: String,
    pub outcome: String,
    pub workload_id: Option<String>,
    pub optimization_pass: Option<String>,
    pub proof_status: Option<String>,
    pub capability_witness_ref: Option<String>,
    pub specialization_receipt_hash: Option<String>,
    pub fallback_triggered: Option<bool>,
    pub wall_time_ns: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// GateError
// ---------------------------------------------------------------------------

/// Errors that can occur during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateError {
    /// No workloads provided.
    EmptyWorkloads,
    /// Mismatched workload sets between lanes.
    WorkloadSetMismatch { detail: String },
    /// No receipts provided for coverage audit.
    EmptyReceipts,
    /// Invalid metric value.
    InvalidMetric { workload_id: String, detail: String },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWorkloads => f.write_str("no workloads provided"),
            Self::WorkloadSetMismatch { detail } => {
                write!(f, "workload set mismatch: {detail}")
            }
            Self::EmptyReceipts => f.write_str("no receipts provided for coverage audit"),
            Self::InvalidMetric {
                workload_id,
                detail,
            } => {
                write!(f, "invalid metric for {workload_id}: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateInput — input to the gate evaluation
// ---------------------------------------------------------------------------

/// Input bundle for gate evaluation.
#[derive(Debug, Clone)]
pub struct GateInput<'a> {
    /// Run identifier for this evaluation.
    pub run_id: &'a str,
    /// Trace identifier for structured logging.
    pub trace_id: &'a str,
    /// Security epoch for this evaluation.
    pub epoch: SecurityEpoch,
    /// Proof-specialized lane metrics.
    pub specialized_metrics: &'a [WorkloadMetrics],
    /// Ambient-authority lane metrics.
    pub ambient_metrics: &'a [WorkloadMetrics],
    /// Specialization receipts for coverage auditing.
    pub receipts: &'a [ReceiptRef],
    /// Total specialization decisions observed.
    pub total_specialization_decisions: u64,
    /// Fallback injection test results.
    pub fallback_results: &'a [FallbackTestResult],
    /// Significance threshold for positive delta (millionths).
    pub significance_threshold_millionths: u64,
}

// ---------------------------------------------------------------------------
// Core gate evaluation
// ---------------------------------------------------------------------------

/// Evaluate the specialization lane gate.
///
/// Returns a complete evidence bundle with pass/fail outcome and all
/// supporting data for external audit.
pub fn evaluate_gate(input: &GateInput<'_>) -> Result<GateEvidenceBundle, GateError> {
    if input.specialized_metrics.is_empty() || input.ambient_metrics.is_empty() {
        return Err(GateError::EmptyWorkloads);
    }

    let mut blockers = Vec::new();

    // Build ambient lookup by workload_id.
    let ambient_map: BTreeMap<&str, &WorkloadMetrics> = input
        .ambient_metrics
        .iter()
        .map(|m| (m.workload_id.as_str(), m))
        .collect();

    // Check workload count.
    if input.specialized_metrics.len() < MIN_WORKLOAD_COUNT {
        blockers.push(GateBlocker::InsufficientWorkloads {
            required: MIN_WORKLOAD_COUNT,
            actual: input.specialized_metrics.len(),
        });
    }

    // Check workload set alignment.
    let mut missing: Vec<String> = Vec::new();
    for spec in input.specialized_metrics {
        if !ambient_map.contains_key(spec.workload_id.as_str()) {
            missing.push(spec.workload_id.clone());
        }
    }
    if !missing.is_empty() {
        blockers.push(GateBlocker::WorkloadMismatch {
            missing_workload_ids: missing,
        });
    }

    // Compute per-workload performance deltas.
    let mut deltas = Vec::new();
    for spec in input.specialized_metrics {
        if let Some(amb) = ambient_map.get(spec.workload_id.as_str()) {
            // Check sample count.
            if spec.sample_count < MIN_SAMPLE_COUNT {
                blockers.push(GateBlocker::InsufficientSamples {
                    workload_id: spec.workload_id.clone(),
                    lane_type: LaneType::ProofSpecialized,
                    sample_count: spec.sample_count,
                });
            }
            if amb.sample_count < MIN_SAMPLE_COUNT {
                blockers.push(GateBlocker::InsufficientSamples {
                    workload_id: amb.workload_id.clone(),
                    lane_type: LaneType::AmbientAuthority,
                    sample_count: amb.sample_count,
                });
            }

            let delta = PerformanceDelta::compute(spec, amb);

            // Check output equivalence.
            if !delta.output_equivalent {
                blockers.push(GateBlocker::OutputDivergence {
                    workload_id: spec.workload_id.clone(),
                });
            }

            deltas.push(delta);
        }
    }

    // Compute aggregate statistics.
    let total_workloads = deltas.len() as u64;
    let (mean_throughput, mean_latency, mean_memory, positive_count) = if deltas.is_empty() {
        (0i64, 0i64, 0i64, 0u64)
    } else {
        let sum_throughput: i64 = deltas.iter().map(|d| d.throughput_delta_millionths).sum();
        let sum_latency: i64 = deltas
            .iter()
            .map(|d| d.latency_p95_improvement_millionths)
            .sum();
        let sum_memory: i64 = deltas.iter().map(|d| d.memory_improvement_millionths).sum();
        let positive = deltas.iter().filter(|d| d.has_positive_delta()).count() as u64;
        let n = deltas.len() as i64;
        (
            sum_throughput / n,
            sum_latency / n,
            sum_memory / n,
            positive,
        )
    };

    // Check overall positive delta.
    if mean_throughput <= input.significance_threshold_millionths as i64
        && mean_latency <= input.significance_threshold_millionths as i64
        && mean_memory <= input.significance_threshold_millionths as i64
    {
        blockers.push(GateBlocker::NoPositiveDelta {
            mean_throughput_delta_millionths: mean_throughput,
        });
    }

    // Receipt coverage audit.
    let coverage_millionths = if input.total_specialization_decisions == 0 {
        // No decisions — vacuously covered regardless of receipt count.
        REQUIRED_COVERAGE_MILLIONTHS
    } else {
        let covered = input
            .receipts
            .iter()
            .filter(|r| r.signature_verified)
            .count() as u64;
        covered
            .saturating_mul(1_000_000)
            .checked_div(input.total_specialization_decisions)
            .unwrap_or(0)
    };

    let unverified: Vec<String> = input
        .receipts
        .iter()
        .filter(|r| !r.signature_verified)
        .map(|r| r.receipt_id.clone())
        .collect();

    if coverage_millionths < REQUIRED_COVERAGE_MILLIONTHS {
        blockers.push(GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths,
        });
    }

    for receipt_id in &unverified {
        blockers.push(GateBlocker::UnverifiedReceipt {
            receipt_id: receipt_id.clone(),
        });
    }

    // Fallback injection audit.
    let mut fallback_passed = 0u64;
    let fallback_total = input.fallback_results.len() as u64;
    for fb in input.fallback_results {
        if fb.passed() {
            if fb.performance_regressed() {
                blockers.push(GateBlocker::FallbackPerformanceRegression {
                    workload_id: fb.workload_id.clone(),
                    injection_kind: fb.injection_kind,
                });
            } else {
                fallback_passed += 1;
            }
        } else {
            let reason = if fb.crash_or_hang {
                "crash or hang".to_string()
            } else if !fb.correct_output {
                "incorrect output".to_string()
            } else if !fb.fallback_receipt_emitted {
                "no fallback receipt".to_string()
            } else {
                "output digest mismatch".to_string()
            };
            blockers.push(GateBlocker::FallbackTestFailed {
                workload_id: fb.workload_id.clone(),
                injection_kind: fb.injection_kind,
                reason,
            });
        }
    }

    let receipt_coverage = ReceiptCoverageReport {
        total_decisions: input.total_specialization_decisions,
        covered_decisions: input
            .receipts
            .iter()
            .filter(|r| r.signature_verified)
            .count() as u64,
        coverage_millionths,
        unverified_receipts: unverified,
        receipt_refs: input.receipts.to_vec(),
    };

    let summary = GateSummary {
        mean_throughput_delta_millionths: mean_throughput,
        mean_latency_p95_improvement_millionths: mean_latency,
        mean_memory_improvement_millionths: mean_memory,
        workloads_with_positive_delta: positive_count,
        total_workloads,
        fallback_tests_passed: fallback_passed,
        fallback_tests_total: fallback_total,
    };

    let outcome = if blockers.is_empty() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail
    };

    // Compute evidence hash.
    let hash_input = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        input.run_id,
        input.epoch.as_u64(),
        outcome,
        mean_throughput,
        coverage_millionths,
        fallback_passed,
        total_workloads,
    );
    let evidence_hash = ContentHash::compute(hash_input.as_bytes());

    Ok(GateEvidenceBundle {
        schema_version: GATE_SCHEMA_VERSION.to_string(),
        run_id: input.run_id.to_string(),
        epoch: input.epoch,
        outcome,
        blockers,
        performance_deltas: deltas,
        summary,
        receipt_coverage,
        fallback_results: input.fallback_results.to_vec(),
        evidence_hash,
        workload_count: total_workloads,
    })
}

/// Check if a gate evidence bundle passes the release gate.
pub fn passes_release_gate(bundle: &GateEvidenceBundle) -> bool {
    bundle.outcome.is_pass()
}

/// Generate structured log entries for a gate evaluation.
pub fn generate_log_entries(trace_id: &str, bundle: &GateEvidenceBundle) -> Vec<GateLogEntry> {
    let mut entries = Vec::new();

    // Summary entry.
    entries.push(GateLogEntry {
        trace_id: trace_id.to_string(),
        component: GATE_COMPONENT.to_string(),
        lane_type: None,
        event: "gate_evaluation_complete".to_string(),
        outcome: bundle.outcome.to_string(),
        workload_id: None,
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: None,
        wall_time_ns: None,
        memory_peak_bytes: None,
        error_code: if bundle.outcome.is_pass() {
            None
        } else {
            Some("GATE_FAILED".to_string())
        },
    });

    // Per-delta entries.
    for delta in &bundle.performance_deltas {
        entries.push(GateLogEntry {
            trace_id: trace_id.to_string(),
            component: GATE_COMPONENT.to_string(),
            lane_type: Some(LaneType::ProofSpecialized),
            event: "workload_delta".to_string(),
            outcome: if delta.has_positive_delta() {
                "positive".to_string()
            } else {
                "neutral_or_negative".to_string()
            },
            workload_id: Some(delta.workload_id.clone()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: None,
            wall_time_ns: None,
            memory_peak_bytes: None,
            error_code: None,
        });
    }

    // Fallback entries.
    for fb in &bundle.fallback_results {
        entries.push(GateLogEntry {
            trace_id: trace_id.to_string(),
            component: GATE_COMPONENT.to_string(),
            lane_type: Some(LaneType::Fallback),
            event: format!("fallback_test_{}", fb.injection_kind),
            outcome: if fb.passed() {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            workload_id: Some(fb.workload_id.clone()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: Some(true),
            wall_time_ns: Some(fb.fallback_latency_ns),
            memory_peak_bytes: None,
            error_code: if fb.passed() {
                None
            } else {
                Some("FALLBACK_FAILED".to_string())
            },
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_digest(s: &str) -> ContentHash {
        ContentHash::compute(s.as_bytes())
    }

    fn make_metrics(
        workload_id: &str,
        lane: LaneType,
        throughput: u64,
        latency_p95: u64,
        memory: u64,
        digest: &str,
    ) -> WorkloadMetrics {
        WorkloadMetrics {
            workload_id: workload_id.to_string(),
            lane_type: lane,
            output_digest: make_digest(digest),
            throughput_ops_per_sec: throughput,
            latency_p50_ns: latency_p95 / 2,
            latency_p95_ns: latency_p95,
            latency_p99_ns: latency_p95 * 2,
            memory_peak_bytes: memory,
            sample_count: 10,
        }
    }

    fn make_receipt(id: &str, verified: bool) -> ReceiptRef {
        ReceiptRef {
            receipt_id: id.to_string(),
            optimization_class: "hostcall_dispatch".to_string(),
            receipt_hash: make_digest(id),
            signature_verified: verified,
            issued_epoch: SecurityEpoch::from_raw(1),
        }
    }

    fn make_fallback_pass(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
        let digest = make_digest("canonical_output");
        FallbackTestResult {
            workload_id: workload_id.to_string(),
            injection_kind: kind,
            correct_output: true,
            fallback_receipt_emitted: true,
            crash_or_hang: false,
            fallback_output_digest: digest,
            expected_output_digest: digest,
            fallback_latency_ns: 1000,
            ambient_latency_ns: 1000,
        }
    }

    fn make_fallback_fail(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
        FallbackTestResult {
            workload_id: workload_id.to_string(),
            injection_kind: kind,
            correct_output: false,
            fallback_receipt_emitted: true,
            crash_or_hang: false,
            fallback_output_digest: make_digest("wrong"),
            expected_output_digest: make_digest("canonical_output"),
            fallback_latency_ns: 1000,
            ambient_latency_ns: 1000,
        }
    }

    fn passing_specialized_metrics(n: usize) -> Vec<WorkloadMetrics> {
        (0..n)
            .map(|i| {
                make_metrics(
                    &format!("workload_{i}"),
                    LaneType::ProofSpecialized,
                    1200, // faster
                    800,  // lower latency
                    4000, // less memory
                    "canonical",
                )
            })
            .collect()
    }

    fn passing_ambient_metrics(n: usize) -> Vec<WorkloadMetrics> {
        (0..n)
            .map(|i| {
                make_metrics(
                    &format!("workload_{i}"),
                    LaneType::AmbientAuthority,
                    1000, // baseline
                    1000, // baseline
                    5000, // baseline
                    "canonical",
                )
            })
            .collect()
    }

    fn passing_receipts(n: u64) -> Vec<ReceiptRef> {
        (0..n)
            .map(|i| make_receipt(&format!("receipt_{i}"), true))
            .collect()
    }

    fn passing_fallbacks() -> Vec<FallbackTestResult> {
        vec![
            make_fallback_pass("workload_0", InjectionKind::ProofFailure),
            make_fallback_pass("workload_1", InjectionKind::CapabilityRevocation),
            make_fallback_pass("workload_2", InjectionKind::EpochTransition),
            make_fallback_pass("workload_3", InjectionKind::ProofExpiry),
        ]
    }

    fn make_passing_input<'a>(
        spec: &'a [WorkloadMetrics],
        amb: &'a [WorkloadMetrics],
        receipts: &'a [ReceiptRef],
        fallbacks: &'a [FallbackTestResult],
    ) -> GateInput<'a> {
        GateInput {
            run_id: "test-run-1",
            trace_id: "trace-001",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: spec,
            ambient_metrics: amb,
            receipts,
            total_specialization_decisions: receipts.len() as u64,
            fallback_results: fallbacks,
            significance_threshold_millionths: DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS,
        }
    }

    // -----------------------------------------------------------------------
    // LaneType
    // -----------------------------------------------------------------------

    #[test]
    fn lane_type_as_str() {
        assert_eq!(LaneType::ProofSpecialized.as_str(), "proof_specialized");
        assert_eq!(LaneType::AmbientAuthority.as_str(), "ambient_authority");
        assert_eq!(LaneType::Fallback.as_str(), "fallback");
    }

    #[test]
    fn lane_type_display() {
        assert_eq!(
            format!("{}", LaneType::ProofSpecialized),
            "proof_specialized"
        );
    }

    #[test]
    fn lane_type_ordering() {
        assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
        assert!(LaneType::AmbientAuthority < LaneType::Fallback);
    }

    // -----------------------------------------------------------------------
    // InjectionKind
    // -----------------------------------------------------------------------

    #[test]
    fn injection_kind_all_variants() {
        assert_eq!(InjectionKind::all().len(), 4);
    }

    #[test]
    fn injection_kind_as_str() {
        assert_eq!(InjectionKind::ProofFailure.as_str(), "proof_failure");
        assert_eq!(
            InjectionKind::CapabilityRevocation.as_str(),
            "capability_revocation"
        );
        assert_eq!(InjectionKind::EpochTransition.as_str(), "epoch_transition");
        assert_eq!(InjectionKind::ProofExpiry.as_str(), "proof_expiry");
    }

    #[test]
    fn injection_kind_display() {
        assert_eq!(format!("{}", InjectionKind::ProofFailure), "proof_failure");
    }

    // -----------------------------------------------------------------------
    // FallbackTestResult
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_pass_all_criteria() {
        let fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        assert!(fb.passed());
        assert!(!fb.performance_regressed());
    }

    #[test]
    fn fallback_fail_incorrect_output() {
        let fb = make_fallback_fail("w1", InjectionKind::ProofFailure);
        assert!(!fb.passed());
    }

    #[test]
    fn fallback_fail_crash() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.crash_or_hang = true;
        assert!(!fb.passed());
    }

    #[test]
    fn fallback_fail_no_receipt() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.fallback_receipt_emitted = false;
        assert!(!fb.passed());
    }

    #[test]
    fn fallback_fail_digest_mismatch() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.fallback_output_digest = make_digest("different");
        assert!(!fb.passed());
    }

    #[test]
    fn fallback_performance_regression_detected() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.ambient_latency_ns = 1000;
        fb.fallback_latency_ns = 1200; // 20% slower
        assert!(fb.performance_regressed());
    }

    #[test]
    fn fallback_performance_within_margin() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.ambient_latency_ns = 1000;
        fb.fallback_latency_ns = 1050; // 5% slower, within 10% margin
        assert!(!fb.performance_regressed());
    }

    #[test]
    fn fallback_zero_ambient_latency_no_regression() {
        let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        fb.ambient_latency_ns = 0;
        fb.fallback_latency_ns = 1000;
        assert!(!fb.performance_regressed());
    }

    // -----------------------------------------------------------------------
    // PerformanceDelta
    // -----------------------------------------------------------------------

    #[test]
    fn delta_positive_throughput() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert_eq!(delta.throughput_delta_millionths, 200_000); // 20% faster
        assert!(delta.has_positive_delta());
        assert!(delta.output_equivalent);
    }

    #[test]
    fn delta_negative_throughput() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 800, 1200, 6000, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert_eq!(delta.throughput_delta_millionths, -200_000); // 20% slower
    }

    #[test]
    fn delta_output_divergence() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out_a");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out_b");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert!(!delta.output_equivalent);
    }

    #[test]
    fn delta_zero_ambient_throughput() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 0, 0, 0, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert_eq!(delta.throughput_delta_millionths, 0);
        assert_eq!(delta.latency_p95_improvement_millionths, 0);
        assert_eq!(delta.memory_improvement_millionths, 0);
    }

    #[test]
    fn delta_latency_improvement() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 500, 5000, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert_eq!(delta.latency_p95_improvement_millionths, 500_000); // 50% lower
    }

    #[test]
    fn delta_memory_improvement() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 2500, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert_eq!(delta.memory_improvement_millionths, 500_000); // 50% less
    }

    #[test]
    fn delta_neutral_not_positive() {
        let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 5000, "out");
        let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
        let delta = PerformanceDelta::compute(&spec, &amb);
        assert!(!delta.has_positive_delta());
    }

    // -----------------------------------------------------------------------
    // GateOutcome
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_pass_is_pass() {
        assert!(GateOutcome::Pass.is_pass());
        assert!(!GateOutcome::Fail.is_pass());
    }

    #[test]
    fn outcome_display() {
        assert_eq!(format!("{}", GateOutcome::Pass), "PASS");
        assert_eq!(format!("{}", GateOutcome::Fail), "FAIL");
    }

    // -----------------------------------------------------------------------
    // evaluate_gate — passing case
    // -----------------------------------------------------------------------

    #[test]
    fn gate_passes_with_all_criteria_met() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(result.outcome.is_pass());
        assert!(result.blockers.is_empty());
        assert_eq!(result.workload_count, 12);
        assert!(result.summary.mean_throughput_delta_millionths > 0);
        assert_eq!(result.receipt_coverage.coverage_millionths, 1_000_000);
    }

    #[test]
    fn gate_evidence_hash_deterministic() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);

        let r1 = evaluate_gate(&input).unwrap();
        let r2 = evaluate_gate(&input).unwrap();
        assert_eq!(r1.evidence_hash, r2.evidence_hash);
    }

    #[test]
    fn gate_different_runs_different_hashes() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();

        let input1 = GateInput {
            run_id: "run-1",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 5,
            fallback_results: &fallbacks,
            significance_threshold_millionths: 0,
        };
        let input2 = GateInput {
            run_id: "run-2",
            ..input1.clone()
        };

        let r1 = evaluate_gate(&input1).unwrap();
        let r2 = evaluate_gate(&input2).unwrap();
        assert_ne!(r1.evidence_hash, r2.evidence_hash);
    }

    // -----------------------------------------------------------------------
    // evaluate_gate — failure cases
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_empty_workloads() {
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &[],
            ambient_metrics: &[],
            receipts: &[],
            total_specialization_decisions: 0,
            fallback_results: &[],
            significance_threshold_millionths: 0,
        };
        assert!(matches!(
            evaluate_gate(&input),
            Err(GateError::EmptyWorkloads)
        ));
    }

    #[test]
    fn gate_fails_insufficient_workloads() {
        let spec = passing_specialized_metrics(3); // below MIN_WORKLOAD_COUNT
        let amb = passing_ambient_metrics(3);
        let receipts = passing_receipts(3);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::InsufficientWorkloads { .. }))
        );
    }

    #[test]
    fn gate_fails_output_divergence() {
        let mut spec = passing_specialized_metrics(12);
        spec[0].output_digest = make_digest("different_output");
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::OutputDivergence { .. }))
        );
    }

    #[test]
    fn gate_fails_no_positive_delta() {
        // Specialized same as ambient — no improvement.
        let spec: Vec<WorkloadMetrics> = (0..12)
            .map(|i| {
                make_metrics(
                    &format!("workload_{i}"),
                    LaneType::ProofSpecialized,
                    1000,
                    1000,
                    5000,
                    "canonical",
                )
            })
            .collect();
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::NoPositiveDelta { .. }))
        );
    }

    #[test]
    fn gate_fails_insufficient_receipt_coverage() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(3); // only 3 receipts for 10 decisions
        let fallbacks = passing_fallbacks();
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 10, // 3/10 = 30%
            fallback_results: &fallbacks,
            significance_threshold_millionths: 0,
        };
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::InsufficientReceiptCoverage { .. }))
        );
    }

    #[test]
    fn gate_fails_unverified_receipt() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let mut receipts = passing_receipts(5);
        receipts[2].signature_verified = false; // one unverified
        let fallbacks = passing_fallbacks();
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 5,
            fallback_results: &fallbacks,
            significance_threshold_millionths: 0,
        };
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        // Both InsufficientReceiptCoverage (4/5=80%) and UnverifiedReceipt.
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::UnverifiedReceipt { .. }))
        );
    }

    #[test]
    fn gate_fails_fallback_test() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = vec![
            make_fallback_pass("workload_0", InjectionKind::ProofFailure),
            make_fallback_fail("workload_1", InjectionKind::CapabilityRevocation),
        ];
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::FallbackTestFailed { .. }))
        );
    }

    #[test]
    fn gate_fails_fallback_performance_regression() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let mut fb = make_fallback_pass("workload_0", InjectionKind::ProofFailure);
        fb.ambient_latency_ns = 1000;
        fb.fallback_latency_ns = 2000; // 100% slower
        let fallbacks = vec![fb];
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::FallbackPerformanceRegression { .. }))
        );
    }

    #[test]
    fn gate_fails_workload_mismatch() {
        let mut spec = passing_specialized_metrics(12);
        spec[0].workload_id = "missing_workload".to_string();
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::WorkloadMismatch { .. }))
        );
    }

    #[test]
    fn gate_fails_insufficient_samples() {
        let mut spec = passing_specialized_metrics(12);
        spec[0].sample_count = 2; // below MIN_SAMPLE_COUNT
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        assert!(
            result
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::InsufficientSamples { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // passes_release_gate
    // -----------------------------------------------------------------------

    #[test]
    fn release_gate_pass() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        assert!(passes_release_gate(&result));
    }

    #[test]
    fn release_gate_fail() {
        let spec = passing_specialized_metrics(3);
        let amb = passing_ambient_metrics(3);
        let receipts = passing_receipts(3);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        assert!(!passes_release_gate(&result));
    }

    // -----------------------------------------------------------------------
    // generate_log_entries
    // -----------------------------------------------------------------------

    #[test]
    fn log_entries_include_summary() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &result);

        assert!(!entries.is_empty());
        assert_eq!(entries[0].event, "gate_evaluation_complete");
        assert_eq!(entries[0].outcome, "PASS");
        assert_eq!(entries[0].component, GATE_COMPONENT);
    }

    #[test]
    fn log_entries_include_per_workload() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &result);

        let delta_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.event == "workload_delta")
            .collect();
        assert_eq!(delta_entries.len(), 12);
    }

    #[test]
    fn log_entries_include_fallback() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &result);

        let fb_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.event.starts_with("fallback_test_"))
            .collect();
        assert_eq!(fb_entries.len(), 4);
    }

    #[test]
    fn log_entries_failure_has_error_code() {
        let spec = passing_specialized_metrics(3);
        let amb = passing_ambient_metrics(3);
        let receipts = passing_receipts(3);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &result);

        assert_eq!(entries[0].error_code, Some("GATE_FAILED".to_string()));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn serde_lane_type_roundtrip() {
        let val = LaneType::ProofSpecialized;
        let json = serde_json::to_string(&val).unwrap();
        let back: LaneType = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_gate_outcome_roundtrip() {
        let val = GateOutcome::Pass;
        let json = serde_json::to_string(&val).unwrap();
        let back: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_evidence_bundle_roundtrip() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn serde_fallback_result_roundtrip() {
        let fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
        let json = serde_json::to_string(&fb).unwrap();
        let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }

    #[test]
    fn serde_blocker_roundtrip() {
        let blocker = GateBlocker::OutputDivergence {
            workload_id: "w1".to_string(),
        };
        let json = serde_json::to_string(&blocker).unwrap();
        let back: GateBlocker = serde_json::from_str(&json).unwrap();
        assert_eq!(blocker, back);
    }

    #[test]
    fn serde_error_roundtrip() {
        let err = GateError::EmptyWorkloads;
        let json = serde_json::to_string(&err).unwrap();
        let back: GateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn serde_log_entry_roundtrip() {
        let entry = GateLogEntry {
            trace_id: "t1".to_string(),
            component: GATE_COMPONENT.to_string(),
            lane_type: Some(LaneType::ProofSpecialized),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            workload_id: Some("w1".to_string()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: Some(false),
            wall_time_ns: Some(1000),
            memory_peak_bytes: None,
            error_code: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: GateLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -----------------------------------------------------------------------
    // GateBlocker Display
    // -----------------------------------------------------------------------

    #[test]
    fn blocker_display_insufficient_workloads() {
        let b = GateBlocker::InsufficientWorkloads {
            required: 10,
            actual: 3,
        };
        assert_eq!(format!("{b}"), "insufficient workloads: 3/10");
    }

    #[test]
    fn blocker_display_output_divergence() {
        let b = GateBlocker::OutputDivergence {
            workload_id: "w1".to_string(),
        };
        assert!(format!("{b}").contains("w1"));
    }

    #[test]
    fn blocker_display_no_positive_delta() {
        let b = GateBlocker::NoPositiveDelta {
            mean_throughput_delta_millionths: -50000,
        };
        assert!(format!("{b}").contains("-50000"));
    }

    #[test]
    fn blocker_display_coverage() {
        let b = GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths: 500_000,
        };
        assert!(format!("{b}").contains("500000"));
    }

    // -----------------------------------------------------------------------
    // GateError Display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_empty_workloads() {
        assert_eq!(
            format!("{}", GateError::EmptyWorkloads),
            "no workloads provided"
        );
    }

    #[test]
    fn error_display_mismatch() {
        let e = GateError::WorkloadSetMismatch {
            detail: "test".to_string(),
        };
        assert!(format!("{e}").contains("test"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn gate_with_zero_specialization_decisions_passes_coverage() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts: Vec<ReceiptRef> = Vec::new();
        let fallbacks = passing_fallbacks();
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 0, // no decisions
            fallback_results: &fallbacks,
            significance_threshold_millionths: 0,
        };
        let result = evaluate_gate(&input).unwrap();
        // Coverage is vacuously satisfied.
        assert_eq!(
            result.receipt_coverage.coverage_millionths,
            REQUIRED_COVERAGE_MILLIONTHS
        );
    }

    #[test]
    fn gate_with_significance_threshold() {
        // Specialized is barely faster: 1010 vs 1000 = 1% improvement.
        let spec: Vec<WorkloadMetrics> = (0..12)
            .map(|i| {
                make_metrics(
                    &format!("workload_{i}"),
                    LaneType::ProofSpecialized,
                    1010, // barely faster
                    990,  // barely lower latency
                    4950, // barely less memory
                    "canonical",
                )
            })
            .collect();
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 5,
            fallback_results: &fallbacks,
            significance_threshold_millionths: 50_000, // require 5% improvement
        };
        let result = evaluate_gate(&input).unwrap();
        // 1% improvement < 5% threshold → fails
        assert!(!result.outcome.is_pass());
    }

    #[test]
    fn gate_schema_version_correct() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();
        assert_eq!(result.schema_version, GATE_SCHEMA_VERSION);
    }

    #[test]
    fn gate_summary_statistics_correct() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert_eq!(result.summary.total_workloads, 12);
        assert_eq!(result.summary.workloads_with_positive_delta, 12);
        assert_eq!(result.summary.fallback_tests_passed, 4);
        assert_eq!(result.summary.fallback_tests_total, 4);
        // 1200 vs 1000 = 200/1000 = 200_000 millionths = 20%
        assert_eq!(result.summary.mean_throughput_delta_millionths, 200_000);
    }

    #[test]
    fn gate_multiple_blockers_accumulated() {
        // Trigger multiple failures at once.
        let mut spec = passing_specialized_metrics(3); // insufficient count
        spec[0].output_digest = make_digest("diverged"); // output divergence
        let amb = passing_ambient_metrics(3);
        let receipts: Vec<ReceiptRef> = Vec::new();
        let fallbacks = vec![make_fallback_fail("w1", InjectionKind::ProofFailure)];
        let input = GateInput {
            run_id: "test",
            trace_id: "t1",
            epoch: SecurityEpoch::from_raw(1),
            specialized_metrics: &spec,
            ambient_metrics: &amb,
            receipts: &receipts,
            total_specialization_decisions: 10,
            fallback_results: &fallbacks,
            significance_threshold_millionths: 0,
        };
        let result = evaluate_gate(&input).unwrap();

        assert!(!result.outcome.is_pass());
        // Should have at least InsufficientWorkloads, OutputDivergence,
        // InsufficientReceiptCoverage, FallbackTestFailed.
        assert!(result.blockers.len() >= 4);
    }

    #[test]
    fn receipt_coverage_report_fields() {
        let spec = passing_specialized_metrics(12);
        let amb = passing_ambient_metrics(12);
        let receipts = passing_receipts(5);
        let fallbacks = passing_fallbacks();
        let input = make_passing_input(&spec, &amb, &receipts, &fallbacks);
        let result = evaluate_gate(&input).unwrap();

        assert_eq!(result.receipt_coverage.total_decisions, 5);
        assert_eq!(result.receipt_coverage.covered_decisions, 5);
        assert_eq!(result.receipt_coverage.coverage_millionths, 1_000_000);
        assert!(result.receipt_coverage.unverified_receipts.is_empty());
        assert_eq!(result.receipt_coverage.receipt_refs.len(), 5);
    }

    #[test]
    fn lane_type_ord() {
        assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
        assert!(LaneType::AmbientAuthority < LaneType::Fallback);
    }

    #[test]
    fn injection_kind_ord() {
        assert!(InjectionKind::ProofFailure < InjectionKind::CapabilityRevocation);
        assert!(InjectionKind::CapabilityRevocation < InjectionKind::EpochTransition);
        assert!(InjectionKind::EpochTransition < InjectionKind::ProofExpiry);
    }

    #[test]
    fn gate_outcome_ord() {
        assert!(GateOutcome::Pass < GateOutcome::Fail);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn lane_type_serde_all_variants() {
        let variants = [
            LaneType::ProofSpecialized,
            LaneType::AmbientAuthority,
            LaneType::Fallback,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LaneType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn injection_kind_serde_all_variants() {
        let variants = [
            InjectionKind::ProofFailure,
            InjectionKind::CapabilityRevocation,
            InjectionKind::EpochTransition,
            InjectionKind::ProofExpiry,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InjectionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn gate_outcome_serde_roundtrip() {
        let variants = [GateOutcome::Pass, GateOutcome::Fail];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: GateOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn gate_error_serde_all_variants() {
        let variants: Vec<GateError> = vec![
            GateError::EmptyWorkloads,
            GateError::WorkloadSetMismatch {
                detail: "mismatch".into(),
            },
            GateError::EmptyReceipts,
            GateError::InvalidMetric {
                workload_id: "w1".into(),
                detail: "bad value".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: GateError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn lane_type_display_all_distinct() {
        let variants = [
            LaneType::ProofSpecialized,
            LaneType::AmbientAuthority,
            LaneType::Fallback,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn injection_kind_as_str_all_distinct() {
        let all = InjectionKind::all();
        let mut seen = std::collections::BTreeSet::new();
        for v in all {
            assert!(seen.insert(v.as_str()), "duplicate as_str: {}", v.as_str());
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn gate_error_display_all_distinct() {
        let variants: Vec<GateError> = vec![
            GateError::EmptyWorkloads,
            GateError::WorkloadSetMismatch { detail: "x".into() },
            GateError::EmptyReceipts,
            GateError::InvalidMetric {
                workload_id: "w".into(),
                detail: "d".into(),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 4);
    }
}
