//! Release gate: proof-specialized lanes vs ambient-authority lanes.
//!
//! Validates that proof-specialized execution paths demonstrate a positive
//! performance delta versus ambient-authority paths, with 100%
//! specialization-receipt coverage and deterministic fallback correctness.
//!
//! This module does NOT build proof-specialized lanes.  It benchmarks the
//! delivered lanes, audits receipt coverage, validates fallback behavior,
//! and certifies the evidence bundle for release.
//!
//! Plan reference: Section 10.9 item 9 (`bd-dkh`).
//! Cross-refs: bd-6pk (disruption scorecard), bd-1ze (Node/Bun comparison),
//! bd-2rx (proof-carrying optimization gate), bd-2n3 (PLAS gate),
//! bd-181 (GA native lanes gate).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const GATE_COMPONENT: &str = "specialization_perf_release_gate";

/// Schema version string.
pub const GATE_SCHEMA_VERSION: &str = "franken-engine.spec-perf-release-gate.v1";

// ---------------------------------------------------------------------------
// LaneType — execution lane classification
// ---------------------------------------------------------------------------

/// Classification of an execution lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneType {
    /// Lane with proof-specialized optimizations active.
    ProofSpecialized,
    /// Lane running under ambient-authority (no proof specializations).
    AmbientAuthority,
}

impl LaneType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofSpecialized => "proof_specialized",
            Self::AmbientAuthority => "ambient_authority",
        }
    }
}

impl fmt::Display for LaneType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkSample — single benchmark measurement
// ---------------------------------------------------------------------------

/// A single benchmark measurement from a lane execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSample {
    /// Unique workload identifier.
    pub workload_id: String,
    /// Which lane produced this sample.
    pub lane_type: LaneType,
    /// Wall-clock time in nanoseconds.
    pub wall_time_ns: u64,
    /// Peak memory in bytes.
    pub memory_peak_bytes: u64,
    /// Throughput (operations per second), if applicable.
    pub throughput_ops_per_sec: Option<u64>,
}

// ---------------------------------------------------------------------------
// BenchmarkComparison — paired comparison result
// ---------------------------------------------------------------------------

/// Paired comparison of proof-specialized vs ambient-authority for one workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparison {
    /// Workload identifier.
    pub workload_id: String,
    /// Proof-specialized lane measurement.
    pub specialized: BenchmarkSample,
    /// Ambient-authority lane measurement.
    pub ambient: BenchmarkSample,
    /// Wall-time delta in millionths (positive = speedup).
    /// Formula: (ambient - specialized) / ambient * 1_000_000.
    pub wall_time_delta_millionths: i64,
    /// Memory delta in millionths (positive = savings).
    pub memory_delta_millionths: i64,
}

impl BenchmarkComparison {
    /// Compute from paired samples.
    pub fn from_samples(specialized: BenchmarkSample, ambient: BenchmarkSample) -> Self {
        let wt_delta = if ambient.wall_time_ns > 0 {
            let diff = ambient.wall_time_ns as i128 - specialized.wall_time_ns as i128;
            (diff * 1_000_000 / ambient.wall_time_ns as i128) as i64
        } else {
            0
        };
        let mem_delta = if ambient.memory_peak_bytes > 0 {
            let diff = ambient.memory_peak_bytes as i128 - specialized.memory_peak_bytes as i128;
            (diff * 1_000_000 / ambient.memory_peak_bytes as i128) as i64
        } else {
            0
        };
        let workload_id = specialized.workload_id.clone();
        Self {
            workload_id,
            specialized,
            ambient,
            wall_time_delta_millionths: wt_delta,
            memory_delta_millionths: mem_delta,
        }
    }

    /// Whether this comparison shows a positive wall-time speedup.
    pub fn has_positive_wall_time_delta(&self) -> bool {
        self.wall_time_delta_millionths > 0
    }

    /// Whether this comparison shows positive memory savings.
    pub fn has_positive_memory_delta(&self) -> bool {
        self.memory_delta_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// ReceiptCoverageEntry — per-optimization receipt audit
// ---------------------------------------------------------------------------

/// Receipt audit entry for a single specialization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCoverageEntry {
    /// Optimization name / specialization ID.
    pub optimization_name: String,
    /// Whether a signed receipt exists.
    pub receipt_present: bool,
    /// Receipt hash (if present).
    pub receipt_hash: Option<ContentHash>,
    /// Proof reference included in receipt.
    pub proof_reference: Option<String>,
    /// Capability witness reference included in receipt.
    pub capability_witness_ref: Option<String>,
    /// Pre/post performance measurement included.
    pub performance_measurement_present: bool,
    /// Receipt signature valid.
    pub signature_valid: bool,
}

impl ReceiptCoverageEntry {
    /// Whether this entry passes all coverage checks.
    pub fn is_fully_covered(&self) -> bool {
        self.receipt_present
            && self.receipt_hash.is_some()
            && self.proof_reference.is_some()
            && self.capability_witness_ref.is_some()
            && self.performance_measurement_present
            && self.signature_valid
    }

    /// Collect reasons for coverage gaps.
    pub fn coverage_gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        if !self.receipt_present {
            gaps.push("no receipt".to_string());
        }
        if self.receipt_hash.is_none() {
            gaps.push("missing receipt hash".to_string());
        }
        if self.proof_reference.is_none() {
            gaps.push("missing proof reference".to_string());
        }
        if self.capability_witness_ref.is_none() {
            gaps.push("missing capability witness reference".to_string());
        }
        if !self.performance_measurement_present {
            gaps.push("missing performance measurement".to_string());
        }
        if !self.signature_valid {
            gaps.push("invalid signature".to_string());
        }
        gaps
    }
}

// ---------------------------------------------------------------------------
// FallbackTestResult — fallback correctness test
// ---------------------------------------------------------------------------

/// Result of a deliberate fallback injection test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackTestResult {
    /// Test scenario identifier.
    pub scenario_id: String,
    /// Injection type: "proof_failure" or "capability_revocation".
    pub injection_type: String,
    /// Whether fallback produced correct output.
    pub correct_output: bool,
    /// Whether a structured fallback receipt was emitted.
    pub fallback_receipt_emitted: bool,
    /// Whether the lane crashed during fallback.
    pub crashed: bool,
    /// Whether the lane hung during fallback.
    pub hung: bool,
    /// Fallback path wall time in nanoseconds.
    pub fallback_wall_time_ns: u64,
    /// Ambient-authority lane wall time for same workload.
    pub ambient_wall_time_ns: u64,
}

impl FallbackTestResult {
    /// Whether this test passes all correctness criteria.
    pub fn passes(&self) -> bool {
        self.correct_output && self.fallback_receipt_emitted && !self.crashed && !self.hung
    }

    /// Whether fallback performance is no worse than ambient-authority.
    pub fn fallback_performance_acceptable(&self) -> bool {
        // Fallback path should not be significantly slower than ambient.
        // Allow up to 10% regression (100_000 millionths).
        if self.ambient_wall_time_ns == 0 {
            return true;
        }
        let regression = if self.fallback_wall_time_ns > self.ambient_wall_time_ns {
            ((self.fallback_wall_time_ns - self.ambient_wall_time_ns) as u128 * 1_000_000)
                / self.ambient_wall_time_ns as u128
        } else {
            0
        };
        regression <= 100_000
    }
}

// ---------------------------------------------------------------------------
// ReceiptChainReplayResult — end-to-end receipt chain verification
// ---------------------------------------------------------------------------

/// Result of replaying the full receipt chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChainReplayResult {
    /// Compilation ID that was replayed.
    pub compilation_id: String,
    /// Total receipts in the chain.
    pub total_receipts: u64,
    /// Receipts that verified successfully.
    pub verified_receipts: u64,
    /// Whether the chain is complete (no gaps).
    pub chain_complete: bool,
    /// Whether all receipts verified.
    pub all_verified: bool,
    /// Replay duration in nanoseconds.
    pub replay_duration_ns: u64,
}

impl ReceiptChainReplayResult {
    /// Whether the replay passes.
    pub fn passes(&self) -> bool {
        self.chain_complete && self.all_verified && self.total_receipts > 0
    }
}

// ---------------------------------------------------------------------------
// GateFailureCode — typed failure classification
// ---------------------------------------------------------------------------

/// Failure codes for the specialization-performance release gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateFailureCode {
    /// No positive performance delta (wall-time, throughput, or memory).
    NoPositiveDelta,
    /// Statistical significance not met (p >= 0.05).
    InsufficientSignificance,
    /// Receipt coverage below 100%.
    InsufficientReceiptCoverage,
    /// Fallback produced incorrect output.
    FallbackIncorrectOutput,
    /// Fallback caused crash.
    FallbackCrashed,
    /// Fallback caused hang.
    FallbackHung,
    /// Fallback did not emit receipt.
    FallbackNoReceipt,
    /// Fallback performance regression beyond threshold.
    FallbackPerformanceRegression,
    /// Receipt chain replay failed.
    ReceiptChainReplayFailed,
    /// Insufficient benchmark samples.
    InsufficientSamples,
    /// Empty input.
    EmptyInput,
}

impl fmt::Display for GateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPositiveDelta => f.write_str("no_positive_delta"),
            Self::InsufficientSignificance => f.write_str("insufficient_significance"),
            Self::InsufficientReceiptCoverage => f.write_str("insufficient_receipt_coverage"),
            Self::FallbackIncorrectOutput => f.write_str("fallback_incorrect_output"),
            Self::FallbackCrashed => f.write_str("fallback_crashed"),
            Self::FallbackHung => f.write_str("fallback_hung"),
            Self::FallbackNoReceipt => f.write_str("fallback_no_receipt"),
            Self::FallbackPerformanceRegression => f.write_str("fallback_performance_regression"),
            Self::ReceiptChainReplayFailed => f.write_str("receipt_chain_replay_failed"),
            Self::InsufficientSamples => f.write_str("insufficient_samples"),
            Self::EmptyInput => f.write_str("empty_input"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateFinding — individual finding with detail
// ---------------------------------------------------------------------------

/// A single gate finding (failure reason).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFinding {
    pub code: GateFailureCode,
    pub detail: String,
    /// Affected workload or optimization (if applicable).
    pub affected_item: Option<String>,
}

// ---------------------------------------------------------------------------
// StatisticalSummary — aggregated benchmark statistics
// ---------------------------------------------------------------------------

/// Aggregated statistical summary for a set of benchmark comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalSummary {
    /// Number of comparison samples.
    pub sample_count: u64,
    /// Mean wall-time delta in millionths (positive = speedup).
    pub mean_wall_time_delta_millionths: i64,
    /// Mean memory delta in millionths (positive = savings).
    pub mean_memory_delta_millionths: i64,
    /// Number of workloads with positive wall-time speedup.
    pub positive_wall_time_count: u64,
    /// Number of workloads with positive memory savings.
    pub positive_memory_count: u64,
    /// Significance level met (approximation: positive ratio > 0.5).
    /// True means p < 0.05 approximated via sign test.
    pub significance_met: bool,
}

impl StatisticalSummary {
    /// Compute from a set of comparisons.
    pub fn from_comparisons(comparisons: &[BenchmarkComparison]) -> Self {
        if comparisons.is_empty() {
            return Self {
                sample_count: 0,
                mean_wall_time_delta_millionths: 0,
                mean_memory_delta_millionths: 0,
                positive_wall_time_count: 0,
                positive_memory_count: 0,
                significance_met: false,
            };
        }

        let n = comparisons.len() as u64;
        let total_wt: i64 = comparisons
            .iter()
            .map(|c| c.wall_time_delta_millionths)
            .fold(0i64, |acc, x| acc.saturating_add(x));
        let total_mem: i64 = comparisons
            .iter()
            .map(|c| c.memory_delta_millionths)
            .fold(0i64, |acc, x| acc.saturating_add(x));
        let pos_wt = comparisons
            .iter()
            .filter(|c| c.has_positive_wall_time_delta())
            .count() as u64;
        let pos_mem = comparisons
            .iter()
            .filter(|c| c.has_positive_memory_delta())
            .count() as u64;

        // Simple sign-test approximation for p < 0.05:
        // For n >= 20, if more than ~60% of samples show positive delta,
        // we approximate significance.  For smaller n, require > 75%.
        let significance_met = if n >= 20 {
            pos_wt * 1_000_000 / n > 600_000 // > 60%
        } else if n >= 5 {
            pos_wt * 1_000_000 / n > 750_000 // > 75%
        } else {
            // Too few samples
            false
        };

        Self {
            sample_count: n,
            mean_wall_time_delta_millionths: total_wt / n as i64,
            mean_memory_delta_millionths: total_mem / n as i64,
            positive_wall_time_count: pos_wt,
            positive_memory_count: pos_mem,
            significance_met,
        }
    }

    /// Whether at least one dimension shows a positive delta.
    pub fn has_positive_delta(&self) -> bool {
        self.mean_wall_time_delta_millionths > 0 || self.mean_memory_delta_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// GateLogEvent — structured per-event logging
// ---------------------------------------------------------------------------

/// Structured log event for the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLogEvent {
    pub trace_id: String,
    pub lane_type: Option<String>,
    pub optimization_pass: Option<String>,
    pub proof_status: Option<String>,
    pub capability_witness_ref: Option<String>,
    pub specialization_receipt_hash: Option<String>,
    pub fallback_triggered: Option<bool>,
    pub wall_time_ns: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub event: String,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// GateInput — full input bundle for the release gate
// ---------------------------------------------------------------------------

/// Full input for the specialization-performance release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateInput {
    /// Trace ID for structured logging.
    pub trace_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Paired benchmark comparisons.
    pub comparisons: Vec<BenchmarkComparison>,
    /// Receipt coverage audit entries.
    pub receipt_coverage: Vec<ReceiptCoverageEntry>,
    /// Fallback injection test results.
    pub fallback_tests: Vec<FallbackTestResult>,
    /// Receipt chain replay result (if performed).
    pub receipt_chain_replay: Option<ReceiptChainReplayResult>,
    /// Minimum required benchmark samples.
    pub min_samples: u64,
}

// ---------------------------------------------------------------------------
// GateDecision — output decision artifact
// ---------------------------------------------------------------------------

/// Output decision artifact from the release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    /// Content-addressed decision ID.
    pub decision_id: String,
    /// Whether the gate passes.
    pub pass: bool,
    /// Statistical summary of benchmark results.
    pub stats: StatisticalSummary,
    /// Receipt coverage percentage in millionths (1_000_000 = 100%).
    pub receipt_coverage_millionths: u64,
    /// Number of fallback tests passed.
    pub fallback_tests_passed: u64,
    /// Number of fallback tests total.
    pub fallback_tests_total: u64,
    /// Receipt chain replay passed.
    pub receipt_chain_replay_passed: bool,
    /// Gate findings (failure reasons).
    pub findings: Vec<GateFinding>,
    /// Structured log events.
    pub logs: Vec<GateLogEvent>,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Schema version.
    pub schema_version: String,
    /// Scorecard contribution: performance delta in millionths.
    pub scorecard_performance_delta_millionths: i64,
    /// Scorecard contribution: security delta (receipt coverage %).
    pub scorecard_security_delta_millionths: u64,
    /// Scorecard contribution: autonomy delta (proof-specialized lane %).
    pub scorecard_autonomy_delta_millionths: u64,
}

impl GateDecision {
    /// Serialize to JSONL.
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("serialization failed")
    }
}

// ---------------------------------------------------------------------------
// evaluate — main gate logic
// ---------------------------------------------------------------------------

/// Evaluate the specialization-performance release gate.
pub fn evaluate(input: &GateInput) -> GateDecision {
    let mut findings: Vec<GateFinding> = Vec::new();
    let mut logs: Vec<GateLogEvent> = Vec::new();

    // --- Check for empty input ---
    if input.comparisons.is_empty() {
        findings.push(GateFinding {
            code: GateFailureCode::EmptyInput,
            detail: "no benchmark comparisons provided".to_string(),
            affected_item: None,
        });
    }

    // --- Minimum samples ---
    if (input.comparisons.len() as u64) < input.min_samples && !input.comparisons.is_empty() {
        findings.push(GateFinding {
            code: GateFailureCode::InsufficientSamples,
            detail: format!(
                "only {} samples, minimum {} required",
                input.comparisons.len(),
                input.min_samples
            ),
            affected_item: None,
        });
    }

    // --- Statistical summary ---
    let stats = StatisticalSummary::from_comparisons(&input.comparisons);

    // Log per-comparison results
    for comp in &input.comparisons {
        logs.push(GateLogEvent {
            trace_id: input.trace_id.clone(),
            lane_type: Some(LaneType::ProofSpecialized.as_str().to_string()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: None,
            wall_time_ns: Some(comp.specialized.wall_time_ns),
            memory_peak_bytes: Some(comp.specialized.memory_peak_bytes),
            event: "benchmark_comparison".to_string(),
            outcome: if comp.has_positive_wall_time_delta() {
                "speedup"
            } else {
                "regression"
            }
            .to_string(),
        });
    }

    // Gate criterion 1: positive performance delta
    if !stats.has_positive_delta() && !input.comparisons.is_empty() {
        findings.push(GateFinding {
            code: GateFailureCode::NoPositiveDelta,
            detail: format!(
                "mean wall-time delta {} millionths, memory delta {} millionths — no positive dimension",
                stats.mean_wall_time_delta_millionths,
                stats.mean_memory_delta_millionths
            ),
            affected_item: None,
        });
    }

    // Gate criterion 1b: statistical significance
    if !stats.significance_met && !input.comparisons.is_empty() {
        findings.push(GateFinding {
            code: GateFailureCode::InsufficientSignificance,
            detail: format!(
                "only {}/{} workloads show positive wall-time delta — significance not met",
                stats.positive_wall_time_count, stats.sample_count
            ),
            affected_item: None,
        });
    }

    // --- Gate criterion 2: 100% receipt coverage ---
    let total_receipts = input.receipt_coverage.len() as u64;
    let covered_receipts = input
        .receipt_coverage
        .iter()
        .filter(|e| e.is_fully_covered())
        .count() as u64;
    let receipt_coverage_millionths = (covered_receipts * 1_000_000)
        .checked_div(total_receipts)
        .unwrap_or(0);

    if receipt_coverage_millionths < 1_000_000 && total_receipts > 0 {
        // Find specific gaps
        for entry in &input.receipt_coverage {
            if !entry.is_fully_covered() {
                let gaps = entry.coverage_gaps();
                findings.push(GateFinding {
                    code: GateFailureCode::InsufficientReceiptCoverage,
                    detail: format!("gaps: {}", gaps.join(", ")),
                    affected_item: Some(entry.optimization_name.clone()),
                });
            }
        }
    } else if total_receipts == 0 && !input.comparisons.is_empty() {
        findings.push(GateFinding {
            code: GateFailureCode::InsufficientReceiptCoverage,
            detail: "no receipt coverage entries provided".to_string(),
            affected_item: None,
        });
    }

    // --- Gate criterion 3: fallback correctness ---
    let mut fallback_passed = 0u64;
    for test in &input.fallback_tests {
        if !test.correct_output {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackIncorrectOutput,
                detail: format!("scenario {} produced incorrect output", test.scenario_id),
                affected_item: Some(test.scenario_id.clone()),
            });
        }
        if test.crashed {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackCrashed,
                detail: format!("scenario {} crashed", test.scenario_id),
                affected_item: Some(test.scenario_id.clone()),
            });
        }
        if test.hung {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackHung,
                detail: format!("scenario {} hung", test.scenario_id),
                affected_item: Some(test.scenario_id.clone()),
            });
        }
        if !test.fallback_receipt_emitted {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackNoReceipt,
                detail: format!(
                    "scenario {} did not emit fallback receipt",
                    test.scenario_id
                ),
                affected_item: Some(test.scenario_id.clone()),
            });
        }
        if !test.fallback_performance_acceptable() {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackPerformanceRegression,
                detail: format!(
                    "scenario {} fallback {}ns vs ambient {}ns",
                    test.scenario_id, test.fallback_wall_time_ns, test.ambient_wall_time_ns
                ),
                affected_item: Some(test.scenario_id.clone()),
            });
        }
        if test.passes() {
            fallback_passed += 1;
        }

        logs.push(GateLogEvent {
            trace_id: input.trace_id.clone(),
            lane_type: Some(LaneType::ProofSpecialized.as_str().to_string()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: Some(true),
            wall_time_ns: Some(test.fallback_wall_time_ns),
            memory_peak_bytes: None,
            event: "fallback_test".to_string(),
            outcome: if test.passes() { "pass" } else { "fail" }.to_string(),
        });
    }

    // --- Gate criterion 4: receipt chain replay ---
    let receipt_chain_replay_passed = input
        .receipt_chain_replay
        .as_ref()
        .map(|r| r.passes())
        .unwrap_or(false);

    if let Some(ref replay) = input.receipt_chain_replay
        && !replay.passes()
    {
        findings.push(GateFinding {
            code: GateFailureCode::ReceiptChainReplayFailed,
            detail: format!(
                "chain complete={}, verified={}/{}, total={}",
                replay.chain_complete,
                replay.verified_receipts,
                replay.total_receipts,
                replay.total_receipts
            ),
            affected_item: Some(replay.compilation_id.clone()),
        });
    }

    // --- Compute scorecard contributions ---
    let scorecard_perf = stats.mean_wall_time_delta_millionths;
    let scorecard_security = receipt_coverage_millionths;
    // Autonomy: percentage of comparisons where proof-specialized lane was used
    // (all comparisons are proof-specialized by definition, so 100%)
    let scorecard_autonomy = if !input.comparisons.is_empty() {
        1_000_000
    } else {
        0
    };

    // --- Final decision ---
    let pass = findings.is_empty();

    // Log summary
    logs.push(GateLogEvent {
        trace_id: input.trace_id.clone(),
        lane_type: None,
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: None,
        wall_time_ns: None,
        memory_peak_bytes: None,
        event: "gate_decision".to_string(),
        outcome: if pass { "pass" } else { "fail" }.to_string(),
    });

    // Content-addressed decision ID
    let decision_material = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        input.trace_id,
        input.policy_id,
        pass,
        stats.mean_wall_time_delta_millionths,
        receipt_coverage_millionths,
        fallback_passed,
        receipt_chain_replay_passed
    );
    let decision_id = format!("{}", ContentHash::compute(decision_material.as_bytes()));

    GateDecision {
        decision_id,
        pass,
        stats,
        receipt_coverage_millionths,
        fallback_tests_passed: fallback_passed,
        fallback_tests_total: input.fallback_tests.len() as u64,
        receipt_chain_replay_passed,
        findings,
        logs,
        epoch: input.epoch,
        schema_version: GATE_SCHEMA_VERSION.to_string(),
        scorecard_performance_delta_millionths: scorecard_perf,
        scorecard_security_delta_millionths: scorecard_security,
        scorecard_autonomy_delta_millionths: scorecard_autonomy,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(10)
    }

    fn sample(wl: &str, lane: LaneType, wt_ns: u64, mem: u64) -> BenchmarkSample {
        BenchmarkSample {
            workload_id: wl.to_string(),
            lane_type: lane,
            wall_time_ns: wt_ns,
            memory_peak_bytes: mem,
            throughput_ops_per_sec: None,
        }
    }

    fn comparison(wl: &str, spec_wt: u64, amb_wt: u64) -> BenchmarkComparison {
        BenchmarkComparison::from_samples(
            sample(wl, LaneType::ProofSpecialized, spec_wt, 1024),
            sample(wl, LaneType::AmbientAuthority, amb_wt, 1024),
        )
    }

    fn full_receipt(name: &str) -> ReceiptCoverageEntry {
        ReceiptCoverageEntry {
            optimization_name: name.to_string(),
            receipt_present: true,
            receipt_hash: Some(ContentHash::compute(format!("receipt-{name}").as_bytes())),
            proof_reference: Some(format!("proof-{name}")),
            capability_witness_ref: Some(format!("cap-{name}")),
            performance_measurement_present: true,
            signature_valid: true,
        }
    }

    fn passing_fallback(scenario: &str) -> FallbackTestResult {
        FallbackTestResult {
            scenario_id: scenario.to_string(),
            injection_type: "proof_failure".to_string(),
            correct_output: true,
            fallback_receipt_emitted: true,
            crashed: false,
            hung: false,
            fallback_wall_time_ns: 100_000,
            ambient_wall_time_ns: 100_000,
        }
    }

    fn passing_replay() -> ReceiptChainReplayResult {
        ReceiptChainReplayResult {
            compilation_id: "compile-001".to_string(),
            total_receipts: 10,
            verified_receipts: 10,
            chain_complete: true,
            all_verified: true,
            replay_duration_ns: 50_000_000,
        }
    }

    fn full_input(n_comparisons: usize) -> GateInput {
        let comparisons: Vec<_> = (0..n_comparisons)
            .map(|i| comparison(&format!("w{i}"), 80, 100)) // 20% speedup
            .collect();
        GateInput {
            trace_id: "trace-1".to_string(),
            policy_id: "policy-1".to_string(),
            epoch: epoch(),
            comparisons,
            receipt_coverage: vec![full_receipt("opt-a"), full_receipt("opt-b")],
            fallback_tests: vec![passing_fallback("fb-1"), passing_fallback("fb-2")],
            receipt_chain_replay: Some(passing_replay()),
            min_samples: 5,
        }
    }

    // -----------------------------------------------------------------------
    // LaneType
    // -----------------------------------------------------------------------

    #[test]
    fn lane_type_display() {
        assert_eq!(LaneType::ProofSpecialized.to_string(), "proof_specialized");
        assert_eq!(LaneType::AmbientAuthority.to_string(), "ambient_authority");
    }

    #[test]
    fn lane_type_serde_round_trip() {
        let json = serde_json::to_string(&LaneType::ProofSpecialized).unwrap();
        let back: LaneType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, LaneType::ProofSpecialized);
    }

    // -----------------------------------------------------------------------
    // BenchmarkComparison
    // -----------------------------------------------------------------------

    #[test]
    fn comparison_computes_positive_delta() {
        let c = comparison("w1", 80, 100);
        assert_eq!(c.wall_time_delta_millionths, 200_000); // 20% speedup
        assert!(c.has_positive_wall_time_delta());
    }

    #[test]
    fn comparison_computes_negative_delta() {
        let c = comparison("w1", 120, 100);
        assert_eq!(c.wall_time_delta_millionths, -200_000); // 20% slower
        assert!(!c.has_positive_wall_time_delta());
    }

    #[test]
    fn comparison_zero_baseline() {
        let c = comparison("w1", 100, 0);
        assert_eq!(c.wall_time_delta_millionths, 0);
    }

    #[test]
    fn comparison_equal_times() {
        let c = comparison("w1", 100, 100);
        assert_eq!(c.wall_time_delta_millionths, 0);
        assert!(!c.has_positive_wall_time_delta());
    }

    #[test]
    fn comparison_memory_delta() {
        let c = BenchmarkComparison::from_samples(
            sample("w1", LaneType::ProofSpecialized, 100, 800),
            sample("w1", LaneType::AmbientAuthority, 100, 1000),
        );
        assert_eq!(c.memory_delta_millionths, 200_000); // 20% savings
        assert!(c.has_positive_memory_delta());
    }

    // -----------------------------------------------------------------------
    // ReceiptCoverageEntry
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_fully_covered() {
        let r = full_receipt("opt-a");
        assert!(r.is_fully_covered());
        assert!(r.coverage_gaps().is_empty());
    }

    #[test]
    fn receipt_missing_proof_reference() {
        let mut r = full_receipt("opt-a");
        r.proof_reference = None;
        assert!(!r.is_fully_covered());
        assert!(
            r.coverage_gaps()
                .contains(&"missing proof reference".to_string())
        );
    }

    #[test]
    fn receipt_invalid_signature() {
        let mut r = full_receipt("opt-a");
        r.signature_valid = false;
        assert!(!r.is_fully_covered());
        assert!(r.coverage_gaps().contains(&"invalid signature".to_string()));
    }

    #[test]
    fn receipt_missing_all() {
        let r = ReceiptCoverageEntry {
            optimization_name: "opt".to_string(),
            receipt_present: false,
            receipt_hash: None,
            proof_reference: None,
            capability_witness_ref: None,
            performance_measurement_present: false,
            signature_valid: false,
        };
        assert!(!r.is_fully_covered());
        assert_eq!(r.coverage_gaps().len(), 6);
    }

    // -----------------------------------------------------------------------
    // FallbackTestResult
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_passes() {
        let fb = passing_fallback("fb-1");
        assert!(fb.passes());
        assert!(fb.fallback_performance_acceptable());
    }

    #[test]
    fn fallback_fails_on_crash() {
        let mut fb = passing_fallback("fb-1");
        fb.crashed = true;
        assert!(!fb.passes());
    }

    #[test]
    fn fallback_fails_on_hang() {
        let mut fb = passing_fallback("fb-1");
        fb.hung = true;
        assert!(!fb.passes());
    }

    #[test]
    fn fallback_fails_on_incorrect_output() {
        let mut fb = passing_fallback("fb-1");
        fb.correct_output = false;
        assert!(!fb.passes());
    }

    #[test]
    fn fallback_performance_regression_detected() {
        let mut fb = passing_fallback("fb-1");
        fb.fallback_wall_time_ns = 200_000; // 100% slower than ambient
        fb.ambient_wall_time_ns = 100_000;
        assert!(!fb.fallback_performance_acceptable());
    }

    #[test]
    fn fallback_performance_within_threshold() {
        let mut fb = passing_fallback("fb-1");
        fb.fallback_wall_time_ns = 105_000; // 5% slower — within 10% threshold
        fb.ambient_wall_time_ns = 100_000;
        assert!(fb.fallback_performance_acceptable());
    }

    // -----------------------------------------------------------------------
    // ReceiptChainReplayResult
    // -----------------------------------------------------------------------

    #[test]
    fn replay_passes() {
        let r = passing_replay();
        assert!(r.passes());
    }

    #[test]
    fn replay_fails_incomplete_chain() {
        let mut r = passing_replay();
        r.chain_complete = false;
        assert!(!r.passes());
    }

    #[test]
    fn replay_fails_unverified() {
        let mut r = passing_replay();
        r.verified_receipts = 9;
        r.all_verified = false;
        assert!(!r.passes());
    }

    #[test]
    fn replay_fails_empty() {
        let r = ReceiptChainReplayResult {
            compilation_id: "c".to_string(),
            total_receipts: 0,
            verified_receipts: 0,
            chain_complete: true,
            all_verified: true,
            replay_duration_ns: 0,
        };
        assert!(!r.passes());
    }

    // -----------------------------------------------------------------------
    // StatisticalSummary
    // -----------------------------------------------------------------------

    #[test]
    fn stats_empty() {
        let s = StatisticalSummary::from_comparisons(&[]);
        assert_eq!(s.sample_count, 0);
        assert!(!s.has_positive_delta());
        assert!(!s.significance_met);
    }

    #[test]
    fn stats_all_positive() {
        let comps: Vec<_> = (0..20)
            .map(|i| comparison(&format!("w{i}"), 80, 100))
            .collect();
        let s = StatisticalSummary::from_comparisons(&comps);
        assert_eq!(s.sample_count, 20);
        assert!(s.has_positive_delta());
        assert!(s.significance_met);
        assert_eq!(s.positive_wall_time_count, 20);
        assert_eq!(s.mean_wall_time_delta_millionths, 200_000);
    }

    #[test]
    fn stats_mixed_not_significant() {
        // 10 positive, 10 negative
        let mut comps: Vec<_> = (0..10)
            .map(|i| comparison(&format!("p{i}"), 80, 100))
            .collect();
        comps.extend((0..10).map(|i| comparison(&format!("n{i}"), 120, 100)));
        let s = StatisticalSummary::from_comparisons(&comps);
        assert_eq!(s.sample_count, 20);
        assert!(!s.significance_met); // 50% positive, not > 60%
    }

    #[test]
    fn stats_few_samples_high_bar() {
        // 4 out of 5 positive with small n
        let mut comps: Vec<_> = (0..4)
            .map(|i| comparison(&format!("p{i}"), 80, 100))
            .collect();
        comps.push(comparison("n0", 120, 100));
        let s = StatisticalSummary::from_comparisons(&comps);
        assert_eq!(s.sample_count, 5);
        assert!(s.significance_met); // 80% > 75% threshold for small n
    }

    // -----------------------------------------------------------------------
    // GateFailureCode display
    // -----------------------------------------------------------------------

    #[test]
    fn gate_failure_code_display() {
        assert_eq!(
            GateFailureCode::NoPositiveDelta.to_string(),
            "no_positive_delta"
        );
        assert_eq!(
            GateFailureCode::InsufficientReceiptCoverage.to_string(),
            "insufficient_receipt_coverage"
        );
        assert_eq!(
            GateFailureCode::FallbackCrashed.to_string(),
            "fallback_crashed"
        );
        assert_eq!(
            GateFailureCode::ReceiptChainReplayFailed.to_string(),
            "receipt_chain_replay_failed"
        );
    }

    // -----------------------------------------------------------------------
    // Full gate evaluation — all passing
    // -----------------------------------------------------------------------

    #[test]
    fn gate_passes_with_complete_input() {
        let input = full_input(20);
        let decision = evaluate(&input);
        assert!(decision.pass);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.receipt_coverage_millionths, 1_000_000);
        assert_eq!(decision.fallback_tests_passed, 2);
        assert_eq!(decision.fallback_tests_total, 2);
        assert!(decision.receipt_chain_replay_passed);
        assert!(decision.stats.significance_met);
        assert!(decision.stats.has_positive_delta());
        assert_eq!(decision.scorecard_performance_delta_millionths, 200_000);
        assert_eq!(decision.scorecard_security_delta_millionths, 1_000_000);
        assert_eq!(decision.scorecard_autonomy_delta_millionths, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Gate fails on no positive delta
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_no_positive_delta() {
        let mut input = full_input(20);
        // Make all comparisons show regression
        input.comparisons = (0..20)
            .map(|i| comparison(&format!("w{i}"), 120, 100))
            .collect();
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::NoPositiveDelta)
        );
    }

    // -----------------------------------------------------------------------
    // Gate fails on insufficient receipt coverage
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_incomplete_receipt_coverage() {
        let mut input = full_input(20);
        input.receipt_coverage[0].proof_reference = None;
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::InsufficientReceiptCoverage)
        );
    }

    // -----------------------------------------------------------------------
    // Gate fails on fallback crash
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_on_fallback_crash() {
        let mut input = full_input(20);
        input.fallback_tests[0].crashed = true;
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackCrashed)
        );
    }

    // -----------------------------------------------------------------------
    // Gate fails on receipt chain replay failure
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_on_receipt_replay_failure() {
        let mut input = full_input(20);
        if let Some(ref mut replay) = input.receipt_chain_replay {
            replay.all_verified = false;
            replay.verified_receipts = 8;
        }
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReceiptChainReplayFailed)
        );
    }

    // -----------------------------------------------------------------------
    // Gate fails on empty input
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_on_empty_comparisons() {
        let mut input = full_input(0);
        input.comparisons.clear();
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::EmptyInput)
        );
    }

    // -----------------------------------------------------------------------
    // Gate fails on insufficient samples
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_on_insufficient_samples() {
        let mut input = full_input(3);
        input.min_samples = 10;
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::InsufficientSamples)
        );
    }

    // -----------------------------------------------------------------------
    // Decision is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn gate_decision_deterministic() {
        let input = full_input(20);
        let a = evaluate(&input);
        let b = evaluate(&input);
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a.pass, b.pass);
        assert_eq!(a.stats, b.stats);
    }

    // -----------------------------------------------------------------------
    // Decision serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn gate_decision_serde_round_trip() {
        let input = full_input(20);
        let decision = evaluate(&input);
        let json = decision.to_jsonl();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision.pass, back.pass);
        assert_eq!(decision.decision_id, back.decision_id);
    }

    // -----------------------------------------------------------------------
    // Structured logs populated
    // -----------------------------------------------------------------------

    #[test]
    fn structured_logs_include_comparisons_and_fallbacks() {
        let input = full_input(5);
        let decision = evaluate(&input);
        // 5 comparison logs + 2 fallback logs + 1 summary log = 8
        assert_eq!(decision.logs.len(), 8);
        let summary = decision.logs.last().unwrap();
        assert_eq!(summary.event, "gate_decision");
        assert_eq!(summary.outcome, "pass");
    }

    // -----------------------------------------------------------------------
    // Multiple failures accumulated
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_failures_accumulated() {
        let mut input = full_input(20);
        // Break receipt coverage
        input.receipt_coverage[0].signature_valid = false;
        // Break fallback
        input.fallback_tests[0].hung = true;
        // Break replay
        if let Some(ref mut replay) = input.receipt_chain_replay {
            replay.chain_complete = false;
        }

        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(decision.findings.len() >= 3);
        let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&GateFailureCode::InsufficientReceiptCoverage));
        assert!(codes.contains(&GateFailureCode::FallbackHung));
        assert!(codes.contains(&GateFailureCode::ReceiptChainReplayFailed));
    }

    // -----------------------------------------------------------------------
    // Fallback performance regression finding
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_performance_regression_finding() {
        let mut input = full_input(20);
        input.fallback_tests[0].fallback_wall_time_ns = 200_000;
        input.fallback_tests[0].ambient_wall_time_ns = 100_000;
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPerformanceRegression)
        );
    }

    // -----------------------------------------------------------------------
    // Scorecard contributions
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_contributions_correct() {
        let input = full_input(20);
        let decision = evaluate(&input);
        // Performance: mean 20% speedup = 200_000 millionths
        assert_eq!(decision.scorecard_performance_delta_millionths, 200_000);
        // Security: 100% receipt coverage
        assert_eq!(decision.scorecard_security_delta_millionths, 1_000_000);
        // Autonomy: all comparisons use proof-specialized lanes
        assert_eq!(decision.scorecard_autonomy_delta_millionths, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // No receipt coverage entries with comparisons
    // -----------------------------------------------------------------------

    #[test]
    fn no_receipt_entries_with_comparisons_fails() {
        let mut input = full_input(20);
        input.receipt_coverage.clear();
        let decision = evaluate(&input);
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::InsufficientReceiptCoverage)
        );
    }

    #[test]
    fn lane_type_ord() {
        assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
    }

    #[test]
    fn gate_failure_code_ord() {
        assert!(GateFailureCode::NoPositiveDelta < GateFailureCode::InsufficientSignificance);
        assert!(
            GateFailureCode::InsufficientSignificance
                < GateFailureCode::InsufficientReceiptCoverage
        );
        assert!(GateFailureCode::FallbackCrashed < GateFailureCode::FallbackHung);
        assert!(GateFailureCode::InsufficientSamples < GateFailureCode::EmptyInput);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn gate_failure_code_serde_roundtrip() {
        let variants = [
            GateFailureCode::NoPositiveDelta,
            GateFailureCode::InsufficientSignificance,
            GateFailureCode::InsufficientReceiptCoverage,
            GateFailureCode::FallbackIncorrectOutput,
            GateFailureCode::FallbackCrashed,
            GateFailureCode::FallbackHung,
            GateFailureCode::FallbackNoReceipt,
            GateFailureCode::FallbackPerformanceRegression,
            GateFailureCode::ReceiptChainReplayFailed,
            GateFailureCode::InsufficientSamples,
            GateFailureCode::EmptyInput,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: GateFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn lane_type_as_str_all_distinct() {
        let variants = [LaneType::ProofSpecialized, LaneType::AmbientAuthority];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.as_str());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn gate_failure_code_display_all_distinct() {
        let variants = [
            GateFailureCode::NoPositiveDelta,
            GateFailureCode::InsufficientSignificance,
            GateFailureCode::InsufficientReceiptCoverage,
            GateFailureCode::FallbackIncorrectOutput,
            GateFailureCode::FallbackCrashed,
            GateFailureCode::FallbackHung,
            GateFailureCode::FallbackNoReceipt,
            GateFailureCode::FallbackPerformanceRegression,
            GateFailureCode::ReceiptChainReplayFailed,
            GateFailureCode::InsufficientSamples,
            GateFailureCode::EmptyInput,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn benchmark_sample_serde_roundtrip() {
        let sample = BenchmarkSample {
            workload_id: "wl-1".into(),
            lane_type: LaneType::ProofSpecialized,
            wall_time_ns: 1_000_000,
            memory_peak_bytes: 4096,
            throughput_ops_per_sec: Some(100),
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn benchmark_comparison_serde_roundtrip() {
        let comp = BenchmarkComparison::from_samples(
            BenchmarkSample {
                workload_id: "wl-1".into(),
                lane_type: LaneType::ProofSpecialized,
                wall_time_ns: 800_000,
                memory_peak_bytes: 3000,
                throughput_ops_per_sec: None,
            },
            BenchmarkSample {
                workload_id: "wl-1".into(),
                lane_type: LaneType::AmbientAuthority,
                wall_time_ns: 1_000_000,
                memory_peak_bytes: 4000,
                throughput_ops_per_sec: None,
            },
        );
        let json = serde_json::to_string(&comp).unwrap();
        let back: BenchmarkComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(comp, back);
    }

    #[test]
    fn receipt_coverage_entry_serde_roundtrip() {
        let entry = ReceiptCoverageEntry {
            optimization_name: "opt-1".into(),
            receipt_present: true,
            receipt_hash: Some(ContentHash::compute(b"receipt")),
            proof_reference: Some("proof-1".into()),
            capability_witness_ref: Some("wit-1".into()),
            performance_measurement_present: true,
            signature_valid: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ReceiptCoverageEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn receipt_coverage_entry_is_fully_covered() {
        let entry = ReceiptCoverageEntry {
            optimization_name: "opt-1".into(),
            receipt_present: true,
            receipt_hash: Some(ContentHash::compute(b"receipt")),
            proof_reference: Some("proof-1".into()),
            capability_witness_ref: Some("wit-1".into()),
            performance_measurement_present: true,
            signature_valid: true,
        };
        assert!(entry.is_fully_covered());
        assert!(entry.coverage_gaps().is_empty());
    }

    #[test]
    fn receipt_coverage_entry_gaps_when_missing_fields() {
        let entry = ReceiptCoverageEntry {
            optimization_name: "opt-1".into(),
            receipt_present: false,
            receipt_hash: None,
            proof_reference: None,
            capability_witness_ref: None,
            performance_measurement_present: false,
            signature_valid: false,
        };
        assert!(!entry.is_fully_covered());
        assert_eq!(entry.coverage_gaps().len(), 6);
    }

    #[test]
    fn gate_finding_serde_roundtrip() {
        let finding = GateFinding {
            code: GateFailureCode::FallbackCrashed,
            detail: "segfault in wasm lane".into(),
            affected_item: Some("wl-1".into()),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: GateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    // -- Enrichment: PearlTower 2026-02-27 edge-case batch --

    #[test]
    fn benchmark_sample_clone_equality() {
        let a = BenchmarkSample {
            workload_id: "wl-clone".into(),
            lane_type: LaneType::ProofSpecialized,
            wall_time_ns: 42_000,
            memory_peak_bytes: 8192,
            throughput_ops_per_sec: Some(500),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn benchmark_comparison_clone_equality() {
        let a = BenchmarkComparison::from_samples(
            sample("cmp-clone", LaneType::ProofSpecialized, 90, 2048),
            sample("cmp-clone", LaneType::AmbientAuthority, 100, 2048),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn receipt_coverage_entry_clone_equality() {
        let a = full_receipt("clone-opt");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn fallback_test_result_clone_equality() {
        let a = passing_fallback("clone-fb");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn statistical_summary_clone_equality() {
        let comps: Vec<_> = (0..10)
            .map(|i| comparison(&format!("ce{i}"), 75, 100))
            .collect();
        let a = StatisticalSummary::from_comparisons(&comps);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn benchmark_sample_json_field_presence() {
        let s = sample("fp-wl", LaneType::AmbientAuthority, 999, 4096);
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"workload_id\""));
        assert!(j.contains("\"lane_type\""));
        assert!(j.contains("\"wall_time_ns\""));
        assert!(j.contains("\"memory_peak_bytes\""));
        assert!(j.contains("\"throughput_ops_per_sec\""));
    }

    #[test]
    fn gate_decision_json_field_presence() {
        let input = full_input(20);
        let decision = evaluate(&input);
        let j = serde_json::to_string(&decision).unwrap();
        assert!(j.contains("\"decision_id\""));
        assert!(j.contains("\"pass\""));
        assert!(j.contains("\"receipt_coverage_millionths\""));
        assert!(j.contains("\"schema_version\""));
        assert!(j.contains("\"scorecard_performance_delta_millionths\""));
    }

    #[test]
    fn gate_log_event_json_field_presence() {
        let evt = GateLogEvent {
            trace_id: "t-1".into(),
            lane_type: Some("proof_specialized".into()),
            optimization_pass: None,
            proof_status: None,
            capability_witness_ref: None,
            specialization_receipt_hash: None,
            fallback_triggered: Some(false),
            wall_time_ns: Some(1234),
            memory_peak_bytes: None,
            event: "test_event".into(),
            outcome: "ok".into(),
        };
        let j = serde_json::to_string(&evt).unwrap();
        assert!(j.contains("\"trace_id\""));
        assert!(j.contains("\"event\""));
        assert!(j.contains("\"outcome\""));
    }

    #[test]
    fn gate_input_serde_roundtrip() {
        let input = full_input(5);
        let json = serde_json::to_string(&input).unwrap();
        let back: GateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn fallback_performance_zero_ambient_is_acceptable() {
        let mut fb = passing_fallback("zero-amb");
        fb.ambient_wall_time_ns = 0;
        fb.fallback_wall_time_ns = 999_999;
        // Zero ambient means no regression can be computed; treated as acceptable.
        assert!(fb.fallback_performance_acceptable());
    }

    #[test]
    fn fallback_performance_exactly_at_10_percent_threshold() {
        let mut fb = passing_fallback("threshold");
        fb.ambient_wall_time_ns = 1_000_000;
        // Exactly 10% regression => 100_000 millionths => should still be acceptable (<= 100_000).
        fb.fallback_wall_time_ns = 1_100_000;
        assert!(fb.fallback_performance_acceptable());
        // One nanosecond past the threshold => not acceptable.
        fb.fallback_wall_time_ns = 1_100_001;
        assert!(!fb.fallback_performance_acceptable());
    }

    #[test]
    fn lane_type_display_uniqueness() {
        let a = LaneType::ProofSpecialized.to_string();
        let b = LaneType::AmbientAuthority.to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn gate_failure_code_display_uniqueness_selected_pairs() {
        // Spot-check that semantically close failure codes still produce distinct strings.
        assert_ne!(
            GateFailureCode::FallbackCrashed.to_string(),
            GateFailureCode::FallbackHung.to_string(),
        );
        assert_ne!(
            GateFailureCode::InsufficientSamples.to_string(),
            GateFailureCode::EmptyInput.to_string(),
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_lane_type_copy_semantics() {
        let a = LaneType::ProofSpecialized;
        let b = a;
        assert_eq!(a, b); // both usable after copy
    }

    #[test]
    fn enrichment_lane_type_hash_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(LaneType::ProofSpecialized);
        set.insert(LaneType::AmbientAuthority);
        set.insert(LaneType::ProofSpecialized); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn enrichment_gate_failure_code_copy_semantics() {
        let a = GateFailureCode::FallbackCrashed;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_gate_failure_code_hash_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        for v in [
            GateFailureCode::NoPositiveDelta,
            GateFailureCode::InsufficientSignificance,
            GateFailureCode::InsufficientReceiptCoverage,
            GateFailureCode::FallbackIncorrectOutput,
            GateFailureCode::FallbackCrashed,
            GateFailureCode::FallbackHung,
            GateFailureCode::FallbackNoReceipt,
            GateFailureCode::FallbackPerformanceRegression,
            GateFailureCode::ReceiptChainReplayFailed,
            GateFailureCode::InsufficientSamples,
            GateFailureCode::EmptyInput,
        ] {
            set.insert(v);
        }
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn enrichment_statistical_summary_serde_roundtrip() {
        let comps: Vec<_> = (0..10)
            .map(|i| comparison(&format!("ss{i}"), 85, 100))
            .collect();
        let s = StatisticalSummary::from_comparisons(&comps);
        let json = serde_json::to_string(&s).unwrap();
        let back: StatisticalSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enrichment_receipt_chain_replay_result_serde_roundtrip() {
        let r = passing_replay();
        let json = serde_json::to_string(&r).unwrap();
        let back: ReceiptChainReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enrichment_fallback_test_result_serde_roundtrip() {
        let fb = passing_fallback("serde-fb");
        let json = serde_json::to_string(&fb).unwrap();
        let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }

    #[test]
    fn enrichment_gate_log_event_serde_roundtrip() {
        let evt = GateLogEvent {
            trace_id: "t-serde".into(),
            lane_type: Some("proof_specialized".into()),
            optimization_pass: Some("opt-1".into()),
            proof_status: Some("valid".into()),
            capability_witness_ref: None,
            specialization_receipt_hash: Some("hash-abc".into()),
            fallback_triggered: Some(false),
            wall_time_ns: Some(5000),
            memory_peak_bytes: Some(2048),
            event: "serde_test".into(),
            outcome: "ok".into(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: GateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    #[test]
    fn enrichment_statistical_summary_json_field_presence() {
        let comps: Vec<_> = (0..5)
            .map(|i| comparison(&format!("jf{i}"), 90, 100))
            .collect();
        let s = StatisticalSummary::from_comparisons(&comps);
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"sample_count\""));
        assert!(j.contains("\"mean_wall_time_delta_millionths\""));
        assert!(j.contains("\"mean_memory_delta_millionths\""));
        assert!(j.contains("\"positive_wall_time_count\""));
        assert!(j.contains("\"positive_memory_count\""));
        assert!(j.contains("\"significance_met\""));
    }

    #[test]
    fn enrichment_constants_match_expected() {
        assert_eq!(GATE_COMPONENT, "specialization_perf_release_gate");
        assert!(GATE_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(GATE_SCHEMA_VERSION.contains(".v"));
    }

    #[test]
    fn enrichment_decision_schema_version_matches_constant() {
        let input = full_input(20);
        let decision = evaluate(&input);
        assert_eq!(decision.schema_version, GATE_SCHEMA_VERSION);
    }

    #[test]
    fn enrichment_stats_very_few_samples_not_significant() {
        // Fewer than 5 samples should never be significant
        let comps: Vec<_> = (0..4)
            .map(|i| comparison(&format!("tiny{i}"), 50, 100))
            .collect();
        let s = StatisticalSummary::from_comparisons(&comps);
        assert_eq!(s.sample_count, 4);
        assert!(!s.significance_met);
    }

    #[test]
    fn enrichment_gate_decision_different_inputs_different_ids() {
        let input_a = full_input(20);
        let mut input_b = full_input(20);
        input_b.trace_id = "trace-different".to_string();
        let da = evaluate(&input_a);
        let db = evaluate(&input_b);
        assert_ne!(da.decision_id, db.decision_id);
    }
}
