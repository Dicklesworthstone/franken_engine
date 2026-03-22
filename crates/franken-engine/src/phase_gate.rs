//! Phase gates for release-quality enforcement.
//!
//! Four gates must pass before a track is complete:
//! 1. Deterministic Replay — byte-identical event sequences on replay.
//! 2. Interleaving Suite — race-surface coverage >= threshold.
//! 3. Conformance Vectors — all conformance vectors pass (>= 500).
//! 4. Fuzz/Adversarial — no crashes/bypasses under adversarial campaign.
//!
//! Each gate produces a structured `GateReport` artifact linked from the
//! track epic evidence chain.
//!
//! Plan references: Section 10.11 item 33, 9G.4, 9G.9, 9G.10.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// GateId — identifies a specific gate
// ---------------------------------------------------------------------------

/// Identifies one of the four phase gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateId {
    /// Gate 1: deterministic replay produces byte-identical event sequences.
    DeterministicReplay,
    /// Gate 2: interleaving explorer achieved required race-surface coverage.
    InterleavingSuite,
    /// Gate 3: all conformance vectors pass.
    ConformanceVectors,
    /// Gate 4: fuzz/adversarial campaign found no crashes or bypasses.
    FuzzAdversarial,
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeterministicReplay => f.write_str("deterministic_replay"),
            Self::InterleavingSuite => f.write_str("interleaving_suite"),
            Self::ConformanceVectors => f.write_str("conformance_vectors"),
            Self::FuzzAdversarial => f.write_str("fuzz_adversarial"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateStatus — pass/fail/pending
// ---------------------------------------------------------------------------

/// Status of a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateStatus {
    /// Not yet evaluated.
    Pending,
    /// Gate passed all criteria.
    Passed,
    /// Gate failed with reasons.
    Failed { reasons: Vec<String> },
    /// Gate was skipped (e.g., not applicable in this configuration).
    Skipped { reason: String },
}

impl GateStatus {
    /// Whether the gate passed.
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Whether the gate is terminal (passed, failed, or skipped).
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }
}

impl fmt::Display for GateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Passed => f.write_str("passed"),
            Self::Failed { reasons } => write!(f, "failed({})", reasons.join("; ")),
            Self::Skipped { reason } => write!(f, "skipped({reason})"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateMetrics — quantitative metrics for each gate
// ---------------------------------------------------------------------------

/// Quantitative metrics produced during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateMetrics {
    /// Key-value metric pairs (e.g., "coverage_pct" -> "97").
    pub values: BTreeMap<String, String>,
}

impl GateMetrics {
    /// Empty metrics.
    pub fn empty() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Add a metric.
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.values.insert(key.to_string(), value.to_string());
        self
    }

    /// Get a metric value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateReport — structured report artifact for a gate evaluation
// ---------------------------------------------------------------------------

/// Structured report produced by evaluating a phase gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Which gate was evaluated.
    pub gate_id: GateId,
    /// Pass/fail/pending status.
    pub status: GateStatus,
    /// Quantitative metrics.
    pub metrics: GateMetrics,
    /// Content hash of this report (for evidence linking).
    pub report_hash: ContentHash,
    /// CI run identifier.
    pub ci_run_id: String,
    /// Epoch at time of evaluation.
    pub epoch_id: u64,
    /// Virtual timestamp.
    pub timestamp_ticks: u64,
    /// Trace identifier.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// GateThresholds — configurable acceptance thresholds
// ---------------------------------------------------------------------------

/// Configurable thresholds for gate acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateThresholds {
    /// Gate 2: minimum interleaving coverage percentage (0-100).
    pub interleaving_coverage_pct: u32,
    /// Gate 3: minimum number of conformance vectors.
    pub min_conformance_vectors: u32,
    /// Gate 4: minimum fuzz campaign CPU-hours.
    pub min_fuzz_cpu_hours: u32,
}

impl Default for GateThresholds {
    fn default() -> Self {
        Self {
            interleaving_coverage_pct: 95,
            min_conformance_vectors: 500,
            min_fuzz_cpu_hours: 24,
        }
    }
}

// ---------------------------------------------------------------------------
// GateInput — input data for evaluating a gate
// ---------------------------------------------------------------------------

/// Input data for evaluating the deterministic replay gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayInput {
    /// Hash of the recorded event transcript.
    pub recorded_hash: ContentHash,
    /// Hash of the replayed event transcript.
    pub replayed_hash: ContentHash,
    /// Number of events in the transcript.
    pub event_count: u64,
}

/// Input data for evaluating the interleaving suite gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterleavingInput {
    /// Total cataloged race surfaces.
    pub total_surfaces: u32,
    /// Surfaces explored.
    pub explored_surfaces: u32,
    /// Unresolved failures.
    pub unresolved_failures: u32,
    /// Race surfaces with committed regression transcripts.
    pub regression_transcripts: u32,
}

/// Input data for evaluating the conformance vectors gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceInput {
    /// Total conformance vectors.
    pub total_vectors: u32,
    /// Vectors that passed.
    pub passed_vectors: u32,
    /// Vectors that failed.
    pub failed_vectors: u32,
    /// Categories covered.
    pub categories: Vec<String>,
}

/// Input data for evaluating the fuzz/adversarial gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzInput {
    /// Total CPU-hours of fuzz campaign.
    pub cpu_hours: u32,
    /// Crashes found.
    pub crashes: u32,
    /// Panics found (excluding expected lab-mode panics).
    pub unexpected_panics: u32,
    /// Bypass vulnerabilities found.
    pub bypasses: u32,
    /// Fuzz targets exercised.
    pub targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// GateEvaluator — evaluates gates against thresholds
// ---------------------------------------------------------------------------

/// Evaluates phase gates against configured thresholds.
#[derive(Debug)]
pub struct GateEvaluator {
    thresholds: GateThresholds,
    current_epoch: SecurityEpoch,
    reports: BTreeMap<GateId, GateReport>,
    events: Vec<GateEvent>,
    event_counts: BTreeMap<String, u64>,
}

/// Structured audit event for gate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    /// Gate identifier.
    pub gate_id: String,
    /// Status after evaluation.
    pub status: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Epoch at time of event.
    pub epoch_id: u64,
    /// Event type.
    pub event: String,
}

impl GateEvaluator {
    /// Create a new gate evaluator.
    pub fn new(epoch: SecurityEpoch, thresholds: GateThresholds) -> Self {
        Self {
            thresholds,
            current_epoch: epoch,
            reports: BTreeMap::new(),
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Evaluate Gate 1: Deterministic Replay.
    pub fn evaluate_replay(
        &mut self,
        input: &ReplayInput,
        ci_run_id: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> GateReport {
        let status = if input.recorded_hash == input.replayed_hash {
            GateStatus::Passed
        } else {
            GateStatus::Failed {
                reasons: vec![format!(
                    "transcript mismatch: recorded={}, replayed={}",
                    input.recorded_hash, input.replayed_hash
                )],
            }
        };

        let metrics = GateMetrics::empty()
            .with("event_count", &input.event_count.to_string())
            .with(
                "match",
                &(input.recorded_hash == input.replayed_hash).to_string(),
            );

        self.finalize_report(
            GateId::DeterministicReplay,
            status,
            metrics,
            ci_run_id,
            trace_id,
            timestamp_ticks,
        )
    }

    /// Evaluate Gate 2: Interleaving Suite.
    pub fn evaluate_interleaving(
        &mut self,
        input: &InterleavingInput,
        ci_run_id: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> GateReport {
        let coverage_pct = (input.explored_surfaces * 100)
            .checked_div(input.total_surfaces)
            .unwrap_or(0);

        let mut reasons = Vec::new();
        if coverage_pct < self.thresholds.interleaving_coverage_pct {
            reasons.push(format!(
                "coverage {coverage_pct}% < required {}%",
                self.thresholds.interleaving_coverage_pct
            ));
        }
        if input.unresolved_failures > 0 {
            reasons.push(format!(
                "{} unresolved race failures",
                input.unresolved_failures
            ));
        }

        let status = if reasons.is_empty() {
            GateStatus::Passed
        } else {
            GateStatus::Failed { reasons }
        };

        let metrics = GateMetrics::empty()
            .with("total_surfaces", &input.total_surfaces.to_string())
            .with("explored_surfaces", &input.explored_surfaces.to_string())
            .with("coverage_pct", &coverage_pct.to_string())
            .with(
                "unresolved_failures",
                &input.unresolved_failures.to_string(),
            )
            .with(
                "regression_transcripts",
                &input.regression_transcripts.to_string(),
            );

        self.finalize_report(
            GateId::InterleavingSuite,
            status,
            metrics,
            ci_run_id,
            trace_id,
            timestamp_ticks,
        )
    }

    /// Evaluate Gate 3: Conformance Vectors.
    pub fn evaluate_conformance(
        &mut self,
        input: &ConformanceInput,
        ci_run_id: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> GateReport {
        let mut reasons = Vec::new();
        if input.total_vectors < self.thresholds.min_conformance_vectors {
            reasons.push(format!(
                "vector count {} < minimum {}",
                input.total_vectors, self.thresholds.min_conformance_vectors
            ));
        }
        if input.failed_vectors > 0 {
            reasons.push(format!(
                "{} conformance vectors failed",
                input.failed_vectors
            ));
        }

        let status = if reasons.is_empty() {
            GateStatus::Passed
        } else {
            GateStatus::Failed { reasons }
        };

        let metrics = GateMetrics::empty()
            .with("total_vectors", &input.total_vectors.to_string())
            .with("passed_vectors", &input.passed_vectors.to_string())
            .with("failed_vectors", &input.failed_vectors.to_string())
            .with("categories", &input.categories.len().to_string());

        self.finalize_report(
            GateId::ConformanceVectors,
            status,
            metrics,
            ci_run_id,
            trace_id,
            timestamp_ticks,
        )
    }

    /// Evaluate Gate 4: Fuzz/Adversarial.
    pub fn evaluate_fuzz(
        &mut self,
        input: &FuzzInput,
        ci_run_id: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> GateReport {
        let mut reasons = Vec::new();
        if input.cpu_hours < self.thresholds.min_fuzz_cpu_hours {
            reasons.push(format!(
                "fuzz campaign {}h < minimum {}h",
                input.cpu_hours, self.thresholds.min_fuzz_cpu_hours
            ));
        }
        if input.crashes > 0 {
            reasons.push(format!("{} crashes found", input.crashes));
        }
        if input.unexpected_panics > 0 {
            reasons.push(format!("{} unexpected panics", input.unexpected_panics));
        }
        if input.bypasses > 0 {
            reasons.push(format!("{} bypass vulnerabilities", input.bypasses));
        }

        let status = if reasons.is_empty() {
            GateStatus::Passed
        } else {
            GateStatus::Failed { reasons }
        };

        let metrics = GateMetrics::empty()
            .with("cpu_hours", &input.cpu_hours.to_string())
            .with("crashes", &input.crashes.to_string())
            .with("unexpected_panics", &input.unexpected_panics.to_string())
            .with("bypasses", &input.bypasses.to_string())
            .with("targets", &input.targets.len().to_string());

        self.finalize_report(
            GateId::FuzzAdversarial,
            status,
            metrics,
            ci_run_id,
            trace_id,
            timestamp_ticks,
        )
    }

    /// Whether all four gates have passed.
    pub fn all_gates_passed(&self) -> bool {
        let required = [
            GateId::DeterministicReplay,
            GateId::InterleavingSuite,
            GateId::ConformanceVectors,
            GateId::FuzzAdversarial,
        ];
        required
            .iter()
            .all(|gate| self.reports.get(gate).is_some_and(|r| r.status.is_passed()))
    }

    /// Summary of all gate statuses.
    pub fn summary(&self) -> BTreeMap<GateId, &GateStatus> {
        self.reports
            .iter()
            .map(|(id, report)| (*id, &report.status))
            .collect()
    }

    /// Get a specific gate report.
    pub fn report(&self, gate_id: GateId) -> Option<&GateReport> {
        self.reports.get(&gate_id)
    }

    /// Export all gate reports (for evidence linking).
    pub fn export_reports(&self) -> Vec<&GateReport> {
        self.reports.values().collect()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<GateEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn finalize_report(
        &mut self,
        gate_id: GateId,
        status: GateStatus,
        metrics: GateMetrics,
        ci_run_id: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> GateReport {
        let mut report_input = format!(
            "{}:{}:{}:{}:{}",
            gate_id,
            status,
            ci_run_id,
            self.current_epoch.as_u64(),
            timestamp_ticks,
        );
        for (k, v) in &metrics.values {
            report_input.push_str(&format!("|{k}={v}"));
        }
        let report_hash = ContentHash::compute(report_input.as_bytes());

        let report = GateReport {
            gate_id,
            status: status.clone(),
            metrics,
            report_hash,
            ci_run_id: ci_run_id.to_string(),
            epoch_id: self.current_epoch.as_u64(),
            timestamp_ticks,
            trace_id: trace_id.to_string(),
        };

        self.reports.insert(gate_id, report.clone());

        self.events.push(GateEvent {
            gate_id: gate_id.to_string(),
            status: status.to_string(),
            trace_id: trace_id.to_string(),
            epoch_id: self.current_epoch.as_u64(),
            event: "gate_evaluated".to_string(),
        });
        *self
            .event_counts
            .entry("gate_evaluated".to_string())
            .or_insert(0) += 1;

        if status.is_passed() {
            *self
                .event_counts
                .entry("gate_passed".to_string())
                .or_insert(0) += 1;
        }

        report
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn default_evaluator() -> GateEvaluator {
        GateEvaluator::new(test_epoch(), GateThresholds::default())
    }

    // -- GateId --

    #[test]
    fn gate_id_display() {
        assert_eq!(
            GateId::DeterministicReplay.to_string(),
            "deterministic_replay"
        );
        assert_eq!(GateId::InterleavingSuite.to_string(), "interleaving_suite");
        assert_eq!(
            GateId::ConformanceVectors.to_string(),
            "conformance_vectors"
        );
        assert_eq!(GateId::FuzzAdversarial.to_string(), "fuzz_adversarial");
    }

    #[test]
    fn gate_id_ordering() {
        assert!(GateId::DeterministicReplay < GateId::InterleavingSuite);
        assert!(GateId::InterleavingSuite < GateId::ConformanceVectors);
        assert!(GateId::ConformanceVectors < GateId::FuzzAdversarial);
    }

    // -- GateStatus --

    #[test]
    fn gate_status_is_passed() {
        assert!(GateStatus::Passed.is_passed());
        assert!(!GateStatus::Pending.is_passed());
        assert!(!GateStatus::Failed { reasons: vec![] }.is_passed());
        assert!(
            !GateStatus::Skipped {
                reason: "n/a".to_string()
            }
            .is_passed()
        );
    }

    #[test]
    fn gate_status_is_terminal() {
        assert!(!GateStatus::Pending.is_terminal());
        assert!(GateStatus::Passed.is_terminal());
        assert!(GateStatus::Failed { reasons: vec![] }.is_terminal());
        assert!(
            GateStatus::Skipped {
                reason: "n/a".to_string()
            }
            .is_terminal()
        );
    }

    // -- Gate 1: Deterministic Replay --

    #[test]
    fn replay_gate_passes_on_matching_hashes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"events"),
                replayed_hash: ContentHash::compute(b"events"),
                event_count: 100,
            },
            "ci-1",
            "t1",
            1000,
        );
        assert!(report.status.is_passed());
        assert_eq!(report.metrics.get("event_count"), Some("100"));
    }

    #[test]
    fn replay_gate_fails_on_mismatch() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"original"),
                replayed_hash: ContentHash::compute(b"diverged"),
                event_count: 50,
            },
            "ci-1",
            "t1",
            1000,
        );
        assert!(!report.status.is_passed());
    }

    // -- Gate 2: Interleaving Suite --

    #[test]
    fn interleaving_gate_passes_above_threshold() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 96,
                unresolved_failures: 0,
                regression_transcripts: 3,
            },
            "ci-1",
            "t1",
            2000,
        );
        assert!(report.status.is_passed());
        assert_eq!(report.metrics.get("coverage_pct"), Some("96"));
    }

    #[test]
    fn interleaving_gate_fails_below_threshold() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 90,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci-1",
            "t1",
            2000,
        );
        assert!(!report.status.is_passed());
    }

    #[test]
    fn interleaving_gate_fails_with_unresolved() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 100,
                unresolved_failures: 2,
                regression_transcripts: 0,
            },
            "ci-1",
            "t1",
            2000,
        );
        assert!(!report.status.is_passed());
    }

    // -- Gate 3: Conformance Vectors --

    #[test]
    fn conformance_gate_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 600,
                passed_vectors: 600,
                failed_vectors: 0,
                categories: vec![
                    "capability".to_string(),
                    "evidence".to_string(),
                    "hash_chain".to_string(),
                ],
            },
            "ci-1",
            "t1",
            3000,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn conformance_gate_fails_too_few_vectors() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 400,
                passed_vectors: 400,
                failed_vectors: 0,
                categories: vec![],
            },
            "ci-1",
            "t1",
            3000,
        );
        assert!(!report.status.is_passed());
    }

    #[test]
    fn conformance_gate_fails_with_failures() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 600,
                passed_vectors: 595,
                failed_vectors: 5,
                categories: vec![],
            },
            "ci-1",
            "t1",
            3000,
        );
        assert!(!report.status.is_passed());
    }

    // -- Gate 4: Fuzz/Adversarial --

    #[test]
    fn fuzz_gate_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec!["schema".to_string(), "capability".to_string()],
            },
            "ci-1",
            "t1",
            4000,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn fuzz_gate_fails_insufficient_hours() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 10,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci-1",
            "t1",
            4000,
        );
        assert!(!report.status.is_passed());
    }

    #[test]
    fn fuzz_gate_fails_with_crashes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 3,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci-1",
            "t1",
            4000,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert!(reasons[0].contains("3 crashes"));
        }
    }

    #[test]
    fn fuzz_gate_fails_with_bypasses() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 1,
                targets: vec![],
            },
            "ci-1",
            "t1",
            4000,
        );
        assert!(!report.status.is_passed());
    }

    // -- All gates passed --

    #[test]
    fn all_gates_passed_requires_all_four() {
        let mut eval = default_evaluator();
        assert!(!eval.all_gates_passed());

        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        assert!(!eval.all_gates_passed());

        eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 100,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(!eval.all_gates_passed());

        eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 500,
                passed_vectors: 500,
                failed_vectors: 0,
                categories: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!eval.all_gates_passed());

        eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 24,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(eval.all_gates_passed());
    }

    #[test]
    fn one_failed_gate_prevents_all_passed() {
        let mut eval = default_evaluator();

        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"a"),
                replayed_hash: ContentHash::compute(b"b"), // mismatch
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 100,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 500,
                passed_vectors: 500,
                failed_vectors: 0,
                categories: vec![],
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 24,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );

        assert!(!eval.all_gates_passed());
    }

    // -- Summary and reports --

    #[test]
    fn summary_shows_all_evaluated_gates() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );

        let summary = eval.summary();
        assert_eq!(summary.len(), 1);
        assert!(summary[&GateId::DeterministicReplay].is_passed());
    }

    #[test]
    fn export_reports_returns_all() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 24,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );

        assert_eq!(eval.export_reports().len(), 2);
    }

    // -- Audit events --

    #[test]
    fn evaluation_emits_events() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );

        let events = eval.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "gate_evaluated");
        assert_eq!(events[0].gate_id, "deterministic_replay");
        assert_eq!(eval.event_counts().get("gate_evaluated"), Some(&1));
        assert_eq!(eval.event_counts().get("gate_passed"), Some(&1));
    }

    // -- GateMetrics --

    #[test]
    fn gate_metrics_builder() {
        let m = GateMetrics::empty().with("a", "1").with("b", "2");
        assert_eq!(m.get("a"), Some("1"));
        assert_eq!(m.get("b"), Some("2"));
        assert_eq!(m.get("c"), None);
    }

    // -- Serialization round-trips --

    #[test]
    fn gate_id_serialization_round_trip() {
        let ids = vec![
            GateId::DeterministicReplay,
            GateId::InterleavingSuite,
            GateId::ConformanceVectors,
            GateId::FuzzAdversarial,
        ];
        for id in &ids {
            let json = serde_json::to_string(id).expect("serialize");
            let restored: GateId = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*id, restored);
        }
    }

    #[test]
    fn gate_status_serialization_round_trip() {
        let statuses = vec![
            GateStatus::Pending,
            GateStatus::Passed,
            GateStatus::Failed {
                reasons: vec!["bad".to_string()],
            },
            GateStatus::Skipped {
                reason: "n/a".to_string(),
            },
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).expect("serialize");
            let restored: GateStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*s, restored);
        }
    }

    #[test]
    fn gate_report_serialization_round_trip() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 42,
            },
            "ci-1",
            "t1",
            1000,
        );
        let json = serde_json::to_string(&report).expect("serialize");
        let restored: GateReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    #[test]
    fn gate_thresholds_serialization_round_trip() {
        let thresholds = GateThresholds::default();
        let json = serde_json::to_string(&thresholds).expect("serialize");
        let restored: GateThresholds = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(thresholds, restored);
    }

    #[test]
    fn gate_event_serialization_round_trip() {
        let event = GateEvent {
            gate_id: "deterministic_replay".to_string(),
            status: "passed".to_string(),
            trace_id: "t1".to_string(),
            epoch_id: 1,
            event: "gate_evaluated".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: GateEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Determinism --

    // -- Enrichment: serde roundtrips --

    #[test]
    fn gate_metrics_serde_roundtrip() {
        let m = GateMetrics::empty()
            .with("latency_p99", "42ms")
            .with("throughput", "1000rps");
        let json = serde_json::to_string(&m).expect("serialize");
        let restored: GateMetrics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, restored);
    }

    #[test]
    fn replay_input_serde_roundtrip() {
        let ri = ReplayInput {
            recorded_hash: ContentHash::compute(b"recorded"),
            replayed_hash: ContentHash::compute(b"replayed"),
            event_count: 512,
        };
        let json = serde_json::to_string(&ri).expect("serialize");
        let restored: ReplayInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ri, restored);
    }

    #[test]
    fn interleaving_input_serde_roundtrip() {
        let ii = InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 87,
            unresolved_failures: 3,
            regression_transcripts: 1,
        };
        let json = serde_json::to_string(&ii).expect("serialize");
        let restored: InterleavingInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ii, restored);
    }

    #[test]
    fn conformance_input_serde_roundtrip() {
        let ci = ConformanceInput {
            total_vectors: 500,
            passed_vectors: 498,
            failed_vectors: 2,
            categories: vec!["syntax".to_string(), "semantics".to_string()],
        };
        let json = serde_json::to_string(&ci).expect("serialize");
        let restored: ConformanceInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ci, restored);
    }

    #[test]
    fn fuzz_input_serde_roundtrip() {
        let fi = FuzzInput {
            cpu_hours: 48,
            crashes: 0,
            unexpected_panics: 1,
            bypasses: 0,
            targets: vec!["parser".to_string(), "interpreter".to_string()],
        };
        let json = serde_json::to_string(&fi).expect("serialize");
        let restored: FuzzInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fi, restored);
    }

    #[test]
    fn deterministic_report_hash() {
        let run = || {
            let mut eval = default_evaluator();
            eval.evaluate_replay(
                &ReplayInput {
                    recorded_hash: ContentHash::compute(b"events"),
                    replayed_hash: ContentHash::compute(b"events"),
                    event_count: 100,
                },
                "ci-1",
                "t1",
                1000,
            )
        };
        let r1 = run();
        let r2 = run();
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    // -- Enrichment: GateStatus display all variants unique --

    #[test]
    fn gate_status_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = vec![
            GateStatus::Pending,
            GateStatus::Passed,
            GateStatus::Failed {
                reasons: vec!["r1".to_string()],
            },
            GateStatus::Skipped {
                reason: "n/a".to_string(),
            },
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 GateStatus variants have distinct Display"
        );
    }

    // -- Enrichment: GateThresholds default values --

    #[test]
    fn gate_thresholds_default_values() {
        let t = GateThresholds::default();
        assert_eq!(t.interleaving_coverage_pct, 95);
        assert_eq!(t.min_conformance_vectors, 500);
        assert_eq!(t.min_fuzz_cpu_hours, 24);
    }

    // -- Enrichment: report() returns None for unevaluated --

    #[test]
    fn report_returns_none_for_unevaluated() {
        let eval = default_evaluator();
        assert!(eval.report(GateId::DeterministicReplay).is_none());
        assert!(eval.report(GateId::FuzzAdversarial).is_none());
    }

    // -- Enrichment: empty evaluator summary is empty --

    #[test]
    fn empty_evaluator_summary() {
        let eval = default_evaluator();
        assert!(eval.summary().is_empty());
        assert!(!eval.all_gates_passed());
    }

    // -- Enrichment: drain_events clears --

    #[test]
    fn drain_events_clears_buffer() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        let events = eval.drain_events();
        assert_eq!(events.len(), 1);
        assert!(eval.drain_events().is_empty());
    }

    // -- Enrichment: re-evaluate same gate overwrites --

    #[test]
    fn re_evaluate_gate_overwrites_report() {
        let mut eval = default_evaluator();
        let r1 = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"a"),
                replayed_hash: ContentHash::compute(b"b"),
                event_count: 1,
            },
            "ci-1",
            "t1",
            1000,
        );
        assert!(!r1.status.is_passed());

        let r2 = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci-2",
            "t2",
            2000,
        );
        assert!(r2.status.is_passed());

        // Latest report should be the overwrite
        let stored = eval.report(GateId::DeterministicReplay).unwrap();
        assert!(stored.status.is_passed());
        assert_eq!(stored.ci_run_id, "ci-2");
    }

    // -- Enrichment: fuzz gate fails with unexpected_panics --

    #[test]
    fn fuzz_gate_fails_with_unexpected_panics() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 2,
                bypasses: 0,
                targets: vec![],
            },
            "ci-1",
            "t1",
            4000,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert!(reasons[0].contains("2 unexpected panics"));
        }
    }

    // -- Enrichment: gate_passed counter only increments on pass --

    #[test]
    fn gate_passed_counter_only_on_pass() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"a"),
                replayed_hash: ContentHash::compute(b"b"), // fail
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        assert_eq!(eval.event_counts().get("gate_evaluated"), Some(&1));
        assert!(eval.event_counts().get("gate_passed").is_none());
    }

    // -- Enrichment: GateMetrics empty has no values --

    #[test]
    fn gate_metrics_empty_has_no_values() {
        let m = GateMetrics::empty();
        assert!(m.values.is_empty());
        assert_eq!(m.get("anything"), None);
    }

    // -- Enrichment: report trace_id populated --

    #[test]
    fn report_trace_id_populated() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 42,
            },
            "ci-run-1",
            "trace-abc",
            1000,
        );
        assert_eq!(report.trace_id, "trace-abc");
        assert_eq!(report.ci_run_id, "ci-run-1");
        assert_eq!(report.timestamp_ticks, 1000);
        assert_eq!(report.epoch_id, 1);
    }

    // -- Enrichment batch 3: boundary conditions and deeper edge cases --

    #[test]
    fn interleaving_zero_surfaces_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 0,
                explored_surfaces: 0,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        // 0/0 = 0%, which is < 95% threshold, so should fail
        assert!(!report.status.is_passed());
    }

    #[test]
    fn interleaving_exact_threshold_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 95,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn interleaving_just_below_threshold_fails() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 94,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
    }

    #[test]
    fn conformance_exact_min_vectors_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 500,
                passed_vectors: 500,
                failed_vectors: 0,
                categories: vec!["cat1".to_string()],
            },
            "ci",
            "t",
            0,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn conformance_below_min_vectors_fails() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 499,
                passed_vectors: 499,
                failed_vectors: 0,
                categories: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
    }

    #[test]
    fn conformance_failed_vectors_cause_failure() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 600,
                passed_vectors: 599,
                failed_vectors: 1,
                categories: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.contains("1 conformance vectors failed"))
            );
        }
    }

    #[test]
    fn fuzz_exact_min_hours_passes() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 24,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn fuzz_below_min_hours_fails() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 23,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert!(reasons[0].contains("23h < minimum 24h"));
        }
    }

    #[test]
    fn fuzz_multiple_failure_reasons() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 10,
                crashes: 2,
                unexpected_panics: 3,
                bypasses: 1,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert_eq!(reasons.len(), 4);
        } else {
            panic!("expected Failed");
        }
    }

    #[test]
    fn fuzz_bypasses_cause_failure() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 1,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert!(reasons[0].contains("bypass"));
        }
    }

    #[test]
    fn gate_status_is_terminal_enrichment() {
        assert!(!GateStatus::Pending.is_terminal());
        assert!(GateStatus::Passed.is_terminal());
        assert!(GateStatus::Failed { reasons: vec![] }.is_terminal());
        assert!(
            GateStatus::Skipped {
                reason: "n/a".to_string()
            }
            .is_terminal()
        );
    }

    #[test]
    fn gate_status_display_failed_multiple_reasons() {
        let status = GateStatus::Failed {
            reasons: vec!["reason-a".to_string(), "reason-b".to_string()],
        };
        let display = status.to_string();
        assert!(display.contains("reason-a"));
        assert!(display.contains("reason-b"));
        assert!(display.contains(';'));
    }

    #[test]
    fn gate_status_display_skipped_contains_reason() {
        let status = GateStatus::Skipped {
            reason: "not applicable".to_string(),
        };
        assert!(status.to_string().contains("not applicable"));
    }

    #[test]
    fn gate_metrics_with_overwrites() {
        let m = GateMetrics::empty()
            .with("key", "first")
            .with("key", "second");
        assert_eq!(m.get("key"), Some("second"));
        assert_eq!(m.values.len(), 1);
    }

    #[test]
    fn custom_thresholds_evaluator() {
        let thresholds = GateThresholds {
            interleaving_coverage_pct: 50,
            min_conformance_vectors: 10,
            min_fuzz_cpu_hours: 1,
        };
        let mut eval = GateEvaluator::new(test_epoch(), thresholds);
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 50,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn report_hash_differs_for_different_inputs() {
        let mut eval1 = default_evaluator();
        let r1 = eval1.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"a"),
                replayed_hash: ContentHash::compute(b"a"),
                event_count: 1,
            },
            "ci-1",
            "t1",
            1000,
        );
        let mut eval2 = default_evaluator();
        let r2 = eval2.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"b"),
                replayed_hash: ContentHash::compute(b"b"),
                event_count: 2,
            },
            "ci-2",
            "t2",
            2000,
        );
        assert_ne!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn export_reports_empty_on_fresh_evaluator() {
        let eval = default_evaluator();
        assert!(eval.export_reports().is_empty());
    }

    #[test]
    fn event_counts_empty_on_fresh_evaluator() {
        let eval = default_evaluator();
        assert!(eval.event_counts().is_empty());
    }

    #[test]
    fn gate_id_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            GateId::DeterministicReplay,
            GateId::InterleavingSuite,
            GateId::ConformanceVectors,
            GateId::FuzzAdversarial,
        ]
        .iter()
        .map(|g| g.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 GateId variants have unique Display"
        );
    }

    #[test]
    fn gate_id_copy_semantics() {
        let id = GateId::DeterministicReplay;
        let id2 = id;
        assert_eq!(id, id2);
    }

    #[test]
    fn report_has_content_hash() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        // report_hash should be non-zero
        assert_ne!(report.report_hash, ContentHash::compute(b""));
    }

    #[test]
    fn interleaving_both_coverage_and_failures_produce_multiple_reasons() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 50,
                unresolved_failures: 3,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert_eq!(reasons.len(), 2);
            assert!(reasons[0].contains("coverage"));
            assert!(reasons[1].contains("unresolved"));
        }
    }

    #[test]
    fn gate_report_metrics_populated() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec!["target1".to_string()],
            },
            "ci",
            "t",
            0,
        );
        assert_eq!(report.metrics.get("cpu_hours"), Some("48"));
        assert_eq!(report.metrics.get("crashes"), Some("0"));
        assert_eq!(report.metrics.get("targets"), Some("1"));
    }

    #[test]
    fn conformance_metrics_populated() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 600,
                passed_vectors: 600,
                failed_vectors: 0,
                categories: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
            "ci",
            "t",
            0,
        );
        assert_eq!(report.metrics.get("total_vectors"), Some("600"));
        assert_eq!(report.metrics.get("categories"), Some("3"));
    }

    #[test]
    fn replay_metrics_populated() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 42,
            },
            "ci",
            "t",
            0,
        );
        assert_eq!(report.metrics.get("event_count"), Some("42"));
        assert_eq!(report.metrics.get("match"), Some("true"));
    }

    // -- Interleaving zero surfaces (div-by-zero) --------------------------

    #[test]
    fn interleaving_zero_surfaces_passes_zero_threshold() {
        let mut eval = GateEvaluator::new(
            test_epoch(),
            GateThresholds {
                interleaving_coverage_pct: 0,
                ..GateThresholds::default()
            },
        );
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 0,
                explored_surfaces: 0,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(report.status.is_passed());
    }

    #[test]
    fn interleaving_zero_surfaces_fails_nonzero_threshold() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 0,
                explored_surfaces: 0,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        // 0% coverage < 95% threshold → failed.
        assert!(!report.status.is_passed());
    }

    // -- Interleaving unresolved failures only (no coverage fail) ----------

    #[test]
    fn interleaving_only_unresolved_failures() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 100,
                explored_surfaces: 100,
                unresolved_failures: 3,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("unresolved"));
        }
    }

    // -- Conformance: insufficient vectors only ----------------------------

    #[test]
    fn conformance_insufficient_vectors_only() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 100,
                passed_vectors: 100,
                failed_vectors: 0,
                categories: vec!["a".to_string()],
            },
            "ci",
            "t",
            0,
        );
        assert!(!report.status.is_passed());
        if let GateStatus::Failed { reasons } = &report.status {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("vector count"));
        }
    }

    // -- Fuzz: all four failure reasons simultaneously --------------------

    #[test]
    fn fuzz_all_four_failures() {
        let mut eval = default_evaluator();
        let report = eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 1,
                crashes: 2,
                unexpected_panics: 3,
                bypasses: 4,
                targets: vec!["t".to_string()],
            },
            "ci",
            "t",
            0,
        );
        if let GateStatus::Failed { reasons } = &report.status {
            assert_eq!(reasons.len(), 4);
        } else {
            panic!("expected Failed");
        }
    }

    // -- Gate re-evaluation overwrites previous report --------------------

    #[test]
    fn re_evaluation_overwrites_report() {
        let mut eval = default_evaluator();
        // First: fail.
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"a"),
                replayed_hash: ContentHash::compute(b"b"),
                event_count: 1,
            },
            "ci1",
            "t1",
            100,
        );
        assert!(!eval.all_gates_passed());
        // Second: pass.
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 2,
            },
            "ci2",
            "t2",
            200,
        );
        let report = eval.report(GateId::DeterministicReplay).unwrap();
        assert!(report.status.is_passed());
        assert_eq!(report.ci_run_id, "ci2");
    }

    // -- Event drain and re-eval isolation --------------------------------

    #[test]
    fn drain_events_then_re_eval() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        let events1 = eval.drain_events();
        assert!(!events1.is_empty());

        // Re-eval generates new events.
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 2,
            },
            "ci2",
            "t2",
            100,
        );
        let events2 = eval.drain_events();
        assert!(!events2.is_empty());
    }

    // -- GateStatus is_terminal -------------------------------------------

    #[test]
    fn gate_status_is_terminal_all_variants() {
        assert!(GateStatus::Passed.is_terminal());
        assert!(
            GateStatus::Failed {
                reasons: vec!["x".into()]
            }
            .is_terminal()
        );
        assert!(
            GateStatus::Skipped {
                reason: "skip".into()
            }
            .is_terminal()
        );
        assert!(!GateStatus::Pending.is_terminal());
    }

    // -- GateMetrics edge cases -------------------------------------------

    #[test]
    fn gate_metrics_overwrite_key() {
        let m = GateMetrics::empty().with("k", "v1").with("k", "v2");
        assert_eq!(m.get("k"), Some("v2"));
    }

    // -- Report hash determinism ------------------------------------------

    #[test]
    fn report_hash_deterministic_same_inputs() {
        let mut eval1 = default_evaluator();
        let mut eval2 = default_evaluator();
        let input = ReplayInput {
            recorded_hash: ContentHash::compute(b"test"),
            replayed_hash: ContentHash::compute(b"test"),
            event_count: 10,
        };
        let r1 = eval1.evaluate_replay(&input, "ci", "trace", 42);
        let r2 = eval2.evaluate_replay(&input, "ci", "trace", 42);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    // -- export_reports returns all evaluated gates ------------------------

    #[test]
    fn export_reports_count() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 48,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec!["t".to_string()],
            },
            "ci",
            "t",
            0,
        );
        assert_eq!(eval.export_reports().len(), 2);
    }

    // -- summary returns evaluated gate statuses --------------------------

    #[test]
    fn summary_includes_only_evaluated() {
        let mut eval = default_evaluator();
        assert!(eval.summary().is_empty());
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        let summary = eval.summary();
        assert_eq!(summary.len(), 1);
        assert!(summary.contains_key(&GateId::DeterministicReplay));
    }

    // -- event_counts persist across drain --------------------------------

    #[test]
    fn event_counts_persist_after_drain() {
        let mut eval = default_evaluator();
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 1,
            },
            "ci",
            "t",
            0,
        );
        let counts_before = eval.event_counts().clone();
        eval.drain_events();
        assert_eq!(eval.event_counts(), &counts_before);
    }

    // -- Custom thresholds ------------------------------------------------

    #[test]
    fn custom_zero_threshold_allows_minimal_input() {
        let mut eval = GateEvaluator::new(
            test_epoch(),
            GateThresholds {
                interleaving_coverage_pct: 0,
                min_conformance_vectors: 0,
                min_fuzz_cpu_hours: 0,
            },
        );
        eval.evaluate_interleaving(
            &InterleavingInput {
                total_surfaces: 1,
                explored_surfaces: 0,
                unresolved_failures: 0,
                regression_transcripts: 0,
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_conformance(
            &ConformanceInput {
                total_vectors: 0,
                passed_vectors: 0,
                failed_vectors: 0,
                categories: vec![],
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_fuzz(
            &FuzzInput {
                cpu_hours: 0,
                crashes: 0,
                unexpected_panics: 0,
                bypasses: 0,
                targets: vec![],
            },
            "ci",
            "t",
            0,
        );
        eval.evaluate_replay(
            &ReplayInput {
                recorded_hash: ContentHash::compute(b"x"),
                replayed_hash: ContentHash::compute(b"x"),
                event_count: 0,
            },
            "ci",
            "t",
            0,
        );
        assert!(eval.all_gates_passed());
    }
}
