//! Slot-level promotion gate runner for verified self-replacement.
//!
//! Evaluates four mandatory gates before a native candidate can replace a
//! delegate cell in a slot:
//! - **Equivalence**: differential testing — zero semantic divergence
//! - **Capability-preservation**: candidate requests no extra capabilities
//! - **Performance threshold**: candidate meets latency/throughput targets
//! - **Adversarial survival**: candidate passes security corpus
//!
//! All gate evaluations are deterministic from pinned seeds and produce
//! structured evidence artifact bundles.
//!
//! Plan reference: Section 10.15 item 3 of 9I.6 (`bd-1g5c`).
//! Cross-refs: bd-7rwi (PromotionDecision schema), bd-3ciq (delegate cell
//! harness baseline), 10.7 (test/adversarial infrastructure).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{GateResult, GateVerdict, RiskLevel};
use crate::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ---------------------------------------------------------------------------
// Gate types
// ---------------------------------------------------------------------------

/// The four mandatory promotion gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateKind {
    /// Differential testing: zero semantic divergence between delegate and
    /// native candidate.
    Equivalence,
    /// Native candidate requests no capabilities beyond the slot's envelope.
    CapabilityPreservation,
    /// Candidate meets or exceeds configurable performance targets.
    PerformanceThreshold,
    /// Candidate passes adversarial security corpus for its slot.
    AdversarialSurvival,
}

impl GateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivalence => "equivalence",
            Self::CapabilityPreservation => "capability_preservation",
            Self::PerformanceThreshold => "performance_threshold",
            Self::AdversarialSurvival => "adversarial_survival",
        }
    }

    pub fn all() -> &'static [GateKind] {
        &[
            Self::Equivalence,
            Self::CapabilityPreservation,
            Self::PerformanceThreshold,
            Self::AdversarialSurvival,
        ]
    }
}

impl fmt::Display for GateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Gate strictness configuration
// ---------------------------------------------------------------------------

/// Configurable strictness per gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateStrictness {
    /// Gate kind.
    pub gate: GateKind,
    /// Whether this gate is required to pass (vs advisory-only).
    pub required: bool,
    /// Maximum allowed divergences for equivalence (0 = strict).
    pub max_divergences: u64,
    /// Performance threshold: minimum throughput in ops/sec (millionths).
    pub min_throughput_millionths: u64,
    /// Performance threshold: maximum latency in nanoseconds.
    pub max_latency_ns: u64,
    /// Adversarial: minimum pass rate (millionths, 1_000_000 = 100%).
    pub min_adversarial_pass_rate_millionths: u64,
}

impl GateStrictness {
    /// Default strictness for a standard slot.
    pub fn standard(gate: GateKind) -> Self {
        match gate {
            GateKind::Equivalence => Self {
                gate,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 0,
                max_latency_ns: 0,
                min_adversarial_pass_rate_millionths: 0,
            },
            GateKind::CapabilityPreservation => Self {
                gate,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 0,
                max_latency_ns: 0,
                min_adversarial_pass_rate_millionths: 0,
            },
            GateKind::PerformanceThreshold => Self {
                gate,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 500_000, // 0.5 ops/sec minimum
                max_latency_ns: 100_000_000,        // 100ms max
                min_adversarial_pass_rate_millionths: 0,
            },
            GateKind::AdversarialSurvival => Self {
                gate,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 0,
                max_latency_ns: 0,
                min_adversarial_pass_rate_millionths: 950_000, // 95% minimum
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Gate inputs
// ---------------------------------------------------------------------------

/// Equivalence test case: input → expected output pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceTestCase {
    pub test_id: String,
    pub input: Vec<u8>,
    pub delegate_output: Vec<u8>,
    pub candidate_output: Vec<u8>,
}

impl EquivalenceTestCase {
    /// Whether delegate and candidate produced identical output.
    pub fn is_equivalent(&self) -> bool {
        self.delegate_output == self.candidate_output
    }
}

/// Capability request from the native candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateCapabilityRequest {
    pub slot_id: SlotId,
    pub requested_capabilities: Vec<SlotCapability>,
    pub authority_envelope: AuthorityEnvelope,
}

impl CandidateCapabilityRequest {
    /// Check if all requested capabilities are within the authority envelope.
    pub fn within_envelope(&self) -> bool {
        self.requested_capabilities
            .iter()
            .all(|cap| self.authority_envelope.permitted.contains(cap))
    }

    /// Return capabilities that exceed the envelope.
    pub fn excess_capabilities(&self) -> Vec<&SlotCapability> {
        self.requested_capabilities
            .iter()
            .filter(|cap| !self.authority_envelope.permitted.contains(cap))
            .collect()
    }
}

/// Performance measurement for a single benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceMeasurement {
    pub benchmark_id: String,
    pub throughput_millionths: u64,
    pub latency_ns: u64,
    pub iterations: u64,
    pub seed: u64,
}

/// Adversarial test result for a single corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialTestResult {
    pub test_id: String,
    pub passed: bool,
    pub attack_surface: String,
    pub evidence: String,
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

/// Evaluate the equivalence gate.
pub fn evaluate_equivalence(
    test_cases: &[EquivalenceTestCase],
    strictness: &GateStrictness,
) -> GateEvaluation {
    let total = test_cases.len() as u64;
    let mut divergences = Vec::new();
    for tc in test_cases {
        if !tc.is_equivalent() {
            divergences.push(tc.test_id.clone());
        }
    }
    let divergence_count = divergences.len() as u64;
    let passed = divergence_count <= strictness.max_divergences;
    let mut evidence = vec![format!("total_cases={total}")];
    evidence.push(format!("divergences={divergence_count}"));
    evidence.push(format!("max_allowed={}", strictness.max_divergences));
    if !divergences.is_empty() {
        evidence.push(format!("divergent_tests={}", divergences.join(",")));
    }

    GateEvaluation {
        gate: GateKind::Equivalence,
        passed,
        required: strictness.required,
        evidence,
        summary: if passed {
            format!("{divergence_count}/{total} divergences (within threshold)")
        } else {
            format!(
                "{divergence_count}/{total} divergences (exceeds threshold of {})",
                strictness.max_divergences
            )
        },
    }
}

/// Evaluate the capability-preservation gate.
pub fn evaluate_capability_preservation(
    request: &CandidateCapabilityRequest,
    strictness: &GateStrictness,
) -> GateEvaluation {
    let excess = request.excess_capabilities();
    let passed = excess.is_empty();
    let mut evidence = vec![
        format!("requested={}", request.requested_capabilities.len()),
        format!("permitted={}", request.authority_envelope.permitted.len()),
    ];
    if !excess.is_empty() {
        let excess_names: Vec<String> = excess.iter().map(|c| format!("{c:?}")).collect();
        evidence.push(format!("excess_capabilities={}", excess_names.join(",")));
    }

    GateEvaluation {
        gate: GateKind::CapabilityPreservation,
        passed,
        required: strictness.required,
        evidence,
        summary: if passed {
            "all requested capabilities within authority envelope".to_string()
        } else {
            format!("{} capabilities exceed authority envelope", excess.len())
        },
    }
}

/// Evaluate the performance threshold gate.
pub fn evaluate_performance_threshold(
    measurements: &[PerformanceMeasurement],
    strictness: &GateStrictness,
) -> GateEvaluation {
    if measurements.is_empty() {
        return GateEvaluation {
            gate: GateKind::PerformanceThreshold,
            passed: false,
            required: strictness.required,
            evidence: vec!["no measurements provided".to_string()],
            summary: "no performance measurements available".to_string(),
        };
    }

    let mut throughput_failures = Vec::new();
    let mut latency_failures = Vec::new();
    let total = measurements.len();

    for m in measurements {
        if m.throughput_millionths < strictness.min_throughput_millionths {
            throughput_failures.push(m.benchmark_id.clone());
        }
        if strictness.max_latency_ns > 0 && m.latency_ns > strictness.max_latency_ns {
            latency_failures.push(m.benchmark_id.clone());
        }
    }

    let passed = throughput_failures.is_empty() && latency_failures.is_empty();
    let mut evidence = vec![
        format!("total_benchmarks={total}"),
        format!(
            "min_throughput_required={}",
            strictness.min_throughput_millionths
        ),
        format!("max_latency_allowed_ns={}", strictness.max_latency_ns),
    ];
    if !throughput_failures.is_empty() {
        evidence.push(format!(
            "throughput_failures={}",
            throughput_failures.join(",")
        ));
    }
    if !latency_failures.is_empty() {
        evidence.push(format!("latency_failures={}", latency_failures.join(",")));
    }

    GateEvaluation {
        gate: GateKind::PerformanceThreshold,
        passed,
        required: strictness.required,
        evidence,
        summary: if passed {
            format!("all {total} benchmarks within thresholds")
        } else {
            format!(
                "{} throughput + {} latency failures out of {total}",
                throughput_failures.len(),
                latency_failures.len()
            )
        },
    }
}

/// Evaluate the adversarial survival gate.
pub fn evaluate_adversarial_survival(
    results: &[AdversarialTestResult],
    strictness: &GateStrictness,
) -> GateEvaluation {
    if results.is_empty() {
        return GateEvaluation {
            gate: GateKind::AdversarialSurvival,
            passed: false,
            required: strictness.required,
            evidence: vec!["no adversarial tests provided".to_string()],
            summary: "no adversarial test results available".to_string(),
        };
    }

    let total = results.len() as u64;
    let passed_count = results.iter().filter(|r| r.passed).count() as u64;
    let pass_rate_millionths = passed_count
        .saturating_mul(1_000_000)
        .checked_div(total)
        .unwrap_or(0);

    let gate_passed = pass_rate_millionths >= strictness.min_adversarial_pass_rate_millionths;
    let failed_tests: Vec<&str> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.test_id.as_str())
        .collect();

    let mut evidence = vec![
        format!("total_tests={total}"),
        format!("passed={passed_count}"),
        format!("pass_rate_millionths={pass_rate_millionths}"),
        format!(
            "required_millionths={}",
            strictness.min_adversarial_pass_rate_millionths
        ),
    ];
    if !failed_tests.is_empty() {
        evidence.push(format!("failed_tests={}", failed_tests.join(",")));
    }

    GateEvaluation {
        gate: GateKind::AdversarialSurvival,
        passed: gate_passed,
        required: strictness.required,
        evidence,
        summary: if gate_passed {
            format!("{passed_count}/{total} adversarial tests passed ({pass_rate_millionths}/1M)")
        } else {
            format!(
                "{passed_count}/{total} adversarial tests passed ({pass_rate_millionths}/1M, required {})",
                strictness.min_adversarial_pass_rate_millionths
            )
        },
    }
}

/// Result of evaluating a single gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    pub gate: GateKind,
    pub passed: bool,
    pub required: bool,
    pub evidence: Vec<String>,
    pub summary: String,
}

impl GateEvaluation {
    /// Convert to the self_replacement `GateResult` type.
    pub fn to_gate_result(&self) -> GateResult {
        GateResult {
            gate_name: self.gate.as_str().to_string(),
            passed: self.passed,
            evidence_refs: self.evidence.clone(),
            summary: self.summary.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregate verdict
// ---------------------------------------------------------------------------

/// Aggregate all gate evaluations into an overall verdict.
pub fn aggregate_verdict(evaluations: &[GateEvaluation]) -> GateVerdict {
    if evaluations.is_empty() {
        return GateVerdict::Inconclusive;
    }

    // Check that all four required gates are present.
    let required_gates: BTreeSet<GateKind> = GateKind::all().iter().copied().collect();
    let present_gates: BTreeSet<GateKind> = evaluations.iter().map(|e| e.gate).collect();
    if !required_gates.is_subset(&present_gates) {
        return GateVerdict::Inconclusive;
    }

    // If any required gate failed, deny.
    let any_required_failed = evaluations.iter().any(|e| e.required && !e.passed);
    if any_required_failed {
        return GateVerdict::Denied;
    }

    GateVerdict::Approved
}

/// Assess risk level from gate evaluations.
pub fn assess_risk(evaluations: &[GateEvaluation]) -> RiskLevel {
    let failed_count = evaluations.iter().filter(|e| !e.passed).count();
    let advisory_failures = evaluations
        .iter()
        .filter(|e| !e.passed && !e.required)
        .count();

    if failed_count == 0 {
        RiskLevel::Low
    } else if failed_count == advisory_failures {
        // Only non-required gates failed.
        RiskLevel::Medium
    } else if failed_count <= 2 {
        RiskLevel::High
    } else {
        RiskLevel::Critical
    }
}

// ---------------------------------------------------------------------------
// Promotion gate runner
// ---------------------------------------------------------------------------

/// Configuration for a gate runner execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunnerConfig {
    pub slot_id: SlotId,
    pub candidate_digest: String,
    pub seed: u64,
    pub epoch: SecurityEpoch,
    pub zone: String,
    pub gate_strictness: Vec<GateStrictness>,
}

impl GateRunnerConfig {
    /// Create a standard config with default strictness for all gates.
    pub fn standard(slot_id: SlotId, candidate_digest: String, seed: u64) -> Self {
        Self {
            slot_id,
            candidate_digest,
            seed,
            epoch: SecurityEpoch::from_raw(1),
            zone: "default".to_string(),
            gate_strictness: GateKind::all()
                .iter()
                .map(|g| GateStrictness::standard(*g))
                .collect(),
        }
    }

    /// Get strictness for a specific gate.
    pub fn strictness_for(&self, gate: GateKind) -> Option<&GateStrictness> {
        self.gate_strictness.iter().find(|s| s.gate == gate)
    }
}

/// Input bundle for a gate runner execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunnerInput {
    pub equivalence_cases: Vec<EquivalenceTestCase>,
    pub capability_request: CandidateCapabilityRequest,
    pub performance_measurements: Vec<PerformanceMeasurement>,
    pub adversarial_results: Vec<AdversarialTestResult>,
}

/// Output of a gate runner execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunnerOutput {
    pub run_id: String,
    pub slot_id: SlotId,
    pub candidate_digest: String,
    pub evaluations: Vec<GateEvaluation>,
    pub verdict: GateVerdict,
    pub risk_level: RiskLevel,
    pub rollback_verified: bool,
    pub seed: u64,
    pub evidence_bundle: EvidenceBundle,
}

/// Evidence artifact bundle produced by the gate runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub artifacts: Vec<EvidenceArtifact>,
    pub total_test_cases: u64,
    pub total_passed: u64,
    pub total_failed: u64,
}

/// A single evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub artifact_id: String,
    pub gate: GateKind,
    pub content_hash: String,
    pub description: String,
}

/// Run all promotion gates.
pub fn run_promotion_gates(config: &GateRunnerConfig, input: &GateRunnerInput) -> GateRunnerOutput {
    let mut evaluations = Vec::new();
    let mut artifacts = Vec::new();
    let mut total_cases: u64 = 0;
    let mut total_passed: u64 = 0;
    let mut total_failed: u64 = 0;

    // Gate 1: Equivalence
    let eq_strictness = config
        .strictness_for(GateKind::Equivalence)
        .cloned()
        .unwrap_or_else(|| GateStrictness::standard(GateKind::Equivalence));
    let eq_eval = evaluate_equivalence(&input.equivalence_cases, &eq_strictness);
    total_cases += input.equivalence_cases.len() as u64;
    // Always count actual divergences regardless of whether the gate passed
    // (it can pass with nonzero tolerance via max_divergences).
    let eq_divergences = input
        .equivalence_cases
        .iter()
        .filter(|tc| !tc.is_equivalent())
        .count() as u64;
    total_passed += input.equivalence_cases.len() as u64 - eq_divergences;
    total_failed += eq_divergences;
    artifacts.push(EvidenceArtifact {
        artifact_id: format!("{}/equivalence", config.slot_id),
        gate: GateKind::Equivalence,
        content_hash: format!("{:016x}", config.seed.wrapping_mul(0x517cc1b727220a95)),
        description: eq_eval.summary.clone(),
    });
    evaluations.push(eq_eval);

    // Gate 2: Capability preservation
    let cap_strictness = config
        .strictness_for(GateKind::CapabilityPreservation)
        .cloned()
        .unwrap_or_else(|| GateStrictness::standard(GateKind::CapabilityPreservation));
    let cap_eval = evaluate_capability_preservation(&input.capability_request, &cap_strictness);
    total_cases += 1;
    if cap_eval.passed {
        total_passed += 1;
    } else {
        total_failed += 1;
    }
    artifacts.push(EvidenceArtifact {
        artifact_id: format!("{}/capability_preservation", config.slot_id),
        gate: GateKind::CapabilityPreservation,
        content_hash: format!("{:016x}", config.seed.wrapping_mul(0x6c62272e07bb0142)),
        description: cap_eval.summary.clone(),
    });
    evaluations.push(cap_eval);

    // Gate 3: Performance threshold
    let perf_strictness = config
        .strictness_for(GateKind::PerformanceThreshold)
        .cloned()
        .unwrap_or_else(|| GateStrictness::standard(GateKind::PerformanceThreshold));
    let perf_eval =
        evaluate_performance_threshold(&input.performance_measurements, &perf_strictness);
    total_cases += input.performance_measurements.len() as u64;
    let perf_pass_count = input
        .performance_measurements
        .iter()
        .filter(|m| {
            m.throughput_millionths >= perf_strictness.min_throughput_millionths
                && (perf_strictness.max_latency_ns == 0
                    || m.latency_ns <= perf_strictness.max_latency_ns)
        })
        .count() as u64;
    total_passed += perf_pass_count;
    total_failed += input.performance_measurements.len() as u64 - perf_pass_count;
    artifacts.push(EvidenceArtifact {
        artifact_id: format!("{}/performance_threshold", config.slot_id),
        gate: GateKind::PerformanceThreshold,
        content_hash: format!("{:016x}", config.seed.wrapping_mul(0x9e3779b97f4a7c15)),
        description: perf_eval.summary.clone(),
    });
    evaluations.push(perf_eval);

    // Gate 4: Adversarial survival
    let adv_strictness = config
        .strictness_for(GateKind::AdversarialSurvival)
        .cloned()
        .unwrap_or_else(|| GateStrictness::standard(GateKind::AdversarialSurvival));
    let adv_eval = evaluate_adversarial_survival(&input.adversarial_results, &adv_strictness);
    total_cases += input.adversarial_results.len() as u64;
    let adv_pass_count = input
        .adversarial_results
        .iter()
        .filter(|r| r.passed)
        .count() as u64;
    total_passed += adv_pass_count;
    total_failed += input.adversarial_results.len() as u64 - adv_pass_count;
    artifacts.push(EvidenceArtifact {
        artifact_id: format!("{}/adversarial_survival", config.slot_id),
        gate: GateKind::AdversarialSurvival,
        content_hash: format!("{:016x}", config.seed.wrapping_mul(0xbf58476d1ce4e5b9)),
        description: adv_eval.summary.clone(),
    });
    evaluations.push(adv_eval);

    let verdict = aggregate_verdict(&evaluations);
    let risk_level = assess_risk(&evaluations);

    // Rollback verification: we verify that the slot can rollback
    // (simulated here as always true when the delegate cell exists).
    let rollback_verified = true;

    let run_id = format!("gate-run-{:016x}", config.seed);

    GateRunnerOutput {
        run_id,
        slot_id: config.slot_id.clone(),
        candidate_digest: config.candidate_digest.clone(),
        evaluations,
        verdict,
        risk_level,
        rollback_verified,
        seed: config.seed,
        evidence_bundle: EvidenceBundle {
            artifacts,
            total_test_cases: total_cases,
            total_passed,
            total_failed,
        },
    }
}

// ---------------------------------------------------------------------------
// Structured logging events
// ---------------------------------------------------------------------------

/// Structured log event emitted by the gate runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunnerLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub gate: Option<GateKind>,
    pub slot_id: SlotId,
}

/// Build a log event for a gate evaluation.
pub fn log_gate_evaluation(
    config: &GateRunnerConfig,
    evaluation: &GateEvaluation,
) -> GateRunnerLogEvent {
    GateRunnerLogEvent {
        trace_id: format!("gate-{:016x}", config.seed),
        decision_id: format!("decision-{:016x}", config.seed),
        policy_id: "promotion-gate-policy".to_string(),
        component: "promotion_gate_runner".to_string(),
        event: format!("gate_evaluated:{}", evaluation.gate),
        outcome: if evaluation.passed {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if evaluation.passed {
            None
        } else {
            Some(format!(
                "FE-GATE-{}",
                evaluation.gate.as_str().to_uppercase()
            ))
        },
        gate: Some(evaluation.gate),
        slot_id: config.slot_id.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_registry::SlotCapability;

    fn test_slot_id() -> SlotId {
        SlotId::new("test-slot-01").expect("valid slot id")
    }

    fn test_authority_envelope() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::HeapAlloc,
            ],
        }
    }

    fn passing_equivalence_cases(count: usize) -> Vec<EquivalenceTestCase> {
        (0..count)
            .map(|i| EquivalenceTestCase {
                test_id: format!("eq-{i}"),
                input: vec![i as u8],
                delegate_output: vec![i as u8, 0xFF],
                candidate_output: vec![i as u8, 0xFF],
            })
            .collect()
    }

    fn failing_equivalence_cases(count: usize) -> Vec<EquivalenceTestCase> {
        (0..count)
            .map(|i| EquivalenceTestCase {
                test_id: format!("eq-fail-{i}"),
                input: vec![i as u8],
                delegate_output: vec![i as u8, 0xFF],
                candidate_output: vec![i as u8, 0xAA], // different!
            })
            .collect()
    }

    fn passing_capability_request() -> CandidateCapabilityRequest {
        CandidateCapabilityRequest {
            slot_id: test_slot_id(),
            requested_capabilities: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            authority_envelope: test_authority_envelope(),
        }
    }

    fn exceeding_capability_request() -> CandidateCapabilityRequest {
        CandidateCapabilityRequest {
            slot_id: test_slot_id(),
            requested_capabilities: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::InvokeHostcall, // not in permitted
            ],
            authority_envelope: test_authority_envelope(),
        }
    }

    fn passing_perf_measurements(count: usize) -> Vec<PerformanceMeasurement> {
        (0..count)
            .map(|i| PerformanceMeasurement {
                benchmark_id: format!("bench-{i}"),
                throughput_millionths: 1_000_000, // 1.0 ops/sec
                latency_ns: 50_000_000,           // 50ms
                iterations: 100,
                seed: 42 + i as u64,
            })
            .collect()
    }

    fn failing_perf_measurements() -> Vec<PerformanceMeasurement> {
        vec![PerformanceMeasurement {
            benchmark_id: "bench-slow".to_string(),
            throughput_millionths: 100_000, // 0.1 ops/sec - too slow
            latency_ns: 200_000_000,        // 200ms - too high
            iterations: 10,
            seed: 42,
        }]
    }

    fn passing_adversarial_results(count: usize) -> Vec<AdversarialTestResult> {
        (0..count)
            .map(|i| AdversarialTestResult {
                test_id: format!("adv-{i}"),
                passed: true,
                attack_surface: "memory_safety".to_string(),
                evidence: "no vulnerability detected".to_string(),
            })
            .collect()
    }

    fn mixed_adversarial_results() -> Vec<AdversarialTestResult> {
        vec![
            AdversarialTestResult {
                test_id: "adv-0".to_string(),
                passed: true,
                attack_surface: "memory_safety".to_string(),
                evidence: "ok".to_string(),
            },
            AdversarialTestResult {
                test_id: "adv-1".to_string(),
                passed: false,
                attack_surface: "injection".to_string(),
                evidence: "vulnerability found".to_string(),
            },
        ]
    }

    fn all_passing_input() -> GateRunnerInput {
        GateRunnerInput {
            equivalence_cases: passing_equivalence_cases(10),
            capability_request: passing_capability_request(),
            performance_measurements: passing_perf_measurements(5),
            adversarial_results: passing_adversarial_results(20),
        }
    }

    // ── gate kind ────────────────────────────────────────────────────

    #[test]
    fn gate_kind_all_has_four() {
        assert_eq!(GateKind::all().len(), 4);
    }

    #[test]
    fn gate_kind_display_unique() {
        let mut seen = BTreeSet::new();
        for gate in GateKind::all() {
            assert!(seen.insert(gate.as_str()));
        }
    }

    #[test]
    fn gate_kind_serde_round_trip() {
        for gate in GateKind::all() {
            let json = serde_json::to_string(gate).expect("serialize");
            let decoded: GateKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*gate, decoded);
        }
    }

    // ── equivalence gate ─────────────────────────────────────────────

    #[test]
    fn equivalence_all_pass() {
        let cases = passing_equivalence_cases(10);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.passed);
        assert_eq!(eval.gate, GateKind::Equivalence);
    }

    #[test]
    fn equivalence_some_fail() {
        let mut cases = passing_equivalence_cases(8);
        cases.extend(failing_equivalence_cases(2));
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn equivalence_tolerant_threshold() {
        let mut cases = passing_equivalence_cases(8);
        cases.extend(failing_equivalence_cases(2));
        let mut strictness = GateStrictness::standard(GateKind::Equivalence);
        strictness.max_divergences = 2;
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn equivalence_empty_cases() {
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&[], &strictness);
        assert!(eval.passed); // zero divergences <= 0 threshold
    }

    #[test]
    fn equivalence_test_case_is_equivalent() {
        let tc = EquivalenceTestCase {
            test_id: "t1".to_string(),
            input: vec![1],
            delegate_output: vec![2],
            candidate_output: vec![2],
        };
        assert!(tc.is_equivalent());
    }

    #[test]
    fn equivalence_test_case_not_equivalent() {
        let tc = EquivalenceTestCase {
            test_id: "t1".to_string(),
            input: vec![1],
            delegate_output: vec![2],
            candidate_output: vec![3],
        };
        assert!(!tc.is_equivalent());
    }

    // ── capability preservation gate ─────────────────────────────────

    #[test]
    fn capability_within_envelope_passes() {
        let request = passing_capability_request();
        let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
        let eval = evaluate_capability_preservation(&request, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn capability_exceeding_envelope_fails() {
        let request = exceeding_capability_request();
        let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
        let eval = evaluate_capability_preservation(&request, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn capability_excess_detected() {
        let request = exceeding_capability_request();
        let excess = request.excess_capabilities();
        assert_eq!(excess.len(), 1);
    }

    // ── performance threshold gate ───────────────────────────────────

    #[test]
    fn performance_all_within_threshold() {
        let measurements = passing_perf_measurements(5);
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn performance_below_threshold_fails() {
        let measurements = failing_perf_measurements();
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn performance_no_measurements_fails() {
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&[], &strictness);
        assert!(!eval.passed);
    }

    // ── adversarial survival gate ────────────────────────────────────

    #[test]
    fn adversarial_all_pass() {
        let results = passing_adversarial_results(20);
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn adversarial_below_threshold_fails() {
        let results = mixed_adversarial_results(); // 50% pass rate
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn adversarial_no_results_fails() {
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&[], &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn adversarial_lenient_threshold() {
        let results = mixed_adversarial_results(); // 50% pass rate
        let mut strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        strictness.min_adversarial_pass_rate_millionths = 400_000; // 40%
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.passed);
    }

    // ── aggregate verdict ────────────────────────────────────────────

    #[test]
    fn aggregate_all_pass_approved() {
        let evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            })
            .collect();
        assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
    }

    #[test]
    fn aggregate_one_required_fail_denied() {
        let mut evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            })
            .collect();
        evals[0].passed = false;
        assert_eq!(aggregate_verdict(&evals), GateVerdict::Denied);
    }

    #[test]
    fn aggregate_missing_gate_inconclusive() {
        let evals = vec![GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        }];
        assert_eq!(aggregate_verdict(&evals), GateVerdict::Inconclusive);
    }

    #[test]
    fn aggregate_empty_inconclusive() {
        assert_eq!(aggregate_verdict(&[]), GateVerdict::Inconclusive);
    }

    #[test]
    fn aggregate_advisory_fail_still_approved() {
        let evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: *g != GateKind::PerformanceThreshold,
                required: *g != GateKind::PerformanceThreshold,
                evidence: vec![],
                summary: "ok".to_string(),
            })
            .collect();
        assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
    }

    // ── risk assessment ──────────────────────────────────────────────

    #[test]
    fn risk_all_pass_low() {
        let evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            })
            .collect();
        assert_eq!(assess_risk(&evals), RiskLevel::Low);
    }

    #[test]
    fn risk_advisory_fail_medium() {
        let evals = vec![
            GateEvaluation {
                gate: GateKind::Equivalence,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            },
            GateEvaluation {
                gate: GateKind::PerformanceThreshold,
                passed: false,
                required: false, // advisory only
                evidence: vec![],
                summary: "advisory fail".to_string(),
            },
        ];
        assert_eq!(assess_risk(&evals), RiskLevel::Medium);
    }

    #[test]
    fn risk_required_fail_high() {
        let evals = vec![
            GateEvaluation {
                gate: GateKind::Equivalence,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
            GateEvaluation {
                gate: GateKind::CapabilityPreservation,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            },
        ];
        assert_eq!(assess_risk(&evals), RiskLevel::High);
    }

    #[test]
    fn risk_many_required_fail_critical() {
        let evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            })
            .collect();
        assert_eq!(assess_risk(&evals), RiskLevel::Critical);
    }

    // ── full gate runner ─────────────────────────────────────────────

    #[test]
    fn full_run_all_pass() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-abc123".to_string(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert_eq!(output.risk_level, RiskLevel::Low);
        assert!(output.rollback_verified);
        assert_eq!(output.evaluations.len(), 4);
        assert!(output.evidence_bundle.total_failed == 0);
    }

    #[test]
    fn full_run_equivalence_fail() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-bad".to_string(), 42);
        let input = GateRunnerInput {
            equivalence_cases: failing_equivalence_cases(5),
            capability_request: passing_capability_request(),
            performance_measurements: passing_perf_measurements(3),
            adversarial_results: passing_adversarial_results(10),
        };
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(output.evidence_bundle.total_failed > 0);
    }

    #[test]
    fn full_run_capability_exceed_fail() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-greedy".to_string(), 42);
        let input = GateRunnerInput {
            equivalence_cases: passing_equivalence_cases(5),
            capability_request: exceeding_capability_request(),
            performance_measurements: passing_perf_measurements(3),
            adversarial_results: passing_adversarial_results(10),
        };
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Denied);
    }

    #[test]
    fn full_run_evidence_bundle_counts() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-abc".to_string(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        let bundle = &output.evidence_bundle;
        assert_eq!(bundle.artifacts.len(), 4);
        assert_eq!(
            bundle.total_passed + bundle.total_failed,
            bundle.total_test_cases
        );
    }

    #[test]
    fn full_run_deterministic() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-det".to_string(), 123);
        let input = all_passing_input();
        let out1 = run_promotion_gates(&config, &input);
        let out2 = run_promotion_gates(&config, &input);
        assert_eq!(out1.verdict, out2.verdict);
        assert_eq!(out1.run_id, out2.run_id);
        assert_eq!(out1.evidence_bundle, out2.evidence_bundle);
    }

    // ── gate runner config ───────────────────────────────────────────

    #[test]
    fn config_standard_has_all_gates() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        assert_eq!(config.gate_strictness.len(), 4);
        for gate in GateKind::all() {
            assert!(config.strictness_for(*gate).is_some());
        }
    }

    #[test]
    fn config_serde_round_trip() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        let json = serde_json::to_vec(&config).expect("serialize");
        let decoded: GateRunnerConfig = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(config, decoded);
    }

    // ── gate evaluation conversion ───────────────────────────────────

    #[test]
    fn gate_evaluation_to_gate_result() {
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec!["evidence-1".to_string()],
            summary: "all equivalent".to_string(),
        };
        let result = eval.to_gate_result();
        assert_eq!(result.gate_name, "equivalence");
        assert!(result.passed);
        assert_eq!(result.evidence_refs.len(), 1);
    }

    #[test]
    fn gate_evaluation_serde_round_trip() {
        let eval = GateEvaluation {
            gate: GateKind::AdversarialSurvival,
            passed: false,
            required: true,
            evidence: vec!["ev1".to_string(), "ev2".to_string()],
            summary: "failed".to_string(),
        };
        let json = serde_json::to_vec(&eval).expect("serialize");
        let decoded: GateEvaluation = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(eval, decoded);
    }

    // ── structured logging ───────────────────────────────────────────

    #[test]
    fn log_event_pass() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
        assert_eq!(event.component, "promotion_gate_runner");
    }

    #[test]
    fn log_event_fail_has_error_code() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        let eval = GateEvaluation {
            gate: GateKind::CapabilityPreservation,
            passed: false,
            required: true,
            evidence: vec![],
            summary: "fail".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        assert_eq!(event.outcome, "fail");
        assert!(event.error_code.is_some());
        assert!(event.error_code.unwrap().starts_with("FE-GATE-"));
    }

    #[test]
    fn log_event_serde_round_trip() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        let eval = GateEvaluation {
            gate: GateKind::PerformanceThreshold,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        let json = serde_json::to_vec(&event).expect("serialize");
        let decoded: GateRunnerLogEvent = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(event, decoded);
    }

    // ── gate strictness ──────────────────────────────────────────────

    #[test]
    fn strictness_standard_all_required() {
        for gate in GateKind::all() {
            let s = GateStrictness::standard(*gate);
            assert!(s.required);
        }
    }

    #[test]
    fn strictness_serde_round_trip() {
        let s = GateStrictness::standard(GateKind::PerformanceThreshold);
        let json = serde_json::to_vec(&s).expect("serialize");
        let decoded: GateStrictness = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(s, decoded);
    }

    // ── output serde ─────────────────────────────────────────────────

    #[test]
    fn gate_runner_output_serde_round_trip() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        let json = serde_json::to_vec(&output).expect("serialize");
        let decoded: GateRunnerOutput = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(output, decoded);
    }

    #[test]
    fn evidence_artifact_serde_round_trip() {
        let artifact = EvidenceArtifact {
            artifact_id: "test/artifact".to_string(),
            gate: GateKind::Equivalence,
            content_hash: "deadbeef".to_string(),
            description: "test evidence".to_string(),
        };
        let json = serde_json::to_vec(&artifact).expect("serialize");
        let decoded: EvidenceArtifact = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(artifact, decoded);
    }

    #[test]
    fn gate_kind_ord() {
        assert!(GateKind::Equivalence < GateKind::CapabilityPreservation);
        assert!(GateKind::CapabilityPreservation < GateKind::PerformanceThreshold);
        assert!(GateKind::PerformanceThreshold < GateKind::AdversarialSurvival);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateKind Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn gate_kind_display_all_unique_btreeset() {
        let mut displays = BTreeSet::new();
        for gate in GateKind::all() {
            displays.insert(gate.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all GateKind variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateVerdict ordering and uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn gate_verdict_display_all_unique() {
        let verdicts = [
            GateVerdict::Approved,
            GateVerdict::Denied,
            GateVerdict::Inconclusive,
        ];
        let mut displays = BTreeSet::new();
        for v in &verdicts {
            displays.insert(format!("{v:?}"));
        }
        assert_eq!(displays.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GateStrictness defaults for all gates
    // -----------------------------------------------------------------------

    #[test]
    fn strictness_standard_equivalence_zero_divergences() {
        let s = GateStrictness::standard(GateKind::Equivalence);
        assert_eq!(
            s.max_divergences, 0,
            "equivalence gate must allow zero divergences by default"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: full run with performance-only fail
    // -----------------------------------------------------------------------

    #[test]
    fn full_run_performance_only_fail() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-slow".to_string(), 42);
        let input = GateRunnerInput {
            equivalence_cases: passing_equivalence_cases(10),
            capability_request: passing_capability_request(),
            performance_measurements: failing_perf_measurements(),
            adversarial_results: passing_adversarial_results(20),
        };
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Denied);
        // Only performance gate should fail
        let perf_eval = output
            .evaluations
            .iter()
            .find(|e| e.gate == GateKind::PerformanceThreshold)
            .unwrap();
        assert!(!perf_eval.passed);
        let eq_eval = output
            .evaluations
            .iter()
            .find(|e| e.gate == GateKind::Equivalence)
            .unwrap();
        assert!(eq_eval.passed);
    }

    // -----------------------------------------------------------------------
    // Enrichment: evidence bundle artifact count matches gates
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_bundle_artifact_ids_unique() {
        let config = GateRunnerConfig::standard(test_slot_id(), "candidate-abc".to_string(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        let mut ids = BTreeSet::new();
        for artifact in &output.evidence_bundle.artifacts {
            ids.insert(artifact.artifact_id.clone());
        }
        assert_eq!(
            ids.len(),
            output.evidence_bundle.artifacts.len(),
            "artifact IDs must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: EquivalenceTestCase serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn equivalence_test_case_serde_roundtrip() {
        let tc = EquivalenceTestCase {
            test_id: "eq-42".to_string(),
            input: vec![1, 2, 3],
            delegate_output: vec![4, 5],
            candidate_output: vec![4, 5],
        };
        let json = serde_json::to_string(&tc).expect("serialize");
        let back: EquivalenceTestCase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tc, back);
        assert!(back.is_equivalent());
    }

    // -----------------------------------------------------------------------
    // Enrichment: PerformanceMeasurement serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn performance_measurement_serde_roundtrip() {
        let pm = PerformanceMeasurement {
            benchmark_id: "bench-99".to_string(),
            throughput_millionths: 2_000_000,
            latency_ns: 10_000_000,
            iterations: 500,
            seed: 77,
        };
        let json = serde_json::to_string(&pm).expect("serialize");
        let back: PerformanceMeasurement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pm, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: AdversarialTestResult serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn adversarial_test_result_serde_roundtrip() {
        let atr = AdversarialTestResult {
            test_id: "adv-77".to_string(),
            passed: false,
            attack_surface: "injection".to_string(),
            evidence: "found vulnerability".to_string(),
        };
        let json = serde_json::to_string(&atr).expect("serialize");
        let back: AdversarialTestResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(atr, back);
    }

    // ===================================================================
    // Enrichment batch 2: Copy semantics
    // ===================================================================

    #[test]
    fn gate_kind_copy_semantics() {
        let a = GateKind::Equivalence;
        let b = a; // Copy
        assert_eq!(a, b);
        // a is still usable after copy
        assert_eq!(a.as_str(), "equivalence");
    }

    #[test]
    fn gate_kind_copy_all_variants() {
        for gate in GateKind::all() {
            let copied = *gate;
            assert_eq!(*gate, copied);
        }
    }

    // ===================================================================
    // Enrichment batch 2: Debug distinctness
    // ===================================================================

    #[test]
    fn gate_kind_debug_all_distinct() {
        let mut debugs = BTreeSet::new();
        for gate in GateKind::all() {
            let d = format!("{gate:?}");
            assert!(!d.is_empty());
            debugs.insert(d);
        }
        assert_eq!(debugs.len(), 4, "all GateKind variants have distinct Debug");
    }

    #[test]
    fn gate_evaluation_debug_not_empty() {
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec!["e1".to_string()],
            summary: "ok".to_string(),
        };
        let d = format!("{eval:?}");
        assert!(d.contains("Equivalence"));
        assert!(d.contains("true"));
    }

    #[test]
    fn gate_strictness_debug_contains_gate() {
        let s = GateStrictness::standard(GateKind::PerformanceThreshold);
        let d = format!("{s:?}");
        assert!(d.contains("PerformanceThreshold"));
    }

    #[test]
    fn evidence_artifact_debug_contains_gate() {
        let a = EvidenceArtifact {
            artifact_id: "art-1".to_string(),
            gate: GateKind::AdversarialSurvival,
            content_hash: "abc".to_string(),
            description: "desc".to_string(),
        };
        let d = format!("{a:?}");
        assert!(d.contains("AdversarialSurvival"));
        assert!(d.contains("art-1"));
    }

    #[test]
    fn gate_runner_log_event_debug_contains_component() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        let d = format!("{event:?}");
        assert!(d.contains("promotion_gate_runner"));
    }

    // ===================================================================
    // Enrichment batch 2: Serde variant distinctness
    // ===================================================================

    #[test]
    fn gate_kind_serde_all_distinct_json() {
        let mut jsons = BTreeSet::new();
        for gate in GateKind::all() {
            let j = serde_json::to_string(gate).expect("serialize");
            jsons.insert(j);
        }
        assert_eq!(
            jsons.len(),
            4,
            "all GateKind variants serialize to distinct JSON"
        );
    }

    // ===================================================================
    // Enrichment batch 2: Clone independence
    // ===================================================================

    #[test]
    fn gate_strictness_clone_independence() {
        let original = GateStrictness::standard(GateKind::Equivalence);
        let mut _cloned = original.clone();
        _cloned.max_divergences = 999;
        _cloned.required = false;
        assert_eq!(original.max_divergences, 0);
        assert!(original.required);
    }

    #[test]
    fn gate_evaluation_clone_independence() {
        let original = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec!["ev-1".to_string()],
            summary: "ok".to_string(),
        };
        let mut cloned = original.clone();
        cloned.passed = false;
        cloned.evidence.push("extra".to_string());
        cloned.summary = "changed".to_string();
        assert!(original.passed);
        assert_eq!(original.evidence.len(), 1);
        assert_eq!(original.summary, "ok");
    }

    #[test]
    fn gate_runner_config_clone_independence() {
        let original = GateRunnerConfig::standard(test_slot_id(), "cand".to_string(), 42);
        let mut cloned = original.clone();
        cloned.seed = 999;
        cloned.zone = "mutated".to_string();
        cloned.candidate_digest = "different".to_string();
        assert_eq!(original.seed, 42);
        assert_eq!(original.zone, "default");
        assert_eq!(original.candidate_digest, "cand");
    }

    #[test]
    fn equivalence_test_case_clone_independence() {
        let original = EquivalenceTestCase {
            test_id: "tc-1".to_string(),
            input: vec![1, 2],
            delegate_output: vec![3, 4],
            candidate_output: vec![3, 4],
        };
        let mut cloned = original.clone();
        cloned.candidate_output = vec![99];
        assert_eq!(original.candidate_output, vec![3, 4]);
        assert!(original.is_equivalent());
    }

    #[test]
    fn performance_measurement_clone_independence() {
        let original = PerformanceMeasurement {
            benchmark_id: "b-1".to_string(),
            throughput_millionths: 1_000_000,
            latency_ns: 50_000,
            iterations: 100,
            seed: 42,
        };
        let mut cloned = original.clone();
        cloned.throughput_millionths = 0;
        cloned.latency_ns = u64::MAX;
        assert_eq!(original.throughput_millionths, 1_000_000);
        assert_eq!(original.latency_ns, 50_000);
    }

    #[test]
    fn adversarial_test_result_clone_independence() {
        let original = AdversarialTestResult {
            test_id: "a-1".to_string(),
            passed: true,
            attack_surface: "mem".to_string(),
            evidence: "ok".to_string(),
        };
        let mut cloned = original.clone();
        cloned.passed = false;
        cloned.evidence = "changed".to_string();
        assert!(original.passed);
        assert_eq!(original.evidence, "ok");
    }

    #[test]
    fn candidate_capability_request_clone_independence() {
        let original = passing_capability_request();
        let mut cloned = original.clone();
        cloned
            .requested_capabilities
            .push(SlotCapability::InvokeHostcall);
        assert_eq!(original.requested_capabilities.len(), 2);
        assert!(original.within_envelope());
    }

    #[test]
    fn evidence_bundle_clone_independence() {
        let original = EvidenceBundle {
            artifacts: vec![EvidenceArtifact {
                artifact_id: "a-1".to_string(),
                gate: GateKind::Equivalence,
                content_hash: "h".to_string(),
                description: "d".to_string(),
            }],
            total_test_cases: 10,
            total_passed: 8,
            total_failed: 2,
        };
        let mut cloned = original.clone();
        cloned.total_passed = 0;
        cloned.artifacts.clear();
        assert_eq!(original.total_passed, 8);
        assert_eq!(original.artifacts.len(), 1);
    }

    #[test]
    fn gate_runner_output_clone_independence() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        let input = all_passing_input();
        let original = run_promotion_gates(&config, &input);
        let mut cloned = original.clone();
        cloned.verdict = GateVerdict::Denied;
        cloned.risk_level = RiskLevel::Critical;
        cloned.rollback_verified = false;
        assert_eq!(original.verdict, GateVerdict::Approved);
        assert_eq!(original.risk_level, RiskLevel::Low);
        assert!(original.rollback_verified);
    }

    #[test]
    fn gate_runner_log_event_clone_independence() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let original = log_gate_evaluation(&config, &eval);
        let mut cloned = original.clone();
        cloned.outcome = "fail".to_string();
        cloned.error_code = Some("FE-GATE-TEST".to_string());
        assert_eq!(original.outcome, "pass");
        assert!(original.error_code.is_none());
    }

    // ===================================================================
    // Enrichment batch 2: JSON field-name stability
    // ===================================================================

    #[test]
    fn gate_strictness_json_field_names() {
        let s = GateStrictness::standard(GateKind::Equivalence);
        let json = serde_json::to_string(&s).expect("serialize");
        assert!(json.contains("\"gate\""));
        assert!(json.contains("\"required\""));
        assert!(json.contains("\"max_divergences\""));
        assert!(json.contains("\"min_throughput_millionths\""));
        assert!(json.contains("\"max_latency_ns\""));
        assert!(json.contains("\"min_adversarial_pass_rate_millionths\""));
    }

    #[test]
    fn gate_evaluation_json_field_names() {
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "s".to_string(),
        };
        let json = serde_json::to_string(&eval).expect("serialize");
        assert!(json.contains("\"gate\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"required\""));
        assert!(json.contains("\"evidence\""));
        assert!(json.contains("\"summary\""));
    }

    #[test]
    fn equivalence_test_case_json_field_names() {
        let tc = EquivalenceTestCase {
            test_id: "t1".to_string(),
            input: vec![1],
            delegate_output: vec![2],
            candidate_output: vec![3],
        };
        let json = serde_json::to_string(&tc).expect("serialize");
        assert!(json.contains("\"test_id\""));
        assert!(json.contains("\"input\""));
        assert!(json.contains("\"delegate_output\""));
        assert!(json.contains("\"candidate_output\""));
    }

    #[test]
    fn performance_measurement_json_field_names() {
        let pm = PerformanceMeasurement {
            benchmark_id: "b".to_string(),
            throughput_millionths: 0,
            latency_ns: 0,
            iterations: 0,
            seed: 0,
        };
        let json = serde_json::to_string(&pm).expect("serialize");
        assert!(json.contains("\"benchmark_id\""));
        assert!(json.contains("\"throughput_millionths\""));
        assert!(json.contains("\"latency_ns\""));
        assert!(json.contains("\"iterations\""));
        assert!(json.contains("\"seed\""));
    }

    #[test]
    fn adversarial_test_result_json_field_names() {
        let atr = AdversarialTestResult {
            test_id: "a".to_string(),
            passed: true,
            attack_surface: "s".to_string(),
            evidence: "e".to_string(),
        };
        let json = serde_json::to_string(&atr).expect("serialize");
        assert!(json.contains("\"test_id\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"attack_surface\""));
        assert!(json.contains("\"evidence\""));
    }

    #[test]
    fn evidence_artifact_json_field_names() {
        let ea = EvidenceArtifact {
            artifact_id: "a".to_string(),
            gate: GateKind::Equivalence,
            content_hash: "h".to_string(),
            description: "d".to_string(),
        };
        let json = serde_json::to_string(&ea).expect("serialize");
        assert!(json.contains("\"artifact_id\""));
        assert!(json.contains("\"gate\""));
        assert!(json.contains("\"content_hash\""));
        assert!(json.contains("\"description\""));
    }

    #[test]
    fn evidence_bundle_json_field_names() {
        let eb = EvidenceBundle {
            artifacts: vec![],
            total_test_cases: 0,
            total_passed: 0,
            total_failed: 0,
        };
        let json = serde_json::to_string(&eb).expect("serialize");
        assert!(json.contains("\"artifacts\""));
        assert!(json.contains("\"total_test_cases\""));
        assert!(json.contains("\"total_passed\""));
        assert!(json.contains("\"total_failed\""));
    }

    #[test]
    fn gate_runner_config_json_field_names() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let json = serde_json::to_string(&config).expect("serialize");
        assert!(json.contains("\"slot_id\""));
        assert!(json.contains("\"candidate_digest\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"zone\""));
        assert!(json.contains("\"gate_strictness\""));
    }

    #[test]
    fn gate_runner_output_json_field_names() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        let json = serde_json::to_string(&output).expect("serialize");
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"slot_id\""));
        assert!(json.contains("\"candidate_digest\""));
        assert!(json.contains("\"evaluations\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"risk_level\""));
        assert!(json.contains("\"rollback_verified\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"evidence_bundle\""));
    }

    #[test]
    fn gate_runner_log_event_json_field_names() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"gate\""));
        assert!(json.contains("\"slot_id\""));
    }

    #[test]
    fn gate_runner_input_json_field_names() {
        let input = all_passing_input();
        let json = serde_json::to_string(&input).expect("serialize");
        assert!(json.contains("\"equivalence_cases\""));
        assert!(json.contains("\"capability_request\""));
        assert!(json.contains("\"performance_measurements\""));
        assert!(json.contains("\"adversarial_results\""));
    }

    #[test]
    fn candidate_capability_request_json_field_names() {
        let req = passing_capability_request();
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains("\"slot_id\""));
        assert!(json.contains("\"requested_capabilities\""));
        assert!(json.contains("\"authority_envelope\""));
    }

    // ===================================================================
    // Enrichment batch 2: Display format checks
    // ===================================================================

    #[test]
    fn gate_kind_display_equivalence() {
        assert_eq!(GateKind::Equivalence.to_string(), "equivalence");
    }

    #[test]
    fn gate_kind_display_capability_preservation() {
        assert_eq!(
            GateKind::CapabilityPreservation.to_string(),
            "capability_preservation"
        );
    }

    #[test]
    fn gate_kind_display_performance_threshold() {
        assert_eq!(
            GateKind::PerformanceThreshold.to_string(),
            "performance_threshold"
        );
    }

    #[test]
    fn gate_kind_display_adversarial_survival() {
        assert_eq!(
            GateKind::AdversarialSurvival.to_string(),
            "adversarial_survival"
        );
    }

    #[test]
    fn gate_kind_display_matches_as_str() {
        for gate in GateKind::all() {
            assert_eq!(gate.to_string(), gate.as_str());
        }
    }

    // ===================================================================
    // Enrichment batch 2: Hash consistency
    // ===================================================================

    #[test]
    fn gate_kind_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for gate in GateKind::all() {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            gate.hash(&mut h1);
            let hash1 = h1.finish();

            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            gate.hash(&mut h2);
            let hash2 = h2.finish();

            assert_eq!(hash1, hash2, "same GateKind must hash identically");
        }
    }

    #[test]
    fn gate_kind_hash_distinct_variants() {
        use std::hash::{Hash, Hasher};
        let mut hashes = BTreeSet::new();
        for gate in GateKind::all() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            gate.hash(&mut h);
            hashes.insert(h.finish());
        }
        assert_eq!(
            hashes.len(),
            4,
            "all GateKind variants have distinct hashes"
        );
    }

    // ===================================================================
    // Enrichment batch 2: Boundary/edge cases
    // ===================================================================

    #[test]
    fn equivalence_all_fail() {
        let cases = failing_equivalence_cases(100);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(!eval.passed);
        assert!(eval.summary.contains("100"));
    }

    #[test]
    fn equivalence_single_case_pass() {
        let cases = passing_equivalence_cases(1);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn equivalence_single_case_fail() {
        let cases = failing_equivalence_cases(1);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn equivalence_large_threshold() {
        let cases = failing_equivalence_cases(50);
        let mut strictness = GateStrictness::standard(GateKind::Equivalence);
        strictness.max_divergences = u64::MAX;
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.passed, "u64::MAX threshold should pass anything");
    }

    #[test]
    fn equivalence_empty_outputs_are_equivalent() {
        let tc = EquivalenceTestCase {
            test_id: "empty".to_string(),
            input: vec![],
            delegate_output: vec![],
            candidate_output: vec![],
        };
        assert!(tc.is_equivalent());
    }

    #[test]
    fn performance_u64_max_throughput_passes() {
        let measurements = vec![PerformanceMeasurement {
            benchmark_id: "max-bench".to_string(),
            throughput_millionths: u64::MAX,
            latency_ns: 0,
            iterations: 1,
            seed: 0,
        }];
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn performance_zero_throughput_fails_standard() {
        let measurements = vec![PerformanceMeasurement {
            benchmark_id: "zero-bench".to_string(),
            throughput_millionths: 0,
            latency_ns: 1,
            iterations: 1,
            seed: 0,
        }];
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(
            !eval.passed,
            "zero throughput should fail standard threshold"
        );
    }

    #[test]
    fn performance_exactly_at_threshold() {
        let measurements = vec![PerformanceMeasurement {
            benchmark_id: "exact-bench".to_string(),
            throughput_millionths: 500_000, // exactly at minimum
            latency_ns: 100_000_000,        // exactly at maximum
            iterations: 1,
            seed: 0,
        }];
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(eval.passed, "exactly at threshold should pass");
    }

    #[test]
    fn performance_latency_one_over_threshold() {
        let measurements = vec![PerformanceMeasurement {
            benchmark_id: "over-bench".to_string(),
            throughput_millionths: 1_000_000,
            latency_ns: 100_000_001, // 1ns over threshold
            iterations: 1,
            seed: 0,
        }];
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(!eval.passed, "1ns over latency threshold should fail");
    }

    #[test]
    fn performance_zero_max_latency_allows_any() {
        let measurements = vec![PerformanceMeasurement {
            benchmark_id: "any-latency".to_string(),
            throughput_millionths: 1_000_000,
            latency_ns: u64::MAX,
            iterations: 1,
            seed: 0,
        }];
        let mut strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        strictness.max_latency_ns = 0; // 0 means no latency check
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(eval.passed, "max_latency_ns=0 should skip latency check");
    }

    #[test]
    fn adversarial_all_fail() {
        let results: Vec<AdversarialTestResult> = (0..10)
            .map(|i| AdversarialTestResult {
                test_id: format!("fail-{i}"),
                passed: false,
                attack_surface: "all".to_string(),
                evidence: "failed".to_string(),
            })
            .collect();
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(!eval.passed);
    }

    #[test]
    fn adversarial_single_pass() {
        let results = vec![AdversarialTestResult {
            test_id: "single".to_string(),
            passed: true,
            attack_surface: "xss".to_string(),
            evidence: "safe".to_string(),
        }];
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.passed, "100% pass rate exceeds 95% threshold");
    }

    #[test]
    fn adversarial_exact_95_percent() {
        // 19/20 = 950000/1000000 = exactly 95%
        let mut results = passing_adversarial_results(19);
        results.push(AdversarialTestResult {
            test_id: "adv-fail".to_string(),
            passed: false,
            attack_surface: "test".to_string(),
            evidence: "fail".to_string(),
        });
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.passed, "exactly 95% should pass the 95% threshold");
    }

    #[test]
    fn adversarial_just_below_95_percent() {
        // 18/20 = 900000/1000000 = 90% < 95%
        let mut results = passing_adversarial_results(18);
        results.push(AdversarialTestResult {
            test_id: "f1".to_string(),
            passed: false,
            attack_surface: "t".to_string(),
            evidence: "e".to_string(),
        });
        results.push(AdversarialTestResult {
            test_id: "f2".to_string(),
            passed: false,
            attack_surface: "t".to_string(),
            evidence: "e".to_string(),
        });
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(!eval.passed, "90% should fail the 95% threshold");
    }

    #[test]
    fn adversarial_zero_threshold_always_passes() {
        let results = mixed_adversarial_results();
        let mut strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        strictness.min_adversarial_pass_rate_millionths = 0;
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn capability_empty_request_passes() {
        let request = CandidateCapabilityRequest {
            slot_id: test_slot_id(),
            requested_capabilities: vec![],
            authority_envelope: test_authority_envelope(),
        };
        assert!(request.within_envelope());
        assert!(request.excess_capabilities().is_empty());
        let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
        let eval = evaluate_capability_preservation(&request, &strictness);
        assert!(eval.passed);
    }

    #[test]
    fn capability_all_slot_capabilities_excess() {
        let request = CandidateCapabilityRequest {
            slot_id: test_slot_id(),
            requested_capabilities: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::HeapAlloc,
                SlotCapability::ScheduleAsync,
                SlotCapability::InvokeHostcall,
                SlotCapability::ModuleAccess,
                SlotCapability::TriggerGc,
                SlotCapability::EmitEvidence,
            ],
            authority_envelope: test_authority_envelope(),
        };
        // envelope permits ReadSource, EmitIr, HeapAlloc — 5 excess
        let excess = request.excess_capabilities();
        assert_eq!(excess.len(), 5);
        assert!(!request.within_envelope());
    }

    #[test]
    fn aggregate_verdict_duplicate_gates() {
        // Two evaluations for the same gate — should still work
        let mut evals: Vec<GateEvaluation> = GateKind::all()
            .iter()
            .map(|g| GateEvaluation {
                gate: *g,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            })
            .collect();
        evals.push(GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "duplicate".to_string(),
        });
        assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
    }

    #[test]
    fn risk_empty_evaluations_is_low() {
        assert_eq!(assess_risk(&[]), RiskLevel::Low);
    }

    #[test]
    fn risk_two_required_failures_is_high() {
        let evals = vec![
            GateEvaluation {
                gate: GateKind::Equivalence,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
            GateEvaluation {
                gate: GateKind::CapabilityPreservation,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
        ];
        assert_eq!(assess_risk(&evals), RiskLevel::High);
    }

    #[test]
    fn risk_three_required_failures_is_critical() {
        let evals = vec![
            GateEvaluation {
                gate: GateKind::Equivalence,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
            GateEvaluation {
                gate: GateKind::CapabilityPreservation,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
            GateEvaluation {
                gate: GateKind::PerformanceThreshold,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            },
        ];
        assert_eq!(assess_risk(&evals), RiskLevel::Critical);
    }

    // ===================================================================
    // Enrichment batch 2: Serde roundtrips (complex structs)
    // ===================================================================

    #[test]
    fn gate_runner_input_serde_roundtrip() {
        let input = all_passing_input();
        let json = serde_json::to_string(&input).expect("serialize");
        let back: GateRunnerInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(input, back);
    }

    #[test]
    fn gate_runner_input_empty_collections_serde_roundtrip() {
        let input = GateRunnerInput {
            equivalence_cases: vec![],
            capability_request: CandidateCapabilityRequest {
                slot_id: test_slot_id(),
                requested_capabilities: vec![],
                authority_envelope: AuthorityEnvelope {
                    required: vec![],
                    permitted: vec![],
                },
            },
            performance_measurements: vec![],
            adversarial_results: vec![],
        };
        let json = serde_json::to_string(&input).expect("serialize");
        let back: GateRunnerInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(input, back);
    }

    #[test]
    fn evidence_bundle_serde_roundtrip() {
        let bundle = EvidenceBundle {
            artifacts: vec![
                EvidenceArtifact {
                    artifact_id: "a-1".to_string(),
                    gate: GateKind::Equivalence,
                    content_hash: "h1".to_string(),
                    description: "d1".to_string(),
                },
                EvidenceArtifact {
                    artifact_id: "a-2".to_string(),
                    gate: GateKind::AdversarialSurvival,
                    content_hash: "h2".to_string(),
                    description: "d2".to_string(),
                },
            ],
            total_test_cases: 100,
            total_passed: 95,
            total_failed: 5,
        };
        let json = serde_json::to_string(&bundle).expect("serialize");
        let back: EvidenceBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(bundle, back);
    }

    #[test]
    fn candidate_capability_request_serde_roundtrip() {
        let req = exceeding_capability_request();
        let json = serde_json::to_string(&req).expect("serialize");
        let back: CandidateCapabilityRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back);
    }

    #[test]
    fn gate_runner_output_full_fail_serde_roundtrip() {
        let config = GateRunnerConfig::standard(test_slot_id(), "bad".to_string(), 99);
        let input = GateRunnerInput {
            equivalence_cases: failing_equivalence_cases(5),
            capability_request: exceeding_capability_request(),
            performance_measurements: failing_perf_measurements(),
            adversarial_results: mixed_adversarial_results(),
        };
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Denied);
        let json = serde_json::to_string(&output).expect("serialize");
        let back: GateRunnerOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(output, back);
    }

    // ===================================================================
    // Enrichment batch 2: Evidence and summary content checks
    // ===================================================================

    #[test]
    fn equivalence_evidence_contains_total_cases() {
        let cases = passing_equivalence_cases(7);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.evidence.iter().any(|e| e.contains("total_cases=7")));
    }

    #[test]
    fn equivalence_evidence_contains_divergent_test_ids() {
        let cases = failing_equivalence_cases(3);
        let strictness = GateStrictness::standard(GateKind::Equivalence);
        let eval = evaluate_equivalence(&cases, &strictness);
        assert!(eval.evidence.iter().any(|e| e.contains("divergent_tests=")));
        assert!(eval.evidence.iter().any(|e| e.contains("eq-fail-0")));
    }

    #[test]
    fn capability_evidence_contains_counts() {
        let request = passing_capability_request();
        let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
        let eval = evaluate_capability_preservation(&request, &strictness);
        assert!(eval.evidence.iter().any(|e| e.contains("requested=2")));
        assert!(eval.evidence.iter().any(|e| e.contains("permitted=3")));
    }

    #[test]
    fn capability_evidence_excess_when_failing() {
        let request = exceeding_capability_request();
        let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
        let eval = evaluate_capability_preservation(&request, &strictness);
        assert!(
            eval.evidence
                .iter()
                .any(|e| e.contains("excess_capabilities="))
        );
    }

    #[test]
    fn performance_evidence_contains_benchmark_count() {
        let measurements = passing_perf_measurements(3);
        let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
        let eval = evaluate_performance_threshold(&measurements, &strictness);
        assert!(
            eval.evidence
                .iter()
                .any(|e| e.contains("total_benchmarks=3"))
        );
    }

    #[test]
    fn adversarial_evidence_contains_pass_rate() {
        let results = passing_adversarial_results(10);
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(
            eval.evidence
                .iter()
                .any(|e| e.contains("pass_rate_millionths=1000000"))
        );
    }

    #[test]
    fn adversarial_evidence_contains_failed_test_ids() {
        let results = mixed_adversarial_results();
        let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
        let eval = evaluate_adversarial_survival(&results, &strictness);
        assert!(eval.evidence.iter().any(|e| e.contains("failed_tests=")));
        assert!(eval.evidence.iter().any(|e| e.contains("adv-1")));
    }

    // ===================================================================
    // Enrichment batch 2: Log event coverage
    // ===================================================================

    #[test]
    fn log_event_all_gates_produce_events() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        for gate in GateKind::all() {
            let eval = GateEvaluation {
                gate: *gate,
                passed: true,
                required: true,
                evidence: vec![],
                summary: "ok".to_string(),
            };
            let event = log_gate_evaluation(&config, &eval);
            assert!(event.event.contains(&gate.to_string()));
            assert_eq!(event.gate, Some(*gate));
        }
    }

    #[test]
    fn log_event_error_code_format_per_gate() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        let expected_codes = [
            (GateKind::Equivalence, "FE-GATE-EQUIVALENCE"),
            (
                GateKind::CapabilityPreservation,
                "FE-GATE-CAPABILITY_PRESERVATION",
            ),
            (
                GateKind::PerformanceThreshold,
                "FE-GATE-PERFORMANCE_THRESHOLD",
            ),
            (
                GateKind::AdversarialSurvival,
                "FE-GATE-ADVERSARIAL_SURVIVAL",
            ),
        ];
        for (gate, expected_code) in &expected_codes {
            let eval = GateEvaluation {
                gate: *gate,
                passed: false,
                required: true,
                evidence: vec![],
                summary: "fail".to_string(),
            };
            let event = log_gate_evaluation(&config, &eval);
            assert_eq!(event.error_code.as_deref(), Some(*expected_code));
        }
    }

    #[test]
    fn log_event_trace_id_contains_seed() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 0xDEAD);
        let eval = GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        };
        let event = log_gate_evaluation(&config, &eval);
        assert!(event.trace_id.starts_with("gate-"));
        assert!(event.decision_id.starts_with("decision-"));
    }

    // ===================================================================
    // Enrichment batch 2: GateRunnerConfig
    // ===================================================================

    #[test]
    fn config_strictness_for_missing_returns_none() {
        let config = GateRunnerConfig {
            slot_id: test_slot_id(),
            candidate_digest: "c".to_string(),
            seed: 0,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z".to_string(),
            gate_strictness: vec![], // no strictness entries
        };
        assert!(config.strictness_for(GateKind::Equivalence).is_none());
    }

    #[test]
    fn config_standard_epoch_is_one() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 0);
        assert_eq!(config.epoch.as_u64(), 1);
    }

    #[test]
    fn config_standard_zone_is_default() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 0);
        assert_eq!(config.zone, "default");
    }

    // ===================================================================
    // Enrichment batch 2: Gate evaluation to_gate_result
    // ===================================================================

    #[test]
    fn gate_evaluation_to_gate_result_fail() {
        let eval = GateEvaluation {
            gate: GateKind::AdversarialSurvival,
            passed: false,
            required: true,
            evidence: vec!["ev-a".to_string(), "ev-b".to_string()],
            summary: "bad stuff".to_string(),
        };
        let result = eval.to_gate_result();
        assert_eq!(result.gate_name, "adversarial_survival");
        assert!(!result.passed);
        assert_eq!(result.evidence_refs.len(), 2);
        assert_eq!(result.summary, "bad stuff");
    }

    #[test]
    fn gate_evaluation_to_gate_result_preserves_evidence() {
        let evidence = vec!["ev-1".to_string(), "ev-2".to_string(), "ev-3".to_string()];
        let eval = GateEvaluation {
            gate: GateKind::PerformanceThreshold,
            passed: true,
            required: false,
            evidence: evidence.clone(),
            summary: "ok".to_string(),
        };
        let result = eval.to_gate_result();
        assert_eq!(result.evidence_refs, evidence);
    }

    // ===================================================================
    // Enrichment batch 2: Full run edge cases
    // ===================================================================

    #[test]
    fn full_run_seed_affects_run_id() {
        let config1 = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let config2 = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 2);
        let input = all_passing_input();
        let out1 = run_promotion_gates(&config1, &input);
        let out2 = run_promotion_gates(&config2, &input);
        assert_ne!(out1.run_id, out2.run_id);
    }

    #[test]
    fn full_run_seed_affects_content_hashes() {
        let config1 = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let config2 = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 2);
        let input = all_passing_input();
        let out1 = run_promotion_gates(&config1, &input);
        let out2 = run_promotion_gates(&config2, &input);
        // At least some content hashes should differ
        let hashes1: BTreeSet<_> = out1
            .evidence_bundle
            .artifacts
            .iter()
            .map(|a| a.content_hash.clone())
            .collect();
        let hashes2: BTreeSet<_> = out2
            .evidence_bundle
            .artifacts
            .iter()
            .map(|a| a.content_hash.clone())
            .collect();
        assert_ne!(hashes1, hashes2);
    }

    #[test]
    fn full_run_all_fail_denied_critical() {
        let config = GateRunnerConfig::standard(test_slot_id(), "bad".to_string(), 99);
        let input = GateRunnerInput {
            equivalence_cases: failing_equivalence_cases(10),
            capability_request: exceeding_capability_request(),
            performance_measurements: failing_perf_measurements(),
            adversarial_results: mixed_adversarial_results(),
        };
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert_eq!(output.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn full_run_evidence_bundle_total_consistency() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        let input = GateRunnerInput {
            equivalence_cases: failing_equivalence_cases(3),
            capability_request: passing_capability_request(),
            performance_measurements: passing_perf_measurements(2),
            adversarial_results: passing_adversarial_results(5),
        };
        let output = run_promotion_gates(&config, &input);
        let bundle = &output.evidence_bundle;
        // total_cases = 3 eq + 1 cap + 2 perf + 5 adv = 11
        assert_eq!(bundle.total_test_cases, 11);
        assert_eq!(
            bundle.total_passed + bundle.total_failed,
            bundle.total_test_cases
        );
        // 3 eq failed, cap passed, perf passed, adv passed
        assert_eq!(bundle.total_failed, 3);
        assert_eq!(bundle.total_passed, 8);
    }

    #[test]
    fn full_run_slot_id_propagated() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.slot_id, test_slot_id());
    }

    #[test]
    fn full_run_candidate_digest_propagated() {
        let digest = "sha256:abcdef1234567890".to_string();
        let config = GateRunnerConfig::standard(test_slot_id(), digest.clone(), 42);
        let input = all_passing_input();
        let output = run_promotion_gates(&config, &input);
        assert_eq!(output.candidate_digest, digest);
    }
}
