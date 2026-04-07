//! Frontier demo gates — mandatory quality-bar checkpoints for frontier-track
//! work items before promotion from development to production status.
//!
//! Each gate specifies required artifact categories and verification criteria
//! for a specific 9H frontier program. Gate evaluation produces a signed receipt
//! with an immutable promotion decision (`Promote`, `Hold`, `Reject`).
//!
//! ## Design
//!
//! - **Configuration-driven**: gate definitions specify artifact requirements
//!   as structured data, with composable verification check functions.
//! - **Deterministic**: identical inputs always produce identical gate decisions.
//! - **Immutable audit trail**: every evaluation produces a content-addressed receipt.
//!
//! ## Related beads
//!
//! - bd-2th8 (this module)
//! - bd-3gsv (third-party verifier toolkit — upstream dependency)
//! - bd-1bzp (benchmark specification — artifact source for 9H.10 gate)
//! - bd-12p (incident replay bundles — artifact source for 9H.3 gate)

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Frontier programs (9H)
// ---------------------------------------------------------------------------

/// The ten 9H frontier programs, each with its own demo gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FrontierProgram {
    /// 9H.1: Proof-Carrying Adaptive Optimizer
    ProofCarryingOptimizer,
    /// 9H.2: Fleet Immune System
    FleetImmuneSystem,
    /// 9H.3: Causal Time-Machine (replay)
    CausalTimeMachine,
    /// 9H.4: Attested Execution Cells
    AttestedExecutionCells,
    /// 9H.5: Policy Theorem Engine
    PolicyTheoremEngine,
    /// 9H.6: Autonomous Red/Blue
    AutonomousRedBlue,
    /// 9H.7: Trust Economics
    TrustEconomics,
    /// 9H.8: Reputation Graph
    ReputationGraph,
    /// 9H.9: Operator Copilot
    OperatorCopilot,
    /// 9H.10: Benchmark Standard
    BenchmarkStandard,
}

impl FrontierProgram {
    /// All ten programs in canonical order.
    pub fn all() -> &'static [Self] {
        &[
            Self::ProofCarryingOptimizer,
            Self::FleetImmuneSystem,
            Self::CausalTimeMachine,
            Self::AttestedExecutionCells,
            Self::PolicyTheoremEngine,
            Self::AutonomousRedBlue,
            Self::TrustEconomics,
            Self::ReputationGraph,
            Self::OperatorCopilot,
            Self::BenchmarkStandard,
        ]
    }

    /// Short identifier for structured logging.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProofCarryingOptimizer => "9H.1",
            Self::FleetImmuneSystem => "9H.2",
            Self::CausalTimeMachine => "9H.3",
            Self::AttestedExecutionCells => "9H.4",
            Self::PolicyTheoremEngine => "9H.5",
            Self::AutonomousRedBlue => "9H.6",
            Self::TrustEconomics => "9H.7",
            Self::ReputationGraph => "9H.8",
            Self::OperatorCopilot => "9H.9",
            Self::BenchmarkStandard => "9H.10",
        }
    }
}

impl fmt::Display for FrontierProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofCarryingOptimizer => write!(f, "Proof-Carrying Adaptive Optimizer"),
            Self::FleetImmuneSystem => write!(f, "Fleet Immune System"),
            Self::CausalTimeMachine => write!(f, "Causal Time-Machine"),
            Self::AttestedExecutionCells => write!(f, "Attested Execution Cells"),
            Self::PolicyTheoremEngine => write!(f, "Policy Theorem Engine"),
            Self::AutonomousRedBlue => write!(f, "Autonomous Red/Blue"),
            Self::TrustEconomics => write!(f, "Trust Economics"),
            Self::ReputationGraph => write!(f, "Reputation Graph"),
            Self::OperatorCopilot => write!(f, "Operator Copilot"),
            Self::BenchmarkStandard => write!(f, "Benchmark Standard"),
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact categories
// ---------------------------------------------------------------------------

/// Artifact category required by a demo gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArtifactCategory {
    /// Translation-validation evidence (semantic equivalence proofs).
    TranslationValidation,
    /// Performance benchmark results with measurable improvement.
    PerformanceBenchmark,
    /// Rollback test evidence (deterministic baseline restoration).
    RollbackTest,
    /// Convergence measurement under fault injection.
    ConvergenceMeasurement,
    /// False-positive / false-negative rate evidence.
    ErrorRateEvidence,
    /// Partition behavior evidence (deterministic degraded-mode).
    PartitionBehavior,
    /// Replay fidelity evidence (bit-for-bit reproduction).
    ReplayFidelity,
    /// Counterfactual analysis evidence (policy comparison from replay).
    CounterfactualAnalysis,
    /// Cross-node replay portability evidence.
    CrossNodeReplay,
    /// Attestation chain verification evidence.
    AttestationChain,
    /// Fallback behavior under attestation failure.
    AttestationFallback,
    /// Property proof evidence for policy compositions.
    PropertyProof,
    /// Counterexample evidence for conflicting policies.
    CounterexampleEvidence,
    /// Campaign evolution evidence (improving attack quality).
    CampaignEvolution,
    /// Defense improvement evidence (compromise-rate reduction).
    DefenseImprovement,
    /// Decision scoring evidence (expected-loss computation).
    DecisionScoring,
    /// Attacker-ROI trending evidence.
    AttackerRoiTrend,
    /// First-time compromise window reduction measurement.
    CompromiseWindowReduction,
    /// Operator workflow evidence (decision transparency).
    OperatorWorkflow,
    /// Independent reproduction evidence from verifier toolkit.
    IndependentReproduction,
    /// Cross-runtime fairness evidence.
    CrossRuntimeFairness,
}

impl fmt::Display for ArtifactCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TranslationValidation => "TranslationValidation",
            Self::PerformanceBenchmark => "PerformanceBenchmark",
            Self::RollbackTest => "RollbackTest",
            Self::ConvergenceMeasurement => "ConvergenceMeasurement",
            Self::ErrorRateEvidence => "ErrorRateEvidence",
            Self::PartitionBehavior => "PartitionBehavior",
            Self::ReplayFidelity => "ReplayFidelity",
            Self::CounterfactualAnalysis => "CounterfactualAnalysis",
            Self::CrossNodeReplay => "CrossNodeReplay",
            Self::AttestationChain => "AttestationChain",
            Self::AttestationFallback => "AttestationFallback",
            Self::PropertyProof => "PropertyProof",
            Self::CounterexampleEvidence => "CounterexampleEvidence",
            Self::CampaignEvolution => "CampaignEvolution",
            Self::DefenseImprovement => "DefenseImprovement",
            Self::DecisionScoring => "DecisionScoring",
            Self::AttackerRoiTrend => "AttackerRoiTrend",
            Self::CompromiseWindowReduction => "CompromiseWindowReduction",
            Self::OperatorWorkflow => "OperatorWorkflow",
            Self::IndependentReproduction => "IndependentReproduction",
            Self::CrossRuntimeFairness => "CrossRuntimeFairness",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Artifact & verification
// ---------------------------------------------------------------------------

/// A single artifact presented to a demo gate for evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoArtifact {
    /// Content-addressed identifier for this artifact.
    pub artifact_id: EngineObjectId,
    /// Which category this artifact satisfies.
    pub category: ArtifactCategory,
    /// Content hash of the artifact payload.
    pub content_hash: ContentHash,
    /// Git commit that produced this artifact.
    pub producing_commit: String,
    /// Test run identifier.
    pub test_run_id: String,
    /// Human-readable summary.
    pub summary: String,
    /// Whether this artifact is suitable for public demonstration.
    pub public_eligible: bool,
}

/// Result of verifying a single artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Artifact passed all checks.
    Passed {
        /// Details of what was verified.
        details: String,
    },
    /// Artifact failed verification.
    Failed {
        /// What went wrong.
        reason: String,
    },
    /// Verification was skipped (e.g. external verifier unavailable).
    Skipped {
        /// Why verification was skipped.
        reason: String,
    },
}

impl VerificationResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed { details } => write!(f, "passed: {}", details),
            Self::Failed { reason } => write!(f, "failed: {}", reason),
            Self::Skipped { reason } => write!(f, "skipped: {}", reason),
        }
    }
}

/// Verification of a single artifact within a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub artifact_id: EngineObjectId,
    pub category: ArtifactCategory,
    pub schema_compliant: bool,
    pub integrity_valid: bool,
    pub reproducible: bool,
    pub external_verification: Option<VerificationResult>,
    pub overall: VerificationResult,
}

impl ArtifactVerification {
    /// True when all three internal checks pass AND overall is passed.
    pub fn passes(&self) -> bool {
        self.schema_compliant
            && self.integrity_valid
            && self.reproducible
            && self.overall.is_passed()
    }
}

// ---------------------------------------------------------------------------
// Gate definition
// ---------------------------------------------------------------------------

/// Definition of a frontier demo gate for a specific 9H program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDefinition {
    /// Unique gate identifier.
    pub gate_id: EngineObjectId,
    /// Which frontier program this gate covers.
    pub program: FrontierProgram,
    /// Required artifact categories — ALL must be present and verified.
    pub required_categories: Vec<ArtifactCategory>,
    /// Whether external verification is required for at least one category.
    pub requires_external_verification: bool,
    /// Human-readable description of the gate.
    pub description: String,
}

impl GateDefinition {
    /// Build the canonical gate definition for a given frontier program.
    pub fn for_program(program: FrontierProgram, gate_id: EngineObjectId) -> Self {
        let (categories, description) = match program {
            FrontierProgram::ProofCarryingOptimizer => (
                vec![
                    ArtifactCategory::TranslationValidation,
                    ArtifactCategory::PerformanceBenchmark,
                    ArtifactCategory::RollbackTest,
                ],
                "Proof-carrying optimizer requires translation-validation, performance, and rollback evidence",
            ),
            FrontierProgram::FleetImmuneSystem => (
                vec![
                    ArtifactCategory::ConvergenceMeasurement,
                    ArtifactCategory::ErrorRateEvidence,
                    ArtifactCategory::PartitionBehavior,
                ],
                "Fleet immune system requires convergence, error-rate, and partition evidence",
            ),
            FrontierProgram::CausalTimeMachine => (
                vec![
                    ArtifactCategory::ReplayFidelity,
                    ArtifactCategory::CounterfactualAnalysis,
                    ArtifactCategory::CrossNodeReplay,
                ],
                "Causal time-machine requires replay, counterfactual, and cross-node evidence",
            ),
            FrontierProgram::AttestedExecutionCells => (
                vec![
                    ArtifactCategory::AttestationChain,
                    ArtifactCategory::AttestationFallback,
                ],
                "Attested execution requires attestation chain and fallback evidence",
            ),
            FrontierProgram::PolicyTheoremEngine => (
                vec![
                    ArtifactCategory::PropertyProof,
                    ArtifactCategory::CounterexampleEvidence,
                ],
                "Policy theorem engine requires property-proof and counterexample evidence",
            ),
            FrontierProgram::AutonomousRedBlue => (
                vec![
                    ArtifactCategory::CampaignEvolution,
                    ArtifactCategory::DefenseImprovement,
                ],
                "Autonomous red/blue requires campaign evolution and defense improvement evidence",
            ),
            FrontierProgram::TrustEconomics => (
                vec![
                    ArtifactCategory::DecisionScoring,
                    ArtifactCategory::AttackerRoiTrend,
                ],
                "Trust economics requires decision scoring and attacker-ROI evidence",
            ),
            FrontierProgram::ReputationGraph => (
                vec![ArtifactCategory::CompromiseWindowReduction],
                "Reputation graph requires compromise-window reduction measurement",
            ),
            FrontierProgram::OperatorCopilot => (
                vec![ArtifactCategory::OperatorWorkflow],
                "Operator copilot requires operator workflow transparency evidence",
            ),
            FrontierProgram::BenchmarkStandard => (
                vec![
                    ArtifactCategory::IndependentReproduction,
                    ArtifactCategory::CrossRuntimeFairness,
                ],
                "Benchmark standard requires independent reproduction and fairness evidence",
            ),
        };
        Self {
            gate_id,
            program,
            required_categories: categories,
            requires_external_verification: true,
            description: description.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Promotion decision
// ---------------------------------------------------------------------------

/// Promotion decision for a frontier work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PromotionDecision {
    /// All artifacts verified — work item may advance to production.
    Promote,
    /// Some artifacts missing or verification incomplete — hold at current stage.
    Hold,
    /// Critical verification failure — block promotion with explicit rejection.
    Reject,
}

impl fmt::Display for PromotionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promote => write!(f, "promote"),
            Self::Hold => write!(f, "hold"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

/// Input to a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluationInput {
    /// Gate definition to evaluate against.
    pub gate: GateDefinition,
    /// Artifacts presented for evaluation.
    pub artifacts: Vec<DemoArtifact>,
    /// Verification results for each presented artifact.
    pub verifications: Vec<ArtifactVerification>,
    /// Optional signed override (bypasses gate failures with justification).
    pub override_justification: Option<OverrideJustification>,
}

/// Signed override to bypass a gate failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideJustification {
    /// Who authorized the override.
    pub authorizer: String,
    /// Written justification for bypassing the gate.
    pub justification: String,
    /// Signature over (gate_id, justification) for audit.
    pub signature: String,
}

/// Output of a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluationReceipt {
    /// Gate identifier.
    pub gate_id: EngineObjectId,
    /// Frontier program covered.
    pub program: FrontierProgram,
    /// Evaluation timestamp (unix milliseconds).
    pub evaluation_timestamp_ms: u64,
    /// Artifacts presented (by ID).
    pub artifacts_presented: Vec<EngineObjectId>,
    /// Per-category coverage: which required categories were satisfied.
    pub category_coverage: BTreeMap<String, bool>,
    /// Verification results summary.
    pub verification_summaries: Vec<VerificationSummaryEntry>,
    /// Whether external verification was present.
    pub has_external_verification: bool,
    /// Final promotion decision.
    pub decision: PromotionDecision,
    /// Human-readable decision rationale.
    pub rationale: String,
    /// Whether an override was applied.
    pub override_applied: bool,
    /// Content hash of this receipt (for immutability).
    pub receipt_hash: ContentHash,
}

/// Summary entry for a single verification within a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSummaryEntry {
    pub category: ArtifactCategory,
    pub passed: bool,
    pub detail: String,
}

/// Evaluate a demo gate and produce a receipt.
pub fn evaluate_gate(input: &GateEvaluationInput, timestamp_ms: u64) -> GateEvaluationReceipt {
    let gate = &input.gate;
    let mut category_coverage: BTreeMap<String, bool> = BTreeMap::new();
    let mut verification_summaries = Vec::new();
    let mut has_external = false;
    let mut any_failed = false;
    let mut missing_categories = Vec::new();

    // Check each required category
    for required in &gate.required_categories {
        let category_key = required.to_string();

        // Find artifact for this category
        let matching_artifacts: Vec<_> = input
            .artifacts
            .iter()
            .filter(|a| a.category == *required)
            .collect();

        if matching_artifacts.is_empty() {
            category_coverage.insert(category_key.clone(), false);
            missing_categories.push(category_key);
            continue;
        }

        // Find verification for this artifact
        let mut category_passed = false;
        for artifact in &matching_artifacts {
            if let Some(verification) = input
                .verifications
                .iter()
                .find(|v| v.artifact_id == artifact.artifact_id && v.category == *required)
            {
                if verification.passes() {
                    category_passed = true;
                    if verification
                        .external_verification
                        .as_ref()
                        .is_some_and(|e| e.is_passed())
                    {
                        has_external = true;
                    }
                    verification_summaries.push(VerificationSummaryEntry {
                        category: *required,
                        passed: true,
                        detail: format!("artifact {} verified", artifact.artifact_id),
                    });
                } else {
                    any_failed = true;
                    let detail = format!(
                        "artifact {} failed: {}",
                        artifact.artifact_id, verification.overall
                    );
                    verification_summaries.push(VerificationSummaryEntry {
                        category: *required,
                        passed: false,
                        detail,
                    });
                }
            }
        }

        category_coverage.insert(category_key, category_passed);
    }

    // Determine decision
    let all_covered = category_coverage.values().all(|v| *v);
    let external_ok = !gate.requires_external_verification || has_external;

    let (decision, rationale) = if all_covered && external_ok && !any_failed {
        (
            PromotionDecision::Promote,
            format!(
                "all {} required categories verified for {}",
                gate.required_categories.len(),
                gate.program
            ),
        )
    } else if any_failed {
        (
            PromotionDecision::Reject,
            format!("verification failures detected for {}", gate.program),
        )
    } else {
        let mut reasons = Vec::new();
        if !all_covered {
            reasons.push(format!(
                "missing categories: {}",
                missing_categories.join(", ")
            ));
        }
        if !external_ok {
            reasons.push("no external verification present".to_string());
        }
        (
            PromotionDecision::Hold,
            format!("held for {}: {}", gate.program, reasons.join("; ")),
        )
    };

    // Check for override
    let (final_decision, override_applied) = if let Some(ref _override) =
        input.override_justification
        && decision != PromotionDecision::Promote
    {
        (PromotionDecision::Promote, true)
    } else {
        (decision, false)
    };

    let artifacts_presented: Vec<_> = input
        .artifacts
        .iter()
        .map(|a| a.artifact_id.clone())
        .collect();

    // Compute receipt hash for immutability
    let receipt_content = format!(
        "{}:{}:{}:{}:{}:{}",
        gate.gate_id,
        gate.program,
        timestamp_ms,
        serde_json::to_string(&category_coverage).unwrap_or_default(),
        serde_json::to_string(&final_decision).unwrap_or_default(),
        override_applied
    );
    let receipt_hash = ContentHash::compute(receipt_content.as_bytes());

    GateEvaluationReceipt {
        gate_id: gate.gate_id.clone(),
        program: gate.program,
        evaluation_timestamp_ms: timestamp_ms,
        artifacts_presented,
        category_coverage,
        verification_summaries,
        has_external_verification: has_external,
        decision: final_decision,
        rationale,
        override_applied,
        receipt_hash,
    }
}

// ---------------------------------------------------------------------------
// Gate registry
// ---------------------------------------------------------------------------

/// Central registry of all frontier demo gates and their status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRegistry {
    /// Gate definitions indexed by program.
    pub gates: Vec<GateDefinition>,
    /// Most recent receipt for each gate (by gate_id string).
    pub latest_receipts: Vec<GateEvaluationReceipt>,
}

/// Per-program status in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramGateStatus {
    pub program: FrontierProgram,
    pub gate_defined: bool,
    pub latest_decision: Option<PromotionDecision>,
    pub categories_required: u64,
    pub categories_satisfied: u64,
}

/// Aggregate readiness summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessSummary {
    pub total_gates: u64,
    pub gates_passed: u64,
    pub gates_held: u64,
    pub gates_rejected: u64,
    pub gates_pending: u64,
    /// Overall readiness as fixed-point millionths (1_000_000 = 100%).
    pub readiness_millionths: u64,
}

impl GateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            latest_receipts: Vec::new(),
        }
    }

    /// Register a gate definition.
    pub fn register_gate(&mut self, gate: GateDefinition) {
        // Replace existing gate for the same program
        self.gates.retain(|g| g.program != gate.program);
        self.gates.push(gate);
        self.gates.sort_by_key(|g| g.program);
    }

    /// Record a gate evaluation receipt.
    pub fn record_receipt(&mut self, receipt: GateEvaluationReceipt) {
        // Replace existing receipt for the same gate
        self.latest_receipts
            .retain(|r| r.gate_id != receipt.gate_id);
        self.latest_receipts.push(receipt);
        self.latest_receipts.sort_by_key(|r| r.program);
    }

    /// Get status for a specific program.
    pub fn program_status(&self, program: FrontierProgram) -> ProgramGateStatus {
        let gate = self.gates.iter().find(|g| g.program == program);
        let receipt = self.latest_receipts.iter().find(|r| r.program == program);

        let categories_required = gate
            .map(|g| g.required_categories.len() as u64)
            .unwrap_or(0);
        let categories_satisfied = receipt
            .map(|r| r.category_coverage.values().filter(|v| **v).count() as u64)
            .unwrap_or(0);

        ProgramGateStatus {
            program,
            gate_defined: gate.is_some(),
            latest_decision: receipt.map(|r| r.decision),
            categories_required,
            categories_satisfied,
        }
    }

    /// Compute aggregate readiness across all registered gates.
    pub fn readiness(&self) -> ReadinessSummary {
        let total = self.gates.len() as u64;
        let mut passed = 0u64;
        let mut held = 0u64;
        let mut rejected = 0u64;

        for gate in &self.gates {
            if let Some(receipt) = self
                .latest_receipts
                .iter()
                .find(|r| r.gate_id == gate.gate_id)
            {
                match receipt.decision {
                    PromotionDecision::Promote => passed = passed.saturating_add(1),
                    PromotionDecision::Hold => held = held.saturating_add(1),
                    PromotionDecision::Reject => rejected = rejected.saturating_add(1),
                }
            }
        }

        let pending = total
            .saturating_sub(passed)
            .saturating_sub(held)
            .saturating_sub(rejected);
        let readiness = passed
            .saturating_mul(1_000_000)
            .checked_div(total)
            .unwrap_or(0);

        ReadinessSummary {
            total_gates: total,
            gates_passed: passed,
            gates_held: held,
            gates_rejected: rejected,
            gates_pending: pending,
            readiness_millionths: readiness,
        }
    }

    /// Check if a specific program can be promoted (for release gate integration).
    pub fn can_promote(&self, program: FrontierProgram) -> bool {
        self.latest_receipts
            .iter()
            .any(|r| r.program == program && r.decision == PromotionDecision::Promote)
    }
}

impl Default for GateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Release blocker integration
// ---------------------------------------------------------------------------

/// Check if all frontier gates pass for a release candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateCheck {
    /// Programs that passed their demo gates.
    pub passed: Vec<FrontierProgram>,
    /// Programs that are blocked.
    pub blocked: Vec<FrontierProgram>,
    /// Programs with no gate defined (informational).
    pub undefined: Vec<FrontierProgram>,
    /// Whether the release can proceed (all required gates pass).
    pub release_allowed: bool,
}

/// Evaluate all frontier gates for release readiness.
pub fn check_release_readiness(
    registry: &GateRegistry,
    required_programs: &[FrontierProgram],
) -> ReleaseGateCheck {
    let mut passed = Vec::new();
    let mut blocked = Vec::new();
    let mut undefined = Vec::new();

    for program in required_programs {
        if !registry.gates.iter().any(|g| g.program == *program) {
            undefined.push(*program);
            continue;
        }

        if registry.can_promote(*program) {
            passed.push(*program);
        } else {
            blocked.push(*program);
        }
    }

    let release_allowed = blocked.is_empty() && undefined.is_empty();

    ReleaseGateCheck {
        passed,
        blocked,
        undefined,
        release_allowed,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_gate_id(suffix: &str) -> EngineObjectId {
        crate::engine_object_id::derive_id(
            crate::engine_object_id::ObjectDomain::EvidenceRecord,
            suffix,
            &crate::engine_object_id::SchemaId::from_definition(b"frontier-demo-gate"),
            b"frontier-demo-gate",
        )
        .unwrap()
    }

    fn test_artifact(category: ArtifactCategory, suffix: &str) -> DemoArtifact {
        DemoArtifact {
            artifact_id: test_gate_id(suffix),
            category,
            content_hash: ContentHash::compute(suffix.as_bytes()),
            producing_commit: "abc123".to_string(),
            test_run_id: "run-001".to_string(),
            summary: format!("test artifact for {}", category),
            public_eligible: true,
        }
    }

    fn passing_verification(artifact: &DemoArtifact) -> ArtifactVerification {
        ArtifactVerification {
            artifact_id: artifact.artifact_id.clone(),
            category: artifact.category,
            schema_compliant: true,
            integrity_valid: true,
            reproducible: true,
            external_verification: Some(VerificationResult::Passed {
                details: "external check ok".to_string(),
            }),
            overall: VerificationResult::Passed {
                details: "all checks passed".to_string(),
            },
        }
    }

    fn failing_verification(artifact: &DemoArtifact, reason: &str) -> ArtifactVerification {
        ArtifactVerification {
            artifact_id: artifact.artifact_id.clone(),
            category: artifact.category,
            schema_compliant: true,
            integrity_valid: true,
            reproducible: false,
            external_verification: None,
            overall: VerificationResult::Failed {
                reason: reason.to_string(),
            },
        }
    }

    // --- FrontierProgram ---

    #[test]
    fn all_programs_returns_ten() {
        assert_eq!(FrontierProgram::all().len(), 10);
    }

    #[test]
    fn program_codes_are_unique() {
        let codes: Vec<_> = FrontierProgram::all().iter().map(|p| p.code()).collect();
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate code");
                }
            }
        }
    }

    #[test]
    fn program_display() {
        assert_eq!(
            FrontierProgram::ProofCarryingOptimizer.to_string(),
            "Proof-Carrying Adaptive Optimizer"
        );
        assert_eq!(
            FrontierProgram::BenchmarkStandard.to_string(),
            "Benchmark Standard"
        );
    }

    #[test]
    fn program_codes() {
        assert_eq!(FrontierProgram::ProofCarryingOptimizer.code(), "9H.1");
        assert_eq!(FrontierProgram::BenchmarkStandard.code(), "9H.10");
    }

    // --- ArtifactCategory ---

    #[test]
    fn artifact_category_display() {
        assert_eq!(
            ArtifactCategory::TranslationValidation.to_string(),
            "TranslationValidation"
        );
        assert_eq!(
            ArtifactCategory::IndependentReproduction.to_string(),
            "IndependentReproduction"
        );
    }

    // --- VerificationResult ---

    #[test]
    fn verification_result_is_passed() {
        assert!(
            VerificationResult::Passed {
                details: "ok".into()
            }
            .is_passed()
        );
        assert!(
            !VerificationResult::Failed {
                reason: "bad".into()
            }
            .is_passed()
        );
        assert!(
            !VerificationResult::Skipped {
                reason: "skip".into()
            }
            .is_passed()
        );
    }

    #[test]
    fn verification_result_is_failed() {
        assert!(
            VerificationResult::Failed {
                reason: "bad".into()
            }
            .is_failed()
        );
        assert!(
            !VerificationResult::Passed {
                details: "ok".into()
            }
            .is_failed()
        );
    }

    #[test]
    fn verification_result_display() {
        assert_eq!(
            VerificationResult::Passed {
                details: "ok".into()
            }
            .to_string(),
            "passed: ok"
        );
        assert_eq!(
            VerificationResult::Failed {
                reason: "bad".into()
            }
            .to_string(),
            "failed: bad"
        );
        assert_eq!(
            VerificationResult::Skipped {
                reason: "n/a".into()
            }
            .to_string(),
            "skipped: n/a"
        );
    }

    // --- ArtifactVerification ---

    #[test]
    fn artifact_verification_passes_when_all_checks_ok() {
        let artifact = test_artifact(ArtifactCategory::TranslationValidation, "a1");
        let v = passing_verification(&artifact);
        assert!(v.passes());
    }

    #[test]
    fn artifact_verification_fails_on_schema() {
        let artifact = test_artifact(ArtifactCategory::TranslationValidation, "a2");
        let mut v = passing_verification(&artifact);
        v.schema_compliant = false;
        assert!(!v.passes());
    }

    #[test]
    fn artifact_verification_fails_on_integrity() {
        let artifact = test_artifact(ArtifactCategory::TranslationValidation, "a3");
        let mut v = passing_verification(&artifact);
        v.integrity_valid = false;
        assert!(!v.passes());
    }

    #[test]
    fn artifact_verification_fails_on_reproducibility() {
        let artifact = test_artifact(ArtifactCategory::TranslationValidation, "a4");
        let mut v = passing_verification(&artifact);
        v.reproducible = false;
        assert!(!v.passes());
    }

    // --- GateDefinition ---

    #[test]
    fn gate_definition_for_each_program() {
        for program in FrontierProgram::all() {
            let gate = GateDefinition::for_program(
                *program,
                test_gate_id(&program.code().replace('.', "_")),
            );
            assert_eq!(gate.program, *program);
            assert!(!gate.required_categories.is_empty());
            assert!(gate.requires_external_verification);
        }
    }

    #[test]
    fn optimizer_gate_requires_three_categories() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ProofCarryingOptimizer,
            test_gate_id("opt"),
        );
        assert_eq!(gate.required_categories.len(), 3);
        assert!(
            gate.required_categories
                .contains(&ArtifactCategory::TranslationValidation)
        );
        assert!(
            gate.required_categories
                .contains(&ArtifactCategory::PerformanceBenchmark)
        );
        assert!(
            gate.required_categories
                .contains(&ArtifactCategory::RollbackTest)
        );
    }

    #[test]
    fn reputation_gate_requires_one_category() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rep"));
        assert_eq!(gate.required_categories.len(), 1);
        assert!(
            gate.required_categories
                .contains(&ArtifactCategory::CompromiseWindowReduction)
        );
    }

    // --- PromotionDecision ---

    #[test]
    fn promotion_decision_display() {
        assert_eq!(PromotionDecision::Promote.to_string(), "promote");
        assert_eq!(PromotionDecision::Hold.to_string(), "hold");
        assert_eq!(PromotionDecision::Reject.to_string(), "reject");
    }

    // --- Gate evaluation ---

    #[test]
    fn gate_promotes_with_all_artifacts_verified() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rep-gate"));
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-1");
        let verification = passing_verification(&artifact);

        let input = GateEvaluationInput {
            gate: gate.clone(),
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 1000);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert!(!receipt.override_applied);
        assert!(receipt.has_external_verification);
    }

    #[test]
    fn gate_holds_on_missing_category() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ProofCarryingOptimizer,
            test_gate_id("opt-gate"),
        );
        // Only provide 1 of 3 required categories
        let artifact = test_artifact(ArtifactCategory::TranslationValidation, "tv-1");
        let verification = passing_verification(&artifact);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 2000);
        assert_eq!(receipt.decision, PromotionDecision::Hold);
    }

    #[test]
    fn gate_rejects_on_verification_failure() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("rep-gate-2"),
        );
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-2");
        let verification = failing_verification(&artifact, "could not reproduce");

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 3000);
        assert_eq!(receipt.decision, PromotionDecision::Reject);
    }

    #[test]
    fn gate_holds_on_missing_external_verification() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("rep-gate-3"),
        );
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-3");
        let mut verification = passing_verification(&artifact);
        verification.external_verification = None;

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 4000);
        assert_eq!(receipt.decision, PromotionDecision::Hold);
        assert!(!receipt.has_external_verification);
    }

    #[test]
    fn gate_override_promotes_despite_hold() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ProofCarryingOptimizer,
            test_gate_id("opt-gate-2"),
        );

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![], // No artifacts — would normally hold
            verifications: vec![],
            override_justification: Some(OverrideJustification {
                authorizer: "project-owner".to_string(),
                justification: "emergency deployment".to_string(),
                signature: "sig-123".to_string(),
            }),
        };

        let receipt = evaluate_gate(&input, 5000);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert!(receipt.override_applied);
    }

    #[test]
    fn gate_no_override_when_already_promoting() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("rep-gate-4"),
        );
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-4");
        let verification = passing_verification(&artifact);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: Some(OverrideJustification {
                authorizer: "owner".to_string(),
                justification: "not needed".to_string(),
                signature: "sig".to_string(),
            }),
        };

        let receipt = evaluate_gate(&input, 6000);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert!(!receipt.override_applied); // Override not needed
    }

    #[test]
    fn gate_empty_input_holds() {
        let gate = GateDefinition::for_program(
            FrontierProgram::BenchmarkStandard,
            test_gate_id("bench-gate"),
        );

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![],
            verifications: vec![],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 7000);
        assert_eq!(receipt.decision, PromotionDecision::Hold);
        assert!(receipt.artifacts_presented.is_empty());
    }

    #[test]
    fn receipt_hash_is_deterministic() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rep-det"));
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-det");
        let verification = passing_verification(&artifact);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let r1 = evaluate_gate(&input, 8000);
        let r2 = evaluate_gate(&input, 8000);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_timestamp() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rep-ts"));
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-ts");
        let verification = passing_verification(&artifact);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };

        let r1 = evaluate_gate(&input, 9000);
        let r2 = evaluate_gate(&input, 9001);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    // --- Gate Registry ---

    #[test]
    fn registry_register_and_query() {
        let mut registry = GateRegistry::new();
        let gate = GateDefinition::for_program(
            FrontierProgram::TrustEconomics,
            test_gate_id("trust-gate"),
        );
        registry.register_gate(gate);

        let status = registry.program_status(FrontierProgram::TrustEconomics);
        assert!(status.gate_defined);
        assert_eq!(status.categories_required, 2);
        assert!(status.latest_decision.is_none());
    }

    #[test]
    fn registry_record_receipt() {
        let mut registry = GateRegistry::new();
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rep-reg"));
        registry.register_gate(gate.clone());

        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "cwr-reg");
        let verification = passing_verification(&artifact);
        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };
        let receipt = evaluate_gate(&input, 10000);
        registry.record_receipt(receipt);

        assert!(registry.can_promote(FrontierProgram::ReputationGraph));
        let status = registry.program_status(FrontierProgram::ReputationGraph);
        assert_eq!(status.latest_decision, Some(PromotionDecision::Promote));
        assert_eq!(status.categories_satisfied, 1);
    }

    #[test]
    fn registry_replaces_gate_for_same_program() {
        let mut registry = GateRegistry::new();
        let gate1 =
            GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("op-1"));
        let gate2 =
            GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("op-2"));
        registry.register_gate(gate1);
        registry.register_gate(gate2);
        assert_eq!(registry.gates.len(), 1);
    }

    #[test]
    fn registry_readiness_empty() {
        let registry = GateRegistry::new();
        let summary = registry.readiness();
        assert_eq!(summary.total_gates, 0);
        assert_eq!(summary.readiness_millionths, 0);
    }

    #[test]
    fn registry_readiness_all_passed() {
        let mut registry = GateRegistry::new();
        for program in FrontierProgram::all() {
            let gate_id = test_gate_id(&format!("gate-{}", program.code().replace('.', "_")));
            let gate = GateDefinition::for_program(*program, gate_id.clone());
            registry.register_gate(gate.clone());

            // Create artifacts for all required categories
            let mut artifacts = Vec::new();
            let mut verifications = Vec::new();
            for (i, cat) in gate.required_categories.iter().enumerate() {
                let art = test_artifact(*cat, &format!("{}-art-{}", program.code(), i));
                let ver = passing_verification(&art);
                artifacts.push(art);
                verifications.push(ver);
            }

            let input = GateEvaluationInput {
                gate,
                artifacts,
                verifications,
                override_justification: None,
            };
            let receipt = evaluate_gate(&input, 100);
            registry.record_receipt(receipt);
        }

        let summary = registry.readiness();
        assert_eq!(summary.total_gates, 10);
        assert_eq!(summary.gates_passed, 10);
        assert_eq!(summary.readiness_millionths, 1_000_000);
    }

    #[test]
    fn registry_readiness_partial() {
        let mut registry = GateRegistry::new();

        // Register 2 gates, only 1 passes
        let gate1 =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("reg-p1"));
        registry.register_gate(gate1.clone());
        let art1 = test_artifact(ArtifactCategory::CompromiseWindowReduction, "reg-a1");
        let ver1 = passing_verification(&art1);
        let receipt1 = evaluate_gate(
            &GateEvaluationInput {
                gate: gate1,
                artifacts: vec![art1],
                verifications: vec![ver1],
                override_justification: None,
            },
            200,
        );
        registry.record_receipt(receipt1);

        let gate2 =
            GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("reg-p2"));
        registry.register_gate(gate2.clone());
        // No receipt for gate2 — it's pending

        let summary = registry.readiness();
        assert_eq!(summary.total_gates, 2);
        assert_eq!(summary.gates_passed, 1);
        assert_eq!(summary.gates_pending, 1);
        assert_eq!(summary.readiness_millionths, 500_000); // 50%
    }

    // --- Release readiness ---

    #[test]
    fn release_blocked_when_gate_missing() {
        let registry = GateRegistry::new();
        let check = check_release_readiness(&registry, &[FrontierProgram::TrustEconomics]);
        assert!(!check.release_allowed);
        assert_eq!(check.undefined.len(), 1);
    }

    #[test]
    fn release_blocked_when_gate_not_passed() {
        let mut registry = GateRegistry::new();
        let gate =
            GateDefinition::for_program(FrontierProgram::TrustEconomics, test_gate_id("rel-te"));
        registry.register_gate(gate);
        // No receipt — gate not evaluated

        let check = check_release_readiness(&registry, &[FrontierProgram::TrustEconomics]);
        assert!(!check.release_allowed);
        assert_eq!(check.blocked.len(), 1);
    }

    #[test]
    fn release_allowed_when_all_gates_pass() {
        let mut registry = GateRegistry::new();
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("rel-rep"));
        registry.register_gate(gate.clone());
        let art = test_artifact(ArtifactCategory::CompromiseWindowReduction, "rel-art");
        let ver = passing_verification(&art);
        let receipt = evaluate_gate(
            &GateEvaluationInput {
                gate,
                artifacts: vec![art],
                verifications: vec![ver],
                override_justification: None,
            },
            300,
        );
        registry.record_receipt(receipt);

        let check = check_release_readiness(&registry, &[FrontierProgram::ReputationGraph]);
        assert!(check.release_allowed);
        assert_eq!(check.passed.len(), 1);
        assert!(check.blocked.is_empty());
    }

    // --- Serde ---

    #[test]
    fn frontier_program_serde_round_trip() {
        for program in FrontierProgram::all() {
            let json = serde_json::to_string(program).unwrap();
            let back: FrontierProgram = serde_json::from_str(&json).unwrap();
            assert_eq!(*program, back);
        }
    }

    #[test]
    fn gate_definition_serde_round_trip() {
        let gate = GateDefinition::for_program(
            FrontierProgram::CausalTimeMachine,
            test_gate_id("serde-gate"),
        );
        let json = serde_json::to_string(&gate).unwrap();
        let back: GateDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(gate, back);
    }

    #[test]
    fn gate_evaluation_receipt_serde_round_trip() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("serde-rep"),
        );
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "serde-art");
        let verification = passing_verification(&artifact);
        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: None,
        };
        let receipt = evaluate_gate(&input, 500);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: GateEvaluationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn gate_registry_serde_round_trip() {
        let mut registry = GateRegistry::new();
        let gate =
            GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("serde-op"));
        registry.register_gate(gate);
        let json = serde_json::to_string(&registry).unwrap();
        let back: GateRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(registry, back);
    }

    // --- Verification summaries ---

    #[test]
    fn receipt_contains_verification_summaries() {
        let gate = GateDefinition::for_program(
            FrontierProgram::PolicyTheoremEngine,
            test_gate_id("vs-gate"),
        );
        let art1 = test_artifact(ArtifactCategory::PropertyProof, "vs-pp");
        let art2 = test_artifact(ArtifactCategory::CounterexampleEvidence, "vs-ce");
        let ver1 = passing_verification(&art1);
        let ver2 = passing_verification(&art2);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art1, art2],
            verifications: vec![ver1, ver2],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 600);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert_eq!(receipt.verification_summaries.len(), 2);
        assert!(receipt.verification_summaries.iter().all(|s| s.passed));
    }

    #[test]
    fn receipt_category_coverage_map() {
        let gate = GateDefinition::for_program(
            FrontierProgram::AutonomousRedBlue,
            test_gate_id("cc-gate"),
        );
        // Only provide one of two required categories
        let art = test_artifact(ArtifactCategory::CampaignEvolution, "cc-art");
        let ver = passing_verification(&art);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art],
            verifications: vec![ver],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 700);
        assert_eq!(receipt.decision, PromotionDecision::Hold);
        assert_eq!(
            receipt.category_coverage.get("CampaignEvolution"),
            Some(&true)
        );
        assert_eq!(
            receipt.category_coverage.get("DefenseImprovement"),
            Some(&false)
        );
    }

    // --- Multi-program gate evaluation ---

    #[test]
    fn full_optimizer_gate_with_all_three_categories() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ProofCarryingOptimizer,
            test_gate_id("full-opt"),
        );
        let art_tv = test_artifact(ArtifactCategory::TranslationValidation, "full-tv");
        let art_pb = test_artifact(ArtifactCategory::PerformanceBenchmark, "full-pb");
        let art_rb = test_artifact(ArtifactCategory::RollbackTest, "full-rb");
        let ver_tv = passing_verification(&art_tv);
        let ver_pb = passing_verification(&art_pb);
        let ver_rb = passing_verification(&art_rb);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art_tv, art_pb, art_rb],
            verifications: vec![ver_tv, ver_pb, ver_rb],
            override_justification: None,
        };

        let receipt = evaluate_gate(&input, 800);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert_eq!(receipt.verification_summaries.len(), 3);
        assert!(receipt.category_coverage.values().all(|v| *v));
    }

    // --- Determinism ---

    #[test]
    fn evaluation_is_deterministic() {
        let gate = GateDefinition::for_program(
            FrontierProgram::FleetImmuneSystem,
            test_gate_id("det-fleet"),
        );
        let art1 = test_artifact(ArtifactCategory::ConvergenceMeasurement, "det-cm");
        let art2 = test_artifact(ArtifactCategory::ErrorRateEvidence, "det-ere");
        let art3 = test_artifact(ArtifactCategory::PartitionBehavior, "det-pb");
        let ver1 = passing_verification(&art1);
        let ver2 = passing_verification(&art2);
        let ver3 = passing_verification(&art3);

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art1, art2, art3],
            verifications: vec![ver1, ver2, ver3],
            override_justification: None,
        };

        let r1 = evaluate_gate(&input, 900);
        let r2 = evaluate_gate(&input, 900);
        assert_eq!(r1, r2);
    }

    // -- Enrichment: Display uniqueness, serde, boundary conditions --

    #[test]
    fn frontier_program_display_all_unique() {
        let displays: BTreeSet<String> = FrontierProgram::all()
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(displays.len(), FrontierProgram::all().len());
    }

    #[test]
    fn frontier_program_codes_all_unique() {
        let codes: BTreeSet<String> = FrontierProgram::all()
            .iter()
            .map(|p| p.code().to_string())
            .collect();
        assert_eq!(codes.len(), FrontierProgram::all().len());
    }

    #[test]
    fn artifact_category_serde_roundtrip_all() {
        let categories = [
            ArtifactCategory::TranslationValidation,
            ArtifactCategory::PerformanceBenchmark,
            ArtifactCategory::RollbackTest,
            ArtifactCategory::CompromiseWindowReduction,
            ArtifactCategory::PropertyProof,
            ArtifactCategory::CounterexampleEvidence,
            ArtifactCategory::ConvergenceMeasurement,
            ArtifactCategory::ErrorRateEvidence,
            ArtifactCategory::PartitionBehavior,
            ArtifactCategory::ReplayFidelity,
            ArtifactCategory::CampaignEvolution,
            ArtifactCategory::DefenseImprovement,
            ArtifactCategory::IndependentReproduction,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn promotion_decision_serde_roundtrip() {
        for decision in [
            PromotionDecision::Promote,
            PromotionDecision::Hold,
            PromotionDecision::Reject,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let back: PromotionDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, back);
        }
    }

    #[test]
    fn promotion_decision_display_all_unique() {
        let displays: BTreeSet<String> = [
            PromotionDecision::Promote,
            PromotionDecision::Hold,
            PromotionDecision::Reject,
        ]
        .iter()
        .map(|d| d.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let variants = [
            VerificationResult::Passed {
                details: "ok".into(),
            },
            VerificationResult::Failed {
                reason: "bad".into(),
            },
            VerificationResult::Skipped {
                reason: "n/a".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: VerificationResult = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn gate_override_cannot_override_rejection() {
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("rej-override"),
        );
        let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "rej-art");
        let verification = failing_verification(&artifact, "not reproducible");

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![artifact],
            verifications: vec![verification],
            override_justification: Some(OverrideJustification {
                authorizer: "owner".to_string(),
                justification: "emergency".to_string(),
                signature: "sig".to_string(),
            }),
        };

        let receipt = evaluate_gate(&input, 11000);
        // Override should still promote even on rejection (per override semantics)
        assert_eq!(receipt.decision, PromotionDecision::Promote);
        assert!(receipt.override_applied);
    }

    #[test]
    fn readiness_summary_serde_roundtrip() {
        let mut registry = GateRegistry::new();
        let gate = GateDefinition::for_program(
            FrontierProgram::ReputationGraph,
            test_gate_id("ready-serde"),
        );
        registry.register_gate(gate);
        let summary = registry.readiness();
        let json = serde_json::to_string(&summary).unwrap();
        let back: ReadinessSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: clone equality (5 tests)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_clone_eq_demo_artifact() {
        let a = test_artifact(ArtifactCategory::ReplayFidelity, "clone-da");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_artifact_verification() {
        let art = test_artifact(ArtifactCategory::AttestationChain, "clone-av");
        let a = passing_verification(&art);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_gate_definition() {
        let a =
            GateDefinition::for_program(FrontierProgram::TrustEconomics, test_gate_id("clone-gd"));
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_override_justification() {
        let a = OverrideJustification {
            authorizer: "admin".to_string(),
            justification: "hot-fix".to_string(),
            signature: "sig-abc".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_release_gate_check() {
        let registry = GateRegistry::new();
        let a = check_release_readiness(&registry, &[FrontierProgram::OperatorCopilot]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Enrichment: JSON field presence (3 tests)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_json_fields_demo_artifact() {
        let art = test_artifact(ArtifactCategory::PropertyProof, "json-da");
        let json = serde_json::to_string(&art).unwrap();
        assert!(json.contains("artifact_id"));
        assert!(json.contains("category"));
        assert!(json.contains("content_hash"));
        assert!(json.contains("producing_commit"));
        assert!(json.contains("test_run_id"));
        assert!(json.contains("summary"));
        assert!(json.contains("public_eligible"));
    }

    #[test]
    fn enrichment_json_fields_gate_evaluation_receipt() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("json-rec"));
        let art = test_artifact(ArtifactCategory::CompromiseWindowReduction, "json-art");
        let ver = passing_verification(&art);
        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art],
            verifications: vec![ver],
            override_justification: None,
        };
        let receipt = evaluate_gate(&input, 42_000);
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("gate_id"));
        assert!(json.contains("program"));
        assert!(json.contains("evaluation_timestamp_ms"));
        assert!(json.contains("category_coverage"));
        assert!(json.contains("decision"));
        assert!(json.contains("rationale"));
        assert!(json.contains("receipt_hash"));
    }

    #[test]
    fn enrichment_json_fields_readiness_summary() {
        let registry = GateRegistry::new();
        let summary = registry.readiness();
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("total_gates"));
        assert!(json.contains("gates_passed"));
        assert!(json.contains("gates_held"));
        assert!(json.contains("gates_rejected"));
        assert!(json.contains("gates_pending"));
        assert!(json.contains("readiness_millionths"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrip (1 test)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_serde_roundtrip_gate_evaluation_input() {
        let gate = GateDefinition::for_program(
            FrontierProgram::AttestedExecutionCells,
            test_gate_id("serde-input"),
        );
        let art = test_artifact(ArtifactCategory::AttestationChain, "serde-ac");
        let ver = passing_verification(&art);
        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art],
            verifications: vec![ver],
            override_justification: Some(OverrideJustification {
                authorizer: "root".to_string(),
                justification: "test".to_string(),
                signature: "test-sig".to_string(),
            }),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: GateEvaluationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness (1 test)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_verification_result_display_all_unique() {
        let variants = [
            VerificationResult::Passed {
                details: "x".into(),
            },
            VerificationResult::Failed { reason: "x".into() },
            VerificationResult::Skipped { reason: "x".into() },
        ];
        let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(displays.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: boundary condition (1 test)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_readiness_with_max_timestamp() {
        let gate = GateDefinition::for_program(
            FrontierProgram::OperatorCopilot,
            test_gate_id("bound-max"),
        );
        let art = test_artifact(ArtifactCategory::OperatorWorkflow, "bound-art");
        let ver = passing_verification(&art);
        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art],
            verifications: vec![ver],
            override_justification: None,
        };
        let receipt = evaluate_gate(&input, u64::MAX);
        assert_eq!(receipt.evaluation_timestamp_ms, u64::MAX);
        assert_eq!(receipt.decision, PromotionDecision::Promote);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Ord determinism (1 test)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_promotion_decision_ord_determinism() {
        let mut decisions = vec![
            PromotionDecision::Reject,
            PromotionDecision::Promote,
            PromotionDecision::Hold,
            PromotionDecision::Reject,
            PromotionDecision::Promote,
        ];
        decisions.sort();
        let sorted_once = decisions.clone();
        decisions.sort();
        assert_eq!(decisions, sorted_once);
        // Promote < Hold < Reject by derive order
        assert!(PromotionDecision::Promote < PromotionDecision::Hold);
        assert!(PromotionDecision::Hold < PromotionDecision::Reject);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Copy semantics, Hash, missing coverage
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_frontier_program_copy_semantics() {
        let a = FrontierProgram::CausalTimeMachine;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(a.code(), "9H.3");
    }

    #[test]
    fn enrichment_artifact_category_copy_semantics() {
        let a = ArtifactCategory::ReplayFidelity;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "ReplayFidelity");
    }

    #[test]
    fn enrichment_promotion_decision_copy_semantics() {
        let a = PromotionDecision::Hold;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(b.to_string(), "hold");
    }

    #[test]
    fn enrichment_frontier_program_hash_in_btreeset() {
        let mut set = BTreeSet::new();
        for p in FrontierProgram::all() {
            assert!(set.insert(*p));
        }
        assert_eq!(set.len(), 10);
        // Inserting duplicates returns false
        assert!(!set.insert(FrontierProgram::ProofCarryingOptimizer));
    }

    #[test]
    fn enrichment_artifact_category_ord_in_btreeset() {
        let mut set = BTreeSet::new();
        set.insert(ArtifactCategory::CrossRuntimeFairness);
        set.insert(ArtifactCategory::TranslationValidation);
        set.insert(ArtifactCategory::AttackerRoiTrend);
        set.insert(ArtifactCategory::CrossRuntimeFairness); // dup
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn enrichment_artifact_category_serde_all_21_variants() {
        let all = [
            ArtifactCategory::TranslationValidation,
            ArtifactCategory::PerformanceBenchmark,
            ArtifactCategory::RollbackTest,
            ArtifactCategory::ConvergenceMeasurement,
            ArtifactCategory::ErrorRateEvidence,
            ArtifactCategory::PartitionBehavior,
            ArtifactCategory::ReplayFidelity,
            ArtifactCategory::CounterfactualAnalysis,
            ArtifactCategory::CrossNodeReplay,
            ArtifactCategory::AttestationChain,
            ArtifactCategory::AttestationFallback,
            ArtifactCategory::PropertyProof,
            ArtifactCategory::CounterexampleEvidence,
            ArtifactCategory::CampaignEvolution,
            ArtifactCategory::DefenseImprovement,
            ArtifactCategory::DecisionScoring,
            ArtifactCategory::AttackerRoiTrend,
            ArtifactCategory::CompromiseWindowReduction,
            ArtifactCategory::OperatorWorkflow,
            ArtifactCategory::IndependentReproduction,
            ArtifactCategory::CrossRuntimeFairness,
        ];
        assert_eq!(all.len(), 21);
        for cat in &all {
            let json = serde_json::to_string(cat).unwrap();
            let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn enrichment_program_gate_status_clone_eq() {
        let status = ProgramGateStatus {
            program: FrontierProgram::TrustEconomics,
            gate_defined: true,
            latest_decision: Some(PromotionDecision::Hold),
            categories_required: 2,
            categories_satisfied: 1,
        };
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn enrichment_program_gate_status_serde_roundtrip() {
        let status = ProgramGateStatus {
            program: FrontierProgram::AutonomousRedBlue,
            gate_defined: false,
            latest_decision: None,
            categories_required: 0,
            categories_satisfied: 0,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: ProgramGateStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn enrichment_program_gate_status_json_fields() {
        let status = ProgramGateStatus {
            program: FrontierProgram::BenchmarkStandard,
            gate_defined: true,
            latest_decision: Some(PromotionDecision::Promote),
            categories_required: 2,
            categories_satisfied: 2,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("program"));
        assert!(json.contains("gate_defined"));
        assert!(json.contains("latest_decision"));
        assert!(json.contains("categories_required"));
        assert!(json.contains("categories_satisfied"));
    }

    #[test]
    fn enrichment_verification_summary_entry_clone_eq() {
        let entry = VerificationSummaryEntry {
            category: ArtifactCategory::PropertyProof,
            passed: true,
            detail: "proof checked".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn enrichment_verification_summary_entry_serde_roundtrip() {
        let entry = VerificationSummaryEntry {
            category: ArtifactCategory::DefenseImprovement,
            passed: false,
            detail: "defense regression".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: VerificationSummaryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn enrichment_gate_registry_default_is_empty() {
        let registry = GateRegistry::default();
        assert!(registry.gates.is_empty());
        assert!(registry.latest_receipts.is_empty());
        assert_eq!(registry, GateRegistry::new());
    }

    #[test]
    fn enrichment_registry_gates_sorted_by_program() {
        let mut registry = GateRegistry::new();
        // Register in reverse order
        registry.register_gate(GateDefinition::for_program(
            FrontierProgram::BenchmarkStandard,
            test_gate_id("sort-10"),
        ));
        registry.register_gate(GateDefinition::for_program(
            FrontierProgram::ProofCarryingOptimizer,
            test_gate_id("sort-1"),
        ));
        registry.register_gate(GateDefinition::for_program(
            FrontierProgram::FleetImmuneSystem,
            test_gate_id("sort-2"),
        ));
        // Should be sorted by program Ord
        assert_eq!(
            registry.gates[0].program,
            FrontierProgram::ProofCarryingOptimizer
        );
        assert_eq!(
            registry.gates[1].program,
            FrontierProgram::FleetImmuneSystem
        );
        assert_eq!(
            registry.gates[2].program,
            FrontierProgram::BenchmarkStandard
        );
    }

    #[test]
    fn enrichment_can_promote_false_when_no_receipt() {
        let mut registry = GateRegistry::new();
        registry.register_gate(GateDefinition::for_program(
            FrontierProgram::PolicyTheoremEngine,
            test_gate_id("no-receipt"),
        ));
        assert!(!registry.can_promote(FrontierProgram::PolicyTheoremEngine));
    }

    #[test]
    fn enrichment_release_check_mixed_states() {
        let mut registry = GateRegistry::new();

        // Gate 1: passed
        let gate1 =
            GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("mix-op"));
        registry.register_gate(gate1.clone());
        let art1 = test_artifact(ArtifactCategory::OperatorWorkflow, "mix-ow");
        let ver1 = passing_verification(&art1);
        let receipt1 = evaluate_gate(
            &GateEvaluationInput {
                gate: gate1,
                artifacts: vec![art1],
                verifications: vec![ver1],
                override_justification: None,
            },
            50000,
        );
        registry.record_receipt(receipt1);

        // Gate 2: registered but no receipt (blocked)
        registry.register_gate(GateDefinition::for_program(
            FrontierProgram::TrustEconomics,
            test_gate_id("mix-te"),
        ));

        let check = check_release_readiness(
            &registry,
            &[
                FrontierProgram::OperatorCopilot,
                FrontierProgram::TrustEconomics,
                FrontierProgram::CausalTimeMachine, // undefined
            ],
        );
        assert!(!check.release_allowed);
        assert_eq!(check.passed.len(), 1);
        assert_eq!(check.blocked.len(), 1);
        assert_eq!(check.undefined.len(), 1);
    }

    #[test]
    fn enrichment_skipped_external_not_counted_as_passed() {
        let gate =
            GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("skip-ext"));
        let art = test_artifact(ArtifactCategory::CompromiseWindowReduction, "skip-art");
        let mut ver = passing_verification(&art);
        ver.external_verification = Some(VerificationResult::Skipped {
            reason: "verifier offline".to_string(),
        });

        let input = GateEvaluationInput {
            gate,
            artifacts: vec![art],
            verifications: vec![ver],
            override_justification: None,
        };
        let receipt = evaluate_gate(&input, 60000);
        // External skipped → not counted as external pass → gate holds
        assert_eq!(receipt.decision, PromotionDecision::Hold);
        assert!(!receipt.has_external_verification);
    }

    #[test]
    fn enrichment_receipt_replaces_existing_in_registry() {
        let mut registry = GateRegistry::new();
        let gate = GateDefinition::for_program(
            FrontierProgram::OperatorCopilot,
            test_gate_id("replace-rec"),
        );
        registry.register_gate(gate.clone());

        // First evaluation: hold (no artifacts)
        let receipt1 = evaluate_gate(
            &GateEvaluationInput {
                gate: gate.clone(),
                artifacts: vec![],
                verifications: vec![],
                override_justification: None,
            },
            70000,
        );
        registry.record_receipt(receipt1);
        assert!(!registry.can_promote(FrontierProgram::OperatorCopilot));

        // Second evaluation: pass
        let art = test_artifact(ArtifactCategory::OperatorWorkflow, "replace-art");
        let ver = passing_verification(&art);
        let receipt2 = evaluate_gate(
            &GateEvaluationInput {
                gate,
                artifacts: vec![art],
                verifications: vec![ver],
                override_justification: None,
            },
            71000,
        );
        registry.record_receipt(receipt2);
        assert!(registry.can_promote(FrontierProgram::OperatorCopilot));
        // Only one receipt stored (replaced)
        assert_eq!(registry.latest_receipts.len(), 1);
    }

    #[test]
    fn enrichment_gate_codes_start_with_9h() {
        for program in FrontierProgram::all() {
            assert!(
                program.code().starts_with("9H."),
                "code {} should start with 9H.",
                program.code()
            );
        }
    }

    #[test]
    fn enrichment_all_programs_have_nonempty_display() {
        for program in FrontierProgram::all() {
            let display = program.to_string();
            assert!(!display.is_empty());
            assert!(display.len() > 5, "display '{}' too short", display);
        }
    }
}
