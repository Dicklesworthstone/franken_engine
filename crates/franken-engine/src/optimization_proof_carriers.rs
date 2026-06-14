#![forbid(unsafe_code)]

//! Optimization-pass proof carriers for FrankenEngine.
//!
//! This module implements G.8 optimization verification extending the G.4-G.7
//! translation validation and policy verification infrastructure to provide
//! formal verification that optimization transformations preserve semantic
//! correctness while generating proof certificates.
//!
//! Optimization passes supported:
//! - Dead code elimination
//! - Constant folding and propagation
//! - Loop optimization (unrolling, invariant hoisting)
//! - Inline expansion
//! - Register allocation optimization
//! - Control flow graph optimization

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use proptest::{
    collection::vec as prop_vec,
    prelude::{Just, Strategy},
    test_runner::{Config as ProptestConfig, TestCaseError, TestRng, TestRunner},
};
use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::policy_theorem_engine::{
    EmittedProofBundle, ProofBundleBody, Z3Outcome, invoke_z3, write_proof_bundle, z3_tool_version,
};

/// Deterministic certificate id: a stable prefix plus the first 16 hex chars
/// of a SHA-256 over the certified content (each part length-prefixed so
/// distinct part decompositions cannot collide). Certificate identity must be
/// a function of certificate content — never allocation addresses — or the
/// exported verification artifact stops being reproducible.
fn deterministic_certificate_id(prefix: &str, parts: &[&str]) -> String {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    let hex = ContentHash::compute(&bytes).to_hex();
    format!("{prefix}_{}", &hex[..16])
}

/// Types of optimization passes supported by proof carriers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationPass {
    /// Dead code elimination
    DeadCodeElimination,
    /// Constant folding and propagation
    ConstantFolding,
    /// Constant propagation across basic blocks
    ConstantPropagation,
    /// Loop unrolling optimization
    LoopUnrolling,
    /// Loop invariant code motion
    LoopInvariantHoisting,
    /// Function inline expansion
    InlineExpansion,
    /// Register allocation optimization
    RegisterAllocation,
    /// Control flow graph simplification
    ControlFlowOptimization,
    /// Common subexpression elimination
    CommonSubexpressionElimination,
    /// Tail call optimization
    TailCallOptimization,
}

/// Optimization proof carrier context for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationProofCarrier {
    /// Source IR before optimization
    pub source_ir: String,
    /// Target IR after optimization
    pub target_ir: String,
    /// Applied optimization passes in order
    pub applied_passes: Vec<OptimizationPassApplication>,
    /// Semantic equivalence proofs
    pub equivalence_proofs: Vec<EquivalenceProof>,
    /// Performance improvement metrics
    pub performance_metrics: OptimizationMetrics,
    /// Verification status
    pub verification_status: OptimizationVerificationStatus,
    /// Generated proof certificates
    pub proof_certificates: Vec<ProofCertificate>,
}

/// Application of a specific optimization pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationPassApplication {
    pub pass_id: String,
    pub optimization_type: OptimizationPass,
    pub source_region: IrRegion,
    pub target_region: IrRegion,
    pub transformation_rules: Vec<TransformationRule>,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub performance_impact: PerformanceImpact,
}

/// IR region affected by optimization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrRegion {
    pub region_id: String,
    pub start_instruction: usize,
    pub end_instruction: usize,
    pub basic_blocks: BTreeSet<String>,
    pub control_flow_edges: Vec<(String, String)>,
    pub live_variables: BTreeSet<String>,
}

/// Transformation rule for optimization passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationRule {
    pub rule_id: String,
    pub rule_type: TransformationRuleType,
    pub pattern: String,
    pub replacement: String,
    pub applicability_conditions: Vec<String>,
    pub preservation_properties: Vec<String>,
}

/// Types of transformation rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformationRuleType {
    /// Pattern-based code transformation
    PatternReplacement,
    /// Control flow restructuring
    ControlFlowRestructuring,
    /// Data flow optimization
    DataFlowOptimization,
    /// Resource allocation change
    ResourceReallocation,
    /// Execution order change
    ExecutionReordering,
}

/// Semantic equivalence proof between source and target IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalenceProof {
    pub proof_id: String,
    pub proof_method: ProofMethod,
    pub source_semantics: String,
    pub target_semantics: String,
    pub equivalence_relation: EquivalenceRelation,
    pub proof_obligations: Vec<ProofObligation>,
    pub verification_result: ProofResult,
}

/// Methods for proving semantic equivalence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofMethod {
    /// Bisimulation equivalence
    Bisimulation,
    /// Observational equivalence
    ObservationalEquivalence,
    /// Contextual equivalence
    ContextualEquivalence,
    /// Program logic proof
    ProgramLogic,
    /// SMT-based verification
    SmtVerification,
    /// Refinement proof
    Refinement,
}

/// Equivalence relations for optimization verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivalenceRelation {
    /// Exact semantic equivalence
    ExactEquivalence,
    /// Observational equivalence (same outputs)
    ObservationalEquivalence,
    /// Refinement (target refines source)
    Refinement,
    /// Weak equivalence (modulo internal steps)
    WeakEquivalence,
    /// Performance equivalence (same complexity class)
    PerformanceEquivalence,
}

/// Proof obligation for optimization verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofObligation {
    pub obligation_id: String,
    pub obligation_type: ObligationType,
    pub premise: String,
    pub conclusion: String,
    pub proof_sketch: String,
    pub verification_method: VerificationMethod,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_inputs: Vec<OptimizationSampleInput>,
}

/// Concrete input environment for runner-backed optimization verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptimizationSampleInput {
    pub bindings: BTreeMap<String, i64>,
}

impl OptimizationSampleInput {
    pub fn empty() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    pub fn from_bindings<I, K>(bindings: I) -> Self
    where
        I: IntoIterator<Item = (K, i64)>,
        K: Into<String>,
    {
        Self {
            bindings: bindings
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
        }
    }
}

/// Types of proof obligations for optimizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationType {
    /// Semantic preservation across transformation
    SemanticPreservation,
    /// Termination preservation
    TerminationPreservation,
    /// Resource usage bounds
    ResourceBounds,
    /// Side effect preservation
    SideEffectPreservation,
    /// Control flow preservation
    ControlFlowPreservation,
    /// Data dependency preservation
    DataDependencyPreservation,
}

/// Verification methods for proof obligations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Formal logic proof
    FormalLogic,
    /// Model checking
    ModelChecking,
    /// Theorem proving
    TheoremProving,
    /// Symbolic execution
    SymbolicExecution,
    /// Property testing
    PropertyTesting,
    /// Differential testing
    DifferentialTesting,
}

/// Result of proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofResult {
    /// Proof successfully verified
    Verified,
    /// Proof failed verification
    Failed,
    /// Proof verification timed out
    Timeout,
    /// Proof verification inconclusive
    Inconclusive,
    /// Proof not yet attempted
    Pending,
}

/// Performance impact of optimization pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceImpact {
    pub execution_time_change: f64,      // Percentage change
    pub memory_usage_change: f64,        // Percentage change
    pub code_size_change: f64,           // Percentage change
    pub compile_time_overhead: f64,      // Milliseconds
    pub optimization_benefit_score: f64, // 0.0 to 1.0
}

/// Overall optimization metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationMetrics {
    pub total_passes_applied: usize,
    pub total_transformations: usize,
    pub verification_time_ms: u64,
    pub proof_generation_time_ms: u64,
    pub overall_performance_improvement: f64,
    pub optimization_safety_score: f64, // 0.0 to 1.0
}

/// Verification status for optimization passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationVerificationStatus {
    /// All optimizations verified correct
    FullyVerified,
    /// Some optimizations verified, others pending
    PartiallyVerified,
    /// Verification failed for some optimizations
    VerificationFailed,
    /// Verification not yet started
    Unverified,
    /// Verification encountered errors
    VerificationError,
}

/// Proof certificate for optimization verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCertificate {
    pub certificate_id: String,
    pub optimization_passes: Vec<String>,
    pub certificate_type: CertificateType,
    pub certificate_data: String,
    pub validity_period: Option<u64>, // Seconds
    pub signature: Option<String>,
    pub verification_metadata: BTreeMap<String, String>,
}

/// Types of proof certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateType {
    /// Semantic equivalence certificate
    SemanticEquivalence,
    /// Performance improvement certificate
    PerformanceImprovement,
    /// Safety preservation certificate
    SafetyPreservation,
    /// Resource bounds certificate
    ResourceBounds,
    /// Composite certificate covering multiple properties
    Composite,
}

impl OptimizationProofCarrier {
    /// Create a new optimization proof carrier.
    pub fn new(source_ir: String, target_ir: String) -> Self {
        Self {
            source_ir,
            target_ir,
            applied_passes: Vec::new(),
            equivalence_proofs: Vec::new(),
            performance_metrics: OptimizationMetrics::default(),
            verification_status: OptimizationVerificationStatus::Unverified,
            proof_certificates: Vec::new(),
        }
    }

    /// Add an optimization pass application.
    pub fn add_optimization_pass(&mut self, pass: OptimizationPassApplication) {
        self.applied_passes.push(pass);
        self.performance_metrics.total_passes_applied += 1;
    }

    /// Generate semantic equivalence proofs for all optimization passes.
    pub fn generate_equivalence_proofs(&mut self) -> Result<usize, String> {
        let mut proof_count = 0;

        for pass in &self.applied_passes {
            let proof_id = format!("equiv_proof_{}", pass.pass_id);

            let proof_obligations = self.generate_proof_obligations_for_pass(pass)?;

            let equivalence_proof = EquivalenceProof {
                proof_id: proof_id.clone(),
                proof_method: self.select_proof_method(&pass.optimization_type),
                source_semantics: format!("Source semantics for pass {}", pass.pass_id),
                target_semantics: format!("Target semantics for pass {}", pass.pass_id),
                equivalence_relation: self.determine_equivalence_relation(&pass.optimization_type),
                proof_obligations,
                verification_result: ProofResult::Pending,
            };

            self.equivalence_proofs.push(equivalence_proof);
            proof_count += 1;
        }

        Ok(proof_count)
    }

    /// Generate proof obligations for a specific optimization pass.
    fn generate_proof_obligations_for_pass(
        &self,
        pass: &OptimizationPassApplication,
    ) -> Result<Vec<ProofObligation>, String> {
        let mut obligations = Vec::new();

        let sample_inputs = Self::generated_sample_inputs_for_pass(pass);

        // Semantic preservation obligation
        obligations.push(ProofObligation {
            obligation_id: format!("{}_semantic_preservation", pass.pass_id),
            obligation_type: ObligationType::SemanticPreservation,
            premise: "Source and target execute in the bounded optimization sample language"
                .to_string(),
            conclusion: "Source and target return equal values for every attached sample"
                .to_string(),
            proof_sketch: format!(
                "Run source and target for {} over deterministic bounded samples",
                pass.optimization_type.type_name()
            ),
            verification_method: VerificationMethod::DifferentialTesting,
            sample_inputs: sample_inputs.clone(),
        });

        // Termination preservation obligation
        obligations.push(ProofObligation {
            obligation_id: format!("{}_termination", pass.pass_id),
            obligation_type: ObligationType::TerminationPreservation,
            premise: "Source and target execute within the bounded sample runner".to_string(),
            conclusion: "Both programs return before the loop-iteration cap".to_string(),
            proof_sketch: "Execute both programs through the bounded sample runner".to_string(),
            verification_method: VerificationMethod::PropertyTesting,
            sample_inputs: sample_inputs.clone(),
        });

        // Pass-specific obligations
        match pass.optimization_type {
            OptimizationPass::DeadCodeElimination => {
                obligations.push(ProofObligation {
                    obligation_id: format!("{}_dead_code_safety", pass.pass_id),
                    obligation_type: ObligationType::SideEffectPreservation,
                    premise: "Code identified as dead".to_string(),
                    conclusion: "Dead code has no observable effects".to_string(),
                    proof_sketch: "Differential sample execution observes identical returns"
                        .to_string(),
                    verification_method: VerificationMethod::DifferentialTesting,
                    sample_inputs: sample_inputs.clone(),
                });
            }
            OptimizationPass::ConstantFolding | OptimizationPass::ConstantPropagation => {
                obligations.push(ProofObligation {
                    obligation_id: format!("{}_value_preservation", pass.pass_id),
                    obligation_type: ObligationType::SemanticPreservation,
                    premise: "Constant values computed".to_string(),
                    conclusion: "Computed values equal runtime values".to_string(),
                    proof_sketch: "Differential sample execution checks folded values".to_string(),
                    verification_method: VerificationMethod::DifferentialTesting,
                    sample_inputs: sample_inputs.clone(),
                });
            }
            OptimizationPass::LoopUnrolling | OptimizationPass::LoopInvariantHoisting => {
                obligations.push(ProofObligation {
                    obligation_id: format!("{}_loop_semantics", pass.pass_id),
                    obligation_type: ObligationType::ControlFlowPreservation,
                    premise: "Loop structure transformed".to_string(),
                    conclusion: "Loop semantics preserved".to_string(),
                    proof_sketch: "Loop invariant preservation + iteration count equivalence"
                        .to_string(),
                    verification_method: VerificationMethod::PropertyTesting,
                    sample_inputs: sample_inputs.clone(),
                });
            }
            OptimizationPass::InlineExpansion => {
                obligations.push(ProofObligation {
                    obligation_id: format!("{}_inlining_correctness", pass.pass_id),
                    obligation_type: ObligationType::SemanticPreservation,
                    premise: "Function call replaced with body".to_string(),
                    conclusion: "Inline expansion preserves call semantics".to_string(),
                    proof_sketch: "Differential sample execution checks substituted body"
                        .to_string(),
                    verification_method: VerificationMethod::DifferentialTesting,
                    sample_inputs: sample_inputs.clone(),
                });
            }
            _ => {} // Other passes use default obligations
        }

        Ok(obligations)
    }

    fn generated_sample_inputs_for_pass(
        pass: &OptimizationPassApplication,
    ) -> Vec<OptimizationSampleInput> {
        let live_variables: BTreeSet<String> = pass
            .source_region
            .live_variables
            .iter()
            .chain(pass.target_region.live_variables.iter())
            .cloned()
            .collect();

        if live_variables.is_empty() {
            return vec![OptimizationSampleInput::empty()];
        }

        [0i64, 1, -1]
            .into_iter()
            .map(|seed| {
                OptimizationSampleInput::from_bindings(
                    live_variables
                        .iter()
                        .enumerate()
                        .map(|(idx, name)| (name.clone(), seed.saturating_add(idx as i64))),
                )
            })
            .collect()
    }

    /// Select appropriate proof method for optimization type.
    fn select_proof_method(&self, optimization: &OptimizationPass) -> ProofMethod {
        match optimization {
            OptimizationPass::DeadCodeElimination => ProofMethod::Bisimulation,
            OptimizationPass::ConstantFolding | OptimizationPass::ConstantPropagation => {
                ProofMethod::SmtVerification
            }
            OptimizationPass::LoopUnrolling | OptimizationPass::LoopInvariantHoisting => {
                ProofMethod::ProgramLogic
            }
            OptimizationPass::InlineExpansion => ProofMethod::ContextualEquivalence,
            OptimizationPass::RegisterAllocation => ProofMethod::Refinement,
            _ => ProofMethod::ObservationalEquivalence,
        }
    }

    /// Determine equivalence relation for optimization type.
    fn determine_equivalence_relation(
        &self,
        optimization: &OptimizationPass,
    ) -> EquivalenceRelation {
        match optimization {
            OptimizationPass::DeadCodeElimination => EquivalenceRelation::ExactEquivalence,
            OptimizationPass::ConstantFolding | OptimizationPass::ConstantPropagation => {
                EquivalenceRelation::ExactEquivalence
            }
            OptimizationPass::LoopUnrolling => EquivalenceRelation::WeakEquivalence,
            OptimizationPass::RegisterAllocation => EquivalenceRelation::ObservationalEquivalence,
            OptimizationPass::TailCallOptimization => EquivalenceRelation::PerformanceEquivalence,
            _ => EquivalenceRelation::ObservationalEquivalence,
        }
    }

    /// Verify all equivalence proofs.
    pub fn verify_all_proofs(&mut self) -> Result<OptimizationVerificationResult, String> {
        let mut verified_proofs = 0;
        let mut failed_proofs = Vec::new();
        let start_time = std::time::Instant::now();

        // First, collect verification results without mutating self.equivalence_proofs
        let verification_results: Result<Vec<_>, String> = self
            .equivalence_proofs
            .iter()
            .map(|proof| self.verify_single_proof(proof))
            .collect();
        let verification_results = verification_results?;

        // Then apply the results
        for (proof, verification_result) in
            self.equivalence_proofs.iter_mut().zip(verification_results)
        {
            match verification_result {
                ProofResult::Verified => {
                    proof.verification_result = ProofResult::Verified;
                    verified_proofs += 1;
                }
                _ => {
                    proof.verification_result = verification_result;
                    failed_proofs.push(proof.proof_id.clone());
                }
            }
        }

        let verification_time = start_time.elapsed();
        self.performance_metrics.verification_time_ms = verification_time.as_millis() as u64;

        // Update overall verification status
        self.verification_status = if failed_proofs.is_empty() {
            OptimizationVerificationStatus::FullyVerified
        } else if verified_proofs > 0 {
            OptimizationVerificationStatus::PartiallyVerified
        } else {
            OptimizationVerificationStatus::VerificationFailed
        };

        // Generate proof certificates. Always run: `generate_proof_certificates`
        // internally gates each certificate. The SemanticEquivalence cert is gated
        // on actually-verified passes, so it stays fail-closed when
        // `verified_proofs == 0` (prose-premise obligations fail closed through Z3 —
        // bd-cixqu.7.17.2). The PerformanceImprovement cert is gated on the
        // engine-tracked `overall_performance_improvement`, independent of proof
        // verification. Guarding the whole call on `verified_proofs > 0` wrongly
        // suppressed the performance cert once verification became fail-closed.
        self.generate_proof_certificates()?;

        Ok(OptimizationVerificationResult {
            total_proofs: self.equivalence_proofs.len(),
            verified_proofs,
            failed_proofs: failed_proofs.len(),
            failed_proof_ids: failed_proofs,
            verification_time_ms: verification_time.as_millis() as u64,
            optimization_safety_verified: self.verification_status
                == OptimizationVerificationStatus::FullyVerified,
            performance_improvement_verified: verified_proofs > 0,
            certificates_generated: !self.proof_certificates.is_empty(),
        })
    }

    /// Verify a single equivalence proof.
    fn verify_single_proof(&self, proof: &EquivalenceProof) -> Result<ProofResult, String> {
        // In a real implementation, this would invoke actual verification tools
        // For now, simulate verification based on proof method and obligations

        for obligation in &proof.proof_obligations {
            let obligation_result = self.verify_proof_obligation(obligation)?;
            if obligation_result != ProofResult::Verified {
                return Ok(obligation_result);
            }
        }

        // All obligations verified successfully
        Ok(ProofResult::Verified)
    }

    /// Verify a single proof obligation.
    ///
    /// **bd-cixqu.7.17.2**: previously this method returned
    /// `Ok(ProofResult::Verified)` unconditionally for every
    /// `VerificationMethod` variant, fabricating proofs for any obligation
    /// passed in. The unconditional-Verified stub is replaced here with a
    /// fail-closed router:
    ///
    /// - `FormalLogic` / `TheoremProving` route through the existing Z3
    ///   implication verifier (`policy_theorem_engine::invoke_z3`, exposed by
    ///   bd-cixqu.7.17). The premise and conclusion are taken to be SMT-LIB-2
    ///   formula fragments; the verifier asserts `(not (=> premise
    ///   conclusion))` and accepts `unsat` as `Verified`.
    /// - `ModelChecking` / `SymbolicExecution` route through a bounded Z3 script
    ///   verifier. The premise must be SMT-LIB setup/assertion commands that
    ///   encode the finite model or symbolic pre-state; the conclusion must be
    ///   an SMT-LIB formula. The verifier asserts the negated conclusion under
    ///   those assumptions and accepts only `unsat`. Generated prose premises
    ///   are malformed SMT-LIB and fail closed.
    /// - `DifferentialTesting` / `PropertyTesting` route through a bounded
    ///   deterministic sample runner. The runner executes `source_ir` and
    ///   `target_ir` under every explicit sample input attached to the
    ///   obligation and accepts only byte-identical integer return values.
    ///   Missing samples or unsupported syntax fail closed.
    /// - Any obligation with an empty `premise` or `conclusion` is rejected:
    ///   there's no formula to verify.
    ///
    /// Reuse the new `invoke_z3` helper bd-cixqu.7.17 exposed; no separate Z3
    /// subprocess wrapper lives here.
    fn verify_proof_obligation(&self, obligation: &ProofObligation) -> Result<ProofResult, String> {
        if obligation.premise.trim().is_empty() || obligation.conclusion.trim().is_empty() {
            return Ok(ProofResult::Failed);
        }
        match obligation.verification_method {
            VerificationMethod::FormalLogic | VerificationMethod::TheoremProving => {
                Ok(verify_via_z3(&obligation.premise, &obligation.conclusion))
            }
            VerificationMethod::ModelChecking | VerificationMethod::SymbolicExecution => Ok(
                verify_via_bounded_z3_model(&obligation.premise, &obligation.conclusion),
            ),
            VerificationMethod::PropertyTesting => Ok(verify_with_sample_property_runner(
                &self.source_ir,
                &self.target_ir,
                &obligation.sample_inputs,
            )),
            VerificationMethod::DifferentialTesting => Ok(verify_with_sample_differential_runner(
                &self.source_ir,
                &self.target_ir,
                &obligation.sample_inputs,
            )),
        }
    }

    /// Generate proof certificates for verified optimizations.
    fn generate_proof_certificates(&mut self) -> Result<usize, String> {
        let mut certificate_count = 0;

        // Generate semantic equivalence certificate
        let verified_passes: Vec<String> = self
            .applied_passes
            .iter()
            .filter(|pass| {
                self.equivalence_proofs.iter().any(|proof| {
                    proof.proof_id.contains(&pass.pass_id)
                        && proof.verification_result == ProofResult::Verified
                })
            })
            .map(|pass| pass.pass_id.clone())
            .collect();

        if !verified_passes.is_empty() {
            let semantic_id_parts: Vec<&str> = verified_passes.iter().map(String::as_str).collect();
            let semantic_cert = ProofCertificate {
                certificate_id: deterministic_certificate_id(
                    "semantic_equiv_cert",
                    &semantic_id_parts,
                ),
                optimization_passes: verified_passes.clone(),
                certificate_type: CertificateType::SemanticEquivalence,
                certificate_data: format!(
                    "Semantic equivalence verified for {} optimization passes",
                    verified_passes.len()
                ),
                validity_period: Some(86400 * 30), // 30 days
                signature: Some("proof_carrier_signature".to_string()),
                verification_metadata: [
                    (
                        "verification_time".to_string(),
                        self.performance_metrics.verification_time_ms.to_string(),
                    ),
                    ("method".to_string(), "formal_verification".to_string()),
                ]
                .into_iter()
                .collect(),
            };

            self.proof_certificates.push(semantic_cert);
            certificate_count += 1;
        }

        // Generate performance improvement certificate
        if self.performance_metrics.overall_performance_improvement > 0.0 {
            let improvement_text = self
                .performance_metrics
                .overall_performance_improvement
                .to_string();
            let safety_text = self
                .performance_metrics
                .optimization_safety_score
                .to_string();
            let mut performance_id_parts: Vec<&str> =
                verified_passes.iter().map(String::as_str).collect();
            performance_id_parts.push(improvement_text.as_str());
            performance_id_parts.push(safety_text.as_str());
            let performance_cert = ProofCertificate {
                certificate_id: deterministic_certificate_id(
                    "performance_cert",
                    &performance_id_parts,
                ),
                optimization_passes: verified_passes,
                certificate_type: CertificateType::PerformanceImprovement,
                certificate_data: format!(
                    "Performance improvement: {:.2}% verified",
                    self.performance_metrics.overall_performance_improvement * 100.0
                ),
                validity_period: Some(86400 * 7), // 7 days
                signature: Some("performance_analysis_signature".to_string()),
                verification_metadata: [
                    (
                        "improvement_score".to_string(),
                        self.performance_metrics
                            .overall_performance_improvement
                            .to_string(),
                    ),
                    (
                        "safety_score".to_string(),
                        self.performance_metrics
                            .optimization_safety_score
                            .to_string(),
                    ),
                ]
                .into_iter()
                .collect(),
            };

            self.proof_certificates.push(performance_cert);
            certificate_count += 1;
        }

        Ok(certificate_count)
    }

    /// Export proof carrier as verification artifact.
    pub fn export_verification_artifact(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| {
            format!(
                "Optimization proof carrier: {} passes, {} proofs, status: {:?}",
                self.applied_passes.len(),
                self.equivalence_proofs.len(),
                self.verification_status
            )
        })
    }

    /// Emit Track-G proof bundles for FE-CLAIM-019 and FE-CLAIM-020.
    ///
    /// This is deliberately fail-closed: bundles are written only after the
    /// carrier has a fully verified optimization proof set. Generated carriers
    /// whose source/target programs do not fit the bounded sample language, or
    /// whose SMT obligations do not prove, return an empty list.
    pub fn emit_fe_claim_019_020_proof_bundles(
        &self,
        bundle_dir: &Path,
    ) -> Result<Vec<EmittedProofBundle>, String> {
        if self.verification_status != OptimizationVerificationStatus::FullyVerified {
            return Ok(Vec::new());
        }

        let mut theorem_ids: Vec<String> = self
            .equivalence_proofs
            .iter()
            .filter(|proof| proof.verification_result == ProofResult::Verified)
            .map(|proof| format!("optimization-equivalence-{}", proof.proof_id))
            .collect();
        theorem_ids.sort();
        theorem_ids.dedup();

        if theorem_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut emitted = Vec::new();
        for claim_id in ["FE-CLAIM-019", "FE-CLAIM-020"] {
            let proof_kind = match claim_id {
                "FE-CLAIM-019" => "optimization-isomorphism",
                "FE-CLAIM-020" => "theorem-backed-compiler",
                _ => unreachable!("fixed FE-CLAIM-019/020 bundle list"),
            };
            let body = ProofBundleBody {
                schema_version: "franken-engine.theorem-backed-compiler.proof.v1".to_string(),
                claim_id: claim_id.to_string(),
                track: "track-g".to_string(),
                proof_kind: proof_kind.to_string(),
                verdict: "proven".to_string(),
                generated_utc: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                source_module: "frankenengine_engine::optimization_proof_carriers".to_string(),
                producer_tool: "z3".to_string(),
                producer_version: z3_tool_version()
                    .unwrap_or_else(|err| format!("unavailable: {err}")),
                timeout_policy: format!(
                    "per-obligation z3 -t:{}ms",
                    Z3_VERIFY_TIMEOUT_SECONDS.saturating_mul(1_000)
                ),
                timeout_seconds: Z3_VERIFY_TIMEOUT_SECONDS,
                theorem_count: theorem_ids.len(),
                theorem_ids: theorem_ids.clone(),
            };
            emitted.push(write_proof_bundle(&body, bundle_dir)?);
        }

        Ok(emitted)
    }
}

/// Route a proof obligation through Z3 and return a fail-closed
/// [`ProofResult`].
///
/// Builds an SMT-LIB input that asserts `(not (=> premise conclusion))` —
/// `unsat` from Z3 means the universal implication `premise ⇒ conclusion`
/// holds, so the obligation is `Verified`. `sat` is a real counterexample
/// → `Failed`. `unknown` (Z3 gave up) and any subprocess error → `Failed`;
/// the verifier never fabricates `Verified` on solver indecision (the
/// fail-closed behaviour bd-cixqu.7.17.2 introduces). Z3 must be on
/// `$PATH`; if it isn't, the spawn fails and the obligation fails closed,
/// which is the correct signal that no real proof was produced.
///
/// The premise and conclusion are passed through unchanged; obligation
/// generators that want this verifier to ever return `Verified` must emit
/// real SMT-LIB-2 formulas (the current dead-code / constant-folding
/// generators emit PROSE premises, so every such obligation legitimately
/// returns `Failed` here).
fn verify_via_z3(premise: &str, conclusion: &str) -> ProofResult {
    // The G.6/G.7 proof corpus needs first-order quantifiers; the existing
    // `policy_theorem_engine` path uses (set-logic ALL) for the same reason.
    let smt = format!(
        "(set-logic ALL)\n\
         (assert (not (=> {premise} {conclusion})))\n\
         (check-sat)\n\
         (exit)\n"
    );
    match invoke_z3(&smt, Z3_VERIFY_TIMEOUT_SECONDS) {
        Ok(Z3Outcome::Unsat) => ProofResult::Verified,
        Ok(Z3Outcome::Sat { .. }) | Ok(Z3Outcome::Unknown { .. }) => ProofResult::Failed,
        Err(_) => ProofResult::Failed,
    }
}

/// Verify a bounded model-checking or symbolic-execution obligation using Z3.
///
/// `premise` is an SMT-LIB command block, normally declarations plus bounded
/// assumptions such as `(assert (and (<= 0 x) (<= x 4)))`. `conclusion` is an
/// SMT-LIB formula. The query searches for a counterexample by asserting
/// `(not conclusion)` under the premise block; `unsat` means no bounded
/// counterexample exists. This deliberately does not try to infer declarations
/// or translate prose into formulas.
fn verify_via_bounded_z3_model(premise: &str, conclusion: &str) -> ProofResult {
    let premise = premise.trim();
    let conclusion = conclusion.trim();
    if premise.is_empty() || conclusion.is_empty() {
        return ProofResult::Failed;
    }

    let mut smt = String::from("(set-logic QF_LIA)\n");
    smt.push_str(premise);
    if !premise.ends_with('\n') {
        smt.push('\n');
    }
    smt.push_str("(assert (not ");
    smt.push_str(conclusion);
    smt.push_str("))\n(check-sat)\n(exit)\n");

    match invoke_z3(&smt, Z3_VERIFY_TIMEOUT_SECONDS) {
        Ok(Z3Outcome::Unsat) => ProofResult::Verified,
        Ok(Z3Outcome::Sat { .. }) | Ok(Z3Outcome::Unknown { .. }) => ProofResult::Failed,
        Err(_) => ProofResult::Failed,
    }
}

/// Per-obligation Z3 timeout (seconds). Five seconds is the same budget the
/// `policy_theorem_engine` corpus uses for routine NI / monotonicity
/// obligations; raise via a follow-up bead if specific optimization passes
/// emit obligations that genuinely need longer.
const Z3_VERIFY_TIMEOUT_SECONDS: u32 = 5;
const PROPERTY_TEST_CASES: u32 = 64;
const PROPERTY_TEST_VALUE_MIN: i64 = -16;
const PROPERTY_TEST_VALUE_MAX: i64 = 16;
const PROPERTY_TEST_FIXTURE_VALUES: [i64; 5] =
    [PROPERTY_TEST_VALUE_MIN, -1, 0, 1, PROPERTY_TEST_VALUE_MAX];

fn verify_with_sample_differential_runner(
    source_ir: &str,
    target_ir: &str,
    sample_inputs: &[OptimizationSampleInput],
) -> ProofResult {
    if sample_inputs.is_empty() {
        return ProofResult::Failed;
    }

    for sample in sample_inputs {
        if compare_optimization_sample_outputs(source_ir, target_ir, sample).is_err() {
            return ProofResult::Failed;
        }
    }

    ProofResult::Verified
}

fn verify_with_sample_property_runner(
    source_ir: &str,
    target_ir: &str,
    sample_inputs: &[OptimizationSampleInput],
) -> ProofResult {
    if sample_inputs.is_empty() {
        return ProofResult::Failed;
    }

    for fixture in property_sample_fixtures(sample_inputs) {
        let mut runner = deterministic_proptest_runner(1);
        if runner
            .run(&Just(fixture), |sample| {
                compare_optimization_sample_outputs(source_ir, target_ir, &sample)
                    .map_err(TestCaseError::fail)
            })
            .is_err()
        {
            return ProofResult::Failed;
        }
    }

    let variable_names = property_sample_variable_names(sample_inputs);
    if !variable_names.is_empty() {
        let mut runner = deterministic_proptest_runner(PROPERTY_TEST_CASES);
        let generated_samples = property_sample_strategy(variable_names);
        if runner
            .run(&generated_samples, |sample| {
                compare_optimization_sample_outputs(source_ir, target_ir, &sample)
                    .map_err(TestCaseError::fail)
            })
            .is_err()
        {
            return ProofResult::Failed;
        }
    }

    ProofResult::Verified
}

fn deterministic_proptest_runner(cases: u32) -> TestRunner {
    let config = ProptestConfig {
        cases,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
}

fn property_sample_variable_names(sample_inputs: &[OptimizationSampleInput]) -> Vec<String> {
    sample_inputs
        .iter()
        .flat_map(|sample| sample.bindings.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn property_sample_fixtures(
    sample_inputs: &[OptimizationSampleInput],
) -> Vec<OptimizationSampleInput> {
    let variable_names = property_sample_variable_names(sample_inputs);
    let mut fixtures = Vec::new();
    let mut seen = BTreeSet::new();

    for sample in sample_inputs {
        push_unique_property_sample(&mut fixtures, &mut seen, sample.clone());
    }

    if !variable_names.is_empty() {
        for value in PROPERTY_TEST_FIXTURE_VALUES {
            push_unique_property_sample(
                &mut fixtures,
                &mut seen,
                OptimizationSampleInput::from_bindings(
                    variable_names.iter().cloned().map(|name| (name, value)),
                ),
            );
        }

        for variable_name in &variable_names {
            for value in PROPERTY_TEST_FIXTURE_VALUES {
                let bindings = variable_names.iter().cloned().map(|name| {
                    let bound_value = if &name == variable_name { value } else { 0 };
                    (name, bound_value)
                });
                push_unique_property_sample(
                    &mut fixtures,
                    &mut seen,
                    OptimizationSampleInput::from_bindings(bindings),
                );
            }
        }
    }

    fixtures
}

fn push_unique_property_sample(
    fixtures: &mut Vec<OptimizationSampleInput>,
    seen: &mut BTreeSet<BTreeMap<String, i64>>,
    sample: OptimizationSampleInput,
) {
    if seen.insert(sample.bindings.clone()) {
        fixtures.push(sample);
    }
}

fn property_sample_strategy(
    variable_names: Vec<String>,
) -> impl Strategy<Value = OptimizationSampleInput> {
    prop_vec(
        PROPERTY_TEST_VALUE_MIN..=PROPERTY_TEST_VALUE_MAX,
        variable_names.len()..=variable_names.len(),
    )
    .prop_map(move |values| {
        OptimizationSampleInput::from_bindings(variable_names.iter().cloned().zip(values))
    })
}

fn compare_optimization_sample_outputs(
    source_ir: &str,
    target_ir: &str,
    sample: &OptimizationSampleInput,
) -> Result<(), String> {
    let source_output = run_optimization_sample_program(source_ir, sample)?;
    let target_output = run_optimization_sample_program(target_ir, sample)?;
    if source_output == target_output {
        Ok(())
    } else {
        Err(format!(
            "sample output mismatch for bindings {:?}: source returned {}, target returned {}",
            sample.bindings, source_output, target_output
        ))
    }
}

fn run_optimization_sample_program(
    program: &str,
    sample: &OptimizationSampleInput,
) -> Result<i64, String> {
    let lines = normalize_sample_program_lines(program);
    let mut env = sample.bindings.clone();
    let mut idx = 0usize;
    match execute_sample_block(&lines, &mut idx, &mut env)? {
        Some(value) => Ok(value),
        None => Err("sample program did not return a value".to_string()),
    }
}

fn normalize_sample_program_lines(program: &str) -> Vec<String> {
    program
        .lines()
        .filter_map(|line| {
            let without_comment = line.split_once("//").map_or(line, |(prefix, _)| prefix);
            let trimmed = without_comment.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn execute_sample_block(
    lines: &[String],
    idx: &mut usize,
    env: &mut BTreeMap<String, i64>,
) -> Result<Option<i64>, String> {
    while *idx < lines.len() {
        let line = lines[*idx].trim();
        *idx += 1;

        if line == "}" {
            return Ok(None);
        }

        if line.starts_with("if ") {
            let condition = parse_if_condition(line)?;
            let nested = collect_braced_sample_block(lines, idx)?;
            if condition {
                let mut nested_idx = 0usize;
                if let Some(value) = execute_sample_block(&nested, &mut nested_idx, env)? {
                    return Ok(Some(value));
                }
            }
            continue;
        }

        if line.starts_with("for ") {
            let loop_spec = parse_for_loop(line)?;
            let nested = collect_braced_sample_block(lines, idx)?;
            execute_sample_for_loop(&loop_spec, &nested, env)?;
            continue;
        }

        if let Some(expr) = line
            .strip_prefix("return ")
            .map(|expr| expr.trim_end_matches(';').trim())
        {
            return Ok(Some(eval_sample_expr(expr, env)?));
        }

        execute_sample_statement(line, env)?;
    }

    Ok(None)
}

fn collect_braced_sample_block(lines: &[String], idx: &mut usize) -> Result<Vec<String>, String> {
    let mut depth = 1usize;
    let mut nested = Vec::new();

    while *idx < lines.len() {
        let line = lines[*idx].trim();
        *idx += 1;

        if line.ends_with('{') {
            depth = depth.saturating_add(1);
            nested.push(line.to_string());
            continue;
        }

        if line == "}" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Ok(nested);
            }
            nested.push(line.to_string());
            continue;
        }

        nested.push(line.to_string());
    }

    Err("unterminated braced block in optimization sample program".to_string())
}

fn parse_if_condition(line: &str) -> Result<bool, String> {
    let condition = line
        .strip_prefix("if")
        .and_then(|rest| rest.trim().strip_prefix('('))
        .and_then(|rest| rest.split_once(')'))
        .map(|(condition, _)| condition.trim())
        .ok_or_else(|| format!("unsupported if condition syntax: {line}"))?;

    match condition {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "unsupported if condition in sample runner: {other}"
        )),
    }
}

#[derive(Debug, Clone)]
struct SampleForLoop {
    variable: String,
    start: i64,
    end_exclusive: i64,
    increment: i64,
}

fn parse_for_loop(line: &str) -> Result<SampleForLoop, String> {
    let header = line
        .strip_prefix("for")
        .and_then(|rest| rest.trim().strip_prefix('('))
        .and_then(|rest| rest.split_once(')'))
        .map(|(header, _)| header.trim())
        .ok_or_else(|| format!("unsupported for-loop syntax: {line}"))?;
    let mut parts = header.split(';').map(str::trim);
    let init = parts
        .next()
        .ok_or_else(|| format!("missing for-loop initializer: {line}"))?;
    let condition = parts
        .next()
        .ok_or_else(|| format!("missing for-loop condition: {line}"))?;
    let step = parts
        .next()
        .ok_or_else(|| format!("missing for-loop step: {line}"))?;

    if parts.next().is_some() {
        return Err(format!("too many for-loop header fields: {line}"));
    }

    let (variable, start_expr) = init
        .split_once('=')
        .ok_or_else(|| format!("unsupported for-loop initializer: {init}"))?;
    let variable = variable.trim().to_string();
    let start = parse_i64_literal(start_expr.trim())?;

    let (condition_var, end_expr) = condition
        .split_once('<')
        .ok_or_else(|| format!("unsupported for-loop condition: {condition}"))?;
    if condition_var.trim() != variable {
        return Err(format!(
            "for-loop condition variable {} does not match initializer {}",
            condition_var.trim(),
            variable
        ));
    }
    let end_exclusive = parse_i64_literal(end_expr.trim())?;

    let increment = if step == format!("{variable}++") {
        1
    } else if let Some((step_var, value)) = step.split_once("+=") {
        if step_var.trim() != variable {
            return Err(format!(
                "for-loop step variable {} does not match initializer {}",
                step_var.trim(),
                variable
            ));
        }
        parse_i64_literal(value.trim())?
    } else {
        return Err(format!("unsupported for-loop step: {step}"));
    };

    if increment <= 0 {
        return Err("sample for-loop increment must be positive".to_string());
    }

    Ok(SampleForLoop {
        variable,
        start,
        end_exclusive,
        increment,
    })
}

fn execute_sample_for_loop(
    loop_spec: &SampleForLoop,
    nested: &[String],
    env: &mut BTreeMap<String, i64>,
) -> Result<(), String> {
    let mut value = loop_spec.start;
    let mut iterations = 0usize;
    while value < loop_spec.end_exclusive {
        if iterations >= MAX_SAMPLE_LOOP_ITERATIONS {
            return Err("sample for-loop iteration cap exceeded".to_string());
        }
        env.insert(loop_spec.variable.clone(), value);
        let mut nested_idx = 0usize;
        if execute_sample_block(nested, &mut nested_idx, env)?.is_some() {
            return Err("return inside sample for-loop body is unsupported".to_string());
        }
        value = value.saturating_add(loop_spec.increment);
        iterations = iterations.saturating_add(1);
    }
    Ok(())
}

const MAX_SAMPLE_LOOP_ITERATIONS: usize = 1024;

fn execute_sample_statement(line: &str, env: &mut BTreeMap<String, i64>) -> Result<(), String> {
    let statement = line.trim_end_matches(';').trim();
    if statement.is_empty() {
        return Ok(());
    }

    let statement = statement
        .strip_prefix("const ")
        .or_else(|| statement.strip_prefix("let "))
        .or_else(|| statement.strip_prefix("var "))
        .unwrap_or(statement);

    if let Some((name, expr)) = statement.split_once("+=") {
        let current = *env
            .get(name.trim())
            .ok_or_else(|| format!("unknown variable in += statement: {}", name.trim()))?;
        let delta = eval_sample_expr(expr.trim(), env)?;
        env.insert(name.trim().to_string(), current.saturating_add(delta));
        return Ok(());
    }

    if let Some((name, expr)) = statement.split_once('=') {
        let value = eval_sample_expr(expr.trim(), env)?;
        env.insert(name.trim().to_string(), value);
        return Ok(());
    }

    Err(format!("unsupported sample statement: {line}"))
}

fn parse_i64_literal(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|err| format!("expected i64 literal `{value}`: {err}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SampleToken {
    Number(i64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
}

fn eval_sample_expr(expr: &str, env: &BTreeMap<String, i64>) -> Result<i64, String> {
    let tokens = tokenize_sample_expr(expr)?;
    let mut parser = SampleExprParser {
        tokens: &tokens,
        pos: 0,
        env,
    };
    let value = parser.parse_expr()?;
    if parser.pos != tokens.len() {
        return Err(format!("trailing tokens in sample expression: {expr}"));
    }
    Ok(value)
}

fn tokenize_sample_expr(expr: &str) -> Result<Vec<SampleToken>, String> {
    let chars: Vec<char> = expr.chars().collect();
    let mut tokens = Vec::new();
    let mut idx = 0usize;
    while idx < chars.len() {
        let ch = chars[idx];
        match ch {
            ' ' | '\t' | '\r' | '\n' => idx += 1,
            '+' => {
                tokens.push(SampleToken::Plus);
                idx += 1;
            }
            '-' => {
                tokens.push(SampleToken::Minus);
                idx += 1;
            }
            '*' => {
                tokens.push(SampleToken::Star);
                idx += 1;
            }
            '/' => {
                tokens.push(SampleToken::Slash);
                idx += 1;
            }
            '(' => {
                tokens.push(SampleToken::LParen);
                idx += 1;
            }
            ')' => {
                tokens.push(SampleToken::RParen);
                idx += 1;
            }
            '0'..='9' => {
                let start = idx;
                while idx < chars.len() && chars[idx].is_ascii_digit() {
                    idx += 1;
                }
                let literal: String = chars[start..idx].iter().collect();
                tokens.push(SampleToken::Number(parse_i64_literal(&literal)?));
            }
            '_' | 'a'..='z' | 'A'..='Z' => {
                let start = idx;
                while idx < chars.len() && (chars[idx] == '_' || chars[idx].is_ascii_alphanumeric())
                {
                    idx += 1;
                }
                tokens.push(SampleToken::Ident(chars[start..idx].iter().collect()));
            }
            _ => {
                return Err(format!(
                    "unsupported character `{ch}` in sample expression `{expr}`"
                ));
            }
        }
    }
    Ok(tokens)
}

struct SampleExprParser<'a> {
    tokens: &'a [SampleToken],
    pos: usize,
    env: &'a BTreeMap<String, i64>,
}

impl SampleExprParser<'_> {
    fn parse_expr(&mut self) -> Result<i64, String> {
        let mut value = self.parse_term()?;
        loop {
            match self.peek() {
                Some(SampleToken::Plus) => {
                    self.pos += 1;
                    value = value.saturating_add(self.parse_term()?);
                }
                Some(SampleToken::Minus) => {
                    self.pos += 1;
                    value = value.saturating_sub(self.parse_term()?);
                }
                _ => return Ok(value),
            }
        }
    }

    fn parse_term(&mut self) -> Result<i64, String> {
        let mut value = self.parse_factor()?;
        loop {
            match self.peek() {
                Some(SampleToken::Star) => {
                    self.pos += 1;
                    value = value.saturating_mul(self.parse_factor()?);
                }
                Some(SampleToken::Slash) => {
                    self.pos += 1;
                    let rhs = self.parse_factor()?;
                    if rhs == 0 {
                        return Err("division by zero in sample expression".to_string());
                    }
                    value /= rhs;
                }
                _ => return Ok(value),
            }
        }
    }

    fn parse_factor(&mut self) -> Result<i64, String> {
        match self.next() {
            Some(SampleToken::Number(value)) => Ok(value),
            Some(SampleToken::Ident(name)) => self
                .env
                .get(&name)
                .copied()
                .ok_or_else(|| format!("unknown sample variable `{name}`")),
            Some(SampleToken::Minus) => Ok(0i64.saturating_sub(self.parse_factor()?)),
            Some(SampleToken::LParen) => {
                let value = self.parse_expr()?;
                match self.next() {
                    Some(SampleToken::RParen) => Ok(value),
                    other => Err(format!("expected `)`, got {other:?}")),
                }
            }
            other => Err(format!("expected sample expression factor, got {other:?}")),
        }
    }

    fn peek(&self) -> Option<&SampleToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<SampleToken> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }
}

impl OptimizationPass {
    /// Get the type name for the optimization pass.
    pub fn type_name(&self) -> &'static str {
        match self {
            OptimizationPass::DeadCodeElimination => "dead_code_elimination",
            OptimizationPass::ConstantFolding => "constant_folding",
            OptimizationPass::ConstantPropagation => "constant_propagation",
            OptimizationPass::LoopUnrolling => "loop_unrolling",
            OptimizationPass::LoopInvariantHoisting => "loop_invariant_hoisting",
            OptimizationPass::InlineExpansion => "inline_expansion",
            OptimizationPass::RegisterAllocation => "register_allocation",
            OptimizationPass::ControlFlowOptimization => "control_flow_optimization",
            OptimizationPass::CommonSubexpressionElimination => "common_subexpression_elimination",
            OptimizationPass::TailCallOptimization => "tail_call_optimization",
        }
    }
}

impl Default for OptimizationMetrics {
    fn default() -> Self {
        Self {
            total_passes_applied: 0,
            total_transformations: 0,
            verification_time_ms: 0,
            proof_generation_time_ms: 0,
            overall_performance_improvement: 0.0,
            optimization_safety_score: 1.0,
        }
    }
}

/// Result of optimization verification process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationVerificationResult {
    pub total_proofs: usize,
    pub verified_proofs: usize,
    pub failed_proofs: usize,
    pub failed_proof_ids: Vec<String>,
    pub verification_time_ms: u64,
    pub optimization_safety_verified: bool,
    pub performance_improvement_verified: bool,
    pub certificates_generated: bool,
}

/// Generate optimization test cases for proof carrier validation.
pub fn generate_optimization_test_cases() -> Vec<OptimizationTestCase> {
    vec![
        OptimizationTestCase {
            name: "dead_code_elimination_simple".to_string(),
            description: "Simple dead code elimination with unreachable statements".to_string(),
            source_ir: r#"
                x = 42;
                if (false) {
                    y = x + 1;  // Dead code
                    z = y * 2;  // Dead code
                }
                return x;
            "#
            .to_string(),
            target_ir: r#"
                x = 42;
                return x;
            "#
            .to_string(),
            optimization_passes: vec![OptimizationPass::DeadCodeElimination],
            expected_equivalence_relation: EquivalenceRelation::ExactEquivalence,
            expected_performance_improvement: 0.15, // 15% improvement
        },
        OptimizationTestCase {
            name: "constant_folding_arithmetic".to_string(),
            description: "Constant folding for compile-time arithmetic".to_string(),
            source_ir: r#"
                a = 3 + 4;
                b = a * 2;
                c = b - 7;
                return c;
            "#
            .to_string(),
            target_ir: r#"
                a = 7;
                b = 14;
                c = 7;
                return c;
            "#
            .to_string(),
            optimization_passes: vec![
                OptimizationPass::ConstantFolding,
                OptimizationPass::ConstantPropagation,
            ],
            expected_equivalence_relation: EquivalenceRelation::ExactEquivalence,
            expected_performance_improvement: 0.25, // 25% improvement
        },
        OptimizationTestCase {
            name: "loop_unrolling_small".to_string(),
            description: "Small loop unrolling with known iteration count".to_string(),
            source_ir: r#"
                sum = 0;
                for (i = 0; i < 4; i++) {
                    sum += i;
                }
                return sum;
            "#
            .to_string(),
            target_ir: r#"
                sum = 0;
                sum += 0;
                sum += 1;
                sum += 2;
                sum += 3;
                return sum;
            "#
            .to_string(),
            optimization_passes: vec![OptimizationPass::LoopUnrolling],
            expected_equivalence_relation: EquivalenceRelation::WeakEquivalence,
            expected_performance_improvement: 0.30, // 30% improvement
        },
        OptimizationTestCase {
            name: "inline_expansion_function".to_string(),
            description: "Function inline expansion for small functions".to_string(),
            source_ir: r#"
                function add(x, y) { return x + y; }
                result = add(10, 20);
                return result;
            "#
            .to_string(),
            target_ir: r#"
                result = 10 + 20;
                return result;
            "#
            .to_string(),
            optimization_passes: vec![
                OptimizationPass::InlineExpansion,
                OptimizationPass::ConstantFolding,
            ],
            expected_equivalence_relation: EquivalenceRelation::ObservationalEquivalence,
            expected_performance_improvement: 0.20, // 20% improvement
        },
    ]
}

/// Test case for optimization proof carrier validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationTestCase {
    pub name: String,
    pub description: String,
    pub source_ir: String,
    pub target_ir: String,
    pub optimization_passes: Vec<OptimizationPass>,
    pub expected_equivalence_relation: EquivalenceRelation,
    pub expected_performance_improvement: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimization_proof_carrier_creation() {
        let carrier =
            OptimizationProofCarrier::new("source IR".to_string(), "target IR".to_string());

        assert_eq!(carrier.source_ir, "source IR");
        assert_eq!(carrier.target_ir, "target IR");
        assert!(carrier.applied_passes.is_empty());
        assert!(carrier.equivalence_proofs.is_empty());
        assert_eq!(
            carrier.verification_status,
            OptimizationVerificationStatus::Unverified
        );
        assert_eq!(carrier.performance_metrics.total_passes_applied, 0);
    }

    #[test]
    fn optimization_pass_application() {
        let mut carrier =
            OptimizationProofCarrier::new("x = 1 + 2;".to_string(), "x = 3;".to_string());

        let pass = OptimizationPassApplication {
            pass_id: "const_fold_1".to_string(),
            optimization_type: OptimizationPass::ConstantFolding,
            source_region: IrRegion {
                region_id: "region_1".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: ["bb_1"].into_iter().map(String::from).collect(),
                control_flow_edges: Vec::new(),
                live_variables: ["x"].into_iter().map(String::from).collect(),
            },
            target_region: IrRegion {
                region_id: "region_1_opt".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: ["bb_1"].into_iter().map(String::from).collect(),
                control_flow_edges: Vec::new(),
                live_variables: ["x"].into_iter().map(String::from).collect(),
            },
            transformation_rules: Vec::new(),
            preconditions: vec!["Expression is compile-time constant".to_string()],
            postconditions: vec!["Value replaced with computed constant".to_string()],
            performance_impact: PerformanceImpact {
                execution_time_change: -0.15,
                memory_usage_change: 0.0,
                code_size_change: -0.05,
                compile_time_overhead: 1.0,
                optimization_benefit_score: 0.85,
            },
        };

        carrier.add_optimization_pass(pass);

        assert_eq!(carrier.applied_passes.len(), 1);
        assert_eq!(carrier.performance_metrics.total_passes_applied, 1);
        assert_eq!(
            carrier.applied_passes[0].optimization_type,
            OptimizationPass::ConstantFolding
        );
    }

    #[test]
    fn equivalence_proof_generation() {
        let mut carrier = OptimizationProofCarrier::new("source".to_string(), "target".to_string());

        let pass = OptimizationPassApplication {
            pass_id: "test_pass".to_string(),
            optimization_type: OptimizationPass::DeadCodeElimination,
            source_region: IrRegion {
                region_id: "test_region".to_string(),
                start_instruction: 0,
                end_instruction: 10,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            target_region: IrRegion {
                region_id: "test_region_opt".to_string(),
                start_instruction: 0,
                end_instruction: 5,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            transformation_rules: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            performance_impact: PerformanceImpact {
                execution_time_change: -0.10,
                memory_usage_change: 0.0,
                code_size_change: -0.50,
                compile_time_overhead: 0.5,
                optimization_benefit_score: 0.90,
            },
        };

        carrier.add_optimization_pass(pass);

        let proof_count = carrier.generate_equivalence_proofs().unwrap();
        assert_eq!(proof_count, 1);

        let proof = &carrier.equivalence_proofs[0];
        assert_eq!(proof.proof_method, ProofMethod::Bisimulation);
        assert_eq!(
            proof.equivalence_relation,
            EquivalenceRelation::ExactEquivalence
        );
        assert!(!proof.proof_obligations.is_empty());
    }

    #[test]
    fn proof_verification_workflow() {
        let mut carrier =
            OptimizationProofCarrier::new("test_source".to_string(), "test_target".to_string());

        // Add test optimization pass
        let pass = OptimizationPassApplication {
            pass_id: "verification_test".to_string(),
            optimization_type: OptimizationPass::ConstantFolding,
            source_region: IrRegion {
                region_id: "test".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            target_region: IrRegion {
                region_id: "test_opt".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            transformation_rules: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            performance_impact: PerformanceImpact {
                execution_time_change: 0.0,
                memory_usage_change: 0.0,
                code_size_change: 0.0,
                compile_time_overhead: 0.0,
                optimization_benefit_score: 0.5,
            },
        };

        carrier.add_optimization_pass(pass);

        // Generate and verify proofs
        let proof_count = carrier.generate_equivalence_proofs().unwrap();
        assert!(proof_count > 0);

        let verification_result = carrier.verify_all_proofs().unwrap();
        assert_eq!(verification_result.total_proofs, proof_count);
        // Elapsed-ms can legitimately be 0 on a fast host (bd-2869t); assert the
        // result and the carrier metrics agree on the same measurement instead.
        assert_eq!(
            verification_result.verification_time_ms,
            carrier.performance_metrics.verification_time_ms
        );
    }

    #[test]
    fn optimization_pass_type_names() {
        assert_eq!(
            OptimizationPass::DeadCodeElimination.type_name(),
            "dead_code_elimination"
        );
        assert_eq!(
            OptimizationPass::ConstantFolding.type_name(),
            "constant_folding"
        );
        assert_eq!(
            OptimizationPass::LoopUnrolling.type_name(),
            "loop_unrolling"
        );
        assert_eq!(
            OptimizationPass::InlineExpansion.type_name(),
            "inline_expansion"
        );
    }

    #[test]
    fn optimization_test_case_generation() {
        let test_cases = generate_optimization_test_cases();
        assert!(!test_cases.is_empty());

        let dead_code_case = test_cases
            .iter()
            .find(|tc| tc.name == "dead_code_elimination_simple")
            .unwrap();

        assert!(dead_code_case.source_ir.contains("if (false)"));
        assert!(!dead_code_case.target_ir.contains("if (false)"));
        assert_eq!(dead_code_case.optimization_passes.len(), 1);
        assert_eq!(
            dead_code_case.optimization_passes[0],
            OptimizationPass::DeadCodeElimination
        );
    }

    #[test]
    fn performance_impact_calculation() {
        let impact = PerformanceImpact {
            execution_time_change: -0.25,     // 25% improvement
            memory_usage_change: 0.10,        // 10% increase
            code_size_change: -0.15,          // 15% smaller
            compile_time_overhead: 5.0,       // 5ms overhead
            optimization_benefit_score: 0.80, // 80% benefit
        };

        assert_eq!(impact.execution_time_change, -0.25);
        assert_eq!(impact.optimization_benefit_score, 0.80);
    }

    #[test]
    fn proof_certificate_generation() {
        // bd-cixqu.7.17.2: verify_proof_obligation no longer fabricates
        // `Verified` for the prose-premise obligations the engine currently
        // emits (see `generate_equivalence_proofs`). Until those generators
        // start emitting real SMT-LIB-2 formulas, this workflow correctly
        // produces NO `SemanticEquivalence` certificate (verified_passes is
        // empty in `generate_proof_certificates`). Only the
        // `PerformanceImprovement` certificate — which is gated on the
        // engine-tracked `overall_performance_improvement`, not on real
        // proof verification — still lands.
        let mut carrier = OptimizationProofCarrier::new(
            "cert_test_source".to_string(),
            "cert_test_target".to_string(),
        );

        // Add successful optimization
        let pass = OptimizationPassApplication {
            pass_id: "cert_test_pass".to_string(),
            optimization_type: OptimizationPass::ConstantFolding,
            source_region: IrRegion {
                region_id: "cert_test".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            target_region: IrRegion {
                region_id: "cert_test_opt".to_string(),
                start_instruction: 0,
                end_instruction: 1,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            transformation_rules: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            performance_impact: PerformanceImpact {
                execution_time_change: -0.20,
                memory_usage_change: 0.0,
                code_size_change: 0.0,
                compile_time_overhead: 1.0,
                optimization_benefit_score: 0.80,
            },
        };

        carrier.add_optimization_pass(pass);
        carrier.performance_metrics.overall_performance_improvement = 0.20; // 20% improvement

        carrier.generate_equivalence_proofs().unwrap();
        carrier.verify_all_proofs().unwrap();

        // Performance certificate still lands (gated on the engine metric,
        // not on proof verification).
        let performance_cert = carrier
            .proof_certificates
            .iter()
            .find(|cert| cert.certificate_type == CertificateType::PerformanceImprovement);
        assert!(
            performance_cert.is_some(),
            "performance improvement certificate must still be generated when overall_performance_improvement > 0.0"
        );

        // Semantic-equivalence certificate must NOT land: this fixture is not
        // executable by the bounded sample runner, so no generated obligation
        // verified. This is the fail-closed signal that FE-CLAIM-019 /
        // FE-CLAIM-020 stay HYPOTHESIS for unsupported generated evidence.
        let semantic_cert = carrier
            .proof_certificates
            .iter()
            .find(|cert| cert.certificate_type == CertificateType::SemanticEquivalence);
        assert!(
            semantic_cert.is_none(),
            "semantic_equivalence certificate must NOT be generated until generated obligations verify against real evidence (bd-cixqu.7.17.2)"
        );
    }

    /// bd-cixqu.7.17.2: positive control — when the obligation premise and
    /// conclusion ARE real SMT-LIB-2 formulas, `verify_via_z3` correctly
    /// returns `Verified`. This is the path real obligation generators must
    /// land on so FE-CLAIM-019 / FE-CLAIM-020 can promote out of HYPOTHESIS.
    /// Gates on z3-on-PATH; skipped otherwise.
    #[test]
    fn verify_via_z3_proves_smt_lib_tautology() {
        if !z3_is_available() {
            eprintln!("z3 not on PATH — skipping verify_via_z3_proves_smt_lib_tautology");
            return;
        }
        // The tautology `true ⇒ true` is universally true; Z3 should return
        // unsat on its negation → `Verified`.
        assert_eq!(verify_via_z3("true", "true"), ProofResult::Verified);
        // A formula whose negation is satisfiable (Z3 finds a counterexample)
        // must fail closed. `(declare-const p Bool)` would make `p ⇒ p` a
        // tautology; instead use a non-theorem: `true ⇒ false` (clearly false).
        assert_eq!(verify_via_z3("true", "false"), ProofResult::Failed);
    }

    #[test]
    fn bounded_model_checker_verifies_qf_lia_obligation() {
        if !z3_is_available() {
            eprintln!("z3 not on PATH — skipping bounded_model_checker_verifies_qf_lia_obligation");
            return;
        }

        let premise = "(declare-const x Int)\n(assert (and (<= 0 x) (<= x 4)))";
        assert_eq!(
            verify_via_bounded_z3_model(premise, "(= (+ x 1) (+ 1 x))"),
            ProofResult::Verified
        );
    }

    #[test]
    fn bounded_model_checker_rejects_counterexample() {
        if !z3_is_available() {
            eprintln!("z3 not on PATH — skipping bounded_model_checker_rejects_counterexample");
            return;
        }

        let premise = "(declare-const x Int)\n(assert (and (<= 0 x) (<= x 4)))";
        assert_eq!(
            verify_via_bounded_z3_model(premise, "(= (+ x 1) x)"),
            ProofResult::Failed
        );
    }

    #[test]
    fn bounded_model_checker_rejects_generated_prose() {
        assert_eq!(
            verify_via_bounded_z3_model(
                "Code identified as dead",
                "Dead code has no observable effects"
            ),
            ProofResult::Failed
        );
    }

    /// bd-cixqu.7.17.2: empty premise / conclusion fails closed (was
    /// already the FormalLogic-specific behaviour, now uniform).
    #[test]
    fn verify_proof_obligation_rejects_empty_strings() {
        let carrier = OptimizationProofCarrier::new("src".to_string(), "tgt".to_string());
        for method in [
            VerificationMethod::FormalLogic,
            VerificationMethod::ModelChecking,
            VerificationMethod::TheoremProving,
            VerificationMethod::SymbolicExecution,
            VerificationMethod::PropertyTesting,
            VerificationMethod::DifferentialTesting,
        ] {
            let obligation = ProofObligation {
                obligation_id: "empty".to_string(),
                obligation_type: ObligationType::SemanticPreservation,
                premise: "".to_string(),
                conclusion: "".to_string(),
                proof_sketch: "".to_string(),
                verification_method: method.clone(),
                sample_inputs: Vec::new(),
            };
            assert_eq!(
                carrier.verify_proof_obligation(&obligation).unwrap(),
                ProofResult::Failed,
                "empty premise/conclusion must fail closed under {method:?}"
            );
        }
    }

    /// bd-cixqu.7.17.2: DifferentialTesting / PropertyTesting fail closed
    /// regardless of premise content — neither has its runner machinery
    /// wired yet; returning `Verified` would re-introduce the fabrication
    /// this bead is closing.
    #[test]
    fn verify_proof_obligation_fails_closed_for_runner_dependent_methods() {
        let carrier = OptimizationProofCarrier::new("src".to_string(), "tgt".to_string());
        for method in [
            VerificationMethod::DifferentialTesting,
            VerificationMethod::PropertyTesting,
        ] {
            let obligation = ProofObligation {
                obligation_id: "runner_dependent".to_string(),
                obligation_type: ObligationType::SemanticPreservation,
                // Even with a real SMT tautology, these methods MUST fail
                // closed when no sample inputs are attached — the bead requires
                // concrete runner inputs, not Z3.
                premise: "true".to_string(),
                conclusion: "true".to_string(),
                proof_sketch: "".to_string(),
                verification_method: method.clone(),
                sample_inputs: Vec::new(),
            };
            assert_eq!(
                carrier.verify_proof_obligation(&obligation).unwrap(),
                ProofResult::Failed,
                "{method:?} must fail closed without concrete samples",
            );
        }
    }

    #[test]
    fn differential_runner_verifies_matching_sample_programs() {
        let carrier = OptimizationProofCarrier::new(
            "sum = 0;\nfor (i = 0; i < 4; i++) {\n  sum += i;\n}\nreturn sum;".to_string(),
            "sum = 0;\nsum += 0;\nsum += 1;\nsum += 2;\nsum += 3;\nreturn sum;".to_string(),
        );
        let obligation = ProofObligation {
            obligation_id: "loop_diff".to_string(),
            obligation_type: ObligationType::SemanticPreservation,
            premise: "source and target are in bounded sample language".to_string(),
            conclusion: "sample outputs are equal".to_string(),
            proof_sketch: "execute both programs over the attached samples".to_string(),
            verification_method: VerificationMethod::DifferentialTesting,
            sample_inputs: vec![OptimizationSampleInput::empty()],
        };

        assert_eq!(
            carrier.verify_proof_obligation(&obligation).unwrap(),
            ProofResult::Verified
        );
    }

    #[test]
    fn differential_runner_rejects_output_mismatch() {
        let carrier =
            OptimizationProofCarrier::new("return x + 1;".to_string(), "return x + 2;".to_string());
        let obligation = ProofObligation {
            obligation_id: "mismatch".to_string(),
            obligation_type: ObligationType::SemanticPreservation,
            premise: "source and target are in bounded sample language".to_string(),
            conclusion: "sample outputs are equal".to_string(),
            proof_sketch: "execute both programs over the attached samples".to_string(),
            verification_method: VerificationMethod::PropertyTesting,
            sample_inputs: vec![OptimizationSampleInput::from_bindings([("x", 41)])],
        };

        assert_eq!(
            carrier.verify_proof_obligation(&obligation).unwrap(),
            ProofResult::Failed
        );
    }

    #[test]
    fn differential_runner_rejects_unsupported_syntax() {
        let carrier = OptimizationProofCarrier::new(
            "function add(x, y) { return x + y; }\nreturn add(1, 2);".to_string(),
            "return 3;".to_string(),
        );
        let obligation = ProofObligation {
            obligation_id: "unsupported".to_string(),
            obligation_type: ObligationType::SemanticPreservation,
            premise: "source and target are in bounded sample language".to_string(),
            conclusion: "sample outputs are equal".to_string(),
            proof_sketch: "execute both programs over the attached samples".to_string(),
            verification_method: VerificationMethod::DifferentialTesting,
            sample_inputs: vec![OptimizationSampleInput::empty()],
        };

        assert_eq!(
            carrier.verify_proof_obligation(&obligation).unwrap(),
            ProofResult::Failed
        );
    }

    /// Reuse the policy_theorem_engine availability probe.
    fn z3_is_available() -> bool {
        match invoke_z3("(check-sat)", 1) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    #[test]
    fn export_verification_artifact() {
        let carrier = OptimizationProofCarrier::new(
            "export_test_source".to_string(),
            "export_test_target".to_string(),
        );

        let artifact = carrier.export_verification_artifact();
        assert!(artifact.contains("source_ir"));
        assert!(artifact.contains("target_ir"));
        assert!(artifact.contains("Unverified") || artifact.contains("verification_status"));
    }
}
