#![forbid(unsafe_code)]

//! Statement and control flow translation validation for FrankenEngine.
//!
//! This module extends the G.4 pure expression translation validation to cover
//! statements (assignments, declarations, if/while/for) and the control-flow
//! normalization that IR2 performs.
//!
//! SSA-ish forms make equivalence non-trivial; phi-node merging needs explicit
//! lemmas to prove semantic preservation across IR transformations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ir_contract::{Ir1Op, Ir2Op, Ir3Instruction};

/// Statement types supported in translation validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StatementKind {
    Assignment,
    Declaration,
    IfStatement,
    WhileLoop,
    ForLoop,
    Block,
    Return,
    Break,
    Continue,
}

/// Control flow graph node for validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowNode {
    pub id: u32,
    pub statement_kind: StatementKind,
    pub predecessors: BTreeSet<u32>,
    pub successors: BTreeSet<u32>,
    pub phi_nodes: Vec<PhiNode>,
}

/// Phi node for SSA form translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhiNode {
    pub target_variable: String,
    pub incoming_values: BTreeMap<u32, String>, // predecessor_id -> variable_name
}

/// Translation validation context for statements and control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementValidationContext {
    pub source_cfg: BTreeMap<u32, ControlFlowNode>,
    pub target_cfg: BTreeMap<u32, ControlFlowNode>,
    pub variable_mapping: BTreeMap<String, String>,
    pub validation_lemmas: Vec<ValidationLemma>,
}

/// Validation lemma for proving statement equivalence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationLemma {
    pub lemma_id: String,
    pub lemma_type: LemmaType,
    pub source_nodes: BTreeSet<u32>,
    pub target_nodes: BTreeSet<u32>,
    pub invariant: String,
    pub proof_obligations: Vec<ProofObligation>,
}

/// Types of validation lemmas for statement translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemmaType {
    PhiNodeMerging,
    ControlFlowPreservation,
    VariableLifetime,
    LoopInvariant,
    ConditionalEquivalence,
}

/// Proof obligation for lemma verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofObligation {
    pub obligation_id: String,
    pub premise: String,
    pub conclusion: String,
    pub verification_method: VerificationMethod,
}

/// Methods for verifying proof obligations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    LeanFormal,
    SymbolicExecution,
    ModelChecking,
    DifferentialTesting,
}

impl VerificationMethod {
    /// Whether a real backend runner for this method is currently wired into
    /// the validator. When this returns `false`, [`StatementValidationContext::
    /// verify_proof_obligation`] (and the equivalent path in
    /// `full_ir_translation_validator`) returns `true` as a placeholder — the
    /// `true` is a *rubber stamp*, not a real discharge. The proof-bundle and
    /// matrix-promotion machinery (bd-cixqu.7 Track G / FE-CLAIM-016..021)
    /// should consult this helper before claiming any obligation verified by
    /// these methods has been formally discharged. Tracked under bd-1lw7r.8;
    /// the parallel optimization_proof_carriers path already routes
    /// `Z3`-discharged methods through `invoke_z3` (bd-cixqu.7.17 /
    /// bd-cixqu.7.17.1) and fail-closes the runner-dependent ones.
    pub fn is_runner_wired(&self) -> bool {
        match self {
            // LeanFormal only does a non-empty-string check in
            // `verify_proof_obligation` — that's structural well-formedness,
            // not a Lean 4 proof discharge. Until the Lean runner is wired
            // (bd-cixqu.7.17.3 / bd-cixqu.7.17), treat as unwired.
            VerificationMethod::LeanFormal => false,
            // The remaining three methods unconditionally return `true` in
            // the current validator. They need: symbolic-execution engine,
            // model-checker (TLA+ / Spin / Z3), and a differential-testing
            // runner respectively.
            VerificationMethod::SymbolicExecution => false,
            VerificationMethod::ModelChecking => false,
            VerificationMethod::DifferentialTesting => false,
        }
    }
}

/// Result of statement translation validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementValidationResult {
    pub validation_successful: bool,
    pub verified_lemmas: usize,
    pub failed_lemmas: Vec<String>,
    pub semantic_equivalence_proven: bool,
    pub control_flow_preservation_proven: bool,
    pub phi_node_correctness_proven: bool,
}

impl StatementValidationContext {
    /// Create a new validation context for statement translation.
    pub fn new() -> Self {
        Self {
            source_cfg: BTreeMap::new(),
            target_cfg: BTreeMap::new(),
            variable_mapping: BTreeMap::new(),
            validation_lemmas: Vec::new(),
        }
    }

    /// Add a control flow node to the source CFG.
    pub fn add_source_node(&mut self, node: ControlFlowNode) {
        self.source_cfg.insert(node.id, node);
    }

    /// Add a control flow node to the target CFG.
    pub fn add_target_node(&mut self, node: ControlFlowNode) {
        self.target_cfg.insert(node.id, node);
    }

    /// Add a variable mapping between source and target.
    pub fn add_variable_mapping(&mut self, source_var: String, target_var: String) {
        self.variable_mapping.insert(source_var, target_var);
    }

    /// Generate phi node merging lemmas for SSA form validation.
    pub fn generate_phi_node_lemmas(&mut self) -> Result<usize, String> {
        let mut lemma_count = 0;

        for (node_id, target_node) in &self.target_cfg {
            for phi_node in &target_node.phi_nodes {
                let lemma_id = format!("phi_merge_{}_{}", node_id, phi_node.target_variable);

                let proof_obligations = vec![
                    ProofObligation {
                        obligation_id: format!("{}_determinism", lemma_id),
                        premise: "All incoming values are well-defined".to_string(),
                        conclusion: "Phi node produces unique value".to_string(),
                        verification_method: VerificationMethod::LeanFormal,
                    },
                    ProofObligation {
                        obligation_id: format!("{}_equivalence", lemma_id),
                        premise: "Source control flow semantics".to_string(),
                        conclusion: "Target phi semantics equivalent".to_string(),
                        verification_method: VerificationMethod::SymbolicExecution,
                    },
                ];

                let lemma = ValidationLemma {
                    lemma_id,
                    lemma_type: LemmaType::PhiNodeMerging,
                    source_nodes: phi_node.incoming_values.keys().copied().collect(),
                    target_nodes: [*node_id].into_iter().collect(),
                    invariant: format!(
                        "Phi node for {} preserves semantic equivalence",
                        phi_node.target_variable
                    ),
                    proof_obligations,
                };

                self.validation_lemmas.push(lemma);
                lemma_count += 1;
            }
        }

        Ok(lemma_count)
    }

    /// Generate control flow preservation lemmas.
    pub fn generate_control_flow_lemmas(&mut self) -> Result<usize, String> {
        let mut lemma_count = 0;

        for (source_id, source_node) in &self.source_cfg {
            if let Some(target_node) = self.target_cfg.get(source_id) {
                if source_node.statement_kind != target_node.statement_kind {
                    continue; // Statement type changes need specialized handling
                }

                let lemma_id = format!("control_flow_{}", source_id);

                let proof_obligations = vec![
                    ProofObligation {
                        obligation_id: format!("{}_successor_preservation", lemma_id),
                        premise: "Source successors well-formed".to_string(),
                        conclusion: "Target successors semantically equivalent".to_string(),
                        verification_method: VerificationMethod::ModelChecking,
                    },
                    ProofObligation {
                        obligation_id: format!("{}_predecessor_preservation", lemma_id),
                        premise: "Source predecessors well-formed".to_string(),
                        conclusion: "Target predecessors semantically equivalent".to_string(),
                        verification_method: VerificationMethod::ModelChecking,
                    },
                ];

                let lemma = ValidationLemma {
                    lemma_id,
                    lemma_type: LemmaType::ControlFlowPreservation,
                    source_nodes: [*source_id].into_iter().collect(),
                    target_nodes: [*source_id].into_iter().collect(),
                    invariant: format!(
                        "Control flow for {:?} statement preserves semantics",
                        source_node.statement_kind
                    ),
                    proof_obligations,
                };

                self.validation_lemmas.push(lemma);
                lemma_count += 1;
            }
        }

        Ok(lemma_count)
    }

    /// Validate all generated lemmas using specified verification methods.
    pub fn validate_lemmas(&self) -> StatementValidationResult {
        let total_lemmas = self.validation_lemmas.len();
        let mut verified_lemmas = 0;
        let mut failed_lemmas = Vec::new();

        for lemma in &self.validation_lemmas {
            let mut lemma_verified = true;

            for obligation in &lemma.proof_obligations {
                // In a real implementation, this would invoke actual verification tools
                let verification_result = self.verify_proof_obligation(obligation);

                if !verification_result {
                    lemma_verified = false;
                    break;
                }
            }

            if lemma_verified {
                verified_lemmas += 1;
            } else {
                failed_lemmas.push(lemma.lemma_id.clone());
            }
        }

        let phi_node_lemmas_verified = self
            .validation_lemmas
            .iter()
            .filter(|l| l.lemma_type == LemmaType::PhiNodeMerging)
            .all(|l| !failed_lemmas.contains(&l.lemma_id));

        let control_flow_lemmas_verified = self
            .validation_lemmas
            .iter()
            .filter(|l| l.lemma_type == LemmaType::ControlFlowPreservation)
            .all(|l| !failed_lemmas.contains(&l.lemma_id));

        StatementValidationResult {
            validation_successful: failed_lemmas.is_empty(),
            verified_lemmas,
            failed_lemmas,
            semantic_equivalence_proven: verified_lemmas == total_lemmas,
            control_flow_preservation_proven: control_flow_lemmas_verified,
            phi_node_correctness_proven: phi_node_lemmas_verified,
        }
    }

    /// Verify a single proof obligation.
    ///
    /// **bd-1lw7r.8 honesty note**: the current implementation does NOT
    /// discharge runner-dependent obligations. `LeanFormal` only checks the
    /// premise/conclusion strings are non-empty (structural well-formedness),
    /// and the other three methods unconditionally return `true`. A `true`
    /// return from this function therefore means "structurally well-formed
    /// *or* rubber-stamped" — not "formally verified". Use
    /// [`VerificationMethod::is_runner_wired`] to filter results that depend
    /// on a real backend before reporting them as proven.
    ///
    /// The matching path in `optimization_proof_carriers::verify_proof_obligation`
    /// already routes `Z3`-discharged methods through `invoke_z3` and
    /// fail-closes the runner-dependent ones (bd-cixqu.7.17,
    /// bd-cixqu.7.17.1); the statement-level validator here is queued for the
    /// equivalent treatment under bd-1lw7r.8.
    fn verify_proof_obligation(&self, obligation: &ProofObligation) -> bool {
        match obligation.verification_method {
            VerificationMethod::LeanFormal => {
                // FIXME (bd-1lw7r.8): rubber-stamp until the Lean 4 runner
                // is wired (bd-cixqu.7.17.3). This is *structural*
                // well-formedness, not a Lean proof discharge — do not
                // interpret a `true` here as a verified obligation.
                !obligation.premise.is_empty() && !obligation.conclusion.is_empty()
            }
            VerificationMethod::SymbolicExecution => {
                // FIXME (bd-1lw7r.8): rubber-stamp until a symbolic-execution
                // engine is wired. `is_runner_wired()` returns false for this
                // method so downstream proof-bundle emitters can detect.
                true
            }
            VerificationMethod::ModelChecking => {
                // FIXME (bd-1lw7r.8): rubber-stamp until a model checker
                // (TLA+ / Spin / Z3) is wired. The Z3 route already exists in
                // `optimization_proof_carriers::verify_proof_obligation`
                // (bd-cixqu.7.17.1); the statement validator should route
                // here when the integration is generalised.
                true
            }
            VerificationMethod::DifferentialTesting => {
                // FIXME (bd-1lw7r.8): rubber-stamp until a differential
                // tester is wired. `optimization_proof_carriers` fail-closes
                // this method explicitly (`Ok(ProofResult::Failed)`); the
                // equivalent fail-close in the statement validator awaits a
                // companion downstream-test sweep.
                true
            }
        }
    }
}

#[cfg(test)]
mod verification_method_wired_tests {
    use super::VerificationMethod;

    // bd-1lw7r.8: every variant must currently report itself as NOT wired.
    // When a real runner lands for any method, flip its arm in
    // `VerificationMethod::is_runner_wired` AND update this test to assert
    // `true` for that variant. The assertion order matches the enum order
    // above so a future addition to the enum forces a deliberate decision.

    #[test]
    fn lean_formal_is_not_runner_wired() {
        assert!(!VerificationMethod::LeanFormal.is_runner_wired());
    }

    #[test]
    fn symbolic_execution_is_not_runner_wired() {
        assert!(!VerificationMethod::SymbolicExecution.is_runner_wired());
    }

    #[test]
    fn model_checking_is_not_runner_wired() {
        assert!(!VerificationMethod::ModelChecking.is_runner_wired());
    }

    #[test]
    fn differential_testing_is_not_runner_wired() {
        assert!(!VerificationMethod::DifferentialTesting.is_runner_wired());
    }
}

impl Default for StatementValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate statement validation test cases covering control flow patterns.
pub fn generate_statement_test_cases() -> Vec<StatementTestCase> {
    vec![
        StatementTestCase {
            name: "simple_assignment".to_string(),
            source_ir: "x = 42;".to_string(),
            statement_kind: StatementKind::Assignment,
            expected_phi_nodes: 0,
            expected_control_edges: 0,
        },
        StatementTestCase {
            name: "if_statement".to_string(),
            source_ir: "if (condition) { x = 1; } else { x = 2; }".to_string(),
            statement_kind: StatementKind::IfStatement,
            expected_phi_nodes: 1,     // Phi node for x
            expected_control_edges: 3, // condition -> then, condition -> else, merge
        },
        StatementTestCase {
            name: "while_loop".to_string(),
            source_ir: "while (condition) { x = x + 1; }".to_string(),
            statement_kind: StatementKind::WhileLoop,
            expected_phi_nodes: 1,     // Phi node for loop variable
            expected_control_edges: 2, // loop header, loop back
        },
        StatementTestCase {
            name: "nested_control_flow".to_string(),
            source_ir: "if (a) { while (b) { x = x + 1; } } else { x = 0; }".to_string(),
            statement_kind: StatementKind::IfStatement,
            expected_phi_nodes: 2,     // Phi nodes for nested control flow
            expected_control_edges: 5, // Complex control flow graph
        },
    ]
}

/// Test case for statement translation validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementTestCase {
    pub name: String,
    pub source_ir: String,
    pub statement_kind: StatementKind,
    pub expected_phi_nodes: usize,
    pub expected_control_edges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_validation_context_creation() {
        let ctx = StatementValidationContext::new();
        assert!(ctx.source_cfg.is_empty());
        assert!(ctx.target_cfg.is_empty());
        assert!(ctx.validation_lemmas.is_empty());
    }

    #[test]
    fn control_flow_node_creation() {
        let node = ControlFlowNode {
            id: 1,
            statement_kind: StatementKind::Assignment,
            predecessors: BTreeSet::new(),
            successors: [2].into_iter().collect(),
            phi_nodes: Vec::new(),
        };

        assert_eq!(node.id, 1);
        assert_eq!(node.statement_kind, StatementKind::Assignment);
        assert!(node.phi_nodes.is_empty());
    }

    #[test]
    fn phi_node_generation() {
        let mut ctx = StatementValidationContext::new();

        let phi_node = PhiNode {
            target_variable: "x".to_string(),
            incoming_values: [(1, "x1".to_string()), (2, "x2".to_string())]
                .into_iter()
                .collect(),
        };

        let target_node = ControlFlowNode {
            id: 3,
            statement_kind: StatementKind::IfStatement,
            predecessors: [1, 2].into_iter().collect(),
            successors: BTreeSet::new(),
            phi_nodes: vec![phi_node],
        };

        ctx.add_target_node(target_node);

        let lemma_count = ctx.generate_phi_node_lemmas().unwrap();
        assert_eq!(lemma_count, 1);

        let lemma = &ctx.validation_lemmas[0];
        assert_eq!(lemma.lemma_type, LemmaType::PhiNodeMerging);
        assert_eq!(lemma.proof_obligations.len(), 2);
    }

    #[test]
    fn control_flow_lemma_generation() {
        let mut ctx = StatementValidationContext::new();

        let source_node = ControlFlowNode {
            id: 1,
            statement_kind: StatementKind::Assignment,
            predecessors: BTreeSet::new(),
            successors: [2].into_iter().collect(),
            phi_nodes: Vec::new(),
        };

        let target_node = ControlFlowNode {
            id: 1,
            statement_kind: StatementKind::Assignment,
            predecessors: BTreeSet::new(),
            successors: [2].into_iter().collect(),
            phi_nodes: Vec::new(),
        };

        ctx.add_source_node(source_node);
        ctx.add_target_node(target_node);

        let lemma_count = ctx.generate_control_flow_lemmas().unwrap();
        assert_eq!(lemma_count, 1);

        let lemma = &ctx.validation_lemmas[0];
        assert_eq!(lemma.lemma_type, LemmaType::ControlFlowPreservation);
    }

    #[test]
    fn statement_test_case_generation() {
        let test_cases = generate_statement_test_cases();
        assert!(!test_cases.is_empty());

        let if_case = test_cases
            .iter()
            .find(|tc| tc.name == "if_statement")
            .unwrap();
        assert_eq!(if_case.statement_kind, StatementKind::IfStatement);
        assert_eq!(if_case.expected_phi_nodes, 1);
    }

    #[test]
    fn validation_result_aggregation() {
        let mut ctx = StatementValidationContext::new();

        // Add a simple phi node to generate lemmas
        let phi_node = PhiNode {
            target_variable: "x".to_string(),
            incoming_values: [(1, "x1".to_string())].into_iter().collect(),
        };

        let target_node = ControlFlowNode {
            id: 2,
            statement_kind: StatementKind::IfStatement,
            predecessors: [1].into_iter().collect(),
            successors: BTreeSet::new(),
            phi_nodes: vec![phi_node],
        };

        ctx.add_target_node(target_node);
        ctx.generate_phi_node_lemmas().unwrap();

        let result = ctx.validate_lemmas();
        assert!(result.validation_successful);
        assert!(result.phi_node_correctness_proven);
    }
}
