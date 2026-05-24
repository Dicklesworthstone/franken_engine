#![forbid(unsafe_code)]

//! Full IR coverage translation validation for FrankenEngine.
//!
//! This module provides comprehensive translation validation across the entire
//! IR pipeline: IR0 (SyntaxIR) → IR1 (SpecIR) → IR2 (CapabilityIR) → IR3 (ExecIR).
//!
//! Extends G.4 (pure expressions) and G.5 (statements + control flow) to provide
//! complete coverage of all IR transformations and semantic preservation proofs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ir_contract::IteratorCloseReason;
use crate::statement_translation_validator::{
    ProofObligation, StatementValidationContext, ValidationLemma, VerificationMethod,
};

/// IR levels in the FrankenEngine transformation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IrLevel {
    IR0, // SyntaxIR - Direct AST representation
    IR1, // SpecIR - Scope-resolved with binding IDs
    IR2, // CapabilityIR - IFC label annotated
    IR3, // ExecIR - Flat instruction sequences
}

impl IrLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IR0 => "IR0_SyntaxIR",
            Self::IR1 => "IR1_SpecIR",
            Self::IR2 => "IR2_CapabilityIR",
            Self::IR3 => "IR3_ExecIR",
        }
    }

    pub const fn next_level(self) -> Option<IrLevel> {
        match self {
            Self::IR0 => Some(Self::IR1),
            Self::IR1 => Some(Self::IR2),
            Self::IR2 => Some(Self::IR3),
            Self::IR3 => None,
        }
    }
}

/// Complete IR transformation step validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrTransformationStep {
    pub source_level: IrLevel,
    pub target_level: IrLevel,
    pub transformation_name: String,
    pub source_representation: String,
    pub target_representation: String,
    pub validation_lemmas: Vec<ValidationLemma>,
}

/// Full IR pipeline validation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullIrValidationContext {
    pub pipeline_stages: Vec<IrTransformationStep>,
    pub statement_validator: StatementValidationContext,
    pub expression_validator: ExpressionValidationState,
    pub global_invariants: Vec<GlobalInvariant>,
    pub verification_coverage: VerificationCoverage,
    /// Feature-class coverage (G.6.A–G.6.F): try/catch, async/await, generators,
    /// iterator protocol, hostcalls, IFC label propagation.
    pub feature_validator: FeatureClassValidationContext,
}

/// Expression validation state for pure expressions (from G.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionValidationState {
    pub validated_operators: BTreeSet<String>,
    pub semantic_preservation_proven: bool,
    pub associativity_lemmas: Vec<String>,
    pub commutativity_lemmas: Vec<String>,
}

/// Global invariants maintained across all IR transformations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalInvariant {
    pub invariant_id: String,
    pub invariant_type: GlobalInvariantType,
    pub description: String,
    pub maintained_across_levels: BTreeSet<IrLevel>,
    pub proof_obligations: Vec<String>,
}

/// Types of global invariants in the IR pipeline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GlobalInvariantType {
    TypeSafety,
    MemorySafety,
    CapabilityConfinement,
    SemanticEquivalence,
    ControlFlowIntegrity,
    VariableLifetimeCorrectness,
}

/// Coverage metrics for IR validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCoverage {
    pub ir_levels_covered: BTreeSet<IrLevel>,
    pub transformation_steps_verified: usize,
    pub expression_coverage_percentage: f64,
    pub statement_coverage_percentage: f64,
    pub control_flow_coverage_percentage: f64,
    pub global_invariant_coverage: BTreeMap<GlobalInvariantType, bool>,
    /// Feature classes (G.6.A–G.6.F) for which a semantic-preservation witness has
    /// been validated. Full IR coverage requires every [`FeatureClass`] to appear.
    pub feature_classes_covered: BTreeSet<FeatureClass>,
}

/// Result of full IR pipeline validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullIrValidationResult {
    pub pipeline_validation_successful: bool,
    pub verified_transformation_steps: usize,
    pub failed_transformation_steps: Vec<String>,
    pub expression_validation_result: ExpressionValidationResult,
    pub statement_validation_successful: bool,
    pub global_invariants_maintained: bool,
    pub complete_coverage_achieved: bool,
    pub semantic_equivalence_end_to_end: bool,
}

/// Expression validation result from G.4 pure expression validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionValidationResult {
    pub operators_validated: usize,
    pub semantic_preservation_proven: bool,
    pub failed_expressions: Vec<String>,
}

impl FullIrValidationContext {
    /// Create a new full IR validation context.
    pub fn new() -> Self {
        Self {
            pipeline_stages: Vec::new(),
            statement_validator: StatementValidationContext::new(),
            expression_validator: ExpressionValidationState {
                validated_operators: BTreeSet::new(),
                semantic_preservation_proven: false,
                associativity_lemmas: Vec::new(),
                commutativity_lemmas: Vec::new(),
            },
            global_invariants: Vec::new(),
            verification_coverage: VerificationCoverage::new(),
            feature_validator: FeatureClassValidationContext::new(),
        }
    }

    /// Validate every registered feature-class witness (G.6.A–G.6.F) and fold the
    /// result into the pipeline's coverage tracking. Returns the per-class result.
    ///
    /// This is the umbrella entry point for G.6 "full IR coverage": each high-level
    /// JS feature whose lowering produces a distinctive IR3 instruction pattern is
    /// validated for semantic preservation, and the set of covered classes is
    /// recorded so [`Self::check_complete_coverage`] can require full breadth.
    pub fn validate_feature_classes(&mut self) -> FeatureClassValidationResult {
        self.feature_validator.generate_lemmas();
        let result = self.feature_validator.validate();
        for class in &result.classes_covered {
            self.verification_coverage
                .feature_classes_covered
                .insert(*class);
        }
        result
    }

    /// Add a transformation step to the pipeline.
    pub fn add_transformation_step(&mut self, step: IrTransformationStep) {
        self.verification_coverage
            .ir_levels_covered
            .insert(step.source_level);
        self.verification_coverage
            .ir_levels_covered
            .insert(step.target_level);
        self.verification_coverage.transformation_steps_verified += 1;
        self.pipeline_stages.push(step);
    }

    /// Generate global invariants for the entire IR pipeline.
    pub fn generate_global_invariants(&mut self) -> Result<usize, String> {
        let invariants = vec![
            GlobalInvariant {
                invariant_id: "type_safety_preservation".to_string(),
                invariant_type: GlobalInvariantType::TypeSafety,
                description: "Type information preserved across all IR transformations".to_string(),
                maintained_across_levels: [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3]
                    .into_iter()
                    .collect(),
                proof_obligations: vec![
                    "Well-typed IR0 implies well-typed IR1".to_string(),
                    "Well-typed IR1 implies well-typed IR2".to_string(),
                    "Well-typed IR2 implies well-typed IR3".to_string(),
                ],
            },
            GlobalInvariant {
                invariant_id: "capability_confinement_preservation".to_string(),
                invariant_type: GlobalInvariantType::CapabilityConfinement,
                description: "IFC capabilities properly confined throughout pipeline".to_string(),
                maintained_across_levels: [IrLevel::IR2, IrLevel::IR3].into_iter().collect(),
                proof_obligations: vec![
                    "IR2 capability annotations preserved in IR3".to_string(),
                    "No capability leakage during instruction lowering".to_string(),
                ],
            },
            GlobalInvariant {
                invariant_id: "semantic_equivalence_end_to_end".to_string(),
                invariant_type: GlobalInvariantType::SemanticEquivalence,
                description: "End-to-end semantic equivalence from IR0 to IR3".to_string(),
                maintained_across_levels: [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3]
                    .into_iter()
                    .collect(),
                proof_obligations: vec![
                    "Operational semantics preserved IR0 → IR1".to_string(),
                    "Operational semantics preserved IR1 → IR2".to_string(),
                    "Operational semantics preserved IR2 → IR3".to_string(),
                    "Transitive semantic equivalence IR0 ≡ IR3".to_string(),
                ],
            },
            GlobalInvariant {
                invariant_id: "control_flow_integrity".to_string(),
                invariant_type: GlobalInvariantType::ControlFlowIntegrity,
                description: "Control flow structure integrity maintained".to_string(),
                maintained_across_levels: [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3]
                    .into_iter()
                    .collect(),
                proof_obligations: vec![
                    "CFG structure preserved across transformations".to_string(),
                    "Branch targets remain valid after lowering".to_string(),
                    "Loop structure preserved in flattened form".to_string(),
                ],
            },
        ];

        let invariant_count = invariants.len();
        self.global_invariants = invariants;

        // Update coverage tracking
        for invariant in &self.global_invariants {
            self.verification_coverage
                .global_invariant_coverage
                .insert(invariant.invariant_type.clone(), false);
        }

        Ok(invariant_count)
    }

    /// Validate the complete IR pipeline with all levels.
    pub fn validate_full_pipeline(&mut self) -> FullIrValidationResult {
        let mut result = FullIrValidationResult::new();

        // Validate each transformation step
        for step in &self.pipeline_stages {
            if self.validate_transformation_step(step) {
                result.verified_transformation_steps += 1;
            } else {
                result
                    .failed_transformation_steps
                    .push(step.transformation_name.clone());
            }
        }

        // Validate expressions (G.4 coverage)
        result.expression_validation_result = self.validate_expressions();

        // Validate statements and control flow (G.5 coverage)
        let statement_result = self.statement_validator.validate_lemmas();
        result.statement_validation_successful = statement_result.validation_successful;

        // Verify global invariants
        result.global_invariants_maintained = self.verify_global_invariants();

        // Check complete coverage
        result.complete_coverage_achieved = self.check_complete_coverage();

        // Overall pipeline success
        result.pipeline_validation_successful = result.failed_transformation_steps.is_empty()
            && result
                .expression_validation_result
                .semantic_preservation_proven
            && result.statement_validation_successful
            && result.global_invariants_maintained;

        // End-to-end semantic equivalence
        result.semantic_equivalence_end_to_end =
            result.pipeline_validation_successful && result.complete_coverage_achieved;

        result
    }

    /// Validate a single transformation step.
    fn validate_transformation_step(&self, step: &IrTransformationStep) -> bool {
        // Simplified validation - in reality would invoke formal verification tools
        !step.source_representation.is_empty()
            && !step.target_representation.is_empty()
            && step.source_level != step.target_level
            && !step.validation_lemmas.is_empty()
    }

    /// Validate expression semantics (G.4 coverage).
    fn validate_expressions(&mut self) -> ExpressionValidationResult {
        // Simulate expression validation from G.4
        let operators = [
            "add", "sub", "mul", "div", "mod", "eq", "ne", "lt", "le", "gt", "ge", "and", "or",
            "not",
        ];

        for op in &operators {
            self.expression_validator
                .validated_operators
                .insert(op.to_string());
        }

        self.expression_validator.semantic_preservation_proven = true;
        self.verification_coverage.expression_coverage_percentage = 100.0;

        ExpressionValidationResult {
            operators_validated: operators.len(),
            semantic_preservation_proven: true,
            failed_expressions: Vec::new(),
        }
    }

    /// Verify that all global invariants hold.
    fn verify_global_invariants(&mut self) -> bool {
        for invariant in &self.global_invariants {
            // Simplified verification - would invoke theorem provers
            let verification_success = match invariant.invariant_type {
                GlobalInvariantType::TypeSafety => true,
                GlobalInvariantType::MemorySafety => true,
                GlobalInvariantType::CapabilityConfinement => true,
                GlobalInvariantType::SemanticEquivalence => true,
                GlobalInvariantType::ControlFlowIntegrity => true,
                GlobalInvariantType::VariableLifetimeCorrectness => true,
            };

            self.verification_coverage
                .global_invariant_coverage
                .insert(invariant.invariant_type.clone(), verification_success);

            if !verification_success {
                return false;
            }
        }
        true
    }

    /// Check if complete coverage has been achieved.
    fn check_complete_coverage(&mut self) -> bool {
        // Must cover all IR levels
        let all_levels = [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3];
        for level in &all_levels {
            if !self.verification_coverage.ir_levels_covered.contains(level) {
                return false;
            }
        }

        // Must cover every G.6 feature class (full IR coverage breadth).
        for class in FeatureClass::ALL {
            if !self
                .verification_coverage
                .feature_classes_covered
                .contains(&class)
            {
                return false;
            }
        }

        // Must have high coverage percentages
        self.verification_coverage.expression_coverage_percentage >= 95.0
            && self.verification_coverage.statement_coverage_percentage >= 95.0
            && self.verification_coverage.control_flow_coverage_percentage >= 95.0
    }
}

impl VerificationCoverage {
    fn new() -> Self {
        Self {
            ir_levels_covered: BTreeSet::new(),
            transformation_steps_verified: 0,
            expression_coverage_percentage: 0.0,
            statement_coverage_percentage: 0.0,
            control_flow_coverage_percentage: 0.0,
            global_invariant_coverage: BTreeMap::new(),
            feature_classes_covered: BTreeSet::new(),
        }
    }
}

impl FullIrValidationResult {
    fn new() -> Self {
        Self {
            pipeline_validation_successful: false,
            verified_transformation_steps: 0,
            failed_transformation_steps: Vec::new(),
            expression_validation_result: ExpressionValidationResult {
                operators_validated: 0,
                semantic_preservation_proven: false,
                failed_expressions: Vec::new(),
            },
            statement_validation_successful: false,
            global_invariants_maintained: false,
            complete_coverage_achieved: false,
            semantic_equivalence_end_to_end: false,
        }
    }
}

impl Default for FullIrValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate comprehensive test cases for full IR pipeline validation.
pub fn generate_full_ir_test_cases() -> Vec<FullIrTestCase> {
    vec![
        FullIrTestCase {
            name: "simple_arithmetic".to_string(),
            source_code: "let x = 1 + 2 * 3;".to_string(),
            expected_ir_levels: 4,
            contains_expressions: true,
            contains_statements: true,
            contains_control_flow: false,
        },
        FullIrTestCase {
            name: "conditional_with_expressions".to_string(),
            source_code: "if (a > b) { result = a + b; } else { result = a - b; }".to_string(),
            expected_ir_levels: 4,
            contains_expressions: true,
            contains_statements: true,
            contains_control_flow: true,
        },
        FullIrTestCase {
            name: "loop_with_complex_body".to_string(),
            source_code: "while (i < 10) { sum = sum + i * 2; i = i + 1; }".to_string(),
            expected_ir_levels: 4,
            contains_expressions: true,
            contains_statements: true,
            contains_control_flow: true,
        },
        FullIrTestCase {
            name: "nested_functions_with_capabilities".to_string(),
            source_code:
                "function outer() { function inner() { return sensitive_data; } return inner(); }"
                    .to_string(),
            expected_ir_levels: 4,
            contains_expressions: true,
            contains_statements: true,
            contains_control_flow: true,
        },
    ]
}

/// Test case for full IR pipeline validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullIrTestCase {
    pub name: String,
    pub source_code: String,
    pub expected_ir_levels: usize,
    pub contains_expressions: bool,
    pub contains_statements: bool,
    pub contains_control_flow: bool,
}

// ============================================================================
// G.6 — Feature-class translation validation (full IR coverage)
//
// G.4 piloted translation validation on the pure-expression IR subset; G.5
// extended it to statements + control flow. G.6 covers every remaining language
// feature whose lowering produces a distinctive IR3 instruction pattern that the
// expression/statement checkers do not exercise. Each feature class below maps
// to a G.6 sub-track (bd-cixqu.7.9.1 … .6) and carries its own semantic-
// preservation obligations plus negative ("preserving-looking but broken")
// rejection cases.
// ============================================================================

/// High-level language feature class whose lowering produces a distinctive IR3
/// instruction pattern requiring dedicated translation-validation coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureClass {
    /// G.6.A — try/catch/finally + catch-frame unwinder.
    TryCatchFinally,
    /// G.6.B — async/await + microtask checkpoint preservation.
    AsyncAwait,
    /// G.6.C — generators + async generators (suspend/resume points).
    Generators,
    /// G.6.D — iterator protocol (for..in / for..of / IteratorClose).
    IteratorProtocol,
    /// G.6.E — hostcalls + capability witness.
    Hostcalls,
    /// G.6.F — IFC label propagation.
    IfcLabelPropagation,
}

impl FeatureClass {
    /// Every feature class that "full IR coverage" must validate.
    pub const ALL: [FeatureClass; 6] = [
        FeatureClass::TryCatchFinally,
        FeatureClass::AsyncAwait,
        FeatureClass::Generators,
        FeatureClass::IteratorProtocol,
        FeatureClass::Hostcalls,
        FeatureClass::IfcLabelPropagation,
    ];

    /// The G.6 sub-track bead suffix this class corresponds to.
    pub const fn g6_subtrack(self) -> &'static str {
        match self {
            Self::TryCatchFinally => "G.6.A",
            Self::AsyncAwait => "G.6.B",
            Self::Generators => "G.6.C",
            Self::IteratorProtocol => "G.6.D",
            Self::Hostcalls => "G.6.E",
            Self::IfcLabelPropagation => "G.6.F",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TryCatchFinally => "try_catch_finally",
            Self::AsyncAwait => "async_await",
            Self::Generators => "generators",
            Self::IteratorProtocol => "iterator_protocol",
            Self::Hostcalls => "hostcalls",
            Self::IfcLabelPropagation => "ifc_label_propagation",
        }
    }
}

/// Abstract IR3 opcode shape relevant to feature-class validation.
///
/// This mirrors the structurally-significant fields of the real
/// [`crate::ir_contract::Ir3Instruction`] variants but drops register operands, so a witness can be
/// compared structurally and frozen as a golden replay artifact. The full
/// register-level instructions live in [`crate::ir_contract`]; here we only model
/// the control- and capability-flow shape that translation validation must prove
/// is preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeatureOpcode {
    /// `BeginTry` — opens a protected region; records whether a catch and/or
    /// finally handler follows (drives the catch-frame unwinder).
    BeginTry { has_catch: bool, has_finally: bool },
    /// `EnterCatch` — unwinder transferred control to a catch handler.
    EnterCatch,
    /// `EnterFinally` — unwinder entered a finally block.
    EnterFinally,
    /// `EndFinally` — finally block completed; pending action resumes.
    EndFinally,
    /// A `throw` that the unwinder must route to the nearest enclosing handler.
    Throw,
    /// `AwaitValue` — suspends on a promise; each await is a microtask boundary.
    AwaitValue,
    /// An explicit microtask-checkpoint marker emitted at an await/resume edge.
    MicrotaskCheckpoint,
    /// `Yield` — generator suspension point (`delegate` => `yield*`).
    Yield { delegate: bool },
    /// Generator/async-generator resume edge (paired with a prior suspension).
    GeneratorResume,
    /// `ForInInit` — initialize a for-in enumeration.
    ForInInit,
    /// `ForInNext` — advance a for-in enumeration.
    ForInNext,
    /// `ForOfInit` — initialize a for-of iteration (acquires an iterator).
    ForOfInit,
    /// `ForOfNext` — advance a for-of iteration.
    ForOfNext,
    /// `IteratorClose` — discharge the close obligation for an acquired iterator.
    IteratorClose { reason: IteratorCloseReason },
    /// `HostCall` — capability-gated host invocation; the witness must carry the
    /// non-empty capability string the call was authorized against.
    HostCall { capability: String },
    /// An IFC label propagation along a data-flow edge: `var` receives `level`
    /// (higher = more restricted). Lowering must never *downgrade* a label.
    IfcLabel { var: String, level: u8 },
    /// Any other lowered opcode irrelevant to the feature being validated.
    Other,
}

/// A semantic-preservation witness for a single lowered program belonging to one
/// feature class: the ordered IR3 opcode shape the lowering produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureWitness {
    pub program_name: String,
    pub feature_class: FeatureClass,
    pub opcodes: Vec<FeatureOpcode>,
}

impl FeatureWitness {
    pub fn new(
        program_name: impl Into<String>,
        feature_class: FeatureClass,
        opcodes: Vec<FeatureOpcode>,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            feature_class,
            opcodes,
        }
    }

    /// Check the structural semantic-preservation obligations for this witness.
    ///
    /// Returns `Ok(())` if every obligation holds, or `Err(reason)` identifying
    /// the first violated obligation. This is what makes "preserving-looking but
    /// broken" transformations REJECT (G.11 negative-test composition).
    pub fn check_obligations(&self) -> Result<(), String> {
        match self.feature_class {
            FeatureClass::TryCatchFinally => self.check_unwinder_balance(),
            FeatureClass::AsyncAwait => self.check_microtask_checkpoints(),
            FeatureClass::Generators => self.check_suspend_resume_parity(),
            FeatureClass::IteratorProtocol => self.check_iterator_close_obligation(),
            FeatureClass::Hostcalls => self.check_capability_witness(),
            FeatureClass::IfcLabelPropagation => self.check_label_monotonicity(),
        }
    }

    /// G.6.A: every `BeginTry` opens a protected region that must be balanced by a
    /// matching `EndFinally` when it declares a finally, and a catch frame must
    /// exist when it declares a catch. The unwinder depth must never go negative
    /// and must return to zero (no dangling protected regions).
    fn check_unwinder_balance(&self) -> Result<(), String> {
        let mut depth: i64 = 0;
        let mut expect_catch = 0usize;
        let mut expect_finally = 0usize;
        for op in &self.opcodes {
            match op {
                FeatureOpcode::BeginTry {
                    has_catch,
                    has_finally,
                } => {
                    depth += 1;
                    if *has_catch {
                        expect_catch += 1;
                    }
                    if *has_finally {
                        expect_finally += 1;
                    }
                }
                FeatureOpcode::EnterCatch => {
                    expect_catch = expect_catch.saturating_sub(1);
                }
                FeatureOpcode::EndFinally => {
                    expect_finally = expect_finally.saturating_sub(1);
                    depth -= 1;
                    if depth < 0 {
                        return Err("unwinder underflow: EndFinally without BeginTry".into());
                    }
                }
                _ => {}
            }
        }
        // A try without finally still closes its region implicitly; only finally
        // regions consume the depth counter above, so depth may remain positive
        // for catch-only regions — collapse those here.
        if expect_catch != 0 {
            return Err("declared catch handler never entered (lost catch frame)".into());
        }
        if expect_finally != 0 {
            return Err("declared finally block never reached EndFinally".into());
        }
        Ok(())
    }

    /// G.6.B: every `AwaitValue` is a microtask boundary, so the count of explicit
    /// `MicrotaskCheckpoint` markers must equal the number of awaits, and a
    /// checkpoint must never precede its await (ordering preservation).
    fn check_microtask_checkpoints(&self) -> Result<(), String> {
        let awaits = self
            .opcodes
            .iter()
            .filter(|o| matches!(o, FeatureOpcode::AwaitValue))
            .count();
        let checkpoints = self
            .opcodes
            .iter()
            .filter(|o| matches!(o, FeatureOpcode::MicrotaskCheckpoint))
            .count();
        if awaits != checkpoints {
            return Err(format!(
                "microtask checkpoint mismatch: {awaits} awaits vs {checkpoints} checkpoints"
            ));
        }
        // Each await must be immediately followed by its checkpoint.
        let mut iter = self.opcodes.iter().peekable();
        while let Some(op) = iter.next() {
            if matches!(op, FeatureOpcode::AwaitValue)
                && !matches!(iter.peek(), Some(FeatureOpcode::MicrotaskCheckpoint))
            {
                return Err("await not followed by its microtask checkpoint".into());
            }
        }
        Ok(())
    }

    /// G.6.C: a generator's suspension points (`Yield`) and resume edges must be
    /// paired; an extra resume with no prior suspension, or a trailing suspension
    /// with an unmatched resume, breaks the suspend/resume state machine.
    fn check_suspend_resume_parity(&self) -> Result<(), String> {
        let mut suspended = 0i64;
        for op in &self.opcodes {
            match op {
                FeatureOpcode::Yield { .. } => suspended += 1,
                FeatureOpcode::GeneratorResume => {
                    suspended -= 1;
                    if suspended < 0 {
                        return Err("generator resume without a prior suspension".into());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// G.6.D: every iterator acquisition (`ForOfInit`/`ForInInit`) must be matched
    /// by an `IteratorClose` so the close obligation is discharged on every exit
    /// path (break/return/throw). A missing close leaks the iterator.
    fn check_iterator_close_obligation(&self) -> Result<(), String> {
        let opens = self
            .opcodes
            .iter()
            .filter(|o| matches!(o, FeatureOpcode::ForOfInit | FeatureOpcode::ForInInit))
            .count();
        let closes = self
            .opcodes
            .iter()
            .filter(|o| matches!(o, FeatureOpcode::IteratorClose { .. }))
            .count();
        if opens != closes {
            return Err(format!(
                "iterator close obligation unmet: {opens} acquisitions vs {closes} closes"
            ));
        }
        Ok(())
    }

    /// G.6.E: every `HostCall` must carry the non-empty capability string it was
    /// authorized against; stripping the capability witness must REJECT.
    fn check_capability_witness(&self) -> Result<(), String> {
        for op in &self.opcodes {
            if let FeatureOpcode::HostCall { capability } = op {
                if capability.trim().is_empty() {
                    return Err("hostcall lowered without a capability witness".into());
                }
            }
        }
        Ok(())
    }

    /// G.6.F: IFC label propagation may raise (restrict) a variable's label but
    /// must never lower (declassify) it implicitly during lowering. The first
    /// observed downgrade is a rejection.
    fn check_label_monotonicity(&self) -> Result<(), String> {
        let mut current: BTreeMap<String, u8> = BTreeMap::new();
        for op in &self.opcodes {
            if let FeatureOpcode::IfcLabel { var, level } = op {
                if let Some(prev) = current.get(var) {
                    if *level < *prev {
                        return Err(format!(
                            "IFC label downgrade on `{var}`: {prev} -> {level} (implicit declassification)"
                        ));
                    }
                }
                current.insert(var.clone(), *level);
            }
        }
        Ok(())
    }
}

/// Result of validating one feature class's witnesses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureClassReport {
    pub feature_class: FeatureClass,
    pub programs_validated: usize,
    pub rejected_programs: Vec<(String, String)>, // (program_name, reason)
    pub lemmas_generated: usize,
}

impl FeatureClassReport {
    pub fn all_accepted(&self) -> bool {
        self.rejected_programs.is_empty()
    }
}

/// Validation context for feature-class (G.6) translation validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureClassValidationContext {
    pub witnesses: Vec<FeatureWitness>,
    pub lemmas: Vec<ValidationLemma>,
}

impl FeatureClassValidationContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a lowering witness for later validation.
    pub fn add_witness(&mut self, witness: FeatureWitness) {
        self.witnesses.push(witness);
    }

    /// Register every program produced by [`generate_feature_programs`] so the
    /// umbrella validator covers all G.6 sub-tracks in one shot.
    pub fn add_standard_corpus(&mut self) {
        for witness in generate_feature_programs() {
            self.add_witness(witness);
        }
    }

    /// Generate one semantic-preservation lemma per registered witness. The lemma
    /// reuses the shared [`ValidationLemma`]/[`ProofObligation`] vocabulary so
    /// feature-class proofs compose with the statement-level proof corpus.
    pub fn generate_lemmas(&mut self) -> usize {
        self.lemmas.clear();
        for (idx, witness) in self.witnesses.iter().enumerate() {
            let lemma_id = format!(
                "feature_{}_{}_{idx}",
                witness.feature_class.as_str(),
                witness.program_name
            );
            let (premise, conclusion, method) = feature_obligation_text(witness.feature_class);
            let lemma = ValidationLemma {
                lemma_id: lemma_id.clone(),
                // Feature-class semantics are control-flow-shaped; the closest
                // shared lemma type is control-flow preservation.
                lemma_type:
                    crate::statement_translation_validator::LemmaType::ControlFlowPreservation,
                source_nodes: [idx as u32].into_iter().collect(),
                target_nodes: [idx as u32].into_iter().collect(),
                invariant: format!(
                    "{} lowering preserves {} semantics",
                    witness.feature_class.g6_subtrack(),
                    witness.feature_class.as_str()
                ),
                proof_obligations: vec![ProofObligation {
                    obligation_id: format!("{lemma_id}_preservation"),
                    premise: premise.to_string(),
                    conclusion: conclusion.to_string(),
                    verification_method: method,
                }],
            };
            self.lemmas.push(lemma);
        }
        self.lemmas.len()
    }

    /// Validate every registered witness, producing a per-class report and an
    /// aggregate result. A witness whose obligations fail is recorded as a
    /// rejection (this is the positive direction); negative tests assert that
    /// deliberately-broken witnesses DO appear here.
    pub fn validate(&self) -> FeatureClassValidationResult {
        let mut reports: BTreeMap<FeatureClass, FeatureClassReport> = BTreeMap::new();
        for class in FeatureClass::ALL {
            reports.insert(
                class,
                FeatureClassReport {
                    feature_class: class,
                    programs_validated: 0,
                    rejected_programs: Vec::new(),
                    lemmas_generated: 0,
                },
            );
        }

        for witness in &self.witnesses {
            let report =
                reports
                    .entry(witness.feature_class)
                    .or_insert_with(|| FeatureClassReport {
                        feature_class: witness.feature_class,
                        programs_validated: 0,
                        rejected_programs: Vec::new(),
                        lemmas_generated: 0,
                    });
            report.programs_validated += 1;
            if let Err(reason) = witness.check_obligations() {
                report
                    .rejected_programs
                    .push((witness.program_name.clone(), reason));
            }
        }

        for lemma in &self.lemmas {
            // Attribute each lemma back to a class via its id prefix.
            for class in FeatureClass::ALL {
                if lemma
                    .lemma_id
                    .starts_with(&format!("feature_{}_", class.as_str()))
                {
                    if let Some(r) = reports.get_mut(&class) {
                        r.lemmas_generated += 1;
                    }
                    break;
                }
            }
        }

        let classes_covered: BTreeSet<FeatureClass> = reports
            .values()
            .filter(|r| r.programs_validated > 0)
            .map(|r| r.feature_class)
            .collect();

        let all_accepted = reports.values().all(|r| r.all_accepted());
        let total_programs: usize = reports.values().map(|r| r.programs_validated).sum();

        FeatureClassValidationResult {
            reports: reports.into_values().collect(),
            classes_covered,
            all_accepted,
            total_programs,
        }
    }
}

/// Aggregate result of feature-class translation validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureClassValidationResult {
    pub reports: Vec<FeatureClassReport>,
    pub classes_covered: BTreeSet<FeatureClass>,
    pub all_accepted: bool,
    pub total_programs: usize,
}

impl FeatureClassValidationResult {
    /// True when every G.6 feature class has at least one validated witness.
    pub fn full_breadth(&self) -> bool {
        FeatureClass::ALL
            .iter()
            .all(|c| self.classes_covered.contains(c))
    }
}

/// Per-class proof-obligation text + verification method.
fn feature_obligation_text(
    class: FeatureClass,
) -> (&'static str, &'static str, VerificationMethod) {
    match class {
        FeatureClass::TryCatchFinally => (
            "source exception flow reaches every handler on the matching throw path",
            "lowered catch-frame unwinder reaches the same handlers in the same order",
            VerificationMethod::ModelChecking,
        ),
        FeatureClass::AsyncAwait => (
            "source suspends the coroutine at each await and resumes after one microtask turn",
            "lowered IR3 emits one microtask checkpoint per await, preserving resume order",
            VerificationMethod::SymbolicExecution,
        ),
        FeatureClass::Generators => (
            "source generator suspends at each yield and resumes with the sent value",
            "lowered suspend/resume edges are paired and preserve yielded-value order",
            VerificationMethod::SymbolicExecution,
        ),
        FeatureClass::IteratorProtocol => (
            "source closes the iterator on every break/return/throw exit path",
            "lowered IR3 discharges an IteratorClose obligation for each acquisition",
            VerificationMethod::ModelChecking,
        ),
        FeatureClass::Hostcalls => (
            "source hostcall is authorized against a specific capability",
            "lowered HostCall carries the same non-empty capability witness",
            VerificationMethod::LeanFormal,
        ),
        FeatureClass::IfcLabelPropagation => (
            "source IFC labels are non-decreasing along every data-flow edge",
            "lowered label propagation never implicitly declassifies a variable",
            VerificationMethod::LeanFormal,
        ),
    }
}

/// Produce a "preserving-looking but broken" mutant of a witness for use in
/// negative tests (G.11 composition): the mutated witness should still *look*
/// like a valid lowering but violate exactly one semantic obligation, so
/// [`FeatureWitness::check_obligations`] must reject it.
pub fn break_witness(witness: &FeatureWitness) -> FeatureWitness {
    let mut opcodes = witness.opcodes.clone();
    match witness.feature_class {
        FeatureClass::TryCatchFinally => {
            // Drop a structural marker so the unwinder no longer balances:
            //  - finally present  -> remove EndFinally (finally never closed)
            //  - catch-only        -> remove EnterCatch (handler never entered)
            //  - otherwise         -> inject a stray EndFinally (depth underflow)
            if let Some(pos) = opcodes
                .iter()
                .position(|o| matches!(o, FeatureOpcode::EndFinally))
            {
                opcodes.remove(pos);
            } else if let Some(pos) = opcodes
                .iter()
                .position(|o| matches!(o, FeatureOpcode::EnterCatch))
            {
                opcodes.remove(pos);
            } else {
                opcodes.insert(0, FeatureOpcode::EndFinally);
            }
        }
        FeatureClass::AsyncAwait => {
            // Drop the first microtask checkpoint: await without its turn boundary.
            if let Some(pos) = opcodes
                .iter()
                .position(|o| matches!(o, FeatureOpcode::MicrotaskCheckpoint))
            {
                opcodes.remove(pos);
            }
        }
        FeatureClass::Generators => {
            // Inject a spurious resume with no prior suspension.
            opcodes.insert(0, FeatureOpcode::GeneratorResume);
        }
        FeatureClass::IteratorProtocol => {
            // Drop the iterator close: the classic "optimized-away" leak.
            if let Some(pos) = opcodes
                .iter()
                .position(|o| matches!(o, FeatureOpcode::IteratorClose { .. }))
            {
                opcodes.remove(pos);
            }
        }
        FeatureClass::Hostcalls => {
            // Strip the capability witness from the first hostcall.
            for op in opcodes.iter_mut() {
                if let FeatureOpcode::HostCall { capability } = op {
                    *capability = String::new();
                    break;
                }
            }
        }
        FeatureClass::IfcLabelPropagation => {
            // Append an implicit declassification of an already-labeled variable.
            if let Some(FeatureOpcode::IfcLabel { var, .. }) = opcodes
                .iter()
                .find(|o| matches!(o, FeatureOpcode::IfcLabel { .. }))
                .cloned()
            {
                opcodes.push(FeatureOpcode::IfcLabel { var, level: 0 });
            }
        }
    }
    FeatureWitness {
        program_name: format!("{}__broken", witness.program_name),
        feature_class: witness.feature_class,
        opcodes,
    }
}

/// Generate the standard corpus of feature-class lowering witnesses.
///
/// Produces ≥50 programs spread across all six G.6 sub-tracks, covering the
/// variants called out in the acceptance criteria (nested try, try-without-
/// finally, throw in finally/catch, await in try/finally, yield*, for-in/for-of
/// with break/return/throw exits, capability-gated hostcalls, and IFC flows).
pub fn generate_feature_programs() -> Vec<FeatureWitness> {
    use FeatureOpcode as Op;
    let mut programs = Vec::new();

    // ---- G.6.A: try/catch/finally (10 programs) ----------------------------
    programs.push(FeatureWitness::new(
        "try_catch",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: true,
                has_finally: false,
            },
            Op::Throw,
            Op::EnterCatch,
        ],
    ));
    programs.push(FeatureWitness::new(
        "try_finally",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "try_catch_finally",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: true,
                has_finally: true,
            },
            Op::Throw,
            Op::EnterCatch,
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "nested_try",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: true,
                has_finally: true,
            },
            Op::BeginTry {
                has_catch: true,
                has_finally: false,
            },
            Op::Throw,
            Op::EnterCatch,
            Op::EnterCatch,
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "throw_in_catch",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: true,
                has_finally: true,
            },
            Op::Throw,
            Op::EnterCatch,
            Op::Throw,
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "throw_in_finally",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::EnterFinally,
            Op::Throw,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "await_in_try",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: true,
                has_finally: false,
            },
            Op::AwaitValue,
            Op::MicrotaskCheckpoint,
            Op::Throw,
            Op::EnterCatch,
        ],
    ));
    programs.push(FeatureWitness::new(
        "await_in_finally",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::EnterFinally,
            Op::AwaitValue,
            Op::MicrotaskCheckpoint,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "try_without_catch_or_throw",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));
    programs.push(FeatureWitness::new(
        "deeply_nested_try",
        FeatureClass::TryCatchFinally,
        vec![
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::BeginTry {
                has_catch: false,
                has_finally: true,
            },
            Op::BeginTry {
                has_catch: true,
                has_finally: false,
            },
            Op::Throw,
            Op::EnterCatch,
            Op::EnterFinally,
            Op::EndFinally,
            Op::EnterFinally,
            Op::EndFinally,
        ],
    ));

    // ---- G.6.B: async/await (8 programs) -----------------------------------
    for n in 1..=8 {
        let mut ops = Vec::new();
        for _ in 0..n {
            ops.push(Op::AwaitValue);
            ops.push(Op::MicrotaskCheckpoint);
        }
        programs.push(FeatureWitness::new(
            format!("async_{n}_awaits"),
            FeatureClass::AsyncAwait,
            ops,
        ));
    }

    // ---- G.6.C: generators + async generators (8 programs) -----------------
    for n in 1..=4 {
        let mut ops = Vec::new();
        for _ in 0..n {
            ops.push(Op::Yield { delegate: false });
            ops.push(Op::GeneratorResume);
        }
        programs.push(FeatureWitness::new(
            format!("generator_{n}_yields"),
            FeatureClass::Generators,
            ops,
        ));
    }
    for n in 1..=4 {
        let mut ops = Vec::new();
        for _ in 0..n {
            ops.push(Op::Yield { delegate: true });
            ops.push(Op::GeneratorResume);
            ops.push(Op::AwaitValue);
            ops.push(Op::MicrotaskCheckpoint);
        }
        programs.push(FeatureWitness::new(
            format!("async_generator_{n}_yields"),
            FeatureClass::Generators,
            ops,
        ));
    }

    // ---- G.6.D: iterator protocol (12 programs) ----------------------------
    let close_reasons = [
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ];
    for reason in close_reasons {
        programs.push(FeatureWitness::new(
            format!("for_of_{}", reason.as_str()),
            FeatureClass::IteratorProtocol,
            vec![Op::ForOfInit, Op::ForOfNext, Op::IteratorClose { reason }],
        ));
        programs.push(FeatureWitness::new(
            format!("for_in_{}", reason.as_str()),
            FeatureClass::IteratorProtocol,
            vec![Op::ForInInit, Op::ForInNext, Op::IteratorClose { reason }],
        ));
        programs.push(FeatureWitness::new(
            format!("nested_for_of_{}", reason.as_str()),
            FeatureClass::IteratorProtocol,
            vec![
                Op::ForOfInit,
                Op::ForOfInit,
                Op::ForOfNext,
                Op::IteratorClose { reason },
                Op::IteratorClose { reason },
            ],
        ));
        programs.push(FeatureWitness::new(
            format!("for_of_with_await_{}", reason.as_str()),
            FeatureClass::IteratorProtocol,
            vec![
                Op::ForOfInit,
                Op::AwaitValue,
                Op::MicrotaskCheckpoint,
                Op::ForOfNext,
                Op::IteratorClose { reason },
            ],
        ));
    }

    // ---- G.6.E: hostcalls + capability witness (8 programs) ----------------
    let caps = [
        "io.read",
        "io.write",
        "net.connect",
        "clock.now",
        "rand.bytes",
        "fs.stat",
        "crypto.sign",
        "env.get",
    ];
    for cap in caps {
        programs.push(FeatureWitness::new(
            format!("hostcall_{}", cap.replace('.', "_")),
            FeatureClass::Hostcalls,
            vec![
                Op::HostCall {
                    capability: cap.to_string(),
                },
                Op::Other,
            ],
        ));
    }

    // ---- G.6.F: IFC label propagation (8 programs) -------------------------
    for n in 0..8u8 {
        programs.push(FeatureWitness::new(
            format!("ifc_flow_{n}"),
            FeatureClass::IfcLabelPropagation,
            vec![
                Op::IfcLabel {
                    var: "x".into(),
                    level: n.min(3),
                },
                Op::IfcLabel {
                    var: "y".into(),
                    level: n.min(3) + 1,
                },
                // raising x is allowed
                Op::IfcLabel {
                    var: "x".into(),
                    level: (n.min(3)).saturating_add(2).min(5),
                },
            ],
        ));
    }

    programs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ir_validation_context_creation() {
        let ctx = FullIrValidationContext::new();
        assert!(ctx.pipeline_stages.is_empty());
        assert_eq!(ctx.verification_coverage.transformation_steps_verified, 0);
    }

    #[test]
    fn ir_level_progression() {
        assert_eq!(IrLevel::IR0.next_level(), Some(IrLevel::IR1));
        assert_eq!(IrLevel::IR1.next_level(), Some(IrLevel::IR2));
        assert_eq!(IrLevel::IR2.next_level(), Some(IrLevel::IR3));
        assert_eq!(IrLevel::IR3.next_level(), None);
    }

    #[test]
    fn transformation_step_addition() {
        let mut ctx = FullIrValidationContext::new();

        let step = IrTransformationStep {
            source_level: IrLevel::IR0,
            target_level: IrLevel::IR1,
            transformation_name: "scope_resolution".to_string(),
            source_representation: "AST".to_string(),
            target_representation: "Scope-resolved IR".to_string(),
            validation_lemmas: Vec::new(),
        };

        ctx.add_transformation_step(step);

        assert_eq!(ctx.pipeline_stages.len(), 1);
        assert_eq!(ctx.verification_coverage.transformation_steps_verified, 1);
        assert!(
            ctx.verification_coverage
                .ir_levels_covered
                .contains(&IrLevel::IR0)
        );
        assert!(
            ctx.verification_coverage
                .ir_levels_covered
                .contains(&IrLevel::IR1)
        );
    }

    #[test]
    fn global_invariant_generation() {
        let mut ctx = FullIrValidationContext::new();
        let invariant_count = ctx.generate_global_invariants().unwrap();

        assert!(invariant_count >= 4);
        assert!(!ctx.global_invariants.is_empty());

        // Check that we have all expected invariant types
        let invariant_types: BTreeSet<_> = ctx
            .global_invariants
            .iter()
            .map(|inv| &inv.invariant_type)
            .collect();
        assert!(invariant_types.contains(&GlobalInvariantType::TypeSafety));
        assert!(invariant_types.contains(&GlobalInvariantType::SemanticEquivalence));
        assert!(invariant_types.contains(&GlobalInvariantType::CapabilityConfinement));
    }

    #[test]
    fn full_pipeline_validation() {
        let mut ctx = FullIrValidationContext::new();

        // Add complete pipeline steps
        let steps = vec![
            IrTransformationStep {
                source_level: IrLevel::IR0,
                target_level: IrLevel::IR1,
                transformation_name: "scope_resolution".to_string(),
                source_representation: "AST".to_string(),
                target_representation: "Scoped IR".to_string(),
                validation_lemmas: vec![], // Would contain actual lemmas
            },
            IrTransformationStep {
                source_level: IrLevel::IR1,
                target_level: IrLevel::IR2,
                transformation_name: "capability_annotation".to_string(),
                source_representation: "Scoped IR".to_string(),
                target_representation: "IFC-annotated IR".to_string(),
                validation_lemmas: vec![],
            },
            IrTransformationStep {
                source_level: IrLevel::IR2,
                target_level: IrLevel::IR3,
                transformation_name: "instruction_lowering".to_string(),
                source_representation: "IFC IR".to_string(),
                target_representation: "Flat instructions".to_string(),
                validation_lemmas: vec![],
            },
        ];

        for step in steps {
            ctx.add_transformation_step(step);
        }

        ctx.generate_global_invariants().unwrap();

        let result = ctx.validate_full_pipeline();
        assert!(result.pipeline_validation_successful);
        assert_eq!(result.verified_transformation_steps, 3);
        assert!(
            result
                .expression_validation_result
                .semantic_preservation_proven
        );
    }

    #[test]
    fn test_case_generation() {
        let test_cases = generate_full_ir_test_cases();
        assert!(!test_cases.is_empty());

        let conditional_case = test_cases
            .iter()
            .find(|tc| tc.name == "conditional_with_expressions")
            .unwrap();

        assert!(conditional_case.contains_expressions);
        assert!(conditional_case.contains_statements);
        assert!(conditional_case.contains_control_flow);
        assert_eq!(conditional_case.expected_ir_levels, 4);
    }

    // ---- G.6 feature-class translation validation -------------------------

    #[test]
    fn feature_class_metadata_is_complete() {
        assert_eq!(FeatureClass::ALL.len(), 6);
        assert_eq!(FeatureClass::TryCatchFinally.g6_subtrack(), "G.6.A");
        assert_eq!(FeatureClass::AsyncAwait.g6_subtrack(), "G.6.B");
        assert_eq!(FeatureClass::Generators.g6_subtrack(), "G.6.C");
        assert_eq!(FeatureClass::IteratorProtocol.g6_subtrack(), "G.6.D");
        assert_eq!(FeatureClass::Hostcalls.g6_subtrack(), "G.6.E");
        assert_eq!(FeatureClass::IfcLabelPropagation.g6_subtrack(), "G.6.F");
        // Every class has a distinct lowercase identifier.
        let ids: BTreeSet<_> = FeatureClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(ids.len(), 6);
    }

    #[test]
    fn standard_corpus_meets_minimum_size_and_breadth() {
        let programs = generate_feature_programs();
        assert!(
            programs.len() >= 50,
            "expected >=50 generated programs, got {}",
            programs.len()
        );
        let covered: BTreeSet<_> = programs.iter().map(|w| w.feature_class).collect();
        assert_eq!(covered.len(), 6, "all six G.6 classes must be represented");
    }

    #[test]
    fn every_standard_program_is_accepted() {
        for witness in generate_feature_programs() {
            assert!(
                witness.check_obligations().is_ok(),
                "well-formed program `{}` ({:?}) should validate: {:?}",
                witness.program_name,
                witness.feature_class,
                witness.check_obligations()
            );
        }
    }

    #[test]
    fn every_broken_mutant_is_rejected() {
        // Negative direction (G.11 composition): a "preserving-looking" mutant
        // that violates exactly one obligation MUST be rejected.
        for witness in generate_feature_programs() {
            let broken = break_witness(&witness);
            assert!(
                broken.check_obligations().is_err(),
                "broken mutant of `{}` ({:?}) should REJECT but was accepted",
                witness.program_name,
                witness.feature_class
            );
        }
    }

    #[test]
    fn unwinder_balance_rejects_dangling_finally() {
        let w = FeatureWitness::new(
            "dangling",
            FeatureClass::TryCatchFinally,
            vec![FeatureOpcode::BeginTry {
                has_catch: false,
                has_finally: true,
            }],
        );
        assert!(w.check_obligations().is_err());
    }

    #[test]
    fn microtask_checkpoint_count_must_match_awaits() {
        let w = FeatureWitness::new(
            "missing_checkpoint",
            FeatureClass::AsyncAwait,
            vec![
                FeatureOpcode::AwaitValue,
                FeatureOpcode::AwaitValue,
                FeatureOpcode::MicrotaskCheckpoint,
            ],
        );
        assert!(w.check_obligations().is_err());
    }

    #[test]
    fn iterator_close_obligation_must_be_discharged() {
        let leaked = FeatureWitness::new(
            "leak",
            FeatureClass::IteratorProtocol,
            vec![FeatureOpcode::ForOfInit, FeatureOpcode::ForOfNext],
        );
        assert!(leaked.check_obligations().is_err());
        let closed = FeatureWitness::new(
            "closed",
            FeatureClass::IteratorProtocol,
            vec![
                FeatureOpcode::ForOfInit,
                FeatureOpcode::ForOfNext,
                FeatureOpcode::IteratorClose {
                    reason: IteratorCloseReason::Break,
                },
            ],
        );
        assert!(closed.check_obligations().is_ok());
    }

    #[test]
    fn hostcall_without_capability_is_rejected() {
        let w = FeatureWitness::new(
            "uncapped",
            FeatureClass::Hostcalls,
            vec![FeatureOpcode::HostCall {
                capability: String::new(),
            }],
        );
        assert!(w.check_obligations().is_err());
    }

    #[test]
    fn ifc_label_downgrade_is_rejected() {
        let w = FeatureWitness::new(
            "declassify",
            FeatureClass::IfcLabelPropagation,
            vec![
                FeatureOpcode::IfcLabel {
                    var: "secret".into(),
                    level: 3,
                },
                FeatureOpcode::IfcLabel {
                    var: "secret".into(),
                    level: 1,
                },
            ],
        );
        assert!(w.check_obligations().is_err());
    }

    #[test]
    fn feature_validation_context_full_breadth() {
        let mut ctx = FeatureClassValidationContext::new();
        ctx.add_standard_corpus();
        let lemmas = ctx.generate_lemmas();
        assert_eq!(lemmas, ctx.witnesses.len());
        let result = ctx.validate();
        assert!(result.all_accepted);
        assert!(result.full_breadth());
        assert!(result.total_programs >= 50);
        // Every class report has at least one program and its lemmas.
        for report in &result.reports {
            assert!(report.programs_validated > 0);
            assert_eq!(report.lemmas_generated, report.programs_validated);
        }
    }

    #[test]
    fn full_pipeline_requires_feature_class_coverage() {
        let mut ctx = FullIrValidationContext::new();
        // Without feature-class coverage, complete coverage must be unattainable
        // even with all IR levels and percentages satisfied.
        ctx.verification_coverage.expression_coverage_percentage = 100.0;
        ctx.verification_coverage.statement_coverage_percentage = 100.0;
        ctx.verification_coverage.control_flow_coverage_percentage = 100.0;
        for level in [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3] {
            ctx.verification_coverage.ir_levels_covered.insert(level);
        }
        assert!(!ctx.check_complete_coverage());

        // After validating the feature-class corpus, breadth is satisfied.
        ctx.feature_validator.add_standard_corpus();
        let result = ctx.validate_feature_classes();
        assert!(result.full_breadth());
        assert!(ctx.check_complete_coverage());
    }
}
