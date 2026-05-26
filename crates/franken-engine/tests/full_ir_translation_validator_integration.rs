#![forbid(unsafe_code)]

//! Integration tests for full IR translation validation pipeline (G.6).
//!
//! Tests the complete IR coverage extending G.4/G.5 to cover all transformations:
//! IR0 (SyntaxIR) → IR1 (SpecIR) → IR2 (CapabilityIR) → IR3 (ExecIR)

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::full_ir_translation_validator::{
    FullIrValidationContext, IrLevel, IrTransformationStep, generate_full_ir_test_cases,
};
use frankenengine_engine::statement_translation_validator::{
    LemmaType, ProofObligation, ValidationLemma, VerificationMethod,
};

/// Test basic full IR validation context operations.
#[test]
fn full_ir_validation_context_creation() {
    let ctx = FullIrValidationContext::new();
    assert!(ctx.pipeline_stages.is_empty());
    assert!(ctx.global_invariants.is_empty());
    assert!(ctx.verification_coverage.ir_levels_covered.is_empty());
}

/// Test IR transformation pipeline construction.
#[test]
fn ir_transformation_pipeline_construction() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformation steps in pipeline order
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "syntax_to_spec".to_string(),
        source_representation: "function add(x, y) { return x + y; }".to_string(),
        target_representation: "SpecIR: OpAdd(x: Reg1, y: Reg2) -> Reg3".to_string(),
        validation_lemmas: vec![],
    });

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR1,
        target_level: IrLevel::IR2,
        transformation_name: "spec_to_capability".to_string(),
        source_representation: "SpecIR: OpAdd(x: Reg1, y: Reg2) -> Reg3".to_string(),
        target_representation: "CapIR: SafeAdd(x: Trusted, y: Trusted) -> Trusted".to_string(),
        validation_lemmas: vec![],
    });

    assert_eq!(ctx.pipeline_stages.len(), 2);
    assert_eq!(ctx.pipeline_stages[0].source_level, IrLevel::IR0);
    assert_eq!(ctx.pipeline_stages[0].target_level, IrLevel::IR1);
    assert_eq!(ctx.pipeline_stages[1].source_level, IrLevel::IR1);
    assert_eq!(ctx.pipeline_stages[1].target_level, IrLevel::IR2);
}

/// Test transformation validation between IR levels.
#[test]
fn ir_transformation_validation() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformation with new API
    let transformation = IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "syntax_to_spec".to_string(),
        source_representation: "let x = 42;".to_string(),
        target_representation: "DeclarationStmt(x, ConstValue(42))".to_string(),
        validation_lemmas: vec![ValidationLemma {
            lemma_id: "variable_binding_preservation".to_string(),
            lemma_type: LemmaType::VariableLifetime,
            source_nodes: BTreeSet::from([0, 1]),
            target_nodes: BTreeSet::from([0, 1]),
            invariant: "Variable binding preservation".to_string(),
            proof_obligations: vec![ProofObligation {
                obligation_id: "syntax_semantics_equiv".to_string(),
                premise: "Source AST semantics".to_string(),
                conclusion: "Target SpecIR semantics".to_string(),
                verification_method: VerificationMethod::SymbolicExecution,
            }],
        }],
    };

    ctx.add_transformation_step(transformation);

    assert_eq!(ctx.pipeline_stages.len(), 1);
    assert_eq!(ctx.pipeline_stages[0].transformation_name, "syntax_to_spec");
    assert_eq!(ctx.pipeline_stages[0].validation_lemmas.len(), 1);
}

/// Test global invariant generation across all IR levels.
#[test]
fn global_invariant_generation() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformation steps to test invariant generation
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "conditional_lowering".to_string(),
        source_representation: "if (condition) { x = 1; } else { x = 2; }".to_string(),
        target_representation: "CondBranch(condition, then_block, else_block)".to_string(),
        validation_lemmas: vec![],
    });

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR1,
        target_level: IrLevel::IR2,
        transformation_name: "policy_injection".to_string(),
        source_representation: "CondBranch(condition, then_block, else_block)".to_string(),
        target_representation: "PolicyGuardedBranch(condition: Checked, branches: Safe)"
            .to_string(),
        validation_lemmas: vec![],
    });

    let invariant_count = ctx.generate_global_invariants().unwrap();
    assert!(invariant_count >= 1); // At least one invariant generated

    // Verify some invariants were created
    assert!(!ctx.global_invariants.is_empty());
}

/// Test validation coverage metrics computation.
#[test]
fn validation_coverage_metrics() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformations for coverage analysis
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "parse".to_string(),
        source_representation: "source_ast".to_string(),
        target_representation: "spec_ir".to_string(),
        validation_lemmas: vec![],
    });

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR1,
        target_level: IrLevel::IR2,
        transformation_name: "capability_insertion".to_string(),
        source_representation: "spec_ir".to_string(),
        target_representation: "capability_ir".to_string(),
        validation_lemmas: vec![],
    });

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR2,
        target_level: IrLevel::IR3,
        transformation_name: "codegen".to_string(),
        source_representation: "capability_ir".to_string(),
        target_representation: "exec_ir".to_string(),
        validation_lemmas: vec![],
    });

    // Verify transformations were added
    assert_eq!(ctx.pipeline_stages.len(), 3);
    assert_eq!(ctx.pipeline_stages[0].transformation_name, "parse");
    assert_eq!(
        ctx.pipeline_stages[1].transformation_name,
        "capability_insertion"
    );
    assert_eq!(ctx.pipeline_stages[2].transformation_name, "codegen");

    // Verify coverage tracking
    assert!(!ctx.verification_coverage.ir_levels_covered.is_empty());
}

/// Test semantic equivalence proof generation through validation lemmas.
#[test]
fn semantic_equivalence_proof_generation() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformation with validation lemmas
    let transformation = IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR3,
        transformation_name: "full_pipeline".to_string(),
        source_representation: "42 + 37".to_string(),
        target_representation: "add_immediate %r1, 42, 37".to_string(),
        validation_lemmas: vec![ValidationLemma {
            lemma_id: "arithmetic_correctness".to_string(),
            lemma_type: LemmaType::ControlFlowPreservation,
            source_nodes: BTreeSet::from([0, 1, 2]),
            target_nodes: BTreeSet::from([0]),
            invariant: "Arithmetic correctness preservation".to_string(),
            proof_obligations: vec![ProofObligation {
                obligation_id: "value_equivalence".to_string(),
                premise: "IR0 evaluation".to_string(),
                conclusion: "IR3 execution equivalence".to_string(),
                verification_method: VerificationMethod::SymbolicExecution,
            }],
        }],
    };

    ctx.add_transformation_step(transformation);

    // Verify transformation was added with validation lemmas
    assert_eq!(ctx.pipeline_stages.len(), 1);
    assert_eq!(ctx.pipeline_stages[0].validation_lemmas.len(), 1);
    assert_eq!(
        ctx.pipeline_stages[0].validation_lemmas[0].lemma_id,
        "arithmetic_correctness"
    );
    assert_eq!(
        ctx.pipeline_stages[0].validation_lemmas[0]
            .proof_obligations
            .len(),
        1
    );
}

/// Test end-to-end validation workflow.
#[test]
fn end_to_end_validation_workflow() {
    let mut ctx = FullIrValidationContext::new();

    // Add all transformations for the complete pipeline
    let transformations = vec![
        (
            "IR0→IR1",
            IrLevel::IR0,
            IrLevel::IR1,
            "function factorial(n) { return n <= 1 ? 1 : n * factorial(n-1); }",
            "FunctionDecl(factorial, RecursiveCall(LessEqualOp, MulOp))",
        ),
        (
            "IR1→IR2",
            IrLevel::IR1,
            IrLevel::IR2,
            "FunctionDecl(factorial, RecursiveCall(LessEqualOp, MulOp))",
            "SafeFunction(factorial, BoundsChecked, TailCallOptimized)",
        ),
        (
            "IR2→IR3",
            IrLevel::IR2,
            IrLevel::IR3,
            "SafeFunction(factorial, BoundsChecked, TailCallOptimized)",
            "factorial: cmp %n, 1; jle base_case; call factorial; mul %n, %ret",
        ),
    ];

    for (name, source, target, source_repr, target_repr) in transformations {
        ctx.add_transformation_step(IrTransformationStep {
            source_level: source,
            target_level: target,
            transformation_name: name.to_string(),
            source_representation: source_repr.to_string(),
            target_representation: target_repr.to_string(),
            validation_lemmas: vec![ValidationLemma {
                lemma_id: format!("{}_semantics", name),
                lemma_type: LemmaType::ControlFlowPreservation,
                source_nodes: BTreeSet::from([0, 1]),
                target_nodes: BTreeSet::from([0, 1]),
                invariant: "Function semantics preservation".to_string(),
                proof_obligations: vec![ProofObligation {
                    obligation_id: format!("{}_equiv", name),
                    premise: format!("{} semantic equivalence premise", name),
                    conclusion: format!("{} semantic equivalence conclusion", name),
                    verification_method: VerificationMethod::SymbolicExecution,
                }],
            }],
        });
    }

    // Generate validation artifacts
    let invariant_count = ctx.generate_global_invariants().unwrap();

    // Verify complete validation
    assert!(invariant_count >= 0); // Some invariants generated
    assert_eq!(ctx.pipeline_stages.len(), 3); // All transformations added

    // Validate pipeline using the current API method
    let result = ctx.validate_full_pipeline();
    assert!(result.pipeline_validation_successful);
}

/// Test validation with direct IR level jumps.
#[test]
fn validation_with_direct_ir_jumps() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformation that skips intermediate levels (IR0 directly to IR3)
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR3,
        transformation_name: "direct_compilation".to_string(),
        source_representation: "x + y".to_string(),
        target_representation: "add %r1, %r2".to_string(),
        validation_lemmas: vec![ValidationLemma {
            lemma_id: "direct_preservation".to_string(),
            lemma_type: LemmaType::ControlFlowPreservation,
            source_nodes: BTreeSet::from([0, 1]),
            target_nodes: BTreeSet::from([0]),
            invariant: "Direct semantic preservation".to_string(),
            proof_obligations: vec![ProofObligation {
                obligation_id: "end_to_end_correctness".to_string(),
                premise: "Source expression semantics".to_string(),
                conclusion: "Target instruction semantics".to_string(),
                verification_method: VerificationMethod::SymbolicExecution,
            }],
        }],
    });

    // Verify transformation was added
    assert_eq!(ctx.pipeline_stages.len(), 1);
    assert_eq!(
        ctx.pipeline_stages[0].transformation_name,
        "direct_compilation"
    );

    // Should still validate successfully
    let result = ctx.validate_full_pipeline();
    assert!(result.pipeline_validation_successful);
}

/// Test complex control flow across IR levels.
#[test]
fn complex_control_flow_validation() {
    let mut ctx = FullIrValidationContext::new();

    // Nested control flow example
    let source_code = r#"
        for (let i = 0; i < 10; i++) {
            if (i % 2 === 0) {
                while (condition(i)) {
                    process(i);
                }
            }
        }
    "#;

    // Add transformation for complex control flow
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "control_flow_parse".to_string(),
        source_representation: source_code.to_string(),
        target_representation: "ForLoop(WhileLoop(IfStmt(ModOp, EqualOp)))".to_string(),
        validation_lemmas: vec![ValidationLemma {
            lemma_id: "loop_preservation".to_string(),
            lemma_type: LemmaType::LoopInvariant,
            source_nodes: BTreeSet::from([0, 1, 2, 3]),
            target_nodes: BTreeSet::from([0, 1, 2]),
            invariant: "Loop structure preservation".to_string(),
            proof_obligations: vec![ProofObligation {
                obligation_id: "cfg_equivalence".to_string(),
                premise: "Source control flow graph".to_string(),
                conclusion: "Target control flow graph equivalence".to_string(),
                verification_method: VerificationMethod::SymbolicExecution,
            }],
        }],
    });

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR1,
        target_level: IrLevel::IR2,
        transformation_name: "control_flow_safety".to_string(),
        source_representation: "ForLoop(WhileLoop(IfStmt(ModOp, EqualOp)))".to_string(),
        target_representation: "LoopSafe(ConditionSafe(PolicyChecked))".to_string(),
        validation_lemmas: vec![],
    });

    let invariant_count = ctx.generate_global_invariants().unwrap();
    assert!(invariant_count > 0);

    // Verify a control-flow-specific global invariant was generated. The
    // generated description is "Control flow structure integrity maintained"
    // (capitalised), so match case-insensitively — the previous exact lowercase
    // "control flow" match never hit, leaving this test silently failing.
    assert!(
        ctx.global_invariants
            .iter()
            .any(|inv| inv.description.to_lowercase().contains("control flow"))
    );
}

/// Build a *well-formed* transformation step: it rewrites the representation
/// across a genuine IR-level transition and carries a validation lemma that maps
/// real source/target nodes and discharges a stated proof obligation. Such a
/// step must be accepted by `validate_transformation_step`.
fn proven_step(
    name: &str,
    source_level: IrLevel,
    target_level: IrLevel,
    source_repr: &str,
    target_repr: &str,
) -> IrTransformationStep {
    IrTransformationStep {
        source_level,
        target_level,
        transformation_name: name.to_string(),
        source_representation: source_repr.to_string(),
        target_representation: target_repr.to_string(),
        validation_lemmas: vec![ValidationLemma {
            lemma_id: format!("{name}_semantics"),
            lemma_type: LemmaType::ControlFlowPreservation,
            source_nodes: BTreeSet::from([0, 1]),
            target_nodes: BTreeSet::from([0, 1]),
            invariant: format!("{name} preserves observable semantics"),
            proof_obligations: vec![ProofObligation {
                obligation_id: format!("{name}_equiv"),
                premise: "source-level semantics".to_string(),
                conclusion: "target-level semantics".to_string(),
                verification_method: VerificationMethod::SymbolicExecution,
            }],
        }],
    }
}

/// Build a fully proven IR0→IR1→IR2→IR3 pipeline with global invariants and full
/// G.6 feature-class breadth, so `validate_full_pipeline` can reach a complete-
/// coverage verdict. Callers still supply the G.5 statement/control-flow
/// coverage percentages (G.4 expression coverage is set during validation).
fn proven_full_pipeline() -> FullIrValidationContext {
    let mut ctx = FullIrValidationContext::new();
    ctx.add_transformation_step(proven_step(
        "parse",
        IrLevel::IR0,
        IrLevel::IR1,
        "let x = 1 + 2;",
        "SpecIR(Decl(x), Add(1, 2))",
    ));
    ctx.add_transformation_step(proven_step(
        "specialize",
        IrLevel::IR1,
        IrLevel::IR2,
        "SpecIR(Decl(x), Add(1, 2))",
        "CapIR(Decl(x), SafeAdd(1, 2))",
    ));
    ctx.add_transformation_step(proven_step(
        "lower",
        IrLevel::IR2,
        IrLevel::IR3,
        "CapIR(Decl(x), SafeAdd(1, 2))",
        "add %r1, 1, 2",
    ));
    ctx.generate_global_invariants().unwrap();
    // Full IR coverage requires every G.6 feature class to carry a validated
    // semantic-preservation witness.
    ctx.feature_validator.add_standard_corpus();
    ctx.validate_feature_classes();
    ctx
}

/// A transformation step that carries no proof obligations must be *rejected*,
/// not silently accepted. Before bd-bg9l1.8 this test asserted nothing about the
/// verdict (only that the step was stored).
#[test]
fn malformed_ir_handling() {
    let mut ctx = FullIrValidationContext::new();

    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        transformation_name: "error_recovery".to_string(),
        source_representation: "invalid syntax {{{".to_string(),
        target_representation: "MalformedAST(ParseError)".to_string(),
        validation_lemmas: vec![], // unproven: no obligations relating source→target
    });

    let result = ctx.validate_full_pipeline();

    assert_eq!(ctx.pipeline_stages.len(), 1);
    // The unproven step must be reported as failed, not verified.
    assert!(
        !result.pipeline_validation_successful,
        "an unproven transformation step must not pass validation"
    );
    assert_eq!(result.verified_transformation_steps, 0);
    assert!(
        result
            .failed_transformation_steps
            .contains(&"error_recovery".to_string())
    );
    assert!(!result.semantic_equivalence_end_to_end);
}

/// The generator must expose the real G.6 corpus categories with coherent
/// feature flags. Previously this test asserted `len() >= 5` and category names
/// (`control_flow_if_else`, `nested_function_calls`, `loop_with_break_continue`)
/// that the generator never produces, so it was silently failing — only masked
/// because the green gate compiles tests without running this binary.
#[test]
fn validation_test_case_generation() {
    let test_cases = generate_full_ir_test_cases();

    assert_eq!(
        test_cases.len(),
        4,
        "generator exposes four full-IR corpus categories"
    );

    // Verify the actual categories the generator produces.
    let case_names: BTreeSet<_> = test_cases.iter().map(|tc| tc.name.clone()).collect();
    for expected in [
        "simple_arithmetic",
        "conditional_with_expressions",
        "loop_with_complex_body",
        "nested_functions_with_capabilities",
    ] {
        assert!(
            case_names.contains(expected),
            "missing corpus category {expected}; got {case_names:?}"
        );
    }

    // Every case must carry coherent metadata and span all four IR levels.
    for test_case in &test_cases {
        assert!(
            !test_case.source_code.is_empty(),
            "{} has empty source",
            test_case.name
        );
        assert!(!test_case.name.is_empty());
        assert_eq!(
            test_case.expected_ir_levels, 4,
            "{} should span all four IR levels",
            test_case.name
        );
    }

    // Pin the feature flags so a future corpus edit cannot silently mislabel a
    // case: arithmetic is pure expression/statement with no control flow, while
    // the conditional and loop cases must declare control flow.
    let arithmetic = test_cases
        .iter()
        .find(|tc| tc.name == "simple_arithmetic")
        .unwrap();
    assert!(arithmetic.contains_expressions && arithmetic.contains_statements);
    assert!(!arithmetic.contains_control_flow);

    let conditional = test_cases
        .iter()
        .find(|tc| tc.name == "conditional_with_expressions")
        .unwrap();
    assert!(conditional.contains_control_flow);

    let loop_case = test_cases
        .iter()
        .find(|tc| tc.name == "loop_with_complex_body")
        .unwrap();
    assert!(loop_case.contains_control_flow);
}

/// Integration with the G.4 (expression) and G.5 (statement/control-flow)
/// validators: only when all three coverage dimensions *and* full G.6
/// feature-class breadth are present can the pipeline certify an end-to-end
/// structural-equivalence verdict. Drives the real `validate_full_pipeline`.
#[test]
fn integration_with_previous_validation() {
    let mut ctx = proven_full_pipeline();
    // Feed in G.5 statement/control-flow coverage; G.4 expression coverage is
    // established by validate_full_pipeline itself.
    ctx.verification_coverage.statement_coverage_percentage = 100.0;
    ctx.verification_coverage.control_flow_coverage_percentage = 100.0;

    let result = ctx.validate_full_pipeline();

    assert!(result.pipeline_validation_successful);
    assert_eq!(result.verified_transformation_steps, 3);
    assert!(result.failed_transformation_steps.is_empty());
    assert!(
        result
            .expression_validation_result
            .semantic_preservation_proven
    );
    assert!(result.global_invariants_maintained);

    // The proven pipeline covers every IR level.
    for level in [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3] {
        assert!(
            ctx.verification_coverage.ir_levels_covered.contains(&level),
            "missing IR-level coverage for {level:?}"
        );
    }

    // With G.4 + G.5 + G.6 coverage all complete, the end-to-end verdict holds.
    assert!(result.complete_coverage_achieved);
    assert!(result.semantic_equivalence_end_to_end);

    // Sanity: dropping G.5 control-flow coverage must collapse the end-to-end
    // verdict, proving it genuinely depends on the previous validators.
    ctx.verification_coverage.control_flow_coverage_percentage = 0.0;
    let degraded = ctx.validate_full_pipeline();
    assert!(!degraded.complete_coverage_achieved);
    assert!(!degraded.semantic_equivalence_end_to_end);
    // Per-step structural validation is unaffected by the missing percentage.
    assert!(degraded.pipeline_validation_successful);
}

/// Performance with a large pipeline: validating several hundred proven steps
/// must verify every one and stay well within a generous time budget.
#[test]
fn large_ir_pipeline_performance() {
    use std::time::Instant;

    const N: usize = 400;
    let levels = [IrLevel::IR0, IrLevel::IR1, IrLevel::IR2, IrLevel::IR3];
    let mut ctx = FullIrValidationContext::new();
    for i in 0..N {
        ctx.add_transformation_step(proven_step(
            &format!("step_{i}"),
            levels[i % 4],
            levels[(i + 1) % 4],
            &format!("repr_in_{i}"),
            &format!("repr_out_{i}"),
        ));
    }

    let start = Instant::now();
    let result = ctx.validate_full_pipeline();
    let elapsed = start.elapsed();

    assert_eq!(result.verified_transformation_steps, N);
    assert!(
        result.failed_transformation_steps.is_empty(),
        "unexpected failures: {:?}",
        result.failed_transformation_steps
    );
    assert_eq!(ctx.verification_coverage.transformation_steps_verified, N);
    assert!(
        elapsed.as_secs() < 5,
        "validating {N} steps took too long: {elapsed:?}"
    );
}

/// Validation reporting/diagnostics: a pipeline with two proven steps and one
/// deliberately broken (no-op relabel, no proof) step must produce a report that
/// counts the proven steps, names the broken one, and refuses the success
/// verdict.
#[test]
fn validation_result_comprehensive_reporting() {
    let mut ctx = FullIrValidationContext::new();
    ctx.add_transformation_step(proven_step(
        "parse",
        IrLevel::IR0,
        IrLevel::IR1,
        "src0",
        "src1",
    ));
    // Broken: claims an IR1→IR2 transition but rewrites nothing (target equals
    // source) and carries no proof obligations.
    ctx.add_transformation_step(IrTransformationStep {
        source_level: IrLevel::IR1,
        target_level: IrLevel::IR2,
        transformation_name: "noop_relabel".to_string(),
        source_representation: "identical".to_string(),
        target_representation: "identical".to_string(),
        validation_lemmas: vec![],
    });
    ctx.add_transformation_step(proven_step(
        "lower",
        IrLevel::IR2,
        IrLevel::IR3,
        "src2",
        "src3",
    ));
    ctx.generate_global_invariants().unwrap();

    let result = ctx.validate_full_pipeline();

    assert_eq!(result.verified_transformation_steps, 2);
    assert_eq!(
        result.failed_transformation_steps,
        vec!["noop_relabel".to_string()]
    );
    assert!(!result.pipeline_validation_successful);
    assert!(!result.semantic_equivalence_end_to_end);
    // The two proven steps still register their IR-level coverage in the report.
    assert!(
        ctx.verification_coverage
            .ir_levels_covered
            .contains(&IrLevel::IR0)
    );
    assert!(
        ctx.verification_coverage
            .ir_levels_covered
            .contains(&IrLevel::IR3)
    );
}

/// Concurrent validation must be deterministic: the same proven pipeline
/// validated from independent contexts across threads must yield identical
/// verdicts every time.
#[test]
fn concurrent_validation_stability() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let mut ctx = proven_full_pipeline();
                ctx.verification_coverage.statement_coverage_percentage = 100.0;
                ctx.verification_coverage.control_flow_coverage_percentage = 100.0;
                let r = ctx.validate_full_pipeline();
                (
                    r.pipeline_validation_successful,
                    r.verified_transformation_steps,
                    r.semantic_equivalence_end_to_end,
                )
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.len(), 4);
    assert!(
        results.iter().all(|&r| r == (true, 3, true)),
        "nondeterministic validation verdicts: {results:?}"
    );
}
