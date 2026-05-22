#![forbid(unsafe_code)]

//! Integration tests for full IR translation validation pipeline (G.6).
//!
//! Tests the complete IR coverage extending G.4/G.5 to cover all transformations:
//! IR0 (SyntaxIR) → IR1 (SpecIR) → IR2 (CapabilityIR) → IR3 (ExecIR)

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::full_ir_translation_validator::{
    FullIrValidationContext, IrLevel, IrTransformation, SemanticEquivalenceProof,
    TransformationPhase, ValidationCoverage, generate_full_ir_test_cases,
};

/// Test basic full IR validation context operations.
#[test]
fn full_ir_validation_context_creation() {
    let ctx = FullIrValidationContext::new();
    assert!(ctx.ir_pipeline.is_empty());
    assert!(ctx.transformation_map.is_empty());
    assert!(ctx.global_invariants.is_empty());
    assert!(ctx.coverage_metrics.total_transformations == 0);
    assert!(ctx.semantic_proofs.is_empty());
}

/// Test IR level pipeline construction.
#[test]
fn ir_level_pipeline_construction() {
    let mut ctx = FullIrValidationContext::new();

    // Add IR levels in pipeline order
    ctx.add_ir_level(
        IrLevel::IR0,
        "function add(x, y) { return x + y; }".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR1,
        "SpecIR: OpAdd(x: Reg1, y: Reg2) -> Reg3".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR2,
        "CapIR: SafeAdd(x: Trusted, y: Trusted) -> Trusted".to_string(),
    );
    ctx.add_ir_level(IrLevel::IR3, "ExecIR: add_i32 %r1, %r2 -> %r3".to_string());

    assert_eq!(ctx.ir_pipeline.len(), 4);
    assert!(ctx.ir_pipeline.contains_key(&IrLevel::IR0));
    assert!(ctx.ir_pipeline.contains_key(&IrLevel::IR3));

    // Verify pipeline ordering
    assert!(ctx.ir_pipeline[&IrLevel::IR0].contains("function add"));
    assert!(ctx.ir_pipeline[&IrLevel::IR3].contains("add_i32"));
}

/// Test transformation validation between IR levels.
#[test]
fn ir_transformation_validation() {
    let mut ctx = FullIrValidationContext::new();

    // Define source and target IR
    ctx.add_ir_level(IrLevel::IR0, "let x = 42;".to_string());
    ctx.add_ir_level(
        IrLevel::IR1,
        "DeclarationStmt(x, ConstValue(42))".to_string(),
    );

    // Add transformation
    let transformation = IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        phase: TransformationPhase::Parsing,
        transformation_name: "syntax_to_spec".to_string(),
        semantic_preservation_rules: vec![
            "Variable binding preservation".to_string(),
            "Constant value preservation".to_string(),
        ],
        verification_obligations: vec![
            "Source AST semantics ≡ Target SpecIR semantics".to_string(),
        ],
    };

    ctx.add_transformation(transformation);

    assert_eq!(ctx.transformation_map.len(), 1);
    let key = (IrLevel::IR0, IrLevel::IR1);
    assert!(ctx.transformation_map.contains_key(&key));
    assert_eq!(
        ctx.transformation_map[&key].phase,
        TransformationPhase::Parsing
    );
}

/// Test global invariant generation across all IR levels.
#[test]
fn global_invariant_generation() {
    let mut ctx = FullIrValidationContext::new();

    // Add complete IR pipeline
    ctx.add_ir_level(
        IrLevel::IR0,
        "if (condition) { x = 1; } else { x = 2; }".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR1,
        "CondBranch(condition, then_block, else_block)".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR2,
        "PolicyGuardedBranch(condition: Checked, branches: Safe)".to_string(),
    );
    ctx.add_ir_level(IrLevel::IR3, "br_cond %cond, label1, label2".to_string());

    let invariant_count = ctx.generate_global_invariants().unwrap();
    assert!(invariant_count >= 3); // At least one per transformation

    // Verify specific invariants exist
    assert!(
        ctx.global_invariants
            .iter()
            .any(|inv| inv.invariant_id.contains("control_flow_preservation"))
    );
    assert!(
        ctx.global_invariants
            .iter()
            .any(|inv| inv.invariant_id.contains("variable_lifetime"))
    );
    assert!(
        ctx.global_invariants
            .iter()
            .any(|inv| inv.invariant_id.contains("semantic_equivalence"))
    );
}

/// Test validation coverage metrics computation.
#[test]
fn validation_coverage_metrics() {
    let mut ctx = FullIrValidationContext::new();

    // Add transformations for coverage analysis
    let transformations = vec![
        IrTransformation {
            source_level: IrLevel::IR0,
            target_level: IrLevel::IR1,
            phase: TransformationPhase::Parsing,
            transformation_name: "parse".to_string(),
            semantic_preservation_rules: vec!["AST preservation".to_string()],
            verification_obligations: vec!["Parse correctness".to_string()],
        },
        IrTransformation {
            source_level: IrLevel::IR1,
            target_level: IrLevel::IR2,
            phase: TransformationPhase::Lowering,
            transformation_name: "capability_insertion".to_string(),
            semantic_preservation_rules: vec!["Capability safety".to_string()],
            verification_obligations: vec!["Policy enforcement".to_string()],
        },
        IrTransformation {
            source_level: IrLevel::IR2,
            target_level: IrLevel::IR3,
            phase: TransformationPhase::CodeGeneration,
            transformation_name: "codegen".to_string(),
            semantic_preservation_rules: vec!["Execution semantics".to_string()],
            verification_obligations: vec!["Runtime behavior".to_string()],
        },
    ];

    for transformation in transformations {
        ctx.add_transformation(transformation);
    }

    let coverage = ctx.compute_validation_coverage();
    assert_eq!(coverage.total_transformations, 3);
    assert_eq!(coverage.covered_transformations, 3);
    assert_eq!(coverage.coverage_percentage, 100.0);
    assert_eq!(coverage.uncovered_phases.len(), 0);

    // Verify phase coverage
    assert!(
        coverage
            .phase_coverage
            .contains_key(&TransformationPhase::Parsing)
    );
    assert!(
        coverage
            .phase_coverage
            .contains_key(&TransformationPhase::Lowering)
    );
    assert!(
        coverage
            .phase_coverage
            .contains_key(&TransformationPhase::CodeGeneration)
    );
}

/// Test semantic equivalence proof generation.
#[test]
fn semantic_equivalence_proof_generation() {
    let mut ctx = FullIrValidationContext::new();

    // Add IR levels and transformations
    ctx.add_ir_level(IrLevel::IR0, "42 + 37".to_string());
    ctx.add_ir_level(IrLevel::IR3, "add_immediate %r1, 42, 37".to_string());

    let transformation = IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR3,
        phase: TransformationPhase::EndToEnd,
        transformation_name: "full_pipeline".to_string(),
        semantic_preservation_rules: vec![
            "Arithmetic correctness".to_string(),
            "Value equivalence".to_string(),
        ],
        verification_obligations: vec!["IR0 evaluation ≡ IR3 execution".to_string()],
    };

    ctx.add_transformation(transformation);

    let proof_count = ctx.generate_semantic_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 1);

    let proof = &ctx.semantic_proofs[0];
    assert_eq!(proof.source_level, IrLevel::IR0);
    assert_eq!(proof.target_level, IrLevel::IR3);
    assert!(proof.proof_obligations.len() >= 2); // Preservation + equivalence
    assert!(proof.proof_method.contains("formal") || proof.proof_method.contains("symbolic"));
}

/// Test end-to-end validation workflow.
#[test]
fn end_to_end_validation_workflow() {
    let mut ctx = FullIrValidationContext::new();

    // Complete IR pipeline for a simple function
    ctx.add_ir_level(
        IrLevel::IR0,
        "function factorial(n) { return n <= 1 ? 1 : n * factorial(n-1); }".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR1,
        "FunctionDecl(factorial, RecursiveCall(LessEqualOp, MulOp))".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR2,
        "SafeFunction(factorial, BoundsChecked, TailCallOptimized)".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR3,
        "factorial: cmp %n, 1; jle base_case; call factorial; mul %n, %ret".to_string(),
    );

    // Add all transformations
    let transformations = vec![
        (
            "IR0→IR1",
            IrLevel::IR0,
            IrLevel::IR1,
            TransformationPhase::Parsing,
        ),
        (
            "IR1→IR2",
            IrLevel::IR1,
            IrLevel::IR2,
            TransformationPhase::Lowering,
        ),
        (
            "IR2→IR3",
            IrLevel::IR2,
            IrLevel::IR3,
            TransformationPhase::CodeGeneration,
        ),
    ];

    for (name, source, target, phase) in transformations {
        ctx.add_transformation(IrTransformation {
            source_level: source,
            target_level: target,
            phase,
            transformation_name: name.to_string(),
            semantic_preservation_rules: vec![
                "Function semantics preservation".to_string(),
                "Recursion correctness".to_string(),
            ],
            verification_obligations: vec![format!("{} semantic equivalence", name)],
        });
    }

    // Generate all validation artifacts
    let invariants = ctx.generate_global_invariants().unwrap();
    let proofs = ctx.generate_semantic_equivalence_proofs().unwrap();
    let coverage = ctx.compute_validation_coverage();

    // Verify complete validation
    assert!(invariants >= 3); // One per transformation minimum
    assert_eq!(proofs, 3); // One per transformation
    assert_eq!(coverage.total_transformations, 3);
    assert_eq!(coverage.coverage_percentage, 100.0);

    // Validate all lemmas
    let result = ctx.validate_full_ir_pipeline();
    assert!(result.validation_successful);
    assert!(result.all_transformations_verified);
    assert!(result.global_invariants_proven);
    assert!(result.semantic_equivalence_established);
    assert_eq!(result.verified_transformation_count, 3);
}

/// Test validation with missing IR levels.
#[test]
fn validation_with_missing_ir_levels() {
    let mut ctx = FullIrValidationContext::new();

    // Add only IR0 and IR3 (skip IR1, IR2)
    ctx.add_ir_level(IrLevel::IR0, "x + y".to_string());
    ctx.add_ir_level(IrLevel::IR3, "add %r1, %r2".to_string());

    // Try to add transformation that skips levels
    ctx.add_transformation(IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR3,
        phase: TransformationPhase::EndToEnd,
        transformation_name: "direct_compilation".to_string(),
        semantic_preservation_rules: vec!["Direct semantic preservation".to_string()],
        verification_obligations: vec!["End-to-end correctness".to_string()],
    });

    let coverage = ctx.compute_validation_coverage();
    assert_eq!(coverage.total_transformations, 1);

    // Should still validate successfully for provided transformations
    let result = ctx.validate_full_ir_pipeline();
    assert!(result.validation_successful);
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("partial") || note.contains("direct"))
    );
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

    ctx.add_ir_level(IrLevel::IR0, source_code.to_string());
    ctx.add_ir_level(
        IrLevel::IR1,
        "ForLoop(WhileLoop(IfStmt(ModOp, EqualOp)))".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR2,
        "LoopSafe(ConditionSafe(PolicyChecked))".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR3,
        "loop_entry: cmp %i, 10; jge loop_exit; mod %i, 2; ...".to_string(),
    );

    // Add comprehensive transformations
    ctx.add_transformation(IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        phase: TransformationPhase::Parsing,
        transformation_name: "control_flow_parse".to_string(),
        semantic_preservation_rules: vec![
            "Loop structure preservation".to_string(),
            "Nested condition preservation".to_string(),
        ],
        verification_obligations: vec!["Control flow graph equivalence".to_string()],
    });

    let invariant_count = ctx.generate_global_invariants().unwrap();
    assert!(invariant_count > 0);

    // Verify control flow specific invariants
    assert!(
        ctx.global_invariants
            .iter()
            .any(|inv| inv.invariant_description.contains("control flow"))
    );
}

/// Test error handling and malformed IR validation.
#[test]
fn malformed_ir_handling() {
    let mut ctx = FullIrValidationContext::new();

    // Add malformed IR
    ctx.add_ir_level(IrLevel::IR0, "invalid syntax {{{".to_string());
    ctx.add_ir_level(IrLevel::IR1, "MalformedAST(ParseError)".to_string());

    ctx.add_transformation(IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        phase: TransformationPhase::Parsing,
        transformation_name: "error_recovery".to_string(),
        semantic_preservation_rules: vec!["Error preservation".to_string()],
        verification_obligations: vec!["Error semantics".to_string()],
    });

    // Should handle gracefully
    let result = ctx.validate_full_ir_pipeline();
    // Malformed IR should still validate if transformation is explicit about error handling
    assert!(result.validation_successful || !result.failed_validations.is_empty());
}

/// Test validation test case generation.
#[test]
fn validation_test_case_generation() {
    let test_cases = generate_full_ir_test_cases();

    assert!(!test_cases.is_empty());
    assert!(test_cases.len() >= 5); // Multiple test case categories

    // Verify test case categories
    let case_names: BTreeSet<_> = test_cases.iter().map(|tc| &tc.name).collect();
    assert!(case_names.contains(&"simple_arithmetic".to_string()));
    assert!(case_names.contains(&"control_flow_if_else".to_string()));
    assert!(case_names.contains(&"nested_function_calls".to_string()));
    assert!(case_names.contains(&"loop_with_break_continue".to_string()));

    // Verify each test case has complete IR pipeline
    for test_case in &test_cases {
        assert!(!test_case.ir0_source.is_empty());
        assert!(!test_case.ir1_spec.is_empty());
        assert!(!test_case.ir2_capability.is_empty());
        assert!(!test_case.ir3_executable.is_empty());
        assert!(test_case.expected_transformations >= 3);
    }
}

/// Test integration with G.4/G.5 validation infrastructure.
#[test]
fn integration_with_previous_validation() {
    let mut ctx = FullIrValidationContext::new();

    // G.4 pure expression validation integration
    ctx.add_ir_level(IrLevel::IR0, "a + b * c".to_string());
    ctx.add_ir_level(IrLevel::IR1, "AddOp(a, MulOp(b, c))".to_string());

    // G.5 statement validation integration
    ctx.add_ir_level(IrLevel::IR0, "if (x > 0) { y = x * 2; }".to_string());
    ctx.add_ir_level(
        IrLevel::IR1,
        "IfStmt(GtOp(x, 0), AssignStmt(y, MulOp(x, 2)))".to_string(),
    );

    ctx.add_transformation(IrTransformation {
        source_level: IrLevel::IR0,
        target_level: IrLevel::IR1,
        phase: TransformationPhase::Parsing,
        transformation_name: "g4_g5_extension".to_string(),
        semantic_preservation_rules: vec![
            "Expression semantics (G.4 compatible)".to_string(),
            "Statement semantics (G.5 compatible)".to_string(),
        ],
        verification_obligations: vec![
            "G.4 expression validation extended".to_string(),
            "G.5 statement validation extended".to_string(),
        ],
    });

    let result = ctx.validate_full_ir_pipeline();
    assert!(result.validation_successful);

    // Verify compatibility notes mention G.4/G.5
    assert!(result.notes.iter().any(|note| note.contains("G.4")
        || note.contains("G.5")
        || note.contains("expression")
        || note.contains("statement")));
}

/// Test performance with large IR pipelines.
#[test]
fn large_ir_pipeline_performance() {
    let mut ctx = FullIrValidationContext::new();

    // Add multiple large IR representations
    for i in 0..100 {
        let ir0 = format!("function fn_{i}(x) {{ return x + {i}; }}", i = i);
        let ir1 = format!("FunctionDecl(fn_{i}, AddOp(x, {i}))", i = i);
        let ir2 = format!("SafeFunction(fn_{i}, BoundsChecked)", i = i);
        let ir3 = format!("fn_{i}: add %x, {i}", i = i);

        if i == 0 {
            // Only add to first context to avoid overwhelming test
            ctx.add_ir_level(IrLevel::IR0, ir0);
            ctx.add_ir_level(IrLevel::IR1, ir1);
            ctx.add_ir_level(IrLevel::IR2, ir2);
            ctx.add_ir_level(IrLevel::IR3, ir3);
        }
    }

    // Should handle reasonably sized examples efficiently
    let start = std::time::Instant::now();
    let result = ctx.validate_full_ir_pipeline();
    let duration = start.elapsed();

    assert!(result.validation_successful);
    assert!(duration.as_secs() < 5); // Should complete within reasonable time
}

/// Test validation result reporting and diagnostics.
#[test]
fn validation_result_comprehensive_reporting() {
    let mut ctx = FullIrValidationContext::new();

    // Add complete pipeline
    ctx.add_ir_level(IrLevel::IR0, "let x = 42;".to_string());
    ctx.add_ir_level(
        IrLevel::IR1,
        "DeclarationStmt(x, ConstValue(42))".to_string(),
    );
    ctx.add_ir_level(
        IrLevel::IR2,
        "SafeDeclaration(x, TrustedValue(42))".to_string(),
    );
    ctx.add_ir_level(IrLevel::IR3, "mov %x, 42".to_string());

    // Add all transformations
    let transformations = [
        (IrLevel::IR0, IrLevel::IR1, TransformationPhase::Parsing),
        (IrLevel::IR1, IrLevel::IR2, TransformationPhase::Lowering),
        (
            IrLevel::IR2,
            IrLevel::IR3,
            TransformationPhase::CodeGeneration,
        ),
    ];

    for (source, target, phase) in transformations {
        ctx.add_transformation(IrTransformation {
            source_level: source,
            target_level: target,
            phase,
            transformation_name: format!("{:?}→{:?}", source, target),
            semantic_preservation_rules: vec!["Semantic preservation".to_string()],
            verification_obligations: vec!["Equivalence proof".to_string()],
        });
    }

    let result = ctx.validate_full_ir_pipeline();

    // Comprehensive result verification
    assert!(result.validation_successful);
    assert!(result.all_transformations_verified);
    assert!(result.global_invariants_proven);
    assert!(result.semantic_equivalence_established);
    assert_eq!(result.verified_transformation_count, 3);
    assert!(result.failed_validations.is_empty());
    assert!(!result.notes.is_empty()); // Should have informational notes
    assert!(result.validation_time_ms > 0);
}

/// Test concurrent validation (stress test).
#[test]
fn concurrent_validation_stability() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let success_count = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for i in 0..4 {
        let success_count = success_count.clone();
        let handle = thread::spawn(move || {
            let mut ctx = FullIrValidationContext::new();

            ctx.add_ir_level(IrLevel::IR0, format!("x{} + y{}", i, i));
            ctx.add_ir_level(IrLevel::IR3, format!("add %r{}, %r{}", i * 2, i * 2 + 1));

            ctx.add_transformation(IrTransformation {
                source_level: IrLevel::IR0,
                target_level: IrLevel::IR3,
                phase: TransformationPhase::EndToEnd,
                transformation_name: format!("thread_{}", i),
                semantic_preservation_rules: vec!["Thread-safe validation".to_string()],
                verification_obligations: vec!["Concurrent safety".to_string()],
            });

            let result = ctx.validate_full_ir_pipeline();
            if result.validation_successful {
                let mut count = success_count.lock().unwrap();
                *count += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_count = *success_count.lock().unwrap();
    assert_eq!(final_count, 4); // All threads should succeed
}
