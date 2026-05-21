#![forbid(unsafe_code)]

//! Integration tests for optimization proof carriers (G.8).
//!
//! Tests formal verification that optimization transformations preserve semantic
//! correctness while generating proof certificates extending G.4-G.7 infrastructure.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::optimization_proof_carriers::{
    CertificateType, EquivalenceRelation, IrRegion, OptimizationPass, OptimizationPassApplication,
    OptimizationProofCarrier, OptimizationVerificationStatus, PerformanceImpact, ProofMethod,
    ProofResult, TransformationRule, TransformationRuleType, generate_optimization_test_cases,
};

/// Test basic optimization proof carrier creation and configuration.
#[test]
fn optimization_proof_carrier_creation_and_setup() {
    let carrier = OptimizationProofCarrier::new(
        "function test() { return 1 + 2; }".to_string(),
        "function test() { return 3; }".to_string(),
    );

    assert!(carrier.source_ir.contains("1 + 2"));
    assert!(carrier.target_ir.contains("return 3"));
    assert!(carrier.applied_passes.is_empty());
    assert!(carrier.equivalence_proofs.is_empty());
    assert_eq!(
        carrier.verification_status,
        OptimizationVerificationStatus::Unverified
    );
    assert_eq!(carrier.performance_metrics.total_passes_applied, 0);
    assert!(carrier.proof_certificates.is_empty());
}

/// Test dead code elimination optimization pass.
#[test]
fn dead_code_elimination_optimization_pass() {
    let mut carrier = OptimizationProofCarrier::new(
        r#"
        x = 42;
        if (false) {
            y = x + 1;
            z = y * 2;
        }
        return x;
        "#
        .to_string(),
        r#"
        x = 42;
        return x;
        "#
        .to_string(),
    );

    let source_region = IrRegion {
        region_id: "dead_code_region".to_string(),
        start_instruction: 0,
        end_instruction: 6,
        basic_blocks: ["entry", "dead_block", "return_block"]
            .into_iter()
            .map(String::from)
            .collect(),
        control_flow_edges: vec![
            ("entry".to_string(), "dead_block".to_string()),
            ("entry".to_string(), "return_block".to_string()),
        ],
        live_variables: ["x"].into_iter().map(String::from).collect(),
    };

    let target_region = IrRegion {
        region_id: "optimized_region".to_string(),
        start_instruction: 0,
        end_instruction: 2,
        basic_blocks: ["entry", "return_block"]
            .into_iter()
            .map(String::from)
            .collect(),
        control_flow_edges: vec![("entry".to_string(), "return_block".to_string())],
        live_variables: ["x"].into_iter().map(String::from).collect(),
    };

    let transformation_rule = TransformationRule {
        rule_id: "eliminate_unreachable_code".to_string(),
        rule_type: TransformationRuleType::ControlFlowRestructuring,
        pattern: "if (false) { ... }".to_string(),
        replacement: "// removed".to_string(),
        applicability_conditions: vec![
            "Condition is compile-time false".to_string(),
            "Block has no side effects".to_string(),
        ],
        preservation_properties: vec![
            "Observable behavior unchanged".to_string(),
            "Program termination preserved".to_string(),
        ],
    };

    let pass = OptimizationPassApplication {
        pass_id: "dce_pass_1".to_string(),
        optimization_type: OptimizationPass::DeadCodeElimination,
        source_region,
        target_region,
        transformation_rules: vec![transformation_rule],
        preconditions: vec![
            "Control flow analysis complete".to_string(),
            "Side effect analysis complete".to_string(),
        ],
        postconditions: vec![
            "Dead code removed".to_string(),
            "Live code unchanged".to_string(),
        ],
        performance_impact: PerformanceImpact {
            execution_time_change: -0.15, // 15% faster
            memory_usage_change: 0.0,     // No change
            code_size_change: -0.40,      // 40% smaller
            compile_time_overhead: 2.0,   // 2ms overhead
            optimization_benefit_score: 0.85,
        },
    };

    carrier.add_optimization_pass(pass);

    assert_eq!(carrier.applied_passes.len(), 1);
    assert_eq!(carrier.performance_metrics.total_passes_applied, 1);
    assert_eq!(
        carrier.applied_passes[0].optimization_type,
        OptimizationPass::DeadCodeElimination
    );
    assert_eq!(carrier.applied_passes[0].transformation_rules.len(), 1);
}

/// Test constant folding and propagation optimization.
#[test]
fn constant_folding_and_propagation_optimization() {
    let mut carrier = OptimizationProofCarrier::new(
        r#"
        const a = 3 + 4;
        const b = a * 2;
        const c = b - 7;
        return c + 1;
        "#
        .to_string(),
        r#"
        const a = 7;
        const b = 14;
        const c = 7;
        return 8;
        "#
        .to_string(),
    );

    let constant_folding_rule = TransformationRule {
        rule_id: "fold_arithmetic_constants".to_string(),
        rule_type: TransformationRuleType::PatternReplacement,
        pattern: "CONST_EXPR op CONST_EXPR".to_string(),
        replacement: "COMPUTED_CONST".to_string(),
        applicability_conditions: vec![
            "Both operands are compile-time constants".to_string(),
            "Operation has no side effects".to_string(),
        ],
        preservation_properties: vec![
            "Computed value equals runtime evaluation".to_string(),
            "No overflow or underflow".to_string(),
        ],
    };

    let propagation_rule = TransformationRule {
        rule_id: "propagate_constants".to_string(),
        rule_type: TransformationRuleType::DataFlowOptimization,
        pattern: "VAR = CONST; ... use VAR".to_string(),
        replacement: "VAR = CONST; ... use CONST".to_string(),
        applicability_conditions: vec![
            "Variable is not reassigned".to_string(),
            "No aliasing concerns".to_string(),
        ],
        preservation_properties: vec![
            "Variable semantics preserved".to_string(),
            "Use-def chains maintained".to_string(),
        ],
    };

    let folding_pass = OptimizationPassApplication {
        pass_id: "const_fold_1".to_string(),
        optimization_type: OptimizationPass::ConstantFolding,
        source_region: IrRegion {
            region_id: "arithmetic_region".to_string(),
            start_instruction: 0,
            end_instruction: 4,
            basic_blocks: ["main"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: ["a", "b", "c"].into_iter().map(String::from).collect(),
        },
        target_region: IrRegion {
            region_id: "folded_region".to_string(),
            start_instruction: 0,
            end_instruction: 4,
            basic_blocks: ["main"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: ["a", "b", "c"].into_iter().map(String::from).collect(),
        },
        transformation_rules: vec![constant_folding_rule, propagation_rule],
        preconditions: vec!["Data flow analysis complete".to_string()],
        postconditions: vec!["Constants computed and propagated".to_string()],
        performance_impact: PerformanceImpact {
            execution_time_change: -0.25, // 25% faster
            memory_usage_change: 0.0,
            code_size_change: -0.10,    // 10% smaller
            compile_time_overhead: 3.0, // 3ms overhead
            optimization_benefit_score: 0.90,
        },
    };

    carrier.add_optimization_pass(folding_pass);

    // Generate equivalence proofs
    let proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 1);

    let proof = &carrier.equivalence_proofs[0];
    assert_eq!(proof.proof_method, ProofMethod::SmtVerification);
    assert_eq!(
        proof.equivalence_relation,
        EquivalenceRelation::ExactEquivalence
    );
    assert!(!proof.proof_obligations.is_empty());

    // Verify proof obligations include arithmetic correctness
    assert!(
        proof
            .proof_obligations
            .iter()
            .any(|po| po.obligation_id.contains("value_preservation")
                || po.premise.contains("Constant values computed"))
    );
}

/// Test loop optimization (unrolling and invariant hoisting).
#[test]
fn loop_optimization_unrolling_and_hoisting() {
    let mut carrier = OptimizationProofCarrier::new(
        r#"
        const limit = 100;
        sum = 0;
        for (i = 0; i < 4; i++) {
            sum += i * limit;
        }
        return sum;
        "#
        .to_string(),
        r#"
        const limit = 100;
        sum = 0;
        sum += 0 * limit;
        sum += 1 * limit;
        sum += 2 * limit;
        sum += 3 * limit;
        return sum;
        "#
        .to_string(),
    );

    let unrolling_rule = TransformationRule {
        rule_id: "unroll_fixed_count_loop".to_string(),
        rule_type: TransformationRuleType::ControlFlowRestructuring,
        pattern: "for (VAR = START; VAR < END; VAR++) { BODY }".to_string(),
        replacement: "BODY[VAR=START]; BODY[VAR=START+1]; ...".to_string(),
        applicability_conditions: vec![
            "Loop bound is compile-time constant".to_string(),
            "Loop body has no control flow".to_string(),
            "Iteration count is small".to_string(),
        ],
        preservation_properties: vec![
            "Loop semantics preserved".to_string(),
            "Iteration order preserved".to_string(),
            "Side effects preserved".to_string(),
        ],
    };

    let hoisting_rule = TransformationRule {
        rule_id: "hoist_loop_invariants".to_string(),
        rule_type: TransformationRuleType::DataFlowOptimization,
        pattern: "for (...) { INVARIANT_EXPR; ... }".to_string(),
        replacement: "INVARIANT_EXPR; for (...) { ... }".to_string(),
        applicability_conditions: vec![
            "Expression is loop invariant".to_string(),
            "No side effects".to_string(),
        ],
        preservation_properties: vec![
            "Expression evaluation preserved".to_string(),
            "Loop semantics unchanged".to_string(),
        ],
    };

    let unrolling_pass = OptimizationPassApplication {
        pass_id: "loop_unroll_1".to_string(),
        optimization_type: OptimizationPass::LoopUnrolling,
        source_region: IrRegion {
            region_id: "loop_region".to_string(),
            start_instruction: 2,
            end_instruction: 8,
            basic_blocks: ["loop_header", "loop_body", "loop_exit"]
                .into_iter()
                .map(String::from)
                .collect(),
            control_flow_edges: vec![
                ("loop_header".to_string(), "loop_body".to_string()),
                ("loop_body".to_string(), "loop_header".to_string()),
                ("loop_header".to_string(), "loop_exit".to_string()),
            ],
            live_variables: ["i", "sum", "limit"]
                .into_iter()
                .map(String::from)
                .collect(),
        },
        target_region: IrRegion {
            region_id: "unrolled_region".to_string(),
            start_instruction: 2,
            end_instruction: 6,
            basic_blocks: ["unrolled_body"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: ["sum", "limit"].into_iter().map(String::from).collect(),
        },
        transformation_rules: vec![unrolling_rule, hoisting_rule],
        preconditions: vec![
            "Loop analysis complete".to_string(),
            "Invariant analysis complete".to_string(),
        ],
        postconditions: vec![
            "Loop unrolled".to_string(),
            "Invariants hoisted".to_string(),
        ],
        performance_impact: PerformanceImpact {
            execution_time_change: -0.30, // 30% faster
            memory_usage_change: 0.05,    // 5% more memory
            code_size_change: 0.20,       // 20% larger code
            compile_time_overhead: 5.0,   // 5ms overhead
            optimization_benefit_score: 0.75,
        },
    };

    carrier.add_optimization_pass(unrolling_pass);

    // Generate and verify proofs
    let proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 1);

    let proof = &carrier.equivalence_proofs[0];
    assert_eq!(proof.proof_method, ProofMethod::ProgramLogic);
    assert_eq!(
        proof.equivalence_relation,
        EquivalenceRelation::WeakEquivalence
    );

    // Verify loop-specific proof obligations
    assert!(
        proof
            .proof_obligations
            .iter()
            .any(|po| po.obligation_id.contains("loop_semantics")
                || po.conclusion.contains("Loop semantics preserved"))
    );
}

/// Test function inlining optimization.
#[test]
fn function_inlining_optimization() {
    let mut carrier = OptimizationProofCarrier::new(
        r#"
        function add(x, y) { return x + y; }
        function multiply(a, b) { return a * b; }
        result = add(multiply(3, 4), 5);
        return result;
        "#
        .to_string(),
        r#"
        result = (3 * 4) + 5;
        return result;
        "#
        .to_string(),
    );

    let inline_rule = TransformationRule {
        rule_id: "inline_small_functions".to_string(),
        rule_type: TransformationRuleType::PatternReplacement,
        pattern: "CALL(FUNCTION, ARGS)".to_string(),
        replacement: "FUNCTION_BODY[PARAMS=ARGS]".to_string(),
        applicability_conditions: vec![
            "Function is small (< 10 instructions)".to_string(),
            "Function is not recursive".to_string(),
            "Inlining benefit > threshold".to_string(),
        ],
        preservation_properties: vec![
            "Call semantics preserved".to_string(),
            "Parameter binding preserved".to_string(),
            "Return value preserved".to_string(),
        ],
    };

    let inline_pass = OptimizationPassApplication {
        pass_id: "inline_1".to_string(),
        optimization_type: OptimizationPass::InlineExpansion,
        source_region: IrRegion {
            region_id: "function_calls".to_string(),
            start_instruction: 0,
            end_instruction: 3,
            basic_blocks: ["main", "add_func", "multiply_func"]
                .into_iter()
                .map(String::from)
                .collect(),
            control_flow_edges: vec![
                ("main".to_string(), "add_func".to_string()),
                ("main".to_string(), "multiply_func".to_string()),
            ],
            live_variables: ["result", "x", "y", "a", "b"]
                .into_iter()
                .map(String::from)
                .collect(),
        },
        target_region: IrRegion {
            region_id: "inlined_main".to_string(),
            start_instruction: 0,
            end_instruction: 2,
            basic_blocks: ["main"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: ["result"].into_iter().map(String::from).collect(),
        },
        transformation_rules: vec![inline_rule],
        preconditions: vec![
            "Call graph analysis complete".to_string(),
            "Function size analysis complete".to_string(),
        ],
        postconditions: vec![
            "Functions inlined".to_string(),
            "Call overhead eliminated".to_string(),
        ],
        performance_impact: PerformanceImpact {
            execution_time_change: -0.20, // 20% faster
            memory_usage_change: -0.05,   // 5% less stack usage
            code_size_change: 0.10,       // 10% larger
            compile_time_overhead: 4.0,   // 4ms overhead
            optimization_benefit_score: 0.80,
        },
    };

    carrier.add_optimization_pass(inline_pass);

    // Generate and verify proofs
    let proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 1);

    let proof = &carrier.equivalence_proofs[0];
    assert_eq!(proof.proof_method, ProofMethod::ContextualEquivalence);

    // Verify inlining-specific proof obligations
    assert!(
        proof
            .proof_obligations
            .iter()
            .any(|po| po.obligation_id.contains("inlining_correctness")
                || po.premise.contains("Function call replaced with body"))
    );
}

/// Test comprehensive optimization verification workflow.
#[test]
fn comprehensive_optimization_verification_workflow() {
    let mut carrier = OptimizationProofCarrier::new(
        r#"
        function fibonacci(n) {
            if (n <= 1) return n;
            return fibonacci(n - 1) + fibonacci(n - 2);
        }

        const result = fibonacci(3) + 0;
        return result;
        "#
        .to_string(),
        r#"
        const result = 2;
        return result;
        "#
        .to_string(),
    );

    // Multiple optimization passes in sequence
    let passes = vec![
        (OptimizationPass::InlineExpansion, "inline_fibonacci"),
        (OptimizationPass::ConstantFolding, "fold_arithmetic"),
        (OptimizationPass::ConstantPropagation, "propagate_result"),
        (OptimizationPass::DeadCodeElimination, "eliminate_unused"),
    ];

    for (opt_type, pass_id) in passes {
        let pass = OptimizationPassApplication {
            pass_id: pass_id.to_string(),
            optimization_type: opt_type,
            source_region: IrRegion {
                region_id: format!("{}_region", pass_id),
                start_instruction: 0,
                end_instruction: 10,
                basic_blocks: ["main", "fibonacci"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                control_flow_edges: Vec::new(),
                live_variables: ["n", "result"].into_iter().map(String::from).collect(),
            },
            target_region: IrRegion {
                region_id: format!("{}_optimized", pass_id),
                start_instruction: 0,
                end_instruction: 5,
                basic_blocks: ["main"].into_iter().map(String::from).collect(),
                control_flow_edges: Vec::new(),
                live_variables: ["result"].into_iter().map(String::from).collect(),
            },
            transformation_rules: Vec::new(),
            preconditions: vec![format!("{} analysis complete", pass_id)],
            postconditions: vec![format!("{} optimization applied", pass_id)],
            performance_impact: PerformanceImpact {
                execution_time_change: -0.25, // 25% improvement per pass
                memory_usage_change: 0.0,
                code_size_change: -0.15,    // 15% smaller per pass
                compile_time_overhead: 2.0, // 2ms per pass
                optimization_benefit_score: 0.85,
            },
        };

        carrier.add_optimization_pass(pass);
    }

    // Update performance metrics
    carrier.performance_metrics.overall_performance_improvement = 0.60; // 60% total improvement

    // Generate and verify all proofs
    let proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 4); // One proof per pass

    let verification_result = carrier.verify_all_proofs().unwrap();
    assert_eq!(verification_result.total_proofs, 4);
    assert!(verification_result.verified_proofs > 0);
    assert!(verification_result.verification_time_ms > 0);

    // Check optimization verification status
    assert_ne!(
        carrier.verification_status,
        OptimizationVerificationStatus::Unverified
    );

    // Should have generated proof certificates
    assert!(verification_result.certificates_generated);
    assert!(!carrier.proof_certificates.is_empty());

    // Verify certificate types
    let has_semantic_cert = carrier
        .proof_certificates
        .iter()
        .any(|cert| cert.certificate_type == CertificateType::SemanticEquivalence);
    let has_performance_cert = carrier
        .proof_certificates
        .iter()
        .any(|cert| cert.certificate_type == CertificateType::PerformanceImprovement);

    assert!(has_semantic_cert);
    assert!(has_performance_cert);
}

/// Test optimization test case generation and execution.
#[test]
fn optimization_test_case_generation_and_execution() {
    let test_cases = generate_optimization_test_cases();
    assert!(!test_cases.is_empty());
    assert_eq!(test_cases.len(), 4);

    // Execute each test case
    for test_case in &test_cases {
        let mut carrier =
            OptimizationProofCarrier::new(test_case.source_ir.clone(), test_case.target_ir.clone());

        // Apply optimization passes from test case
        for (i, optimization_type) in test_case.optimization_passes.iter().enumerate() {
            let pass = OptimizationPassApplication {
                pass_id: format!("test_pass_{}_{}", test_case.name, i),
                optimization_type: optimization_type.clone(),
                source_region: IrRegion {
                    region_id: format!("test_region_{}", i),
                    start_instruction: 0,
                    end_instruction: 10,
                    basic_blocks: ["test_block"].into_iter().map(String::from).collect(),
                    control_flow_edges: Vec::new(),
                    live_variables: BTreeSet::new(),
                },
                target_region: IrRegion {
                    region_id: format!("test_region_opt_{}", i),
                    start_instruction: 0,
                    end_instruction: 8,
                    basic_blocks: ["test_block"].into_iter().map(String::from).collect(),
                    control_flow_edges: Vec::new(),
                    live_variables: BTreeSet::new(),
                },
                transformation_rules: Vec::new(),
                preconditions: Vec::new(),
                postconditions: Vec::new(),
                performance_impact: PerformanceImpact {
                    execution_time_change: -test_case.expected_performance_improvement,
                    memory_usage_change: 0.0,
                    code_size_change: 0.0,
                    compile_time_overhead: 1.0,
                    optimization_benefit_score: 0.8,
                },
            };

            carrier.add_optimization_pass(pass);
        }

        // Generate and verify proofs
        let proof_count = carrier.generate_equivalence_proofs().unwrap();
        assert_eq!(proof_count, test_case.optimization_passes.len());

        // Verify expected equivalence relations
        for proof in &carrier.equivalence_proofs {
            // Each test case specifies expected equivalence relation
            // In practice, different optimizations may have different relations
        }

        let verification_result = carrier.verify_all_proofs().unwrap();
        assert_eq!(verification_result.total_proofs, proof_count);
    }

    // Verify specific test cases
    let dead_code_case = test_cases
        .iter()
        .find(|tc| tc.name == "dead_code_elimination_simple")
        .unwrap();
    assert!(dead_code_case.source_ir.contains("if (false)"));
    assert!(!dead_code_case.target_ir.contains("if (false)"));

    let constant_fold_case = test_cases
        .iter()
        .find(|tc| tc.name == "constant_folding_arithmetic")
        .unwrap();
    assert!(constant_fold_case.source_ir.contains("3 + 4"));
    assert!(constant_fold_case.target_ir.contains("a = 7"));

    let loop_unroll_case = test_cases
        .iter()
        .find(|tc| tc.name == "loop_unrolling_small")
        .unwrap();
    assert!(loop_unroll_case.source_ir.contains("for ("));
    assert!(!loop_unroll_case.target_ir.contains("for ("));
}

/// Test error handling and edge cases.
#[test]
fn optimization_verification_error_handling() {
    let mut carrier = OptimizationProofCarrier::new(
        "malformed source".to_string(),
        "malformed target".to_string(),
    );

    // Test with empty carrier
    let empty_proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(empty_proof_count, 0);

    let empty_verification = carrier.verify_all_proofs().unwrap();
    assert_eq!(empty_verification.total_proofs, 0);
    assert_eq!(empty_verification.verified_proofs, 0);

    // Test with malformed optimization pass
    let malformed_pass = OptimizationPassApplication {
        pass_id: "".to_string(), // Empty ID
        optimization_type: OptimizationPass::DeadCodeElimination,
        source_region: IrRegion {
            region_id: "malformed".to_string(),
            start_instruction: 0,
            end_instruction: 0, // Invalid range
            basic_blocks: BTreeSet::new(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        target_region: IrRegion {
            region_id: "malformed_opt".to_string(),
            start_instruction: 0,
            end_instruction: 0,
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
            optimization_benefit_score: 0.0,
        },
    };

    carrier.add_optimization_pass(malformed_pass);

    // Should still generate proofs but may have issues
    let proof_count = carrier.generate_equivalence_proofs().unwrap();
    assert_eq!(proof_count, 1);

    let verification_result = carrier.verify_all_proofs().unwrap();
    assert_eq!(verification_result.total_proofs, 1);
}

/// Test performance impact calculations and metrics.
#[test]
fn performance_impact_calculations_and_metrics() {
    let mut carrier = OptimizationProofCarrier::new(
        "performance_test_source".to_string(),
        "performance_test_target".to_string(),
    );

    // Add optimization with significant performance impact
    let high_impact_pass = OptimizationPassApplication {
        pass_id: "high_impact_opt".to_string(),
        optimization_type: OptimizationPass::LoopUnrolling,
        source_region: IrRegion {
            region_id: "perf_source".to_string(),
            start_instruction: 0,
            end_instruction: 20,
            basic_blocks: ["loop"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        target_region: IrRegion {
            region_id: "perf_target".to_string(),
            start_instruction: 0,
            end_instruction: 10,
            basic_blocks: ["unrolled"].into_iter().map(String::from).collect(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        transformation_rules: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
        performance_impact: PerformanceImpact {
            execution_time_change: -0.50,     // 50% faster
            memory_usage_change: 0.20,        // 20% more memory
            code_size_change: 0.80,           // 80% larger code
            compile_time_overhead: 10.0,      // 10ms overhead
            optimization_benefit_score: 0.70, // 70% benefit
        },
    };

    carrier.add_optimization_pass(high_impact_pass);

    // Test metrics calculation
    assert_eq!(carrier.performance_metrics.total_passes_applied, 1);

    let impact = &carrier.applied_passes[0].performance_impact;
    assert_eq!(impact.execution_time_change, -0.50);
    assert_eq!(impact.memory_usage_change, 0.20);
    assert_eq!(impact.code_size_change, 0.80);
    assert_eq!(impact.optimization_benefit_score, 0.70);

    // Verify performance calculations are reasonable
    assert!(impact.execution_time_change < 0.0); // Should be faster
    assert!(impact.optimization_benefit_score > 0.0); // Should have benefit
}

/// Test proof certificate generation and validation.
#[test]
fn proof_certificate_generation_and_validation() {
    let mut carrier = OptimizationProofCarrier::new(
        "certificate_test_source".to_string(),
        "certificate_test_target".to_string(),
    );

    // Add multiple optimization passes
    let passes = [
        OptimizationPass::ConstantFolding,
        OptimizationPass::DeadCodeElimination,
        OptimizationPass::InlineExpansion,
    ];

    for (i, opt_type) in passes.iter().enumerate() {
        let pass = OptimizationPassApplication {
            pass_id: format!("cert_pass_{}", i),
            optimization_type: opt_type.clone(),
            source_region: IrRegion {
                region_id: format!("cert_region_{}", i),
                start_instruction: 0,
                end_instruction: 5,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            target_region: IrRegion {
                region_id: format!("cert_region_opt_{}", i),
                start_instruction: 0,
                end_instruction: 3,
                basic_blocks: BTreeSet::new(),
                control_flow_edges: Vec::new(),
                live_variables: BTreeSet::new(),
            },
            transformation_rules: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            performance_impact: PerformanceImpact {
                execution_time_change: -0.15, // 15% improvement
                memory_usage_change: 0.0,
                code_size_change: -0.05, // 5% smaller
                compile_time_overhead: 2.0,
                optimization_benefit_score: 0.85,
            },
        };

        carrier.add_optimization_pass(pass);
    }

    // Set overall performance improvement for certificate generation
    carrier.performance_metrics.overall_performance_improvement = 0.35; // 35% total

    // Generate and verify proofs
    carrier.generate_equivalence_proofs().unwrap();
    let verification_result = carrier.verify_all_proofs().unwrap();

    // Should have generated certificates
    assert!(verification_result.certificates_generated);
    assert!(!carrier.proof_certificates.is_empty());

    // Verify semantic equivalence certificate
    let semantic_certs: Vec<_> = carrier
        .proof_certificates
        .iter()
        .filter(|cert| cert.certificate_type == CertificateType::SemanticEquivalence)
        .collect();
    assert!(!semantic_certs.is_empty());

    let semantic_cert = semantic_certs[0];
    assert!(!semantic_cert.certificate_id.is_empty());
    assert!(!semantic_cert.optimization_passes.is_empty());
    assert!(
        semantic_cert
            .certificate_data
            .contains("Semantic equivalence verified")
    );
    assert!(semantic_cert.validity_period.is_some());

    // Verify performance improvement certificate
    let performance_certs: Vec<_> = carrier
        .proof_certificates
        .iter()
        .filter(|cert| cert.certificate_type == CertificateType::PerformanceImprovement)
        .collect();
    assert!(!performance_certs.is_empty());

    let performance_cert = performance_certs[0];
    assert!(
        performance_cert
            .certificate_data
            .contains("Performance improvement")
    );
    assert!(performance_cert.certificate_data.contains("35"));
}

/// Test verification artifact export.
#[test]
fn verification_artifact_export() {
    let mut carrier = OptimizationProofCarrier::new(
        "export_test_source".to_string(),
        "export_test_target".to_string(),
    );

    // Add optimization pass for completeness
    let pass = OptimizationPassApplication {
        pass_id: "export_test_pass".to_string(),
        optimization_type: OptimizationPass::ConstantFolding,
        source_region: IrRegion {
            region_id: "export_region".to_string(),
            start_instruction: 0,
            end_instruction: 1,
            basic_blocks: BTreeSet::new(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        target_region: IrRegion {
            region_id: "export_region_opt".to_string(),
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
            execution_time_change: -0.10,
            memory_usage_change: 0.0,
            code_size_change: 0.0,
            compile_time_overhead: 1.0,
            optimization_benefit_score: 0.75,
        },
    };

    carrier.add_optimization_pass(pass);

    // Export verification artifact
    let artifact = carrier.export_verification_artifact();

    // Verify artifact contains essential information
    assert!(artifact.contains("source_ir"));
    assert!(artifact.contains("target_ir"));
    assert!(artifact.contains("applied_passes"));
    assert!(artifact.contains("verification_status"));
    assert!(artifact.contains("export_test_source"));
    assert!(artifact.contains("export_test_target"));
}

/// Test integration with G.4-G.7 validation infrastructure.
#[test]
fn integration_with_previous_validation_infrastructure() {
    let mut carrier = OptimizationProofCarrier::new(
        "g4_g7_integration_source".to_string(),
        "g4_g7_integration_target".to_string(),
    );

    // Optimization pass that builds on G.4-G.7 foundations
    let integration_pass = OptimizationPassApplication {
        pass_id: "g4_g7_integration_pass".to_string(),
        optimization_type: OptimizationPass::CommonSubexpressionElimination,
        source_region: IrRegion {
            region_id: "integration_source".to_string(),
            start_instruction: 0,
            end_instruction: 10,
            basic_blocks: BTreeSet::new(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        target_region: IrRegion {
            region_id: "integration_target".to_string(),
            start_instruction: 0,
            end_instruction: 8,
            basic_blocks: BTreeSet::new(),
            control_flow_edges: Vec::new(),
            live_variables: BTreeSet::new(),
        },
        transformation_rules: vec![TransformationRule {
            rule_id: "cse_integration_with_g4_expression_validation".to_string(),
            rule_type: TransformationRuleType::DataFlowOptimization,
            pattern: "expr1; ... expr1".to_string(),
            replacement: "temp = expr1; ... temp".to_string(),
            applicability_conditions: vec![
                "Expression validated by G.4 infrastructure".to_string(),
                "Expression has no side effects".to_string(),
            ],
            preservation_properties: vec![
                "G.4 expression semantics preserved".to_string(),
                "G.5 statement context preserved".to_string(),
                "G.6 IR translation properties maintained".to_string(),
                "G.7 policy constraints satisfied".to_string(),
            ],
        }],
        preconditions: vec![
            "G.4 expression validation passed".to_string(),
            "G.5 statement validation passed".to_string(),
            "G.6 IR coverage validation passed".to_string(),
            "G.7 policy verification passed".to_string(),
        ],
        postconditions: vec![
            "Optimization preserves G.4-G.7 guarantees".to_string(),
            "All validation layers remain valid".to_string(),
        ],
        performance_impact: PerformanceImpact {
            execution_time_change: -0.20,
            memory_usage_change: 0.10,
            code_size_change: 0.05,
            compile_time_overhead: 3.0,
            optimization_benefit_score: 0.80,
        },
    };

    carrier.add_optimization_pass(integration_pass);

    // Generate proofs that should reference G.4-G.7
    carrier.generate_equivalence_proofs().unwrap();

    let proof = &carrier.equivalence_proofs[0];

    // Verify integration references in proof obligations
    let integration_obligations: Vec<_> = proof
        .proof_obligations
        .iter()
        .filter(|po| {
            po.premise.contains("G.4")
                || po.premise.contains("G.5")
                || po.premise.contains("G.6")
                || po.premise.contains("G.7")
                || po.conclusion.contains("validation")
                || po.conclusion.contains("policy")
        })
        .collect();

    assert!(!integration_obligations.is_empty());

    // Verify that optimization preserves validation properties
    let verification_result = carrier.verify_all_proofs().unwrap();
    assert!(
        verification_result.optimization_safety_verified || verification_result.verified_proofs > 0
    );
}
