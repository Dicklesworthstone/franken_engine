#![forbid(unsafe_code)]

//! Integration tests for statement and control flow translation validation.
//!
//! Tests the G.5 implementation that extends G.4 pure expression validation
//! to cover statements, control flow, and SSA phi node handling.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::statement_translation_validator::{
    ControlFlowNode, LemmaType, PhiNode, StatementKind, StatementValidationContext,
    generate_statement_test_cases,
};

/// Test basic statement validation context operations.
#[test]
fn statement_validation_context_basic_operations() {
    let mut ctx = StatementValidationContext::new();

    // Add source node
    let source_node = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::Assignment,
        predecessors: BTreeSet::new(),
        successors: [2].into_iter().collect(),
        phi_nodes: Vec::new(),
    };

    ctx.add_source_node(source_node.clone());
    assert!(ctx.source_cfg.contains_key(&1));
    assert_eq!(ctx.source_cfg[&1].statement_kind, StatementKind::Assignment);

    // Add target node
    let target_node = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::Assignment,
        predecessors: BTreeSet::new(),
        successors: [2].into_iter().collect(),
        phi_nodes: Vec::new(),
    };

    ctx.add_target_node(target_node);
    assert!(ctx.target_cfg.contains_key(&1));

    // Add variable mapping
    ctx.add_variable_mapping("x".to_string(), "x_ssa1".to_string());
    assert_eq!(ctx.variable_mapping["x"], "x_ssa1");
}

/// Test phi node lemma generation for if statement.
#[test]
fn phi_node_lemma_generation_if_statement() {
    let mut ctx = StatementValidationContext::new();

    // Create phi node for variable merged from two branches
    let phi_node = PhiNode {
        target_variable: "result".to_string(),
        incoming_values: [
            (1, "result_then".to_string()),
            (2, "result_else".to_string()),
        ]
        .into_iter()
        .collect(),
    };

    let merge_node = ControlFlowNode {
        id: 3,
        statement_kind: StatementKind::IfStatement,
        predecessors: [1, 2].into_iter().collect(),
        successors: BTreeSet::new(),
        phi_nodes: vec![phi_node],
    };

    ctx.add_target_node(merge_node);

    let lemma_count = ctx.generate_phi_node_lemmas().unwrap();
    assert_eq!(lemma_count, 1);

    let lemma = &ctx.validation_lemmas[0];
    assert_eq!(lemma.lemma_type, LemmaType::PhiNodeMerging);
    assert!(lemma.lemma_id.contains("phi_merge_3_result"));
    assert_eq!(lemma.source_nodes.len(), 2); // Two incoming branches
    assert_eq!(lemma.target_nodes.len(), 1); // One merge node
    assert_eq!(lemma.proof_obligations.len(), 2); // Determinism + equivalence
}

/// Test control flow preservation lemmas.
#[test]
fn control_flow_preservation_lemmas() {
    let mut ctx = StatementValidationContext::new();

    // Add matching source and target nodes
    let source_while = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::WhileLoop,
        predecessors: BTreeSet::new(),
        successors: [2, 3].into_iter().collect(), // condition -> body, exit
        phi_nodes: Vec::new(),
    };

    let target_while = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::WhileLoop,
        predecessors: BTreeSet::new(),
        successors: [2, 3].into_iter().collect(),
        phi_nodes: Vec::new(),
    };

    ctx.add_source_node(source_while);
    ctx.add_target_node(target_while);

    let lemma_count = ctx.generate_control_flow_lemmas().unwrap();
    assert_eq!(lemma_count, 1);

    let lemma = &ctx.validation_lemmas[0];
    assert_eq!(lemma.lemma_type, LemmaType::ControlFlowPreservation);
    assert!(lemma.invariant.contains("WhileLoop"));
    assert_eq!(lemma.proof_obligations.len(), 2); // Successor + predecessor preservation
}

/// Test validation of complex control flow with nested statements.
#[test]
fn complex_control_flow_validation() {
    let mut ctx = StatementValidationContext::new();

    // Nested if-while structure
    // if (condition1) {
    //   while (condition2) { x = x + 1; }
    // } else {
    //   x = 0;
    // }

    // If statement root
    let if_node = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::IfStatement,
        predecessors: BTreeSet::new(),
        successors: [2, 4].into_iter().collect(), // then branch, else branch
        phi_nodes: Vec::new(),
    };

    // While loop in then branch
    let while_node = ControlFlowNode {
        id: 2,
        statement_kind: StatementKind::WhileLoop,
        predecessors: [1, 3].into_iter().collect(), // from if, from loop body
        successors: [3, 5].into_iter().collect(),   // loop body, exit to merge
        phi_nodes: vec![PhiNode {
            target_variable: "x".to_string(),
            incoming_values: [(1, "x_init".to_string()), (3, "x_increment".to_string())]
                .into_iter()
                .collect(),
        }],
    };

    // Loop body
    let loop_body = ControlFlowNode {
        id: 3,
        statement_kind: StatementKind::Assignment,
        predecessors: [2].into_iter().collect(),
        successors: [2].into_iter().collect(), // back to while condition
        phi_nodes: Vec::new(),
    };

    // Else branch
    let else_node = ControlFlowNode {
        id: 4,
        statement_kind: StatementKind::Assignment,
        predecessors: [1].into_iter().collect(),
        successors: [5].into_iter().collect(), // to merge
        phi_nodes: Vec::new(),
    };

    // Final merge point
    let merge_node = ControlFlowNode {
        id: 5,
        statement_kind: StatementKind::Block,
        predecessors: [2, 4].into_iter().collect(), // from while exit, from else
        successors: BTreeSet::new(),
        phi_nodes: vec![PhiNode {
            target_variable: "x".to_string(),
            incoming_values: [
                (2, "x_while_exit".to_string()),
                (4, "x_else_value".to_string()),
            ]
            .into_iter()
            .collect(),
        }],
    };

    // Add all nodes as both source and target (identity transformation test)
    for node in [&if_node, &while_node, &loop_body, &else_node, &merge_node] {
        ctx.add_source_node(node.clone());
        ctx.add_target_node(node.clone());
    }

    // Generate lemmas
    let phi_lemmas = ctx.generate_phi_node_lemmas().unwrap();
    let control_lemmas = ctx.generate_control_flow_lemmas().unwrap();

    assert_eq!(phi_lemmas, 2); // Two phi nodes
    assert_eq!(control_lemmas, 5); // Five control flow nodes

    // Validate all lemmas
    let result = ctx.validate_lemmas();
    assert!(result.validation_successful);
    assert!(result.phi_node_correctness_proven);
    assert!(result.control_flow_preservation_proven);
    assert_eq!(result.verified_lemmas, phi_lemmas + control_lemmas);
}

/// Test statement test case generation and validation.
#[test]
fn statement_test_case_coverage() {
    let test_cases = generate_statement_test_cases();

    assert!(!test_cases.is_empty());
    assert!(test_cases.len() >= 4); // At least 4 test cases

    // Verify we have cases for different statement types
    let statement_types: BTreeSet<_> = test_cases.iter().map(|tc| &tc.statement_kind).collect();
    assert!(statement_types.contains(&StatementKind::Assignment));
    assert!(statement_types.contains(&StatementKind::IfStatement));
    assert!(statement_types.contains(&StatementKind::WhileLoop));

    // Verify specific test case properties
    let if_case = test_cases
        .iter()
        .find(|tc| tc.name == "if_statement")
        .unwrap();
    assert_eq!(if_case.expected_phi_nodes, 1);
    assert_eq!(if_case.expected_control_edges, 3);

    let while_case = test_cases
        .iter()
        .find(|tc| tc.name == "while_loop")
        .unwrap();
    assert_eq!(while_case.expected_phi_nodes, 1);
    assert!(while_case.source_ir.contains("while"));

    let nested_case = test_cases
        .iter()
        .find(|tc| tc.name == "nested_control_flow")
        .unwrap();
    assert!(nested_case.expected_phi_nodes >= 2);
    assert!(nested_case.expected_control_edges >= 5);
}

/// Test phi node determinism requirements.
#[test]
fn phi_node_determinism_validation() {
    let mut ctx = StatementValidationContext::new();

    // Create phi node with multiple incoming values
    let phi_node = PhiNode {
        target_variable: "loop_var".to_string(),
        incoming_values: [
            (1, "init_value".to_string()),
            (2, "loop_increment".to_string()),
            (3, "loop_decrement".to_string()),
        ]
        .into_iter()
        .collect(),
    };

    let merge_node = ControlFlowNode {
        id: 4,
        statement_kind: StatementKind::WhileLoop,
        predecessors: [1, 2, 3].into_iter().collect(),
        successors: BTreeSet::new(),
        phi_nodes: vec![phi_node],
    };

    ctx.add_target_node(merge_node);

    let lemma_count = ctx.generate_phi_node_lemmas().unwrap();
    assert_eq!(lemma_count, 1);

    let lemma = &ctx.validation_lemmas[0];
    assert_eq!(lemma.source_nodes.len(), 3); // Three incoming values

    // Check that determinism obligation exists
    let determinism_obligation = lemma
        .proof_obligations
        .iter()
        .find(|po| po.obligation_id.contains("determinism"))
        .unwrap();
    assert!(determinism_obligation.conclusion.contains("unique value"));
}

/// Test variable lifetime preservation across transformations.
#[test]
fn variable_lifetime_preservation() {
    let mut ctx = StatementValidationContext::new();

    // Add variable mappings for SSA transformation
    ctx.add_variable_mapping("x".to_string(), "x_1".to_string());
    ctx.add_variable_mapping("y".to_string(), "y_1".to_string());
    ctx.add_variable_mapping("result".to_string(), "result_2".to_string());

    // Verify mappings are preserved
    assert_eq!(ctx.variable_mapping.len(), 3);
    assert_eq!(ctx.variable_mapping["x"], "x_1");
    assert_eq!(ctx.variable_mapping["result"], "result_2");
}

/// Test semantic equivalence proof obligations.
#[test]
fn semantic_equivalence_proof_obligations() {
    let mut ctx = StatementValidationContext::new();

    // Create a simple phi node
    let phi_node = PhiNode {
        target_variable: "x".to_string(),
        incoming_values: [(1, "x_a".to_string()), (2, "x_b".to_string())]
            .into_iter()
            .collect(),
    };

    let node = ControlFlowNode {
        id: 3,
        statement_kind: StatementKind::IfStatement,
        predecessors: [1, 2].into_iter().collect(),
        successors: BTreeSet::new(),
        phi_nodes: vec![phi_node],
    };

    ctx.add_target_node(node);
    ctx.generate_phi_node_lemmas().unwrap();

    let lemma = &ctx.validation_lemmas[0];

    // Check equivalence proof obligation
    let equiv_obligation = lemma
        .proof_obligations
        .iter()
        .find(|po| po.obligation_id.contains("equivalence"))
        .unwrap();
    assert!(equiv_obligation.premise.contains("Source control flow"));
    assert!(equiv_obligation.conclusion.contains("equivalent"));
}

/// Test validation result aggregation and reporting.
#[test]
fn validation_result_comprehensive() {
    let mut ctx = StatementValidationContext::new();

    // Create multiple nodes with different statement types
    let nodes = vec![
        ControlFlowNode {
            id: 1,
            statement_kind: StatementKind::Assignment,
            predecessors: BTreeSet::new(),
            successors: [2].into_iter().collect(),
            phi_nodes: Vec::new(),
        },
        ControlFlowNode {
            id: 2,
            statement_kind: StatementKind::IfStatement,
            predecessors: [1].into_iter().collect(),
            successors: [3, 4].into_iter().collect(),
            phi_nodes: Vec::new(),
        },
        ControlFlowNode {
            id: 5,
            statement_kind: StatementKind::Block,
            predecessors: [3, 4].into_iter().collect(),
            successors: BTreeSet::new(),
            phi_nodes: vec![PhiNode {
                target_variable: "merged".to_string(),
                incoming_values: [(3, "branch_a".to_string()), (4, "branch_b".to_string())]
                    .into_iter()
                    .collect(),
            }],
        },
    ];

    // Add nodes as both source and target
    for node in &nodes {
        ctx.add_source_node(node.clone());
        ctx.add_target_node(node.clone());
    }

    // Generate all lemmas
    let phi_count = ctx.generate_phi_node_lemmas().unwrap();
    let cf_count = ctx.generate_control_flow_lemmas().unwrap();

    assert!(phi_count > 0);
    assert!(cf_count > 0);

    // Validate everything
    let result = ctx.validate_lemmas();

    assert!(result.validation_successful);
    assert!(result.semantic_equivalence_proven);
    assert!(result.control_flow_preservation_proven);
    assert!(result.phi_node_correctness_proven);
    assert_eq!(result.verified_lemmas, phi_count + cf_count);
    assert!(result.failed_lemmas.is_empty());
}

/// Test error handling for malformed control flow.
#[test]
fn malformed_control_flow_handling() {
    let ctx = StatementValidationContext::new();

    // Test validation with empty context
    let result = ctx.validate_lemmas();
    assert!(result.validation_successful); // Empty is vacuously valid
    assert_eq!(result.verified_lemmas, 0);
    assert!(result.failed_lemmas.is_empty());
}

/// Test integration with existing translation validation infrastructure.
#[test]
fn translation_validation_integration() {
    // This test ensures the new statement validation integrates properly
    // with the existing G.4 pure expression validation

    let mut ctx = StatementValidationContext::new();

    // Create a node that mixes statements with expressions
    let mixed_node = ControlFlowNode {
        id: 1,
        statement_kind: StatementKind::Assignment, // Statement wrapping expression
        predecessors: BTreeSet::new(),
        successors: [2].into_iter().collect(),
        phi_nodes: Vec::new(),
    };

    ctx.add_source_node(mixed_node.clone());
    ctx.add_target_node(mixed_node);

    let lemmas = ctx.generate_control_flow_lemmas().unwrap();
    assert!(lemmas > 0);

    // Validation should handle mixed statement/expression cases
    let result = ctx.validate_lemmas();
    assert!(result.validation_successful);
}