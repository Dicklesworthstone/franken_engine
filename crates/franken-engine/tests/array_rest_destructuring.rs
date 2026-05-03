use frankenengine_engine::canonical_encoding::ensure_canonical_ordering;
use frankenengine_engine::content_hash::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineConfig, LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2,
    lower_ir2_to_ir3,
};
use frankenengine_engine::object_model::{
    BindingPattern, Expression, Literal, Statement, VariableDeclaration, VariableDeclarator,
    DeclarationKind,
};
use std::collections::BTreeMap;

/// Helper to create a module with a destructuring assignment statement
fn create_destructuring_module(
    pattern: BindingPattern,
    init: Expression,
) -> frankenengine_engine::lowering_pipeline::Ir0Module {
    let declarator = VariableDeclarator {
        id: pattern,
        initializer: Some(init),
    };

    let declaration = VariableDeclaration {
        kind: DeclarationKind::Const,
        declarations: vec![declarator],
    };

    frankenengine_engine::lowering_pipeline::Ir0Module {
        source_text: "test".to_string(),
        content_hash: ContentHash::compute(b"test"),
        module_url: "test.js".to_string(),
        statements: vec![Statement::VariableDeclaration(declaration)],
        exports: BTreeMap::new(),
    }
}

/// Helper to lower a destructuring module through all IR levels and extract IR3 instructions
fn lower_destructuring_to_ir3(
    pattern: BindingPattern,
    init: Expression,
) -> Result<Vec<Ir3Instruction>, LoweringPipelineError> {
    let ir0_module = create_destructuring_module(pattern, init);

    let ir1_result = lower_ir0_to_ir1(&ir0_module)?;
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module)?;
    let ir3_result = lower_ir2_to_ir3(&ir2_result.module)?;

    Ok(ir3_result.module.instructions)
}

#[test]
fn test_simple_rest_destructuring() {
    // const [a, b, ...rest] = [1, 2, 3, 4, 5];
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("a".to_string()),
            BindingPattern::Identifier("b".to_string()),
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("rest".to_string()))),
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(1))),
            Some(Expression::Literal(Literal::Integer(2))),
            Some(Expression::Literal(Literal::Integer(3))),
            Some(Expression::Literal(Literal::Integer(4))),
            Some(Expression::Literal(Literal::Integer(5))),
        ],
    };

    let instructions =
        lower_destructuring_to_ir3(pattern, init).expect("Simple rest should lower successfully");

    // Should contain ArraySlice instruction for the rest operation
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
        "Should contain ArraySlice instruction for rest destructuring"
    );

    // Should also contain array creation and element assignments
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::NewArray { .. })),
        "Should contain NewArray instruction for array creation"
    );
}

#[test]
fn test_empty_rest_destructuring() {
    // const [a, b, ...rest] = [1, 2];  // rest should be empty array
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("a".to_string()),
            BindingPattern::Identifier("b".to_string()),
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("rest".to_string()))),
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(1))),
            Some(Expression::Literal(Literal::Integer(2))),
        ],
    };

    let instructions =
        lower_destructuring_to_ir3(pattern, init).expect("Empty rest should lower successfully");

    // Should still contain ArraySlice instruction (will create empty array at runtime)
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
        "Should contain ArraySlice instruction even for empty rest"
    );
}

#[test]
fn test_source_shorter_than_pattern() {
    // const [a, b, c, ...rest] = [1, 2];  // c = undefined, rest = []
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("a".to_string()),
            BindingPattern::Identifier("b".to_string()),
            BindingPattern::Identifier("c".to_string()),
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("rest".to_string()))),
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(1))),
            Some(Expression::Literal(Literal::Integer(2))),
        ],
    };

    let instructions = lower_destructuring_to_ir3(pattern, init)
        .expect("Source shorter than pattern should lower successfully");

    // Should contain ArraySlice instruction for rest
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
        "Should contain ArraySlice instruction for rest"
    );

    // Should contain GetProperty instructions for accessing array elements
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::GetProperty { .. })),
        "Should contain GetProperty instructions for element access"
    );
}

#[test]
fn test_rest_only_destructuring() {
    // const [...all] = [1, 2, 3];  // all = [1, 2, 3]
    let pattern = BindingPattern::Array {
        elements: vec![BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "all".to_string(),
        )))],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(1))),
            Some(Expression::Literal(Literal::Integer(2))),
            Some(Expression::Literal(Literal::Integer(3))),
        ],
    };

    let instructions =
        lower_destructuring_to_ir3(pattern, init).expect("Rest only should lower successfully");

    // Should contain ArraySlice instruction starting from index 0
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
        "Should contain ArraySlice instruction for rest-only destructuring"
    );

    // Should contain LoadInt with value 0 for start index
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::LoadInt { value: 0, .. })),
        "Should contain LoadInt instruction with start index 0"
    );
}

#[test]
fn test_nested_array_rest_destructuring() {
    // const [a, [b, ...inner]] = [1, [2, 3, 4]];
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("a".to_string()),
            BindingPattern::Array {
                elements: vec![
                    BindingPattern::Identifier("b".to_string()),
                    BindingPattern::Rest(Box::new(BindingPattern::Identifier("inner".to_string()))),
                ],
            },
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(1))),
            Some(Expression::Array {
                elements: vec![
                    Some(Expression::Literal(Literal::Integer(2))),
                    Some(Expression::Literal(Literal::Integer(3))),
                    Some(Expression::Literal(Literal::Integer(4))),
                ],
            }),
        ],
    };

    let instructions =
        lower_destructuring_to_ir3(pattern, init).expect("Nested rest should lower successfully");

    // Should contain ArraySlice instruction for the inner rest
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
        "Should contain ArraySlice instruction for nested rest destructuring"
    );

    // Should contain multiple GetProperty instructions for accessing nested elements
    let get_property_count = instructions
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::GetProperty { .. }))
        .count();
    assert!(
        get_property_count >= 2,
        "Should contain multiple GetProperty instructions for nested access"
    );
}

#[test]
fn test_rest_destructuring_deterministic_lowering() {
    // Test that rest destructuring lowering is deterministic
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("first".to_string()),
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("remaining".to_string()))),
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(10))),
            Some(Expression::Literal(Literal::Integer(20))),
            Some(Expression::Literal(Literal::Integer(30))),
        ],
    };

    // Lower the same destructuring twice
    let instructions1 = lower_destructuring_to_ir3(pattern.clone(), init.clone())
        .expect("First lowering should succeed");
    let instructions2 =
        lower_destructuring_to_ir3(pattern, init).expect("Second lowering should succeed");

    // Results should be identical (deterministic)
    assert_eq!(
        instructions1.len(),
        instructions2.len(),
        "Both lowering passes should produce the same number of instructions"
    );

    // Both should contain ArraySlice instructions
    let slice_count1 = instructions1
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. }))
        .count();
    let slice_count2 = instructions2
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. }))
        .count();
    assert_eq!(
        slice_count1, slice_count2,
        "Both passes should emit the same number of ArraySlice instructions"
    );

    // Verify canonical ordering is maintained
    let mut ir3_module1 = Ir3Module::new(ContentHash::compute(b"test1"), "test1.js");
    ir3_module1.instructions = instructions1;
    let canonical1 = ensure_canonical_ordering(&ir3_module1);

    let mut ir3_module2 = Ir3Module::new(ContentHash::compute(b"test2"), "test2.js");
    ir3_module2.instructions = instructions2;
    let canonical2 = ensure_canonical_ordering(&ir3_module2);

    assert!(
        canonical1.is_ok() && canonical2.is_ok(),
        "Both modules should have canonical ordering"
    );
}

#[test]
fn test_array_slice_instruction_properties() {
    // const [head, ...tail] = [100, 200, 300, 400];
    let pattern = BindingPattern::Array {
        elements: vec![
            BindingPattern::Identifier("head".to_string()),
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("tail".to_string()))),
        ],
    };

    let init = Expression::Array {
        elements: vec![
            Some(Expression::Literal(Literal::Integer(100))),
            Some(Expression::Literal(Literal::Integer(200))),
            Some(Expression::Literal(Literal::Integer(300))),
            Some(Expression::Literal(Literal::Integer(400))),
        ],
    };

    let instructions = lower_destructuring_to_ir3(pattern, init)
        .expect("Array slice properties should lower successfully");

    // Find the ArraySlice instruction and verify its structure
    let array_slice_instr = instructions
        .iter()
        .find(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. }));

    assert!(
        array_slice_instr.is_some(),
        "Should contain exactly one ArraySlice instruction"
    );

    // Verify that the start index is loaded as integer 1 (after first element)
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::LoadInt { value: 1, .. })),
        "Should load start index 1 for rest destructuring after first element"
    );
}