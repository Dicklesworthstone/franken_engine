use frankenengine_engine::ast::{
    BindingPattern, Expression, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

/// Helper to create a module with a destructuring assignment statement
fn create_destructuring_module(pattern: BindingPattern, init: Expression) -> Ir0Module {
    let declarator = VariableDeclarator {
        pattern,
        initializer: Some(init),
        span: span(),
    };

    let declaration = VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![declarator],
        span: span(),
    };

    Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(declaration)],
            span: span(),
        },
        "test.js",
    )
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
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("a".to_string())),
        Some(BindingPattern::Identifier("b".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "rest".to_string(),
        )))),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        Some(Expression::NumericLiteral(2)),
        Some(Expression::NumericLiteral(3)),
        Some(Expression::NumericLiteral(4)),
        Some(Expression::NumericLiteral(5)),
    ]);

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
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("a".to_string())),
        Some(BindingPattern::Identifier("b".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "rest".to_string(),
        )))),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        Some(Expression::NumericLiteral(2)),
    ]);

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
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("a".to_string())),
        Some(BindingPattern::Identifier("b".to_string())),
        Some(BindingPattern::Identifier("c".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "rest".to_string(),
        )))),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        Some(Expression::NumericLiteral(2)),
    ]);

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
    let pattern = BindingPattern::ArrayPattern(vec![Some(BindingPattern::Rest(Box::new(
        BindingPattern::Identifier("all".to_string()),
    )))]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        Some(Expression::NumericLiteral(2)),
        Some(Expression::NumericLiteral(3)),
    ]);

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
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("a".to_string())),
        Some(BindingPattern::ArrayPattern(vec![
            Some(BindingPattern::Identifier("b".to_string())),
            Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
                "inner".to_string(),
            )))),
        ])),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        Some(Expression::ArrayLiteral(vec![
            Some(Expression::NumericLiteral(2)),
            Some(Expression::NumericLiteral(3)),
            Some(Expression::NumericLiteral(4)),
        ])),
    ]);

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
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("first".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "remaining".to_string(),
        )))),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(10)),
        Some(Expression::NumericLiteral(20)),
        Some(Expression::NumericLiteral(30)),
    ]);

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

    // Verify deterministic canonical encoding for equivalent modules.
    let mut ir3_module1 = Ir3Module::new(ContentHash::compute(b"test"), "test.js");
    ir3_module1.instructions = instructions1;

    let mut ir3_module2 = Ir3Module::new(ContentHash::compute(b"test"), "test.js");
    ir3_module2.instructions = instructions2;

    assert_eq!(
        ir3_module1.canonical_bytes(),
        ir3_module2.canonical_bytes(),
        "Equivalent rest-destructuring modules should encode deterministically"
    );
}

#[test]
fn test_array_slice_instruction_properties() {
    // const [head, ...tail] = [100, 200, 300, 400];
    let pattern = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("head".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "tail".to_string(),
        )))),
    ]);

    let init = Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(100)),
        Some(Expression::NumericLiteral(200)),
        Some(Expression::NumericLiteral(300)),
        Some(Expression::NumericLiteral(400)),
    ]);

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
