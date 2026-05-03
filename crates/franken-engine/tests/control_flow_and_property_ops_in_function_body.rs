use frankenengine_engine::ast::{
    AssignmentOperator, BinaryOperator, BlockStatement, Expression, FunctionDeclaration,
    ParseGoal, ReturnStatement, SourceSpan, Statement, SyntaxTree, UnaryOperator,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

/// Helper to create a function declaration with control flow or property operations in the body
fn create_function_with_expression(function_body_expr: Expression) -> FunctionDeclaration {
    FunctionDeclaration {
        name: Some("testFunc".to_string()),
        params: vec![],
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(function_body_expr),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
    }
}

/// Helper to lower a function declaration through all IR levels and extract IR3 instructions
fn lower_function_to_ir3(
    func_decl: FunctionDeclaration,
) -> Result<Vec<Ir3Instruction>, LoweringPipelineError> {
    let ir0_module = Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::FunctionDeclaration(func_decl)],
            span: span(),
        },
        "test.js",
    );

    let ir1_result = lower_ir0_to_ir1(&ir0_module)?;
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module)?;
    let ir3_result = lower_ir2_to_ir3(&ir2_result.module)?;

    Ok(ir3_result.module.instructions)
}

// -----------------------------------------------------------------------
// bd-2xjzi: Control Flow Operations Tests
// -----------------------------------------------------------------------

#[test]
fn test_nullish_coalescing_in_function_body() {
    // function testFunc() { return a ?? b; }
    let nullish_expr = Expression::Binary {
        left: Box::new(Expression::Identifier("a".to_string())),
        operator: BinaryOperator::NullishCoalescing,
        right: Box::new(Expression::Identifier("b".to_string())),
    };

    let func_decl = create_function_with_expression(nullish_expr);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Nullish coalescing should lower successfully");

    // Should contain JumpIfNullish instruction for the ?? operator
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. })),
        "Function body should contain JumpIfNullish instruction for nullish coalescing"
    );
}

#[test]
fn test_optional_chaining_in_function_body() {
    // function testFunc() { return obj?.prop; }
    let optional_member = Expression::OptionalMember {
        object: Box::new(Expression::Identifier("obj".to_string())),
        property: Box::new(Expression::Identifier("prop".to_string())),
        computed: false,
    };

    let func_decl = create_function_with_expression(optional_member);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Optional chaining should lower successfully");

    // Should contain JumpIfNullish instruction for optional chaining
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. })),
        "Function body should contain JumpIfNullish instruction for optional chaining"
    );

    // Should also contain GetProperty for the actual property access
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::GetProperty { .. })),
        "Function body should contain GetProperty instruction for property access"
    );
}

#[test]
fn test_nullish_coalescing_assignment_in_function_body() {
    // function testFunc() { return a ??= b; }
    let nullish_assign = Expression::Assignment {
        operator: AssignmentOperator::NullishCoalescingAssign,
        left: Box::new(Expression::Identifier("a".to_string())),
        right: Box::new(Expression::Identifier("b".to_string())),
    };

    let func_decl = create_function_with_expression(nullish_assign);
    let instructions = lower_function_to_ir3(func_decl)
        .expect("Nullish coalescing assignment should lower successfully");

    // Should contain JumpIfNullish instruction for the ??= operator
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. })),
        "Function body should contain JumpIfNullish instruction for nullish coalescing assignment"
    );
}

#[test]
fn test_nested_optional_chaining() {
    // function testFunc() { return obj?.prop?.method?.(); }
    let nested_optional = Expression::OptionalCall {
        callee: Box::new(Expression::OptionalMember {
            object: Box::new(Expression::OptionalMember {
                object: Box::new(Expression::Identifier("obj".to_string())),
                property: Box::new(Expression::Identifier("prop".to_string())),
                computed: false,
            }),
            property: Box::new(Expression::Identifier("method".to_string())),
            computed: false,
        }),
        arguments: vec![],
    };

    let func_decl = create_function_with_expression(nested_optional);
    let instructions = lower_function_to_ir3(func_decl)
        .expect("Nested optional chaining should lower successfully");

    // Should contain multiple JumpIfNullish instructions for each ?. in the chain
    let nullish_count = instructions
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. }))
        .count();
    assert!(
        nullish_count >= 2,
        "Nested optional chaining should emit multiple JumpIfNullish instructions"
    );
}

#[test]
fn test_control_flow_deterministic_lowering() {
    // Test that control flow lowering is deterministic
    let complex_expr = Expression::Binary {
        left: Box::new(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("a".to_string())),
            property: Box::new(Expression::Identifier("b".to_string())),
            computed: false,
        }),
        operator: BinaryOperator::NullishCoalescing,
        right: Box::new(Expression::Identifier("fallback".to_string())),
    };

    let func_decl = create_function_with_expression(complex_expr.clone());

    // Lower the same function twice
    let instructions1 =
        lower_function_to_ir3(func_decl.clone()).expect("First lowering should succeed");
    let instructions2 = lower_function_to_ir3(func_decl).expect("Second lowering should succeed");

    // Results should be identical (deterministic)
    assert_eq!(
        instructions1.len(),
        instructions2.len(),
        "Both lowering passes should produce the same number of instructions"
    );

    // Both should contain JumpIfNullish instructions
    let nullish_count1 = instructions1
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. }))
        .count();
    let nullish_count2 = instructions2
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. }))
        .count();
    assert_eq!(
        nullish_count1, nullish_count2,
        "Both passes should emit the same number of JumpIfNullish instructions"
    );
}

// -----------------------------------------------------------------------
// bd-1neuk: Property Operations Tests
// -----------------------------------------------------------------------

#[test]
fn test_delete_simple_property() {
    // function testFunc() { return delete obj.prop; }
    let delete_expr = Expression::Unary {
        operator: UnaryOperator::Delete,
        argument: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        }),
    };

    let func_decl = create_function_with_expression(delete_expr);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Delete simple property should lower successfully");

    // Should contain DeleteProperty instruction
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. })),
        "Function body should contain DeleteProperty instruction for delete operator"
    );
}

#[test]
fn test_delete_computed_property() {
    // function testFunc() { return delete obj[key]; }
    let delete_computed = Expression::Unary {
        operator: UnaryOperator::Delete,
        argument: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("key".to_string())),
            computed: true,
        }),
    };

    let func_decl = create_function_with_expression(delete_computed);
    let instructions = lower_function_to_ir3(func_decl)
        .expect("Delete computed property should lower successfully");

    // Should contain DeleteProperty instruction
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. })),
        "Function body should contain DeleteProperty instruction for computed delete"
    );
}

#[test]
fn test_delete_nested_property() {
    // function testFunc() { return delete obj.nested.prop; }
    let delete_nested = Expression::Unary {
        operator: UnaryOperator::Delete,
        argument: Box::new(Expression::Member {
            object: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".to_string())),
                property: Box::new(Expression::Identifier("nested".to_string())),
                computed: false,
            }),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        }),
    };

    let func_decl = create_function_with_expression(delete_nested);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Delete nested property should lower successfully");

    // Should contain DeleteProperty instruction for the final deletion
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. })),
        "Function body should contain DeleteProperty instruction for nested delete"
    );

    // Should also contain GetProperty instruction for accessing the nested object
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::GetProperty { .. })),
        "Function body should contain GetProperty instruction for nested object access"
    );
}

#[test]
fn test_property_operations_deterministic_lowering() {
    // Test that property operations lower deterministically
    let property_expr = Expression::Unary {
        operator: UnaryOperator::Delete,
        argument: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("target".to_string())),
            property: Box::new(Expression::StringLiteral("dynamicKey".to_string())),
            computed: true,
        }),
    };

    let func_decl = create_function_with_expression(property_expr.clone());

    // Lower the same function twice
    let instructions1 =
        lower_function_to_ir3(func_decl.clone()).expect("First lowering should succeed");
    let instructions2 = lower_function_to_ir3(func_decl).expect("Second lowering should succeed");

    // Results should be identical (deterministic)
    assert_eq!(
        instructions1.len(),
        instructions2.len(),
        "Both lowering passes should produce the same number of instructions"
    );

    // Both should contain DeleteProperty instructions
    let delete_count1 = instructions1
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. }))
        .count();
    let delete_count2 = instructions2
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. }))
        .count();
    assert_eq!(
        delete_count1, delete_count2,
        "Both passes should emit the same number of DeleteProperty instructions"
    );

    // Verify canonical ordering is maintained
    let mut ir3_module1 = Ir3Module::new(ContentHash::compute(b"property-test"), "property.js");
    ir3_module1.instructions = instructions1;
    let canonical1 = ir3_module1.canonical_bytes();

    let mut ir3_module2 = Ir3Module::new(ContentHash::compute(b"property-test"), "property.js");
    ir3_module2.instructions = instructions2;
    let canonical2 = ir3_module2.canonical_bytes();

    assert_eq!(canonical1, canonical2, "canonical IR3 bytes should be stable");
}
