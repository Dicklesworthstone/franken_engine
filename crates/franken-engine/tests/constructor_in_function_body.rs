use frankenengine_engine::ast::{
    AssignmentOperator, BinaryOperator, BlockStatement, Expression, FunctionDeclaration,
    ObjectProperty, ParseGoal, ReturnStatement, SourceSpan, Statement, SyntaxTree, UnaryOperator,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

/// Helper to create a function declaration with constructor calls in the body
fn create_function_with_constructor(function_body_expr: Expression) -> FunctionDeclaration {
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

#[test]
fn test_simple_constructor_in_function() {
    // function testFunc() { return new Foo(); }
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![],
    };

    let func_decl = create_function_with_constructor(constructor_call);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Function should lower successfully");

    // Should contain Construct instruction
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::Construct { .. })),
        "Function body should contain Construct instruction"
    );
}

#[test]
fn test_constructor_with_arguments() {
    // function testFunc() { return new Foo(1, 'hello', {x: 1}); }
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![
            Expression::NumericLiteral(1),
            Expression::StringLiteral("hello".to_string()),
            Expression::ObjectLiteral(vec![ObjectProperty {
                key: Expression::Identifier("x".to_string()),
                value: Expression::NumericLiteral(1),
                computed: false,
                shorthand: false,
            }]),
        ],
    };

    let func_decl = create_function_with_constructor(constructor_call);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Function with args should lower successfully");

    // Should contain Construct instruction with proper arg range
    let construct_count = instructions
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::Construct { .. }))
        .count();
    assert_eq!(
        construct_count, 1,
        "Should have exactly one Construct instruction"
    );
}

#[test]
fn test_nested_constructor_calls() {
    // function testFunc() { return new Outer(new Inner()); }
    let inner_constructor = Expression::New {
        callee: Box::new(Expression::Identifier("Inner".to_string())),
        arguments: vec![],
    };

    let outer_constructor = Expression::New {
        callee: Box::new(Expression::Identifier("Outer".to_string())),
        arguments: vec![inner_constructor],
    };

    let func_decl = create_function_with_constructor(outer_constructor);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Nested constructors should lower successfully");

    // Should contain two Construct instructions (inner and outer)
    let construct_count = instructions
        .iter()
        .filter(|instr| matches!(instr, Ir3Instruction::Construct { .. }))
        .count();
    assert_eq!(
        construct_count, 2,
        "Should have two Construct instructions for nested calls"
    );
}

#[test]
fn test_constructor_stored_to_local() {
    // function testFunc() { var x = new Foo(); return x; }
    // We'll simulate this with a sequence expression for simplicity
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![],
    };

    // Use assignment to simulate storing to local
    let assignment = Expression::Assignment {
        operator: AssignmentOperator::Assign,
        left: Box::new(Expression::Identifier("x".to_string())),
        right: Box::new(constructor_call),
    };

    let func_decl = create_function_with_constructor(assignment);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Constructor assignment should lower successfully");

    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::Construct { .. })),
        "Should contain Construct instruction even when assigned to variable"
    );
}

#[test]
fn test_constructor_as_method_argument() {
    // function testFunc() { return obj.method(new Foo()); }
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![],
    };

    let method_call = Expression::Call {
        callee: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("method".to_string())),
            computed: false,
        }),
        arguments: vec![constructor_call],
    };

    let func_decl = create_function_with_constructor(method_call);
    let instructions = lower_function_to_ir3(func_decl)
        .expect("Constructor as method arg should lower successfully");

    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::Construct { .. })),
        "Should contain Construct instruction when used as method argument"
    );
    assert!(
        instructions.iter().any(|instr| matches!(
            instr,
            Ir3Instruction::Call { .. } | Ir3Instruction::CallMethod { .. }
        )),
        "Should also contain a call instruction for method invocation"
    );
}

#[test]
fn test_constructor_chain_with_property_access() {
    // function testFunc() { return new Foo().bar.baz; }
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![],
    };

    let property_chain = Expression::Member {
        object: Box::new(Expression::Member {
            object: Box::new(constructor_call),
            property: Box::new(Expression::Identifier("bar".to_string())),
            computed: false,
        }),
        property: Box::new(Expression::Identifier("baz".to_string())),
        computed: false,
    };

    let func_decl = create_function_with_constructor(property_chain);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Constructor chain should lower successfully");

    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::Construct { .. })),
        "Should contain Construct instruction"
    );
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::GetProperty { .. })),
        "Should contain GetProperty instructions for property access"
    );
}

#[test]
fn test_constructor_deterministic_lowering() {
    // Test that the same constructor call lowers to identical IR3 every time
    let constructor_call = Expression::New {
        callee: Box::new(Expression::Identifier("TestClass".to_string())),
        arguments: vec![
            Expression::NumericLiteral(42),
            Expression::StringLiteral("test".to_string()),
        ],
    };

    let func_decl = create_function_with_constructor(constructor_call.clone());

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

    // Verify canonical ordering is maintained
    let mut ir3_module1 = Ir3Module::new(ContentHash::compute(b"constructor-test"), "test.js");
    ir3_module1.instructions = instructions1;
    let canonical1 = ir3_module1.canonical_bytes();

    let mut ir3_module2 = Ir3Module::new(ContentHash::compute(b"constructor-test"), "test.js");
    ir3_module2.instructions = instructions2;
    let canonical2 = ir3_module2.canonical_bytes();

    assert_eq!(
        canonical1, canonical2,
        "canonical IR3 bytes should be stable"
    );
}

// Additional tests for JumpIfNullish and DeleteProperty that were fixed alongside Construct

#[test]
fn test_nullish_coalescing_in_function() {
    // function testFunc() { return a ?? b; }
    let nullish_coalescing = Expression::Binary {
        left: Box::new(Expression::Identifier("a".to_string())),
        operator: BinaryOperator::NullishCoalescing,
        right: Box::new(Expression::Identifier("b".to_string())),
    };

    let func_decl = create_function_with_constructor(nullish_coalescing);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Nullish coalescing should lower successfully");

    // Should contain JumpIfNullish instruction
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. })),
        "Function body should contain JumpIfNullish instruction for nullish coalescing"
    );
}

#[test]
fn test_delete_property_in_function() {
    // function testFunc() { return delete obj.prop; }
    let delete_expr = Expression::Unary {
        operator: UnaryOperator::Delete,
        argument: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        }),
    };

    let func_decl = create_function_with_constructor(delete_expr);
    let instructions =
        lower_function_to_ir3(func_decl).expect("Delete property should lower successfully");

    // Should contain DeleteProperty instruction
    assert!(
        instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::DeleteProperty { .. })),
        "Function body should contain DeleteProperty instruction"
    );
}
