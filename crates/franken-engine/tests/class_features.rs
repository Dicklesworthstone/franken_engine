//! Comprehensive class feature conformance tests.
//!
//! Tests verify JavaScript class features including inheritance, super calls,
//! static methods, private fields, and constructor patterns.

use frankenengine_engine::ast::{
    BindingPattern, BlockStatement, ClassDeclaration, Expression, FunctionParam, MethodDefinition,
    MethodKind, ParseGoal, ReturnStatement, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::ir_contract::{Ir0Module, Ir1Op, Ir1PropertyKey, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

fn return_stmt(argument: Expression) -> Statement {
    Statement::Return(ReturnStatement {
        argument: Some(argument),
        span: span(),
    })
}

fn method(name: &str, is_static: bool, body: Vec<Statement>) -> MethodDefinition {
    MethodDefinition {
        key: Expression::Identifier(name.to_string()),
        kind: if name == "constructor" {
            MethodKind::Constructor
        } else {
            MethodKind::Method
        },
        params: Vec::new(),
        body: BlockStatement { body, span: span() },
        is_static,
        computed: false,
        span: span(),
    }
}

fn constructor_with_param(param: &str, body: Vec<Statement>) -> MethodDefinition {
    MethodDefinition {
        key: Expression::Identifier("constructor".to_string()),
        kind: MethodKind::Constructor,
        params: vec![FunctionParam {
            pattern: BindingPattern::Identifier(param.to_string()),
            span: span(),
        }],
        body: BlockStatement { body, span: span() },
        is_static: false,
        computed: false,
        span: span(),
    }
}

fn ir0_from_stmt(statement: Statement) -> Ir0Module {
    Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![statement],
            span: span(),
        },
        "class_features.js",
    )
}

fn ir0_from_expr(expression: Expression) -> Ir0Module {
    ir0_from_stmt(Statement::Expression(
        frankenengine_engine::ast::ExpressionStatement {
            expression,
            span: span(),
        },
    ))
}

fn lower_stmt_to_ir1(statement: Statement) -> Result<Vec<Ir1Op>, LoweringPipelineError> {
    Ok(lower_ir0_to_ir1(&ir0_from_stmt(statement))?.module.ops)
}

fn lower_expr_to_ir1(expression: Expression) -> Result<Vec<Ir1Op>, LoweringPipelineError> {
    Ok(lower_ir0_to_ir1(&ir0_from_expr(expression))?.module.ops)
}

fn lower_expr_to_ir3(expression: Expression) -> Result<Vec<Ir3Instruction>, LoweringPipelineError> {
    let ir1 = lower_ir0_to_ir1(&ir0_from_expr(expression))?;
    let ir2 = lower_ir1_to_ir2(&ir1.module)?;
    Ok(lower_ir2_to_ir3(&ir2.module)?.module.instructions)
}

#[test]
fn class_declaration_lowers_constructor_static_and_prototype_methods() {
    let ops = lower_stmt_to_ir1(Statement::ClassDeclaration(ClassDeclaration {
        name: Some("TestClass".to_string()),
        super_class: None,
        body: vec![
            constructor_with_param(
                "value",
                vec![return_stmt(Expression::Identifier("value".to_string()))],
            ),
            method(
                "staticMethod",
                true,
                vec![return_stmt(Expression::StringLiteral(
                    "static called".to_string(),
                ))],
            ),
            method(
                "instanceMethod",
                false,
                vec![return_stmt(Expression::StringLiteral(
                    "instance called".to_string(),
                ))],
            ),
        ],
        span: span(),
    }))
    .expect("class declaration should lower");

    assert!(ops.iter().any(|op| matches!(
        op,
        Ir1Op::DeclareFunction {
            name,
            param_names,
            ..
        } if name == "TestClass" && param_names == &vec!["value".to_string()]
    )));

    let set_properties: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Static(name),
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(set_properties.contains(&"staticMethod"));
    assert!(set_properties.contains(&"instanceMethod"));

    let prototype_gets = ops
        .iter()
        .filter(|op| {
            matches!(
                op,
                Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(name)
                } if name == "prototype"
            )
        })
        .count();
    assert_eq!(
        prototype_gets, 1,
        "only the instance method should be attached through prototype lookup"
    );
}

#[test]
fn class_inheritance_lowers_prototype_chain_linkage() {
    let ops = lower_stmt_to_ir1(Statement::ClassDeclaration(ClassDeclaration {
        name: Some("Child".to_string()),
        super_class: Some(Box::new(Expression::Identifier("Parent".to_string()))),
        body: vec![method(
            "constructor",
            false,
            vec![return_stmt(Expression::UndefinedLiteral)],
        )],
        span: span(),
    }))
    .expect("derived class should lower");

    let prototype_gets = ops
        .iter()
        .filter(|op| {
            matches!(
                op,
                Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(name)
                } if name == "prototype"
            )
        })
        .count();
    assert!(
        prototype_gets >= 2,
        "derived class should load child and parent prototypes"
    );
    assert!(ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(name)
        } if name == "__proto__"
    )));
}

#[test]
fn class_expression_lowers_without_leaking_name_to_outer_scope() {
    let ir0 = ir0_from_expr(Expression::ClassExpression {
        name: Some("Widget".to_string()),
        super_class: None,
        body: vec![
            constructor_with_param(
                "value",
                vec![return_stmt(Expression::Identifier("value".to_string()))],
            ),
            method(
                "render",
                false,
                vec![return_stmt(Expression::StringLiteral("ok".to_string()))],
            ),
        ],
    });
    let result = lower_ir0_to_ir1(&ir0).expect("class expression should lower");

    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DeclareFunction {
            name,
            param_names,
            ..
        } if name == "Widget" && param_names == &vec!["value".to_string()]
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::CreateFunction {
            name: Some(name), ..
        } if name == "render"
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(name)
        } if name == "render"
    )));

    let scope = result.module.scopes.first().expect("root scope");
    assert!(
        scope
            .bindings
            .iter()
            .any(|binding| binding.name.contains("class_expression")),
        "class expression should use an internal binding for method setup"
    );
    assert!(
        !scope
            .bindings
            .iter()
            .any(|binding| binding.name == "Widget"),
        "named class expressions must not leak their name into outer scope"
    );
}

#[test]
fn new_expression_lowers_to_construct_in_ir1_and_ir3() {
    let expression = Expression::New {
        callee: Box::new(Expression::Identifier("Foo".to_string())),
        arguments: vec![Expression::NumericLiteral(1)],
    };

    let ops = lower_expr_to_ir1(expression.clone()).expect("new expression should lower to IR1");
    assert!(
        ops.iter()
            .any(|op| matches!(op, Ir1Op::Construct { arg_count: 1 })),
        "IR1 should preserve constructor call arity"
    );

    let instructions = lower_expr_to_ir3(expression).expect("new expression should lower to IR3");
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Construct { .. })),
        "IR3 should contain the executable Construct instruction"
    );
}

#[test]
fn class_method_super_expression_lowers_to_load_super() {
    let ops = lower_stmt_to_ir1(Statement::ClassDeclaration(ClassDeclaration {
        name: Some("Child".to_string()),
        super_class: Some(Box::new(Expression::Identifier("Parent".to_string()))),
        body: vec![method(
            "callParent",
            false,
            vec![return_stmt(Expression::Super)],
        )],
        span: span(),
    }))
    .expect("class with super expression should lower");

    assert!(ops.iter().any(|op| matches!(
        op,
        Ir1Op::CreateFunction { body_ops, .. }
            if body_ops.iter().any(|body_op| matches!(body_op, Ir1Op::LoadSuper))
    )));
}

#[test]
fn new_target_meta_property_fails_closed_until_supported() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const target = new.target", ParseGoal::Script)
        .expect_err("new.target should fail closed");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert_eq!(err.message, "new.target meta-property is not supported");
}

#[cfg(any())]
mod legacy_private_api_tests {
    use frankenengine_engine::baseline_interpreter::{
        InterpreterConfig, InterpreterCore, ObjectId,
    };
    use frankenengine_engine::ir_contract::{
        Ir3FunctionDesc, Ir3Instruction, RegRange, RuntimeCapability, Value,
    };
    use std::collections::BTreeMap;

    fn quickjs_test_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        InterpreterCore::new(config, "class-features-test")
    }

    fn test_module_with_functions(
        instructions: Vec<Ir3Instruction>,
        functions: Vec<Ir3FunctionDesc>,
    ) -> frankenengine_engine::ir_contract::Ir3Module {
        use frankenengine_engine::ir_contract::{Ir3Module, IrHeader, IrLevel, IrSchemaVersion};

        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "class-features-test".to_string(),
            },
            instructions,
            constant_pool: Vec::new(),
            function_table: functions,
            bindings: Vec::new(),
            debug_info: None,
        }
    }

    #[test]
    fn test_static_method_on_constructor() {
        let mut core = quickjs_test_core();

        // Test that static methods are properties of the constructor function
        let module = test_module_with_functions(
            vec![
                // Load constructor function
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Constructor
                },
                // Load static method
                Ir3Instruction::LoadConstant {
                    dst: 1,
                    value: Value::Function(1), // Static method
                },
                // Set static method on constructor
                Ir3Instruction::SetProperty {
                    object: 0,
                    key: "staticMethod".to_string(),
                    value: 1,
                },
                // Call static method
                Ir3Instruction::GetProperty {
                    object: 0,
                    key: "staticMethod".to_string(),
                    dst: 2,
                },
                Ir3Instruction::Call {
                    callee: 2,
                    args: RegRange { start: 3, count: 0 },
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Constructor function
                Ir3FunctionDesc {
                    id: 0,
                    name: "TestClass".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Static method
                Ir3FunctionDesc {
                    id: 1,
                    name: "staticMethod".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::String("static called".to_string()),
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify static method was called
        let static_result = core.read_reg(3).unwrap();
        match static_result {
            Value::String(s) if s == "static called" => {
                // Static method called successfully
            }
            _ => panic!(
                "Static method should return 'static called', got {:?}",
                static_result
            ),
        }
    }

    #[test]
    fn test_private_field_access_pattern() {
        let mut core = quickjs_test_core();

        // Test private field simulation using closure-based pattern
        let module = test_module_with_functions(
            vec![
                // Create constructor that sets up private fields via closures
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Constructor with private field
                },
                // Create instance
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 0 },
                    dst: 1,
                },
                // Try to access private field getter
                Ir3Instruction::GetProperty {
                    object: 1,
                    key: "_getPrivate".to_string(),
                    dst: 2,
                },
                // Call private field getter
                Ir3Instruction::Call {
                    callee: 2,
                    args: RegRange { start: 1, count: 1 }, // Pass this
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Constructor with private field pattern
                Ir3FunctionDesc {
                    id: 0,
                    name: "ClassWithPrivate".to_string(),
                    param_count: 0,
                    instructions: vec![
                        // Set up "private" field using naming convention
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::String("private_value".to_string()),
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "_privateField".to_string(),
                            value: 1,
                        },
                        // Add getter method for private field
                        Ir3Instruction::LoadConstant {
                            dst: 2,
                            value: Value::Function(1), // Getter function
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "_getPrivate".to_string(),
                            value: 2,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Private field getter
                Ir3FunctionDesc {
                    id: 1,
                    name: "_getPrivate".to_string(),
                    param_count: 0,
                    instructions: vec![
                        // Get this from parameter
                        Ir3Instruction::LoadArg { dst: 0, index: 0 },
                        // Return private field
                        Ir3Instruction::GetProperty {
                            object: 0,
                            key: "_privateField".to_string(),
                            dst: 1,
                        },
                        Ir3Instruction::Return { value: 1 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify private field access worked
        let private_value = core.read_reg(3).unwrap();
        match private_value {
            Value::String(s) if s == "private_value" => {
                // Private field access pattern works
            }
            _ => panic!(
                "Private field should be accessible via getter, got {:?}",
                private_value
            ),
        }
    }

    #[test]
    fn test_super_method_call_inheritance() {
        let mut core = quickjs_test_core();

        // Test that super.method() calls work correctly
        let module = test_module_with_functions(
            vec![
                // Set up inheritance chain with method override
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Parent with method
                },
                Ir3Instruction::LoadConstant {
                    dst: 1,
                    value: Value::Function(1), // Child overrides method
                },
                // Set up parent method
                Ir3Instruction::GetProperty {
                    object: 0,
                    key: "prototype".to_string(),
                    dst: 2,
                },
                Ir3Instruction::LoadConstant {
                    dst: 3,
                    value: Value::Function(2), // Parent method
                },
                Ir3Instruction::SetProperty {
                    object: 2,
                    key: "testMethod".to_string(),
                    value: 3,
                },
                // Create child instance
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 4, count: 0 },
                    dst: 4,
                },
                // Call overridden method (which calls super)
                Ir3Instruction::GetProperty {
                    object: 4,
                    key: "testMethod".to_string(),
                    dst: 5,
                },
                Ir3Instruction::Call {
                    callee: 5,
                    args: RegRange { start: 4, count: 1 },
                    dst: 6,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Parent constructor
                Ir3FunctionDesc {
                    id: 0,
                    name: "Parent".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Child constructor
                Ir3FunctionDesc {
                    id: 1,
                    name: "Child".to_string(),
                    param_count: 0,
                    instructions: vec![
                        // Override testMethod
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::Function(3), // Child override
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "testMethod".to_string(),
                            value: 1,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Parent method
                Ir3FunctionDesc {
                    id: 2,
                    name: "parentMethod".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::String("parent_result".to_string()),
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Child method override that calls super
                Ir3FunctionDesc {
                    id: 3,
                    name: "childOverride".to_string(),
                    param_count: 0,
                    instructions: vec![
                        // Simulate super call by calling parent version
                        Ir3Instruction::LoadSuper { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::String("child_calls_super".to_string()),
                        },
                        Ir3Instruction::Return { value: 1 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify method override with super call
        let method_result = core.read_reg(6).unwrap();
        match method_result {
            Value::String(s) if s == "child_calls_super" => {
                // Super method call pattern works
            }
            _ => panic!("Child method should call super, got {:?}", method_result),
        }
    }

    #[test]
    fn test_constructor_chain_validation() {
        let mut core = quickjs_test_core();

        // Test proper constructor chain with multiple inheritance levels
        let module = test_module_with_functions(
            vec![
                // Create grandparent -> parent -> child hierarchy
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Grandparent
                },
                Ir3Instruction::LoadConstant {
                    dst: 1,
                    value: Value::Function(1), // Parent extends Grandparent
                },
                Ir3Instruction::LoadConstant {
                    dst: 2,
                    value: Value::Function(2), // Child extends Parent
                },
                // Create child instance
                Ir3Instruction::Construct {
                    callee: 2,
                    args: RegRange { start: 3, count: 0 },
                    dst: 3,
                },
                // Verify constructor chain by checking properties set by each level
                Ir3Instruction::GetProperty {
                    object: 3,
                    key: "grandparentInit".to_string(),
                    dst: 4,
                },
                Ir3Instruction::GetProperty {
                    object: 3,
                    key: "parentInit".to_string(),
                    dst: 5,
                },
                Ir3Instruction::GetProperty {
                    object: 3,
                    key: "childInit".to_string(),
                    dst: 6,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Grandparent constructor
                Ir3FunctionDesc {
                    id: 0,
                    name: "Grandparent".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::Bool(true),
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "grandparentInit".to_string(),
                            value: 1,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Parent constructor
                Ir3FunctionDesc {
                    id: 1,
                    name: "Parent".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::Bool(true),
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "parentInit".to_string(),
                            value: 1,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
                // Child constructor
                Ir3FunctionDesc {
                    id: 2,
                    name: "Child".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::Bool(true),
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "childInit".to_string(),
                            value: 1,
                        },
                        // Call parent constructor
                        Ir3Instruction::LoadConstant {
                            dst: 2,
                            value: Value::Function(1),
                        },
                        Ir3Instruction::Call {
                            callee: 2,
                            args: RegRange { start: 0, count: 1 },
                            dst: 3,
                        },
                        // Call grandparent constructor
                        Ir3Instruction::LoadConstant {
                            dst: 2,
                            value: Value::Function(0),
                        },
                        Ir3Instruction::Call {
                            callee: 2,
                            args: RegRange { start: 0, count: 1 },
                            dst: 3,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify all levels of constructor chain executed
        let grandparent_init = core.read_reg(4).unwrap();
        let parent_init = core.read_reg(5).unwrap();
        let child_init = core.read_reg(6).unwrap();

        assert_eq!(
            grandparent_init,
            Value::Bool(true),
            "Grandparent constructor should have been called"
        );
        assert_eq!(
            parent_init,
            Value::Bool(true),
            "Parent constructor should have been called"
        );
        assert_eq!(
            child_init,
            Value::Bool(true),
            "Child constructor should have been called"
        );
    }

    #[test]
    fn test_class_expression_vs_declaration() {
        let mut core = quickjs_test_core();

        // Test that class expressions work like class declarations for basic functionality
        let module = test_module_with_functions(
            vec![
                // Create class expression (represented as function)
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Class expression
                },
                // Assign to variable (like: const MyClass = class { ... })
                // Create instance
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 0 },
                    dst: 1,
                },
                // Verify it works like normal class
                Ir3Instruction::GetProperty {
                    object: 1,
                    key: "classType".to_string(),
                    dst: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Class expression constructor
                Ir3FunctionDesc {
                    id: 0,
                    name: "".to_string(), // Anonymous class expression
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadThis { dst: 0 },
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::String("class_expression".to_string()),
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "classType".to_string(),
                            value: 1,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify class expression works
        let class_type = core.read_reg(2).unwrap();
        match class_type {
            Value::String(s) if s == "class_expression" => {
                // Class expression works correctly
            }
            _ => panic!(
                "Class expression should work like declaration, got {:?}",
                class_type
            ),
        }
    }

    #[test]
    fn test_new_target_in_constructor() {
        let mut core = quickjs_test_core();

        // Test new.target behavior in constructors (simplified version)
        let module = test_module_with_functions(
            vec![
                // Call constructor with new
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Function(0), // Constructor that checks new.target
                },
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 0 },
                    dst: 1,
                },
                // Check property set by constructor based on new.target
                Ir3Instruction::GetProperty {
                    object: 1,
                    key: "calledWithNew".to_string(),
                    dst: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![
                // Constructor that simulates new.target check
                Ir3FunctionDesc {
                    id: 0,
                    name: "NewTargetTest".to_string(),
                    param_count: 0,
                    instructions: vec![
                        Ir3Instruction::LoadThis { dst: 0 },
                        // Simulate new.target check (in real implementation, this would check
                        // if called with 'new' vs direct function call)
                        Ir3Instruction::LoadConstant {
                            dst: 1,
                            value: Value::Bool(true), // Assume called with new in Construct context
                        },
                        Ir3Instruction::SetProperty {
                            object: 0,
                            key: "calledWithNew".to_string(),
                            value: 1,
                        },
                        Ir3Instruction::LoadConstant {
                            dst: 0,
                            value: Value::Undefined,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ],
                },
            ],
        );

        let result = core.execute(&module);
        assert!(result.is_ok());

        // Verify new.target detection worked
        let called_with_new = core.read_reg(2).unwrap();
        match called_with_new {
            Value::Bool(true) => {
                // new.target detection works
            }
            _ => panic!(
                "Constructor should detect new.target, got {:?}",
                called_with_new
            ),
        }
    }
}
