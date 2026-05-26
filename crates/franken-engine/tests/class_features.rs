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

mod class_runtime_execution_tests {
    //! Real-source class-feature RUNTIME tests (bd-bg9l1.7).
    //!
    //! Replaces the dead `#[cfg(any())] mod legacy_private_api_tests` block, which
    //! hand-built obsolete IR3 modules against a removed interpreter surface
    //! (`InterpreterCore::read_reg`, per-function `Ir3FunctionDesc.instructions`) and
    //! so was never compiled — class-feature *runtime* execution had no live coverage
    //! here, only lowering.
    //!
    //! Each test drives REAL JavaScript class source through the full pipeline
    //! (parse -> IR0 -> IR1 -> IR2 -> IR3 -> interpreter execution) and asserts on the
    //! observable `ExecutionResult.value` (the value left in r0 at `Halt`). No mocks,
    //! no hand-built IR.
    //!
    //! Coverage is split into two fail-closed halves:
    //!   * Positive — class declaration, `new` construction, and a constructor-assigned
    //!     instance field execute and are observable from the constructed instance.
    //!   * Boundary — features the engine does NOT yet execute from source are pinned
    //!     to their current fail-closed errors: `super` (rejected by the parser),
    //!     static-method access and prototype/instance-method dispatch (the interpreter
    //!     does not treat function values as property-bearing objects). Constructor
    //!     *parameter* flow into a field is likewise not yet observable from source.
    //!     If the engine gains these, the boundary tests break and must be upgraded to
    //!     positive assertions. Tracked by bd-a7kpw.

    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{
        ExecutionResult, InterpreterConfig, InterpreterCore, Value,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{
        lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
    };
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

    /// Drive real JS source through the full lowering + execution pipeline.
    /// Returns the interpreter `ExecutionResult`, or a stage-labelled error string
    /// (`parse:` / `ir0->ir1:` / ... / `execute:`) so a regression surfaces with its
    /// failing stage.
    fn run_source(source: &str) -> Result<ExecutionResult, String> {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(source, ParseGoal::Script)
            .map_err(|e| format!("parse: {e:?}"))?;
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-features-runtime");
        let ir1 = lower_ir0_to_ir1(&ir0).map_err(|e| format!("ir0->ir1: {e:?}"))?;
        let ir2 = lower_ir1_to_ir2(&ir1.module).map_err(|e| format!("ir1->ir2: {e:?}"))?;
        let ir3 = lower_ir2_to_ir3(&ir2.module).map_err(|e| format!("ir2->ir3: {e:?}"))?;

        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
        let mut core = InterpreterCore::new(config, "class-features-runtime");
        core.execute(&ir3.module)
            .map_err(|e| format!("execute: {e:?}"))
    }

    /// Run source and require successful execution, returning the result.
    fn run_ok(source: &str) -> ExecutionResult {
        run_source(source).unwrap_or_else(|e| panic!("class source should execute cleanly: {e}"))
    }

    /// Run source and require a fail-closed rejection, returning the error string.
    fn run_err(source: &str) -> String {
        match run_source(source) {
            Ok(result) => panic!(
                "expected a fail-closed rejection, but execution produced {:?}",
                result.value
            ),
            Err(err) => err,
        }
    }

    // -- Positive: real class semantics that execute end-to-end --

    /// A class declaration binds a callable constructor at runtime.
    #[test]
    fn class_declaration_binds_callable_constructor() {
        let result = run_ok("class Widget { constructor() {} }\nWidget;\n");
        assert!(
            matches!(result.value, Value::Closure(_) | Value::Function(_)),
            "a class declaration should bind a callable constructor, got {:?}",
            result.value
        );
    }

    /// `new C()` allocates and returns a fresh instance object.
    #[test]
    fn new_expression_constructs_instance_object() {
        let result = run_ok(concat!(
            "class Widget { constructor() { this.ready = true; } }\n",
            "new Widget();\n",
        ));
        assert!(
            matches!(result.value, Value::Object(_)),
            "`new` should allocate and return an instance object, got {:?}",
            result.value
        );
    }

    /// The constructor body runs on `new`, and a field it assigns is readable from
    /// the constructed instance. (This is the runtime substance the old
    /// `test_private_field_access_pattern` / `test_new_target_in_constructor` /
    /// `test_constructor_chain_validation` cases were reaching for.)
    #[test]
    fn constructor_body_assigns_readable_instance_field() {
        let result = run_ok(concat!(
            "class ClassWithField {\n",
            "  constructor() { this.storedField = \"private_value\"; }\n",
            "}\n",
            "var instance = new ClassWithField();\n",
            "instance.storedField;\n",
        ));
        assert_eq!(
            result.value,
            Value::str("private_value"),
            "a field assigned in the constructor must be readable from the instance"
        );
    }

    // -- Boundary: current fail-closed behavior (real engine, no mocks; bd-a7kpw) --

    /// `super` expressions are rejected fail-closed by the parser today.
    /// (The AST `Expression::Super` lowers fine, but the source parser never emits it.)
    #[test]
    fn super_expression_fails_closed_at_parser() {
        let err = run_err(concat!(
            "class Parent { testMethod() { return 1; } }\n",
            "class Child extends Parent {\n",
            "  testMethod() { return super.testMethod(); }\n",
            "}\n",
            "new Child();\n",
        ));
        assert!(
            err.starts_with("parse:") && err.contains("super expressions are not supported"),
            "super source must be rejected fail-closed by the parser, got: {err}"
        );
    }

    /// Static-method access on a class constructor fails closed: statics lower onto
    /// the constructor function, but the interpreter does not treat function values
    /// as property-bearing objects, so the access raises a `TypeError` rather than
    /// silently mis-resolving. Pinned until bd-a7kpw lands.
    #[test]
    fn static_method_access_fails_closed() {
        let err = run_err(concat!(
            "class TestClass { static staticMethod() { return \"static called\"; } }\n",
            "TestClass.staticMethod;\n",
        ));
        assert!(
            err.starts_with("execute:") && err.contains("TypeError") && err.contains("function"),
            "static access on a class constructor must fail closed today, got: {err}"
        );
    }

    /// Prototype/instance method dispatch from source fails closed today: the method
    /// is reached through the constructor function (not a property object), so the
    /// call raises a `TypeError`. Pinned until bd-a7kpw lands.
    #[test]
    fn instance_method_dispatch_fails_closed() {
        let err = run_err(concat!(
            "class Greeter { greet() { return \"hi\"; } }\n",
            "var g = new Greeter();\n",
            "g.greet();\n",
        ));
        assert!(
            err.starts_with("execute:") && err.contains("TypeError"),
            "instance-method dispatch from source must fail closed today, got: {err}"
        );
    }
}
