#![forbid(unsafe_code)]

//! Enrichment integration tests for the `ast` module.
//!
//! Focuses on cross-cutting integration scenarios: deep AST composition,
//! deterministic hashing across complex trees, binding pattern recursion,
//! full program round-trips, and canonical value stability.

use std::collections::BTreeSet;

use frankenengine_engine::ast::*;

// =========================================================================
// Helpers
// =========================================================================

fn span(start: u64, end: u64) -> SourceSpan {
    SourceSpan::new(start, end, 1, start + 1, 1, end + 1)
}

fn s0() -> SourceSpan {
    span(0, 10)
}

fn id(name: &str) -> Expression {
    Expression::Identifier(name.to_string())
}

fn num(n: i64) -> Expression {
    Expression::NumericLiteral(n)
}

fn str_lit(s: &str) -> Expression {
    Expression::StringLiteral(s.to_string())
}

fn expr_stmt(e: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: e,
        span: s0(),
    })
}

fn var_stmt(name: &str, init: Option<Expression>) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Let,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier(name.to_string()),
            initializer: init,
            span: s0(),
        }],
        span: s0(),
    })
}

fn block(stmts: Vec<Statement>) -> BlockStatement {
    BlockStatement {
        body: stmts,
        span: s0(),
    }
}

fn tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: s0(),
    }
}

fn simple_func(name: &str, params: &[&str], body: Vec<Statement>) -> FunctionDeclaration {
    FunctionDeclaration {
        name: Some(name.to_string()),
        params: params
            .iter()
            .map(|p| FunctionParam {
                pattern: BindingPattern::Identifier(p.to_string()),
                span: s0(),
            })
            .collect(),
        body: block(body),
        is_async: false,
        is_generator: false,
        span: s0(),
    }
}

// =========================================================================
// Cross-cutting: full program hash determinism
// =========================================================================

#[test]
fn enrichment_full_program_hash_deterministic_across_constructions() {
    let build = || {
        tree(
            ParseGoal::Module,
            vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("React".to_string()),
                    source: "react".to_string(),
                    span: span(0, 30),
                }),
                Statement::FunctionDeclaration(simple_func(
                    "App",
                    &["props"],
                    vec![Statement::Return(ReturnStatement {
                        argument: Some(Expression::Call {
                            callee: Box::new(id("h")),
                            arguments: vec![str_lit("div"), id("props")],
                        }),
                        span: s0(),
                    })],
                )),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(id("App")),
                    span: span(100, 120),
                }),
            ],
        )
    };
    let t1 = build();
    let t2 = build();
    assert_eq!(t1.canonical_hash(), t2.canonical_hash());
    assert_eq!(t1.canonical_bytes(), t2.canonical_bytes());
}

#[test]
fn enrichment_different_import_sources_produce_different_hashes() {
    let make = |src: &str| {
        tree(
            ParseGoal::Module,
            vec![Statement::Import(ImportDeclaration {
                binding: Some("x".to_string()),
                source: src.to_string(),
                span: s0(),
            })],
        )
    };
    assert_ne!(make("react").canonical_hash(), make("vue").canonical_hash());
}

#[test]
fn enrichment_statement_order_affects_hash() {
    let a = expr_stmt(num(1));
    let b = expr_stmt(num(2));
    let t1 = tree(ParseGoal::Script, vec![a.clone(), b.clone()]);
    let t2 = tree(ParseGoal::Script, vec![b, a]);
    assert_ne!(t1.canonical_hash(), t2.canonical_hash());
}

// =========================================================================
// Deep nesting scenarios
// =========================================================================

#[test]
fn enrichment_deeply_nested_if_else_chain_round_trips() {
    fn nested_if(depth: usize) -> Statement {
        if depth == 0 {
            expr_stmt(num(0))
        } else {
            Statement::If(IfStatement {
                condition: Expression::Binary {
                    operator: BinaryOperator::GreaterThan,
                    left: Box::new(id("x")),
                    right: Box::new(num(depth as i64)),
                },
                consequent: Box::new(expr_stmt(num(depth as i64))),
                alternate: Some(Box::new(nested_if(depth - 1))),
                span: s0(),
            })
        }
    }
    let stmt = nested_if(20);
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_deeply_nested_binary_expression() {
    fn nested_add(depth: usize) -> Expression {
        if depth == 0 {
            num(1)
        } else {
            Expression::Binary {
                operator: BinaryOperator::Add,
                left: Box::new(nested_add(depth - 1)),
                right: Box::new(num(depth as i64)),
            }
        }
    }
    let expr = nested_add(30);
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_nested_function_declarations_hash_determinism() {
    let inner = simple_func("inner", &["y"], vec![expr_stmt(id("y"))]);
    let outer = simple_func(
        "outer",
        &["x"],
        vec![
            Statement::FunctionDeclaration(inner),
            Statement::Return(ReturnStatement {
                argument: Some(Expression::Call {
                    callee: Box::new(id("inner")),
                    arguments: vec![id("x")],
                }),
                span: s0(),
            }),
        ],
    );
    let t = tree(
        ParseGoal::Script,
        vec![Statement::FunctionDeclaration(outer)],
    );
    let h1 = t.canonical_hash();
    let h2 = t.canonical_hash();
    assert_eq!(h1, h2);
    assert!(h1.starts_with("sha256:"));
}

// =========================================================================
// BindingPattern recursion
// =========================================================================

#[test]
fn enrichment_binding_pattern_deep_object_destructuring_names() {
    let pat = BindingPattern::ObjectPattern(vec![
        ObjectPatternProperty {
            key: id("a"),
            value: BindingPattern::Identifier("a".to_string()),
            computed: false,
            shorthand: true,
        },
        ObjectPatternProperty {
            key: id("nested"),
            value: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                key: id("b"),
                value: BindingPattern::Identifier("b".to_string()),
                computed: false,
                shorthand: true,
            }]),
            computed: false,
            shorthand: false,
        },
    ]);
    let names = pat.binding_names();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn enrichment_binding_pattern_array_with_holes_and_rest() {
    let pat = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("first".to_string())),
        None, // hole
        Some(BindingPattern::Identifier("third".to_string())),
        Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
            "rest".to_string(),
        )))),
    ]);
    let names = pat.binding_names();
    assert_eq!(names, vec!["first", "third", "rest"]);
}

#[test]
fn enrichment_binding_pattern_assignment_with_default() {
    let pat = BindingPattern::AssignmentPattern {
        left: Box::new(BindingPattern::Identifier("x".to_string())),
        right: num(42),
    };
    assert_eq!(pat.as_identifier(), None);
    assert_eq!(pat.binding_names(), vec!["x"]);
}

#[test]
fn enrichment_binding_pattern_nested_array_in_object() {
    let pat = BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
        key: id("items"),
        value: BindingPattern::ArrayPattern(vec![
            Some(BindingPattern::Identifier("x".to_string())),
            Some(BindingPattern::Identifier("y".to_string())),
        ]),
        computed: false,
        shorthand: false,
    }]);
    assert_eq!(pat.binding_names(), vec!["x", "y"]);
}

#[test]
fn enrichment_binding_pattern_display_identifier() {
    let pat = BindingPattern::Identifier("myVar".to_string());
    assert_eq!(pat.to_string(), "myVar");
    assert_eq!(pat.as_identifier(), Some("myVar"));
}

#[test]
fn enrichment_binding_pattern_display_rest() {
    let pat = BindingPattern::Rest(Box::new(BindingPattern::Identifier("args".to_string())));
    assert_eq!(pat.to_string(), "...args");
}

#[test]
fn enrichment_binding_pattern_display_assignment() {
    let pat = BindingPattern::AssignmentPattern {
        left: Box::new(BindingPattern::Identifier("x".to_string())),
        right: num(10),
    };
    assert_eq!(pat.to_string(), "x = 10");
}

#[test]
fn enrichment_binding_pattern_display_array() {
    let pat = BindingPattern::ArrayPattern(vec![
        Some(BindingPattern::Identifier("a".to_string())),
        None,
        Some(BindingPattern::Identifier("c".to_string())),
    ]);
    assert_eq!(pat.to_string(), "[a, , c]");
}

#[test]
fn enrichment_binding_pattern_canonical_value_all_kinds() {
    let patterns: Vec<(BindingPattern, &str)> = vec![
        (
            BindingPattern::Identifier("x".to_string()),
            "identifier",
        ),
        (BindingPattern::ObjectPattern(vec![]), "object_pattern"),
        (BindingPattern::ArrayPattern(vec![]), "array_pattern"),
        (
            BindingPattern::Rest(Box::new(BindingPattern::Identifier("r".to_string()))),
            "rest_element",
        ),
        (
            BindingPattern::AssignmentPattern {
                left: Box::new(BindingPattern::Identifier("a".to_string())),
                right: num(0),
            },
            "assignment_pattern",
        ),
    ];
    let mut seen = BTreeSet::new();
    for (pat, expected_kind) in &patterns {
        match pat.canonical_value() {
            frankenengine_engine::deterministic_serde::CanonicalValue::Map(map) => {
                if let Some(frankenengine_engine::deterministic_serde::CanonicalValue::String(k)) =
                    map.get("kind")
                {
                    assert_eq!(k, expected_kind);
                    assert!(seen.insert(k.clone()));
                }
            }
            _ => panic!("expected map"),
        }
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn enrichment_binding_pattern_serde_roundtrip_all_variants() {
    let patterns = vec![
        BindingPattern::Identifier("x".to_string()),
        BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
            key: id("k"),
            value: BindingPattern::Identifier("v".to_string()),
            computed: true,
            shorthand: false,
        }]),
        BindingPattern::ArrayPattern(vec![
            Some(BindingPattern::Identifier("a".to_string())),
            None,
        ]),
        BindingPattern::Rest(Box::new(BindingPattern::Identifier("rest".to_string()))),
        BindingPattern::AssignmentPattern {
            left: Box::new(BindingPattern::Identifier("d".to_string())),
            right: str_lit("default"),
        },
    ];
    for pat in patterns {
        let json = serde_json::to_string(&pat).unwrap();
        let restored: BindingPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, pat);
    }
}

// =========================================================================
// Expression Display
// =========================================================================

#[test]
fn enrichment_expression_display_all_simple_variants() {
    assert_eq!(id("foo").to_string(), "foo");
    assert_eq!(str_lit("bar").to_string(), "\"bar\"");
    assert_eq!(num(42).to_string(), "42");
    assert_eq!(num(-1).to_string(), "-1");
    assert_eq!(Expression::BooleanLiteral(false).to_string(), "false");
    assert_eq!(Expression::NullLiteral.to_string(), "null");
    assert_eq!(Expression::UndefinedLiteral.to_string(), "undefined");
    assert_eq!(Expression::This.to_string(), "this");
    assert_eq!(
        Expression::Raw("a + b".to_string()).to_string(),
        "a + b"
    );
}

#[test]
fn enrichment_expression_display_complex_uses_debug() {
    // Complex expressions fall back to Debug formatting
    let expr = Expression::Binary {
        operator: BinaryOperator::Add,
        left: Box::new(num(1)),
        right: Box::new(num(2)),
    };
    let display = expr.to_string();
    assert!(display.contains("Binary"));
}

// =========================================================================
// Operator coverage
// =========================================================================

#[test]
fn enrichment_all_binary_operators_have_nonzero_precedence() {
    let ops = [
        BinaryOperator::Add,
        BinaryOperator::Subtract,
        BinaryOperator::Multiply,
        BinaryOperator::Divide,
        BinaryOperator::Remainder,
        BinaryOperator::Exponentiate,
        BinaryOperator::Equal,
        BinaryOperator::NotEqual,
        BinaryOperator::StrictEqual,
        BinaryOperator::StrictNotEqual,
        BinaryOperator::LessThan,
        BinaryOperator::LessThanOrEqual,
        BinaryOperator::GreaterThan,
        BinaryOperator::GreaterThanOrEqual,
        BinaryOperator::LogicalAnd,
        BinaryOperator::LogicalOr,
        BinaryOperator::NullishCoalescing,
        BinaryOperator::BitwiseAnd,
        BinaryOperator::BitwiseOr,
        BinaryOperator::BitwiseXor,
        BinaryOperator::LeftShift,
        BinaryOperator::RightShift,
        BinaryOperator::UnsignedRightShift,
        BinaryOperator::Instanceof,
        BinaryOperator::In,
    ];
    for op in &ops {
        assert!(op.precedence() > 0, "{:?} has zero precedence", op);
    }
}

#[test]
fn enrichment_precedence_same_level_operators() {
    // Arithmetic at same level
    assert_eq!(
        BinaryOperator::Multiply.precedence(),
        BinaryOperator::Divide.precedence()
    );
    assert_eq!(
        BinaryOperator::Divide.precedence(),
        BinaryOperator::Remainder.precedence()
    );
    assert_eq!(
        BinaryOperator::Add.precedence(),
        BinaryOperator::Subtract.precedence()
    );
    // Equality at same level
    assert_eq!(
        BinaryOperator::Equal.precedence(),
        BinaryOperator::StrictNotEqual.precedence()
    );
    // Shift at same level
    assert_eq!(
        BinaryOperator::LeftShift.precedence(),
        BinaryOperator::UnsignedRightShift.precedence()
    );
    // Relational at same level
    assert_eq!(
        BinaryOperator::LessThan.precedence(),
        BinaryOperator::Instanceof.precedence()
    );
}

#[test]
fn enrichment_only_exponentiate_is_right_associative() {
    let all_ops = [
        BinaryOperator::Add,
        BinaryOperator::Subtract,
        BinaryOperator::Multiply,
        BinaryOperator::Divide,
        BinaryOperator::Remainder,
        BinaryOperator::Equal,
        BinaryOperator::NotEqual,
        BinaryOperator::StrictEqual,
        BinaryOperator::StrictNotEqual,
        BinaryOperator::LessThan,
        BinaryOperator::LessThanOrEqual,
        BinaryOperator::GreaterThan,
        BinaryOperator::GreaterThanOrEqual,
        BinaryOperator::LogicalAnd,
        BinaryOperator::LogicalOr,
        BinaryOperator::NullishCoalescing,
        BinaryOperator::BitwiseAnd,
        BinaryOperator::BitwiseOr,
        BinaryOperator::BitwiseXor,
        BinaryOperator::LeftShift,
        BinaryOperator::RightShift,
        BinaryOperator::UnsignedRightShift,
        BinaryOperator::Instanceof,
        BinaryOperator::In,
    ];
    for op in &all_ops {
        assert!(!op.is_right_associative(), "{:?} should be left-assoc", op);
    }
    assert!(BinaryOperator::Exponentiate.is_right_associative());
}

#[test]
fn enrichment_all_assignment_operators_as_str_unique() {
    let ops = [
        AssignmentOperator::Assign,
        AssignmentOperator::AddAssign,
        AssignmentOperator::SubtractAssign,
        AssignmentOperator::MultiplyAssign,
        AssignmentOperator::DivideAssign,
        AssignmentOperator::RemainderAssign,
        AssignmentOperator::ExponentiateAssign,
        AssignmentOperator::LeftShiftAssign,
        AssignmentOperator::RightShiftAssign,
        AssignmentOperator::UnsignedRightShiftAssign,
        AssignmentOperator::BitwiseAndAssign,
        AssignmentOperator::BitwiseOrAssign,
        AssignmentOperator::BitwiseXorAssign,
        AssignmentOperator::LogicalAndAssign,
        AssignmentOperator::LogicalOrAssign,
        AssignmentOperator::NullishCoalescingAssign,
    ];
    let mut seen = BTreeSet::new();
    for op in &ops {
        assert!(seen.insert(op.as_str()), "duplicate: {}", op.as_str());
    }
    assert_eq!(seen.len(), 16);
}

// =========================================================================
// VariableDeclarator
// =========================================================================

#[test]
fn enrichment_variable_declarator_name_simple_identifier() {
    let decl = VariableDeclarator {
        pattern: BindingPattern::Identifier("count".to_string()),
        initializer: Some(num(0)),
        span: s0(),
    };
    assert_eq!(decl.name(), Some("count"));
}

#[test]
fn enrichment_variable_declarator_name_destructured_returns_none() {
    let decl = VariableDeclarator {
        pattern: BindingPattern::ObjectPattern(vec![]),
        initializer: None,
        span: s0(),
    };
    assert_eq!(decl.name(), None);
}

#[test]
fn enrichment_variable_declaration_with_destructuring_serde() {
    let decl = VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ArrayPattern(vec![
                Some(BindingPattern::Identifier("x".to_string())),
                Some(BindingPattern::Identifier("y".to_string())),
            ]),
            initializer: Some(Expression::ArrayLiteral(vec![
                Some(num(1)),
                Some(num(2)),
            ])),
            span: s0(),
        }],
        span: s0(),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let restored: VariableDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, restored);
}

// =========================================================================
// FunctionParam
// =========================================================================

#[test]
fn enrichment_function_param_name_with_simple_binding() {
    let param = FunctionParam {
        pattern: BindingPattern::Identifier("arg".to_string()),
        span: s0(),
    };
    assert_eq!(param.name(), Some("arg"));
}

#[test]
fn enrichment_function_param_name_with_destructured_binding() {
    let param = FunctionParam {
        pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
            key: id("a"),
            value: BindingPattern::Identifier("a".to_string()),
            computed: false,
            shorthand: true,
        }]),
        span: s0(),
    };
    assert_eq!(param.name(), None);
}

// =========================================================================
// FunctionDeclaration
// =========================================================================

#[test]
fn enrichment_function_declaration_with_destructured_params_serde() {
    let func = FunctionDeclaration {
        name: Some("handler".to_string()),
        params: vec![
            FunctionParam {
                pattern: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: id("req"),
                        value: BindingPattern::Identifier("req".to_string()),
                        computed: false,
                        shorthand: true,
                    },
                    ObjectPatternProperty {
                        key: id("res"),
                        value: BindingPattern::Identifier("res".to_string()),
                        computed: false,
                        shorthand: true,
                    },
                ]),
                span: s0(),
            },
            FunctionParam {
                pattern: BindingPattern::AssignmentPattern {
                    left: Box::new(BindingPattern::Identifier("options".to_string())),
                    right: Expression::ObjectLiteral(vec![]),
                },
                span: s0(),
            },
        ],
        body: block(vec![]),
        is_async: true,
        is_generator: false,
        span: s0(),
    };
    let json = serde_json::to_string(&func).unwrap();
    let restored: FunctionDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(func, restored);
}

// =========================================================================
// ArrowBody
// =========================================================================

#[test]
fn enrichment_arrow_body_expression_vs_block_serde() {
    let expr_body = ArrowBody::Expression(Box::new(num(42)));
    let block_body = ArrowBody::Block(block(vec![Statement::Return(ReturnStatement {
        argument: Some(num(42)),
        span: s0(),
    })]));
    for body in &[expr_body, block_body] {
        let json = serde_json::to_string(body).unwrap();
        let restored: ArrowBody = serde_json::from_str(&json).unwrap();
        assert_eq!(&restored, body);
    }
}

// =========================================================================
// ArrowFunction expression
// =========================================================================

#[test]
fn enrichment_arrow_function_async_with_destructured_params() {
    let expr = Expression::ArrowFunction {
        params: vec![FunctionParam {
            pattern: BindingPattern::ArrayPattern(vec![
                Some(BindingPattern::Identifier("a".to_string())),
                Some(BindingPattern::Identifier("b".to_string())),
            ]),
            span: s0(),
        }],
        body: ArrowBody::Expression(Box::new(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(id("a")),
            right: Box::new(id("b")),
        })),
        is_async: true,
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

// =========================================================================
// Control flow statements comprehensive round-trip
// =========================================================================

#[test]
fn enrichment_try_catch_finally_full_serde() {
    let stmt = Statement::TryCatch(TryCatchStatement {
        block: block(vec![expr_stmt(Expression::Call {
            callee: Box::new(id("riskyOp")),
            arguments: vec![],
        })]),
        handler: Some(CatchClause {
            parameter: Some("err".to_string()),
            body: block(vec![expr_stmt(Expression::Call {
                callee: Box::new(Expression::Member {
                    object: Box::new(id("console")),
                    property: Box::new(id("error")),
                    computed: false,
                }),
                arguments: vec![id("err")],
            })]),
            span: s0(),
        }),
        finalizer: Some(block(vec![expr_stmt(Expression::Call {
            callee: Box::new(id("cleanup")),
            arguments: vec![],
        })])),
        span: s0(),
    });
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_try_without_handler_or_finalizer_serde() {
    let stmt = TryCatchStatement {
        block: block(vec![]),
        handler: None,
        finalizer: None,
        span: s0(),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: TryCatchStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_switch_with_default_and_fallthrough_serde() {
    let stmt = Statement::Switch(SwitchStatement {
        discriminant: id("action"),
        cases: vec![
            SwitchCase {
                test: Some(str_lit("start")),
                consequent: vec![
                    expr_stmt(Expression::Call {
                        callee: Box::new(id("begin")),
                        arguments: vec![],
                    }),
                    Statement::Break(BreakStatement {
                        label: None,
                        span: s0(),
                    }),
                ],
                span: s0(),
            },
            SwitchCase {
                test: Some(str_lit("stop")),
                consequent: vec![], // fallthrough
                span: s0(),
            },
            SwitchCase {
                test: None, // default
                consequent: vec![Statement::Throw(ThrowStatement {
                    argument: Expression::New {
                        callee: Box::new(id("Error")),
                        arguments: vec![str_lit("unknown")],
                    },
                    span: s0(),
                })],
                span: s0(),
            },
        ],
        span: s0(),
    });
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_for_in_with_const_binding() {
    let stmt = ForInStatement {
        binding: BindingPattern::Identifier("key".to_string()),
        binding_kind: Some(VariableDeclarationKind::Const),
        object: id("obj"),
        body: Box::new(expr_stmt(Expression::Call {
            callee: Box::new(Expression::Member {
                object: Box::new(id("console")),
                property: Box::new(id("log")),
                computed: false,
            }),
            arguments: vec![id("key")],
        })),
        span: s0(),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: ForInStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_for_of_without_binding_kind() {
    let stmt = ForOfStatement {
        binding: BindingPattern::ArrayPattern(vec![
            Some(BindingPattern::Identifier("k".to_string())),
            Some(BindingPattern::Identifier("v".to_string())),
        ]),
        binding_kind: None,
        iterable: Expression::Call {
            callee: Box::new(Expression::Member {
                object: Box::new(id("map")),
                property: Box::new(id("entries")),
                computed: false,
            }),
            arguments: vec![],
        },
        body: Box::new(Statement::Block(block(vec![]))),
        span: s0(),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: ForOfStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_while_with_complex_condition() {
    let stmt = WhileStatement {
        condition: Expression::Binary {
            operator: BinaryOperator::LogicalAnd,
            left: Box::new(Expression::Binary {
                operator: BinaryOperator::GreaterThan,
                left: Box::new(id("i")),
                right: Box::new(num(0)),
            }),
            right: Box::new(Expression::Unary {
                operator: UnaryOperator::LogicalNot,
                argument: Box::new(id("done")),
            }),
        },
        body: Box::new(Statement::Block(block(vec![]))),
        span: s0(),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: WhileStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

#[test]
fn enrichment_do_while_serde() {
    let stmt = DoWhileStatement {
        body: Box::new(expr_stmt(Expression::Assignment {
            operator: AssignmentOperator::AddAssign,
            left: Box::new(id("sum")),
            right: Box::new(num(1)),
        })),
        condition: Expression::Binary {
            operator: BinaryOperator::LessThan,
            left: Box::new(id("sum")),
            right: Box::new(num(100)),
        },
        span: s0(),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let restored: DoWhileStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(stmt, restored);
}

// =========================================================================
// Complex expression types
// =========================================================================

#[test]
fn enrichment_optional_chaining_member_and_call() {
    let expr = Expression::OptionalCall {
        callee: Box::new(Expression::OptionalMember {
            object: Box::new(id("obj")),
            property: Box::new(id("method")),
            computed: false,
        }),
        arguments: vec![num(1), num(2)],
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_optional_member_computed() {
    let expr = Expression::OptionalMember {
        object: Box::new(id("arr")),
        property: Box::new(num(0)),
        computed: true,
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_template_literal_empty() {
    let expr = Expression::TemplateLiteral {
        quasis: vec!["".to_string()],
        expressions: vec![],
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_template_literal_multiple_expressions() {
    let expr = Expression::TemplateLiteral {
        quasis: vec![
            "Hello ".to_string(),
            ", you are ".to_string(),
            " years old".to_string(),
        ],
        expressions: vec![id("name"), id("age")],
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_new_expression_with_no_args() {
    let expr = Expression::New {
        callee: Box::new(id("Map")),
        arguments: vec![],
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_array_literal_all_holes() {
    let expr = Expression::ArrayLiteral(vec![None, None, None]);
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

#[test]
fn enrichment_object_literal_computed_key() {
    let expr = Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::Call {
            callee: Box::new(id("Symbol")),
            arguments: vec![str_lit("key")],
        },
        value: num(42),
        computed: true,
        shorthand: false,
    }]);
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

// =========================================================================
// Constants and metadata
// =========================================================================

#[test]
fn enrichment_constants_are_stable() {
    assert_eq!(
        CANONICAL_AST_CONTRACT_VERSION,
        "franken-engine.parser-ast.contract.v1"
    );
    assert_eq!(
        CANONICAL_AST_SCHEMA_VERSION,
        "franken-engine.parser-ast.schema.v1"
    );
    assert_eq!(CANONICAL_AST_HASH_ALGORITHM, "sha256");
    assert_eq!(CANONICAL_AST_HASH_PREFIX, "sha256:");
}

#[test]
fn enrichment_syntax_tree_accessors_match_constants() {
    assert_eq!(
        SyntaxTree::canonical_contract_version(),
        CANONICAL_AST_CONTRACT_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_schema_version(),
        CANONICAL_AST_SCHEMA_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_hash_algorithm(),
        CANONICAL_AST_HASH_ALGORITHM
    );
    assert_eq!(
        SyntaxTree::canonical_hash_prefix(),
        CANONICAL_AST_HASH_PREFIX
    );
}

// =========================================================================
// Canonical hash format validation
// =========================================================================

#[test]
fn enrichment_canonical_hash_format() {
    let t = tree(ParseGoal::Script, vec![expr_stmt(num(42))]);
    let hash = t.canonical_hash();
    assert!(hash.starts_with("sha256:"));
    let hex_part = &hash[7..];
    assert_eq!(hex_part.len(), 64);
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_canonical_bytes_nonempty_for_empty_tree() {
    let t = tree(ParseGoal::Script, vec![]);
    let bytes = t.canonical_bytes();
    assert!(!bytes.is_empty());
}

// =========================================================================
// Full program round-trip: realistic JS program
// =========================================================================

#[test]
fn enrichment_realistic_module_round_trip() {
    let program = tree(
        ParseGoal::Module,
        vec![
            // import React from 'react';
            Statement::Import(ImportDeclaration {
                binding: Some("React".to_string()),
                source: "react".to_string(),
                span: span(0, 28),
            }),
            // import { useState } from 'react';
            Statement::Import(ImportDeclaration {
                binding: Some("useState".to_string()),
                source: "react".to_string(),
                span: span(29, 60),
            }),
            // const [count, setCount] = useState(0);
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::ArrayPattern(vec![
                        Some(BindingPattern::Identifier("count".to_string())),
                        Some(BindingPattern::Identifier("setCount".to_string())),
                    ]),
                    initializer: Some(Expression::Call {
                        callee: Box::new(id("useState")),
                        arguments: vec![num(0)],
                    }),
                    span: span(61, 95),
                }],
                span: span(61, 95),
            }),
            // function increment() { setCount(count + 1); }
            Statement::FunctionDeclaration(simple_func(
                "increment",
                &[],
                vec![expr_stmt(Expression::Call {
                    callee: Box::new(id("setCount")),
                    arguments: vec![Expression::Binary {
                        operator: BinaryOperator::Add,
                        left: Box::new(id("count")),
                        right: Box::new(num(1)),
                    }],
                })],
            )),
            // export default increment;
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(id("increment")),
                span: span(200, 225),
            }),
        ],
    );
    let json = serde_json::to_string(&program).unwrap();
    let restored: SyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(program, restored);
    assert_eq!(program.canonical_hash(), restored.canonical_hash());
}

// =========================================================================
// Statement span accessor for all 18 variants
// =========================================================================

#[test]
fn enrichment_statement_span_returns_correct_for_all_18_variants() {
    let target = span(42, 84);
    let stmts: Vec<Statement> = vec![
        Statement::Import(ImportDeclaration {
            binding: None,
            source: "m".to_string(),
            span: target.clone(),
        }),
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("x".to_string()),
            span: target.clone(),
        }),
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![],
            span: target.clone(),
        }),
        Statement::Expression(ExpressionStatement {
            expression: Expression::NullLiteral,
            span: target.clone(),
        }),
        Statement::Block(BlockStatement {
            body: vec![],
            span: target.clone(),
        }),
        Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(expr_stmt(Expression::NullLiteral)),
            alternate: None,
            span: target.clone(),
        }),
        Statement::For(ForStatement {
            init: None,
            condition: None,
            update: None,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: target.clone(),
        }),
        Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: target.clone(),
        }),
        Statement::DoWhile(DoWhileStatement {
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            condition: Expression::BooleanLiteral(true),
            span: target.clone(),
        }),
        Statement::Return(ReturnStatement {
            argument: None,
            span: target.clone(),
        }),
        Statement::Throw(ThrowStatement {
            argument: Expression::NullLiteral,
            span: target.clone(),
        }),
        Statement::TryCatch(TryCatchStatement {
            block: block(vec![]),
            handler: None,
            finalizer: None,
            span: target.clone(),
        }),
        Statement::Switch(SwitchStatement {
            discriminant: Expression::NullLiteral,
            cases: vec![],
            span: target.clone(),
        }),
        Statement::Break(BreakStatement {
            label: None,
            span: target.clone(),
        }),
        Statement::Continue(ContinueStatement {
            label: None,
            span: target.clone(),
        }),
        Statement::FunctionDeclaration(FunctionDeclaration {
            name: None,
            params: vec![],
            body: block(vec![]),
            is_async: false,
            is_generator: false,
            span: target.clone(),
        }),
        Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".to_string()),
            binding_kind: None,
            object: Expression::NullLiteral,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: target.clone(),
        }),
        Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("v".to_string()),
            binding_kind: None,
            iterable: Expression::NullLiteral,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: target.clone(),
        }),
    ];
    assert_eq!(stmts.len(), 18);
    for stmt in &stmts {
        assert_eq!(stmt.span(), &target);
    }
}

// =========================================================================
// All 18 statement canonical kinds are unique
// =========================================================================

#[test]
fn enrichment_all_18_statement_canonical_kinds_unique() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let stmts = vec![
        Statement::Import(ImportDeclaration {
            binding: None,
            source: "m".to_string(),
            span: s0(),
        }),
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("x".to_string()),
            span: s0(),
        }),
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![],
            span: s0(),
        }),
        Statement::Expression(ExpressionStatement {
            expression: Expression::NullLiteral,
            span: s0(),
        }),
        Statement::Block(block(vec![])),
        Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(expr_stmt(Expression::NullLiteral)),
            alternate: None,
            span: s0(),
        }),
        Statement::For(ForStatement {
            init: None,
            condition: None,
            update: None,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: s0(),
        }),
        Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: s0(),
        }),
        Statement::DoWhile(DoWhileStatement {
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            condition: Expression::BooleanLiteral(true),
            span: s0(),
        }),
        Statement::Return(ReturnStatement {
            argument: None,
            span: s0(),
        }),
        Statement::Throw(ThrowStatement {
            argument: Expression::NullLiteral,
            span: s0(),
        }),
        Statement::TryCatch(TryCatchStatement {
            block: block(vec![]),
            handler: None,
            finalizer: None,
            span: s0(),
        }),
        Statement::Switch(SwitchStatement {
            discriminant: Expression::NullLiteral,
            cases: vec![],
            span: s0(),
        }),
        Statement::Break(BreakStatement {
            label: None,
            span: s0(),
        }),
        Statement::Continue(ContinueStatement {
            label: None,
            span: s0(),
        }),
        Statement::FunctionDeclaration(FunctionDeclaration {
            name: None,
            params: vec![],
            body: block(vec![]),
            is_async: false,
            is_generator: false,
            span: s0(),
        }),
        Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".to_string()),
            binding_kind: None,
            object: Expression::NullLiteral,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: s0(),
        }),
        Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("v".to_string()),
            binding_kind: None,
            iterable: Expression::NullLiteral,
            body: Box::new(expr_stmt(Expression::NullLiteral)),
            span: s0(),
        }),
    ];
    let mut kinds = BTreeSet::new();
    for stmt in &stmts {
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            if let Some(CanonicalValue::String(k)) = map.get("kind") {
                assert!(kinds.insert(k.clone()), "duplicate: {k}");
            }
        }
    }
    assert_eq!(kinds.len(), 18);
}

// =========================================================================
// ParseGoal
// =========================================================================

#[test]
fn enrichment_parse_goal_as_str() {
    assert_eq!(ParseGoal::Script.as_str(), "script");
    assert_eq!(ParseGoal::Module.as_str(), "module");
}

#[test]
fn enrichment_parse_goal_serde_roundtrip() {
    for goal in [ParseGoal::Script, ParseGoal::Module] {
        let json = serde_json::to_string(&goal).unwrap();
        let restored: ParseGoal = serde_json::from_str(&json).unwrap();
        assert_eq!(goal, restored);
    }
}

// =========================================================================
// VariableDeclarationKind
// =========================================================================

#[test]
fn enrichment_variable_declaration_kind_as_str() {
    assert_eq!(VariableDeclarationKind::Var.as_str(), "var");
    assert_eq!(VariableDeclarationKind::Let.as_str(), "let");
    assert_eq!(VariableDeclarationKind::Const.as_str(), "const");
}

// =========================================================================
// ExportKind
// =========================================================================

#[test]
fn enrichment_export_kind_default_vs_named_different_canonical() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let default = ExportKind::Default(id("x"));
    let named = ExportKind::NamedClause("x".to_string());
    let cv1 = default.canonical_value();
    let cv2 = named.canonical_value();
    assert_ne!(cv1, cv2);
    // Both are maps with "kind" key
    if let (CanonicalValue::Map(m1), CanonicalValue::Map(m2)) = (&cv1, &cv2) {
        assert_eq!(
            m1.get("kind"),
            Some(&CanonicalValue::String("default".to_string()))
        );
        assert_eq!(
            m2.get("kind"),
            Some(&CanonicalValue::String("named".to_string()))
        );
    }
}

// =========================================================================
// Multi-declarator variable declarations
// =========================================================================

#[test]
fn enrichment_multi_declarator_var_serde() {
    let decl = VariableDeclaration {
        kind: VariableDeclarationKind::Let,
        declarations: vec![
            VariableDeclarator {
                pattern: BindingPattern::Identifier("x".to_string()),
                initializer: Some(num(1)),
                span: s0(),
            },
            VariableDeclarator {
                pattern: BindingPattern::Identifier("y".to_string()),
                initializer: Some(num(2)),
                span: s0(),
            },
            VariableDeclarator {
                pattern: BindingPattern::Identifier("z".to_string()),
                initializer: None,
                span: s0(),
            },
        ],
        span: s0(),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let restored: VariableDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, restored);
    assert_eq!(decl.declarations.len(), 3);
}

// =========================================================================
// CatchClause
// =========================================================================

#[test]
fn enrichment_catch_clause_with_and_without_parameter() {
    let with_param = CatchClause {
        parameter: Some("e".to_string()),
        body: block(vec![]),
        span: s0(),
    };
    let without_param = CatchClause {
        parameter: None,
        body: block(vec![]),
        span: s0(),
    };
    for clause in &[with_param, without_param] {
        let json = serde_json::to_string(clause).unwrap();
        let restored: CatchClause = serde_json::from_str(&json).unwrap();
        assert_eq!(clause, &restored);
    }
}

// =========================================================================
// BreakStatement / ContinueStatement with labels
// =========================================================================

#[test]
fn enrichment_break_continue_with_labels() {
    let brk = BreakStatement {
        label: Some("outer".to_string()),
        span: s0(),
    };
    let cont = ContinueStatement {
        label: Some("inner".to_string()),
        span: s0(),
    };
    let json_brk = serde_json::to_string(&brk).unwrap();
    let json_cont = serde_json::to_string(&cont).unwrap();
    let r_brk: BreakStatement = serde_json::from_str(&json_brk).unwrap();
    let r_cont: ContinueStatement = serde_json::from_str(&json_cont).unwrap();
    assert_eq!(brk, r_brk);
    assert_eq!(cont, r_cont);
}

// =========================================================================
// Complex scenarios: conditional + call chaining
// =========================================================================

#[test]
fn enrichment_conditional_with_call_chains() {
    let expr = Expression::Conditional {
        test: Expression::Binary {
            operator: BinaryOperator::StrictEqual,
            left: Box::new(Expression::Unary {
                operator: UnaryOperator::Typeof,
                argument: Box::new(id("x")),
            }),
            right: Box::new(str_lit("function")),
        }.into(),
        consequent: Box::new(Expression::Call {
            callee: Box::new(id("x")),
            arguments: vec![],
        }),
        alternate: Box::new(Expression::Identifier("x".to_string())),
    };
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

// =========================================================================
// ObjectPatternProperty
// =========================================================================

#[test]
fn enrichment_object_pattern_property_computed_vs_shorthand() {
    let computed = ObjectPatternProperty {
        key: Expression::Call {
            callee: Box::new(id("Symbol")),
            arguments: vec![str_lit("key")],
        },
        value: BindingPattern::Identifier("val".to_string()),
        computed: true,
        shorthand: false,
    };
    let shorthand = ObjectPatternProperty {
        key: id("x"),
        value: BindingPattern::Identifier("x".to_string()),
        computed: false,
        shorthand: true,
    };
    for prop in &[computed, shorthand] {
        let json = serde_json::to_string(prop).unwrap();
        let restored: ObjectPatternProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(prop, &restored);
    }
}

// =========================================================================
// Await expression
// =========================================================================

#[test]
fn enrichment_await_deeply_nested() {
    let expr = Expression::Await(Box::new(Expression::Await(Box::new(Expression::Await(
        Box::new(Expression::Call {
            callee: Box::new(id("fetch")),
            arguments: vec![str_lit("https://example.com")],
        }),
    )))));
    let json = serde_json::to_string(&expr).unwrap();
    let restored: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, restored);
}

// =========================================================================
// Span boundary values
// =========================================================================

#[test]
fn enrichment_source_span_zero_length() {
    let sp = SourceSpan::new(5, 5, 1, 6, 1, 6);
    assert_eq!(sp.start_offset, sp.end_offset);
    let json = serde_json::to_string(&sp).unwrap();
    let restored: SourceSpan = serde_json::from_str(&json).unwrap();
    assert_eq!(sp, restored);
}

#[test]
fn enrichment_source_span_large_values() {
    let sp = SourceSpan::new(u64::MAX - 1, u64::MAX, 999_999, 1, 999_999, 100);
    let json = serde_json::to_string(&sp).unwrap();
    let restored: SourceSpan = serde_json::from_str(&json).unwrap();
    assert_eq!(sp, restored);
}

// =========================================================================
// Full expression variant canonical kinds unique
// =========================================================================

#[test]
fn enrichment_all_expression_canonical_kinds_unique() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let exprs: Vec<Expression> = vec![
        Expression::Identifier("a".to_string()),
        Expression::StringLiteral("b".to_string()),
        Expression::NumericLiteral(0),
        Expression::BooleanLiteral(true),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Await(Box::new(Expression::NullLiteral)),
        Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(num(1)),
            right: Box::new(num(2)),
        },
        Expression::Unary {
            operator: UnaryOperator::Negate,
            argument: Box::new(num(1)),
        },
        Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(id("x")),
            right: Box::new(num(1)),
        },
        Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(num(1)),
            alternate: Box::new(num(0)),
        },
        Expression::Call {
            callee: Box::new(id("f")),
            arguments: vec![],
        },
        Expression::Member {
            object: Box::new(id("o")),
            property: Box::new(id("p")),
            computed: false,
        },
        Expression::OptionalCall {
            callee: Box::new(id("f")),
            arguments: vec![],
        },
        Expression::OptionalMember {
            object: Box::new(id("o")),
            property: Box::new(id("p")),
            computed: false,
        },
        Expression::This,
        Expression::ArrayLiteral(vec![]),
        Expression::ObjectLiteral(vec![]),
        Expression::ArrowFunction {
            params: vec![],
            body: ArrowBody::Expression(Box::new(num(0))),
            is_async: false,
        },
        Expression::New {
            callee: Box::new(id("C")),
            arguments: vec![],
        },
        Expression::TemplateLiteral {
            quasis: vec!["".to_string()],
            expressions: vec![],
        },
        Expression::Raw("raw".to_string()),
    ];
    let mut kinds = BTreeSet::new();
    for expr in &exprs {
        if let CanonicalValue::Map(map) = expr.canonical_value() {
            if let Some(CanonicalValue::String(k)) = map.get("kind") {
                assert!(kinds.insert(k.clone()), "duplicate kind: {k}");
            }
        }
    }
    assert_eq!(kinds.len(), 22);
}

// =========================================================================
// UnaryOperator
// =========================================================================

#[test]
fn enrichment_unary_operator_all_as_str_unique() {
    let ops = [
        UnaryOperator::Negate,
        UnaryOperator::BitwiseNot,
        UnaryOperator::LogicalNot,
        UnaryOperator::Typeof,
        UnaryOperator::Void,
        UnaryOperator::Delete,
        UnaryOperator::UnaryPlus,
    ];
    let mut seen = BTreeSet::new();
    for op in &ops {
        assert!(seen.insert(op.as_str()), "duplicate: {}", op.as_str());
    }
    assert_eq!(seen.len(), 7);
}

// =========================================================================
// Syntax tree with every statement type
// =========================================================================

#[test]
fn enrichment_syntax_tree_with_all_statement_types_round_trips() {
    let program = tree(
        ParseGoal::Script,
        vec![
            Statement::Import(ImportDeclaration {
                binding: Some("x".to_string()),
                source: "mod".to_string(),
                span: s0(),
            }),
            var_stmt("y", Some(num(1))),
            expr_stmt(id("y")),
            Statement::Block(block(vec![])),
            Statement::If(IfStatement {
                condition: Expression::BooleanLiteral(true),
                consequent: Box::new(expr_stmt(num(1))),
                alternate: None,
                span: s0(),
            }),
            Statement::For(ForStatement {
                init: None,
                condition: None,
                update: None,
                body: Box::new(Statement::Break(BreakStatement {
                    label: None,
                    span: s0(),
                })),
                span: s0(),
            }),
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: Some(VariableDeclarationKind::Const),
                object: id("obj"),
                body: Box::new(expr_stmt(id("k"))),
                span: s0(),
            }),
            Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                iterable: id("arr"),
                body: Box::new(expr_stmt(id("v"))),
                span: s0(),
            }),
            Statement::While(WhileStatement {
                condition: Expression::BooleanLiteral(false),
                body: Box::new(expr_stmt(num(0))),
                span: s0(),
            }),
            Statement::DoWhile(DoWhileStatement {
                body: Box::new(expr_stmt(num(0))),
                condition: Expression::BooleanLiteral(false),
                span: s0(),
            }),
            Statement::Return(ReturnStatement {
                argument: Some(num(0)),
                span: s0(),
            }),
            Statement::Throw(ThrowStatement {
                argument: str_lit("error"),
                span: s0(),
            }),
            Statement::TryCatch(TryCatchStatement {
                block: block(vec![]),
                handler: Some(CatchClause {
                    parameter: Some("e".to_string()),
                    body: block(vec![]),
                    span: s0(),
                }),
                finalizer: None,
                span: s0(),
            }),
            Statement::Switch(SwitchStatement {
                discriminant: id("x"),
                cases: vec![SwitchCase {
                    test: Some(num(1)),
                    consequent: vec![],
                    span: s0(),
                }],
                span: s0(),
            }),
            Statement::Continue(ContinueStatement {
                label: None,
                span: s0(),
            }),
            Statement::FunctionDeclaration(simple_func("f", &[], vec![])),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(id("f")),
                span: s0(),
            }),
        ],
    );
    let json = serde_json::to_string(&program).unwrap();
    let restored: SyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(program, restored);
    assert_eq!(program.canonical_hash(), restored.canonical_hash());
}
