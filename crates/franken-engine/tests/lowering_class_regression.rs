#![forbid(unsafe_code)]

use frankenengine_engine::ast::{
    BlockStatement, ClassDeclaration, Expression, ExpressionStatement, MethodDefinition,
    MethodKind, ParseGoal, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::ir_contract::{Ir1Op, Ir1PropertyKey};
use frankenengine_engine::lowering_pipeline::lower_ir0_to_ir1;

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 0, 1, 1)
}

fn empty_block() -> BlockStatement {
    BlockStatement {
        body: Vec::new(),
        span: span(),
    }
}

fn class_declaration(name: Option<&str>, body: Vec<MethodDefinition>) -> Statement {
    Statement::ClassDeclaration(ClassDeclaration {
        name: name.map(str::to_string),
        super_class: None,
        body,
        span: span(),
    })
}

fn static_method(name: &str) -> MethodDefinition {
    MethodDefinition {
        key: Expression::Identifier(name.to_string()),
        kind: MethodKind::Method,
        params: Vec::new(),
        body: empty_block(),
        is_static: true,
        computed: false,
        span: span(),
    }
}

fn constructor(body: Vec<Statement>) -> MethodDefinition {
    MethodDefinition {
        key: Expression::Identifier("constructor".to_string()),
        kind: MethodKind::Constructor,
        params: Vec::new(),
        body: BlockStatement { body, span: span() },
        is_static: false,
        computed: false,
        span: span(),
    }
}

fn lower_statements(body: Vec<Statement>, source_label: &str) -> Vec<Ir1Op> {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body,
        span: span(),
    };
    let ir0 = frankenengine_engine::ir_contract::Ir0Module::from_syntax_tree(tree, source_label);

    lower_ir0_to_ir1(&ir0)
        .expect("class fixture should lower")
        .module
        .ops
}

fn assert_declares_default_constructor(ops: &[Ir1Op], class_name: &str) {
    let Some(Ir1Op::DeclareFunction {
        name,
        param_names,
        body_ops,
        ..
    }) = ops.iter().find(|op| {
        matches!(
            op,
            Ir1Op::DeclareFunction { name, .. } if name == class_name
        )
    })
    else {
        panic!("expected DeclareFunction for {class_name}, got {ops:?}");
    };

    assert_eq!(name, class_name);
    assert!(
        param_names.is_empty(),
        "default constructor should not synthesize params"
    );
    assert!(
        matches!(body_ops.last(), Some(Ir1Op::Return)),
        "default constructor body should terminate with return"
    );
}

#[test]
fn empty_class_declaration_without_constructor_lowers_default_constructor() {
    let ops = lower_statements(
        vec![class_declaration(Some("NoConstructor"), Vec::new())],
        "class-no-constructor.js",
    );

    assert_declares_default_constructor(&ops, "NoConstructor");
}

#[test]
fn anonymous_class_declaration_without_constructor_lowers_default_constructor() {
    let ops = lower_statements(
        vec![class_declaration(None, Vec::new())],
        "anonymous-class-no-constructor.js",
    );

    assert_declares_default_constructor(&ops, "anonymous");
}

#[test]
fn static_only_class_declaration_without_constructor_lowers_static_member() {
    let ops = lower_statements(
        vec![class_declaration(
            Some("StaticOnly"),
            vec![static_method("make")],
        )],
        "static-only-class-no-constructor.js",
    );

    assert_declares_default_constructor(&ops, "StaticOnly");
    assert!(ops.iter().any(|op| matches!(
        op,
        Ir1Op::CreateFunction {
            name: Some(name),
            ..
        } if name == "make"
    )));
    assert!(ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(key),
        } if key == "make"
    )));
}

#[test]
fn constructor_with_nested_class_expression_without_constructor_lowers() {
    let nested_class = Statement::Expression(ExpressionStatement {
        expression: Expression::ClassExpression {
            name: Some("Nested".to_string()),
            super_class: None,
            body: Vec::new(),
        },
        span: span(),
    });
    let ops = lower_statements(
        vec![class_declaration(
            Some("Outer"),
            vec![constructor(vec![nested_class])],
        )],
        "nested-class-expression-no-constructor.js",
    );

    assert!(
        ops.iter()
            .any(|op| matches!(op, Ir1Op::DeclareFunction { name, .. } if name == "Outer")),
        "outer class should lower while visiting nested class expression"
    );
}
