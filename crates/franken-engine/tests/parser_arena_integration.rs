#![forbid(unsafe_code)]
//! Integration tests for the `parser_arena` module.
//!
//! These tests exercise the public API from outside the crate, covering:
//! - Handle types (`NodeHandle`, `ExpressionHandle`, `SpanHandle`): construction, accessors,
//!   ordering, serde round-trips
//! - `ArenaBudgetKind` enum: all variants, serde round-trips
//! - `ArenaBudget` struct: construction, Default, serde round-trip
//! - `ArenaError` enum: all variants, Display formatting, std::error::Error impl
//! - `ArenaNode` / `ArenaExpression` enums: variant construction
//! - `HandleAuditKind` / `HandleAuditEntry`: construction, serde round-trips
//! - `ParserArena`: construction via `from_syntax_tree`, handle lookups, budget enforcement,
//!   roundtrip to/from `SyntaxTree`, canonical hashing, audit trail
//! - Determinism: same inputs always produce identical outputs
//! - Cross-concern integration with AST types

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::parser_arena::{
    ArenaBudget, ArenaBudgetKind, ArenaError, ArenaExpression, ArenaNode, ExpressionHandle,
    HandleAuditEntry, HandleAuditKind, NodeHandle, ParserArena, SpanHandle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_span(start: u64, end: u64) -> SourceSpan {
    SourceSpan::new(start, end, 1, start + 1, 1, end + 1)
}

fn simple_expression_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: make_span(0, 2),
        })],
        span: make_span(0, 10),
    }
}

fn import_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: Some("foo".to_string()),
            source: "./foo.js".to_string(),
            span: make_span(0, 20),
        })],
        span: make_span(0, 20),
    }
}

fn import_no_binding_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: None,
            source: "./side-effects.js".to_string(),
            span: make_span(0, 30),
        })],
        span: make_span(0, 30),
    }
}

fn export_default_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Identifier("bar".to_string())),
            span: make_span(0, 25),
        })],
        span: make_span(0, 25),
    }
}

fn export_named_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("{ baz }".to_string()),
            span: make_span(0, 15),
        })],
        span: make_span(0, 15),
    }
}

fn all_expression_types_tree() -> SyntaxTree {
    let expressions = vec![
        Expression::Identifier("x".to_string()),
        Expression::StringLiteral("hello".to_string()),
        Expression::NumericLiteral(123),
        Expression::BooleanLiteral(true),
        Expression::BooleanLiteral(false),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Await(Box::new(Expression::Identifier("promise".to_string()))),
        Expression::Raw("raw_code()".to_string()),
    ];
    SyntaxTree {
        goal: ParseGoal::Script,
        body: expressions
            .into_iter()
            .enumerate()
            .map(|(i, expr)| {
                Statement::Expression(ExpressionStatement {
                    expression: expr,
                    span: make_span(i as u64 * 10, (i as u64 + 1) * 10),
                })
            })
            .collect(),
        span: make_span(0, 100),
    }
}

fn mixed_statement_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                binding: Some("fs".to_string()),
                source: "node:fs".to_string(),
                span: make_span(0, 20),
            }),
            Statement::Import(ImportDeclaration {
                binding: None,
                source: "./polyfill.js".to_string(),
                span: make_span(21, 50),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::StringLiteral("default_val".to_string())),
                span: make_span(51, 80),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ alpha, beta }".to_string()),
                span: make_span(81, 110),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::BooleanLiteral(false),
                span: make_span(111, 120),
            }),
        ],
        span: make_span(0, 120),
    }
}

fn default_arena(tree: &SyntaxTree) -> ParserArena {
    ParserArena::from_syntax_tree(tree, ArenaBudget::default()).expect("arena construction")
}

// ===========================================================================
// NodeHandle
// ===========================================================================

#[test]
fn node_handle_from_parts_and_accessors() {
    let h = NodeHandle::from_parts(7, 3);
    assert_eq!(h.index(), 7);
    assert_eq!(h.generation(), 3);
}

#[test]
fn node_handle_equality() {
    let a = NodeHandle::from_parts(1, 1);
    let b = NodeHandle::from_parts(1, 1);
    let c = NodeHandle::from_parts(2, 1);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn node_handle_ordering() {
    let a = NodeHandle::from_parts(0, 1);
    let b = NodeHandle::from_parts(1, 1);
    let c = NodeHandle::from_parts(1, 2);
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn node_handle_hash_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(NodeHandle::from_parts(0, 1));
    set.insert(NodeHandle::from_parts(0, 1));
    set.insert(NodeHandle::from_parts(1, 1));
    assert_eq!(set.len(), 2);
}

#[test]
fn node_handle_serde_round_trip() {
    let original = NodeHandle::from_parts(42, 7);
    let json = serde_json::to_string(&original).expect("serialize NodeHandle");
    let decoded: NodeHandle = serde_json::from_str(&json).expect("deserialize NodeHandle");
    assert_eq!(decoded, original);
}

#[test]
fn node_handle_debug_format() {
    let h = NodeHandle::from_parts(5, 1);
    let debug = format!("{:?}", h);
    assert!(debug.contains("NodeHandle"));
    assert!(debug.contains("5"));
}

// ===========================================================================
// ExpressionHandle
// ===========================================================================

#[test]
fn expression_handle_from_parts_and_accessors() {
    let h = ExpressionHandle::from_parts(3, 2);
    assert_eq!(h.index(), 3);
    assert_eq!(h.generation(), 2);
}

#[test]
fn expression_handle_equality() {
    let a = ExpressionHandle::from_parts(0, 1);
    let b = ExpressionHandle::from_parts(0, 1);
    assert_eq!(a, b);
    assert_ne!(a, ExpressionHandle::from_parts(0, 2));
}

#[test]
fn expression_handle_ordering() {
    let a = ExpressionHandle::from_parts(0, 1);
    let b = ExpressionHandle::from_parts(1, 1);
    assert!(a < b);
}

#[test]
fn expression_handle_serde_round_trip() {
    let original = ExpressionHandle::from_parts(99, 5);
    let json = serde_json::to_string(&original).expect("serialize ExpressionHandle");
    let decoded: ExpressionHandle =
        serde_json::from_str(&json).expect("deserialize ExpressionHandle");
    assert_eq!(decoded, original);
}

#[test]
fn expression_handle_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ExpressionHandle::from_parts(0, 1));
    set.insert(ExpressionHandle::from_parts(0, 1));
    set.insert(ExpressionHandle::from_parts(1, 1));
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// SpanHandle
// ===========================================================================

#[test]
fn span_handle_from_parts_and_accessors() {
    let h = SpanHandle::from_parts(10, 3);
    assert_eq!(h.index(), 10);
    assert_eq!(h.generation(), 3);
}

#[test]
fn span_handle_equality_and_ordering() {
    let a = SpanHandle::from_parts(0, 1);
    let b = SpanHandle::from_parts(0, 1);
    let c = SpanHandle::from_parts(1, 1);
    assert_eq!(a, b);
    assert!(a < c);
}

#[test]
fn span_handle_serde_round_trip() {
    let original = SpanHandle::from_parts(255, 1);
    let json = serde_json::to_string(&original).expect("serialize SpanHandle");
    let decoded: SpanHandle = serde_json::from_str(&json).expect("deserialize SpanHandle");
    assert_eq!(decoded, original);
}

#[test]
fn span_handle_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(SpanHandle::from_parts(5, 1));
    set.insert(SpanHandle::from_parts(5, 1));
    assert_eq!(set.len(), 1);
}

// ===========================================================================
// ArenaBudgetKind
// ===========================================================================

#[test]
fn arena_budget_kind_all_variants_serde_round_trip() {
    let variants = [
        ArenaBudgetKind::Nodes,
        ArenaBudgetKind::Expressions,
        ArenaBudgetKind::Spans,
        ArenaBudgetKind::Bytes,
    ];
    for kind in &variants {
        let json = serde_json::to_string(kind).expect("serialize ArenaBudgetKind");
        let decoded: ArenaBudgetKind =
            serde_json::from_str(&json).expect("deserialize ArenaBudgetKind");
        assert_eq!(&decoded, kind);
    }
}

#[test]
fn arena_budget_kind_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&ArenaBudgetKind::Nodes).unwrap(),
        "\"nodes\""
    );
    assert_eq!(
        serde_json::to_string(&ArenaBudgetKind::Expressions).unwrap(),
        "\"expressions\""
    );
    assert_eq!(
        serde_json::to_string(&ArenaBudgetKind::Spans).unwrap(),
        "\"spans\""
    );
    assert_eq!(
        serde_json::to_string(&ArenaBudgetKind::Bytes).unwrap(),
        "\"bytes\""
    );
}

#[test]
fn arena_budget_kind_equality() {
    assert_eq!(ArenaBudgetKind::Nodes, ArenaBudgetKind::Nodes);
    assert_ne!(ArenaBudgetKind::Nodes, ArenaBudgetKind::Bytes);
}

#[test]
fn arena_budget_kind_debug() {
    let dbg = format!("{:?}", ArenaBudgetKind::Expressions);
    assert!(dbg.contains("Expressions"));
}

// ===========================================================================
// ArenaBudget
// ===========================================================================

#[test]
fn arena_budget_default_values() {
    let budget = ArenaBudget::default();
    assert_eq!(budget.max_nodes, 262_144);
    assert_eq!(budget.max_expressions, 524_288);
    assert_eq!(budget.max_spans, 524_288);
    assert_eq!(budget.max_bytes, 64 * 1024 * 1024);
}

#[test]
fn arena_budget_custom_values() {
    let budget = ArenaBudget {
        max_nodes: 10,
        max_expressions: 20,
        max_spans: 30,
        max_bytes: 1024,
    };
    assert_eq!(budget.max_nodes, 10);
    assert_eq!(budget.max_expressions, 20);
    assert_eq!(budget.max_spans, 30);
    assert_eq!(budget.max_bytes, 1024);
}

#[test]
fn arena_budget_serde_round_trip() {
    let budget = ArenaBudget {
        max_nodes: 100,
        max_expressions: 200,
        max_spans: 300,
        max_bytes: 4096,
    };
    let json = serde_json::to_string(&budget).expect("serialize ArenaBudget");
    let decoded: ArenaBudget = serde_json::from_str(&json).expect("deserialize ArenaBudget");
    assert_eq!(decoded, budget);
}

#[test]
fn arena_budget_default_serde_round_trip() {
    let budget = ArenaBudget::default();
    let json = serde_json::to_string(&budget).unwrap();
    let decoded: ArenaBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, budget);
}

#[test]
fn arena_budget_equality() {
    let a = ArenaBudget::default();
    let b = ArenaBudget::default();
    assert_eq!(a, b);
    let c = ArenaBudget {
        max_nodes: 1,
        ..ArenaBudget::default()
    };
    assert_ne!(a, c);
}

// ===========================================================================
// ArenaError — Display formatting for all variants
// ===========================================================================

#[test]
fn arena_error_display_budget_exceeded() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Nodes,
        limit: 100,
        attempted: 101,
    };
    let msg = err.to_string();
    assert!(msg.contains("arena budget exceeded"));
    assert!(msg.contains("Nodes"));
    assert!(msg.contains("100"));
    assert!(msg.contains("101"));
}

#[test]
fn arena_error_display_budget_exceeded_expressions() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Expressions,
        limit: 50,
        attempted: 51,
    };
    let msg = err.to_string();
    assert!(msg.contains("Expressions"));
}

#[test]
fn arena_error_display_budget_exceeded_spans() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Spans,
        limit: 10,
        attempted: 11,
    };
    let msg = err.to_string();
    assert!(msg.contains("Spans"));
}

#[test]
fn arena_error_display_budget_exceeded_bytes() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Bytes,
        limit: 1024,
        attempted: 2048,
    };
    let msg = err.to_string();
    assert!(msg.contains("Bytes"));
    assert!(msg.contains("1024"));
    assert!(msg.contains("2048"));
}

#[test]
fn arena_error_display_invalid_generation() {
    let err = ArenaError::InvalidGeneration {
        handle_kind: "node",
        expected: 1,
        actual: 99,
        index: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid"));
    assert!(msg.contains("node"));
    assert!(msg.contains("index 5"));
    assert!(msg.contains("expected 1"));
    assert!(msg.contains("got 99"));
}

#[test]
fn arena_error_display_invalid_generation_expression() {
    let err = ArenaError::InvalidGeneration {
        handle_kind: "expression",
        expected: 1,
        actual: 0,
        index: 3,
    };
    let msg = err.to_string();
    assert!(msg.contains("expression"));
    assert!(msg.contains("index 3"));
}

#[test]
fn arena_error_display_invalid_generation_span() {
    let err = ArenaError::InvalidGeneration {
        handle_kind: "span",
        expected: 1,
        actual: 2,
        index: 7,
    };
    let msg = err.to_string();
    assert!(msg.contains("span"));
}

#[test]
fn arena_error_display_missing_node() {
    let err = ArenaError::MissingNode { index: 42 };
    let msg = err.to_string();
    assert!(msg.contains("node handle"));
    assert!(msg.contains("missing index 42"));
}

#[test]
fn arena_error_display_missing_expression() {
    let err = ArenaError::MissingExpression { index: 7 };
    let msg = err.to_string();
    assert!(msg.contains("expression handle"));
    assert!(msg.contains("missing index 7"));
}

#[test]
fn arena_error_display_missing_span() {
    let err = ArenaError::MissingSpan { index: 0 };
    let msg = err.to_string();
    assert!(msg.contains("span handle"));
    assert!(msg.contains("missing index 0"));
}

#[test]
fn arena_error_display_handle_audit_serialization() {
    let err = ArenaError::HandleAuditSerialization;
    let msg = err.to_string();
    assert!(msg.contains("serialize"));
    assert!(msg.contains("parser arena"));
}

#[test]
fn arena_error_is_std_error() {
    let err = ArenaError::MissingNode { index: 0 };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn arena_error_equality() {
    let a = ArenaError::MissingNode { index: 1 };
    let b = ArenaError::MissingNode { index: 1 };
    let c = ArenaError::MissingNode { index: 2 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn arena_error_clone() {
    let original = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Bytes,
        limit: 100,
        attempted: 200,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ===========================================================================
// ArenaNode — variant construction
// ===========================================================================

#[test]
fn arena_node_import_with_binding() {
    let node = ArenaNode::Import {
        binding: Some("mod".to_string()),
        source: "./mod.js".to_string(),
        span: SpanHandle::from_parts(0, 1),
    };
    if let ArenaNode::Import {
        binding,
        source,
        span,
    } = &node
    {
        assert_eq!(binding.as_deref(), Some("mod"));
        assert_eq!(source, "./mod.js");
        assert_eq!(span.index(), 0);
    } else {
        panic!("expected Import variant");
    }
}

#[test]
fn arena_node_import_without_binding() {
    let node = ArenaNode::Import {
        binding: None,
        source: "./side.js".to_string(),
        span: SpanHandle::from_parts(1, 1),
    };
    if let ArenaNode::Import { binding, .. } = &node {
        assert!(binding.is_none());
    } else {
        panic!("expected Import variant");
    }
}

#[test]
fn arena_node_export_default() {
    let node = ArenaNode::ExportDefault {
        expression: ExpressionHandle::from_parts(0, 1),
        span: SpanHandle::from_parts(2, 1),
    };
    if let ArenaNode::ExportDefault { expression, span } = &node {
        assert_eq!(expression.index(), 0);
        assert_eq!(span.index(), 2);
    } else {
        panic!("expected ExportDefault variant");
    }
}

#[test]
fn arena_node_export_named_clause() {
    let node = ArenaNode::ExportNamedClause {
        clause: "{ x, y }".to_string(),
        span: SpanHandle::from_parts(3, 1),
    };
    if let ArenaNode::ExportNamedClause { clause, .. } = &node {
        assert_eq!(clause, "{ x, y }");
    } else {
        panic!("expected ExportNamedClause variant");
    }
}

#[test]
fn arena_node_expression_statement() {
    let node = ArenaNode::ExpressionStatement {
        expression: ExpressionHandle::from_parts(5, 1),
        span: SpanHandle::from_parts(4, 1),
    };
    if let ArenaNode::ExpressionStatement { expression, .. } = &node {
        assert_eq!(expression.index(), 5);
    } else {
        panic!("expected ExpressionStatement variant");
    }
}

#[test]
fn arena_node_clone_and_equality() {
    let node = ArenaNode::Import {
        binding: Some("a".to_string()),
        source: "b".to_string(),
        span: SpanHandle::from_parts(0, 1),
    };
    let cloned = node.clone();
    assert_eq!(node, cloned);
}

// ===========================================================================
// ArenaExpression — all variants
// ===========================================================================

#[test]
fn arena_expression_identifier() {
    let expr = ArenaExpression::Identifier("foo".to_string());
    if let ArenaExpression::Identifier(v) = &expr {
        assert_eq!(v, "foo");
    } else {
        panic!("expected Identifier");
    }
}

#[test]
fn arena_expression_string_literal() {
    let expr = ArenaExpression::StringLiteral("hello world".to_string());
    if let ArenaExpression::StringLiteral(v) = &expr {
        assert_eq!(v, "hello world");
    } else {
        panic!("expected StringLiteral");
    }
}

#[test]
fn arena_expression_numeric_literal() {
    let expr = ArenaExpression::NumericLiteral(9999);
    assert_eq!(expr, ArenaExpression::NumericLiteral(9999));
}

#[test]
fn arena_expression_boolean_literal_true() {
    let expr = ArenaExpression::BooleanLiteral(true);
    assert_eq!(expr, ArenaExpression::BooleanLiteral(true));
}

#[test]
fn arena_expression_boolean_literal_false() {
    let expr = ArenaExpression::BooleanLiteral(false);
    assert_eq!(expr, ArenaExpression::BooleanLiteral(false));
    assert_ne!(expr, ArenaExpression::BooleanLiteral(true));
}

#[test]
fn arena_expression_null_literal() {
    let expr = ArenaExpression::NullLiteral;
    assert_eq!(expr, ArenaExpression::NullLiteral);
}

#[test]
fn arena_expression_undefined_literal() {
    let expr = ArenaExpression::UndefinedLiteral;
    assert_eq!(expr, ArenaExpression::UndefinedLiteral);
    assert_ne!(expr, ArenaExpression::NullLiteral);
}

#[test]
fn arena_expression_await() {
    let inner = ExpressionHandle::from_parts(3, 1);
    let expr = ArenaExpression::Await(inner);
    if let ArenaExpression::Await(h) = &expr {
        assert_eq!(h.index(), 3);
    } else {
        panic!("expected Await");
    }
}

#[test]
fn arena_expression_raw() {
    let expr = ArenaExpression::Raw("console.log(1)".to_string());
    if let ArenaExpression::Raw(v) = &expr {
        assert_eq!(v, "console.log(1)");
    } else {
        panic!("expected Raw");
    }
}

#[test]
fn arena_expression_clone_and_equality() {
    let expr = ArenaExpression::StringLiteral("test".to_string());
    let cloned = expr.clone();
    assert_eq!(expr, cloned);
}

// ===========================================================================
// HandleAuditKind
// ===========================================================================

#[test]
fn handle_audit_kind_all_variants_serde_round_trip() {
    for kind in [
        HandleAuditKind::Node,
        HandleAuditKind::Expression,
        HandleAuditKind::Span,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize HandleAuditKind");
        let decoded: HandleAuditKind =
            serde_json::from_str(&json).expect("deserialize HandleAuditKind");
        assert_eq!(decoded, kind);
    }
}

#[test]
fn handle_audit_kind_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&HandleAuditKind::Node).unwrap(),
        "\"node\""
    );
    assert_eq!(
        serde_json::to_string(&HandleAuditKind::Expression).unwrap(),
        "\"expression\""
    );
    assert_eq!(
        serde_json::to_string(&HandleAuditKind::Span).unwrap(),
        "\"span\""
    );
}

#[test]
fn handle_audit_kind_equality() {
    assert_eq!(HandleAuditKind::Node, HandleAuditKind::Node);
    assert_ne!(HandleAuditKind::Node, HandleAuditKind::Span);
}

// ===========================================================================
// HandleAuditEntry
// ===========================================================================

#[test]
fn handle_audit_entry_construction_and_field_access() {
    let entry = HandleAuditEntry {
        handle_kind: HandleAuditKind::Expression,
        index: 7,
        generation: 1,
        descriptor: "identifier x".to_string(),
    };
    assert_eq!(entry.handle_kind, HandleAuditKind::Expression);
    assert_eq!(entry.index, 7);
    assert_eq!(entry.generation, 1);
    assert_eq!(entry.descriptor, "identifier x");
}

#[test]
fn handle_audit_entry_serde_round_trip() {
    let entry = HandleAuditEntry {
        handle_kind: HandleAuditKind::Span,
        index: 42,
        generation: 1,
        descriptor: "1:1-1:10 offsets 0..10".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize HandleAuditEntry");
    let decoded: HandleAuditEntry =
        serde_json::from_str(&json).expect("deserialize HandleAuditEntry");
    assert_eq!(decoded, entry);
}

#[test]
fn handle_audit_entry_clone_and_equality() {
    let entry = HandleAuditEntry {
        handle_kind: HandleAuditKind::Node,
        index: 0,
        generation: 1,
        descriptor: "import".to_string(),
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ===========================================================================
// ParserArena — construction from various SyntaxTree shapes
// ===========================================================================

#[test]
fn arena_from_simple_expression_tree() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 1);
    assert!(arena.bytes_used() > 0);
}

#[test]
fn arena_from_import_tree() {
    let tree = import_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn arena_from_import_no_binding_tree() {
    let tree = import_no_binding_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn arena_from_export_default_tree() {
    let tree = export_default_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn arena_from_export_named_tree() {
    let tree = export_named_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn arena_from_all_expression_types() {
    let tree = all_expression_types_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 9);
}

#[test]
fn arena_from_mixed_statements() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 5);
}

#[test]
fn arena_from_empty_body() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 0);
    // Even empty tree allocates the tree span
    assert!(arena.bytes_used() > 0);
}

#[test]
fn arena_budget_accessor_reflects_construction_budget() {
    let budget = ArenaBudget {
        max_nodes: 10,
        max_expressions: 20,
        max_spans: 30,
        max_bytes: 512,
    };
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = ParserArena::from_syntax_tree(&tree, budget).unwrap();
    assert_eq!(arena.budget().max_nodes, 10);
    assert_eq!(arena.budget().max_expressions, 20);
    assert_eq!(arena.budget().max_spans, 30);
    assert_eq!(arena.budget().max_bytes, 512);
}

// ===========================================================================
// ParserArena — handle lookups: happy path
// ===========================================================================

#[test]
fn node_lookup_returns_correct_variant_expression_statement() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).expect("node lookup");
    assert!(matches!(node, ArenaNode::ExpressionStatement { .. }));
}

#[test]
fn node_lookup_returns_correct_variant_import() {
    let tree = import_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).expect("node lookup");
    if let ArenaNode::Import {
        binding, source, ..
    } = node
    {
        assert_eq!(binding.as_deref(), Some("foo"));
        assert_eq!(source, "./foo.js");
    } else {
        panic!("expected Import node");
    }
}

#[test]
fn node_lookup_returns_correct_variant_export_default() {
    let tree = export_default_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).expect("node lookup");
    assert!(matches!(node, ArenaNode::ExportDefault { .. }));
}

#[test]
fn node_lookup_returns_correct_variant_export_named() {
    let tree = export_named_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).expect("node lookup");
    if let ArenaNode::ExportNamedClause { clause, .. } = node {
        assert_eq!(clause, "{ baz }");
    } else {
        panic!("expected ExportNamedClause");
    }
}

#[test]
fn expression_lookup_via_node() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).unwrap();
    if let ArenaNode::ExpressionStatement { expression, .. } = node {
        let expr = arena.expression(*expression).unwrap();
        assert!(matches!(expr, ArenaExpression::NumericLiteral(42)));
    } else {
        panic!("expected ExpressionStatement");
    }
}

#[test]
fn span_lookup_via_node() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let handle = arena.statement_handles()[0];
    let node = arena.node(handle).unwrap();
    if let ArenaNode::ExpressionStatement { span, .. } = node {
        let source_span = arena.span(*span).unwrap();
        assert_eq!(source_span.start_offset, 0);
        assert_eq!(source_span.end_offset, 2);
    } else {
        panic!("expected ExpressionStatement");
    }
}

// ===========================================================================
// ParserArena — handle lookups: error paths
// ===========================================================================

#[test]
fn node_lookup_invalid_generation_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = NodeHandle::from_parts(0, 999);
    let err = arena.node(bad).unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn node_lookup_missing_index_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = NodeHandle::from_parts(9999, 1);
    let err = arena.node(bad).unwrap_err();
    assert!(matches!(err, ArenaError::MissingNode { index: 9999 }));
}

#[test]
fn expression_lookup_invalid_generation_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = ExpressionHandle::from_parts(0, 0);
    let err = arena.expression(bad).unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn expression_lookup_missing_index_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = ExpressionHandle::from_parts(5000, 1);
    let err = arena.expression(bad).unwrap_err();
    assert!(matches!(err, ArenaError::MissingExpression { index: 5000 }));
}

#[test]
fn span_lookup_invalid_generation_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = SpanHandle::from_parts(0, 42);
    let err = arena.span(bad).unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn span_lookup_missing_index_returns_error() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let bad = SpanHandle::from_parts(10000, 1);
    let err = arena.span(bad).unwrap_err();
    assert!(matches!(err, ArenaError::MissingSpan { index: 10000 }));
}

// ===========================================================================
// ParserArena — budget enforcement
// ===========================================================================

#[test]
fn budget_exceeded_nodes_zero() {
    let budget = ArenaBudget {
        max_nodes: 0,
        ..ArenaBudget::default()
    };
    let tree = simple_expression_tree();
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            ..
        }
    ));
}

#[test]
fn budget_exceeded_expressions_zero() {
    let budget = ArenaBudget {
        max_expressions: 0,
        ..ArenaBudget::default()
    };
    let tree = simple_expression_tree();
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Expressions,
            ..
        }
    ));
}

#[test]
fn budget_exceeded_spans_zero() {
    let budget = ArenaBudget {
        max_spans: 0,
        ..ArenaBudget::default()
    };
    let tree = simple_expression_tree();
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Spans,
            ..
        }
    ));
}

#[test]
fn budget_exceeded_bytes_tiny() {
    let budget = ArenaBudget {
        max_bytes: 1,
        ..ArenaBudget::default()
    };
    let tree = simple_expression_tree();
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Bytes,
            ..
        }
    ));
}

#[test]
fn budget_exactly_sufficient_succeeds() {
    // An empty body only needs 1 span (the tree span), so max_spans: 1 should work.
    let budget = ArenaBudget {
        max_nodes: 0,
        max_expressions: 0,
        max_spans: 1,
        max_bytes: 1024,
    };
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = ParserArena::from_syntax_tree(&tree, budget).unwrap();
    assert_eq!(arena.statement_handles().len(), 0);
}

#[test]
fn budget_nodes_one_with_single_statement() {
    // Need 1 node, 1 expression, at least 2 spans (tree + statement)
    let budget = ArenaBudget {
        max_nodes: 1,
        max_expressions: 1,
        max_spans: 2,
        max_bytes: 64 * 1024 * 1024,
    };
    let tree = simple_expression_tree();
    let arena = ParserArena::from_syntax_tree(&tree, budget).unwrap();
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn budget_nodes_insufficient_for_two_statements() {
    let budget = ArenaBudget {
        max_nodes: 1,
        max_expressions: 10,
        max_spans: 10,
        max_bytes: 64 * 1024 * 1024,
    };
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: make_span(0, 1),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(2),
                span: make_span(2, 3),
            }),
        ],
        span: make_span(0, 3),
    };
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            ..
        }
    ));
}

// ===========================================================================
// ParserArena — SyntaxTree roundtrip
// ===========================================================================

#[test]
fn roundtrip_simple_expression() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_import_with_binding() {
    let tree = import_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_import_without_binding() {
    let tree = import_no_binding_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_export_default() {
    let tree = export_default_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_export_named() {
    let tree = export_named_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_all_expression_types() {
    let tree = all_expression_types_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_mixed_statements() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_empty_body() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_await_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier(
                "fetchData".to_string(),
            ))),
            span: make_span(0, 20),
        })],
        span: make_span(0, 20),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_nested_await() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Await(Box::new(
                Expression::Identifier("deepPromise".to_string()),
            )))),
            span: make_span(0, 30),
        })],
        span: make_span(0, 30),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn roundtrip_preserves_parse_goal_script() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered.goal, ParseGoal::Script);
}

#[test]
fn roundtrip_preserves_parse_goal_module() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered.goal, ParseGoal::Module);
}

#[test]
fn roundtrip_preserves_span_values() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(7),
            span: SourceSpan::new(100, 200, 5, 10, 10, 20),
        })],
        span: SourceSpan::new(0, 500, 1, 1, 50, 1),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered.span.start_offset, 0);
    assert_eq!(recovered.span.end_offset, 500);
    assert_eq!(recovered.body[0].span().start_line, 5);
    assert_eq!(recovered.body[0].span().start_column, 10);
}

// ===========================================================================
// ParserArena — canonical hash
// ===========================================================================

#[test]
fn canonical_hash_is_deterministic() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let hash1 = arena.canonical_hash().unwrap();
    let hash2 = arena.canonical_hash().unwrap();
    assert_eq!(hash1, hash2);
    assert!(!hash1.is_empty());
}

#[test]
fn canonical_hash_differs_for_different_trees() {
    let tree1 = simple_expression_tree();
    let tree2 = import_tree();
    let arena1 = default_arena(&tree1);
    let arena2 = default_arena(&tree2);
    let hash1 = arena1.canonical_hash().unwrap();
    let hash2 = arena2.canonical_hash().unwrap();
    assert_ne!(hash1, hash2);
}

#[test]
fn canonical_hash_same_for_identical_trees() {
    let tree1 = simple_expression_tree();
    let tree2 = simple_expression_tree();
    let arena1 = default_arena(&tree1);
    let arena2 = default_arena(&tree2);
    assert_eq!(
        arena1.canonical_hash().unwrap(),
        arena2.canonical_hash().unwrap()
    );
}

#[test]
fn canonical_hash_differs_for_different_expression_values() {
    let tree1 = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: make_span(0, 1),
        })],
        span: make_span(0, 1),
    };
    let tree2 = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(2),
            span: make_span(0, 1),
        })],
        span: make_span(0, 1),
    };
    let arena1 = default_arena(&tree1);
    let arena2 = default_arena(&tree2);
    assert_ne!(
        arena1.canonical_hash().unwrap(),
        arena2.canonical_hash().unwrap()
    );
}

#[test]
fn canonical_hash_differs_for_different_goals() {
    let tree_script = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let tree_module = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena1 = default_arena(&tree_script);
    let arena2 = default_arena(&tree_module);
    assert_ne!(
        arena1.canonical_hash().unwrap(),
        arena2.canonical_hash().unwrap()
    );
}

// ===========================================================================
// ParserArena — handle audit entries
// ===========================================================================

#[test]
fn handle_audit_entries_for_simple_tree() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    assert!(!entries.is_empty());

    let node_count = entries
        .iter()
        .filter(|e| e.handle_kind == HandleAuditKind::Node)
        .count();
    let expr_count = entries
        .iter()
        .filter(|e| e.handle_kind == HandleAuditKind::Expression)
        .count();
    let span_count = entries
        .iter()
        .filter(|e| e.handle_kind == HandleAuditKind::Span)
        .count();

    assert!(node_count >= 1, "must have at least 1 node");
    assert!(expr_count >= 1, "must have at least 1 expression");
    assert!(span_count >= 1, "must have at least 1 span");
}

#[test]
fn handle_audit_entries_for_mixed_tree() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();

    let node_count = entries
        .iter()
        .filter(|e| e.handle_kind == HandleAuditKind::Node)
        .count();
    // 5 statements
    assert_eq!(node_count, 5);
}

#[test]
fn handle_audit_entries_all_have_generation_1() {
    let tree = all_expression_types_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    for entry in &entries {
        assert_eq!(entry.generation, 1, "all handles use generation 1");
    }
}

#[test]
fn handle_audit_entries_descriptors_nonempty() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    for entry in &entries {
        assert!(
            !entry.descriptor.is_empty(),
            "descriptor must not be empty for {:?} at index {}",
            entry.handle_kind,
            entry.index
        );
    }
}

#[test]
fn handle_audit_entries_for_empty_body() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    // Only the tree span
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].handle_kind, HandleAuditKind::Span);
}

// ===========================================================================
// ParserArena — handle audit JSONL
// ===========================================================================

#[test]
fn handle_audit_jsonl_produces_valid_json_lines() {
    let tree = simple_expression_tree();
    let arena = default_arena(&tree);
    let jsonl = arena.handle_audit_jsonl().unwrap();
    assert!(!jsonl.is_empty());
    for line in jsonl.lines() {
        let parsed: HandleAuditEntry =
            serde_json::from_str(line).expect("each JSONL line must be valid JSON");
        assert!(!parsed.descriptor.is_empty());
    }
}

#[test]
fn handle_audit_jsonl_line_count_matches_entries() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    let jsonl = arena.handle_audit_jsonl().unwrap();
    let line_count = jsonl.lines().count();
    assert_eq!(line_count, entries.len());
}

#[test]
fn handle_audit_jsonl_for_empty_body() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let jsonl = arena.handle_audit_jsonl().unwrap();
    // Only the tree span entry
    assert_eq!(jsonl.lines().count(), 1);
}

#[test]
fn handle_audit_jsonl_round_trip_each_line() {
    let tree = all_expression_types_tree();
    let arena = default_arena(&tree);
    let jsonl = arena.handle_audit_jsonl().unwrap();
    for line in jsonl.lines() {
        let entry: HandleAuditEntry = serde_json::from_str(line).unwrap();
        let reserialized = serde_json::to_string(&entry).unwrap();
        let re_entry: HandleAuditEntry = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(entry, re_entry);
    }
}

// ===========================================================================
// ParserArena — bytes_used tracking
// ===========================================================================

#[test]
fn bytes_used_increases_with_more_content() {
    let small_tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: make_span(0, 1),
        })],
        span: make_span(0, 1),
    };
    let large_tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("a".repeat(1000)),
                span: make_span(0, 1000),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("b".repeat(1000)),
                span: make_span(1000, 2000),
            }),
        ],
        span: make_span(0, 2000),
    };
    let small_arena = default_arena(&small_tree);
    let large_arena = default_arena(&large_tree);
    assert!(large_arena.bytes_used() > small_arena.bytes_used());
}

#[test]
fn bytes_used_for_empty_body_is_span_only() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    // The tree span allocation charges SPAN_ESTIMATED_BYTES (48)
    assert_eq!(arena.bytes_used(), 48);
}

// ===========================================================================
// Determinism: same inputs produce same outputs
// ===========================================================================

#[test]
fn determinism_arena_construction() {
    let tree = mixed_statement_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(arena1, arena2);
}

#[test]
fn determinism_roundtrip() {
    let tree = all_expression_types_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(
        arena1.to_syntax_tree().unwrap(),
        arena2.to_syntax_tree().unwrap()
    );
}

#[test]
fn determinism_canonical_hash() {
    let tree = mixed_statement_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(
        arena1.canonical_hash().unwrap(),
        arena2.canonical_hash().unwrap()
    );
}

#[test]
fn determinism_handle_audit() {
    let tree = mixed_statement_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(arena1.handle_audit_entries(), arena2.handle_audit_entries());
}

#[test]
fn determinism_handle_audit_jsonl() {
    let tree = all_expression_types_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(
        arena1.handle_audit_jsonl().unwrap(),
        arena2.handle_audit_jsonl().unwrap()
    );
}

#[test]
fn determinism_bytes_used() {
    let tree = mixed_statement_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(arena1.bytes_used(), arena2.bytes_used());
}

#[test]
fn determinism_statement_handles() {
    let tree = mixed_statement_tree();
    let arena1 = default_arena(&tree);
    let arena2 = default_arena(&tree);
    assert_eq!(arena1.statement_handles(), arena2.statement_handles());
}

// ===========================================================================
// Cross-concern integration
// ===========================================================================

#[test]
fn cross_concern_arena_to_tree_canonical_hash_matches_direct() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    // The recovered tree's canonical hash should match the arena's canonical hash
    assert_eq!(arena.canonical_hash().unwrap(), recovered.canonical_hash());
}

#[test]
fn cross_concern_double_roundtrip() {
    let original = mixed_statement_tree();
    let arena1 = default_arena(&original);
    let tree1 = arena1.to_syntax_tree().unwrap();
    let arena2 = default_arena(&tree1);
    let tree2 = arena2.to_syntax_tree().unwrap();
    assert_eq!(original, tree1);
    assert_eq!(tree1, tree2);
    assert_eq!(
        arena1.canonical_hash().unwrap(),
        arena2.canonical_hash().unwrap()
    );
}

#[test]
fn cross_concern_all_audit_entries_are_valid_serde() {
    let tree = all_expression_types_tree();
    let arena = default_arena(&tree);
    for entry in arena.handle_audit_entries() {
        let json = serde_json::to_string(&entry).expect("serialize entry");
        let decoded: HandleAuditEntry = serde_json::from_str(&json).expect("deserialize entry");
        assert_eq!(decoded, entry);
    }
}

#[test]
fn cross_concern_large_tree_budget_tracking() {
    // Build a tree with many statements to verify budget tracking works at scale
    let stmts: Vec<Statement> = (0..100)
        .map(|i| {
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(i),
                span: make_span(i as u64 * 10, (i as u64 + 1) * 10),
            })
        })
        .collect();
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: stmts,
        span: make_span(0, 1000),
    };
    let arena = default_arena(&tree);
    assert_eq!(arena.statement_handles().len(), 100);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn cross_concern_audit_node_count_matches_statements() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let entries = arena.handle_audit_entries();
    let node_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.handle_kind == HandleAuditKind::Node)
        .collect();
    assert_eq!(node_entries.len(), arena.statement_handles().len());
}

#[test]
fn cross_concern_handle_indices_are_sequential() {
    let tree = mixed_statement_tree();
    let arena = default_arena(&tree);
    let handles = arena.statement_handles();
    for (i, handle) in handles.iter().enumerate() {
        assert_eq!(handle.index() as usize, i);
    }
}

#[test]
fn cross_concern_arena_equality_is_structural() {
    let tree = simple_expression_tree();
    let a = default_arena(&tree);
    let b = default_arena(&tree);
    assert_eq!(a, b);

    // Different tree should produce a different arena
    let other_tree = import_tree();
    let c = default_arena(&other_tree);
    assert_ne!(a, c);
}

#[test]
fn cross_concern_string_heavy_tree_bytes_accounting() {
    let long_string = "x".repeat(10_000);
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral(long_string),
            span: make_span(0, 10_000),
        })],
        span: make_span(0, 10_000),
    };
    let arena = default_arena(&tree);
    // bytes_used must account for the 10,000-byte string
    assert!(arena.bytes_used() >= 10_000);
}

#[test]
fn cross_concern_budget_bytes_rejects_large_string() {
    let long_string = "y".repeat(100);
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral(long_string),
            span: make_span(0, 100),
        })],
        span: make_span(0, 100),
    };
    let budget = ArenaBudget {
        max_bytes: 80, // Too small to hold the string + overhead
        ..ArenaBudget::default()
    };
    let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Bytes,
            ..
        }
    ));
}

#[test]
fn cross_concern_import_binding_affects_bytes() {
    let with_binding = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: Some("longBindingName".to_string()),
            source: "./m.js".to_string(),
            span: make_span(0, 30),
        })],
        span: make_span(0, 30),
    };
    let without_binding = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: None,
            source: "./m.js".to_string(),
            span: make_span(0, 30),
        })],
        span: make_span(0, 30),
    };
    let arena_with = default_arena(&with_binding);
    let arena_without = default_arena(&without_binding);
    assert!(arena_with.bytes_used() > arena_without.bytes_used());
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn edge_empty_string_literal() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral(String::new()),
            span: make_span(0, 2),
        })],
        span: make_span(0, 2),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_empty_identifier() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier(String::new()),
            span: make_span(0, 0),
        })],
        span: make_span(0, 0),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_numeric_literal_zero() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(0),
            span: make_span(0, 1),
        })],
        span: make_span(0, 1),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_numeric_literal_negative() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(-999),
            span: make_span(0, 4),
        })],
        span: make_span(0, 4),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_numeric_literal_i64_max() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(i64::MAX),
            span: make_span(0, 20),
        })],
        span: make_span(0, 20),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_numeric_literal_i64_min() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(i64::MIN),
            span: make_span(0, 20),
        })],
        span: make_span(0, 20),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_raw_expression_with_special_chars() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Raw("console.log(\"hello\\nworld\")".to_string()),
            span: make_span(0, 30),
        })],
        span: make_span(0, 30),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_unicode_in_identifiers() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier("\u{00E9}\u{00F1}\u{00FC}".to_string()),
            span: make_span(0, 10),
        })],
        span: make_span(0, 10),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_unicode_in_strings() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral("\u{1F600}\u{1F601}\u{1F602}".to_string()),
            span: make_span(0, 12),
        })],
        span: make_span(0, 12),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_export_named_empty_clause() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(String::new()),
            span: make_span(0, 5),
        })],
        span: make_span(0, 5),
    };
    let arena = default_arena(&tree);
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn edge_node_handle_from_parts_zero_generation() {
    let h = NodeHandle::from_parts(0, 0);
    assert_eq!(h.index(), 0);
    assert_eq!(h.generation(), 0);
}

#[test]
fn edge_handle_max_u32_index() {
    let h = NodeHandle::from_parts(u32::MAX, 1);
    assert_eq!(h.index(), u32::MAX);
}

#[test]
fn edge_expression_handle_max_u32_index() {
    let h = ExpressionHandle::from_parts(u32::MAX, u32::MAX);
    assert_eq!(h.index(), u32::MAX);
    assert_eq!(h.generation(), u32::MAX);
}

#[test]
fn edge_span_handle_max_values() {
    let h = SpanHandle::from_parts(u32::MAX, u32::MAX);
    assert_eq!(h.index(), u32::MAX);
    assert_eq!(h.generation(), u32::MAX);
}
