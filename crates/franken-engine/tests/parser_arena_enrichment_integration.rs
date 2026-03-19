#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_arena` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    BindingPattern, ExportDeclaration, ExportKind, Expression, ExpressionStatement,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::parser_arena::{
    ArenaBudget, ArenaBudgetKind, ArenaError, ExpressionHandle, HandleAuditEntry, HandleAuditKind,
    NodeHandle, ParserArena, SpanHandle,
};

fn test_span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 11)
}

fn simple_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: test_span(),
        })],
        span: test_span(),
    }
}

#[test]
fn enrichment_node_handle_from_parts_roundtrip() {
    let h = NodeHandle::from_parts(7, 3);
    assert_eq!(h.index(), 7);
    assert_eq!(h.generation(), 3);
}

#[test]
fn enrichment_node_handle_serde_roundtrip() {
    let h = NodeHandle::from_parts(42, 1);
    let json = serde_json::to_string(&h).unwrap();
    let back: NodeHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn enrichment_node_handle_ordering() {
    let a = NodeHandle::from_parts(0, 1);
    let b = NodeHandle::from_parts(1, 1);
    assert!(a < b);
}

#[test]
fn enrichment_node_handle_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(NodeHandle::from_parts(0, 1));
    set.insert(NodeHandle::from_parts(0, 1));
    set.insert(NodeHandle::from_parts(1, 1));
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_expression_handle_serde_roundtrip() {
    let h = ExpressionHandle::from_parts(99, 2);
    let json = serde_json::to_string(&h).unwrap();
    let back: ExpressionHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn enrichment_expression_handle_ordering() {
    let a = ExpressionHandle::from_parts(0, 1);
    let b = ExpressionHandle::from_parts(1, 1);
    assert!(a < b);
}

#[test]
fn enrichment_span_handle_serde_roundtrip() {
    let h = SpanHandle::from_parts(5, 1);
    let json = serde_json::to_string(&h).unwrap();
    let back: SpanHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn enrichment_span_handle_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(SpanHandle::from_parts(0, 1));
    set.insert(SpanHandle::from_parts(0, 1));
    assert_eq!(set.len(), 1);
}

#[test]
fn enrichment_arena_budget_kind_serde_snake_case() {
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
fn enrichment_arena_budget_kind_debug_distinct() {
    let all = [
        ArenaBudgetKind::Nodes,
        ArenaBudgetKind::Expressions,
        ArenaBudgetKind::Spans,
        ArenaBudgetKind::Bytes,
    ];
    let set: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_arena_budget_default_values() {
    let b = ArenaBudget::default();
    assert_eq!(b.max_nodes, 262_144);
    assert_eq!(b.max_expressions, 524_288);
    assert_eq!(b.max_spans, 524_288);
    assert_eq!(b.max_bytes, 64 * 1024 * 1024);
}

#[test]
fn enrichment_arena_budget_serde_roundtrip() {
    let b = ArenaBudget {
        max_nodes: 10,
        max_expressions: 20,
        max_spans: 30,
        max_bytes: 1024,
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: ArenaBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_arena_budget_json_fields() {
    let b = ArenaBudget::default();
    let val: serde_json::Value = serde_json::to_value(b).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("max_nodes"));
    assert!(obj.contains_key("max_expressions"));
    assert!(obj.contains_key("max_spans"));
    assert!(obj.contains_key("max_bytes"));
    assert_eq!(obj.len(), 4);
}

#[test]
fn enrichment_arena_error_display_all_variants_unique() {
    let variants: Vec<ArenaError> = vec![
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            limit: 10,
            attempted: 11,
        },
        ArenaError::InvalidGeneration {
            handle_kind: "node",
            expected: 1,
            actual: 2,
            index: 0,
        },
        ArenaError::MissingNode { index: 0 },
        ArenaError::MissingExpression { index: 0 },
        ArenaError::MissingSpan { index: 0 },
        ArenaError::UnsupportedStatement { kind: "block" },
        ArenaError::UnsupportedExpression { kind: "binary" },
        ArenaError::HandleAuditSerialization,
    ];
    let set: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_arena_error_is_std_error() {
    let e = ArenaError::MissingNode { index: 5 };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_arena_from_empty_tree() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.statement_handles().len(), 0);
    assert!(arena.bytes_used() > 0);
}

#[test]
fn enrichment_arena_from_import_tree() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: Some("x".into()),
            source: "./x.js".into(),
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn enrichment_arena_from_export_default() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::NumericLiteral(42)),
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn enrichment_arena_from_export_named() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("{ a, b }".into()),
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn enrichment_arena_from_variable_declaration() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("x".into()),
                initializer: Some(Expression::StringLiteral("hello".into())),
                span: test_span(),
            }],
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.statement_handles().len(), 1);
}

#[test]
fn enrichment_roundtrip_all_literal_types() {
    let expressions = vec![
        Expression::Identifier("foo".into()),
        Expression::StringLiteral("bar".into()),
        Expression::NumericLiteral(99),
        Expression::BooleanLiteral(false),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Raw("raw code".into()),
    ];
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: expressions
            .into_iter()
            .map(|e| {
                Statement::Expression(ExpressionStatement {
                    expression: e,
                    span: test_span(),
                })
            })
            .collect(),
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let recovered = arena.to_syntax_tree().unwrap();
    assert_eq!(recovered, tree);
}

#[test]
fn enrichment_roundtrip_await_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("promise".into()))),
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.to_syntax_tree().unwrap(), tree);
}

#[test]
fn enrichment_roundtrip_variable_no_init() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("y".into()),
                initializer: None,
                span: test_span(),
            }],
            span: test_span(),
        })],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.to_syntax_tree().unwrap(), tree);
}

#[test]
fn enrichment_canonical_hash_deterministic() {
    let tree = simple_tree();
    let a1 = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let a2 = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(a1.canonical_hash().unwrap(), a2.canonical_hash().unwrap());
}

#[test]
fn enrichment_canonical_hash_differs_for_different_trees() {
    let t1 = simple_tree();
    let t2 = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(99),
            span: test_span(),
        })],
        span: test_span(),
    };
    let a1 = ParserArena::from_syntax_tree(&t1, ArenaBudget::default()).unwrap();
    let a2 = ParserArena::from_syntax_tree(&t2, ArenaBudget::default()).unwrap();
    assert_ne!(a1.canonical_hash().unwrap(), a2.canonical_hash().unwrap());
}

#[test]
fn enrichment_node_lookup_bad_generation() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let err = arena.node(NodeHandle::from_parts(0, 999)).unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn enrichment_expression_lookup_bad_generation() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let err = arena
        .expression(ExpressionHandle::from_parts(0, 999))
        .unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn enrichment_span_lookup_bad_generation() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let err = arena.span(SpanHandle::from_parts(0, 999)).unwrap_err();
    assert!(matches!(err, ArenaError::InvalidGeneration { .. }));
}

#[test]
fn enrichment_node_lookup_missing_index() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let err = arena.node(NodeHandle::from_parts(9999, 1)).unwrap_err();
    assert!(matches!(err, ArenaError::MissingNode { .. }));
}

#[test]
fn enrichment_budget_zero_nodes_rejects() {
    let budget = ArenaBudget {
        max_nodes: 0,
        ..ArenaBudget::default()
    };
    let err = ParserArena::from_syntax_tree(&simple_tree(), budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            ..
        }
    ));
}

#[test]
fn enrichment_budget_zero_expressions_rejects() {
    let budget = ArenaBudget {
        max_expressions: 0,
        ..ArenaBudget::default()
    };
    let err = ParserArena::from_syntax_tree(&simple_tree(), budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Expressions,
            ..
        }
    ));
}

#[test]
fn enrichment_budget_zero_spans_rejects() {
    let budget = ArenaBudget {
        max_spans: 0,
        ..ArenaBudget::default()
    };
    let err = ParserArena::from_syntax_tree(&simple_tree(), budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Spans,
            ..
        }
    ));
}

#[test]
fn enrichment_budget_tiny_bytes_rejects() {
    let budget = ArenaBudget {
        max_bytes: 1,
        ..ArenaBudget::default()
    };
    let err = ParserArena::from_syntax_tree(&simple_tree(), budget).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Bytes,
            ..
        }
    ));
}

#[test]
fn enrichment_handle_audit_entries_serde_roundtrip() {
    let entry = HandleAuditEntry {
        handle_kind: HandleAuditKind::Node,
        index: 0,
        generation: 1,
        descriptor: "test".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: HandleAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_handle_audit_kind_serde_snake_case() {
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
fn enrichment_handle_audit_jsonl_parseable() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let jsonl = arena.handle_audit_jsonl().unwrap();
    for line in jsonl.lines() {
        let parsed: HandleAuditEntry = serde_json::from_str(line).unwrap();
        assert!(!parsed.descriptor.is_empty());
    }
}

#[test]
fn enrichment_handle_audit_entries_empty_tree() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let entries = arena.handle_audit_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].handle_kind, HandleAuditKind::Span);
}

#[test]
fn enrichment_arena_clone_eq() {
    let tree = simple_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    let cloned = arena.clone();
    assert_eq!(arena, cloned);
    assert_eq!(arena.bytes_used(), cloned.bytes_used());
}

#[test]
fn enrichment_bytes_used_grows_with_content() {
    let small = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: test_span(),
        })],
        span: test_span(),
    };
    let big = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("a".repeat(500)),
                span: test_span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("b".repeat(500)),
                span: test_span(),
            }),
        ],
        span: test_span(),
    };
    let small_a = ParserArena::from_syntax_tree(&small, ArenaBudget::default()).unwrap();
    let big_a = ParserArena::from_syntax_tree(&big, ArenaBudget::default()).unwrap();
    assert!(big_a.bytes_used() > small_a.bytes_used());
}

#[test]
fn enrichment_unsupported_this_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::This,
            span: test_span(),
        })],
        span: test_span(),
    };
    let err = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap_err();
    assert!(matches!(
        err,
        ArenaError::UnsupportedExpression { kind: "this" }
    ));
}

#[test]
fn enrichment_budget_accessor_returns_configured() {
    let budget = ArenaBudget {
        max_nodes: 7,
        max_expressions: 14,
        max_spans: 21,
        max_bytes: 256,
    };
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: test_span(),
    };
    let arena = ParserArena::from_syntax_tree(&tree, budget).unwrap();
    assert_eq!(arena.budget().max_nodes, 7);
    assert_eq!(arena.budget().max_expressions, 14);
    assert_eq!(arena.budget().max_spans, 21);
    assert_eq!(arena.budget().max_bytes, 256);
}
