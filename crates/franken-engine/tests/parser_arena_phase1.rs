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

mod ast {
    pub use frankenengine_engine::ast::*;
}

#[path = "../src/parser_arena.rs"]
mod parser_arena;

use ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree,
};
use parser_arena::{
    ArenaBudget, ArenaBudgetKind, ArenaError, ArenaNode, ExpressionHandle, HandleAuditEntry,
    HandleAuditKind, NodeHandle, ParserArena, SpanHandle,
};

fn span(start: u64, end: u64, line: u64, col: u64) -> SourceSpan {
    SourceSpan::new(start, end, line, col, line, col + end.saturating_sub(start))
}

fn fixture_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                binding: Some("alpha".to_string()),
                source: "./dep.mjs".to_string(),
                span: span(0, 24, 1, 1),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "alpha".to_string(),
                ))),
                span: span(25, 37, 2, 1),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("alpha".to_string()),
                span: span(38, 55, 3, 1),
            }),
        ],
        span: span(0, 55, 1, 1),
    }
}

#[test]
fn arena_alloc_order_is_deterministic() {
    let tree = fixture_tree();

    let a = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("first arena");
    let b = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("second arena");

    let a_handles: Vec<u32> = a.statement_handles().iter().map(|h| h.index()).collect();
    let b_handles: Vec<u32> = b.statement_handles().iter().map(|h| h.index()).collect();

    assert_eq!(a_handles, vec![0, 1, 2]);
    assert_eq!(a_handles, b_handles);
    assert_eq!(
        a.canonical_hash().expect("hash a"),
        b.canonical_hash().expect("hash b")
    );

    let expression_node = a.node(a.statement_handles()[1]).expect("expression node");
    if let ArenaNode::ExpressionStatement { expression, span } = expression_node {
        let expression_roundtrip =
            ExpressionHandle::from_parts(expression.index(), expression.generation());
        let span_roundtrip = SpanHandle::from_parts(span.index(), span.generation());

        assert_eq!(expression_roundtrip.index(), expression.index());
        assert_eq!(expression_roundtrip.generation(), expression.generation());
        assert_eq!(span_roundtrip.index(), span.index());
        assert_eq!(span_roundtrip.generation(), span.generation());

        let _ = a
            .expression(expression_roundtrip)
            .expect("expression handle should resolve");
        let _ = a.span(span_roundtrip).expect("span handle should resolve");
    } else {
        panic!("expected expression statement node at index 1");
    }

    assert!(a.bytes_used() > 0);
    assert_eq!(a.budget(), ArenaBudget::default());
}

#[test]
fn semantic_roundtrip_preserves_hash() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let round_trip = arena.to_syntax_tree().expect("round-trip");
    assert_eq!(round_trip.canonical_hash(), tree.canonical_hash());
}

#[test]
fn budget_enforcement_is_deterministic() {
    let tree = fixture_tree();
    let budget = ArenaBudget {
        max_nodes: 32,
        max_expressions: 1,
        max_spans: 64,
        max_bytes: 1024 * 1024,
    };

    let err_a = ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail");
    let err_b = ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail again");

    assert_eq!(err_a, err_b);
    assert!(matches!(
        err_a,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Expressions,
            ..
        }
    ));
}

#[test]
fn arena_rejects_invalid_handle_generation() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let first = arena.statement_handles()[0];

    let invalid = NodeHandle::from_parts(first.index(), first.generation() + 1);
    let err = arena
        .node(invalid)
        .expect_err("invalid generation must fail");

    assert!(matches!(
        err,
        ArenaError::InvalidGeneration {
            handle_kind: "node",
            ..
        }
    ));
}

#[test]
fn arena_rejects_out_of_bounds_handles() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let missing = NodeHandle::from_parts(99_999, 1);
    let err = arena.node(missing).expect_err("missing handle should fail");
    assert!(matches!(err, ArenaError::MissingNode { .. }));
}

#[test]
fn handle_audit_entries_are_deterministic() {
    let tree = fixture_tree();
    let a = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena a");
    let b = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena b");

    let entries_a = a.handle_audit_entries();
    let entries_b = b.handle_audit_entries();

    assert_eq!(entries_a, entries_b);
    assert!(!entries_a.is_empty());
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Node)
    );
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Expression)
    );
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Span)
    );
}

#[test]
fn handle_audit_jsonl_is_parseable_and_stable() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let jsonl = arena.handle_audit_jsonl().expect("audit jsonl");
    let parsed: Vec<HandleAuditEntry> = jsonl
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit entry json"))
        .collect();

    assert_eq!(parsed, arena.handle_audit_entries());
}

#[test]
fn corruption_injection_guards_fail_closed_deterministically() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let node_handle = arena.statement_handles()[0];
    let node_err = arena
        .node(NodeHandle::from_parts(
            node_handle.index(),
            node_handle.generation() + 7,
        ))
        .expect_err("node generation corruption should fail");

    let expr_err = arena
        .expression(ExpressionHandle::from_parts(90_001, 1))
        .expect_err("expression OOB corruption should fail");

    let span_err = arena
        .span(SpanHandle::from_parts(70_001, 1))
        .expect_err("span OOB corruption should fail");

    assert!(matches!(
        node_err,
        ArenaError::InvalidGeneration {
            handle_kind: "node",
            ..
        }
    ));
    assert!(matches!(expr_err, ArenaError::MissingExpression { .. }));
    assert!(matches!(span_err, ArenaError::MissingSpan { .. }));
}

// ---------- span helper ----------

#[test]
fn span_helper_sets_fields() {
    let s = span(10, 20, 3, 5);
    assert_eq!(s.start_offset, 10);
    assert_eq!(s.end_offset, 20);
    assert_eq!(s.start_line, 3);
    assert_eq!(s.start_column, 5);
}

// ---------- fixture_tree ----------

#[test]
fn fixture_tree_has_three_statements() {
    let tree = fixture_tree();
    assert_eq!(tree.body.len(), 3);
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn fixture_tree_starts_with_import() {
    let tree = fixture_tree();
    assert!(matches!(tree.body[0], Statement::Import(_)));
}

#[test]
fn fixture_tree_ends_with_export() {
    let tree = fixture_tree();
    assert!(matches!(tree.body[2], Statement::Export(_)));
}

// ---------- ArenaBudget ----------

#[test]
fn arena_budget_default_has_positive_limits() {
    let budget = ArenaBudget::default();
    assert!(budget.max_nodes > 0);
    assert!(budget.max_expressions > 0);
    assert!(budget.max_spans > 0);
    assert!(budget.max_bytes > 0);
}

#[test]
fn arena_budget_serde_roundtrip() {
    let budget = ArenaBudget {
        max_nodes: 100,
        max_expressions: 50,
        max_spans: 200,
        max_bytes: 8192,
    };
    let json = serde_json::to_string(&budget).expect("serialize");
    let recovered: ArenaBudget = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.max_nodes, 100);
    assert_eq!(recovered.max_expressions, 50);
}

// ---------- ArenaBudgetKind ----------

#[test]
fn arena_budget_kind_serde_roundtrip() {
    for kind in [
        ArenaBudgetKind::Nodes,
        ArenaBudgetKind::Expressions,
        ArenaBudgetKind::Spans,
        ArenaBudgetKind::Bytes,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ArenaBudgetKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- ArenaError ----------

#[test]
fn arena_error_display_is_nonempty() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Nodes,
        limit: 10,
        attempted: 11,
    };
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

// ---------- HandleAuditKind ----------

#[test]
fn handle_audit_kind_serde_roundtrip() {
    for kind in [
        HandleAuditKind::Node,
        HandleAuditKind::Expression,
        HandleAuditKind::Span,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HandleAuditKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- NodeHandle ----------

#[test]
fn node_handle_from_parts_roundtrips() {
    let handle = NodeHandle::from_parts(7, 3);
    assert_eq!(handle.index(), 7);
    assert_eq!(handle.generation(), 3);
}

// ---------- ParserArena ----------

#[test]
fn arena_bytes_used_is_positive_for_nonempty_tree() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    assert!(arena.bytes_used() > 0);
}

#[test]
fn arena_to_syntax_tree_preserves_statement_count() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let recovered = arena.to_syntax_tree().expect("recover");
    assert_eq!(recovered.body.len(), tree.body.len());
    assert_eq!(recovered.goal, tree.goal);
}

#[test]
fn arena_budget_default_has_positive_max_expressions() {
    let budget = ArenaBudget::default();
    assert!(budget.max_expressions > 0);
    assert!(budget.max_spans > 0);
}

#[test]
fn node_handle_from_parts_deterministic() {
    let a = NodeHandle::from_parts(5, 2);
    let b = NodeHandle::from_parts(5, 2);
    assert_eq!(a, b);
}

#[test]
fn arena_roundtrip_preserves_parse_goal() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let recovered = arena.to_syntax_tree().expect("recover");
    assert_eq!(recovered.goal, tree.goal);
}

#[test]
fn arena_canonical_hash_is_nonempty_string() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let hash = arena.canonical_hash().expect("hash");
    assert!(!hash.is_empty(), "canonical hash must be non-empty");
}

#[test]
fn arena_canonical_hash_changes_with_different_tree() {
    let tree_a = fixture_tree();
    let mut tree_b = fixture_tree();
    tree_b.body.pop(); // remove last statement

    let arena_a = ParserArena::from_syntax_tree(&tree_a, ArenaBudget::default()).expect("arena a");
    let arena_b = ParserArena::from_syntax_tree(&tree_b, ArenaBudget::default()).expect("arena b");

    assert_ne!(
        arena_a.canonical_hash().expect("hash a"),
        arena_b.canonical_hash().expect("hash b"),
        "different trees must produce different hashes"
    );
}

#[test]
fn arena_statement_handles_count_matches_tree() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    assert_eq!(arena.statement_handles().len(), tree.body.len());
}

#[test]
fn arena_budget_node_limit_enforcement() {
    let tree = fixture_tree();
    let budget = ArenaBudget {
        max_nodes: 1, // too few for 3 statements
        max_expressions: 1024,
        max_spans: 1024,
        max_bytes: 1024 * 1024,
    };
    let err =
        ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail with node limit");
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            ..
        }
    ));
}

#[test]
fn arena_budget_span_limit_enforcement() {
    let tree = fixture_tree();
    let budget = ArenaBudget {
        max_nodes: 1024,
        max_expressions: 1024,
        max_spans: 1, // too few
        max_bytes: 1024 * 1024,
    };
    let err =
        ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail with span limit");
    assert!(matches!(
        err,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Spans,
            ..
        }
    ));
}

#[test]
fn arena_error_display_includes_budget_kind() {
    let err = ArenaError::BudgetExceeded {
        kind: ArenaBudgetKind::Nodes,
        limit: 10,
        attempted: 11,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("10") || msg.contains("11"),
        "error should mention limits: {msg}"
    );
}

#[test]
fn handle_audit_entry_serde_roundtrip() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let entries = arena.handle_audit_entries();
    assert!(!entries.is_empty());
    let entry = &entries[0];
    let json = serde_json::to_string(entry).expect("serialize");
    let recovered: HandleAuditEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*entry, recovered);
}

#[test]
fn expression_handle_from_parts_roundtrips() {
    let handle = ExpressionHandle::from_parts(42, 7);
    assert_eq!(handle.index(), 42);
    assert_eq!(handle.generation(), 7);
}

#[test]
fn span_handle_from_parts_roundtrips() {
    let handle = SpanHandle::from_parts(99, 5);
    assert_eq!(handle.index(), 99);
    assert_eq!(handle.generation(), 5);
}
