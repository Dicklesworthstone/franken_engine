#![forbid(unsafe_code)]

//! Integration tests for `frankenengine_engine::ast`.
//!
//! Coverage targets:
//! - Every public enum variant (construction, serde round-trip)
//! - Every public struct (construction, field access, serde round-trip)
//! - Every public method (happy path, edge cases)
//! - AST node construction and traversal
//! - Canonical value / bytes / hash determinism
//! - Cross-concern integration scenarios

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
    CANONICAL_AST_CONTRACT_VERSION, CANONICAL_AST_HASH_ALGORITHM, CANONICAL_AST_HASH_PREFIX,
    CANONICAL_AST_SCHEMA_VERSION, ExportDeclaration, ExportKind, Expression, ExpressionStatement,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span(start: u64, end: u64) -> SourceSpan {
    SourceSpan::new(start, end, 1, start + 1, 1, end + 1)
}

fn zero_span() -> SourceSpan {
    SourceSpan::new(0, 0, 1, 1, 1, 1)
}

fn expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: zero_span(),
    })
}

fn import_stmt(binding: Option<&str>, source: &str) -> Statement {
    Statement::Import(ImportDeclaration {
        binding: binding.map(String::from),
        source: source.to_string(),
        span: zero_span(),
    })
}

fn export_default_stmt(expr: Expression) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expr),
        span: zero_span(),
    })
}

fn export_named_stmt(clause: &str) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(clause.to_string()),
        span: zero_span(),
    })
}

fn simple_script(body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Script,
        body,
        span: zero_span(),
    }
}

fn simple_module(body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body,
        span: zero_span(),
    }
}

// ===========================================================================
// 1. ParseGoal — enum variant coverage
// ===========================================================================

#[test]
fn parse_goal_as_str_script() {
    assert_eq!(ParseGoal::Script.as_str(), "script");
}

#[test]
fn parse_goal_as_str_module() {
    assert_eq!(ParseGoal::Module.as_str(), "module");
}

#[test]
fn parse_goal_equality() {
    assert_eq!(ParseGoal::Script, ParseGoal::Script);
    assert_eq!(ParseGoal::Module, ParseGoal::Module);
    assert_ne!(ParseGoal::Script, ParseGoal::Module);
}

#[test]
fn parse_goal_clone() {
    let original = ParseGoal::Module;
    let cloned = original;
    assert_eq!(original, cloned);
}

#[test]
fn parse_goal_debug_format() {
    let dbg = format!("{:?}", ParseGoal::Script);
    assert!(dbg.contains("Script"));
    let dbg = format!("{:?}", ParseGoal::Module);
    assert!(dbg.contains("Module"));
}

#[test]
fn parse_goal_serde_round_trip_script() {
    let json = serde_json::to_string(&ParseGoal::Script).unwrap();
    let decoded: ParseGoal = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, ParseGoal::Script);
}

#[test]
fn parse_goal_serde_round_trip_module() {
    let json = serde_json::to_string(&ParseGoal::Module).unwrap();
    let decoded: ParseGoal = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, ParseGoal::Module);
}

#[test]
fn parse_goal_serde_json_values_are_distinct() {
    let script_json = serde_json::to_string(&ParseGoal::Script).unwrap();
    let module_json = serde_json::to_string(&ParseGoal::Module).unwrap();
    assert_ne!(script_json, module_json);
}

// ===========================================================================
// 2. SourceSpan — struct field coverage
// ===========================================================================

#[test]
fn source_span_new_stores_all_fields() {
    let s = SourceSpan::new(10, 50, 2, 3, 5, 20);
    assert_eq!(s.start_offset, 10);
    assert_eq!(s.end_offset, 50);
    assert_eq!(s.start_line, 2);
    assert_eq!(s.start_column, 3);
    assert_eq!(s.end_line, 5);
    assert_eq!(s.end_column, 20);
}

#[test]
fn source_span_zero_offsets() {
    let s = SourceSpan::new(0, 0, 0, 0, 0, 0);
    assert_eq!(s.start_offset, 0);
    assert_eq!(s.end_offset, 0);
}

#[test]
fn source_span_max_offsets() {
    let s = SourceSpan::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(s.start_offset, u64::MAX);
    assert_eq!(s.end_offset, u64::MAX);
}

#[test]
fn source_span_equality_all_fields() {
    let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let b = SourceSpan::new(0, 10, 1, 1, 1, 11);
    assert_eq!(a, b);
}

#[test]
fn source_span_inequality_start_offset() {
    let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let b = SourceSpan::new(1, 10, 1, 1, 1, 11);
    assert_ne!(a, b);
}

#[test]
fn source_span_inequality_end_offset() {
    let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let b = SourceSpan::new(0, 11, 1, 1, 1, 11);
    assert_ne!(a, b);
}

#[test]
fn source_span_inequality_lines() {
    let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let b = SourceSpan::new(0, 10, 2, 1, 1, 11);
    assert_ne!(a, b);
}

#[test]
fn source_span_inequality_columns() {
    let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let b = SourceSpan::new(0, 10, 1, 2, 1, 11);
    assert_ne!(a, b);
}

#[test]
fn source_span_clone() {
    let original = SourceSpan::new(3, 7, 1, 4, 1, 8);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn source_span_serde_round_trip() {
    let s = SourceSpan::new(7, 99, 3, 8, 10, 1);
    let json = serde_json::to_string(&s).unwrap();
    let decoded: SourceSpan = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn source_span_canonical_value_contains_all_six_keys() {
    let s = SourceSpan::new(0, 100, 1, 1, 10, 5);
    let cv = s.canonical_value();
    let cv_dbg = format!("{cv:?}");
    assert!(cv_dbg.contains("start_offset"));
    assert!(cv_dbg.contains("end_offset"));
    assert!(cv_dbg.contains("start_line"));
    assert!(cv_dbg.contains("start_column"));
    assert!(cv_dbg.contains("end_line"));
    assert!(cv_dbg.contains("end_column"));
}

#[test]
fn source_span_canonical_value_deterministic() {
    let s = SourceSpan::new(5, 42, 1, 6, 1, 43);
    let cv1 = s.canonical_value();
    let cv2 = s.canonical_value();
    assert_eq!(cv1, cv2);
}

// ===========================================================================
// 3. Expression — all 8 variants
// ===========================================================================

#[test]
fn expression_identifier_construction() {
    let expr = Expression::Identifier("myVar".to_string());
    if let Expression::Identifier(name) = &expr {
        assert_eq!(name, "myVar");
    } else {
        panic!("expected Identifier");
    }
}

#[test]
fn expression_string_literal_construction() {
    let expr = Expression::StringLiteral("hello world".to_string());
    if let Expression::StringLiteral(val) = &expr {
        assert_eq!(val, "hello world");
    } else {
        panic!("expected StringLiteral");
    }
}

#[test]
fn expression_numeric_literal_positive() {
    let expr = Expression::NumericLiteral(42);
    if let Expression::NumericLiteral(val) = &expr {
        assert_eq!(*val, 42);
    } else {
        panic!("expected NumericLiteral");
    }
}

#[test]
fn expression_numeric_literal_negative() {
    let expr = Expression::NumericLiteral(-1_000_000);
    if let Expression::NumericLiteral(val) = &expr {
        assert_eq!(*val, -1_000_000);
    } else {
        panic!("expected NumericLiteral");
    }
}

#[test]
fn expression_numeric_literal_zero() {
    let expr = Expression::NumericLiteral(0);
    if let Expression::NumericLiteral(val) = &expr {
        assert_eq!(*val, 0);
    } else {
        panic!("expected NumericLiteral");
    }
}

#[test]
fn expression_numeric_literal_i64_max() {
    let expr = Expression::NumericLiteral(i64::MAX);
    if let Expression::NumericLiteral(val) = &expr {
        assert_eq!(*val, i64::MAX);
    } else {
        panic!("expected NumericLiteral");
    }
}

#[test]
fn expression_numeric_literal_i64_min() {
    let expr = Expression::NumericLiteral(i64::MIN);
    if let Expression::NumericLiteral(val) = &expr {
        assert_eq!(*val, i64::MIN);
    } else {
        panic!("expected NumericLiteral");
    }
}

#[test]
fn expression_boolean_literal_true() {
    let expr = Expression::BooleanLiteral(true);
    if let Expression::BooleanLiteral(val) = &expr {
        assert!(*val);
    } else {
        panic!("expected BooleanLiteral");
    }
}

#[test]
fn expression_boolean_literal_false() {
    let expr = Expression::BooleanLiteral(false);
    if let Expression::BooleanLiteral(val) = &expr {
        assert!(!(*val));
    } else {
        panic!("expected BooleanLiteral");
    }
}

#[test]
fn expression_null_literal() {
    let expr = Expression::NullLiteral;
    assert_eq!(expr, Expression::NullLiteral);
}

#[test]
fn expression_undefined_literal() {
    let expr = Expression::UndefinedLiteral;
    assert_eq!(expr, Expression::UndefinedLiteral);
}

#[test]
fn expression_await_wraps_inner() {
    let inner = Expression::Identifier("promise".to_string());
    let expr = Expression::Await(Box::new(inner.clone()));
    if let Expression::Await(boxed) = &expr {
        assert_eq!(**boxed, inner);
    } else {
        panic!("expected Await");
    }
}

#[test]
fn expression_await_nested_deeply() {
    let level0 = Expression::NumericLiteral(1);
    let level1 = Expression::Await(Box::new(level0));
    let level2 = Expression::Await(Box::new(level1));
    let level3 = Expression::Await(Box::new(level2));
    // Verify outer is Await
    assert!(matches!(&level3, Expression::Await(_)));
}

#[test]
fn expression_raw_construction() {
    let expr = Expression::Raw("a + b * c".to_string());
    if let Expression::Raw(val) = &expr {
        assert_eq!(val, "a + b * c");
    } else {
        panic!("expected Raw");
    }
}

#[test]
fn expression_raw_empty_string() {
    let expr = Expression::Raw(String::new());
    if let Expression::Raw(val) = &expr {
        assert!(val.is_empty());
    } else {
        panic!("expected Raw");
    }
}

// ---------------------------------------------------------------------------
// Expression canonical_value kind tags
// ---------------------------------------------------------------------------

#[test]
fn expression_canonical_value_identifier_kind_tag() {
    let cv = Expression::Identifier("x".to_string()).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"identifier\""));
}

#[test]
fn expression_canonical_value_string_kind_tag() {
    let cv = Expression::StringLiteral("s".to_string()).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"string\""));
}

#[test]
fn expression_canonical_value_numeric_kind_tag() {
    let cv = Expression::NumericLiteral(7).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"numeric\""));
}

#[test]
fn expression_canonical_value_boolean_kind_tag() {
    let cv = Expression::BooleanLiteral(false).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"boolean\""));
}

#[test]
fn expression_canonical_value_null_kind_tag() {
    let cv = Expression::NullLiteral.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"null\""));
}

#[test]
fn expression_canonical_value_undefined_kind_tag() {
    let cv = Expression::UndefinedLiteral.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"undefined\""));
}

#[test]
fn expression_canonical_value_await_kind_tag() {
    let cv = Expression::Await(Box::new(Expression::NumericLiteral(0))).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"await\""));
}

#[test]
fn expression_canonical_value_raw_kind_tag() {
    let cv = Expression::Raw("x".to_string()).canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"raw\""));
}

// ---------------------------------------------------------------------------
// Expression serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn expression_serde_round_trip_all_variants() {
    let variants = vec![
        Expression::Identifier("foo".to_string()),
        Expression::StringLiteral("bar".to_string()),
        Expression::NumericLiteral(42),
        Expression::NumericLiteral(-999),
        Expression::NumericLiteral(0),
        Expression::BooleanLiteral(true),
        Expression::BooleanLiteral(false),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
        Expression::Raw("raw text".to_string()),
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let decoded: Expression = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, variant);
    }
}

// ---------------------------------------------------------------------------
// Expression equality distinguishes variants
// ---------------------------------------------------------------------------

#[test]
fn expression_different_variants_same_payload_not_equal() {
    let id = Expression::Identifier("x".to_string());
    let string = Expression::StringLiteral("x".to_string());
    let raw = Expression::Raw("x".to_string());
    assert_ne!(id, string);
    assert_ne!(id, raw);
    assert_ne!(string, raw);
}

#[test]
fn expression_null_and_undefined_not_equal() {
    assert_ne!(Expression::NullLiteral, Expression::UndefinedLiteral);
}

#[test]
fn expression_boolean_true_and_false_not_equal() {
    assert_ne!(
        Expression::BooleanLiteral(true),
        Expression::BooleanLiteral(false)
    );
}

// ===========================================================================
// 4. ImportDeclaration
// ===========================================================================

#[test]
fn import_declaration_with_binding() {
    let decl = ImportDeclaration {
        binding: Some("foo".to_string()),
        source: "bar".to_string(),
        span: zero_span(),
    };
    assert_eq!(decl.binding.as_deref(), Some("foo"));
    assert_eq!(decl.source, "bar");
}

#[test]
fn import_declaration_without_binding() {
    let decl = ImportDeclaration {
        binding: None,
        source: "side-effect-only".to_string(),
        span: zero_span(),
    };
    assert!(decl.binding.is_none());
}

#[test]
fn import_declaration_canonical_value_with_binding_has_string() {
    let decl = ImportDeclaration {
        binding: Some("dep".to_string()),
        source: "pkg".to_string(),
        span: zero_span(),
    };
    let cv = decl.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"dep\""));
    assert!(dbg.contains("\"pkg\""));
}

#[test]
fn import_declaration_canonical_value_without_binding_has_null() {
    let decl = ImportDeclaration {
        binding: None,
        source: "side".to_string(),
        span: zero_span(),
    };
    let cv = decl.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("Null"));
}

#[test]
fn import_declaration_serde_round_trip() {
    let decl = ImportDeclaration {
        binding: Some("x".to_string()),
        source: "mod".to_string(),
        span: span(0, 20),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let decoded: ImportDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, decl);
}

#[test]
fn import_declaration_serde_round_trip_no_binding() {
    let decl = ImportDeclaration {
        binding: None,
        source: "mod".to_string(),
        span: span(0, 15),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let decoded: ImportDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, decl);
}

// ===========================================================================
// 5. ExportKind
// ===========================================================================

#[test]
fn export_kind_default_construction() {
    let kind = ExportKind::Default(Expression::Identifier("main".to_string()));
    assert!(matches!(&kind, ExportKind::Default(_)));
}

#[test]
fn export_kind_named_clause_construction() {
    let kind = ExportKind::NamedClause("{ a, b }".to_string());
    if let ExportKind::NamedClause(clause) = &kind {
        assert_eq!(clause, "{ a, b }");
    } else {
        panic!("expected NamedClause");
    }
}

#[test]
fn export_kind_default_canonical_value_kind_tag() {
    let kind = ExportKind::Default(Expression::NumericLiteral(1));
    let cv = kind.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"default\""));
}

#[test]
fn export_kind_named_canonical_value_kind_tag() {
    let kind = ExportKind::NamedClause("foo".to_string());
    let cv = kind.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"named\""));
}

#[test]
fn export_kind_serde_round_trip_default() {
    let kind = ExportKind::Default(Expression::StringLiteral("val".to_string()));
    let json = serde_json::to_string(&kind).unwrap();
    let decoded: ExportKind = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, kind);
}

#[test]
fn export_kind_serde_round_trip_named() {
    let kind = ExportKind::NamedClause("{ x }".to_string());
    let json = serde_json::to_string(&kind).unwrap();
    let decoded: ExportKind = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, kind);
}

// ===========================================================================
// 6. ExportDeclaration
// ===========================================================================

#[test]
fn export_declaration_construction() {
    let decl = ExportDeclaration {
        kind: ExportKind::Default(Expression::NullLiteral),
        span: span(0, 20),
    };
    assert!(matches!(&decl.kind, ExportKind::Default(_)));
}

#[test]
fn export_declaration_canonical_value_has_kind_and_span() {
    let decl = ExportDeclaration {
        kind: ExportKind::NamedClause("{ a }".to_string()),
        span: zero_span(),
    };
    let cv = decl.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("kind"));
    assert!(dbg.contains("span"));
}

#[test]
fn export_declaration_serde_round_trip() {
    let decl = ExportDeclaration {
        kind: ExportKind::Default(Expression::BooleanLiteral(true)),
        span: span(5, 25),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let decoded: ExportDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, decl);
}

// ===========================================================================
// 7. ExpressionStatement
// ===========================================================================

#[test]
fn expression_statement_construction() {
    let stmt = ExpressionStatement {
        expression: Expression::Identifier("x".to_string()),
        span: span(0, 1),
    };
    assert_eq!(stmt.expression, Expression::Identifier("x".to_string()));
}

#[test]
fn expression_statement_canonical_value_has_expression_and_span() {
    let stmt = ExpressionStatement {
        expression: Expression::NumericLiteral(99),
        span: zero_span(),
    };
    let cv = stmt.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("expression"));
    assert!(dbg.contains("span"));
}

#[test]
fn expression_statement_serde_round_trip() {
    let stmt = ExpressionStatement {
        expression: Expression::Await(Box::new(Expression::Raw("fetch()".to_string()))),
        span: span(0, 15),
    };
    let json = serde_json::to_string(&stmt).unwrap();
    let decoded: ExpressionStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, stmt);
}

// ===========================================================================
// 8. Statement — all 3 variants
// ===========================================================================

#[test]
fn statement_import_variant_span() {
    let s = import_stmt(Some("x"), "mod");
    assert_eq!(*s.span(), zero_span());
}

#[test]
fn statement_export_variant_span() {
    let s = export_default_stmt(Expression::NullLiteral);
    assert_eq!(*s.span(), zero_span());
}

#[test]
fn statement_expression_variant_span() {
    let s = expr_stmt(Expression::NumericLiteral(1));
    assert_eq!(*s.span(), zero_span());
}

#[test]
fn statement_canonical_value_import_kind_tag() {
    let s = import_stmt(Some("x"), "mod");
    let cv = s.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"import\""));
    assert!(dbg.contains("payload"));
    assert!(dbg.contains("span"));
}

#[test]
fn statement_canonical_value_export_kind_tag() {
    let s = export_named_stmt("{ a }");
    let cv = s.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"export\""));
}

#[test]
fn statement_canonical_value_expression_kind_tag() {
    let s = expr_stmt(Expression::Raw("x".to_string()));
    let cv = s.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("\"expression\""));
}

#[test]
fn statement_serde_round_trip_import() {
    let s = import_stmt(Some("dep"), "pkg");
    let json = serde_json::to_string(&s).unwrap();
    let decoded: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn statement_serde_round_trip_export_default() {
    let s = export_default_stmt(Expression::Identifier("main".to_string()));
    let json = serde_json::to_string(&s).unwrap();
    let decoded: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn statement_serde_round_trip_export_named() {
    let s = export_named_stmt("{ foo, bar }");
    let json = serde_json::to_string(&s).unwrap();
    let decoded: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn statement_serde_round_trip_expression() {
    let s = expr_stmt(Expression::BooleanLiteral(true));
    let json = serde_json::to_string(&s).unwrap();
    let decoded: Statement = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, s);
}

// ===========================================================================
// 9. SyntaxTree — construction, canonical_value, canonical_bytes, canonical_hash
// ===========================================================================

#[test]
fn syntax_tree_empty_script() {
    let tree = simple_script(vec![]);
    assert_eq!(tree.goal, ParseGoal::Script);
    assert!(tree.body.is_empty());
}

#[test]
fn syntax_tree_empty_module() {
    let tree = simple_module(vec![]);
    assert_eq!(tree.goal, ParseGoal::Module);
    assert!(tree.body.is_empty());
}

#[test]
fn syntax_tree_with_single_statement() {
    let tree = simple_script(vec![expr_stmt(Expression::NumericLiteral(42))]);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn syntax_tree_with_multiple_statement_kinds() {
    let tree = simple_module(vec![
        import_stmt(Some("dep"), "pkg"),
        expr_stmt(Expression::Identifier("dep".to_string())),
        export_default_stmt(Expression::Identifier("dep".to_string())),
    ]);
    assert_eq!(tree.body.len(), 3);
}

#[test]
fn syntax_tree_canonical_value_has_goal_body_span() {
    let tree = simple_script(vec![expr_stmt(Expression::Identifier("x".to_string()))]);
    let cv = tree.canonical_value();
    let dbg = format!("{cv:?}");
    assert!(dbg.contains("goal"));
    assert!(dbg.contains("body"));
    assert!(dbg.contains("span"));
}

#[test]
fn syntax_tree_canonical_bytes_non_empty() {
    let tree = simple_script(vec![]);
    let bytes = tree.canonical_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn syntax_tree_canonical_bytes_deterministic() {
    let tree = simple_module(vec![expr_stmt(Expression::NumericLiteral(42))]);
    let bytes1 = tree.canonical_bytes();
    let bytes2 = tree.canonical_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn syntax_tree_canonical_hash_starts_with_sha256() {
    let tree = simple_script(vec![]);
    let hash = tree.canonical_hash();
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn syntax_tree_canonical_hash_length() {
    let tree = simple_script(vec![]);
    let hash = tree.canonical_hash();
    // "sha256:" prefix (7 chars) + 64 hex chars
    assert_eq!(hash.len(), 7 + 64);
}

#[test]
fn syntax_tree_canonical_hash_hex_only() {
    let tree = simple_script(vec![expr_stmt(Expression::NumericLiteral(1))]);
    let hash = tree.canonical_hash();
    let hex_part = &hash[7..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn syntax_tree_canonical_hash_deterministic() {
    let tree = simple_module(vec![expr_stmt(Expression::StringLiteral("hi".to_string()))]);
    let hash1 = tree.canonical_hash();
    let hash2 = tree.canonical_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn syntax_tree_different_goals_different_hashes() {
    let script = simple_script(vec![]);
    let module = simple_module(vec![]);
    assert_ne!(script.canonical_hash(), module.canonical_hash());
}

#[test]
fn syntax_tree_different_bodies_different_hashes() {
    let tree1 = simple_script(vec![expr_stmt(Expression::NumericLiteral(1))]);
    let tree2 = simple_script(vec![expr_stmt(Expression::NumericLiteral(2))]);
    assert_ne!(tree1.canonical_hash(), tree2.canonical_hash());
}

#[test]
fn syntax_tree_different_spans_different_hashes() {
    let tree1 = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: span(0, 10),
    };
    let tree2 = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: span(0, 20),
    };
    assert_ne!(tree1.canonical_hash(), tree2.canonical_hash());
}

#[test]
fn syntax_tree_serde_round_trip_empty() {
    let tree = simple_script(vec![]);
    let json = serde_json::to_string(&tree).unwrap();
    let decoded: SyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, tree);
}

#[test]
fn syntax_tree_serde_round_trip_complex() {
    let tree = simple_module(vec![
        import_stmt(Some("x"), "mod"),
        import_stmt(None, "side-effect"),
        expr_stmt(Expression::Await(Box::new(Expression::Identifier(
            "x".to_string(),
        )))),
        export_default_stmt(Expression::StringLiteral("result".to_string())),
        export_named_stmt("{ a, b }"),
    ]);
    let json = serde_json::to_string(&tree).unwrap();
    let decoded: SyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, tree);
}

// ===========================================================================
// 10. Determinism: same inputs produce same outputs
// ===========================================================================

#[test]
fn determinism_independent_constructions_yield_identical_hashes() {
    let build = || {
        simple_module(vec![
            import_stmt(Some("dep"), "pkg"),
            export_default_stmt(Expression::Identifier("dep".to_string())),
        ])
    };
    let tree1 = build();
    let tree2 = build();
    assert_eq!(tree1.canonical_bytes(), tree2.canonical_bytes());
    assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
}

#[test]
fn determinism_canonical_value_stable_across_clones() {
    let tree = simple_script(vec![
        expr_stmt(Expression::BooleanLiteral(true)),
        expr_stmt(Expression::NullLiteral),
        expr_stmt(Expression::UndefinedLiteral),
    ]);
    let cloned = tree.clone();
    assert_eq!(tree.canonical_value(), cloned.canonical_value());
}

#[test]
fn determinism_hash_uniqueness_across_many_variants() {
    let trees: Vec<SyntaxTree> = vec![
        simple_script(vec![]),
        simple_module(vec![]),
        simple_script(vec![expr_stmt(Expression::NumericLiteral(0))]),
        simple_script(vec![expr_stmt(Expression::NumericLiteral(1))]),
        simple_script(vec![expr_stmt(Expression::StringLiteral(String::new()))]),
        simple_script(vec![expr_stmt(Expression::StringLiteral("a".to_string()))]),
        simple_script(vec![expr_stmt(Expression::BooleanLiteral(true))]),
        simple_script(vec![expr_stmt(Expression::BooleanLiteral(false))]),
        simple_script(vec![expr_stmt(Expression::NullLiteral)]),
        simple_script(vec![expr_stmt(Expression::UndefinedLiteral)]),
        simple_script(vec![expr_stmt(Expression::Raw("x".to_string()))]),
        simple_script(vec![expr_stmt(Expression::Identifier("x".to_string()))]),
        simple_script(vec![expr_stmt(Expression::Await(Box::new(
            Expression::NumericLiteral(0),
        )))]),
    ];
    let hashes: BTreeSet<String> = trees.iter().map(|t| t.canonical_hash()).collect();
    assert_eq!(hashes.len(), trees.len(), "all hashes must be unique");
}

// ===========================================================================
// 11. Cross-concern integration: AST traversal
// ===========================================================================

#[test]
fn traverse_body_collecting_spans() {
    let tree = simple_module(vec![
        Statement::Import(ImportDeclaration {
            binding: Some("a".to_string()),
            source: "pkg_a".to_string(),
            span: span(0, 20),
        }),
        Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Identifier("a".to_string())),
            span: span(21, 45),
        }),
        Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: span(46, 48),
        }),
    ]);

    let offsets: Vec<(u64, u64)> = tree
        .body
        .iter()
        .map(|s| (s.span().start_offset, s.span().end_offset))
        .collect();

    assert_eq!(offsets, vec![(0, 20), (21, 45), (46, 48)]);
}

#[test]
fn traverse_extracting_all_import_sources() {
    let tree = simple_module(vec![
        import_stmt(Some("a"), "alpha"),
        import_stmt(None, "beta"),
        expr_stmt(Expression::NumericLiteral(1)),
        import_stmt(Some("c"), "gamma"),
    ]);

    let sources: Vec<&str> = tree
        .body
        .iter()
        .filter_map(|s| {
            if let Statement::Import(decl) = s {
                Some(decl.source.as_str())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(sources, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn traverse_counting_expression_statements() {
    let tree = simple_script(vec![
        expr_stmt(Expression::NumericLiteral(1)),
        import_stmt(Some("x"), "m"),
        expr_stmt(Expression::NumericLiteral(2)),
        export_named_stmt("{ y }"),
        expr_stmt(Expression::NumericLiteral(3)),
    ]);

    let count = tree
        .body
        .iter()
        .filter(|s| matches!(s, Statement::Expression(_)))
        .count();

    assert_eq!(count, 3);
}

// ===========================================================================
// 12. Cross-concern: canonical hash survives serde round-trip
// ===========================================================================

#[test]
fn canonical_hash_stable_after_serde_round_trip() {
    let tree = simple_module(vec![
        import_stmt(Some("dep"), "pkg"),
        expr_stmt(Expression::Await(Box::new(Expression::Identifier(
            "dep".to_string(),
        )))),
        export_default_stmt(Expression::StringLiteral("done".to_string())),
    ]);

    let hash_before = tree.canonical_hash();
    let json = serde_json::to_string(&tree).unwrap();
    let decoded: SyntaxTree = serde_json::from_str(&json).unwrap();
    let hash_after = decoded.canonical_hash();

    assert_eq!(hash_before, hash_after);
}

#[test]
fn canonical_bytes_stable_after_serde_round_trip() {
    let tree = simple_script(vec![
        expr_stmt(Expression::BooleanLiteral(false)),
        expr_stmt(Expression::NullLiteral),
    ]);

    let bytes_before = tree.canonical_bytes();
    let json = serde_json::to_string(&tree).unwrap();
    let decoded: SyntaxTree = serde_json::from_str(&json).unwrap();
    let bytes_after = decoded.canonical_bytes();

    assert_eq!(bytes_before, bytes_after);
}

// ===========================================================================
// 13. Edge cases: empty strings, special characters
// ===========================================================================

#[test]
fn import_empty_source_string() {
    let decl = ImportDeclaration {
        binding: Some(String::new()),
        source: String::new(),
        span: zero_span(),
    };
    let json = serde_json::to_string(&decl).unwrap();
    let decoded: ImportDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, decl);
}

#[test]
fn export_named_empty_clause() {
    let kind = ExportKind::NamedClause(String::new());
    let json = serde_json::to_string(&kind).unwrap();
    let decoded: ExportKind = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, kind);
}

#[test]
fn expression_string_literal_unicode() {
    let expr = Expression::StringLiteral("\u{1F600}\u{00E9}\u{4E16}\u{754C}".to_string());
    let json = serde_json::to_string(&expr).unwrap();
    let decoded: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, expr);
}

#[test]
fn expression_identifier_with_special_chars() {
    let expr = Expression::Identifier("$_foo123".to_string());
    let json = serde_json::to_string(&expr).unwrap();
    let decoded: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, expr);
}

#[test]
fn expression_raw_with_newlines_and_tabs() {
    let expr = Expression::Raw("line1\nline2\ttab".to_string());
    let json = serde_json::to_string(&expr).unwrap();
    let decoded: Expression = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, expr);
}

#[test]
fn syntax_tree_large_body() {
    let body: Vec<Statement> = (0..100)
        .map(|i| expr_stmt(Expression::NumericLiteral(i)))
        .collect();
    let tree = simple_script(body);
    assert_eq!(tree.body.len(), 100);
    // Hash should still work
    let hash = tree.canonical_hash();
    assert!(hash.starts_with("sha256:"));
    // And be deterministic
    let hash2 = tree.canonical_hash();
    assert_eq!(hash, hash2);
}

// ===========================================================================
// 14. Canonical value determinism at every level
// ===========================================================================

#[test]
fn expression_canonical_value_deterministic_all_variants() {
    let variants = vec![
        Expression::Identifier("x".to_string()),
        Expression::StringLiteral("s".to_string()),
        Expression::NumericLiteral(99),
        Expression::BooleanLiteral(true),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Await(Box::new(Expression::NumericLiteral(0))),
        Expression::Raw("r".to_string()),
    ];
    for variant in variants {
        let cv1 = variant.canonical_value();
        let cv2 = variant.canonical_value();
        assert_eq!(cv1, cv2);
    }
}

#[test]
fn import_declaration_canonical_value_deterministic() {
    let decl = ImportDeclaration {
        binding: Some("x".to_string()),
        source: "m".to_string(),
        span: span(0, 10),
    };
    let cv1 = decl.canonical_value();
    let cv2 = decl.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn export_kind_canonical_value_deterministic() {
    let kind = ExportKind::Default(Expression::Identifier("a".to_string()));
    let cv1 = kind.canonical_value();
    let cv2 = kind.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn export_declaration_canonical_value_deterministic() {
    let decl = ExportDeclaration {
        kind: ExportKind::NamedClause("{ b }".to_string()),
        span: span(5, 15),
    };
    let cv1 = decl.canonical_value();
    let cv2 = decl.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn expression_statement_canonical_value_deterministic() {
    let stmt = ExpressionStatement {
        expression: Expression::BooleanLiteral(false),
        span: span(0, 5),
    };
    let cv1 = stmt.canonical_value();
    let cv2 = stmt.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn statement_canonical_value_deterministic_all_variants() {
    let stmts = vec![
        import_stmt(Some("a"), "b"),
        export_default_stmt(Expression::NullLiteral),
        export_named_stmt("{ c }"),
        expr_stmt(Expression::UndefinedLiteral),
    ];
    for stmt in stmts {
        let cv1 = stmt.canonical_value();
        let cv2 = stmt.canonical_value();
        assert_eq!(cv1, cv2);
    }
}

// ===========================================================================
// 15. Clone and equality exhaustive
// ===========================================================================

#[test]
fn syntax_tree_clone_preserves_equality() {
    let tree = simple_module(vec![
        import_stmt(Some("x"), "m"),
        expr_stmt(Expression::Await(Box::new(Expression::StringLiteral(
            "data".to_string(),
        )))),
        export_named_stmt("{ x }"),
    ]);
    let cloned = tree.clone();
    assert_eq!(tree, cloned);
}

#[test]
fn syntax_tree_inequality_different_goals() {
    let a = simple_script(vec![]);
    let b = simple_module(vec![]);
    assert_ne!(a, b);
}

#[test]
fn syntax_tree_inequality_different_body_length() {
    let a = simple_script(vec![]);
    let b = simple_script(vec![expr_stmt(Expression::NullLiteral)]);
    assert_ne!(a, b);
}

#[test]
fn syntax_tree_inequality_different_body_content() {
    let a = simple_script(vec![expr_stmt(Expression::NumericLiteral(1))]);
    let b = simple_script(vec![expr_stmt(Expression::NumericLiteral(2))]);
    assert_ne!(a, b);
}

// ===========================================================================
// 16. Mixed statement-type AST canonical hashing
// ===========================================================================

#[test]
fn mixed_statement_order_affects_hash() {
    let tree1 = simple_module(vec![
        import_stmt(Some("a"), "m"),
        expr_stmt(Expression::NumericLiteral(1)),
    ]);
    let tree2 = simple_module(vec![
        expr_stmt(Expression::NumericLiteral(1)),
        import_stmt(Some("a"), "m"),
    ]);
    assert_ne!(tree1.canonical_hash(), tree2.canonical_hash());
}

#[test]
fn duplicate_statements_differ_from_single() {
    let tree1 = simple_script(vec![expr_stmt(Expression::NumericLiteral(1))]);
    let tree2 = simple_script(vec![
        expr_stmt(Expression::NumericLiteral(1)),
        expr_stmt(Expression::NumericLiteral(1)),
    ]);
    assert_ne!(tree1.canonical_hash(), tree2.canonical_hash());
}

// ===========================================================================
// 17. Debug format sanity checks
// ===========================================================================

#[test]
fn expression_debug_format_variants() {
    let cases = vec![
        (Expression::Identifier("x".to_string()), "Identifier"),
        (Expression::StringLiteral("s".to_string()), "StringLiteral"),
        (Expression::NumericLiteral(0), "NumericLiteral"),
        (Expression::BooleanLiteral(true), "BooleanLiteral"),
        (Expression::NullLiteral, "NullLiteral"),
        (Expression::UndefinedLiteral, "UndefinedLiteral"),
        (
            Expression::Await(Box::new(Expression::NullLiteral)),
            "Await",
        ),
        (Expression::Raw("r".to_string()), "Raw"),
    ];
    for (expr, expected_tag) in cases {
        let dbg = format!("{expr:?}");
        assert!(
            dbg.contains(expected_tag),
            "Debug for {expected_tag} should contain the variant name"
        );
    }
}

#[test]
fn statement_debug_format_variants() {
    let import = import_stmt(Some("x"), "m");
    let export = export_default_stmt(Expression::NullLiteral);
    let expression = expr_stmt(Expression::NumericLiteral(0));

    assert!(format!("{import:?}").contains("Import"));
    assert!(format!("{export:?}").contains("Export"));
    assert!(format!("{expression:?}").contains("Expression"));
}

#[test]
fn syntax_tree_debug_contains_goal() {
    let tree = simple_script(vec![]);
    let dbg = format!("{tree:?}");
    assert!(dbg.contains("Script"));
}

// ===========================================================================
// 18. Fixed-point millionths convention test
// ===========================================================================

#[test]
fn numeric_literal_fixed_point_millionths_convention() {
    // 1_000_000 represents 1.0 in fixed-point millionths
    let one = Expression::NumericLiteral(1_000_000);
    if let Expression::NumericLiteral(val) = &one {
        assert_eq!(*val, 1_000_000);
    } else {
        panic!("expected NumericLiteral");
    }

    let half = Expression::NumericLiteral(500_000);
    if let Expression::NumericLiteral(val) = &half {
        assert_eq!(*val, 500_000);
    } else {
        panic!("expected NumericLiteral");
    }
}

// ===========================================================================
// 19. Await with every expression variant as inner
// ===========================================================================

#[test]
fn await_wrapping_every_expression_variant() {
    let inners = vec![
        Expression::Identifier("p".to_string()),
        Expression::StringLiteral("s".to_string()),
        Expression::NumericLiteral(42),
        Expression::BooleanLiteral(true),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Raw("raw()".to_string()),
    ];
    for inner in inners {
        let awaited = Expression::Await(Box::new(inner.clone()));
        let json = serde_json::to_string(&awaited).unwrap();
        let decoded: Expression = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, awaited);
        // Canonical value should have "await" kind
        let cv = awaited.canonical_value();
        let dbg = format!("{cv:?}");
        assert!(dbg.contains("\"await\""));
    }
}

// ===========================================================================
// 20. Export default with every expression variant
// ===========================================================================

#[test]
fn export_default_with_every_expression_variant() {
    let variants = vec![
        Expression::Identifier("x".to_string()),
        Expression::StringLiteral("s".to_string()),
        Expression::NumericLiteral(0),
        Expression::BooleanLiteral(false),
        Expression::NullLiteral,
        Expression::UndefinedLiteral,
        Expression::Await(Box::new(Expression::NumericLiteral(1))),
        Expression::Raw("fn()".to_string()),
    ];
    for variant in variants {
        let kind = ExportKind::Default(variant.clone());
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ExportKind = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, kind);
    }
}

// ===========================================================================
// 21. Canonical AST contract metadata
// ===========================================================================

#[test]
fn canonical_ast_contract_constants_are_pinned() {
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
fn canonical_ast_contract_accessors_are_stable() {
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

#[test]
fn canonical_hash_prefix_matches_contract_constant() {
    let tree = simple_script(vec![expr_stmt(Expression::NumericLiteral(42))]);
    let hash = tree.canonical_hash();
    assert!(hash.starts_with(CANONICAL_AST_HASH_PREFIX));
}
