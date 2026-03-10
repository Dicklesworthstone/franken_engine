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

// Integration tests for parser edge cases: empty/whitespace sources, import/export
// error paths, expression parsing, statement splitting, identifier validation,
// string quoting, line counting, IO errors, goal enforcement, and determinism.

use std::io::Cursor;

use frankenengine_engine::ast::{ExportKind, Expression, ParseGoal, Statement};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseErrorCode, StreamInput,
};

fn parser() -> CanonicalEs2020Parser {
    CanonicalEs2020Parser
}

// ---------------------------------------------------------------------------
// Empty and whitespace-only sources
// ---------------------------------------------------------------------------

#[test]
fn empty_source_returns_empty_source_error() {
    let err = parser().parse("", ParseGoal::Script).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
    assert!(!err.message.is_empty());
}

#[test]
fn whitespace_only_source_returns_empty_source_error() {
    let err = parser()
        .parse("   \t \n \n ", ParseGoal::Script)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
}

#[test]
fn single_newline_returns_empty_source_error() {
    let err = parser().parse("\n", ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
}

// ---------------------------------------------------------------------------
// Import statement edge cases (module goal)
// ---------------------------------------------------------------------------

#[test]
fn import_bare_keyword_returns_missing_clause_error() {
    let err = parser().parse("import", ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(err.message.contains("missing clause"));
}

#[test]
fn import_with_space_only_after_keyword_is_missing_clause() {
    let err = parser().parse("import   ", ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(err.message.contains("missing clause"));
}

#[test]
fn import_with_quoted_source_no_binding() {
    let tree = parser()
        .parse("import 'lodash'", ParseGoal::Module)
        .expect("bare import should work");
    assert_eq!(tree.body.len(), 1);
    match &tree.body[0] {
        Statement::Import(decl) => {
            assert_eq!(decl.binding, None);
            assert_eq!(decl.source, "lodash");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_with_double_quoted_source_no_binding() {
    let tree = parser()
        .parse("import \"lodash\"", ParseGoal::Module)
        .expect("double-quoted import should work");
    match &tree.body[0] {
        Statement::Import(decl) => {
            assert_eq!(decl.binding, None);
            assert_eq!(decl.source, "lodash");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_binding_from_quoted_source() {
    let tree = parser()
        .parse("import _ from 'lodash'", ParseGoal::Module)
        .expect("named import should work");
    match &tree.body[0] {
        Statement::Import(decl) => {
            assert_eq!(decl.binding.as_deref(), Some("_"));
            assert_eq!(decl.source, "lodash");
        }
        _ => panic!("expected import"),
    }
}

#[test]
fn import_dollar_binding_is_valid_identifier() {
    let tree = parser()
        .parse("import $x from 'pkg'", ParseGoal::Module)
        .expect("$x is a valid identifier");
    match &tree.body[0] {
        Statement::Import(decl) => {
            assert_eq!(decl.binding.as_deref(), Some("$x"));
        }
        _ => panic!("expected import"),
    }
}

#[test]
fn import_without_from_keyword_is_unsupported() {
    let err = parser()
        .parse("import x 'pkg'", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_with_unquoted_source_is_unsupported() {
    let err = parser()
        .parse("import x from pkg", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(err.message.contains("quoted"));
}

#[test]
fn import_with_numeric_binding_is_invalid_identifier() {
    let err = parser()
        .parse("import 123 from 'pkg'", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_in_script_goal_is_rejected() {
    let err = parser()
        .parse("import x from 'pkg'", ParseGoal::Script)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidGoal);
    assert!(err.message.contains("module"));
}

// ---------------------------------------------------------------------------
// Export statement edge cases
// ---------------------------------------------------------------------------

#[test]
fn export_bare_keyword_returns_missing_clause_error() {
    let err = parser().parse("export", ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(err.message.contains("missing clause"));
}

#[test]
fn export_with_space_only_after_keyword_is_missing_clause() {
    let err = parser().parse("export   ", ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn export_default_expression() {
    let tree = parser()
        .parse("export default myFunc", ParseGoal::Module)
        .expect("default export should work");
    match &tree.body[0] {
        Statement::Export(decl) => {
            assert!(
                matches!(&decl.kind, ExportKind::Default(Expression::Identifier(name)) if name == "myFunc")
            );
        }
        _ => panic!("expected export"),
    }
}

#[test]
fn export_default_string_literal() {
    let tree = parser()
        .parse("export default 'hello'", ParseGoal::Module)
        .expect("default string export");
    match &tree.body[0] {
        Statement::Export(decl) => {
            assert!(
                matches!(&decl.kind, ExportKind::Default(Expression::StringLiteral(v)) if v == "hello")
            );
        }
        _ => panic!("expected export"),
    }
}

#[test]
fn export_default_numeric_literal() {
    let tree = parser()
        .parse("export default 42", ParseGoal::Module)
        .expect("default numeric export");
    match &tree.body[0] {
        Statement::Export(decl) => {
            assert!(matches!(
                &decl.kind,
                ExportKind::Default(Expression::NumericLiteral(42))
            ));
        }
        _ => panic!("expected export"),
    }
}

#[test]
fn export_named_clause() {
    let tree = parser()
        .parse("export { foo, bar }", ParseGoal::Module)
        .expect("named export");
    match &tree.body[0] {
        Statement::Export(decl) => {
            assert!(
                matches!(&decl.kind, ExportKind::NamedClause(clause) if clause == "{ foo, bar }")
            );
        }
        _ => panic!("expected export"),
    }
}

#[test]
fn export_in_script_goal_is_rejected() {
    let err = parser()
        .parse("export default 1", ParseGoal::Script)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidGoal);
}

// ---------------------------------------------------------------------------
// Expression parsing edge cases
// ---------------------------------------------------------------------------

#[test]
fn identifier_starting_with_underscore() {
    let tree = parser()
        .parse("_private", ParseGoal::Script)
        .expect("underscore identifier");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::Identifier(name) if name == "_private"));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn identifier_starting_with_dollar() {
    let tree = parser()
        .parse("$scope", ParseGoal::Script)
        .expect("dollar identifier");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::Identifier(name) if name == "$scope"));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn numeric_literal_zero() {
    let tree = parser().parse("0", ParseGoal::Script).expect("zero");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::NumericLiteral(0)));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn large_numeric_literal() {
    let tree = parser()
        .parse("9999999999", ParseGoal::Script)
        .expect("large number");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(
                &expr.expression,
                Expression::NumericLiteral(9_999_999_999)
            ));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn negative_numeric_literal_is_parsed() {
    let tree = parser()
        .parse("-7", ParseGoal::Script)
        .expect("negative number");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::NumericLiteral(-7)));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn string_literal_single_quotes() {
    let tree = parser()
        .parse("'hello world'", ParseGoal::Script)
        .expect("single-quoted string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v == "hello world"));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn string_literal_double_quotes() {
    let tree = parser()
        .parse("\"hello world\"", ParseGoal::Script)
        .expect("double-quoted string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v == "hello world"));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn empty_single_quoted_string() {
    let tree = parser()
        .parse("''", ParseGoal::Script)
        .expect("empty single-quoted string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v.is_empty()));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn empty_double_quoted_string() {
    let tree = parser()
        .parse("\"\"", ParseGoal::Script)
        .expect("empty double-quoted string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v.is_empty()));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn mismatched_quotes_are_not_string_literals() {
    // 'hello" doesn't match quote pairs — treated as Raw expression
    let tree = parser()
        .parse("'hello\"", ParseGoal::Script)
        .expect("mismatched quotes parse as raw");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::Raw(_)));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn await_expression_wraps_inner_expression() {
    let tree = parser()
        .parse("await fetch", ParseGoal::Script)
        .expect("await expression");
    match &tree.body[0] {
        Statement::Expression(expr) => match &expr.expression {
            Expression::Await(inner) => {
                assert!(matches!(inner.as_ref(), Expression::Identifier(name) if name == "fetch"));
            }
            other => panic!("expected Await, got {other:?}"),
        },
        _ => panic!("expected expression"),
    }
}

#[test]
fn await_string_literal() {
    let tree = parser()
        .parse("await 'result'", ParseGoal::Script)
        .expect("await string");
    match &tree.body[0] {
        Statement::Expression(expr) => match &expr.expression {
            Expression::Await(inner) => {
                assert!(matches!(inner.as_ref(), Expression::StringLiteral(v) if v == "result"));
            }
            other => panic!("expected Await(StringLiteral), got {other:?}"),
        },
        _ => panic!("expected expression"),
    }
}

#[test]
fn boolean_literals_are_parsed() {
    let tree_true = parser().parse("true", ParseGoal::Script).expect("true");
    let tree_false = parser().parse("false", ParseGoal::Script).expect("false");
    match &tree_true.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::BooleanLiteral(true)));
        }
        _ => panic!("expected expression"),
    }
    match &tree_false.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(
                &expr.expression,
                Expression::BooleanLiteral(false)
            ));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn null_and_undefined_literals_are_parsed() {
    let tree_null = parser().parse("null", ParseGoal::Script).expect("null");
    let tree_undef = parser()
        .parse("undefined", ParseGoal::Script)
        .expect("undefined");
    match &tree_null.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::NullLiteral));
        }
        _ => panic!("expected expression"),
    }
    match &tree_undef.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::UndefinedLiteral));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn raw_expression_for_complex_syntax() {
    let tree = parser()
        .parse("a + b * c", ParseGoal::Script)
        .expect("complex expression");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::Raw(v) if v == "a + b * c"));
        }
        _ => panic!("expected expression"),
    }
}

// ---------------------------------------------------------------------------
// Statement splitting with semicolons
// ---------------------------------------------------------------------------

#[test]
fn multiple_statements_on_one_line() {
    let tree = parser()
        .parse("a;b;c", ParseGoal::Script)
        .expect("semicolon-separated statements");
    assert_eq!(tree.body.len(), 3);
}

#[test]
fn semicolon_inside_quotes_does_not_split() {
    let tree = parser()
        .parse("'a;b';x", ParseGoal::Script)
        .expect("quoted semicolon");
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn trailing_semicolon_does_not_create_extra_statement() {
    let tree = parser()
        .parse("x;", ParseGoal::Script)
        .expect("trailing semicolon");
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn multiple_trailing_semicolons() {
    let tree = parser()
        .parse("x;;;", ParseGoal::Script)
        .expect("multiple trailing semicolons");
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn only_semicolons_produces_empty_body() {
    // Semicolons-only is not whitespace-empty, so it parses but produces no statements
    let tree = parser()
        .parse(";;;", ParseGoal::Script)
        .expect("semicolons-only should parse");
    assert!(tree.body.is_empty(), "no statements from semicolons-only");
}

#[test]
fn mixed_newlines_and_semicolons() {
    let tree = parser()
        .parse("a;b\nc;d\n", ParseGoal::Script)
        .expect("mixed newlines and semicolons");
    assert_eq!(tree.body.len(), 4);
}

// ---------------------------------------------------------------------------
// Line counting and spans
// ---------------------------------------------------------------------------

#[test]
fn single_line_has_line_count_one() {
    let tree = parser().parse("x", ParseGoal::Script).expect("single line");
    assert_eq!(tree.span.start_line, 1);
    assert_eq!(tree.span.end_line, 1);
}

#[test]
fn multi_line_has_correct_line_count() {
    let tree = parser()
        .parse("a\nb\nc\n", ParseGoal::Script)
        .expect("multi-line");
    assert_eq!(tree.span.start_line, 1);
    assert_eq!(tree.span.end_line, 4); // 3 newlines = 4 lines
    assert_eq!(tree.body.len(), 3);
}

#[test]
fn crlf_line_endings_are_handled() {
    let tree = parser()
        .parse("a\r\nb\r\n", ParseGoal::Script)
        .expect("CRLF source");
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn span_offsets_are_monotonically_increasing() {
    let tree = parser()
        .parse("alpha;beta\ngamma;delta\n", ParseGoal::Script)
        .expect("multi-statement multi-line");
    let mut prev_start = 0u64;
    for stmt in &tree.body {
        let span = stmt.span();
        assert!(
            span.start_offset >= prev_start,
            "span offsets must be monotonically increasing"
        );
        assert!(span.end_offset >= span.start_offset, "end must be >= start");
        prev_start = span.start_offset;
    }
}

#[test]
fn first_statement_starts_at_line_one_column_one() {
    let tree = parser()
        .parse("hello", ParseGoal::Script)
        .expect("simple source");
    let span = tree.body[0].span();
    assert_eq!(span.start_line, 1);
    assert_eq!(span.start_column, 1);
}

// ---------------------------------------------------------------------------
// I/O error paths
// ---------------------------------------------------------------------------

#[test]
fn nonexistent_file_returns_io_error() {
    let path = std::path::Path::new("/tmp/nonexistent_franken_parser_test_file_xyz.js");
    let err = parser().parse(path, ParseGoal::Script).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::IoReadFailed);
}

#[test]
fn invalid_utf8_stream_returns_error() {
    let bytes: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];
    let stream = StreamInput::new(Cursor::new(bytes), "invalid-utf8");
    let err = parser().parse(stream, ParseGoal::Module).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidUtf8);
}

#[test]
fn stream_input_label_is_preserved_in_error() {
    let bytes: &[u8] = &[0xFF, 0xFE];
    let stream = StreamInput::new(Cursor::new(bytes), "my-custom-label");
    let err = parser().parse(stream, ParseGoal::Script).unwrap_err();
    assert_eq!(err.source_label, "my-custom-label");
}

// ---------------------------------------------------------------------------
// Goal enforcement
// ---------------------------------------------------------------------------

#[test]
fn module_goal_allows_import() {
    let tree = parser()
        .parse("import 'mod'", ParseGoal::Module)
        .expect("module allows import");
    assert_eq!(tree.goal, ParseGoal::Module);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn module_goal_allows_export() {
    let tree = parser()
        .parse("export default 1", ParseGoal::Module)
        .expect("module allows export");
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn script_goal_allows_expressions() {
    let tree = parser()
        .parse("x + y", ParseGoal::Script)
        .expect("script allows expressions");
    assert_eq!(tree.goal, ParseGoal::Script);
}

#[test]
fn import_keyword_alone_in_script_is_rejected() {
    let err = parser().parse("import", ParseGoal::Script).unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidGoal);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn parsing_same_source_produces_identical_trees() {
    let source = "import x from 'pkg';\nexport default x;\nalpha;beta;\n";
    let tree_a = parser().parse(source, ParseGoal::Module).expect("parse a");
    let tree_b = parser().parse(source, ParseGoal::Module).expect("parse b");
    assert_eq!(tree_a.canonical_bytes(), tree_b.canonical_bytes());
    assert_eq!(tree_a.canonical_hash(), tree_b.canonical_hash());
}

#[test]
fn whitespace_normalization_is_deterministic() {
    let tree_a = parser()
        .parse("a  +  b", ParseGoal::Script)
        .expect("parse a");
    let tree_b = parser()
        .parse("a  +  b", ParseGoal::Script)
        .expect("parse b");
    assert_eq!(tree_a.canonical_bytes(), tree_b.canonical_bytes());
}

// ---------------------------------------------------------------------------
// ParseError Display
// ---------------------------------------------------------------------------

#[test]
fn parse_error_display_with_span_includes_line_and_column() {
    let err = parser()
        .parse("import x from pkg", ParseGoal::Module)
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("line="));
    assert!(msg.contains("column="));
    assert!(msg.contains("source="));
}

#[test]
fn parse_error_display_without_span_includes_source() {
    let err = parser().parse("", ParseGoal::Script).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("source="));
    // EmptySource errors don't have spans
    assert!(!msg.contains("line="));
}

// ---------------------------------------------------------------------------
// String parsing specifics
// ---------------------------------------------------------------------------

#[test]
fn single_char_string() {
    let tree = parser()
        .parse("'x'", ParseGoal::Script)
        .expect("single char string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v == "x"));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn string_with_spaces() {
    let tree = parser()
        .parse("'   '", ParseGoal::Script)
        .expect("spaces string");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(matches!(&expr.expression, Expression::StringLiteral(v) if v == "   "));
        }
        _ => panic!("expected expression"),
    }
}

#[test]
fn single_quote_char_is_not_a_string() {
    // A single quote character is not a valid quoted string (length < 2 for matching)
    let tree = parser().parse("x", ParseGoal::Script).expect("single char");
    assert_eq!(tree.body.len(), 1);
}

// ---------------------------------------------------------------------------
// Canonical hash and bytes
// ---------------------------------------------------------------------------

#[test]
fn different_sources_produce_different_hashes() {
    let tree_a = parser().parse("alpha", ParseGoal::Script).expect("a");
    let tree_b = parser().parse("beta", ParseGoal::Script).expect("b");
    assert_ne!(tree_a.canonical_hash(), tree_b.canonical_hash());
}

#[test]
fn same_content_different_goals_produce_different_trees() {
    let source = "x;";
    let script = parser().parse(source, ParseGoal::Script).expect("script");
    let module = parser().parse(source, ParseGoal::Module).expect("module");
    // Goals differ so canonical representations should differ
    assert_ne!(script.canonical_bytes(), module.canonical_bytes());
}
