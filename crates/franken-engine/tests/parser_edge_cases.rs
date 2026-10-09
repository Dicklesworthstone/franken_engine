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

use frankenengine_engine::ast::{BinaryOperator, ExportKind, Expression, ParseGoal, Statement};
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

// Malformed import declarations are SyntaxErrors (InvalidSyntax), as in
// Node, not refusals (bd-9vouw.429).
#[test]
fn import_without_from_keyword_is_a_syntax_error() {
    let err = parser()
        .parse("import x 'pkg'", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn import_with_unquoted_source_is_a_syntax_error() {
    let err = parser()
        .parse("import x from pkg", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
    assert!(err.message.contains("quoted"));
}

#[test]
fn import_with_numeric_binding_is_invalid_identifier() {
    let err = parser()
        .parse("import 123 from 'pkg'", ParseGoal::Module)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
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
            assert!(matches!(&decl.kind, ExportKind::NamedClause(clause)
                    if clause.canonical_head() == "{ foo, bar }" && clause.source().is_none()));
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
fn mismatched_quotes_are_a_syntax_error() {
    // 'hello" is an unterminated string literal (Node: SyntaxError: Invalid
    // or unexpected token); it used to be accepted as a Raw expression.
    let error = parser()
        .parse("'hello\"", ParseGoal::Script)
        .expect_err("an unterminated string literal must not parse");
    assert!(error.message.contains("unterminated"), "{}", error.message);
}

#[test]
fn await_expression_wraps_inner_expression() {
    let tree = parser()
        .parse("await fetch", ParseGoal::Module)
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
        .parse("await 'result'", ParseGoal::Module)
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
            // The parser now fully parses binary expressions instead of falling
            // back to Expression::Raw.  "a + b * c" becomes Add(a, Mul(b, c)).
            assert!(
                matches!(&expr.expression, Expression::Binary { .. }),
                "expected Binary expression, got {:?}",
                expr.expression,
            );
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

// ---------------------------------------------------------------------------
// Assignments inside conditional branches (dayjs UMD header)
// ---------------------------------------------------------------------------

fn expression_statement(source: &str) -> Expression {
    let tree = parser()
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("{source}: {error}"));
    assert_eq!(tree.body.len(), 1, "{source}");
    let Statement::Expression(statement) = &tree.body[0] else {
        panic!("{source}: expected an expression statement");
    };
    statement.expression.clone()
}

#[test]
fn assignments_inside_conditional_branches_belong_to_the_branch() {
    // An `=` in either branch is that branch's assignment. `c ? m.x = 1 : 0`
    // used to parse as `(c ? m.x) = (1 : 0)` and `c ? 0 : m.x = 2` failed with
    // "invalid assignment target".
    let Expression::Conditional {
        consequent,
        alternate,
        ..
    } = expression_statement("c ? m.x = 1 : 0;")
    else {
        panic!("expected a conditional");
    };
    assert!(matches!(*consequent, Expression::Assignment { .. }));
    assert!(!matches!(*alternate, Expression::Raw(_)));
    let Expression::Conditional { alternate, .. } = expression_statement("c ? 0 : m.x = 2;") else {
        panic!("expected a conditional");
    };
    assert!(matches!(*alternate, Expression::Assignment { .. }));

    // dayjs's UMD header (dayjs.min.js 1.11.13), which failed at 1:1.
    expression_statement(
        "!function(t,e){\"object\"==typeof exports&&\"undefined\"!=typeof module?module.exports=e():\"function\"==typeof define&&define.amd?define(e):(t=\"undefined\"!=typeof globalThis?globalThis:t||self).dayjs=e()}(this,(function(){}));",
    );

    // An assignment whose value is a conditional is still an assignment, `??`
    // is not a conditional `?`, and a `?` inside a regex literal is not an
    // operator.
    for source in [
        "r = c ? 1 : 2;",
        "r = x ?? y ? 1 : 2;",
        "r = /a?/.test(s) ? 1 : 2;",
    ] {
        let Expression::Assignment { right, .. } = expression_statement(source) else {
            panic!("{source}: expected an assignment");
        };
        let Expression::Conditional {
            test,
            consequent,
            alternate,
        } = *right
        else {
            panic!("{source}: expected a conditional value");
        };
        for part in [&*test, &*consequent, &*alternate] {
            assert!(!matches!(part, Expression::Raw(_)), "{source}: {part:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Regex literal contents are pattern text to every splitter (lodash 4.17.21)
// ---------------------------------------------------------------------------

fn collect_raw_fragments(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(text)) = map.get("Raw") {
                out.push(text.clone());
            }
            for nested in map.values() {
                collect_raw_fragments(nested, out);
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                collect_raw_fragments(nested, out);
            }
        }
        _ => {}
    }
}

fn parse_without_raw(source: &str) -> Vec<Statement> {
    let tree = parser()
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("{source}: {error}"));
    let mut raws = Vec::new();
    collect_raw_fragments(
        &serde_json::to_value(&tree).expect("serialize tree"),
        &mut raws,
    );
    assert!(raws.is_empty(), "{source}: unparsed fragments {raws:?}");
    tree.body
}

fn regex_pattern(expression: &Expression) -> &str {
    match expression {
        Expression::RegExpLiteral { pattern, .. } => pattern,
        other => panic!("expected a regex literal, got {other:?}"),
    }
}

#[test]
fn regex_literal_contents_never_split_statements_or_operands() {
    // lodash 4.17.21's template regexes. The `'';` inside the first pattern
    // ended the `var` statement mid-literal; the remainder then failed with
    // "invalid assignment target" and lodash's whole IIFE fell back to Raw.
    let body = parse_without_raw(
        "var reEmptyStringLeading = /\\b__p \\+= '';/g,\n    reEmptyStringMiddle = /\\b(__p \\+=) '' \\+/g,\n    reEmptyStringTrailing = /(__e\\(.*?\\)|\\b__t\\)) \\+\\n'';/g;",
    );
    assert_eq!(body.len(), 1);
    let Statement::VariableDeclaration(declaration) = &body[0] else {
        panic!("expected a var declaration");
    };
    let patterns: Vec<&str> = declaration
        .declarations
        .iter()
        .map(|declarator| regex_pattern(declarator.initializer.as_ref().expect("initializer")))
        .collect();
    assert_eq!(
        patterns,
        [
            r"\b__p \+= '';",
            r"\b(__p \+=) '' \+",
            r"(__e\(.*?\)|\b__t\)) \+\n'';"
        ]
    );
    let body = parse_without_raw(
        "var reUnescapedHtml = /[&<>\"']/g, reHasUnescapedHtml = RegExp(reUnescapedHtml.source);",
    );
    let Statement::VariableDeclaration(declaration) = &body[0] else {
        panic!("expected a var declaration");
    };
    assert_eq!(declaration.declarations.len(), 2);

    // Quotes, brackets, `;`, `.`, `,`, `:`, `?`, `=>`, `{` and `)` inside a
    // pattern are pattern text to the statement, operator, member, call,
    // argument, conditional, block and for-header splitters.
    assert_eq!(parse_without_raw("a = /;/; b = 2;").len(), 2);
    for source in [
        "y = /'/.test(s) ? /\"/ : /`/;",
        "f(/,/, /a=>b/, /:/);",
        "z = g(/[)]/);",
        "z = g(/\\)/);",
        "if (/[{]/.test(s)) { t = 1; }",
        "for (i = 0; /;/.test(s) && i < 3; i++) { t = i; }",
        "o = { k: /}/ };",
    ] {
        parse_without_raw(source);
    }
    let Expression::Assignment { right, .. } = expression_statement("x = /a.b/.test(s);") else {
        panic!("expected an assignment");
    };
    let Expression::Call { callee, .. } = *right else {
        panic!("expected a call");
    };
    let Expression::Member { object, .. } = *callee else {
        panic!("expected a member callee");
    };
    assert_eq!(regex_pattern(&object), "a.b");
    let Expression::Call { arguments, .. } = expression_statement("s.replace(/[()]/g, '');") else {
        panic!("expected a call");
    };
    assert_eq!(arguments.len(), 2);
    assert_eq!(regex_pattern(&arguments[0]), "[()]");

    // A `/` after an operand still divides.
    for source in [
        "q = a / b / c;",
        "q = (a + b) / 2;",
        "q = s.length / 2 / n;",
        "q = x[0] / 2;",
    ] {
        let Expression::Assignment { right, .. } = expression_statement(source) else {
            panic!("{source}: expected an assignment");
        };
        assert!(
            matches!(
                *right,
                Expression::Binary {
                    operator: BinaryOperator::Divide,
                    ..
                }
            ),
            "{source}: {right:?}"
        );
    }
}

#[test]
fn new_with_a_parenthesised_callee_and_no_argument_list() {
    // lodash 4.17.21 `mapCacheClear`: `new (Map || ListCache)` constructs the
    // parenthesised expression's value. The `(...)` used to be read as an
    // argument list with an empty callee ("empty expression statement").
    let Expression::Assignment { right, .. } = expression_statement("x = new (Map || ListCache);")
    else {
        panic!("expected an assignment");
    };
    let Expression::New { callee, arguments } = *right else {
        panic!("expected a new expression");
    };
    assert!(arguments.is_empty());
    assert!(!matches!(*callee, Expression::Raw(_)), "{callee:?}");
    assert!(format!("{callee:?}").contains("LogicalOr"), "{callee:?}");

    // A parenthesised callee followed by an argument list keeps its arguments.
    let Expression::Assignment { right, .. } = expression_statement("x = new (a.b)(1, 2);") else {
        panic!("expected an assignment");
    };
    let Expression::New { arguments, .. } = *right else {
        panic!("expected a new expression");
    };
    assert_eq!(arguments.len(), 2);

    parse_without_raw(
        "function mapCacheClear() { this.size = 0; this.__data__ = { 'hash': new Hash, 'map': new (Map || ListCache), 'string': new Hash }; }",
    );
}

// ---------------------------------------------------------------------------
// Class fields and private names (bd-9vouw.64)
// ---------------------------------------------------------------------------

/// Private elements parse as members keyed by `Identifier("#name")` with
/// `computed: true`; `o.#x` is a computed member with that key. The early
/// errors of ES2022 15.7.1 (undeclared names, duplicates, `#constructor`),
/// 13.5.1.1 (`delete o.#x`) and a bare `#x` are parse errors.
#[test]
fn private_names_parse_as_private_members() {
    use frankenengine_engine::ast::MethodKind;
    /// Each member's key, whether it is static, and its kind.
    type Members = &'static [(&'static str, bool, MethodKind)];
    let cases: [(&str, Members); 5] = [
        (
            "class A { #x = 1; get x() { return this.#x; } }",
            &[
                ("#x", false, MethodKind::Field),
                ("x", false, MethodKind::Get),
            ],
        ),
        ("class A { #m() {} }", &[("#m", false, MethodKind::Method)]),
        (
            "class A { static #s() {} }",
            &[("#s", true, MethodKind::Method)],
        ),
        (
            "class A { y = 1; #z; }",
            &[
                ("y", false, MethodKind::Field),
                ("#z", false, MethodKind::Field),
            ],
        ),
        (
            "class A { get #v() { return 1; } set #v(x) {} static { A.k = 1; } }",
            &[
                ("#v", false, MethodKind::Get),
                ("#v", false, MethodKind::Set),
                ("static", true, MethodKind::StaticBlock),
            ],
        ),
    ];
    for (source, expected) in cases {
        let tree = parser()
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let Statement::ClassDeclaration(class) = &tree.body[0] else {
            panic!("expected a class declaration: {source}");
        };
        let members: Vec<(String, bool, MethodKind, bool)> = class
            .body
            .iter()
            .map(|member| {
                let Expression::Identifier(name) = &member.key else {
                    panic!("{source}: unexpected key {:?}", member.key);
                };
                (name.clone(), member.is_static, member.kind, member.computed)
            })
            .collect();
        let expected: Vec<(String, bool, MethodKind, bool)> = expected
            .iter()
            .map(|(name, is_static, kind)| {
                (name.to_string(), *is_static, *kind, name.starts_with('#'))
            })
            .collect();
        assert_eq!(members, expected, "{source}");
    }

    let tree = parser()
        .parse(
            "class A { #x; m(o) { return o?.#x + this.#x + (#x in o); } }",
            ParseGoal::Script,
        )
        .expect("private member accesses parse");
    let rendered = format!("{:?}", tree.body[0]);
    assert!(!rendered.contains("Raw("), "{rendered}");
    assert!(
        rendered.contains("OptionalMember") && rendered.contains("Identifier(\"#x\")"),
        "{rendered}"
    );

    for (source, message) in [
        ("class A { m() { return this.#y; } }", "must be declared"),
        ("this.#x;", "must be declared"),
        ("class A { #x; #x; }", "declared more than once"),
        ("class A { #x; #x() {} }", "declared more than once"),
        (
            "class A { get #x() {} static set #x(v) {} }",
            "declared more than once",
        ),
        ("class A { #constructor() {} }", "#constructor"),
        (
            "class A { #x; m() { delete this.#x; } }",
            "can not be deleted",
        ),
        (
            "class A extends B { #x; m() { return super.#x; } }",
            "super",
        ),
        ("class A { #x; m() { return #x; } }", "only valid"),
        ("class A { #x; m() { this.# x; } }", "invalid private name"),
        // ES2022 15.7.1 ClassStaticBlockBody early errors.
        ("class A { static { return; } }", "`return`"),
        ("class A { static { arguments; } }", "`arguments`"),
        (
            "label: while (false) { class C { static { break; } } }",
            "`break`",
        ),
        (
            "label: while (false) { class C { static { continue label; } } }",
            "`continue`",
        ),
    ] {
        let error = parser().parse(source, ParseGoal::Script).expect_err(source);
        assert!(
            error.message.contains(message),
            "{source}: {}",
            error.message
        );
    }
    for source in [
        "class A { static { for (;;) { break; } } }",
        "class A { static { x: { break x; } } }",
        "class A { static { function f() { return arguments; } } }",
    ] {
        parser()
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
    }

    // An inner class reads the private names of the class around it.
    parser()
        .parse(
            "class A { #x = 1; m() { return class { n(o) { return o.#x; } }; } }",
            ParseGoal::Script,
        )
        .expect("an enclosing class's private name is in scope");

    // Methods, accessors, default parameters, string and computed keys and
    // stray `;` separators still parse, with every member kept.
    let tree = parser()
        .parse(
            "class B { constructor(a = 1) { this.a = a; }; get v() { return 1; } set v(x) {}; static s() {} 'q'() {} [k](y) {} async m() {} *g() {} }",
            ParseGoal::Script,
        )
        .expect("a methods-only class parses");
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("expected a class declaration");
    };
    assert_eq!(class.body.len(), 8);
}

/// ES2022 public fields become `MethodKind::Field` members in source order,
/// including fields separated only by line breaks (ASI), a field named `get`,
/// arrow initializers whose body contains `}`, and an initializer continued
/// after an object literal. A derived class with instance fields and no
/// constructor gets the implicit `constructor(...args) { super(...args); }`.
#[test]
fn public_class_fields_parse_as_field_members() {
    use frankenengine_engine::ast::MethodKind;
    let cases: [(&str, &[(&str, bool)]); 8] = [
        ("class A { y = 2; }", &[("y", false)]),
        (
            "class A { y = 2; m() { return 1; } }",
            &[("y", false), ("m", false)],
        ),
        ("class A { static s = 3; }", &[("s", true)]),
        ("class A { x }", &[("x", false)]),
        (
            "class A { a = 1\n b = 2\n m() {}\n static c }",
            &[("a", false), ("b", false), ("m", false), ("c", true)],
        ),
        (
            "class A { handler = () => { return 1; }; }",
            &[("handler", false)],
        ),
        (
            "class A { 'q' = 1; get = 1; o = { v: 1 }.v; }",
            &[("q", false), ("get", false), ("o", false)],
        ),
        (
            "class A { t = cond\n ? 1\n : 2\n u = a\n .b }",
            &[("t", false), ("u", false)],
        ),
    ];
    for (source, expected) in cases {
        let tree = parser()
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let Statement::ClassDeclaration(class) = &tree.body[0] else {
            panic!("expected a class declaration: {source}");
        };
        let members: Vec<(String, bool, bool)> = class
            .body
            .iter()
            .map(|member| {
                let name = match &member.key {
                    Expression::Identifier(name) => name.clone(),
                    Expression::StringLiteral(name) => name.to_string(),
                    other => format!("{other:?}"),
                };
                (name, member.is_static, member.kind == MethodKind::Field)
            })
            .collect();
        assert_eq!(members.len(), expected.len(), "{source}: {members:?}");
        for ((name, is_static, _), (expected_name, expected_static)) in members.iter().zip(expected)
        {
            assert_eq!(
                (name.as_str(), *is_static),
                (*expected_name, *expected_static),
                "{source}"
            );
        }
        assert!(
            members
                .iter()
                .filter(|(name, ..)| name != "m")
                .all(|(_, _, is_field)| *is_field),
            "{source}: {members:?}"
        );
    }

    let tree = parser()
        .parse("class B extends A { x = 1; }", ParseGoal::Script)
        .expect("a derived class with a field parses");
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("expected a class declaration");
    };
    assert_eq!(class.body.len(), 2);
    assert_eq!(class.body[0].kind, MethodKind::Constructor);
    assert_eq!(class.body[1].kind, MethodKind::Field);

    for source in [
        "class A { constructor = 1; }",
        "class A { 'constructor'; }",
        "class A { static prototype = 1; }",
    ] {
        parser().parse(source, ParseGoal::Script).expect_err(source);
    }
}

#[test]
fn for_header_with_a_fourth_part_is_a_parse_error() {
    // Test262 S12.6.3_A7.1_T1: `for(a; b; c; d)` is an early SyntaxError. The
    // fourth part used to stay in the update clause, which became an
    // expression that threw only when the loop ran.
    for source in [
        "for(var index=0; index<10; index++; index--);",
        "for (;;;) {}",
    ] {
        let err = parser().parse(source, ParseGoal::Script).unwrap_err();
        assert_eq!(err.code, ParseErrorCode::InvalidSyntax, "{source}");
    }
    // A `;` nested in the update clause is not a fourth part.
    parser()
        .parse(
            "for (var i = 0; i < 1; (() => { i++; })()) {}",
            ParseGoal::Script,
        )
        .expect("nested `;` in the update clause");
}
