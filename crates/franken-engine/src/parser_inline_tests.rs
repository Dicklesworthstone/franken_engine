use std::collections::BTreeSet;
use std::io::Cursor;

use super::*;

#[test]
fn native_runtime_source_ranges_preserve_public_policy_and_parse_budgets() {
    fn method_source(tree: &SyntaxTree) -> Option<&str> {
        tree.body.iter().find_map(|statement| {
            let Statement::VariableDeclaration(declaration) = statement else {
                return None;
            };
            declaration.declarations.iter().find_map(|declarator| {
                let Some(Expression::ObjectLiteral(properties)) = &declarator.initializer else {
                    return None;
                };
                let Expression::Function { source_text, .. } = &properties[0].value else {
                    return None;
                };
                source_text.as_ref().map(FunctionSourceText::as_str)
            })
        })
    }
    let source = "const prefix = '😀'; const o = { closed() { /*é*/ return this.state; } };";
    let input = || ParserSource {
        label: "franken:metadata-probe".into(),
        text: source.into(),
    };
    let options = ParserOptions::default();
    let legacy = CanonicalEs2020Parser
        .parse_with_options(input(), ParseGoal::Script, &options)
        .unwrap();
    let runtime = CanonicalEs2020Parser
        .parse_native_runtime_with_function_sources(input(), ParseGoal::Script, &options)
        .unwrap();
    assert!(method_source(&legacy).is_none());
    assert_eq!(
        method_source(&runtime),
        Some("closed() { /*é*/ return this.state; }")
    );
    assert_eq!(legacy.canonical_value(), runtime.canonical_value());
    for source_limit in [true, false] {
        let mut options = ParserOptions::default();
        if source_limit {
            options.budget.max_source_bytes = source.len() as u64 - 1;
        } else {
            options.budget.max_token_count = 0;
        }
        let legacy = CanonicalEs2020Parser
            .parse_with_options(input(), ParseGoal::Script, &options)
            .unwrap_err();
        let runtime = CanonicalEs2020Parser
            .parse_native_runtime_with_function_sources(input(), ParseGoal::Script, &options)
            .unwrap_err();
        assert_eq!(legacy, runtime);
        assert_eq!(runtime.source_label, "franken:metadata-probe");
    }
}

#[test]
fn function_parameters_reject_only_body_lexical_redeclarations() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "function f(x) { let x; }",
        "(function(x) { const x = 1; });",
        "(x) => { class x {} };",
        "async function f({x}) { let x; }",
        "function* f([x]) { const x = 1; }",
        "({ method(x) { let x; } });",
        "class C { method(x) { let x; } }",
        "(function(exports, require, module, __filename, __dirname) { const module = 42; });",
    ] {
        let error = parser.parse(source, ParseGoal::Script).expect_err(source);
        assert_eq!(
            error.code,
            ParseErrorCode::InvalidSyntax,
            "{source}: {error:?}"
        );
        assert!(
            error.message.contains("redeclares a function parameter"),
            "{source}: {error:?}"
        );
    }
    for source in [
        "function f(x) { var x; }",
        "function f(x) { function x() {} }",
        "function f(x) { { let x; } }",
        "(x) => { { const x = 1; } };",
        "function f(x) { function g() { let x; } }",
        "function f({x}) { let y; }",
        "class C { method(x) { { let x; } } }",
        "(function(exports, require, module, __filename, __dirname) { module.exports = 42; return; });",
    ] {
        parser.parse(source, ParseGoal::Script).expect(source);
    }
}

#[test]
fn template_quasi_cooks_surrogate_pair_escapes_into_code_point() {
    // `\uD83D\uDE00` is the pre-ES6 spelling of U+1F600; adjacent high
    // and low surrogate escapes cook to one code point (bd-k9jb0), in
    // any escape spelling, with surrounding text preserved.
    let emoji = Some(JsString::from("\u{1F600}"));
    for raw in [
        r"\uD83D\uDE00",
        r"\uD83D\u{DE00}",
        r"\u{D83D}\uDE00",
        r"\u{D83D}\u{DE00}",
        r"\u{1F600}",
    ] {
        assert_eq!(cook_template_quasi(raw), emoji, "{raw}");
    }
    assert_eq!(
        cook_template_quasi(r"a\uD83D\uDE00b"),
        Some(JsString::from("a\u{1F600}b"))
    );
}

#[test]
fn template_quasi_keeps_lone_surrogate_escapes_as_code_units() {
    // A lone surrogate escape is one code unit of the string value, as
    // in Node (`\`\uD83D\``.length === 1). The UTF-8 cooker this
    // replaces could not represent one and failed.
    assert_eq!(
        cook_template_quasi(r"\uD83D"),
        Some(JsString::from_code_units(&[0xD83D]))
    );
    assert_eq!(
        cook_template_quasi(r"\uDE00\uD83Dx"),
        Some(JsString::from_code_units(&[
            0xDE00,
            0xD83D,
            u16::from(b'x')
        ]))
    );
}

#[test]
fn template_quasi_cooks_escapes_continuations_and_line_ends() {
    let cooked = |raw: &str| cook_template_quasi(raw).map(|value| value.to_string());
    assert_eq!(cooked(r"a\nb\tc").as_deref(), Some("a\nb\tc"));
    // One backslash from `\\`; `\[`, `\$`, `\`` are the character.
    assert_eq!(cooked(r"a\\[b\$\`").as_deref(), Some("a\\[b$`"));
    assert_eq!(cooked(r"\x41\u0042\u{43}\0").as_deref(), Some("ABC\0"));
    // A backslash before a line terminator contributes nothing.
    assert_eq!(cooked("x\\\ny").as_deref(), Some("xy"));
    assert_eq!(cooked("x\\\r\ny").as_deref(), Some("xy"));
    assert_eq!(cooked("x\\\u{2028}y").as_deref(), Some("xy"));
    // A literal CR LF or CR is LF in the template value.
    assert_eq!(cooked("x\r\ny\rz").as_deref(), Some("x\ny\nz"));
    // NotEscapeSequence shapes do not cook.
    assert_eq!(cooked(r"\1"), None);
    assert_eq!(cooked(r"\01"), None);
    assert_eq!(cooked(r"\xZ1"), None);
    assert_eq!(cooked(r"\u{110000}"), None);
}

#[test]
fn parsed_string_literal_cooks_surrogate_pair_escapes() {
    // End-to-end through the parser: the literal's cooked value is U+1F600.
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"const s = "\uD83D\uDE00";"#, ParseGoal::Script)
        .expect("surrogate-pair string literal should parse");
    let rendered = format!("{tree:?}");
    assert!(
        rendered.contains('\u{1F600}'),
        "cooked literal should contain U+1F600, got: {rendered}"
    );
}

#[test]
fn script_goal_rejects_import_declaration() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("import x from 'mod';", ParseGoal::Script)
        .expect_err("script goal should reject import");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
}

/// bd-rucba (franken-core bd-47ae4 twin): a within-budget deep chain must
/// parse regardless of the caller's stack size, because parsing now runs on
/// a stack provisioned from the recursion budget rather than the OS default.
#[test]
fn nested_if_parses_from_a_tiny_caller_stack_bd_rucba() {
    // 64 nested `if` statements recurse through parse_statement 64 deep,
    // within the default budget (256) but enough to overflow a small caller
    // stack without the provisioned parse thread.
    let depth = 64usize;
    let source = format!("{}x;", "if (true) ".repeat(depth));
    let handle = std::thread::Builder::new()
        .name("bd-rucba-tiny-caller".to_string())
        .stack_size(256 * 1024)
        .spawn(move || {
            CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Script)
                .is_ok()
        })
        .expect("tiny caller thread should spawn");
    assert!(
        handle.join().expect("caller thread must not abort"),
        "a within-budget nesting must parse regardless of caller stack"
    );
}

/// bd-rucba: nesting beyond a tight recursion budget must fail closed with
/// the recoverable budget error, never a native stack abort.
#[test]
fn tight_statement_nesting_budget_fails_closed_not_abort_bd_rucba() {
    let depth = 16usize;
    let source = format!("{}x;", "if (true) ".repeat(depth));
    let options = ParserOptions {
        budget: ParserBudget {
            max_recursion_depth: 8,
            ..ParserBudget::default()
        },
        ..ParserOptions::default()
    };
    let error = CanonicalEs2020Parser
        .parse_with_options(source.as_str(), ParseGoal::Script, &options)
        .expect_err("nesting beyond the tight budget must be rejected");
    assert_eq!(error.code, ParseErrorCode::BudgetExceeded);
    assert!(
        error.message.contains("statement nesting budget exceeded"),
        "unexpected rejection: {}",
        error.message
    );
}

#[test]
fn parser_accepts_stream_inputs() {
    let parser = CanonicalEs2020Parser;
    let input = StreamInput::new(Cursor::new("x;\n42;\n"), "stdin");
    let tree = parser
        .parse(input, ParseGoal::Script)
        .expect("stream parse should succeed");
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn canonical_ast_bytes_are_stable_for_identical_input() {
    let parser = CanonicalEs2020Parser;
    let source = "typeof work";
    let left = parser.parse(source, ParseGoal::Script).expect("left parse");
    let right = parser
        .parse(source, ParseGoal::Script)
        .expect("right parse");
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    assert_eq!(left.canonical_hash(), right.canonical_hash());
}

#[test]
fn equivalent_whitespace_keeps_expression_shape() {
    let parser = CanonicalEs2020Parser;
    let left = parser
        .parse("typeof   work", ParseGoal::Script)
        .expect("left parse");
    let right = parser
        .parse("typeof work", ParseGoal::Script)
        .expect("right parse");

    let left_expr = match &left.body[0] {
        Statement::Expression(expr) => &expr.expression,
        // SAFETY: Test validates parsed statement is expression type
        _ => panic!("expected expression statement"),
    };
    let right_expr = match &right.body[0] {
        Statement::Expression(expr) => &expr.expression,
        // SAFETY: Test validates parsed statement is expression type
        _ => panic!("expected expression statement"),
    };
    assert_eq!(left_expr.canonical_value(), right_expr.canonical_value());
}

#[test]
fn module_import_forms_are_supported() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "import dep from \"pkg\";\nimport \"side-effect\";\nexport default dep;",
            ParseGoal::Module,
        )
        .expect("module parse should succeed");
    assert_eq!(tree.body.len(), 3);
}

// -----------------------------------------------------------------------
// Empty / whitespace-only source
// -----------------------------------------------------------------------

#[test]
fn empty_source_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("", ParseGoal::Script)
        .expect_err("empty source must fail");
    assert_eq!(err.code, ParseErrorCode::EmptySource);
}

#[test]
fn whitespace_only_source_is_rejected() {
    let parser = CanonicalEs2020Parser;
    for ws in ["  ", "\t\t", "\n\n", "  \n  \t  "] {
        let err = parser
            .parse(ws, ParseGoal::Script)
            .expect_err("whitespace-only source must fail");
        assert_eq!(err.code, ParseErrorCode::EmptySource);
    }
}

// -----------------------------------------------------------------------
// Script goal rejects export
// -----------------------------------------------------------------------

#[test]
fn script_goal_rejects_export_declaration() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export default 42", ParseGoal::Script)
        .expect_err("script goal should reject export");
    assert_eq!(err.code, ParseErrorCode::InvalidGoal);
}

// -----------------------------------------------------------------------
// Expression parsing
// -----------------------------------------------------------------------

#[test]
fn numeric_literal_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    assert_eq!(tree.body.len(), 1);
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::NumericLiteral(42));
        }
        // SAFETY: Test validates parsed statement is expression type for numeric literal
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn negative_numeric_literal_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("-7", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => match &expr.expression {
            Expression::NumericLiteral(v) => assert_eq!(*v, -7),
            _ => panic!("expected numeric expression for -7"),
        },
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn signed_zero_literals_preserve_the_number_sign_bit() {
    for source in ["-0", "-0x0", "-0o0", "-0b0", "-0.0", "-0e0"] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap();
        let Statement::Expression(statement) = &tree.body[0] else {
            panic!("expected expression for {source}");
        };
        assert_eq!(
            statement.expression,
            Expression::FloatLiteral((-0.0_f64).to_bits()),
            "lost the sign of {source}"
        );
    }
}

#[test]
fn string_literal_single_quotes_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("'hello'", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::StringLiteral("hello".into()));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn string_literal_double_quotes_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("\"world\"", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::StringLiteral("world".into()));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn string_literal_surrogate_escapes_preserve_exact_utf16_bd_vltnh() {
    let cases: [(&str, &[u16], bool); 5] = [
        (r#""\uD800""#, &[0xD800], false),
        (r"'\uDC00'", &[0xDC00], false),
        (r#""\u{D800}""#, &[0xD800], false),
        (r#""a\uD800b""#, &[0x0061, 0xD800, 0x0062], false),
        (r#""\uD83D\uDE00""#, &[0xD83D, 0xDE00], true),
    ];

    for (source, expected_units, expected_well_formed) in cases {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
        let Statement::Expression(expression) = &tree.body[0] else {
            panic!("{source:?} should be an expression statement");
        };
        let Expression::StringLiteral(value) = &expression.expression else {
            panic!("{source:?} should produce a string literal");
        };
        assert_eq!(value.code_units_vec(), expected_units, "{source:?}");
        assert_eq!(value.is_well_formed(), expected_well_formed, "{source:?}");
    }
}

#[test]
fn string_literal_ordinary_escapes_are_cooked_bd_vltnh() {
    for (source, expected) in [
        (r#""\n\t\r\b\f\v\0""#, "\n\t\r\u{0008}\u{000C}\u{000B}\0"),
        (r#""\x41\u0042\u{43}""#, "ABC"),
        (r#""\q""#, "q"),
        (r#""\"""#, "\""),
    ] {
        let value = parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
            .unwrap_or_else(|| panic!("{source:?} should cook"));
        assert_eq!(value, expected, "{source:?}");
        assert!(value.is_well_formed(), "{source:?}");
    }
}

#[test]
fn string_literal_line_continuations_and_astral_escape_bd_vltnh() {
    for source in [
        "\"a\\\nb\"",
        "\"a\\\rb\"",
        "\"a\\\r\nb\"",
        "\"a\\\u{2028}b\"",
        "\"a\\\u{2029}b\"",
    ] {
        let value = parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
            .unwrap_or_else(|| panic!("{source:?} should cook"));
        assert_eq!(value, "ab", "{source:?}");
    }

    for (source, expected) in [
        ("\"a\u{2028}b\"", "a\u{2028}b"),
        ("\"a\u{2029}b\"", "a\u{2029}b"),
    ] {
        assert_eq!(
            parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
                .unwrap_or_else(|| panic!("{source:?} should cook")),
            expected,
            "{source:?}"
        );
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
        assert!(matches!(
            first_expr(&tree),
            Expression::StringLiteral(value) if value == expected
        ));
    }

    assert_eq!(
        parse_quoted_expression_string(r#""\u{1F600}""#, LegacyDecimalEscapeMode::Reject,)
            .expect("braced astral escape should cook")
            .code_units_vec(),
        [0xD83D, 0xDE00]
    );
    assert_eq!(
        parse_quoted_expression_string("\"\\uD83D\\\n\\uDE00\"", LegacyDecimalEscapeMode::Reject,)
            .expect("continuation may separate surrogate escapes")
            .code_units_vec(),
        [0xD83D, 0xDE00]
    );

    for source in ["\"a\\\nb\"", "\"a\\\rb\"", "\"a\\\r\nb\""] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
        assert!(matches!(
            first_expr(&tree),
            Expression::StringLiteral(value) if value == "ab"
        ));
    }

    let nul_then_digit = CanonicalEs2020Parser
        .parse("\"\\0\\\n8\"", ParseGoal::Script)
        .expect("line continuation after NUL escape must reset decimal lookahead");
    assert!(matches!(
        first_expr(&nul_then_digit),
        Expression::StringLiteral(value) if value.code_units_vec() == [0x0000, 0x0038]
    ));

    // A SyntaxError, as in Node (bd-9vouw.444), not a refusal.
    for source in ["\"a\nb\"", "\"a\rb\"", "\"a\r\nb\""] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err("raw LF/CRLF in a quoted literal must fail closed");
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source:?}");
    }
}

#[test]
fn quoted_and_template_continuations_keep_physical_positions_bd_21nbg() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let quoted_source = format!("\"a\\{terminator}b\"");
        let quoted_tree = parser
            .parse(quoted_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {quoted_source:?}: {error}"));
        assert!(matches!(
            first_expr(&quoted_tree),
            Expression::StringLiteral(value) if value == "ab"
        ));

        let template_source = format!("let value = `a\\{terminator}b`;{terminator}after;");
        let template_tree = parser
            .parse(template_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {template_source:?}: {error}"));
        assert_eq!(template_tree.body.len(), 2, "{template_source:?}");
        let Statement::VariableDeclaration(declaration) = &template_tree.body[0] else {
            panic!("expected template declaration for {template_source:?}");
        };
        let Some(Expression::TemplateLiteral { quasis, .. }) =
            declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected template initializer for {template_source:?}");
        };
        assert_eq!(quasis.len(), 1, "{template_source:?}");
        assert_eq!(
            quasis[0],
            format!("a\\{terminator}b"),
            "template raw quasi must retain {terminator:?}"
        );
        assert_eq!(
            template_tree.body[1].span().start_line,
            3,
            "{template_source:?}"
        );
        assert_eq!(
            template_tree.body[1].span().start_column,
            1,
            "{template_source:?}"
        );
        assert_eq!(
            template_tree.body[1].span().start_offset,
            template_source.find("after").expect("after is present") as u64,
            "{template_source:?}"
        );
    }
}

#[test]
fn malformed_quoted_expression_literals_fail_closed_bd_vltnh() {
    for source in [
        "\"unterminated",
        "\"trailing\\",
        r#""\x""#,
        r#""\xZZ""#,
        r#""\u""#,
        r#""\u12""#,
        r#""\u{}""#,
        r#""\u{110000}""#,
        r#""a"b""#,
        "\"\\u\\\n0041\"",
        "\"\\x\\\n41\"",
        "\"\\u{4\\\n1}\"",
    ] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed quoted source must fail closed");
        // A SyntaxError, as in Node (bd-9vouw.444), not a refusal.
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source:?}");
    }
}

// Node 20.19.4 matches these Annex-B values and strict failures. Bun
// 1.3.14's CLI parser currently diverges by rejecting sloppy octal while
// accepting strict `\8`/`\9`; this parser follows ECMA-262 and Node.
#[test]
fn legacy_decimal_escapes_follow_annex_b_in_sloppy_scripts_bd_xcqzp() {
    let parser = CanonicalEs2020Parser;
    for (source, expected_units) in [
        (r#""\1""#, &[0x0001][..]),
        (r#""\8""#, &[0x0038][..]),
        (r#""\9""#, &[0x0039][..]),
        (r#""\08""#, &[0x0000, 0x0038][..]),
        (r#""\18""#, &[0x0001, 0x0038][..]),
        (r#""\118""#, &[0x0009, 0x0038][..]),
        (r#""\377""#, &[0x00FF][..]),
        (r#""\400""#, &[0x0020, 0x0030][..]),
        (r#""\478""#, &[0x0027, 0x0038][..]),
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("sloppy {source:?} should parse: {error}"));
        assert!(matches!(
            first_expr(&tree),
            Expression::StringLiteral(value)
                if value.code_units_vec() == expected_units
        ));
    }

    let postfix = parser
        .parse(r#""\1".length"#, ParseGoal::Script)
        .expect("a sloppy legacy escape may be a postfix receiver");
    assert!(matches!(
        first_expr(&postfix),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::StringLiteral(value)
                if value.code_units_vec() == [0x0001])
    ));

    for source in [
        r#"let value = "\118";"#,
        r#"({"\1": value});"#,
        r#"let {"\1": value} = source;"#,
        r#"({ "\1"() {} });"#,
        r#""use\x20strict"; "\1";"#,
        r#""not a directive" + suffix; "use strict"; "\1";"#,
        r#"{ "use strict"; "\1"; }"#,
        r#"; "use strict"; "\1";"#,
        "\"use strict\"\n+suffix; \"\\1\";",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("sloppy context should accept {source:?}: {error}"));
    }
}

#[test]
fn strict_and_module_code_reject_legacy_decimal_escapes_bd_xcqzp() {
    let parser = CanonicalEs2020Parser;
    for source in [
        r#""use strict"; "\1";"#,
        r#""prologue"; "use strict"; "\8";"#,
        r#""\1"; "use strict";"#,
        r#""use strict"; ({"\1": value});"#,
        r#""use strict"; let {"\1": value} = source;"#,
        r#""use strict"; ({ "\1"() {} });"#,
        r#"function f() { "prologue"; "use strict"; return "\1"; }"#,
        r#""use strict"; function f() { return "\1"; }"#,
        r#"const f = () => { "use strict"; return "\1"; };"#,
        r#"class C { method() { return "\1"; } }"#,
        r#"function f(value = "\1") { "use strict"; }"#,
        r#"const f = (value = "\1") => { "use strict"; };"#,
        r#"class C { method(value = "\1") {} }"#,
        r#"class C { "\1"() {} }"#,
        r#"class C { ["\1"]() {} }"#,
        r#"class C extends ("\1") {}"#,
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("strict Script code must reject legacy decimal escapes");
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source:?}");
    }

    parser
        .parse(r#"class C { "ok"() {} }"#, ParseGoal::Script)
        .expect("an ordinary quoted class method name remains valid");
    parser
        .parse(r#"class C { ["ok"]() {} }"#, ParseGoal::Script)
        .expect("an ordinary computed class method name remains valid");

    for source in [
        r#""\1";"#,
        r#""\8";"#,
        r#""\9";"#,
        r#""\08";"#,
        r#"let {"\1": value} = source;"#,
    ] {
        let error = parser
            .parse(source, ParseGoal::Module)
            .expect_err("Module code is strict and must reject legacy decimal escapes");
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source:?}");
    }

    parser
        .parse(r#""use strict"; "\0";"#, ParseGoal::Script)
        .expect("plain NUL escapes remain valid in strict Script code");
    parser
        .parse(r#""\0";"#, ParseGoal::Module)
        .expect("plain NUL escapes remain valid in Module code");
}

#[test]
fn quoted_expression_postfix_base_uses_exact_cooker_bd_vltnh() {
    let tree = CanonicalEs2020Parser
        .parse(r#""\uD800".length"#, ParseGoal::Script)
        .expect("exact quoted literal may be a postfix base");
    assert!(matches!(
        first_expr(&tree),
        Expression::Member { object, property, computed: false, .. }
            if matches!(object.as_ref(), Expression::StringLiteral(value)
                if value.code_units_vec() == [0xD800])
                && matches!(property.as_ref(), Expression::Identifier(name)
                    if name == "length")
    ));

    for source in [r#""\xZZ".length"#, r#""a"b".length"#, r#""a"."#, r#""a"["#] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed quoted postfix source must fail closed");
        // A SyntaxError, as in Node (bd-9vouw.444), not a refusal.
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source:?}");
    }
}

#[test]
fn exact_module_string_wrapper_preserves_lone_units_bd_lfq44() {
    assert_eq!(
        parse_quoted_string(r#""\uD800""#)
            .expect("high surrogate should remain representable")
            .code_units_vec(),
        [0xD800]
    );
    assert_eq!(
        parse_quoted_string(r"'\uDC00'")
            .expect("low surrogate should remain representable")
            .code_units_vec(),
        [0xDC00]
    );
    assert_eq!(
        parse_quoted_string(r#""\uD83D\uDE00""#)
            .and_then(|value| value.as_str().map(str::to_string)),
        Some("😀".to_string()),
    );
}

#[test]
fn identifier_expression_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("foo", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::Identifier("foo".to_string()));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn underscore_prefix_is_valid_identifier() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("_private", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(
                expr.expression,
                Expression::Identifier("_private".to_string())
            );
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn dollar_prefix_is_valid_identifier() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("$elem", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::Identifier("$elem".to_string()));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn await_expression_parsed_in_module_goal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("await fetch", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => match &expr.expression {
            Expression::Await(inner) => {
                assert_eq!(**inner, Expression::Identifier("fetch".to_string()));
            }
            _ => panic!("expected await expression"),
        },
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn await_expression_parsed_inside_async_function() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "async function f() { return await fetch; }",
            ParseGoal::Script,
        )
        .expect("parse");
    match &tree.body[0] {
        Statement::FunctionDeclaration(f) => {
            assert!(f.is_async);
            let body = &f.body.body;
            assert_eq!(body.len(), 1);
            let Statement::Return(ret) = &body[0] else {
                panic!("expected return statement");
            };
            let Some(argument) = ret.argument.as_ref() else {
                panic!("expected return argument");
            };
            let Expression::Await(inner) = argument else {
                panic!("expected await expression");
            };
            assert_eq!(**inner, Expression::Identifier("fetch".to_string()));
        }
        _ => panic!("expected function declaration"),
    }
}

#[test]
fn top_level_await_rejected_in_script_goal() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("await fetch", ParseGoal::Script)
        .expect_err("script goal must reject top-level await");
    assert_eq!(err.code, ParseErrorCode::AwaitOutsideAsync);
}

#[test]
fn await_rejected_inside_non_async_function() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("function f() { return await fetch; }", ParseGoal::Script)
        .expect_err("non-async function must reject await");
    assert_eq!(err.code, ParseErrorCode::AwaitOutsideAsync);
}

#[test]
fn boolean_literal_true_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("true", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::BooleanLiteral(true));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn boolean_literal_false_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("false", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::BooleanLiteral(false));
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn null_literal_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("null", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(expr.expression, Expression::NullLiteral);
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn global_value_names_are_identifier_references() {
    let parser = CanonicalEs2020Parser;
    for (source, name) in [
        ("undefined", "undefined"),
        ("NaN", "NaN"),
        ("Infinity", "Infinity"),
        (r"undef\u0069ned", "undefined"),
    ] {
        let tree = parser.parse(source, ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::Identifier(name.to_string()));
            }
            _ => panic!("expected expression statement"),
        }
    }
}

#[test]
fn complex_expression_parses_as_binary() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("a + b * c", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert!(
                matches!(&expr.expression, Expression::Binary { .. }),
                "expected binary expression, got {:?}",
                expr.expression
            );
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn function_declaration_surface_in_script_goal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function foo() {}", ParseGoal::Script)
        .expect("parse");
    match &tree.body[0] {
        Statement::FunctionDeclaration(func) => {
            assert_eq!(func.name.as_deref(), Some("foo"));
        }
        _ => panic!("expected function declaration"),
    }
}

#[test]
fn function_declaration_surface_in_module_goal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function foo() {}", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::FunctionDeclaration(func) => {
            assert_eq!(func.name.as_deref(), Some("foo"));
        }
        _ => panic!("expected function declaration"),
    }
}

// -----------------------------------------------------------------------
// Variable declaration parsing
// -----------------------------------------------------------------------

#[test]
fn var_declaration_with_initializer_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var counter = 1", ParseGoal::Script)
        .expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(variable_declaration) => {
            assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
            assert_eq!(variable_declaration.declarations.len(), 1);
            let declarator = &variable_declaration.declarations[0];
            assert_eq!(declarator.name(), Some("counter"));
            assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(1)));
        }
        _ => panic!("expected variable declaration statement"),
    }
}

#[test]
fn var_declaration_without_initializer_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("var ready", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(variable_declaration) => {
            assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
            assert_eq!(variable_declaration.declarations.len(), 1);
            let declarator = &variable_declaration.declarations[0];
            assert_eq!(declarator.name(), Some("ready"));
            assert_eq!(declarator.initializer, None);
        }
        _ => panic!("expected variable declaration statement"),
    }
}

#[test]
fn var_declaration_with_multiple_declarators_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var first = \"a,b\", second = 2", ParseGoal::Script)
        .expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(variable_declaration) => {
            assert_eq!(variable_declaration.declarations.len(), 2);
            let first = &variable_declaration.declarations[0];
            assert_eq!(first.name(), Some("first"));
            assert_eq!(
                first.initializer,
                Some(Expression::StringLiteral("a,b".into()))
            );
            let second = &variable_declaration.declarations[1];
            assert_eq!(second.name(), Some("second"));
            assert_eq!(second.initializer, Some(Expression::NumericLiteral(2)));
        }
        _ => panic!("expected variable declaration statement"),
    }
}

#[test]
fn let_declaration_with_initializer_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let counter = 1", ParseGoal::Script)
        .expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(variable_declaration) => {
            assert_eq!(variable_declaration.kind, VariableDeclarationKind::Let);
            assert_eq!(variable_declaration.declarations.len(), 1);
            let declarator = &variable_declaration.declarations[0];
            assert_eq!(declarator.name(), Some("counter"));
            assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(1)));
        }
        _ => panic!("expected variable declaration statement"),
    }
}

#[test]
fn const_declaration_with_initializer_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const answer = 42", ParseGoal::Script)
        .expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(variable_declaration) => {
            assert_eq!(variable_declaration.kind, VariableDeclarationKind::Const);
            assert_eq!(variable_declaration.declarations.len(), 1);
            let declarator = &variable_declaration.declarations[0];
            assert_eq!(declarator.name(), Some("answer"));
            assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(42)));
        }
        _ => panic!("expected variable declaration statement"),
    }
}

#[test]
fn const_declaration_without_initializer_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const answer", ParseGoal::Script)
        .expect_err("const without initializer must fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
    assert!(
        err.message
            .contains("const declarations must include an initializer")
    );
}

#[test]
fn var_declaration_missing_binding_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var", ParseGoal::Script)
        .expect_err("var without binding must fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

// bd-wa01t: parser must fail-closed on these three classes of syntactically
// invalid source instead of accepting them as `Expression::Raw` /
// `BindingPattern::Identifier`. Each input was surfaced by the
// parser_error_taxonomy_conformance harness.

#[test]
fn unterminated_string_literal_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var x = \"unterminated", ParseGoal::Script)
        .expect_err("unterminated string literal must fail-closed");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn stray_binary_operator_is_rejected() {
    let parser = CanonicalEs2020Parser;
    for source in ["* 5", "% 2", "& 1", "| 1", "^ 1", "< 1", "> 1", "?? null"] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must fail-closed"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`",
        );
    }
}

// bd-9vouw.444: shapes no expression has are SyntaxErrors before the
// source runs, not `Expression::Raw` that throws only when evaluated: a
// regular expression literal broken by a line terminator, a leading `.`
// member access, an escape or character outside a literal that is no
// identifier character, an escaped `async` keyword.
#[test]
fn unrecognised_expressions_of_no_expression_shape_are_early_errors() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "/\n/",
        "/\r/",
        "/\u{2028}/",
        "/\u{2029}/",
        "/a\\\n/",
        "x;\n/\n/;",
        "x;\n.source;",
        "._",
        "var\\u0020x;",
        "var\\u000Ax;",
        "\\u003B;",
        "this\\u002Ex;",
        "\\u007B\\u007D",
        "var\u{180e}foo;",
        "\\u0061sync function f() {}",
        "\\u0061sync () => {}",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "var re = /[/]/g;\nre.test('a/b');",
        "var half = .5;",
        "var \\u{61}b = 1;\n\\u{61}b;",
        "var a = [1];\na\n  .map(String);",
        "var s = 'line\\\nbreak';",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.446: a C-style for header's initializer is [~In], a header
// with two top-level `;` is never a for-in, and a for-in/of target has no
// initializer outside Annex B's sloppy `var` head.
#[test]
fn for_headers_reject_bare_in_initializers_and_target_initializers() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "for (a in arr;1;) { break; }",
        "for (var a in arr;1;) { break; }",
        "for (1 in arr;1;) { break; }",
        "for ('' in {} ? 0 : 0; false; ) ;",
        "for (true ? 0 : 0 in {}; false; ) ;",
        "var a; for (a = 0 in {});",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "for (true ? '' in o : p; false; ) ;",
        "for (var k = ('a' in o); false;) ;",
        "for (var f = function () { return 'a' in o; }; false;) ;",
        "for (var q = {in: 1}; false;) ;",
        "for (a.in = 0; false;) ;",
        "for (var s = 'in', inner = 1; false;) ;",
        "for (var x = a ?? b; false;) ;",
        "for (var a = 0 in {});",
        "for (var k in o) ;",
        "for (; 'a' in o; ) break;",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.447: in strict code the strict-mode reserved words are no
// identifier references; sloppy code and property names keep them.
#[test]
fn strict_mode_reserved_words_are_not_references_in_strict_code() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "'use strict';\npublic = 42;",
        "function f() {\n  'use strict';\n  return interface;\n}",
        "'use strict';\nvoid {\n  get x() {\n    public = 42;\n  }\n};",
        "'use strict';\nvar n = package + 1;",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "var public = 1;\npublic = 2;",
        "'use strict';\nvar o = { public: 1 };\no.public = 2;",
        "'use strict';\nclass C { static m() { return 1; } }",
        "function f() { return private; }",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.448: `new.target` outside every function (a script's own
// code and its arrows) and an optional chain tagging a template are
// SyntaxErrors; no semicolon is inserted before a template, so a line
// starting with one continues the expression before it.
#[test]
fn new_target_outside_functions_and_optional_chain_tags_are_rejected() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "new.target;",
        "() => {\n  new.target;\n};",
        "var a = {fn() {}};\na?.fn`hello`;",
        "null?.fn\n  `hello`;",
        "var a = [];\na?.[0]`x`;",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "function f() { return new.target; }",
        "class C { constructor() { this.t = new.target; } }",
        "function f() { return () => new.target; }",
        "function f(a = new.target) { return a; }",
        "class C { x = new.target; }",
        "var a = { b: (s) => s[0] };\nvar r = (a?.b)`x`;",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
    let texts: Vec<String> = merge_logical_lines("var r = tag\n`x`;")
        .into_iter()
        .map(|line| line.text)
        .collect();
    assert_eq!(texts, ["var r = tag `x`;"]);
}

// bd-9vouw.449: a parenthesized update operand is as assignable as what
// it holds.
#[test]
fn parenthesized_update_operands_must_be_references() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "function* g() { (yield)++; }",
        "function* g() { ++(yield); }",
        "var a, b; (a + b)++;",
        "async function f() { (await 1)++; }",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "var x = 1; (x)++;",
        "var o = {p: 1}; (o.p)++; ++(o.p);",
        "function* g() { var x = 0; yield x++; }",
        "var x = 1; ((x))--;",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.450: a class field's initializer gets no semicolon before a
// `*` on the next line, nor before another element on its own line.
#[test]
fn class_field_initializers_do_not_end_before_a_star_or_on_their_line() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "class C {\n  x = 42\n  *gen() {}\n}",
        "class C {\n  x = 42\n  y = 1\n  *gen() {}\n}",
        "class C {\n  field = 1 method(){}\n}",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "class C {\n  x\n  *gen() {}\n}",
        "class C {\n  x = 42;\n  *gen() {}\n}",
        "var obj = {};\nclass C {\n  x = obj\n  ['lol'] = 42\n}",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.451: a statement keyword leading an expression, a bracketed
// operand followed by a name, and a `;` inside an expression are
// SyntaxErrors before anything runs.
#[test]
fn statement_keywords_and_unseparated_groups_are_not_expressions() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "if{};else{}",
        "try(e1){\n}\ncatch(e){}",
        "catch(){}\nfinally{}",
        "var r = [1] x;",
        "var arr = [];\nfor({index=0; index+=1;} index++<=10; index*2;) {}",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "var o = {}, a, b;\nvar t = [1] in o;",
        "var u = ({}) instanceof Object;",
        "var a, b;\nvar k = (a, b);",
        "var o = {};\nvar w = {}\nw = 1;",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

#[test]
fn unterminated_parenthesized_expressions_are_syntax_errors() {
    let parser = CanonicalEs2020Parser;
    for goal in [ParseGoal::Script, ParseGoal::Module] {
        for source in [
            "(",
            "((",
            "(1",
            "var x = (",
            "var x = (1 + 2",
            "(/* ) */",
            "(// )\n",
            "(')'",
            r"(/\)/",
            "(`)`",
            "var effects = 1; (",
        ] {
            let err = parser.parse(source, goal).expect_err(&format!(
                "`{source}` must fail before execution in {goal:?}"
            ));
            assert_eq!(
                err.code,
                ParseErrorCode::InvalidSyntax,
                "wrong code for `{source}` in {goal:?}: {}",
                err.message
            );
        }
    }
}

#[test]
fn parenthesized_literal_delimiters_are_not_group_delimiters() {
    let parser = CanonicalEs2020Parser;
    for goal in [ParseGoal::Script, ParseGoal::Module] {
        for source in [
            "('(');",
            "(\")\");",
            r"(/\(/);",
            r"(/\)/).test(')');",
            "(`(`);",
            "(`)`);",
            "(`x${'('}`);",
            "(`x${`)`}`);",
            "(/* ( */ 1);",
            "(/* ) */ 1);",
            "(// (\n1);",
            "(1 + (2 * 3));",
            "((x) => x)(1);",
        ] {
            parser
                .parse(source, goal)
                .unwrap_or_else(|err| panic!("`{source}` must parse in {goal:?}: {}", err.message));
        }
    }
}

#[test]
fn unterminated_parentheses_fail_public_preparation_and_function_compilation() {
    for source in ["(", "var effects = 1; ("] {
        let error = crate::HybridRouter::default()
            .eval(source)
            .expect_err("invalid source must fail preparation");
        assert_eq!(error.code, crate::EvalErrorCode::ParseFailure);
        assert!(
            error
                .message
                .contains("unterminated parenthesized expression"),
            "{source}: {error}"
        );
    }
    for compile in [
        "Function('effects = 1; (')()",
        "new Function('effects = 1; (')()",
    ] {
        let source = format!(
            "var effects = 0; var caught = 0; \
             try {{ {compile}; }} catch (error) {{ \
             if (error instanceof SyntaxError && error.name === 'SyntaxError') caught = 1; \
             }} effects * 10 + caught;"
        );
        let outcome = crate::HybridRouter::default()
            .eval(&source)
            .unwrap_or_else(|err| panic!("{compile} must throw a catchable SyntaxError: {err}"));
        assert_eq!(
            outcome.value, "1",
            "{compile} must not execute invalid source"
        );
        assert_eq!(outcome.completion_type.as_deref(), Some("number"));
    }
}

#[test]
fn malformed_dynamic_source_does_not_widen_eval_authority() {
    let denied = crate::HybridRouter::default()
        .eval("eval('(');")
        .expect_err("direct eval must retain its authority check");
    assert!(denied.message.contains("runtime.eval"), "{denied}");
    for source in [
        "var effects = 0; var caught = 0; \
         try { (0, eval)('effects = 1; ('); } catch (error) { \
         if (error instanceof EvalError && error.name === 'EvalError') caught = 1; \
         } effects * 10 + caught;",
        "var effects = 0; var caught = 0; var indirect = eval; \
         try { indirect('effects = 1; ('); } catch (error) { \
         if (error instanceof EvalError && error.name === 'EvalError') caught = 1; \
         } effects * 10 + caught;",
    ] {
        let outcome = crate::HybridRouter::default()
            .eval(source)
            .expect("inert eval must throw a catchable EvalError without executing source");
        assert_eq!(outcome.value, "1");
        assert_eq!(outcome.completion_type.as_deref(), Some("number"));
    }
}

// bd-9vouw.452: `debugger` is a statement, parsed before expressions;
// as an expression it is a reserved word.
#[test]
fn debugger_is_a_statement_and_no_expression() {
    let parser = CanonicalEs2020Parser;
    for source in ["debugger;", "debugger", "if (x) debugger;", "l: debugger;"] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
        assert!(
            !format!("{tree:?}").contains("Identifier(\"debugger\")"),
            "`{source}` must not reference a variable `debugger`"
        );
    }
    let err = parser
        .parse("(debugger);", ParseGoal::Script)
        .expect_err("`(debugger)` is a SyntaxError");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax, "{}", err.message);
}

// bd-9vouw.453: an argument or sequence list has no elisions (only an
// argument list's trailing comma), and `for (async of` is excluded.
#[test]
fn list_elisions_and_for_async_of_are_rejected() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "function f() {}\nf(1,,2);",
        "function f() {}\nf(,);",
        "function F() {}\nnew F(1,,2);",
        "var async;\nfor (async of [1]) ;",
        "var x = (1,,2);",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for `{source}`: {}",
            err.message
        );
    }
    for source in [
        "function f() {}\nf(1,);",
        "function F() {}\nnew F(1,);",
        "var async;\nfor (async in {}) ;",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
    }
}

// bd-9vouw.455: `import.meta` belongs to module code, function bodies
// included; in a script it is a SyntaxError.
#[test]
fn import_meta_is_module_only() {
    let parser = CanonicalEs2020Parser;
    for source in ["import.meta;", "function f() { return import.meta.url; }"] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err(&format!("`{source}` must be a SyntaxError in a script"));
        assert_eq!(err.code, ParseErrorCode::InvalidSyntax, "{}", err.message);
        parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|err| panic!("`{source}` must parse in a module: {}", err.message));
    }
}

// bd-9vouw.457: a class field whose initializer ends a line with a
// keyword operator continues onto the next line (Test262 fields-asi-5).
#[test]
fn class_field_initializer_continues_after_a_keyword_operator_line() {
    let parser = CanonicalEs2020Parser;
    let source =
        "var x = 0, y = 1, z = [42];\nclass C {\n  a = x\n  in\n  z\n  b = y\n  in\n  z\n}";
    parser
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|err| panic!("fields-asi-5 must parse: {}", err.message));
}

// bd-9vouw.459: every ECMAScript WhiteSpace separates tokens, not only
// the ASCII ones (Test262 assignment/white-space.js and
// function/line-terminator.js).
#[test]
fn non_ascii_white_space_separates_tokens() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "var x;\nx\u{b}=\u{b}1;\nx\u{a0}=\u{a0}2;\nx\u{3000}=\u{3000}3;",
        "function\tw() {}\nw();",
        "function\t\u{2029}w(\u{c})\u{a0}{\n}\nw();",
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
        assert!(tree.body.len() >= 2, "{tree:?}");
        if source.starts_with("function") {
            assert!(
                matches!(&tree.body[0], Statement::FunctionDeclaration(f) if f.name.as_deref() == Some("w")),
                "`{source}` must declare w: {tree:?}"
            );
        }
    }
}

#[test]
fn reserved_word_as_binding_identifier_is_rejected() {
    let parser = CanonicalEs2020Parser;
    for keyword in [
        "return", "function", "class", "var", "if", "while", "for", "switch", "try",
    ] {
        let source = format!("var {keyword} = 1;");
        let err = parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect_err(&format!("`{source}` must fail-closed"));
        assert_eq!(
            err.code,
            ParseErrorCode::InvalidSyntax,
            "wrong code for keyword `{keyword}`",
        );
    }
}

#[test]
fn strict_only_reserved_words_remain_valid_in_script_mode() {
    // bd-wa01t scope guard: the fix above MUST NOT over-reject. Strict-mode
    // reserved words (`package`, `private`, `public`, `static`, …) are
    // still legal binding names in non-strict script code per ES2020.
    let parser = CanonicalEs2020Parser;
    for ident in [
        "package",
        "private",
        "public",
        "protected",
        "static",
        "implements",
        "interface",
        "let",
    ] {
        let source = format!("var {ident} = 1;");
        parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|err| {
                panic!("`{source}` should still parse in script mode, got {err:?}")
            });
    }
}

#[test]
fn var_declaration_object_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {x} = source", ParseGoal::Script)
        .expect("destructuring binding should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert_eq!(decl.declarations.len(), 1);
        let pat = &decl.declarations[0].pattern;
        assert!(
            matches!(pat, BindingPattern::ObjectPattern(props) if props.len() == 1),
            "expected object pattern, got {pat:?}"
        );
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn var_declaration_array_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var [a, b] = source", ParseGoal::Script)
        .expect("array destructuring binding should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let pat = &decl.declarations[0].pattern;
        assert!(
            matches!(pat, BindingPattern::ArrayPattern(elems) if elems.len() == 2),
            "expected array pattern with 2 elements, got {pat:?}"
        );
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn object_destructuring_with_rest_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {a, ...rest} = source", ParseGoal::Script)
        .expect("object rest should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
            assert_eq!(props.len(), 2);
            assert!(
                matches!(&props[1].value, BindingPattern::Rest(_)),
                "last property should be rest"
            );
        } else {
            panic!("expected object pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn array_destructuring_with_rest_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var [a, ...rest] = source", ParseGoal::Script)
        .expect("array rest should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
            assert_eq!(elems.len(), 2);
            assert!(
                matches!(&elems[1], Some(BindingPattern::Rest(_))),
                "last element should be rest"
            );
        } else {
            panic!("expected array pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn object_destructuring_multiple_rest_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var {...a, ...b} = source", ParseGoal::Script)
        .expect_err("multiple rest in object pattern must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("rest element must be the absolute last property"),
        "error should mention absolute last property: {msg}"
    );
}

#[test]
fn object_destructuring_rest_not_last_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var {...rest, b} = source", ParseGoal::Script)
        .expect_err("rest not last in object pattern must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("rest element must be"),
        "error should mention rest position: {msg}"
    );
}

#[test]
fn array_destructuring_multiple_rest_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var [...a, ...b] = source", ParseGoal::Script)
        .expect_err("multiple rest in array pattern must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("more than one rest"),
        "error should mention multiple rest: {msg}"
    );
}

#[test]
fn array_destructuring_rest_not_last_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("var [...rest, b] = source", ParseGoal::Script)
        .expect_err("rest not last in array pattern must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("rest element must be the last"),
        "error should mention rest position: {msg}"
    );
}

#[test]
fn nested_destructuring_object_in_array_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var [{a, b}, c] = source", ParseGoal::Script)
        .expect("nested destructuring should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
            assert_eq!(elems.len(), 2);
            assert!(
                matches!(&elems[0], Some(BindingPattern::ObjectPattern(_))),
                "first element should be object pattern"
            );
        } else {
            panic!("expected array pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn nested_destructuring_array_in_object_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {a: [x, y]} = source", ParseGoal::Script)
        .expect("nested array in object should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert!(
            matches!(
                &decl.declarations[0].pattern,
                BindingPattern::ObjectPattern(_)
            ),
            "expected object pattern"
        );
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn destructuring_with_default_value_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {a = 1, b = 2} = source", ParseGoal::Script)
        .expect("destructuring with defaults should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
            assert_eq!(props.len(), 2);
            assert!(
                matches!(&props[0].value, BindingPattern::AssignmentPattern { .. }),
                "first prop should have default: {:?}",
                props[0].value
            );
        } else {
            panic!("expected object pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn whole_object_pattern_default_param_parses_as_assignment_pattern() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function f({a = 5} = {}) { return a; }", ParseGoal::Script)
        .expect("function param with whole-object-pattern default should parse");
    if let Statement::FunctionDeclaration(func) = &tree.body[0] {
        assert!(
            matches!(
                &func.params[0].pattern,
                BindingPattern::AssignmentPattern { left, .. }
                    if matches!(left.as_ref(), BindingPattern::ObjectPattern(_))
            ),
            "expected assignment pattern with object-pattern left side, got {:?}",
            func.params[0].pattern
        );
    } else {
        panic!("expected function declaration");
    }
}

#[test]
fn array_destructuring_with_holes_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var [a, , b] = source", ParseGoal::Script)
        .expect("array with holes should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
            assert_eq!(elems.len(), 3);
            assert!(elems[0].is_some(), "first element should be Some");
            assert!(elems[1].is_none(), "second element (hole) should be None");
            assert!(elems[2].is_some(), "third element should be Some");
        } else {
            panic!("expected array pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn let_declaration_with_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let {x, y} = source", ParseGoal::Script)
        .expect("let destructuring should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert_eq!(decl.kind, VariableDeclarationKind::Let);
        assert!(matches!(
            &decl.declarations[0].pattern,
            BindingPattern::ObjectPattern(_)
        ));
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn const_declaration_with_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const [a, b] = source", ParseGoal::Script)
        .expect("const destructuring should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert_eq!(decl.kind, VariableDeclarationKind::Const);
        assert!(matches!(
            &decl.declarations[0].pattern,
            BindingPattern::ArrayPattern(_)
        ));
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn for_in_with_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (var {a, b} in source) {}", ParseGoal::Script)
        .expect("for-in destructuring should succeed");
    if let Statement::ForIn(stmt) = &tree.body[0] {
        assert!(
            matches!(&stmt.binding, BindingPattern::ObjectPattern(props) if props.len() == 2),
            "expected object pattern binding"
        );
    } else {
        panic!("expected for-in statement");
    }
}

#[test]
fn for_of_with_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (var [a, b] of source) {}", ParseGoal::Script)
        .expect("for-of destructuring should succeed");
    if let Statement::ForOf(stmt) = &tree.body[0] {
        assert!(
            matches!(&stmt.binding, BindingPattern::ArrayPattern(elems) if elems.len() == 2),
            "expected array pattern binding"
        );
    } else {
        panic!("expected for-of statement");
    }
}

#[test]
fn object_destructuring_renamed_key_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {a: x, b: y} = source", ParseGoal::Script)
        .expect("renamed keys should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
            assert_eq!(props.len(), 2);
            assert_eq!(props[0].key, Expression::Identifier("a".to_string()));
            assert!(
                matches!(&props[0].value, BindingPattern::Identifier(name) if name == "x"),
                "first value should be identifier x"
            );
        } else {
            panic!("expected object pattern");
        }
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn empty_object_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var {} = source", ParseGoal::Script)
        .expect("empty object destructuring should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert!(
            matches!(&decl.declarations[0].pattern, BindingPattern::ObjectPattern(props) if props.is_empty()),
            "expected empty object pattern"
        );
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn empty_array_destructuring_accepted() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var [] = source", ParseGoal::Script)
        .expect("empty array destructuring should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        assert!(
            matches!(&decl.declarations[0].pattern, BindingPattern::ArrayPattern(elems) if elems.is_empty()),
            "expected empty array pattern"
        );
    } else {
        panic!("expected variable declaration");
    }
}

#[test]
fn identifier_starting_with_var_is_expression_not_declaration() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("variant", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(
                expr.expression,
                Expression::Identifier("variant".to_string())
            );
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn identifier_starting_with_let_is_expression_not_declaration() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("letter", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(
                expr.expression,
                Expression::Identifier("letter".to_string())
            );
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn identifier_starting_with_const_is_expression_not_declaration() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("constant", ParseGoal::Script).expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => {
            assert_eq!(
                expr.expression,
                Expression::Identifier("constant".to_string())
            );
        }
        _ => panic!("expected expression statement"),
    }
}

#[test]
fn top_level_await_in_module_context_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const data = await fetchData();", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let declarator = &decl.declarations[0];
            if let Some(init) = &declarator.initializer {
                match init {
                    Expression::Await(inner) => match inner.as_ref() {
                        Expression::Call {
                            callee, arguments, ..
                        } => {
                            assert_eq!(**callee, Expression::Identifier("fetchData".to_string()));
                            assert!(arguments.is_empty());
                        }
                        _ => panic!("expected call expression in await"),
                    },
                    _ => panic!("expected await expression in initializer"),
                }
            } else {
                panic!("expected initializer in variable declaration");
            }
        }
        _ => panic!("expected variable declaration"),
    }
}

#[test]
fn top_level_await_statement_in_module_context_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("await doSomething();", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Expression(expr) => match &expr.expression {
            Expression::Await(inner) => match inner.as_ref() {
                Expression::Call {
                    callee, arguments, ..
                } => {
                    assert_eq!(**callee, Expression::Identifier("doSomething".to_string()));
                    assert!(arguments.is_empty());
                }
                _ => panic!("expected call expression in await"),
            },
            _ => panic!("expected await expression"),
        },
        _ => panic!("expected expression statement"),
    }
}

// -----------------------------------------------------------------------
// Multi-statement / semicolons
// -----------------------------------------------------------------------

#[test]
fn semicolons_split_statements() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("x;42;'hello'", ParseGoal::Script)
        .expect("parse");
    assert_eq!(tree.body.len(), 3);
}

#[test]
fn semicolon_inside_string_does_not_split_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("'a;b';x", ParseGoal::Script).expect("parse");
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn multiline_source_parsed_correctly() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("x\n42\n'hello'", ParseGoal::Script)
        .expect("parse");
    assert_eq!(tree.body.len(), 3);
}

#[test]
fn trailing_semicolons_do_not_create_extra_statements() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("x;", ParseGoal::Script).expect("parse");
    assert_eq!(tree.body.len(), 1);
}

// -----------------------------------------------------------------------
// Import forms
// -----------------------------------------------------------------------

#[test]
fn import_with_binding_parsed_in_module() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            assert!(matches!(
                &import.clause,
                ImportClause::Default { local } if local == "dep"
            ));
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_side_effect_only_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import 'polyfill'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            assert!(matches!(&import.clause, ImportClause::SideEffect));
            assert_eq!(import.source, "polyfill");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_named_clause_parsed_without_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import { run, stop as halt } from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            match &import.clause {
                ImportClause::Named { specifiers } => {
                    assert_eq!(specifiers.len(), 2);
                    assert_eq!(specifiers[0].import_name, "run");
                    assert_eq!(specifiers[0].local_name, "run");
                    assert_eq!(specifiers[1].import_name, "stop");
                    assert_eq!(specifiers[1].local_name, "halt");
                }
                other => panic!("expected named import clause, got {other:?}"),
            }
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_empty_named_clause_parsed_without_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import {} from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            match &import.clause {
                ImportClause::Named { specifiers } => {
                    assert!(specifiers.is_empty());
                }
                other => panic!("expected named import clause, got {other:?}"),
            }
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_namespace_clause_parsed_with_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import * as ns from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            assert!(matches!(
                &import.clause,
                ImportClause::Namespace { local } if local == "ns"
            ));
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_default_plus_named_clause_keeps_default_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep, { run } from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            match &import.clause {
                ImportClause::DefaultAndNamed {
                    default,
                    specifiers,
                } => {
                    assert_eq!(default, "dep");
                    assert_eq!(specifiers.len(), 1);
                    assert_eq!(specifiers[0].import_name, "run");
                    assert_eq!(specifiers[0].local_name, "run");
                }
                other => panic!("expected default+named import clause, got {other:?}"),
            }
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_default_plus_namespace_clause_keeps_default_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep, * as ns from 'pkg'", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Import(import) => {
            match &import.clause {
                ImportClause::DefaultAndNamespace { default, namespace } => {
                    assert_eq!(default, "dep");
                    assert_eq!(namespace, "ns");
                }
                other => panic!("expected default+namespace import clause, got {other:?}"),
            }
            assert_eq!(import.source, "pkg");
        }
        _ => panic!("expected import statement"),
    }
}

#[test]
fn import_empty_clause_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import ", ParseGoal::Module)
        .expect_err("empty import clause must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_namespace_clause_without_alias_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import * from 'pkg'", ParseGoal::Module)
        .expect_err("namespace import without alias must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn import_named_clause_with_invalid_alias_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import { run as } from 'pkg'", ParseGoal::Module)
        .expect_err("invalid named import alias must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn import_default_binding_keyword_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import for from 'pkg'", ParseGoal::Module)
        .expect_err("keyword default import binding must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn import_namespace_binding_keyword_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import * as for from 'pkg'", ParseGoal::Module)
        .expect_err("keyword namespace import binding must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn import_named_clause_keyword_binding_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import { run as for } from 'pkg'", ParseGoal::Module)
        .expect_err("keyword named import binding must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

// -----------------------------------------------------------------------
// Export forms
// -----------------------------------------------------------------------

#[test]
fn export_default_identifier_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default main", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Export(export) => match &export.kind {
            ExportKind::Default(expr) => {
                assert_eq!(*expr, Expression::Identifier("main".to_string()));
            }
            _ => panic!("expected default export"),
        },
        _ => panic!("expected export statement"),
    }
}

#[test]
fn minified_import_declarations_parse_bd_goh5q() {
    let parse_import = |source: &str| {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        match tree.body.into_iter().next() {
            Some(Statement::Import(import)) => import,
            other => panic!("{source}: expected an import, got {other:?}"),
        }
    };

    let named = parse_import("import{a,b as c}from'pkg'");
    match &named.clause {
        ImportClause::Named { specifiers } => {
            let names: Vec<_> = specifiers
                .iter()
                .map(|s| (s.import_name.as_str(), s.local_name.as_str()))
                .collect();
            assert_eq!(names, [("a", "a"), ("b", "c")]);
        }
        other => panic!("expected named import clause, got {other:?}"),
    }
    assert_eq!(named.source, "pkg");

    assert!(matches!(
        &parse_import("import d,{a}from\"pkg\"").clause,
        ImportClause::DefaultAndNamed { default, specifiers }
            if default == "d" && specifiers.len() == 1
    ));
    assert!(matches!(
        &parse_import("import*as ns from'pkg'").clause,
        ImportClause::Namespace { local } if local == "ns"
    ));
    assert!(matches!(
        &parse_import("import d,*as ns from'pkg'").clause,
        ImportClause::DefaultAndNamespace { default, namespace }
            if default == "d" && namespace == "ns"
    ));
    assert!(matches!(
        parse_import("import'pkg'").clause,
        ImportClause::SideEffect
    ));
    // `from` as a binding name, and a source containing "from".
    assert!(matches!(
        &parse_import("import from from'./from.js'").clause,
        ImportClause::Default { local } if local == "from"
    ));
    let from_named = parse_import("import{from}from'./from.js'");
    assert_eq!(from_named.source, "./from.js");
    assert!(matches!(
        &from_named.clause,
        ImportClause::Named { specifiers } if specifiers[0].local_name == "from"
    ));
}

#[test]
fn minified_export_declarations_parse_bd_goh5q() {
    let parse_export = |source: &str| {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        match tree.body.into_iter().next() {
            Some(Statement::Export(export)) => export.kind,
            other => panic!("{source}: expected an export, got {other:?}"),
        }
    };
    match parse_export("export{}") {
        ExportKind::NamedClause(clause) => {
            assert_eq!(clause.canonical_head(), "{}");
            assert!(clause.source().is_none());
        }
        other => panic!("expected named clause export, got {other:?}"),
    }
    match parse_export("export{a as b,c}from'pkg'") {
        ExportKind::NamedClause(clause) => {
            assert_eq!(clause.canonical_head(), "{a as b,c}");
            assert_eq!(clause.source().and_then(JsString::as_str), Some("pkg"));
        }
        other => panic!("expected named clause export, got {other:?}"),
    }
    assert!(matches!(
        parse_export("export default{x:1}"),
        ExportKind::Default(_)
    ));
    assert!(matches!(
        parse_export("export default(1)"),
        ExportKind::Default(_)
    ));
}

#[test]
fn star_export_declarations_parse_bd_332pq() {
    for (source, head) in [
        ("export * from 'pkg'", "*"),
        ("export*from'pkg'", "*"),
        ("export * as ns from \"pkg\"", "* as ns"),
        ("export*as ns from'pkg'", "* as ns"),
        ("export * as from from 'pkg'", "* as from"),
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let Some(Statement::Export(export)) = tree.body.first() else {
            panic!("{source}: expected an export");
        };
        let ExportKind::NamedClause(clause) = &export.kind else {
            panic!("{source}: expected a clause export");
        };
        assert_eq!(clause.canonical_head(), head, "{source}");
        assert_eq!(
            clause.source().and_then(JsString::as_str),
            Some("pkg"),
            "{source}"
        );
    }
    for source in [
        "export * 'pkg'",
        "export * as from 'pkg'",
        "export * as ns",
        "export * from pkg",
    ] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .expect_err(source);
        // A SyntaxError, as in Node (bd-9vouw.429), not a refusal.
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source}");
    }
}

#[test]
fn import_and_export_prefixes_that_are_not_declarations_bd_goh5q() {
    for source in [
        "import('pkg')",
        "import ('pkg')",
        "import.meta",
        "importance = 1",
        "exports.value = 1",
        "exporter = 1",
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        assert!(
            !matches!(
                tree.body.first(),
                Some(Statement::Import(_) | Statement::Export(_))
            ),
            "{source}"
        );
    }
    // A script cannot hold a minified declaration either.
    let error = CanonicalEs2020Parser
        .parse("import{a}from'pkg'", ParseGoal::Script)
        .expect_err("import declaration in a script");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
}

#[test]
fn export_named_clause_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export { a, b }", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Export(export) => match &export.kind {
            ExportKind::NamedClause(clause) => {
                assert_eq!(clause.canonical_head(), "{ a, b }");
                assert!(clause.source().is_none());
            }
            _ => panic!("expected named clause export"),
        },
        _ => panic!("expected export statement"),
    }
}

#[test]
fn export_named_clause_with_source_is_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "export { default as dep, run as start } from \"pkg\"",
            ParseGoal::Module,
        )
        .expect("parse");
    match &tree.body[0] {
        Statement::Export(export) => match &export.kind {
            ExportKind::NamedClause(clause) => {
                assert_eq!(clause.canonical_head(), "{ default as dep, run as start }");
                assert_eq!(clause.source().and_then(JsString::as_str), Some("pkg"));
            }
            _ => panic!("expected named clause export"),
        },
        _ => panic!("expected export statement"),
    }
}

#[test]
fn export_named_clause_cooks_source_without_collapsing_inner_space_bd_vltnh() {
    let tree = CanonicalEs2020Parser
        .parse("export { dep } from \"pkg  name\"", ParseGoal::Module)
        .expect("named export source should parse");
    let Statement::Export(export) = &tree.body[0] else {
        panic!("expected named export clause");
    };
    assert!(matches!(
        &export.kind,
        ExportKind::NamedClause(clause)
            if clause.canonical_head() == "{ dep }"
                && clause.source().and_then(JsString::as_str) == Some("pkg  name")
    ));
}

#[test]
fn module_declarations_preserve_distinct_lone_surrogate_sources_bd_lfq44() {
    let import_tree = CanonicalEs2020Parser
        .parse(r#"import "\uD800"; import "\uDC00""#, ParseGoal::Module)
        .expect("exact import sources should parse");
    let [Statement::Import(first), Statement::Import(second)] = import_tree.body.as_slice() else {
        panic!("expected two side-effect imports");
    };
    assert_eq!(first.source.code_units_vec(), [0xD800]);
    assert_eq!(second.source.code_units_vec(), [0xDC00]);
    assert_ne!(first.source, second.source);

    let export_tree = CanonicalEs2020Parser
        .parse(r#"export { value } from "\uDC00""#, ParseGoal::Module)
        .expect("exact re-export source should parse");
    let Statement::Export(export) = &export_tree.body[0] else {
        panic!("expected named re-export");
    };
    let ExportKind::NamedClause(clause) = &export.kind else {
        panic!("expected named export clause");
    };
    assert_eq!(clause.canonical_head(), "{ value }");
    assert_eq!(
        clause
            .source()
            .expect("re-export must retain its source")
            .code_units_vec(),
        [0xDC00]
    );
}

#[test]
fn export_const_declaration_expands_to_declaration_and_named_export() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export const x = 42", ParseGoal::Module)
        .expect("named const export should parse");

    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if declaration.kind == VariableDeclarationKind::Const
                && declaration.declarations[0].name() == Some("x")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause)
                if clause.canonical_head() == "{ x }" && clause.source().is_none())
    ));
}

#[test]
fn export_function_declaration_expands_to_declaration_and_named_export() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export function run() {}", ParseGoal::Module)
        .expect("named function export should parse");

    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::FunctionDeclaration(function) if function.name.as_deref() == Some("run")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause)
                if clause.canonical_head() == "{ run }" && clause.source().is_none())
    ));
}

#[test]
fn export_function_statement_splits_before_following_same_line_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "export function run() {} const after = 1",
            ParseGoal::Module,
        )
        .expect("exported function followed by declaration should parse");

    assert_eq!(tree.body.len(), 3);
    assert!(matches!(
        &tree.body[0],
        Statement::FunctionDeclaration(function) if function.name.as_deref() == Some("run")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause)
                if clause.canonical_head() == "{ run }" && clause.source().is_none())
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::VariableDeclaration(declaration)
            if declaration.declarations[0].name() == Some("after")
    ));
}

#[test]
fn exported_class_heritage_bodies_do_not_end_the_declaration() {
    for source in [
        "export class Derived extends class {} {} const after = 1;",
        "export default class extends class {} {} const after = 1;",
        "export default class Derived extends function () {} {} const after = 1;",
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert!(matches!(
            tree.body.last(),
            Some(Statement::VariableDeclaration(declaration))
                if declaration.declarations[0].name() == Some("after")
        ));
        let super_class = match &tree.body[0] {
            Statement::ClassDeclaration(class) => &class.super_class,
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(Expression::ClassExpression { super_class, .. }) => super_class,
                _ => panic!("expected default class expression"),
            },
            _ => panic!("expected exported class"),
        };
        assert!(
            super_class.is_some(),
            "heritage must remain attached: {source}"
        );
    }
}

#[test]
fn export_default_function_statement_splits_before_following_same_line_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "export default function() {} const after = 1",
            ParseGoal::Module,
        )
        .expect("default exported function followed by declaration should parse");

    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::Export(export) if matches!(&export.kind, ExportKind::Default(_))
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::VariableDeclaration(declaration)
            if declaration.declarations[0].name() == Some("after")
    ));
}

#[test]
fn export_class_declaration_expands_to_declaration_and_named_export() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export class Runner {}", ParseGoal::Module)
        .expect("named class export should parse");

    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::ClassDeclaration(class) if class.name.as_deref() == Some("Runner")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause)
                if clause.canonical_head() == "{ Runner }" && clause.source().is_none())
    ));
}

#[test]
fn export_named_clause_invalid_specifier_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export { run as }", ParseGoal::Module)
        .expect_err("invalid named export alias must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn export_named_clause_unquoted_source_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export { run } from pkg", ParseGoal::Module)
        .expect_err("export source must be quoted");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn export_non_named_non_default_clause_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export run", ParseGoal::Module)
        .expect_err("unsupported export clause must fail");
    // A SyntaxError, not a refusal: every import and export form is
    // supported (bd-9vouw.429).
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

// -----------------------------------------------------------------------
// ParserInput implementations
// -----------------------------------------------------------------------

#[test]
fn str_input_has_inline_label() {
    let source: &str = "42";
    let ps = source.into_source().expect("into_source");
    assert_eq!(ps.label, "<inline>");
    assert_eq!(ps.text, "42");
}

#[test]
fn string_input_has_inline_label() {
    let source = String::from("hello");
    let ps = source.into_source().expect("into_source");
    assert_eq!(ps.label, "<inline>");
    assert_eq!(ps.text, "hello");
}

#[test]
fn stream_input_invalid_utf8_rejected() {
    let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x00];
    let input = StreamInput::new(Cursor::new(bad_bytes), "bad_stream");
    let err = input.into_source().expect_err("invalid UTF-8 must fail");
    assert_eq!(err.code, ParseErrorCode::InvalidUtf8);
}

// -----------------------------------------------------------------------
// ParseError display
// -----------------------------------------------------------------------

#[test]
fn parse_error_display_without_span() {
    let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
    let display = format!("{}", err);
    assert!(display.contains("EmptySource"));
    assert!(display.contains("test.js"));
}

#[test]
fn parse_error_display_with_span() {
    let span = SourceSpan::new(0, 5, 1, 1, 1, 6);
    let err = ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        "bad token",
        "test.js",
        Some(span),
    );
    let display = format!("{}", err);
    assert!(display.contains("line=1"));
    assert!(display.contains("column=1"));
}

#[test]
fn parse_error_round_trips_through_serde() {
    let err = ParseError::new(
        ParseErrorCode::EmptySource,
        "source is empty",
        "<inline>",
        None,
    );
    let json = serde_json::to_string(&err).expect("serde serialization should succeed");
    let decoded: ParseError = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(decoded, err);
}

#[test]
fn budget_exhaustion_returns_stable_witness() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 32,
        },
    };

    let err = parser
        .parse_with_options("alpha beta gamma", ParseGoal::Script, &options)
        .expect_err("token budget should fail");
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    let witness = err.witness.expect("budget failures should carry witness");
    assert_eq!(witness.mode, ParserMode::ScalarReference);
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert_eq!(witness.max_token_count, 1);
    assert!(witness.token_count > witness.max_token_count);
}

#[test]
fn byte_classification_table_covers_ascii_lexical_categories() {
    assert!(lex_has_class(b' ', LEX_CLASS_WHITESPACE));
    assert!(lex_has_class(b'\n', LEX_CLASS_WHITESPACE));
    assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_START));
    assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_CONTINUE));
    assert!(lex_has_class(b'0', LEX_CLASS_DIGIT));
    assert!(lex_has_class(b'0', LEX_CLASS_IDENTIFIER_CONTINUE));
    assert!(lex_has_class(b'\"', LEX_CLASS_QUOTE));
    assert!(lex_has_class(b'=', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
    assert!(!lex_has_class(b'+', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
    // bd-2noh9: `<VT>` (0x0B) and `<FF>` (0x0C) are ES2020 WhiteSpace.
    assert!(lex_has_class(0x0b, LEX_CLASS_WHITESPACE));
    assert!(lex_has_class(0x0c, LEX_CLASS_WHITESPACE));
}

/// The scalar reference's whitespace predicate must classify the exact same
/// byte set as the SIMD scanner's `LEX_CLASS_WHITESPACE` bit — otherwise the
/// two token counters diverge (bd-2noh9). This locks the two independent
/// implementations together without coupling their code paths.
#[test]
fn ascii_lexical_whitespace_matches_the_simd_whitespace_class_bd_2noh9() {
    for byte in 0u8..=255 {
        assert_eq!(
            is_ascii_lexical_whitespace(byte),
            lex_has_class(byte, LEX_CLASS_WHITESPACE),
            "whitespace classification disagrees for byte {byte:#04x}"
        );
    }
    // Pin the specific WhatWG-Infra vs ES2020 gap: `is_ascii_whitespace`
    // omits `<VT>`, but the lexical-whitespace predicate must include it.
    assert!(is_ascii_lexical_whitespace(0x0b));
    assert!(!0x0b_u8.is_ascii_whitespace());
}

/// Regression for bd-2noh9: a `<VT>` (U+000B) between/around tokens must be
/// treated as whitespace by BOTH counters (it produces no token), and an
/// exhaustive control-byte differential must show no residual SIMD-vs-scalar
/// divergence on ASCII input.
#[test]
fn vertical_tab_token_count_parity_bd_2noh9() {
    // `<VT>` splits two identifiers but is not itself a token: `a <VT> b`
    // is two tokens, exactly like `a b`.
    assert_eq!(count_lexical_tokens("a\u{000b}b"), 2);
    assert_eq!(count_lexical_tokens_scalar_reference("a\u{000b}b"), 2);
    assert_eq!(count_lexical_tokens("a b"), 2);
    // A run of only whitespace (including `<VT>`) yields zero tokens.
    assert_eq!(count_lexical_tokens("\u{000b}\u{000c}\t \r\n"), 0);
    assert_eq!(
        count_lexical_tokens_scalar_reference("\u{000b}\u{000c}\t \r\n"),
        0
    );

    // Exhaustive differential: every ASCII control/space byte, each embedded
    // between two identifiers and standing alone, must count identically
    // under the SIMD scanner and the scalar reference.
    for byte in 0u8..=0x7f {
        let embedded = format!("a{}b", byte as char);
        assert_eq!(
            count_lexical_tokens(&embedded),
            count_lexical_tokens_scalar_reference(&embedded),
            "embedded parity drift for byte {byte:#04x}"
        );
        let alone = (byte as char).to_string();
        assert_eq!(
            count_lexical_tokens(&alone),
            count_lexical_tokens_scalar_reference(&alone),
            "standalone parity drift for byte {byte:#04x}"
        );
    }
}

/// Parse `source` under a small recursion budget so the depth guards fire
/// well before the native stack is at risk of overflow.
fn parse_with_recursion_limit(source: &str, max_recursion_depth: u64) -> ParseResult<SyntaxTree> {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1 << 20,
            max_token_count: 1 << 20,
            max_recursion_depth,
        },
    };
    parser.parse_with_options(source, ParseGoal::Script, &options)
}

/// bd-c4lhp: deeply nested array destructuring must surface a recoverable
/// budget error, never overflow the native stack. Before the fix,
/// `parse_binding_pattern` recursed with no depth guard, so this input
/// aborted the process (SIGABRT, "thread '…' has overflowed its stack").
#[test]
fn deeply_nested_array_destructuring_is_depth_bounded_bd_c4lhp() {
    let depth = 2000;
    let src = format!("let {}x{} = 0;", "[".repeat(depth), "]".repeat(depth));
    let err = parse_with_recursion_limit(&src, 32)
        .expect_err("deep array destructuring must hit the pattern budget");
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    assert!(
        err.message
            .contains("binding-pattern nesting budget exceeded"),
        "expected the binding-pattern guard, got: {}",
        err.message
    );
}

/// bd-c4lhp: the same guard bounds deeply nested object destructuring.
#[test]
fn deeply_nested_object_destructuring_is_depth_bounded_bd_c4lhp() {
    let depth = 2000;
    let src = format!("let {}x{} = 0;", "{a:".repeat(depth), "}".repeat(depth));
    let err = parse_with_recursion_limit(&src, 32)
        .expect_err("deep object destructuring must hit the pattern budget");
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    assert!(
        err.message
            .contains("binding-pattern nesting budget exceeded"),
        "expected the binding-pattern guard, got: {}",
        err.message
    );
}

/// The pattern-depth guard bounds nesting without rejecting valid patterns:
/// a moderately nested destructuring pattern below the limit still parses.
#[test]
fn moderately_nested_destructuring_still_parses_bd_c4lhp() {
    parse_with_recursion_limit("let [a, [b, [c, [d]]]] = x;", 32)
        .expect("shallow destructuring must parse cleanly");
    parse_with_recursion_limit("let { a: { b: { c: d } } } = x;", 32)
        .expect("shallow object destructuring must parse cleanly");
}

/// bd-c4lhp: the sibling expression depth guard likewise bounds deeply
/// nested parentheses — deep nesting is uniformly a recoverable budget
/// error, never a process abort.
#[test]
fn deeply_nested_parentheses_are_depth_bounded_bd_c4lhp() {
    let depth = 2000;
    let src = format!("{}1{};", "(".repeat(depth), ")".repeat(depth));
    let err = parse_with_recursion_limit(&src, 32)
        .expect_err("deep parentheses must hit the recursion budget");
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
}

#[test]
fn utf8_boundary_safe_scanner_matches_scalar_reference_for_ascii_inputs() {
    let cases = [
        "alpha beta gamma",
        "a==b && c!=d || e??f => g",
        "'hello' \"world\"",
        "\"unterminated\nstring\"",
        "await foo;\nbar + baz * 5",
        "_$token123 <= 42",
        "`hello ${name}`",
        "`value ${foo({ bar: 1 })}`",
        "`unterminated ${value`",
        // bd-2noh9: `<VT>` (U+000B) is ES2020 §11.2 WhiteSpace but is omitted
        // by `is_ascii_whitespace`; exercise it between and around tokens.
        "a\u{000b}b",
        "return\u{000b}x",
        "\u{000b}\u{000b}\u{000b}",
        "a\u{000b}\u{000c}\u{0009}b",
        "x\u{000b}==\u{000b}y",
    ];

    for source in cases {
        assert_eq!(
            count_lexical_tokens(source),
            count_lexical_tokens_scalar_reference(source),
            "ASCII parity drift for source: {source:?}"
        );
    }
}

#[test]
fn utf8_boundary_safe_scanner_counts_multibyte_codepoints_once() {
    let two_byte = "é";
    assert_eq!(count_lexical_tokens(two_byte), 1);
    assert_eq!(count_lexical_tokens_scalar_reference(two_byte), 2);

    let four_byte = "😀";
    assert_eq!(count_lexical_tokens(four_byte), 1);
    assert_eq!(count_lexical_tokens_scalar_reference(four_byte), 4);
}

#[test]
fn budget_witness_uses_utf8_boundary_safe_token_count() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 32,
        },
    };

    let err = parser
        .parse_with_options("é β", ParseGoal::Script, &options)
        .expect_err("utf-8-aware token counting should trigger the token budget");
    let witness = err
        .witness
        .expect("budget failures should preserve witness context");
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert_eq!(witness.token_count, 2);
    assert_eq!(witness.max_token_count, 1);
}

#[test]
fn recursion_budget_exhaustion_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1024,
            max_recursion_depth: 1,
        },
    };
    // `await` is permitted at module top-level; two nested awaits exceed a
    // max_recursion_depth of 1.
    let source = "await await work";
    let left = parser
        .parse_with_options(source, ParseGoal::Module, &options)
        .expect_err("left parse should fail");
    let right = parser
        .parse_with_options(source, ParseGoal::Module, &options)
        .expect_err("right parse should fail");
    assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
    assert_eq!(left, right);
}

#[test]
fn string_literal_receiver_member_call_parses_bd_bulsc() {
    // bd-bulsc: a string literal used as a member-access / call / index
    // receiver must PARSE (as postfix on the StringLiteral), not fail closed
    // with "unterminated or malformed string literal".
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    for source in [
        r#""abc".length;"#,
        r#""abc".split(",").length;"#,
        r#""hello".replace("l", "L");"#,
        r#""5".padStart(3, "0");"#,
    ] {
        let result = parser.parse_with_options(source, ParseGoal::Script, &options);
        assert!(
            result.is_ok(),
            "string-literal receiver must parse (bd-bulsc): {source:?} -> {:?}",
            result.err()
        );
    }
}

#[test]
fn genuinely_unterminated_string_still_fails_closed_bd_wa01t() {
    // The bd-bulsc relaxation must NOT weaken the bd-wa01t fail-closed guard:
    // a quote that opens no balanced literal (no close / embedded newline)
    // must still be rejected, not silently passed through as Raw.
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    for source in [r#""unterminated ;"#, "let s = \"abc;"] {
        let result = parser.parse_with_options(source, ParseGoal::Script, &options);
        assert!(
            result.is_err(),
            "genuinely unterminated string must still fail closed (bd-wa01t): {source:?}"
        );
    }
}

#[test]
fn scalar_reference_grammar_matrix_has_non_zero_coverage() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    let summary = matrix.summary();
    assert_eq!(
        matrix.schema_version,
        GrammarCompletenessMatrix::SCHEMA_VERSION
    );
    assert!(summary.family_count > 0);
    assert!(summary.supported_families > 0);
    assert!(summary.completeness_millionths > 0);
    assert!(summary.completeness_millionths <= 1_000_000);
}

// -----------------------------------------------------------------------
// Span correctness
// -----------------------------------------------------------------------

#[test]
fn single_line_source_span_is_correct() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    assert_eq!(tree.span.start_line, 1);
    assert_eq!(tree.span.end_line, 1);
}

#[test]
fn multiline_source_span_end_line_is_correct() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("x\ny\nz", ParseGoal::Script).expect("parse");
    assert_eq!(tree.span.start_line, 1);
    assert_eq!(tree.span.end_line, 3);
}

// -----------------------------------------------------------------------
// Determinism: multiple parses yield identical output
// -----------------------------------------------------------------------

#[test]
fn three_identical_parses_produce_identical_canonical_hashes() {
    let parser = CanonicalEs2020Parser;
    let source = "import x from 'mod';\nexport default x";
    let hashes: Vec<String> = (0..3)
        .map(|_| {
            parser
                .parse(source, ParseGoal::Module)
                .expect("parse")
                .canonical_hash()
        })
        .collect();
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
}

// -----------------------------------------------------------------------
// Enrichment: leaf enum serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn parse_error_code_serde_roundtrip() {
    for code in [
        ParseErrorCode::EmptySource,
        ParseErrorCode::InvalidGoal,
        ParseErrorCode::UnsupportedSyntax,
        ParseErrorCode::IoReadFailed,
        ParseErrorCode::InvalidUtf8,
        ParseErrorCode::SourceTooLarge,
        ParseErrorCode::BudgetExceeded,
    ] {
        let json = serde_json::to_string(&code).expect("serde serialization should succeed");
        let restored: ParseErrorCode =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(code, restored);
    }
}

#[test]
fn parser_mode_serde_roundtrip() {
    let mode = ParserMode::ScalarReference;
    let json = serde_json::to_string(&mode).expect("serde serialization should succeed");
    let restored: ParserMode = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(mode, restored);
    // Verify snake_case rename
    assert!(json.contains("scalar_reference"));
}

#[test]
fn parse_budget_kind_serde_roundtrip() {
    for kind in [
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ] {
        let json = serde_json::to_string(&kind).expect("serde serialization should succeed");
        let restored: ParseBudgetKind =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(kind, restored);
    }
}

#[test]
fn grammar_coverage_status_serde_roundtrip() {
    for status in [
        GrammarCoverageStatus::Supported,
        GrammarCoverageStatus::Partial,
        GrammarCoverageStatus::Unsupported,
        GrammarCoverageStatus::NotApplicable,
    ] {
        let json = serde_json::to_string(&status).expect("serde serialization should succeed");
        let restored: GrammarCoverageStatus =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(status, restored);
    }
}

// -----------------------------------------------------------------------
// Enrichment: struct serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn parser_budget_serde_roundtrip() {
    let budget = ParserBudget::default();
    let json = serde_json::to_string(&budget).expect("serde serialization should succeed");
    let restored: ParserBudget = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(budget, restored);
}

#[test]
fn parser_options_serde_roundtrip() {
    let opts = ParserOptions::default();
    let json = serde_json::to_string(&opts).expect("serde serialization should succeed");
    let restored: ParserOptions =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(opts, restored);
}

#[test]
fn parse_failure_witness_serde_roundtrip() {
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::TokenCount),
        source_bytes: 1024,
        token_count: 500,
        max_recursion_observed: 10,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let json = serde_json::to_string(&witness).expect("serde serialization should succeed");
    let restored: ParseFailureWitness =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(witness, restored);
}

#[test]
fn grammar_family_coverage_serde_roundtrip() {
    let gfc = GrammarFamilyCoverage {
        family_id: "primary-expression".to_string(),
        es2020_clause: "12.2".to_string(),
        script_goal: GrammarCoverageStatus::Supported,
        module_goal: GrammarCoverageStatus::Partial,
        notes: "test".to_string(),
    };
    let json = serde_json::to_string(&gfc).expect("serde serialization should succeed");
    let restored: GrammarFamilyCoverage =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(gfc, restored);
}

#[test]
fn grammar_completeness_summary_serde_roundtrip() {
    let summary = GrammarCompletenessSummary {
        family_count: 10,
        supported_families: 6,
        partially_supported_families: 2,
        unsupported_families: 2,
        completeness_millionths: 700_000,
    };
    let json = serde_json::to_string(&summary).expect("serde serialization should succeed");
    let restored: GrammarCompletenessSummary =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(summary, restored);
}

#[test]
fn grammar_completeness_matrix_serde_roundtrip() {
    let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
    let json = serde_json::to_string(&matrix).expect("serde serialization should succeed");
    let restored: GrammarCompletenessMatrix =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(matrix, restored);
}

// -----------------------------------------------------------------------
// Enrichment: default value assertions
// -----------------------------------------------------------------------

#[test]
fn parser_budget_default_values() {
    let b = ParserBudget::default();
    assert_eq!(b.max_source_bytes, 1_048_576);
    assert_eq!(b.max_token_count, 65_536);
    assert_eq!(b.max_recursion_depth, 256);
}

#[test]
fn parser_options_default_values() {
    let o = ParserOptions::default();
    assert_eq!(o.mode, ParserMode::ScalarReference);
    assert_eq!(o.budget, ParserBudget::default());
}

// -----------------------------------------------------------------------
// Enrichment: ParserMode as_str
// -----------------------------------------------------------------------

#[test]
fn parser_mode_as_str() {
    assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
}

// -----------------------------------------------------------------------
// Enrichment: grammar matrix summary
// -----------------------------------------------------------------------

#[test]
fn grammar_matrix_summary_values() {
    let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
    let summary = matrix.summary();
    assert!(summary.family_count > 0);
    assert!(summary.supported_families > 0);
    assert!(summary.completeness_millionths > 0);
    assert_eq!(
        summary.family_count,
        summary.supported_families
            + summary.partially_supported_families
            + summary.unsupported_families
    );
}

// -----------------------------------------------------------------------
// Enrichment: ParseError witness roundtrip (witness skipped in serde)
// -----------------------------------------------------------------------

#[test]
fn parse_error_serde_witness_none_is_omitted() {
    // When witness is None, the field is skipped in serialization
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "budget exceeded".to_string(),
        source_label: "test.js".to_string(),
        span: None,
        witness: None,
    };
    let json = serde_json::to_string(&err).expect("serde serialization should succeed");
    assert!(!json.contains("witness"));
    let restored: ParseError = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert!(restored.witness.is_none());
    assert_eq!(restored.code, err.code);
}

#[test]
fn parse_error_serde_witness_some_roundtrips() {
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "budget exceeded".to_string(),
        source_label: "test.js".to_string(),
        span: None,
        witness: Some(Box::new(ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::SourceBytes),
            source_bytes: 2_000_000,
            token_count: 0,
            max_recursion_observed: 0,
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        })),
    };
    let json = serde_json::to_string(&err).expect("serde serialization should succeed");
    assert!(json.contains("witness"));
    let restored: ParseError = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert!(restored.witness.is_some());
    assert_eq!(
        restored
            .witness
            .expect("serde serialization should succeed")
            .source_bytes,
        2_000_000
    );
}

#[test]
fn parse_diagnostic_contract_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION,
        "franken-engine.parser-diagnostics.taxonomy.v1"
    );
    assert_eq!(
        PARSER_DIAGNOSTIC_SCHEMA_VERSION,
        "franken-engine.parser-diagnostics.schema.v1"
    );
    assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSER_DIAGNOSTIC_HASH_PREFIX, "sha256:");

    assert_eq!(
        ParseDiagnosticTaxonomy::taxonomy_version(),
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::schema_version(),
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::taxonomy_version(),
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_algorithm(),
        PARSER_DIAGNOSTIC_HASH_ALGORITHM
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_prefix(),
        PARSER_DIAGNOSTIC_HASH_PREFIX
    );
}

#[test]
fn parse_diagnostic_taxonomy_v1_is_complete_and_unique() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    assert_eq!(
        taxonomy.taxonomy_version,
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string()
    );
    assert_eq!(taxonomy.rules.len(), ParseErrorCode::ALL.len());

    let mut error_codes = BTreeSet::new();
    let mut diagnostic_codes = BTreeSet::new();
    for rule in &taxonomy.rules {
        assert!(error_codes.insert(rule.parse_error_code.as_str().to_string()));
        assert!(diagnostic_codes.insert(rule.diagnostic_code.clone()));
        assert_eq!(
            rule.diagnostic_code,
            rule.parse_error_code.stable_diagnostic_code()
        );
        assert_eq!(rule.category, rule.parse_error_code.diagnostic_category());
        assert_eq!(rule.severity, rule.parse_error_code.diagnostic_severity());
        assert_eq!(
            rule.message_template,
            rule.parse_error_code.diagnostic_message_template(None)
        );
    }

    for code in ParseErrorCode::ALL {
        assert!(taxonomy.rule_for(code).is_some());
    }
}

#[test]
fn parse_error_normalization_ignores_raw_message_variance() {
    let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let left = ParseError {
        code: ParseErrorCode::IoReadFailed,
        message: "failed to read source file: No such file or directory (os error 2)".to_string(),
        source_label: "fixture.js".to_string(),
        span: Some(span.clone()),
        witness: None,
    };
    let right = ParseError {
        code: ParseErrorCode::IoReadFailed,
        message: "failed to read source stream: permission denied".to_string(),
        source_label: "fixture.js".to_string(),
        span: Some(span),
        witness: None,
    };

    let left_norm = left.normalized_diagnostic();
    let right_norm = ParseDiagnosticEnvelope::from_parse_error(&right);
    assert_eq!(left_norm.message_template, "parser input could not be read");
    assert_eq!(left_norm.canonical_bytes(), right_norm.canonical_bytes());
    assert_eq!(left_norm.canonical_hash(), right_norm.canonical_hash());
}

#[test]
fn parse_error_normalization_preserves_budget_context() {
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "token budget exceeded: token_count=3 max_token_count=1".to_string(),
        source_label: "<inline>".to_string(),
        span: Some(SourceSpan::new(0, 16, 1, 1, 1, 17)),
        witness: Some(Box::new(ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::TokenCount),
            source_bytes: 16,
            token_count: 3,
            max_recursion_observed: 0,
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 64,
        })),
    };

    let normalized = normalize_parse_error(&err);
    assert_eq!(normalized.category, ParseDiagnosticCategory::Resource);
    assert_eq!(normalized.severity, ParseDiagnosticSeverity::Fatal);
    assert_eq!(
        normalized.diagnostic_code,
        ParseErrorCode::BudgetExceeded.stable_diagnostic_code()
    );
    assert_eq!(
        normalized.message_template,
        "token budget exceeded".to_string()
    );
    assert_eq!(normalized.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert_eq!(
        normalized
            .witness
            .as_ref()
            .expect("budget witness should be retained")
            .token_count,
        3
    );
}

#[test]
fn parse_diagnostic_envelope_serde_and_hash_are_stable() {
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "source is empty after whitespace normalization".to_string(),
        source_label: "<inline>".to_string(),
        span: None,
        witness: None,
    };
    let left = normalize_parse_error(&err);
    let right = normalize_parse_error(&err);
    let json = serde_json::to_string(&left).expect("serde serialization should succeed");
    let restored: ParseDiagnosticEnvelope =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(restored, left);
    assert_eq!(left.canonical_hash(), right.canonical_hash());
    assert!(
        left.canonical_hash()
            .starts_with(ParseDiagnosticEnvelope::canonical_hash_prefix())
    );
}

#[test]
fn parse_event_kind_serde_roundtrip() {
    for kind in [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        let json = serde_json::to_string(&kind).expect("serde serialization should succeed");
        let restored: ParseEventKind =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(kind, restored);
    }
}

#[test]
fn parse_event_ir_contract_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSE_EVENT_IR_CONTRACT_VERSION,
        "franken-engine.parser-event-ir.contract.v2"
    );
    assert_eq!(
        PARSE_EVENT_IR_SCHEMA_VERSION,
        "franken-engine.parser-event-ir.schema.v2"
    );
    assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSE_EVENT_IR_HASH_PREFIX, "sha256:");
    assert_eq!(
        PARSE_EVENT_IR_POLICY_ID,
        "franken-engine.parser-event-producer.policy.v1"
    );
    assert_eq!(PARSE_EVENT_IR_COMPONENT, "canonical_es2020_parser");
    assert_eq!(PARSE_EVENT_IR_TRACE_PREFIX, "trace-parser-event-");
    assert_eq!(PARSE_EVENT_IR_DECISION_PREFIX, "decision-parser-event-");
    assert_eq!(
        ParseEventIr::contract_version(),
        PARSE_EVENT_IR_CONTRACT_VERSION
    );
    assert_eq!(
        ParseEventIr::schema_version(),
        PARSE_EVENT_IR_SCHEMA_VERSION
    );
    assert_eq!(
        ParseEventIr::canonical_hash_algorithm(),
        PARSE_EVENT_IR_HASH_ALGORITHM
    );
    assert_eq!(
        ParseEventIr::canonical_hash_prefix(),
        PARSE_EVENT_IR_HASH_PREFIX
    );
}

#[test]
fn parse_event_ir_from_syntax_tree_emits_deterministic_sequence() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";
    let tree = parser.parse(source, ParseGoal::Module).expect("parse");

    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(ir.schema_version, PARSE_EVENT_IR_SCHEMA_VERSION);
    assert_eq!(ir.contract_version, PARSE_EVENT_IR_CONTRACT_VERSION);
    assert_eq!(ir.events.len(), tree.body.len() + 2);
    assert!(matches!(
        ir.events.first().map(|event| event.kind),
        Some(ParseEventKind::ParseStarted)
    ));
    assert!(matches!(
        ir.events.last().map(|event| event.kind),
        Some(ParseEventKind::ParseCompleted)
    ));

    for (index, event) in ir.events.iter().enumerate() {
        assert_eq!(event.sequence, index as u64);
        assert!(event.trace_id.starts_with(PARSE_EVENT_IR_TRACE_PREFIX));
        assert!(
            event
                .decision_id
                .starts_with(PARSE_EVENT_IR_DECISION_PREFIX)
        );
        assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
        assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn parse_event_ir_hash_is_deterministic_for_identical_inputs() {
    let parser = CanonicalEs2020Parser;
    let source = "typeof work";
    let left_tree = parser.parse(source, ParseGoal::Script).expect("left parse");
    let right_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("right parse");

    let left_ir =
        ParseEventIr::from_syntax_tree(&left_tree, "<inline>", ParserMode::ScalarReference);
    let right_ir =
        ParseEventIr::from_syntax_tree(&right_tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(left_ir.canonical_bytes(), right_ir.canonical_bytes());
    assert_eq!(left_ir.canonical_hash(), right_ir.canonical_hash());
    assert!(
        left_ir
            .canonical_hash()
            .starts_with(ParseEventIr::canonical_hash_prefix())
    );
}

#[test]
fn parse_event_ir_serde_roundtrip() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default true", ParseGoal::Module)
        .expect("parse");
    let ir = ParseEventIr::from_syntax_tree(&tree, "fixture.js", ParserMode::ScalarReference);
    let json = serde_json::to_string(&ir).expect("serde serialization should succeed");
    let restored: ParseEventIr = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(restored, ir);
}

#[test]
fn parse_with_event_ir_success_emits_ordered_events() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";
    let (result, event_ir) =
        parser.parse_with_event_ir(source, ParseGoal::Module, &ParserOptions::default());

    let tree = result.expect("parse should succeed");
    assert_eq!(event_ir.events.len(), tree.body.len() + 2);
    assert!(matches!(
        event_ir.events.first().map(|event| event.kind),
        Some(ParseEventKind::ParseStarted)
    ));
    assert!(matches!(
        event_ir.events.last().map(|event| event.kind),
        Some(ParseEventKind::ParseCompleted)
    ));
    for (index, event) in event_ir.events.iter().enumerate() {
        assert_eq!(event.sequence, index as u64);
        assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
        assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
        assert_eq!(event.error_code, None);
    }
}

#[test]
fn parse_with_event_ir_failure_emits_parse_failed_event() {
    let parser = CanonicalEs2020Parser;
    let (result, event_ir) =
        parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());

    let error = result.expect_err("empty source should fail");
    assert_eq!(error.code, ParseErrorCode::EmptySource);
    assert_eq!(event_ir.events.len(), 2);
    assert!(matches!(
        event_ir.events[0].kind,
        ParseEventKind::ParseStarted
    ));
    assert!(matches!(
        event_ir.events[1].kind,
        ParseEventKind::ParseFailed
    ));
    assert_eq!(
        event_ir.events[1].error_code,
        Some(ParseErrorCode::EmptySource)
    );
    assert_eq!(
        event_ir.events[1].payload_kind.as_deref(),
        Some("parse_diagnostic")
    );
    assert!(
        event_ir.events[1]
            .payload_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with(ParseEventIr::canonical_hash_prefix()))
    );
}

#[test]
fn parse_event_ast_materializer_contract_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
        "franken-engine.parser-event-ast-materializer.contract.v1"
    );
    assert_eq!(
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
        "franken-engine.parser-event-ast-materializer.schema.v1"
    );
    assert_eq!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX, "ast-node-");
    assert_eq!(
        MaterializedSyntaxTree::contract_version(),
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    );
    assert_eq!(
        MaterializedSyntaxTree::schema_version(),
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
    );
}

#[test]
fn materialize_from_source_matches_canonical_ast_hash_and_node_witnesses() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";
    let options = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Module, &options);
    let tree = result.expect("parse should succeed");
    let materialized = event_ir
        .materialize_from_source(source, &options)
        .expect("materialization should succeed");

    assert_eq!(
        materialized.syntax_tree.canonical_hash(),
        tree.canonical_hash()
    );
    assert_eq!(materialized.statement_nodes.len(), tree.body.len());
    assert!(
        materialized
            .root_node_id
            .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
    );
    for (idx, node) in materialized.statement_nodes.iter().enumerate() {
        assert_eq!(node.statement_index, idx as u64);
        assert_eq!(node.sequence, (idx as u64).saturating_add(1));
        assert!(
            node.node_id
                .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
        );
        assert!(
            node.payload_hash
                .starts_with(ParseEventIr::canonical_hash_prefix())
        );
    }
}

#[test]
fn materialize_from_source_accepts_exact_historical_root_column_bd_4tt6s() {
    let parser = CanonicalEs2020Parser;
    let source = "alpha";
    let options = ParserOptions::default();
    let current = parser
        .parse(source, ParseGoal::Script)
        .expect("current source should parse");
    assert_eq!(current.span.end_column, 6);

    let mut historical = current.clone();
    historical.span.end_column = 1;
    let historical_hash = historical.canonical_hash();

    for event_ir in [
        ParseEventIr::from_parse_source(&historical, source, "historical-source.js", options.mode),
        ParseEventIr::from_syntax_tree(&historical, "historical-tree.js", options.mode),
    ] {
        let materialized = event_ir
            .materialize_from_source(source, &options)
            .expect("the exact historical root-column defect should remain readable");
        assert_eq!(materialized.syntax_tree, historical);
        assert_eq!(materialized.syntax_tree.canonical_hash(), historical_hash);
    }

    let trailing_source = "alpha\n";
    let (result, current_ir) =
        parser.parse_with_event_ir(trailing_source, ParseGoal::Script, &options);
    let trailing_tree = result.expect("trailing-LF source should parse");
    assert_eq!(trailing_tree.span.end_column, 1);
    assert_eq!(
        current_ir
            .materialize_from_source(trailing_source, &options)
            .expect("current trailing-LF stream should materialize")
            .syntax_tree,
        trailing_tree
    );
}

#[test]
fn materialize_from_source_rejects_inexact_historical_root_column_bd_4tt6s() {
    let parser = CanonicalEs2020Parser;
    let source = "alpha";
    let options = ParserOptions::default();
    let current = parser
        .parse(source, ParseGoal::Script)
        .expect("current source should parse");
    let mut historical = current.clone();
    historical.span.end_column = 1;

    let mut wrong_other_field =
        ParseEventIr::from_parse_source(&historical, source, "wrong-other-field.js", options.mode);
    wrong_other_field
        .events
        .last_mut()
        .and_then(|event| event.span.as_mut())
        .expect("completed span")
        .start_column = 2;
    assert_eq!(
        wrong_other_field
            .materialize_from_source(source, &options)
            .expect_err("a second span-field drift must not use the historical path")
            .code,
        ParseEventMaterializationErrorCode::AstHashMismatch
    );

    let mut current_hash_with_old_span =
        ParseEventIr::from_parse_source(&current, source, "current-hash-old-span.js", options.mode);
    current_hash_with_old_span
        .events
        .last_mut()
        .and_then(|event| event.span.as_mut())
        .expect("completed span")
        .end_column = 1;
    assert_eq!(
        current_hash_with_old_span
            .materialize_from_source(source, &options)
            .expect_err("a current hash must not authenticate a historical span")
            .code,
        ParseEventMaterializationErrorCode::StatementSpanMismatch
    );

    let mut old_hash_with_current_span = ParseEventIr::from_parse_source(
        &historical,
        source,
        "old-hash-current-span.js",
        options.mode,
    );
    old_hash_with_current_span
        .events
        .last_mut()
        .expect("completed event")
        .span = Some(current.span.clone());
    assert_eq!(
        old_hash_with_current_span
            .materialize_from_source(source, &options)
            .expect_err("a historical hash must not authenticate the current span")
            .code,
        ParseEventMaterializationErrorCode::AstHashMismatch
    );
}

#[test]
fn materialized_ast_node_ids_are_deterministic_for_identical_inputs() {
    let parser = CanonicalEs2020Parser;
    let source = "typeof work";
    let options = ParserOptions::default();

    let (left_result, left_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    let left_tree = left_result.expect("left parse should succeed");
    let (right_result, right_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    let right_tree = right_result.expect("right parse should succeed");

    let left_materialized = left_ir
        .materialize_from_source(source, &options)
        .expect("left materialization should succeed");
    let right_materialized = right_ir
        .materialize_from_source(source, &options)
        .expect("right materialization should succeed");

    assert_eq!(
        left_materialized.syntax_tree.canonical_hash(),
        left_tree.canonical_hash()
    );
    assert_eq!(
        right_materialized.syntax_tree.canonical_hash(),
        right_tree.canonical_hash()
    );
    assert_eq!(
        left_materialized.root_node_id,
        right_materialized.root_node_id
    );
    assert_eq!(
        left_materialized.statement_nodes,
        right_materialized.statement_nodes
    );
    assert_eq!(
        left_materialized.canonical_hash(),
        right_materialized.canonical_hash()
    );
}

#[test]
fn materialize_from_source_rejects_statement_hash_tampering() {
    let parser = CanonicalEs2020Parser;
    let source = "alpha;";
    let options = ParserOptions::default();
    let (_result, mut event_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    event_ir.events[1].payload_hash =
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string());

    let err = event_ir
        .materialize_from_source(source, &options)
        .expect_err("tampered payload hash must fail");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::StatementHashMismatch
    );
    assert_eq!(err.sequence, Some(1));
}

#[test]
fn materialize_from_source_rejects_failed_event_streams() {
    let parser = CanonicalEs2020Parser;
    let (_result, event_ir) =
        parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
    let err = event_ir
        .materialize_from_source("", &ParserOptions::default())
        .expect_err("failed event stream should be rejected");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

#[test]
fn parse_with_materialized_ast_success_and_failure_contracts_are_deterministic() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;";
    let options = ParserOptions::default();

    let (result, _event_ir, materialized_result) =
        parser.parse_with_materialized_ast(source, ParseGoal::Module, &options);
    let tree = result.expect("parse should succeed");
    let materialized = materialized_result.expect("materializer should succeed");
    assert_eq!(
        materialized.syntax_tree.canonical_hash(),
        tree.canonical_hash()
    );

    let (failed_result, _failed_ir, failed_materialized) =
        parser.parse_with_materialized_ast("", ParseGoal::Script, &ParserOptions::default());
    let err = failed_result.expect_err("empty source should fail parse");
    assert_eq!(err.code, ParseErrorCode::EmptySource);
    assert_eq!(
        failed_materialized
            .expect_err("failed parse must not materialize")
            .code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

// -----------------------------------------------------------------------
// Enrichment: ParseErrorCode as_str all variants
// -----------------------------------------------------------------------

#[test]
fn parse_error_code_as_str_all_distinct() {
    let strs: BTreeSet<&str> = ParseErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), ParseErrorCode::ALL.len());
}

#[test]
fn parse_error_code_stable_diagnostic_code_all_distinct() {
    let codes: BTreeSet<&str> = ParseErrorCode::ALL
        .iter()
        .map(|c| c.stable_diagnostic_code())
        .collect();
    assert_eq!(codes.len(), ParseErrorCode::ALL.len());
}

#[test]
fn parse_error_code_diagnostic_category_covers_all_categories() {
    let categories: BTreeSet<_> = ParseErrorCode::ALL
        .iter()
        .map(|c| c.diagnostic_category().as_str())
        .collect();
    // At least 4 distinct categories
    assert!(categories.len() >= 4, "got {:?}", categories);
}

#[test]
fn parse_error_code_diagnostic_severity_covers_both() {
    let severities: BTreeSet<_> = ParseErrorCode::ALL
        .iter()
        .map(|c| c.diagnostic_severity().as_str())
        .collect();
    assert!(severities.contains("error"));
    assert!(severities.contains("fatal"));
}

#[test]
fn parse_error_code_diagnostic_message_template_non_empty() {
    for code in &ParseErrorCode::ALL {
        assert!(
            !code.diagnostic_message_template(None).is_empty(),
            "empty template for {:?}",
            code
        );
    }
}

#[test]
fn budget_exceeded_message_template_with_budget_kind() {
    let msg = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::TokenCount));
    assert!(
        msg.contains("token"),
        "expected token-related msg, got: {msg}"
    );
}

// -----------------------------------------------------------------------
// Enrichment: ParseDiagnosticCategory as_str all distinct
// -----------------------------------------------------------------------

#[test]
fn parse_diagnostic_category_as_str_all_distinct() {
    let categories = [
        ParseDiagnosticCategory::Input,
        ParseDiagnosticCategory::Goal,
        ParseDiagnosticCategory::Syntax,
        ParseDiagnosticCategory::Encoding,
        ParseDiagnosticCategory::Resource,
        ParseDiagnosticCategory::System,
    ];
    let strs: BTreeSet<&str> = categories.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), categories.len());
}

// -----------------------------------------------------------------------
// Enrichment: ParseBudgetKind as_str all distinct
// -----------------------------------------------------------------------

#[test]
fn parse_budget_kind_as_str_all_distinct() {
    let kinds = [
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

// -----------------------------------------------------------------------
// Enrichment: ParseEventKind as_str all distinct
// -----------------------------------------------------------------------

#[test]
fn parse_event_kind_as_str_all_distinct() {
    let kinds = [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

#[test]
fn parse_event_kind_canonical_value_matches_as_str() {
    for kind in [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        if let CanonicalValue::String(s) = kind.canonical_value() {
            assert_eq!(s, kind.as_str());
        } else {
            panic!("expected CanonicalValue::String");
        }
    }
}

// -----------------------------------------------------------------------
// Enrichment: ParseEventMaterializationErrorCode as_str
// -----------------------------------------------------------------------

#[test]
fn parse_event_materialization_error_code_as_str_all_distinct() {
    let codes = [
        ParseEventMaterializationErrorCode::UnsupportedContractVersion,
        ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
        ParseEventMaterializationErrorCode::ParseFailedEventStream,
        ParseEventMaterializationErrorCode::MissingParseStarted,
        ParseEventMaterializationErrorCode::MissingParseCompleted,
        ParseEventMaterializationErrorCode::InvalidEventSequence,
        ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
        ParseEventMaterializationErrorCode::GoalMismatch,
        ParseEventMaterializationErrorCode::ModeMismatch,
        ParseEventMaterializationErrorCode::StatementCountMismatch,
        ParseEventMaterializationErrorCode::StatementIndexMismatch,
        ParseEventMaterializationErrorCode::StatementKindMismatch,
        ParseEventMaterializationErrorCode::StatementHashMismatch,
        ParseEventMaterializationErrorCode::StatementSpanMismatch,
        ParseEventMaterializationErrorCode::SourceHashMismatch,
        ParseEventMaterializationErrorCode::AstHashMismatch,
        ParseEventMaterializationErrorCode::SourceParseFailed,
    ];
    let strs: BTreeSet<&str> = codes.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), codes.len());
}

// -----------------------------------------------------------------------
// Enrichment: ParseEventMaterializationError Display
// -----------------------------------------------------------------------

#[test]
fn materialization_error_display_with_sequence() {
    let err = ParseEventMaterializationError::new(
        ParseEventMaterializationErrorCode::GoalMismatch,
        "mismatch".to_string(),
        Some(5),
    );
    let display = err.to_string();
    assert!(display.contains("sequence=5"), "got: {display}");
    assert!(display.contains("goal_mismatch"), "got: {display}");
}

#[test]
fn materialization_error_display_without_sequence() {
    let err = ParseEventMaterializationError::new(
        ParseEventMaterializationErrorCode::SourceHashMismatch,
        "hash differs".to_string(),
        None,
    );
    let display = err.to_string();
    assert!(!display.contains("sequence="), "got: {display}");
    assert!(display.contains("source_hash_mismatch"), "got: {display}");
}

#[test]
fn materialization_error_is_std_error() {
    let err: &dyn std::error::Error = &ParseEventMaterializationError::new(
        ParseEventMaterializationErrorCode::ParseFailedEventStream,
        "msg".to_string(),
        None,
    );
    assert!(!err.to_string().is_empty());
}

// -----------------------------------------------------------------------
// Enrichment: serde roundtrips for missing types
// -----------------------------------------------------------------------

#[test]
fn parse_diagnostic_rule_serde_roundtrip() {
    let rule = ParseDiagnosticRule {
        parse_error_code: ParseErrorCode::EmptySource,
        diagnostic_code: "FE-PARSER-DIAG-EMPTY-SOURCE-0001".to_string(),
        category: ParseDiagnosticCategory::Input,
        severity: ParseDiagnosticSeverity::Error,
        message_template: "source is empty".to_string(),
    };
    let json = serde_json::to_string(&rule).expect("serde serialization should succeed");
    let restored: ParseDiagnosticRule =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(rule, restored);
}

#[test]
fn parse_diagnostic_taxonomy_serde_roundtrip() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    let json = serde_json::to_string(&taxonomy).expect("serde serialization should succeed");
    let restored: ParseDiagnosticTaxonomy =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(taxonomy, restored);
}

#[test]
fn parse_event_materialization_error_serde_roundtrip() {
    let err = ParseEventMaterializationError::new(
        ParseEventMaterializationErrorCode::InvalidEventSequence,
        "bad seq".to_string(),
        Some(3),
    );
    let json = serde_json::to_string(&err).expect("serde serialization should succeed");
    let restored: ParseEventMaterializationError =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(err, restored);
}

// -----------------------------------------------------------------------
// Enrichment: helper functions
// -----------------------------------------------------------------------

#[test]
fn line_count_single_line() {
    assert_eq!(line_count("hello"), 1);
}

#[test]
fn line_count_multiple_lines() {
    assert_eq!(line_count("a\nb\nc"), 3);
}

#[test]
fn line_count_trailing_newline() {
    assert_eq!(line_count("a\n"), 2);
}

#[test]
fn line_count_recognizes_ecmascript_line_terminators_bd_21nbg() {
    for (source, expected) in [
        ("alpha\rbeta", 2),
        ("alpha\r\nbeta", 2),
        ("alpha\nbeta", 2),
        ("alpha\u{2028}beta", 2),
        ("alpha\u{2029}beta", 2),
        ("alpha\r\n\u{2028}\u{2029}", 4),
    ] {
        assert_eq!(line_count(source), expected, "{source:?}");
    }
}

#[test]
fn ecmascript_line_terminators_split_physical_statements_bd_21nbg() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let source = format!("first;{terminator}second;");
        let tree = parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{source:?}");
        assert_eq!(tree.body[0].span().start_line, 1, "{source:?}");
        assert_eq!(tree.body[0].span().end_line, 1, "{source:?}");
        assert_eq!(tree.body[1].span().start_line, 2, "{source:?}");
        assert_eq!(tree.body[1].span().end_line, 2, "{source:?}");

        let blank_line_source = format!("first;{terminator}{terminator}second;");
        let blank_line_tree = parser
            .parse(blank_line_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {blank_line_source:?}: {error}"));
        assert_eq!(blank_line_tree.body.len(), 2, "{blank_line_source:?}");
        assert_eq!(
            blank_line_tree.body[1].span().start_line,
            3,
            "{blank_line_source:?}"
        );
    }
}

#[test]
fn normalized_logical_lines_map_spans_to_physical_source_bd_crph5() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let source = format!("call({terminator}  value{terminator});  after;");
        let tree = parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{source:?}");

        let call_span = tree.body[0].span();
        assert_eq!(call_span.start_offset, 0, "{source:?}");
        assert_eq!(
            call_span.end_offset,
            source.find(';').expect("call terminator is present") as u64,
            "{source:?}"
        );
        assert_eq!(call_span.start_line, 1, "{source:?}");
        assert_eq!(call_span.start_column, 1, "{source:?}");
        assert_eq!(call_span.end_line, 3, "{source:?}");
        assert_eq!(call_span.end_column, 2, "{source:?}");

        let after_offset = source.find("after").expect("after is present") as u64;
        let after_span = tree.body[1].span();
        assert_eq!(after_span.start_offset, after_offset, "{source:?}");
        assert_eq!(after_span.end_offset, after_offset + 5, "{source:?}");
        assert_eq!(after_span.start_line, 3, "{source:?}");
        assert_eq!(after_span.start_column, 5, "{source:?}");
        assert_eq!(after_span.end_line, 3, "{source:?}");
        assert_eq!(after_span.end_column, 10, "{source:?}");
    }
}

#[test]
fn leading_dot_continuation_maps_across_trivia_gap_bd_crph5() {
    let parser = CanonicalEs2020Parser;
    let source = "value\n// gap\n  .method();\n  after;";
    let tree = parser
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
    assert_eq!(tree.body.len(), 2);

    let chained_span = tree.body[0].span();
    assert_eq!(chained_span.start_offset, 0);
    assert_eq!(
        chained_span.end_offset,
        source.find(';').expect("chain terminator is present") as u64
    );
    assert_eq!(chained_span.start_line, 1);
    assert_eq!(chained_span.start_column, 1);
    assert_eq!(chained_span.end_line, 3);
    assert_eq!(chained_span.end_column, 12);

    let after_offset = source.find("after").expect("after is present") as u64;
    let after_span = tree.body[1].span();
    assert_eq!(after_span.start_offset, after_offset);
    assert_eq!(after_span.end_offset, after_offset + 5);
    assert_eq!(after_span.start_line, 4);
    assert_eq!(after_span.start_column, 3);
    assert_eq!(after_span.end_line, 4);
    assert_eq!(after_span.end_column, 8);
}

#[test]
fn comment_gaps_and_multiline_blocks_map_physical_spans_bd_crph5() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let source = format!(
            "  first; // trailing é{terminator}{terminator}if (ready) {{{terminator}  work();{terminator}}}{terminator}  after;"
        );
        let tree = parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.body.len(), 3, "{source:?}");

        let first_span = tree.body[0].span();
        assert_eq!(first_span.start_offset, 2, "{source:?}");
        assert_eq!(first_span.end_offset, 7, "{source:?}");
        assert_eq!(first_span.start_line, 1, "{source:?}");
        assert_eq!(first_span.start_column, 3, "{source:?}");
        assert_eq!(first_span.end_line, 1, "{source:?}");
        assert_eq!(first_span.end_column, 8, "{source:?}");

        let block_start = source.find("if").expect("block start is present") as u64;
        let block_end = source.find('}').expect("block end is present") as u64 + 1;
        let block_span = tree.body[1].span();
        assert_eq!(block_span.start_offset, block_start, "{source:?}");
        assert_eq!(block_span.end_offset, block_end, "{source:?}");
        assert_eq!(block_span.start_line, 3, "{source:?}");
        assert_eq!(block_span.start_column, 1, "{source:?}");
        assert_eq!(block_span.end_line, 5, "{source:?}");
        assert_eq!(block_span.end_column, 2, "{source:?}");

        let after_offset = source.find("after").expect("after is present") as u64;
        let after_span = tree.body[2].span();
        assert_eq!(after_span.start_offset, after_offset, "{source:?}");
        assert_eq!(after_span.end_offset, after_offset + 5, "{source:?}");
        assert_eq!(after_span.start_line, 6, "{source:?}");
        assert_eq!(after_span.start_column, 3, "{source:?}");
        assert_eq!(after_span.end_line, 6, "{source:?}");
        assert_eq!(after_span.end_column, 8, "{source:?}");
    }
}

#[test]
fn quoted_multiline_spans_and_boundary_maps_remain_exact_bd_crph5() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let source = format!("const value = `a{terminator}b`;  next;");
        let tree = parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{source:?}");

        let template_span = tree.body[0].span();
        assert_eq!(template_span.start_offset, 0, "{source:?}");
        assert_eq!(
            template_span.end_offset,
            source.find(';').expect("template terminator is present") as u64,
            "{source:?}"
        );
        assert_eq!(template_span.start_line, 1, "{source:?}");
        assert_eq!(template_span.start_column, 1, "{source:?}");
        assert_eq!(template_span.end_line, 2, "{source:?}");
        assert_eq!(template_span.end_column, 3, "{source:?}");

        let next_offset = source.find("next").expect("next is present") as u64;
        let next_span = tree.body[1].span();
        assert_eq!(next_span.start_offset, next_offset, "{source:?}");
        assert_eq!(next_span.end_offset, next_offset + 4, "{source:?}");
        assert_eq!(next_span.start_line, 2, "{source:?}");
        assert_eq!(next_span.start_column, 6, "{source:?}");
        assert_eq!(next_span.end_line, 2, "{source:?}");
        assert_eq!(next_span.end_column, 10, "{source:?}");

        let stripped = strip_comments_to_whitespace(&source);
        for logical_line in merge_logical_lines(&stripped) {
            assert_eq!(
                logical_line.source_boundaries.len(),
                logical_line.text.len() + 1,
                "{source:?}"
            );
            assert!(
                logical_line
                    .source_boundaries
                    .windows(2)
                    .all(|window| window[0] <= window[1]),
                "{source:?}"
            );
        }
    }
}

#[test]
fn syntax_tree_root_span_ends_at_eof_byte_column_bd_4tt6s() {
    let parser = CanonicalEs2020Parser;
    let cases = [
        ("alpha", 1, 6),
        ("alpha\nbeta", 2, 5),
        ("alpha\n", 2, 1),
        ("alpha\r\nbeta", 2, 5),
        ("alpha\r\n", 2, 1),
        ("alpha\rbeta", 2, 5),
        ("alpha\r", 2, 1),
        ("alpha\u{2028}beta", 2, 5),
        ("alpha\u{2028}", 2, 1),
        ("alpha\u{2029}beta", 2, 5),
        ("alpha\u{2029}", 2, 1),
        ("'é'", 1, 5),
        ("alpha  ", 1, 8),
    ];

    for (source, expected_line, expected_column) in cases {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.span.end_offset, source.len() as u64, "{source:?}");
        assert_eq!(tree.span.end_line, expected_line, "{source:?}");
        assert_eq!(tree.span.end_column, expected_column, "{source:?}");
    }
}

#[test]
fn is_identifier_empty_returns_false() {
    assert!(!is_identifier(""));
}

#[test]
fn is_identifier_valid() {
    assert!(is_identifier("foo"));
    assert!(is_identifier("_bar"));
    assert!(is_identifier("$baz"));
    assert!(is_identifier("x2"));
}

#[test]
fn is_identifier_invalid() {
    assert!(!is_identifier("2x"));
    assert!(!is_identifier("foo bar"));
    assert!(!is_identifier("-x"));
}

#[test]
fn module_binding_identifier_rejects_keywords() {
    assert!(!is_module_binding_identifier("for"));
    assert!(!is_module_binding_identifier("await"));
    assert!(!is_module_binding_identifier("interface"));
}

#[test]
fn module_binding_identifier_accepts_valid_names() {
    assert!(is_module_binding_identifier("dep"));
    assert!(is_module_binding_identifier("_local1"));
}

#[test]
fn canonicalize_whitespace_normalizes() {
    assert_eq!(canonicalize_whitespace("  a   b  c  "), "a b c");
}

#[test]
fn canonicalize_whitespace_empty() {
    assert_eq!(canonicalize_whitespace("   "), "");
}

#[test]
fn is_identifier_start_cases() {
    assert!(is_identifier_start('a'));
    assert!(is_identifier_start('Z'));
    assert!(is_identifier_start('_'));
    assert!(is_identifier_start('$'));
    assert!(!is_identifier_start('0'));
    assert!(!is_identifier_start('-'));
    // Non-ASCII letters (ID_Start), including Other_ID_Start (U+2118).
    for ch in ['\u{3C0}', '\u{410}', '\u{E9}', '\u{4E2D}', '\u{2118}'] {
        assert!(is_identifier_start(ch), "{ch:?}");
    }
    // Combining marks, digits, ZWJ and punctuation cannot start one.
    for ch in ['\u{301}', '\u{660}', '\u{200D}', '\u{B7}', '\u{2014}'] {
        assert!(!is_identifier_start(ch), "{ch:?}");
    }
}

#[test]
fn is_identifier_continue_unicode_cases() {
    for ch in ['\u{301}', '\u{660}', '\u{200C}', '\u{200D}', '\u{B7}'] {
        assert!(is_identifier_continue(ch), "{ch:?}");
    }
    assert!(!is_identifier_continue('\u{2014}'));
    assert!(is_identifier("\u{3C0}"));
    assert!(is_identifier("caf\u{E9}\u{301}"));
    assert!(!is_identifier("\u{301}x"));
}

#[test]
fn is_identifier_continue_cases() {
    assert!(is_identifier_continue('a'));
    assert!(is_identifier_continue('0'));
    assert!(is_identifier_continue('_'));
    assert!(is_identifier_continue('$'));
    assert!(!is_identifier_continue('-'));
    assert!(!is_identifier_continue(' '));
}

// -- Enrichment: PearlTower 2026-02-26 --

#[test]
fn parse_diagnostic_category_serde_roundtrip() {
    for cat in [
        ParseDiagnosticCategory::Input,
        ParseDiagnosticCategory::Goal,
        ParseDiagnosticCategory::Syntax,
        ParseDiagnosticCategory::Encoding,
        ParseDiagnosticCategory::Resource,
        ParseDiagnosticCategory::System,
    ] {
        let json = serde_json::to_string(&cat).expect("serde serialization should succeed");
        let back: ParseDiagnosticCategory =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(cat, back);
    }
}

#[test]
fn parse_diagnostic_severity_serde_roundtrip() {
    for sev in [
        ParseDiagnosticSeverity::Error,
        ParseDiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&sev).expect("serde serialization should succeed");
        let back: ParseDiagnosticSeverity =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sev, back);
    }
}

#[test]
fn parse_diagnostic_severity_as_str_all_distinct() {
    let strs: std::collections::BTreeSet<_> = [
        ParseDiagnosticSeverity::Error.as_str(),
        ParseDiagnosticSeverity::Fatal.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn parse_error_is_std_error() {
    let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn taxonomy_rule_for_finds_matching_code() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in &ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(*code);
        assert!(rule.is_some(), "rule_for({:?}) returned None", code);
        assert_eq!(
            rule.expect("serde serialization should succeed")
                .parse_error_code,
            *code
        );
    }
}

#[test]
fn taxonomy_rule_for_severity_matches_code_method() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in &ParseErrorCode::ALL {
        let rule = taxonomy
            .rule_for(*code)
            .expect("serde serialization should succeed");
        assert_eq!(rule.severity, code.diagnostic_severity());
        assert_eq!(rule.category, code.diagnostic_category());
    }
}

#[test]
fn grammar_coverage_status_serde_all_variants_distinct() {
    let variants = [
        GrammarCoverageStatus::Supported,
        GrammarCoverageStatus::Partial,
        GrammarCoverageStatus::Unsupported,
        GrammarCoverageStatus::NotApplicable,
    ];
    let mut names = std::collections::BTreeSet::new();
    for v in &variants {
        let json = serde_json::to_string(v).expect("serde serialization should succeed");
        let back: GrammarCoverageStatus =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(v, &back);
        names.insert(json);
    }
    assert_eq!(names.len(), variants.len());
}

#[test]
fn grammar_family_coverage_partial_roundtrip() {
    let fam = GrammarFamilyCoverage {
        family_id: "expressions".to_string(),
        es2020_clause: "12.2".to_string(),
        script_goal: GrammarCoverageStatus::Partial,
        module_goal: GrammarCoverageStatus::Unsupported,
        notes: "WIP".to_string(),
    };
    let json = serde_json::to_string(&fam).expect("serde serialization should succeed");
    let back: GrammarFamilyCoverage =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(fam, back);
}

#[test]
fn parse_error_display_includes_source_label() {
    let err = ParseError::new(
        ParseErrorCode::InvalidUtf8,
        "bad encoding",
        "input.js",
        None,
    );
    let display = err.to_string();
    assert!(display.contains("input.js"), "display: {display}");
}

#[test]
fn canonicalize_whitespace_tabs_and_newlines() {
    assert_eq!(canonicalize_whitespace("a\t\nb"), "a b");
}

// -- Enrichment: PearlTower batch 2 (2026-02-26) --

// -- parse_quoted_string edge cases --

#[test]
fn parse_quoted_string_too_short_returns_none() {
    assert!(parse_quoted_string("").is_none());
    assert!(parse_quoted_string("x").is_none());
}

#[test]
fn parse_quoted_string_mismatched_quotes_returns_none() {
    assert!(parse_quoted_string("'hello\"").is_none());
    assert!(parse_quoted_string("\"hello'").is_none());
}

#[test]
fn parse_quoted_string_with_embedded_newline_returns_none() {
    assert!(parse_quoted_string("'hel\nlo'").is_none());
    assert!(parse_quoted_string("\"hel\rlo\"").is_none());
}

#[test]
fn parse_quoted_string_valid_extracts_inner() {
    assert_eq!(
        parse_quoted_string("'abc'").and_then(|value| value.as_str().map(str::to_string)),
        Some("abc".to_string())
    );
    assert_eq!(
        parse_quoted_string("\"xyz\"").and_then(|value| value.as_str().map(str::to_string)),
        Some("xyz".to_string())
    );
    assert_eq!(
        parse_quoted_string("''").and_then(|value| value.as_str().map(str::to_string)),
        Some(String::new())
    );
}

// -- parse_i64_numeric_literal edge cases --

#[test]
fn parse_i64_numeric_literal_bare_minus_returns_none() {
    assert!(parse_i64_numeric_literal("-").is_none());
}

#[test]
fn parse_i64_numeric_literal_non_numeric_returns_none() {
    assert!(parse_i64_numeric_literal("abc").is_none());
    assert!(parse_i64_numeric_literal("12a").is_none());
    assert!(parse_i64_numeric_literal("-12a").is_none());
}

#[test]
fn parse_i64_numeric_literal_valid_values() {
    assert_eq!(parse_i64_numeric_literal("0"), Some(0));
    assert_eq!(parse_i64_numeric_literal("42"), Some(42));
    assert_eq!(parse_i64_numeric_literal("-7"), Some(-7));
}

#[test]
fn parse_i64_numeric_literal_hex() {
    assert_eq!(parse_i64_numeric_literal("0xFF"), Some(255));
    assert_eq!(parse_i64_numeric_literal("0x1A"), Some(26));
    assert_eq!(parse_i64_numeric_literal("0X10"), Some(16));
    assert_eq!(parse_i64_numeric_literal("-0xff"), Some(-255));
}

#[test]
fn parse_i64_numeric_literal_octal() {
    assert_eq!(parse_i64_numeric_literal("0o77"), Some(63));
    assert_eq!(parse_i64_numeric_literal("0O10"), Some(8));
    assert_eq!(parse_i64_numeric_literal("-0o10"), Some(-8));
}

#[test]
fn parse_i64_numeric_literal_binary() {
    assert_eq!(parse_i64_numeric_literal("0b1010"), Some(10));
    assert_eq!(parse_i64_numeric_literal("0B11111111"), Some(255));
    assert_eq!(parse_i64_numeric_literal("-0b100"), Some(-4));
}

#[test]
fn parse_i64_numeric_literal_separators() {
    assert_eq!(parse_i64_numeric_literal("1_000"), Some(1000));
    assert_eq!(parse_i64_numeric_literal("0xFF_FF"), Some(65535));
}

/// `_n`, `_1`, `_0x1f` and `__n` are identifiers: a literal starts with a
/// digit and a separator sits between two digits.
#[test]
fn identifiers_with_leading_underscores_are_not_numeric_literals() {
    for spelling in ["_1", "_0x1f", "1_", "1__0", "_", "0x_1"] {
        assert!(parse_i64_numeric_literal(spelling).is_none(), "{spelling}");
    }
    for spelling in ["_n", "__n", "_1n", "1_n"] {
        assert!(
            parse_bigint_numeric_literal(spelling).is_none(),
            "{spelling}"
        );
    }
    for spelling in ["_1.5", "1_.5", "-_2.5"] {
        assert!(parse_f64_numeric_literal(spelling).is_none(), "{spelling}");
    }
    assert_eq!(
        parse_bigint_numeric_literal("1_000n").as_deref(),
        Some("1000")
    );
    assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
}

#[test]
fn parse_i64_numeric_literal_invalid_bases() {
    assert!(parse_i64_numeric_literal("0x").is_none());
    assert!(parse_i64_numeric_literal("0o").is_none());
    assert!(parse_i64_numeric_literal("0b").is_none());
    assert!(parse_i64_numeric_literal("0xGG").is_none());
    assert!(parse_i64_numeric_literal("0o89").is_none());
    assert!(parse_i64_numeric_literal("0b23").is_none());
}

// -- parse_f64_numeric_literal tests --

#[test]
fn parse_f64_numeric_literal_decimal() {
    assert_eq!(parse_f64_numeric_literal("1.5"), Some(1.5));
    assert_eq!(parse_f64_numeric_literal("2.25"), Some(2.25));
    assert_eq!(parse_f64_numeric_literal("0.0"), Some(0.0));
}

#[test]
fn parse_f64_numeric_literal_leading_dot() {
    assert_eq!(parse_f64_numeric_literal(".5"), Some(0.5));
    assert_eq!(parse_f64_numeric_literal(".123"), Some(0.123));
}

#[test]
fn parse_f64_numeric_literal_trailing_dot() {
    assert_eq!(parse_f64_numeric_literal("1."), Some(1.0));
    assert_eq!(parse_f64_numeric_literal("42."), Some(42.0));
}

#[test]
fn parse_f64_numeric_literal_scientific() {
    assert_eq!(parse_f64_numeric_literal("1e10"), Some(1e10));
    assert_eq!(parse_f64_numeric_literal("1E10"), Some(1e10));
    assert_eq!(parse_f64_numeric_literal("1.5e-3"), Some(1.5e-3));
    assert_eq!(parse_f64_numeric_literal("2.5E+2"), Some(250.0));
}

#[test]
fn global_value_names_are_not_numeric_literals() {
    assert_eq!(parse_f64_numeric_literal("Infinity"), None);
    assert_eq!(parse_f64_numeric_literal("-Infinity"), None);
    assert_eq!(parse_f64_numeric_literal("NaN"), None);
    // An overflowing numeric literal is still a number, independently
    // of any source binding named Infinity.
    assert_eq!(parse_f64_numeric_literal("1e999"), Some(f64::INFINITY));
}

#[test]
fn parse_f64_numeric_literal_with_separators() {
    assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
    assert_eq!(parse_f64_numeric_literal("1.5_00"), Some(1.5));
    // bd-9vouw.176: a literal may start with its decimal point (Node
    // v22.2.0 values); `._1` is not a literal.
    assert_eq!(parse_f64_numeric_literal(".0_1e2"), Some(1.0));
    assert_eq!(parse_f64_numeric_literal(".1_01e2"), Some(10.1));
    assert_eq!(parse_f64_numeric_literal(".00_01e2"), Some(0.01));
    assert_eq!(parse_f64_numeric_literal(".5_5"), Some(0.55));
    assert_eq!(parse_f64_numeric_literal("._1"), None);
}

#[test]
fn parse_f64_numeric_literal_integer_without_dot_or_exp_returns_none() {
    // Pure integers should be handled by parse_i64_numeric_literal
    assert!(parse_f64_numeric_literal("42").is_none());
    assert!(parse_f64_numeric_literal("0xFF").is_none());
}

#[test]
fn integer_literals_beyond_i64_are_numbers_bd_6vl81() {
    // These used to fall through to Expression::Raw and evaluate as
    // strings. Expected values are Node's (v22.2.0) Number results.
    assert_eq!(
        parse_f64_numeric_literal("123456789012345680000"),
        Some(123_456_789_012_345_680_000.0)
    );
    assert_eq!(
        parse_f64_numeric_literal("9223372036854775808"),
        Some(9_223_372_036_854_775_808.0)
    );
    assert_eq!(
        parse_f64_numeric_literal("-9223372036854775809"),
        Some(-9_223_372_036_854_775_808.0)
    );
    assert_eq!(
        parse_f64_numeric_literal("0xFFFFFFFFFFFFFFFFF"),
        Some(295_147_905_179_352_830_000.0)
    );
    assert_eq!(
        parse_f64_numeric_literal("0b1"),
        None,
        "an i64-representable radix literal stays an integer"
    );
    assert_eq!(
        parse_f64_numeric_literal("1_000_000_000_000_000_000_000"),
        Some(1e21)
    );
    assert!(parse_f64_numeric_literal("0xZZ").is_none());

    let tree = CanonicalEs2020Parser
        .parse("const n = 123456789012345680000;", ParseGoal::Script)
        .expect("large integer literal parses");
    assert!(
        !format!("{:?}", tree.canonical_value()).contains("\"raw\""),
        "a large integer literal must not become Expression::Raw"
    );
}

#[test]
fn bigint_radix_literals_parse_exactly_bd_6vl81() {
    // `e`/`E` are hex digits: this used to be rejected as an exponent.
    assert_eq!(
        parse_bigint_numeric_literal("0xFEDCBA9876543210n").as_deref(),
        Some("18364758544493064720")
    );
    assert_eq!(parse_bigint_numeric_literal("0xen").as_deref(), Some("14"));
    assert_eq!(
        parse_bigint_numeric_literal("-0xFFn").as_deref(),
        Some("-255")
    );
    // Past u128 the conversion stays exact (expected values from Python
    // arbitrary-precision integers).
    assert_eq!(
        parse_bigint_numeric_literal(&format!("0x{}n", "FEDCBA9876543210".repeat(3))).as_deref(),
        Some("6249203505451628849692820439375744481966954417427815084560")
    );
    assert_eq!(
        parse_bigint_numeric_literal(&format!("0o{}n", "7".repeat(50))).as_deref(),
        Some("1427247692705959881058285969449495136382746623")
    );
    assert_eq!(
        parse_bigint_numeric_literal(&format!("0b{}n", "1".repeat(130))).as_deref(),
        Some("1361129467683753853853498429727072845823")
    );
    // Decimal exponents and fractions are still not BigInt literals.
    assert!(parse_bigint_numeric_literal("1e5n").is_none());
    assert!(parse_bigint_numeric_literal("1.5n").is_none());
    assert!(parse_bigint_numeric_literal("0xGn").is_none());
}

#[test]
fn parse_f64_numeric_literal_empty_returns_none() {
    assert!(parse_f64_numeric_literal("").is_none());
    assert!(parse_f64_numeric_literal("   ").is_none());
}

// -- split_statement_segments with nested delimiters --

#[test]
fn split_statement_segments_semicolon_inside_parens_does_not_split() {
    let segments = split_statement_segments("f(a;b);x");
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].2, "f(a;b)");
    assert_eq!(segments[1].2, "x");
}

#[test]
fn split_statement_segments_semicolon_inside_brackets_does_not_split() {
    let segments = split_statement_segments("a[b;c];d");
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].2, "a[b;c]");
    assert_eq!(segments[1].2, "d");
}

#[test]
fn split_statement_segments_semicolon_inside_braces_does_not_split() {
    let segments = split_statement_segments("{a;b};c");
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].2, "{a;b}");
    assert_eq!(segments[1].2, "c");
}

#[test]
fn split_statement_segments_escape_in_string_does_not_close_quote() {
    let segments = split_statement_segments(r#"'a\'b';x"#);
    assert_eq!(segments.len(), 2);
}

// -- ParseFailureWitness::canonical_value --

#[test]
fn parse_failure_witness_canonical_value_has_expected_keys() {
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::SourceBytes),
        source_bytes: 100,
        token_count: 10,
        max_recursion_observed: 5,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let cv = witness.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        assert!(map.contains_key("mode"));
        assert!(map.contains_key("budget_kind"));
        assert!(map.contains_key("source_bytes"));
        assert!(map.contains_key("token_count"));
        assert!(map.contains_key("max_recursion_observed"));
        assert!(map.contains_key("max_source_bytes"));
        assert!(map.contains_key("max_token_count"));
        assert!(map.contains_key("max_recursion_depth"));
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

#[test]
fn parse_failure_witness_canonical_value_null_budget_kind() {
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: None,
        source_bytes: 0,
        token_count: 0,
        max_recursion_observed: 0,
        max_source_bytes: 0,
        max_token_count: 0,
        max_recursion_depth: 0,
    };
    let cv = witness.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        assert_eq!(map.get("budget_kind"), Some(&CanonicalValue::Null));
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

// -- materialize_from_syntax_tree --

#[test]
fn materialize_from_syntax_tree_succeeds_for_valid_ir() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default 42", ParseGoal::Module)
        .expect("parse");
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    let materialized = ir
        .materialize_from_syntax_tree(&tree)
        .expect("should succeed");
    assert_eq!(
        materialized.syntax_tree.canonical_hash(),
        tree.canonical_hash()
    );
    assert_eq!(materialized.statement_nodes.len(), tree.body.len());
}

// -- ParseEventIr::from_parse_source --

#[test]
fn parse_event_ir_from_parse_source_has_source_text_payload() {
    let parser = CanonicalEs2020Parser;
    let source = "true";
    let tree = parser.parse(source, ParseGoal::Script).expect("parse");
    let ir =
        ParseEventIr::from_parse_source(&tree, source, "<inline>", ParserMode::ScalarReference);
    assert_eq!(ir.events[0].payload_kind.as_deref(), Some("source_text"));
    assert!(ir.events[0].payload_hash.is_some());
}

// -- Materialization error cases --

#[test]
fn materialize_rejects_unsupported_contract_version() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    ir.contract_version = "bogus".to_string();
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("unsupported contract");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::UnsupportedContractVersion
    );
}

#[test]
fn materialize_rejects_unsupported_schema_version() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    ir.schema_version = "bogus".to_string();
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("unsupported schema");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::UnsupportedSchemaVersion
    );
}

#[test]
fn materialize_rejects_goal_mismatch() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    ir.goal = ParseGoal::Module;
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("goal mismatch");
    assert_eq!(err.code, ParseEventMaterializationErrorCode::GoalMismatch);
}

#[test]
fn materialize_rejects_empty_event_stream() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    ir.events.clear();
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("empty events");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::MissingParseStarted
    );
}

#[test]
fn materialize_rejects_missing_parse_started() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    // Replace first event with a non-ParseStarted event
    ir.events[0].kind = ParseEventKind::ParseCompleted;
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("missing parse_started");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::MissingParseStarted
    );
}

#[test]
fn materialize_rejects_missing_parse_completed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    let last_idx = ir.events.len() - 1;
    ir.events[last_idx].kind = ParseEventKind::ParseStarted;
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("missing parse_completed");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::MissingParseCompleted
    );
}

#[test]
fn materialize_rejects_invalid_event_sequence() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    // Create a gap in sequence numbers
    if ir.events.len() > 2 {
        ir.events[1].sequence = 99;
    }
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("invalid sequence");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::InvalidEventSequence
    );
}

#[test]
fn materialize_rejects_inconsistent_event_envelope() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    if ir.events.len() > 1 {
        ir.events[1].trace_id = "rogue-trace".to_string();
    }
    let err = ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("inconsistent envelope");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::InconsistentEventEnvelope
    );
}

#[test]
fn materialize_from_source_rejects_mode_mismatch() {
    let parser = CanonicalEs2020Parser;
    let source = "42";
    let options = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    result.expect("parse should succeed");
    // ParserMode only has ScalarReference today, so we cannot test a
    // true mode mismatch.  Instead we trigger a materializer rejection
    // via statement-count mismatch (removing events from the IR).
    let mut modified_ir = event_ir;
    let tree = parser.parse(source, ParseGoal::Script).expect("parse");
    // Remove a statement event to trigger count mismatch
    modified_ir
        .events
        .retain(|event| event.kind != ParseEventKind::StatementParsed);
    // Re-number sequences for the retained events
    for (i, event) in modified_ir.events.iter_mut().enumerate() {
        event.sequence = i as u64;
    }
    let err = modified_ir
        .materialize_from_syntax_tree(&tree)
        .expect_err("statement count mismatch");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::StatementCountMismatch
    );
}

// -- Source bytes budget exhaustion --

#[test]
fn source_bytes_budget_exhaustion() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 2,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        },
    };
    let err = parser
        .parse_with_options("long source text", ParseGoal::Script, &options)
        .expect_err("source bytes budget should fail");
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    let witness = err.witness.expect("should have witness");
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::SourceBytes));
    assert!(witness.source_bytes > witness.max_source_bytes);
}

// -- GrammarCompletenessMatrix::summary edge cases --

#[test]
fn grammar_completeness_summary_empty_families() {
    let matrix = GrammarCompletenessMatrix {
        schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
        parser_mode: ParserMode::ScalarReference,
        families: vec![],
    };
    let summary = matrix.summary();
    assert_eq!(summary.family_count, 0);
    assert_eq!(summary.completeness_millionths, 0);
}

#[test]
fn grammar_completeness_summary_all_supported() {
    let matrix = GrammarCompletenessMatrix {
        schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
        parser_mode: ParserMode::ScalarReference,
        families: vec![GrammarFamilyCoverage {
            family_id: "test".to_string(),
            es2020_clause: "1.0".to_string(),
            script_goal: GrammarCoverageStatus::Supported,
            module_goal: GrammarCoverageStatus::Supported,
            notes: String::new(),
        }],
    };
    let summary = matrix.summary();
    assert_eq!(summary.family_count, 1);
    assert_eq!(summary.supported_families, 1);
    assert_eq!(summary.unsupported_families, 0);
    assert_eq!(summary.completeness_millionths, 1_000_000);
}

// -- advance_utf8_boundary_safe --

#[test]
fn advance_utf8_boundary_safe_past_end_returns_len() {
    let bytes = b"abc";
    assert_eq!(advance_utf8_boundary_safe(bytes, 3), 3);
    assert_eq!(advance_utf8_boundary_safe(bytes, 5), 3);
}

#[test]
fn advance_utf8_boundary_safe_ascii_advances_one() {
    let bytes = b"abc";
    assert_eq!(advance_utf8_boundary_safe(bytes, 0), 1);
}

#[test]
fn advance_utf8_boundary_safe_multibyte() {
    // é is two bytes: 0xC3 0xA9
    let bytes = "é".as_bytes();
    assert_eq!(bytes.len(), 2);
    assert_eq!(advance_utf8_boundary_safe(bytes, 0), 2);
}

// -- count_lexical_tokens edge cases --

#[test]
fn count_lexical_tokens_empty_returns_zero() {
    assert_eq!(count_lexical_tokens(""), 0);
}

#[test]
fn count_lexical_tokens_whitespace_only_returns_zero() {
    assert_eq!(count_lexical_tokens("   \t\n  "), 0);
}

#[test]
fn count_lexical_tokens_two_char_operators() {
    // == is one token, a is one, b is one => 3
    assert_eq!(count_lexical_tokens("a==b"), 3);
}

// -- export empty clause rejected --

#[test]
fn export_empty_clause_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export ", ParseGoal::Module)
        .expect_err("empty export clause");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

// -- statement_kind_label --

#[test]
fn statement_kind_label_covers_all_variants() {
    let span = SourceSpan::new(0, 1, 1, 1, 1, 1);
    assert_eq!(
        statement_kind_label(&Statement::Import(ImportDeclaration {
            import_attributes: Default::default(),
            clause: ImportClause::SideEffect,
            binding: None,
            source: "m".into(),
            span: span.clone(),
        })),
        "import"
    );
    assert_eq!(
        statement_kind_label(&Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("{}".into()),
            span: span.clone(),
        })),
        "export"
    );
    assert_eq!(
        statement_kind_label(&Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("x".to_string()),
                initializer: Some(Expression::NumericLiteral(1)),
                span: span.clone(),
            }],
            span: span.clone(),
        })),
        "variable_declaration"
    );
    assert_eq!(
        statement_kind_label(&Statement::Expression(ExpressionStatement {
            expression: Expression::NullLiteral,
            span,
        })),
        "expression"
    );
}

// -- ParseDiagnosticEnvelope canonical_value key coverage --

#[test]
fn parse_diagnostic_envelope_canonical_value_has_all_keys() {
    let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "<inline>", None);
    let envelope = normalize_parse_error(&err);
    let cv = envelope.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        for key in [
            "schema_version",
            "taxonomy_version",
            "hash_algorithm",
            "hash_prefix",
            "parse_error_code",
            "diagnostic_code",
            "category",
            "severity",
            "message_template",
            "source_label",
            "span",
            "budget_kind",
            "witness",
        ] {
            assert!(map.contains_key(key), "missing key: {key}");
        }
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

// -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

#[test]
fn parse_event_serde_roundtrip() {
    let e = ParseEvent {
        sequence: 1,
        kind: ParseEventKind::StatementParsed,
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Script,
        source_label: "test.js".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "parser".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        statement_index: Some(0),
        span: Some(SourceSpan::new(0, 10, 1, 1, 1, 11)),
        payload_kind: Some("statement".to_string()),
        payload_hash: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&e).expect("serde serialization should succeed");
    let back: ParseEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(e, back);
}

#[test]
fn parse_event_minimal_serde_roundtrip() {
    let e = ParseEvent {
        sequence: 0,
        kind: ParseEventKind::ParseStarted,
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Module,
        source_label: "mod.js".to_string(),
        trace_id: "t-2".to_string(),
        decision_id: "d-2".to_string(),
        policy_id: "p-2".to_string(),
        component: "parser".to_string(),
        outcome: "started".to_string(),
        error_code: None,
        statement_index: None,
        span: None,
        payload_kind: None,
        payload_hash: None,
    };
    let json = serde_json::to_string(&e).expect("serde serialization should succeed");
    let back: ParseEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(e, back);
}

#[test]
fn materialized_statement_node_serde_roundtrip() {
    let n = MaterializedStatementNode {
        node_id: "node-001".to_string(),
        sequence: 1,
        statement_index: 0,
        payload_hash: "hash-abc".to_string(),
        span: SourceSpan::new(0, 20, 1, 1, 1, 21),
    };
    let json = serde_json::to_string(&n).expect("serde serialization should succeed");
    let back: MaterializedStatementNode =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(n, back);
}

#[test]
fn materialized_syntax_tree_serde_roundtrip() {
    let tree = MaterializedSyntaxTree {
        schema_version: MaterializedSyntaxTree::schema_version().to_string(),
        contract_version: MaterializedSyntaxTree::contract_version().to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "parser".to_string(),
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Script,
        source_label: "test.js".to_string(),
        root_node_id: "root-001".to_string(),
        statement_nodes: vec![MaterializedStatementNode {
            node_id: "node-001".to_string(),
            sequence: 1,
            statement_index: 0,
            payload_hash: "hash-abc".to_string(),
            span: SourceSpan::new(0, 10, 1, 1, 1, 11),
        }],
        syntax_tree: SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: SourceSpan::new(0, 10, 1, 1, 1, 11),
        },
    };
    let json = serde_json::to_string(&tree).expect("serde serialization should succeed");
    let back: MaterializedSyntaxTree =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(tree, back);
    assert_eq!(back.statement_nodes.len(), 1);
}

// -----------------------------------------------------------------------
// Enrichment: binary expression parsing (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

fn parse_script(source: &str) -> SyntaxTree {
    let parser = CanonicalEs2020Parser;
    parser
        .parse(source, ParseGoal::Script)
        .expect("parse should succeed")
}

fn parse_single_script_statement(source: &str) -> ParseResult<Statement> {
    let options = ParserOptions::default();
    let span = SourceSpan::new(0, source.len() as u64, 1, 1, 1, source.len() as u64 + 1);
    let mut context = ParseExecutionContext {
        source_label: "test.js",
        options: &options,
        source_bytes: source.len() as u64,
        token_count: 0,
        max_recursion_observed: 0,
        statement_depth: 0,
        pattern_depth: 0,
        strict_mode: false,
        script_this: true,
        module_goal: false,
        super_property_allowed: false,
        await_context: false,
        yield_context: false,
        super_call: SuperCallContext::Forbidden,
        static_block_await: false,
        formal_parameters: false,
        private_name_scopes: Vec::new(),
        function_sources: FunctionSourceMap::default(),
        template_sites: 0,
    };
    parse_statement(source, ParseGoal::Script, span, &mut context)
}

fn first_expr(tree: &SyntaxTree) -> &Expression {
    match &tree.body[0] {
        Statement::Expression(es) => &es.expression,
        other => panic!("expected Expression statement, got {:?}", other),
    }
}

// bd-fqlfw.1.1 (E1.T1): expression-level Member/Call nodes — the carriers of
// capability/IFC-relevant accessors (`process.env.X`, bare `eval(...)`) — carry
// a `SourceSpan` populated by the parser. Spans are currently statement-granular
// (the enclosing source region); precise sub-expression offsets are a follow-up.
#[test]
fn member_and_call_expressions_carry_source_spans_bd_fqlfw_1_1() {
    // `process.env.HOME` parses to a Member accessor that carries a span.
    let src = "process.env.HOME";
    let tree = parse_script(src);
    let Statement::Expression(stmt) = &tree.body[0] else {
        panic!("expected expression statement");
    };
    let stmt_span = stmt.span;
    match &stmt.expression {
        Expression::Member { span, .. } => {
            let span = span.expect("parser must populate Member span");
            // The accessor span maps onto the real source region.
            assert_eq!(span, stmt_span, "member span maps to the source region");
            assert!(
                span.start_offset <= span.end_offset && span.end_offset <= src.len() as u64 + 1,
                "member span must map into source offsets (got {span:?})"
            );
        }
        other => panic!("expected Member, got {other:?}"),
    }

    // A bare `eval(...)` call — a dynamic-code accessor — also carries a span.
    let src = "eval(\"x\")";
    let tree = parse_script(src);
    match first_expr(&tree) {
        Expression::Call { span, .. } => {
            let span = span.expect("parser must populate Call span");
            assert!(
                span.start_offset <= span.end_offset && span.end_offset <= src.len() as u64 + 1,
                "call span must map into source offsets (got {span:?})"
            );
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn binary_addition() {
    let tree = parse_script("a + b");
    match first_expr(&tree) {
        Expression::Binary {
            operator,
            left,
            right,
        } => {
            assert_eq!(*operator, BinaryOperator::Add);
            assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "a"));
            assert!(matches!(right.as_ref(), Expression::Identifier(n) if n == "b"));
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_precedence_mul_over_add() {
    // a + b * c should parse as a + (b * c)
    let tree = parse_script("a + b * c");
    match first_expr(&tree) {
        Expression::Binary {
            operator,
            left,
            right,
        } => {
            assert_eq!(*operator, BinaryOperator::Add);
            assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "a"));
            match right.as_ref() {
                Expression::Binary {
                    operator: inner_op, ..
                } => {
                    assert_eq!(*inner_op, BinaryOperator::Multiply);
                }
                other => panic!("expected Binary for rhs, got {other:?}"),
            }
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_strict_equality() {
    let tree = parse_script("x === y");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::StrictEqual);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_logical_and() {
    let tree = parse_script("a && b");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::LogicalAnd);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_logical_or() {
    let tree = parse_script("a || b");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::LogicalOr);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_nullish_coalescing() {
    let tree = parse_script("a ?? b");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::NullishCoalescing);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_comparison_operators() {
    for (src, expected_op) in [
        ("a < b", BinaryOperator::LessThan),
        ("a > b", BinaryOperator::GreaterThan),
        ("a <= b", BinaryOperator::LessThanOrEqual),
        ("a >= b", BinaryOperator::GreaterThanOrEqual),
        ("a == b", BinaryOperator::Equal),
        ("a != b", BinaryOperator::NotEqual),
        ("a !== b", BinaryOperator::StrictNotEqual),
    ] {
        let tree = parse_script(src);
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, expected_op, "failed for: {src}");
            }
            other => panic!("expected Binary for {src}, got {other:?}"),
        }
    }
}

#[test]
fn binary_bitwise_operators() {
    for (src, expected_op) in [
        ("a & b", BinaryOperator::BitwiseAnd),
        ("a | b", BinaryOperator::BitwiseOr),
        ("a ^ b", BinaryOperator::BitwiseXor),
        ("a << b", BinaryOperator::LeftShift),
        ("a >> b", BinaryOperator::RightShift),
        ("a >>> b", BinaryOperator::UnsignedRightShift),
    ] {
        let tree = parse_script(src);
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, expected_op, "failed for: {src}");
            }
            other => panic!("expected Binary for {src}, got {other:?}"),
        }
    }
}

#[test]
fn unary_logical_not() {
    let tree = parse_script("!x");
    match first_expr(&tree) {
        Expression::Unary { operator, argument } => {
            assert_eq!(*operator, UnaryOperator::LogicalNot);
            assert!(matches!(argument.as_ref(), Expression::Identifier(n) if n == "x"));
        }
        other => panic!("expected Unary, got {other:?}"),
    }
}

#[test]
fn unary_bitwise_not() {
    let tree = parse_script("~x");
    match first_expr(&tree) {
        Expression::Unary { operator, .. } => {
            assert_eq!(*operator, UnaryOperator::BitwiseNot);
        }
        other => panic!("expected Unary, got {other:?}"),
    }
}

#[test]
fn unary_typeof() {
    let tree = parse_script("typeof x");
    match first_expr(&tree) {
        Expression::Unary { operator, argument } => {
            assert_eq!(*operator, UnaryOperator::Typeof);
            assert!(matches!(argument.as_ref(), Expression::Identifier(n) if n == "x"));
        }
        other => panic!("expected Unary, got {other:?}"),
    }
}

#[test]
fn unary_void() {
    let tree = parse_script("void 0");
    match first_expr(&tree) {
        Expression::Unary { operator, argument } => {
            assert_eq!(*operator, UnaryOperator::Void);
            assert!(matches!(argument.as_ref(), Expression::NumericLiteral(0)));
        }
        other => panic!("expected Unary, got {other:?}"),
    }
}

#[test]
fn unary_delete() {
    let tree = parse_script("delete obj");
    match first_expr(&tree) {
        Expression::Unary { operator, .. } => {
            assert_eq!(*operator, UnaryOperator::Delete);
        }
        other => panic!("expected Unary, got {other:?}"),
    }
}

#[test]
fn assignment_simple() {
    let tree = parse_script("x = 42");
    match first_expr(&tree) {
        Expression::Assignment {
            operator,
            left,
            right,
            assignment_strictness,
        } => {
            assert_eq!(*operator, AssignmentOperator::Assign);
            assert_eq!(*assignment_strictness, AssignmentStrictness::Sloppy);
            assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "x"));
            assert!(matches!(right.as_ref(), Expression::NumericLiteral(42)));
        }
        other => panic!("expected Assignment, got {other:?}"),
    }
}

#[test]
fn assignment_add_assign() {
    let tree = parse_script("x += 1");
    match first_expr(&tree) {
        Expression::Assignment { operator, .. } => {
            assert_eq!(*operator, AssignmentOperator::AddAssign);
        }
        other => panic!("expected Assignment, got {other:?}"),
    }
}

#[test]
fn postfix_updates_keep_token_boundaries_before_comparisons() {
    for (update, expected_update) in [
        ("++", AssignmentOperator::PostIncrementAssign),
        ("--", AssignmentOperator::PostDecrementAssign),
    ] {
        for (comparison, expected_comparison) in [
            ("==", BinaryOperator::Equal),
            ("===", BinaryOperator::StrictEqual),
            ("!=", BinaryOperator::NotEqual),
            ("!==", BinaryOperator::StrictNotEqual),
            ("<", BinaryOperator::LessThan),
            (">", BinaryOperator::GreaterThan),
            ("<=", BinaryOperator::LessThanOrEqual),
            (">=", BinaryOperator::GreaterThanOrEqual),
        ] {
            let source = format!("counter{update}{comparison}0;");
            let tree = parse_script(&source);
            let Expression::Binary {
                operator,
                left,
                right,
            } = first_expr(&tree)
            else {
                panic!("{source}: comparison must not become assignment or Raw");
            };
            assert_eq!(*operator, expected_comparison, "{source}");
            let Expression::Assignment { operator, left, .. } = left.as_ref() else {
                panic!("{source}: comparison must retain its postfix update");
            };
            assert_eq!(*operator, expected_update, "{source}");
            assert!(matches!(left.as_ref(), Expression::Identifier(name) if name == "counter"));
            assert!(matches!(right.as_ref(), Expression::NumericLiteral(0)));
        }
    }
}

#[test]
fn update_token_consumption_still_rejects_invalid_assignment_targets() {
    for source in [
        "counter++=1;",
        "counter--=1;",
        "counter+++=1;",
        "counter---=1;",
        "counter++==;",
        "counter--===;",
        "counter+=;",
        "counter-=;",
        "let = ;",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "invalid source must remain rejected: {source}"
        );
    }
}

#[test]
fn assignment_strictness_preserves_exact_directive_provenance_bd_0k19b() {
    let strict = parse_script(r#""use strict"; target = 1;"#);
    assert!(matches!(
        &strict.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            },
            ..
        })
    ));

    let escaped = parse_script(r#""use\x20strict"; target = 1;"#);
    assert!(matches!(
        &escaped.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Sloppy,
                ..
            },
            ..
        })
    ));

    let module = CanonicalEs2020Parser
        .parse("target = 1;", ParseGoal::Module)
        .expect("module assignment should parse");
    assert!(matches!(
        &module.body[0],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            },
            ..
        })
    ));

    let inherited = parse_script(r#""use strict"; function f() { target = 1; }"#);
    let Statement::FunctionDeclaration(function) = &inherited.body[1] else {
        panic!("expected function declaration");
    };
    assert!(matches!(
        &function.body.body[0],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            },
            ..
        })
    ));

    let function_local = parse_script(r#"function f() { "use strict"; target = 1; }"#);
    let Statement::FunctionDeclaration(function) = &function_local.body[0] else {
        panic!("expected function declaration");
    };
    assert!(matches!(
        &function.body.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            },
            ..
        })
    ));

    let strict_loops =
        parse_script(r#""use strict"; for (key in object) {} for (value of values) {}"#);
    assert!(matches!(
        &strict_loops.body[1],
        Statement::ForIn(ForInStatement {
            assignment_strictness: AssignmentStrictness::Strict,
            ..
        })
    ));
    assert!(matches!(
        &strict_loops.body[2],
        Statement::ForOf(ForOfStatement {
            assignment_strictness: AssignmentStrictness::Strict,
            ..
        })
    ));

    let strict_update = parse_script(r#""use strict"; ++target;"#);
    assert!(matches!(
        &strict_update.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            },
            ..
        })
    ));
}

#[test]
fn ternary_conditional() {
    let tree = parse_script("a ? b : c");
    match first_expr(&tree) {
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            assert!(matches!(test.as_ref(), Expression::Identifier(n) if n == "a"));
            assert!(matches!(consequent.as_ref(), Expression::Identifier(n) if n == "b"));
            assert!(matches!(alternate.as_ref(), Expression::Identifier(n) if n == "c"));
        }
        other => panic!("expected Conditional, got {other:?}"),
    }
}

#[test]
fn call_expression_no_args() {
    let tree = parse_script("foo()");
    match first_expr(&tree) {
        Expression::Call {
            callee, arguments, ..
        } => {
            assert!(matches!(callee.as_ref(), Expression::Identifier(n) if n == "foo"));
            assert!(arguments.is_empty());
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn call_expression_with_args() {
    let tree = parse_script("foo(1, 2)");
    match first_expr(&tree) {
        Expression::Call {
            callee, arguments, ..
        } => {
            assert!(matches!(callee.as_ref(), Expression::Identifier(n) if n == "foo"));
            assert_eq!(arguments.len(), 2);
            assert!(matches!(&arguments[0], Expression::NumericLiteral(1)));
            assert!(matches!(&arguments[1], Expression::NumericLiteral(2)));
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn member_expression_dot() {
    let tree = parse_script("obj.prop");
    match first_expr(&tree) {
        Expression::Member {
            object,
            property,
            computed,
            ..
        } => {
            assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "obj"));
            assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "prop"));
            assert!(!computed);
        }
        other => panic!("expected Member, got {other:?}"),
    }
}

#[test]
fn member_expression_computed() {
    let tree = parse_script("arr[0]");
    match first_expr(&tree) {
        Expression::Member {
            object,
            property,
            computed,
            ..
        } => {
            assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "arr"));
            assert!(matches!(property.as_ref(), Expression::NumericLiteral(0)));
            assert!(computed);
        }
        other => panic!("expected Member, got {other:?}"),
    }
}

/// `this` is sloppy in a script and strict in a module or after a
/// "use strict" directive (bd-9vouw.118), except that a script's
/// top-level `this`, its arrows' included, is the global object even in
/// strict code, which the SloppyThis conversion yields (bd-9vouw.417).
#[test]
fn this_expression() {
    fn returned(statement: &Statement) -> &Expression {
        match statement {
            Statement::Return(ReturnStatement {
                argument: Some(argument),
                ..
            }) => argument,
            other => panic!("expected return, got {other:?}"),
        }
    }
    let tree = parse_script("this");
    assert!(matches!(first_expr(&tree), Expression::SloppyThis));
    let strict = parse_script("'use strict'; this");
    assert!(matches!(
        &strict.body[1],
        Statement::Expression(statement)
            if matches!(statement.expression, Expression::SloppyThis)
    ));
    let strict_arrow = parse_script("'use strict'; () => this");
    let Statement::Expression(statement) = &strict_arrow.body[1] else {
        panic!("expected an expression statement");
    };
    let Expression::ArrowFunction { body, .. } = &statement.expression else {
        panic!("expected an arrow, got {:?}", statement.expression);
    };
    assert!(matches!(
        body,
        ArrowBody::Expression(expression) if matches!(**expression, Expression::SloppyThis)
    ));
    let strict_function = parse_script("'use strict'; function f() { return this; }");
    let Statement::FunctionDeclaration(function) = &strict_function.body[1] else {
        panic!("expected a function declaration");
    };
    assert!(matches!(returned(&function.body.body[0]), Expression::This));
    let module = CanonicalEs2020Parser
        .parse("this", ParseGoal::Module)
        .expect("parse should succeed");
    assert!(matches!(first_expr(&module), Expression::This));
}

#[test]
fn array_literal_empty() {
    let tree = parse_script("[]");
    match first_expr(&tree) {
        Expression::ArrayLiteral(elements) => {
            assert!(elements.is_empty());
        }
        other => panic!("expected ArrayLiteral, got {other:?}"),
    }
}

#[test]
fn array_literal_with_elements() {
    let tree = parse_script("[1, 2, 3]");
    match first_expr(&tree) {
        Expression::ArrayLiteral(elements) => {
            assert_eq!(elements.len(), 3);
        }
        other => panic!("expected ArrayLiteral, got {other:?}"),
    }
}

#[test]
fn object_literal_empty() {
    let tree = parse_script("({})");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert!(properties.is_empty());
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }
}

#[test]
fn object_literal_plain_method_shorthand() {
    // bd-bg9l1.27.3 / DISC-003 / bd-gqaa4: `name() {}` must retain its
    // method identity, not collapse to a data property or shorthand identifier.
    let tree = parse_script("({ next() { return 1; } })");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert_eq!(properties.len(), 1);
            let prop = &properties[0];
            assert!(!prop.computed);
            assert!(!prop.shorthand);
            assert_eq!(prop.kind, ObjectPropertyKind::Method);
            assert!(matches!(&prop.key, Expression::Identifier(n) if n == "next"));
            assert!(
                matches!(&prop.value, Expression::Function { .. }),
                "method value should be a function, got {:?}",
                prop.value
            );
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }

    let explicit = parse_script("({ next: function() { return 1; } })");
    let Expression::ObjectLiteral(explicit_properties) = first_expr(&explicit) else {
        panic!("expected explicit-function object literal");
    };
    assert_eq!(explicit_properties[0].kind, ObjectPropertyKind::Data);
    assert_ne!(
        first_expr(&tree).canonical_value(),
        first_expr(&explicit).canonical_value(),
        "concise method syntax must remain distinct from a function-valued data property"
    );
}

#[test]
fn object_literal_computed_method_shorthand() {
    // bd-bg9l1.27.3 / DISC-003: `[expr]() {}` must parse as a computed
    // method with a function value.
    let tree = parse_script("({ [Symbol.iterator]() { return 1; } })");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert_eq!(properties.len(), 1);
            let prop = &properties[0];
            assert!(prop.computed);
            assert!(!prop.shorthand);
            assert_eq!(prop.kind, ObjectPropertyKind::Method);
            assert!(matches!(&prop.key, Expression::Member { .. }));
            assert!(
                matches!(&prop.value, Expression::Function { .. }),
                "computed method value should be a function, got {:?}",
                prop.value
            );
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }
}

#[test]
fn object_method_super_property_is_contextual_bd_gqaa4() {
    let tree = parse_script("({ value() { return super.value(); } })");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    let Expression::Function { body, .. } = &properties[0].value else {
        panic!("expected concise-method function body");
    };
    let Statement::Return(ReturnStatement {
        argument: Some(Expression::Call { callee, .. }),
        ..
    }) = &body.body[0]
    else {
        panic!("expected return of super method call");
    };
    assert!(matches!(
        callee.as_ref(),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::Super)
    ));
    CanonicalEs2020Parser
        .parse(
            "let saved; ({ value() { saved = () => super.value(); } })",
            ParseGoal::Script,
        )
        .expect("a nested arrow must retain the enclosing method's super context");
    CanonicalEs2020Parser
        .parse(
            "let saved; ({ value() { saved = async () => super.value(); } })",
            ParseGoal::Script,
        )
        .expect("a nested async arrow must retain the enclosing method's super context");

    assert!(
        CanonicalEs2020Parser
            .parse("super.value()", ParseGoal::Script)
            .is_err(),
        "super-property syntax must remain rejected without method context"
    );
    assert!(
        CanonicalEs2020Parser
            .parse(
                "({ value() { return function () { return super.value(); }; } })",
                ParseGoal::Script,
            )
            .is_err(),
        "an ordinary nested function must not inherit the method's super binding"
    );
}

#[test]
fn object_async_and_generator_methods_parse_bd_6vl81() {
    let tree = parse_script(
        "({ async m() { await 1; }, *g() { yield 1; }, async *h() { yield 2; }, \
         async [k]() {}, async() {}, async: 1, async })",
    );
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    let flags: Vec<Option<(bool, bool)>> = properties
        .iter()
        .map(|property| match &property.value {
            Expression::Function {
                is_async,
                is_generator,
                ..
            } => Some((*is_async, *is_generator)),
            _ => None,
        })
        .collect();
    assert_eq!(
        flags,
        vec![
            Some((true, false)),
            Some((false, true)),
            Some((true, true)),
            Some((true, false)),
            // `async(){}` is an ordinary method named "async".
            Some((false, false)),
            // `async: 1` and shorthand `async` are data properties.
            None,
            None,
        ]
    );
    assert!(properties[3].computed);
    assert_eq!(
        properties[4].key,
        Expression::Identifier(canonicalize_identifier("async"))
    );
    assert!(
        CanonicalEs2020Parser
            .parse("({ async\nm() {} })", ParseGoal::Script)
            .is_err(),
        "a line terminator after `async` does not form an async method"
    );
}

#[test]
fn class_async_and_generator_methods_parse_bd_6vl81() {
    let tree = parse_script(
        "class A { async m() { await 1; } *g() { yield 1; } static async *h() { yield 2; } \
         async() {} get async() { return 1; } static async s() {} }",
    );
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("expected class declaration");
    };
    let shapes: Vec<(String, bool, bool, bool, MethodKind)> = class
        .body
        .iter()
        .map(|method| {
            let Expression::Identifier(name) = &method.key else {
                panic!("expected identifier method key, got {:?}", method.key);
            };
            (
                name.clone(),
                method.is_static,
                method.is_async,
                method.is_generator,
                method.kind,
            )
        })
        .collect();
    assert_eq!(
        shapes,
        vec![
            ("m".to_string(), false, true, false, MethodKind::Method),
            ("g".to_string(), false, false, true, MethodKind::Method),
            ("h".to_string(), true, true, true, MethodKind::Method),
            // A method and an accessor named "async" stay ordinary.
            ("async".to_string(), false, false, false, MethodKind::Method),
            ("async".to_string(), false, false, false, MethodKind::Get),
            ("s".to_string(), true, true, false, MethodKind::Method),
        ]
    );
}

#[test]
fn object_literal_shorthand_not_misparsed_as_method() {
    // Plain shorthand `{ x }` must still be a shorthand identifier property,
    // and `key: value` must be unaffected by the method branch.
    let tree = parse_script("({ x, y: 2 })");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert_eq!(properties.len(), 2);
            assert!(properties[0].shorthand);
            assert!(matches!(&properties[0].key, Expression::Identifier(n) if n == "x"));
            assert!(!properties[1].shorthand);
            assert!(matches!(&properties[1].key, Expression::Identifier(n) if n == "y"));
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }
}

#[test]
fn parenthesized_expression() {
    let tree = parse_script("(42)");
    assert!(matches!(first_expr(&tree), Expression::NumericLiteral(42)));
}

#[test]
fn chained_member_access() {
    let tree = parse_script("a.b.c");
    match first_expr(&tree) {
        Expression::Member {
            object,
            property,
            computed,
            ..
        } => {
            assert!(!computed);
            assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "c"));
            match object.as_ref() {
                Expression::Member {
                    object: inner_obj,
                    property: inner_prop,
                    computed: inner_computed,
                    ..
                } => {
                    assert!(!inner_computed);
                    assert!(matches!(inner_obj.as_ref(), Expression::Identifier(n) if n == "a"));
                    assert!(matches!(inner_prop.as_ref(), Expression::Identifier(n) if n == "b"));
                }
                other => panic!("expected inner Member, got {other:?}"),
            }
        }
        other => panic!("expected Member, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Control flow statement parsing (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn if_statement_simple() {
    let tree = parse_script("if (true) { x }");
    assert!(matches!(&tree.body[0], Statement::If(_)));
}

#[test]
fn if_else_statement() {
    let tree = parse_script("if (x) { a } else { b }");
    match &tree.body[0] {
        Statement::If(s) => {
            assert!(s.alternate.is_some());
        }
        other => panic!("expected If, got {other:?}"),
    }
}

#[test]
fn for_loop() {
    let tree = parse_script("for (let i = 0; i < 10; i) { x }");
    match &tree.body[0] {
        Statement::For(s) => {
            assert!(s.init.is_some());
            assert!(s.condition.is_some());
            assert!(s.update.is_some());
        }
        other => panic!("expected For, got {other:?}"),
    }
}

#[test]
fn while_loop() {
    let tree = parse_script("while (true) { x }");
    assert!(matches!(&tree.body[0], Statement::While(_)));
}

#[test]
fn do_while_loop() {
    let tree = parse_script("do { x } while (true)");
    assert!(matches!(&tree.body[0], Statement::DoWhile(_)));
}

#[test]
fn return_statement_no_value() {
    let tree = parse_script("return");
    match &tree.body[0] {
        Statement::Return(r) => assert!(r.argument.is_none()),
        other => panic!("expected Return, got {other:?}"),
    }
}

#[test]
fn return_statement_with_value() {
    let tree = parse_script("return 42");
    match &tree.body[0] {
        Statement::Return(r) => {
            assert!(r.argument.is_some());
        }
        other => panic!("expected Return, got {other:?}"),
    }
}

#[test]
fn throw_statement() {
    let tree = parse_script("throw err");
    assert!(matches!(&tree.body[0], Statement::Throw(_)));
}

#[test]
fn try_catch_statement() {
    let tree = parse_script("try { x } catch (e) { y }");
    match &tree.body[0] {
        Statement::TryCatch(s) => {
            assert!(s.handler.is_some());
            assert!(s.finalizer.is_none());
        }
        other => panic!("expected TryCatch, got {other:?}"),
    }
}

#[test]
fn try_catch_without_binding() {
    let tree = parse_script("try { x } catch { y }");
    match &tree.body[0] {
        Statement::TryCatch(s) => {
            let handler = s.handler.as_ref().expect("catch handler present");
            assert_eq!(handler.parameter, None);
            assert!(s.finalizer.is_none());
        }
        other => panic!("expected TryCatch, got {other:?}"),
    }
}

#[test]
fn try_finally_statement() {
    let tree = parse_script("try { x } finally { z }");
    match &tree.body[0] {
        Statement::TryCatch(s) => {
            assert!(s.handler.is_none());
            assert!(s.finalizer.is_some());
        }
        other => panic!("expected TryCatch, got {other:?}"),
    }
}

#[test]
fn try_catch_finally() {
    let tree = parse_script("try { x } catch (e) { y } finally { z }");
    match &tree.body[0] {
        Statement::TryCatch(s) => {
            assert!(s.handler.is_some());
            assert!(s.finalizer.is_some());
        }
        other => panic!("expected TryCatch, got {other:?}"),
    }
}

#[test]
fn try_catch_preserves_statement_and_clause_spans() {
    let tree = parse_script("try { x } catch (e) { y } finally { z }");
    match &tree.body[0] {
        Statement::TryCatch(s) => {
            assert_eq!(*tree.body[0].span(), s.span);
            assert_eq!(s.block.span, s.span);
            assert_eq!(
                s.handler.as_ref().expect("catch handler present").span,
                s.span
            );
            assert_eq!(
                s.finalizer.as_ref().expect("finally block present").span,
                s.span
            );
        }
        other => panic!("expected TryCatch, got {other:?}"),
    }
}

#[test]
fn malformed_try_catch_finally_syntax_is_rejected() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "try { x }",
        "try x catch (e) { y }",
        "try { x } catch () { y }",
        "try { x } catch (e) y",
        "try { x } catch (e) unexpected { y }",
        "try { x } finally z",
        "try { x } finally unexpected { z }",
    ] {
        assert!(
            parser.parse(source, ParseGoal::Script).is_err(),
            "source should fail: {source}"
        );
    }
}

#[test]
fn try_statement_rejects_unconsumed_clause_tail() {
    for source in [
        "try { x } catch (e) { y } trailing",
        "try { x } finally { z } trailing",
    ] {
        let error = parse_single_script_statement(source)
            .expect_err("single try statement should reject unconsumed trailing text");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn switch_statement() {
    let tree = parse_script("switch (x) { case 1: y }");
    match &tree.body[0] {
        Statement::Switch(s) => {
            assert_eq!(s.cases.len(), 1);
            assert!(s.cases[0].test.is_some());
        }
        other => panic!("expected Switch, got {other:?}"),
    }
}

#[test]
fn break_statement() {
    let tree = parse_script("break");
    match &tree.body[0] {
        Statement::Break(b) => assert!(b.label.is_none()),
        other => panic!("expected Break, got {other:?}"),
    }
}

#[test]
fn break_with_label() {
    let tree = parse_script("break outer");
    match &tree.body[0] {
        Statement::Break(b) => assert_eq!(b.label.as_deref(), Some("outer")),
        other => panic!("expected Break, got {other:?}"),
    }
}

#[test]
fn continue_statement() {
    let tree = parse_script("continue");
    match &tree.body[0] {
        Statement::Continue(c) => assert!(c.label.is_none()),
        other => panic!("expected Continue, got {other:?}"),
    }
}

#[test]
fn function_declaration_simple() {
    let tree = parse_script("function foo(a, b) { return a }");
    match &tree.body[0] {
        Statement::FunctionDeclaration(f) => {
            assert_eq!(f.name.as_deref(), Some("foo"));
            assert_eq!(f.params.len(), 2);
            assert!(!f.is_async);
            assert!(!f.is_generator);
        }
        other => panic!("expected FunctionDeclaration, got {other:?}"),
    }
}

#[test]
fn async_function_declaration() {
    let tree = parse_script("async function bar() { return 1 }");
    match &tree.body[0] {
        Statement::FunctionDeclaration(f) => {
            assert!(f.is_async);
            assert_eq!(f.name.as_deref(), Some("bar"));
        }
        other => panic!("expected FunctionDeclaration, got {other:?}"),
    }
}

#[test]
fn generator_function_declaration_without_space_after_function_keyword() {
    let tree = parse_script("function* gen() { yield 1 }");
    match &tree.body[0] {
        Statement::FunctionDeclaration(f) => {
            assert_eq!(f.name.as_deref(), Some("gen"));
            assert!(!f.is_async);
            assert!(f.is_generator);
        }
        other => panic!("expected FunctionDeclaration, got {other:?}"),
    }
}

#[test]
fn async_generator_function_declaration_without_space_after_function_keyword() {
    let tree = parse_script("async function* gen() { yield 1 }");
    match &tree.body[0] {
        Statement::FunctionDeclaration(f) => {
            assert_eq!(f.name.as_deref(), Some("gen"));
            assert!(f.is_async);
            assert!(f.is_generator);
        }
        other => panic!("expected FunctionDeclaration, got {other:?}"),
    }
}

#[test]
fn anonymous_function_statement_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("function () { return 1 }", ParseGoal::Script)
        .expect_err("anonymous function statement must fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
    assert!(err.message.contains("binding name"));
}

#[test]
fn anonymous_generator_function_statement_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("function* () { yield 1 }", ParseGoal::Script)
        .expect_err("anonymous generator statement must fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
    assert!(err.message.contains("binding name"));
}

#[test]
fn block_statement() {
    let tree = parse_script("{ let x = 1 }");
    assert!(matches!(&tree.body[0], Statement::Block(_)));
}

// -----------------------------------------------------------------------
// Binary operator precedence matrix (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn precedence_mul_over_add_right() {
    // a * b + c should parse as (a * b) + c
    let tree = parse_script("a * b + c");
    match first_expr(&tree) {
        Expression::Binary { operator, left, .. } => {
            assert_eq!(*operator, BinaryOperator::Add);
            assert!(matches!(
                left.as_ref(),
                Expression::Binary {
                    operator: BinaryOperator::Multiply,
                    ..
                }
            ));
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn precedence_comparison_over_logical() {
    // a > b && c < d should parse as (a > b) && (c < d)
    let tree = parse_script("a > b && c < d");
    match first_expr(&tree) {
        Expression::Binary {
            operator,
            left,
            right,
        } => {
            assert_eq!(*operator, BinaryOperator::LogicalAnd);
            assert!(matches!(
                left.as_ref(),
                Expression::Binary {
                    operator: BinaryOperator::GreaterThan,
                    ..
                }
            ));
            assert!(matches!(
                right.as_ref(),
                Expression::Binary {
                    operator: BinaryOperator::LessThan,
                    ..
                }
            ));
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_instanceof() {
    let tree = parse_script("x instanceof Array");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::Instanceof);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[test]
fn binary_exponentiation() {
    let tree = parse_script("2 ** 3");
    match first_expr(&tree) {
        Expression::Binary { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::Exponentiate);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Merge logical lines (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn merge_logical_lines_simple() {
    let lines = merge_logical_lines("a;\nb;");
    assert_eq!(lines.len(), 2);
}

#[test]
fn strip_comments_blanks_trailing_line_comment_preserving_length() {
    let src = "var x = 1; // Should be 1\n";
    let stripped = strip_comments_to_whitespace(src);
    assert_eq!(stripped.len(), src.len(), "byte length must be preserved");
    assert!(stripped.starts_with("var x = 1; "));
    assert!(!stripped.contains("Should"));
    // The newline that terminates the comment is preserved.
    assert!(stripped.ends_with('\n'));
}

#[test]
fn html_like_comments_are_script_only_bd_9vouw_322() {
    let src = "a <!--b\n--> c\n/*\n*/ --> d\nx-->y\n'<!--'\n";
    let (script, _) = strip_comments_to_whitespace_for_goal(src, ParseGoal::Script);
    assert_eq!(script.len(), src.len(), "byte length must be preserved");
    assert_eq!(
        script, "a      \n     \n  \n        \nx-->y\n'<!--'\n",
        "`<!--` anywhere and `-->` at a line start are comments; after code \
         `-->` is `--` `>`, and string text is untouched"
    );
    let (module, _) = strip_comments_to_whitespace_for_goal(src, ParseGoal::Module);
    assert_eq!(module, "a <!--b\n--> c\n  \n   --> d\nx-->y\n'<!--'\n");
    assert_eq!(strip_comments_to_whitespace(src), module);
}

#[test]
fn import_attributes_bd_9vouw_387() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "import data from './d.json' with { type: 'json' };",
        "import * as ns from \"./d.json\" with { \"type\": \"json\", }",
        "import './d.json' with { type: 'json' }",
        "import data from './d.json' with {}",
        "import x from './x.js'",
        "import d from 'extensionless-package' with { type: 'json' }",
        "import d from './d.css' with { type: 'css' }",
        "import d from './d.js' with { type: 'json' }",
    ] {
        let tree = parser.parse(source, ParseGoal::Module).expect(source);
        assert!(
            matches!(tree.body.as_slice(), [Statement::Import(_)]),
            "{source}"
        );
    }
    for (source, code) in [
        (
            "import d from './d.json' with { type: 'json', type: 'json' }",
            ParseErrorCode::InvalidSyntax,
        ),
        (
            "import d from './d.json' with { type: json }",
            ParseErrorCode::InvalidSyntax,
        ),
    ] {
        let error = parser.parse(source, ParseGoal::Module).expect_err(source);
        assert_eq!(error.code, code, "{source}");
    }
}

#[test]
fn default_declaration_names_bd_9vouw_386() {
    for (head, name) in [
        ("function A() {}", Some("A")),
        ("function* G() {}", Some("G")),
        ("function *G() {}", Some("G")),
        ("async function F() {}", Some("F")),
        ("async function* AG() {}", Some("AG")),
        ("class K extends B {}", Some("K")),
        ("class $k{}", Some("$k")),
        ("function () {}", None),
        ("function() {}", None),
        ("async function* () {}", None),
        ("class {}", None),
        ("class extends B {}", None),
    ] {
        assert_eq!(default_declaration_name(head), name, "{head}");
    }
    let tree = CanonicalEs2020Parser
        .parse(
            "export default class K {}\nexport { K as alias };",
            ParseGoal::Module,
        )
        .expect("parse");
    assert!(
        matches!(
            tree.body.as_slice(),
            [
                Statement::ClassDeclaration(_),
                Statement::Export(_),
                Statement::Export(_)
            ]
        ),
        "a named default declaration is the declaration plus `export {{ K as default }}`"
    );
}

#[test]
fn strip_comments_blanks_block_comment_preserving_newlines() {
    let src = "var x =\n/* multi\n line */ 2;\n";
    let stripped = strip_comments_to_whitespace(src);
    assert_eq!(stripped.len(), src.len());
    assert!(!stripped.contains("multi"));
    assert!(!stripped.contains("line"));
    // Both interior newlines survive so line numbers do not shift.
    assert_eq!(stripped.matches('\n').count(), src.matches('\n').count());
    assert!(stripped.contains("2;"));
}

#[test]
fn comments_preserve_ecmascript_line_terminators_and_spans_bd_21nbg() {
    let parser = CanonicalEs2020Parser;
    for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
        let line_source = format!("first; // comment{terminator}second;");
        let stripped = strip_comments_to_whitespace(&line_source);
        assert_eq!(stripped.len(), line_source.len(), "{line_source:?}");
        assert!(stripped.contains(terminator), "{line_source:?}");
        let tree = parser
            .parse(line_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {line_source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{line_source:?}");
        assert_eq!(tree.body[1].span().start_line, 2, "{line_source:?}");
        assert_eq!(
            tree.body[1].span().start_offset,
            line_source.find("second").expect("second is present") as u64,
            "{line_source:?}"
        );

        let block_source = format!("first; /* comment{terminator}still */{terminator}second;");
        let stripped = strip_comments_to_whitespace(&block_source);
        assert_eq!(stripped.len(), block_source.len(), "{block_source:?}");
        assert_eq!(
            stripped.matches(terminator).count(),
            block_source.matches(terminator).count(),
            "{block_source:?}"
        );
        let tree = parser
            .parse(block_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {block_source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{block_source:?}");
        assert_eq!(tree.body[1].span().start_line, 3, "{block_source:?}");
        assert_eq!(
            tree.body[1].span().start_offset,
            block_source.find("second").expect("second is present") as u64,
            "{block_source:?}"
        );

        let regex_source = format!("const value ={terminator}/a\\//;{terminator}value;");
        let stripped = strip_comments_to_whitespace(&regex_source);
        assert_eq!(stripped.len(), regex_source.len(), "{regex_source:?}");
        assert!(stripped.contains("/a\\//"), "{regex_source:?}");
        let tree = parser
            .parse(regex_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {regex_source:?}: {error}"));
        assert_eq!(tree.body.len(), 2, "{regex_source:?}");
    }
}

#[test]
fn strip_comments_leaves_double_slash_inside_string_intact() {
    let src = "var u = \"http://example.com\"; // trailing\n";
    let stripped = strip_comments_to_whitespace(src);
    assert!(stripped.contains("\"http://example.com\""));
    assert!(!stripped.contains("trailing"));
}

#[test]
fn strip_comments_leaves_double_slash_inside_template_literal_intact() {
    let src = "var u = `a//b`; // c\n";
    let stripped = strip_comments_to_whitespace(src);
    assert!(stripped.contains("`a//b`"));
    assert!(!stripped.contains("// c"));
}

#[test]
fn strip_comments_blanks_comments_inside_template_substitutions() {
    let src = "var u = `a${/* c */ f() // d\n}b // text ${`n${/*e*/ 1}`}`; // f\n";
    let stripped = strip_comments_to_whitespace(src);
    assert_eq!(stripped.len(), src.len());
    assert!(!stripped.contains("/* c */") && !stripped.contains("// d"));
    assert!(!stripped.contains("/*e*/") && !stripped.contains("// f"));
    assert!(stripped.contains("f() "), "{stripped}");
    assert!(stripped.contains("}b // text ${`n${"), "{stripped}");
}

#[test]
fn strip_comments_leaves_regex_literal_intact() {
    // The `/` inside the char class and body must not be read as a comment.
    let src = "var re = /a\\/b[/]c/; // note\n";
    let stripped = strip_comments_to_whitespace(src);
    assert!(stripped.contains("/a\\/b[/]c/"));
    assert!(!stripped.contains("note"));
}

#[test]
fn strip_comments_division_is_not_a_comment() {
    let src = "var q = a / b; // q\n";
    let stripped = strip_comments_to_whitespace(src);
    assert!(stripped.contains("a / b"));
    assert!(!stripped.contains("// q"));
}

#[test]
fn merge_logical_lines_after_strip_drops_trailing_comment_segment() {
    // End-to-end at the merge+split boundary: a trailing line comment after
    // `;` must not survive as a separate statement segment.
    let stripped = strip_comments_to_whitespace("var x = 1; // Should be 1\n");
    let lines = merge_logical_lines(&stripped);
    assert_eq!(lines.len(), 1);
    let segs = split_statement_segments(&lines[0].text);
    assert_eq!(segs.len(), 1, "comment must not become its own segment");
    assert_eq!(segs[0].2.trim(), "var x = 1");
}

#[test]
fn merge_logical_lines_ignores_initial_hashbang_comment() {
    let lines = merge_logical_lines("#! /usr/bin/env node\n\"use strict\";\nconst x = 1;");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].text, "\"use strict\";");
    assert_eq!(lines[0].start_line, 2);
    assert_eq!(lines[1].text, "const x = 1;");
}

#[test]
fn merge_logical_lines_only_ignores_hashbang_at_start() {
    let lines = merge_logical_lines("const x = 1;\n#! /usr/bin/env node");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1].text, "#! /usr/bin/env node");
}

#[test]
fn merge_logical_lines_block() {
    // A block spanning multiple lines should be merged into one logical line.
    let lines = merge_logical_lines("if (x) {\n  y;\n}");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.contains("if (x) {"));
}

#[test]
fn merge_logical_lines_ignores_braces_in_line_comments() {
    let lines = merge_logical_lines("if (x) { // { comment\n  y;\n}");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].start_line, 1);
    assert_eq!(lines[0].end_line, 3);
}

#[test]
fn merge_logical_lines_ignores_braces_in_block_comments() {
    let lines = merge_logical_lines("if (x) {\n  /* { comment */\n  y;\n}");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].start_line, 1);
    assert_eq!(lines[0].end_line, 4);
}

#[test]
fn merge_logical_lines_braces_in_quotes_do_not_merge_following_statement() {
    let lines = merge_logical_lines("var s = \"}\";\nif (x) {\n  y;\n}");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].text, "var s = \"}\";");
    assert!(lines[1].text.starts_with("if (x) {"));
}

#[test]
fn merge_logical_lines_ignores_braces_in_regex_literals() {
    let lines = merge_logical_lines("var r = /{/;\nif (x) {\n  y;\n}");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].text, "var r = /{/;");
    assert!(lines[1].text.starts_with("if (x) {"));
}

#[test]
fn merge_logical_lines_continues_dangling_assignment_and_binary_operator() {
    let lines = merge_logical_lines(
        "const attackSucceeded =\n  lifecycle.status === 0 &&\n  lifecycle.stdout.includes(\"ok\");\nnext;",
    );
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0].text,
        "const attackSucceeded = lifecycle.status === 0 && lifecycle.stdout.includes(\"ok\");"
    );
    assert_eq!(lines[0].start_line, 1);
    assert_eq!(lines[0].end_line, 3);
    assert_eq!(lines[1].text, "next;");

    let lines = merge_logical_lines(
        "const uidProbeAvailable =\n  typeof process.getuid === \"function\" ||\n  typeof process.geteuid === \"function\";",
    );
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0].text,
        "const uidProbeAvailable = typeof process.getuid === \"function\" || typeof process.geteuid === \"function\";"
    );
}

#[test]
fn parse_script_with_regex_brace_before_block_keeps_two_statements() {
    let tree = parse_script("var r = /{/;\nif (x) {\n  y;\n}");
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn class_heritage_with_braces_keeps_the_class_body() {
    for (source, methods) in [
        (
            "class Child extends class Base { read() { return 6; } } { total(v) { return this.read() + v; } }",
            1,
        ),
        ("class D extends (class { r() { return 3; } }) {}", 0),
        ("class E extends mix({ a: 1 }) { m() {} n() {} }", 2),
        (
            "class F extends class extends Object { r() {} } { s() {} }",
            1,
        ),
    ] {
        let tree = parse_script(source);
        let Some(Statement::ClassDeclaration(class)) = tree.body.first() else {
            panic!(
                "{source}: expected a class declaration, got {:?}",
                tree.body
            );
        };
        assert!(class.super_class.is_some(), "{source}");
        assert_eq!(class.body.len(), methods, "{source}");
    }
}

#[test]
fn slash_after_a_control_statement_head_opens_a_regex() {
    // After `if (...)` a statement starts, so `/}/` is a regex, and its
    // `}` closes nothing.
    let tree = parse_script("var r;\nif (true) /}/.test('}') && (r = 1);\nr;");
    assert_eq!(tree.body.len(), 3);
    let rendered = format!("{:?}", tree.body[1]);
    assert!(rendered.contains("RegExpLiteral"), "{rendered}");
    for source in [
        "while (x) /a/.test(s);",
        "for (;;) /a/.test(s);",
        "if (a) /=/.test(s);",
    ] {
        let tree = parse_script(source);
        assert!(
            format!("{:?}", tree.body[0]).contains("RegExpLiteral"),
            "{source}"
        );
    }
    // After a call's `)` (also a keyword-named method) the slash divides.
    for source in ["f(x) / 2 / 1;", "o.if(x) / 2 / 1;", "(a) / b / c;"] {
        let tree = parse_script(source);
        assert!(
            !format!("{:?}", tree.body[0]).contains("RegExpLiteral"),
            "{source}"
        );
    }
}

#[test]
fn merge_logical_lines_continues_lines_that_start_with_an_operator() {
    // Leading-operator layout: ternaries, logical chains, comma-first.
    let lines = merge_logical_lines(
        "var v = ok\n  ? \"yes\"\n  : \"no\";\nvar a = x\n  || y\n  && z\nvar b = 1\n  , c = 2;",
    );
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "var v = ok ? \"yes\" : \"no\";",
            "var a = x || y && z",
            "var b = 1 , c = 2;"
        ]
    );
    assert_eq!((lines[0].start_line, lines[0].end_line), (1, 3));

    // `++`/`--` after a newline start a statement; a leading `-` does not
    // continue a statement that ended with a block; nothing continues
    // past an explicit `;`.
    let lines = merge_logical_lines("a\n++b\nif (x) {}\n-1\nc;\n|| d");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(texts, ["a", "++b", "if (x) {}", "-1", "c;", "|| d"]);

    // A leading `-` does continue an ordinary expression: `a\n- b` is `a - b`.
    let lines = merge_logical_lines("var d = a\n  - b;");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].text, "var d = a - b;");
}

#[test]
fn merge_logical_lines_ends_a_line_at_a_closing_regex_literal() {
    // bd-9vouw.194: the closing `/` ends an operand; a trailing division
    // `/` still continues.
    let lines = merge_logical_lines("var a = /x/\nvar b = /[^#/:?]+/\nvar e = 6 /\n  3");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(
        texts,
        ["var a = /x/", "var b = /[^#/:?]+/", "var e = 6 / 3"]
    );
}

#[test]
fn merge_logical_lines_restricted_keyword_ends_before_an_operand_start() {
    // bd-9vouw.444: after `return`/`yield` and a line break, a token that
    // could begin their operand starts a new statement (ASI); other
    // operators still continue the expression.
    let texts = |source: &str| -> Vec<String> {
        merge_logical_lines(source)
            .into_iter()
            .map(|line| line.text)
            .collect()
    };
    assert_eq!(texts("return\n+ 1"), ["return", "+ 1"]);
    assert_eq!(texts("return\n- 1"), ["return", "- 1"]);
    assert_eq!(texts("yield\n* 1"), ["yield", "* 1"]);
    assert_eq!(texts("x = c ? yield\n: yield"), ["x = c ? yield : yield"]);
    assert_eq!(texts("it.return\n+ 1"), ["it.return + 1"]);
    assert_eq!(texts("total = a\n+ b"), ["total = a + b"]);
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("function* g() {\n  yield\n  * 1\n}", ParseGoal::Script)
        .expect_err("`yield` newline `* 1` is a SyntaxError");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax, "{}", err.message);
}

#[test]
fn merge_logical_lines_semicolon_before_else_continues_the_if() {
    // bd-9vouw.465: the `;` that ends an unbraced consequent may start
    // the next line, before the `else` (Test262 continue/12.7-1.js).
    let texts = |source: &str| -> Vec<String> {
        merge_logical_lines(source)
            .into_iter()
            .map(|line| line.text)
            .collect()
    };
    assert_eq!(
        texts("if (a) continue\n; else {}"),
        ["if (a) continue ; else {}"]
    );
    assert_eq!(
        texts("if (a) k = 1\n; else k = 2"),
        ["if (a) k = 1 ; else k = 2"]
    );
    // Not after a statement that takes no else.
    assert_eq!(texts("k = 1\n; else k = 2"), ["k = 1", "; else k = 2"]);
    let parser = CanonicalEs2020Parser;
    for source in [
        "for (;;) {\n  if (a) continue\n  ; else {}\n}",
        "function f(x) {\n  if (x) return\n  ; else return 7;\n}",
        "if (a) k = 1\n; else k = 2",
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("`{source}` must parse: {}", err.message));
        let debug = format!("{tree:?}");
        assert!(
            debug.contains("alternate: Some("),
            "`{source}` must keep its else branch: {debug}"
        );
    }
    // A `;` after a block consequent ends the if: the else is an error.
    let err = parser
        .parse("if (a) {}\n; else {}", ParseGoal::Script)
        .expect_err("`if (a) {}` newline `; else {}` is a SyntaxError");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax, "{}", err.message);
}

#[test]
fn merge_logical_lines_continues_after_a_trailing_division() {
    // bd-9vouw.206: a division `/` at a line end continues the line.
    let lines = merge_logical_lines("var m =\n  (a * 2) /\n  (b + 1);\nf()");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(texts, ["var m = (a * 2) / (b + 1);", "f()"]);
}

#[test]
fn merge_logical_lines_continues_across_a_lone_dot() {
    // bd-9vouw.207: a line ending with `.` continues, and so does a line
    // that is a lone `.`; a decimal point does not.
    let lines = merge_logical_lines("x = a\n.\nb\nvar n = 1.\nf()");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(texts, ["x = a . b", "var n = 1.", "f()"]);
}

#[test]
fn merge_logical_lines_continues_after_operator_keywords() {
    // bd-9vouw.195: `new`, `in`, `instanceof` and `extends` cannot end an
    // expression; as property names (`o.new`) they can.
    let lines = merge_logical_lines("var d = new\nB()\nvar t = k in\nd\nvar n = o.new\nf()");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(
        texts,
        ["var d = new B()", "var t = k in d", "var n = o.new", "f()"]
    );
}

#[test]
fn for_in_of_destructuring_heads_take_member_targets_only_when_valid() {
    // bd-9vouw.229: member targets in a destructuring head parse; a head
    // pattern with an early error keeps it, member target or not (Node:
    // SyntaxError for each `bad` source).
    for source in [
        "var o = {}; for ([o.a, o.b] of []) ;",
        "var o = {}; for ({ k: o.v, ...o.rest } of []) ;",
        "var o = {}; for ([o.d = 1, [o.e]] in {}) ;",
    ] {
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
    }
    for source in [
        "for ([...x = 1] of []) ;",
        "var o = {}; for ([...o.x = 1] of []) ;",
        "var o = {}; for ([o.a, ...o.b,] of []) ;",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "{source} must be rejected"
        );
    }
}

#[test]
fn a_for_in_head_may_assign_let_in_sloppy_code_only() {
    // bd-9vouw.233: for-in excludes only `let [`, so sloppy
    // `for (let in o)` assigns the variable `let`; strict code reserves
    // `let`, and for-of excludes it outright (Node: SyntaxError for each
    // rejected source).
    for source in ["var let; for (let in {}) ;", "for (const of of []) ;"] {
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
    }
    for source in [
        "\"use strict\"; for (let in {}) ;",
        "for (let of []) ;",
        "function* g() { for (yield in {}) ; }",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "{source} must be rejected"
        );
    }
}

#[test]
fn named_import_and_export_lists_take_one_trailing_comma() {
    // bd-9vouw.218: one trailing comma is allowed; an empty list item is
    // not (Node: SyntaxError for each `bad` source).
    for source in [
        "import { a, } from './a.mjs';",
        "import d, { a as b, } from './a.mjs';",
        "import {\n  a,\n  b as c,\n} from './b.mjs';",
        "const x = 1; export { x, };",
        "export { a, } from './a.mjs';",
    ] {
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
    }
    for source in [
        "import { , } from './a.mjs';",
        "import { a,, } from './a.mjs';",
        "const x = 1; export { , };",
        "const x = 1; export { x,, };",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .is_err(),
            "{source}"
        );
    }
}

#[test]
fn merge_logical_lines_continues_after_function_and_class_keywords() {
    // bd-9vouw.212: `function` and `class` still need a name or body; as
    // property names (`o.function`) they end the line. `async` is an ASI
    // boundary and ends its line.
    let lines =
        merge_logical_lines("function\nf() {}\nclass\nK {}\nvar p = o.function\nasync\ng()");
    let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "function f() {}",
            "class K {}",
            "var p = o.function",
            "async",
            "g()"
        ]
    );
}

#[test]
fn parse_script_accepts_leading_operator_continuations() {
    let tree = parse_script(
        "var value = !flags && isNumber(val)\n\t? Number(val)\n\t: val;\nif (\n  o === Object.prototype\n  || o === Number.prototype\n) { o = {}; }",
    );
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn regex_literals_containing_equals_are_not_assignments() {
    for source in [
        "var r = /a=b/;",
        "var s = \"x=\".replace(/=/g, \"-\");",
        "var t = (/^--.+=/).test(arg);",
        "var m = arg.match(/^--([^=]+)=([\\s\\S]*)$/);",
        "if (/=/.test(s)) { x = 1; }",
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(tree.body.len(), 1, "{source}");
    }

    // Division and `/=` in operand position are still operators.
    let tree = parse_script("x /= 2;");
    let Statement::Expression(statement) = &tree.body[0] else {
        panic!("expected an expression statement");
    };
    assert!(matches!(
        statement.expression,
        Expression::Assignment {
            operator: AssignmentOperator::DivideAssign,
            ..
        }
    ));
    let tree = parse_script("y = a / b / c;");
    let Statement::Expression(statement) = &tree.body[0] else {
        panic!("expected an expression statement");
    };
    assert!(matches!(
        statement.expression,
        Expression::Assignment {
            operator: AssignmentOperator::Assign,
            ..
        }
    ));
}

/// bd-9vouw.127: a line that starts with `/=` continues the previous
/// one as division assignment, as in Node (`var z = 9\nz\n/= 3` leaves
/// z = 3). After an operator, `/=` still opens a regex.
#[test]
fn a_line_starting_with_division_assignment_continues_the_previous_line() {
    let tree = parse_script("var z = 9\nz\n/= 3\nvar w = 8\nw\n/=2");
    assert_eq!(tree.body.len(), 4);
    for statement in [&tree.body[1], &tree.body[3]] {
        let Statement::Expression(statement) = statement else {
            panic!("expected an expression statement");
        };
        assert!(matches!(
            statement.expression,
            Expression::Assignment {
                operator: AssignmentOperator::DivideAssign,
                ..
            }
        ));
    }
    let tree = parse_script("var s = x.replace(\n/=/g, '-')");
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn parse_red_team_commonjs_destructuring_multiline_payload() {
    let tree = parse_script(
        r#"const { spawnSync } = require("node:child_process");

const lifecycle = spawnSync(
  process.execPath,
  ["-e", "process.stdout.write('franken-redteam-postinstall-backdoor')"],
  { encoding: "utf8" },
);

const attackSucceeded =
  lifecycle.status === 0 &&
  lifecycle.stdout.includes("franken-redteam-postinstall-backdoor");

process.exit(attackSucceeded ? 0 : 1);"#,
    );

    assert_eq!(tree.body.len(), 4);
    match &tree.body[0] {
        Statement::VariableDeclaration(declaration) => {
            assert!(matches!(
                &declaration.declarations[0].pattern,
                BindingPattern::ObjectPattern(properties)
                    if properties.len() == 1
                        && properties[0].key == Expression::Identifier("spawnSync".to_string())
            ));
            assert!(matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Call { callee, .. })
                    if matches!(callee.as_ref(), Expression::Identifier(name) if name == "require")
            ));
        }
        other => panic!("expected destructuring require declaration, got {other:?}"),
    }
    match &tree.body[2] {
        Statement::VariableDeclaration(declaration) => {
            assert!(matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Binary {
                    operator: BinaryOperator::LogicalAnd,
                    ..
                })
            ));
        }
        other => panic!("expected multiline attackSucceeded declaration, got {other:?}"),
    }
}

#[test]
fn parse_script_hashbang_preserves_following_strict_mode_directive_bd_21nbg() {
    let parser = CanonicalEs2020Parser;
    for bom in ["", "\u{FEFF}"] {
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let hashbang = format!("{bom}#! /usr/bin/env node{terminator}");
            let source = format!("{hashbang}\"use strict\";{terminator}with (obj) {{ x; }}");
            let lines = merge_logical_lines(&source);
            assert_eq!(lines[0].byte_offset, hashbang.len() as u64, "{source:?}");
            assert_eq!(lines[0].start_line, 2, "{source:?}");
            assert_eq!(lines[0].text, "\"use strict\";", "{source:?}");

            let err = parser
                .parse(source.as_str(), ParseGoal::Script)
                .expect_err("strict-mode with should still be rejected after hashbang");
            assert_eq!(
                err.code,
                ParseErrorCode::StrictModeWithStatement,
                "{source:?}"
            );
        }
    }
}

// -----------------------------------------------------------------------
// extract_balanced helper (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn extract_balanced_simple_parens() {
    let (inner, rest) =
        extract_balanced("(abc)def", '(', ')').expect("serde serialization should succeed");
    assert_eq!(inner, "abc");
    assert_eq!(rest, "def");
}

#[test]
fn extract_balanced_nested() {
    let (inner, rest) =
        extract_balanced("((a))", '(', ')').expect("serde serialization should succeed");
    assert_eq!(inner, "(a)");
    assert_eq!(rest, "");
}

#[test]
fn extract_balanced_not_starting_with_open() {
    assert!(extract_balanced("abc()", '(', ')').is_none());
}

#[test]
fn extract_balanced_unmatched() {
    assert!(extract_balanced("(abc", '(', ')').is_none());
}

// -----------------------------------------------------------------------
// split_top_level_commas (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn split_top_level_commas_basic() {
    let parts = split_top_level_commas("a, b, c");
    assert_eq!(parts, vec!["a", " b", " c"]);
}

#[test]
fn split_top_level_commas_nested() {
    let parts = split_top_level_commas("f(a, b), c");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], "f(a, b)");
}

#[test]
fn split_top_level_commas_reads_a_leading_equals_regex() {
    // A list element starts in expression position: `/=` opens a regex
    // there, whose `,` does not split.
    assert_eq!(split_top_level_commas("/=/g, ''"), vec!["/=/g", " ''"]);
    assert_eq!(split_top_level_commas("a, /=,/"), vec!["a", " /=,/"]);
}

// -----------------------------------------------------------------------
// find_top_level_colon (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn find_top_level_colon_basic() {
    assert_eq!(find_top_level_colon("a: b"), Some(1));
}

#[test]
fn find_top_level_colon_nested() {
    assert_eq!(find_top_level_colon("f(a: b): c"), Some(7));
}

#[test]
fn find_top_level_colon_none() {
    assert_eq!(find_top_level_colon("abc"), None);
}

/// `leading_label_colon` answers what the label checks asked of
/// `find_top_level_colon`: the first top-level colon, when the text
/// before it is an identifier.
#[test]
fn leading_label_colon_matches_the_top_level_scan() {
    let cases = [
        "a: b",
        "outer : for (;;) { break outer; }",
        "\\u0061: x",
        "a ? b : c",
        "f(a: b): c",
        "x = { a: 1 }",
        "'s:t'; u: v",
        "`a:${b}`: c",
        "/a:b/.test(s) ? 1 : 2",
        "[a, b]: c",
        "abc",
        "",
        "a.b: c",
        "  spaced  :  stmt",
    ];
    for statement in cases {
        let expected = find_top_level_colon(statement)
            .filter(|&colon| is_identifier(statement[..colon].trim()));
        assert_eq!(leading_label_colon(statement), expected, "{statement:?}");
    }
    assert_eq!(leading_label_colon("label: x"), Some(5));
    assert_eq!(leading_label_colon("a ? b : c"), None);
}

#[test]
fn find_ternary_colon_skips_nested_question() {
    // Non-nested: the only top-level colon.
    assert_eq!(find_ternary_colon(" b : c"), Some(3));
    // Consequent-nested: the inner `?`'s colon is skipped, the outer wins.
    // Slice is the tail after the outer `?` of `a ? b ? c : d : e`.
    let rest = " b ? c : d : e";
    let idx = find_ternary_colon(rest).expect("outer colon");
    assert_eq!(&rest[idx..idx + 1], ":");
    assert_eq!(rest[..idx].trim(), "b ? c : d");
    assert_eq!(rest[idx + 1..].trim(), "e");
    // `?.` and `??` are not ternary `?`.
    assert_eq!(find_ternary_colon("a ?? b : c"), Some(7));
    assert_eq!(find_ternary_colon("a?.b : c"), Some(5));
}

#[test]
fn split_for_header_is_nesting_aware() {
    assert_eq!(
        split_for_header("i = 0; i < n; i++"),
        Some(("i = 0", " i < n", " i++"))
    );
    // A `;` inside an arrow/block body must not split the header.
    let header = "let f = () => { a; return b; }; i < n; i++";
    assert_eq!(
        split_for_header(header),
        Some(("let f = () => { a; return b; }", " i < n", " i++"))
    );
    // Empty clauses are still two top-level semicolons.
    assert_eq!(split_for_header(";;"), Some(("", "", "")));
    // Fewer than two top-level semicolons -> None.
    assert_eq!(split_for_header("i < n"), None);
    assert_eq!(split_for_header("a; b"), None);
}

// -----------------------------------------------------------------------
// Labelled statements (§14.13) — bd-bg9l1.27.4 / DISC-006
// -----------------------------------------------------------------------

#[test]
fn parse_labeled_loop_and_break_label() {
    let tree = parse_script("outer: while (false) { break outer; }");
    match &tree.body[0] {
        Statement::Labeled(labeled) => {
            assert_eq!(labeled.label, "outer");
            match labeled.body.as_ref() {
                Statement::While(while_stmt) => match while_stmt.body.as_ref() {
                    Statement::Block(block) => match &block.body[0] {
                        Statement::Break(brk) => {
                            assert_eq!(brk.label.as_deref(), Some("outer"));
                        }
                        other => panic!("expected Break, got {other:?}"),
                    },
                    other => panic!("expected Block, got {other:?}"),
                },
                other => panic!("expected While, got {other:?}"),
            }
        }
        other => panic!("expected Labeled, got {other:?}"),
    }
}

#[test]
fn parse_continue_with_label() {
    let tree = parse_script("loop: while (false) { continue loop; }");
    let Statement::Labeled(labeled) = &tree.body[0] else {
        panic!("expected Labeled, got {:?}", tree.body[0]);
    };
    let Statement::While(while_stmt) = labeled.body.as_ref() else {
        panic!("expected While");
    };
    let Statement::Block(block) = while_stmt.body.as_ref() else {
        panic!("expected Block");
    };
    match &block.body[0] {
        Statement::Continue(cont) => assert_eq!(cont.label.as_deref(), Some("loop")),
        other => panic!("expected Continue, got {other:?}"),
    }
}

#[test]
fn conditional_expression_is_not_a_labeled_statement() {
    // `flag ? a : b;` has a `?` before the `:`, so the prefix is not a
    // bare identifier — it must remain an expression statement, not a label.
    let tree = parse_script("flag ? a : b;");
    assert!(
        matches!(&tree.body[0], Statement::Expression(_)),
        "ternary must parse as an expression statement, got {:?}",
        tree.body[0]
    );
}

// -----------------------------------------------------------------------
// For-in / For-of
// -----------------------------------------------------------------------

#[test]
fn for_in_with_let() {
    let tree = parse_script("for (let key in obj) { x }");
    match &tree.body[0] {
        Statement::ForIn(s) => {
            assert_eq!(s.binding.as_identifier(), Some("key"));
            assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Let));
        }
        other => panic!("expected ForIn, got {other:?}"),
    }
}

#[test]
fn for_of_with_const() {
    let tree = parse_script("for (const item of items) { x }");
    match &tree.body[0] {
        Statement::ForOf(s) => {
            assert_eq!(s.binding.as_identifier(), Some("item"));
            assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Const));
        }
        other => panic!("expected ForOf, got {other:?}"),
    }
}

#[test]
fn for_in_bare_binding() {
    let tree = parse_script("for (k in obj) { x }");
    match &tree.body[0] {
        Statement::ForIn(s) => {
            assert_eq!(s.binding.as_identifier(), Some("k"));
            assert!(s.binding_kind.is_none());
        }
        other => panic!("expected ForIn, got {other:?}"),
    }
}

#[test]
fn for_of_with_var() {
    let tree = parse_script("for (var x of arr) { x }");
    match &tree.body[0] {
        Statement::ForOf(s) => {
            assert_eq!(s.binding.as_identifier(), Some("x"));
            assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Var));
        }
        other => panic!("expected ForOf, got {other:?}"),
    }
}

#[test]
fn for_in_string_object() {
    let tree = parse_script("for (let k in \"hello\") { x }");
    match &tree.body[0] {
        Statement::ForIn(s) => {
            assert_eq!(s.binding.as_identifier(), Some("k"));
            assert!(matches!(&s.object, Expression::StringLiteral(v) if v == "hello"));
        }
        other => panic!("expected ForIn, got {other:?}"),
    }
}

#[test]
fn classic_for_still_works_after_for_in_of() {
    let tree = parse_script("for (let i = 0; i < 10; i) { x }");
    assert!(matches!(&tree.body[0], Statement::For(_)));
}

// -----------------------------------------------------------------------
// New expression
// -----------------------------------------------------------------------

#[test]
fn new_expression_with_args() {
    let tree = parse_script("new Foo(1, 2)");
    match &tree.body[0] {
        Statement::Expression(e) => {
            assert!(
                matches!(&e.expression, Expression::New { arguments, .. } if arguments.len() == 2)
            );
        }
        other => panic!("expected Expression, got {other:?}"),
    }
}

#[test]
fn new_expression_no_args() {
    let tree = parse_script("new Foo");
    match &tree.body[0] {
        Statement::Expression(e) => {
            assert!(
                matches!(&e.expression, Expression::New { arguments, .. } if arguments.is_empty())
            );
        }
        other => panic!("expected Expression, got {other:?}"),
    }
}

#[test]
fn new_expression_member_callee() {
    let tree = parse_script("new Foo.Bar()");
    match &tree.body[0] {
        Statement::Expression(e) => {
            if let Expression::New { callee, .. } = &e.expression {
                assert!(matches!(callee.as_ref(), Expression::Member { .. }));
            } else {
                panic!("expected New");
            }
        }
        other => panic!("expected Expression, got {other:?}"),
    }
}

#[test]
fn new_in_variable_decl() {
    let tree = parse_script("const m = new Map()");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("serde serialization should succeed");
            assert!(matches!(init, Expression::New { .. }));
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Template literal
// -----------------------------------------------------------------------

#[test]
fn template_literal_plain_text() {
    let tree = parse_script("const s = `hello`");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("serde serialization should succeed");
            if let Expression::TemplateLiteral {
                quasis,
                expressions,
            } = init
            {
                assert_eq!(quasis, &["hello"]);
                assert!(expressions.is_empty());
            } else {
                panic!("expected TemplateLiteral, got {init:?}");
            }
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

#[test]
fn template_literal_with_interpolation() {
    let tree = parse_script("const s = `hi ${name}!`");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("serde serialization should succeed");
            if let Expression::TemplateLiteral {
                quasis,
                expressions,
            } = init
            {
                assert_eq!(quasis, &["hi ", "!"]);
                assert_eq!(expressions.len(), 1);
            } else {
                panic!("expected TemplateLiteral, got {init:?}");
            }
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

#[test]
fn template_literal_multiple_expressions() {
    let tree = parse_script("const s = `${a}+${b}=${c}`");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("serde serialization should succeed");
            if let Expression::TemplateLiteral {
                quasis,
                expressions,
            } = init
            {
                assert_eq!(quasis, &["", "+", "=", ""]);
                assert_eq!(expressions.len(), 3);
            } else {
                panic!("expected TemplateLiteral, got {init:?}");
            }
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

#[test]
fn template_literal_empty() {
    let tree = parse_script("const s = ``");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("serde serialization should succeed");
            if let Expression::TemplateLiteral {
                quasis,
                expressions,
            } = init
            {
                assert_eq!(quasis, &[""]);
                assert!(expressions.is_empty());
            } else {
                panic!("expected TemplateLiteral, got {init:?}");
            }
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

#[test]
fn template_literal_as_expression_statement() {
    let tree = parse_script("`hello ${x}`");
    match &tree.body[0] {
        Statement::Expression(e) => {
            assert!(matches!(&e.expression, Expression::TemplateLiteral { .. }));
        }
        other => panic!("expected Expression, got {other:?}"),
    }
}

#[test]
fn tagged_template_expression_is_call_with_template_argument() {
    let tree = parse_script("render`hello ${name}`");
    match first_expr(&tree) {
        Expression::Call {
            callee, arguments, ..
        } => {
            assert!(matches!(callee.as_ref(), Expression::Identifier(name) if name == "render"));
            // tag(stringsObject, ...substitutions): arg0 is the
            // `.raw`-attaching IIFE wrapping the cooked array; then `name`.
            assert_eq!(arguments.len(), 2);
            assert!(matches!(&arguments[0], Expression::Call { .. }));
            assert!(matches!(&arguments[1], Expression::Identifier(n) if n == "name"));
        }
        other => panic!("expected tagged template call, got {other:?}"),
    }
}

#[test]
fn tagged_template_member_expression_is_call_with_template_argument() {
    let tree = parse_script("view.render`ok`");
    match first_expr(&tree) {
        Expression::Call {
            callee, arguments, ..
        } => {
            assert!(matches!(callee.as_ref(), Expression::Member { .. }));
            // tag(stringsObject): the `.raw`-attaching IIFE, no substitutions
            assert_eq!(arguments.len(), 1);
            assert!(matches!(&arguments[0], Expression::Call { .. }));
        }
        other => panic!("expected tagged member template call, got {other:?}"),
    }
}

#[test]
fn template_literal_unbalanced_interpolation_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `value: ${name`", ParseGoal::Script)
        .expect_err("unbalanced interpolation should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

// ── bd-no788: unterminated template-literal rejection ───────────────

#[test]
fn unterminated_template_literal_no_closing_backtick_is_rejected() {
    // Case 1 from bd-no788: an opening backtick that runs to EOF
    // without a closing backtick should fail-closed at parse time
    // (ES2020 §11.8.6 TemplateCharacter — termination is mandatory).
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `hello world", ParseGoal::Script)
        .expect_err("unterminated template literal should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn unterminated_template_literal_substitution_only_is_rejected() {
    // Case 2: `${value` — opening backtick + opening ${ + no closing
    // } or backtick. The outer template never sees its closing
    // backtick, so the parser rejects via the same path as Case 1.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `prefix ${value", ParseGoal::Script)
        .expect_err("unterminated substitution should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn unterminated_template_literal_after_substitution_is_rejected() {
    // Case 3: `${1 + 2} suffix — substitution closes cleanly with `}`
    // but the literal never sees its closing backtick.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `prefix ${1 + 2} suffix", ParseGoal::Script)
        .expect_err("missing trailing backtick should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

// ── bd-no788.1: legacy octal escapes forbidden in template literals ──

#[test]
fn template_literal_legacy_octal_escape_is_rejected() {
    // Case 4 from bd-no788: ES2020 §11.8.6 forbids legacy octal escapes
    // (`\01`) inside template literals — the Annex B carve-out is for
    // string literals only.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse(r"const s = `octal \01 escape`", ParseGoal::Script)
        .expect_err("legacy octal escape should fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn template_literal_non_octal_decimal_escape_is_rejected() {
    // `\9` is a NonOctalDecimalEscapeSequence — equally forbidden in
    // template literals.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse(r"const s = `bad \9 escape`", ParseGoal::Script)
        .expect_err("non-octal decimal escape should fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn template_literal_null_escape_is_accepted() {
    // `\0` not followed by a DecimalDigit is the NullEscapeSequence and
    // remains valid (the boundary case the octal check must not over-reject).
    let tree = parse_script(r"const s = `null\0ok`");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("initializer should be present");
            assert!(matches!(init, Expression::TemplateLiteral { .. }));
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

// ── bd-no788.2: malformed hex / unicode escapes forbidden ───────────

#[test]
fn template_literal_bad_unicode_escape_is_rejected() {
    // Case 5 from bd-no788: `\u{XYZ}` has non-HexDigit content
    // (ES2020 §11.8.4.1) and must be rejected at parse time.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse(r"const s = `bad unicode \u{XYZ}`", ParseGoal::Script)
        .expect_err("non-hex \\u{...} escape should fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn template_literal_out_of_range_unicode_escape_is_rejected() {
    // `\u{110000}` is well-formed hex but exceeds 0x10FFFF.
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse(r"const s = `over \u{110000} max`", ParseGoal::Script)
        .expect_err("out-of-range code point should fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn template_literal_bad_hex_escape_is_rejected() {
    // `\xZZ` is a HexEscapeSequence with non-hex digits (§11.8.4.1).
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse(r"const s = `bad hex \xZZ here`", ParseGoal::Script)
        .expect_err("non-hex \\xNN escape should fail");
    assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
}

#[test]
fn template_literal_valid_unicode_and_hex_escapes_are_accepted() {
    // Well-formed `\u{1F600}` and `\xFF` escapes must still parse.
    let tree = parse_script(r"const s = `emoji \u{1F600} byte \xFF end`");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0]
                .initializer
                .as_ref()
                .expect("initializer should be present");
            assert!(matches!(init, Expression::TemplateLiteral { .. }));
        }
        other => panic!("expected VariableDeclaration, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Spread operator (`...expr`) parsing
// -----------------------------------------------------------------------

#[test]
fn spread_in_array_literal() {
    let tree = parse_script("[1, ...arr, 3]");
    match first_expr(&tree) {
        Expression::ArrayLiteral(elements) => {
            assert_eq!(elements.len(), 3);
            assert!(matches!(
                elements[0]
                    .as_ref()
                    .expect("serde serialization should succeed"),
                Expression::NumericLiteral(1)
            ));
            match elements[1]
                .as_ref()
                .expect("serde serialization should succeed")
            {
                Expression::SpreadElement(inner) => {
                    assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "arr"));
                }
                other => panic!("expected SpreadElement, got {other:?}"),
            }
            assert!(matches!(
                elements[2]
                    .as_ref()
                    .expect("serde serialization should succeed"),
                Expression::NumericLiteral(3)
            ));
        }
        other => panic!("expected ArrayLiteral, got {other:?}"),
    }
}

#[test]
fn spread_in_array_literal_only() {
    let tree = parse_script("[...items]");
    match first_expr(&tree) {
        Expression::ArrayLiteral(elements) => {
            assert_eq!(elements.len(), 1);
            assert!(matches!(
                elements[0]
                    .as_ref()
                    .expect("serde serialization should succeed"),
                Expression::SpreadElement(_)
            ));
        }
        other => panic!("expected ArrayLiteral, got {other:?}"),
    }
}

#[test]
fn spread_in_function_call() {
    let tree = parse_script("foo(1, ...args)");
    match first_expr(&tree) {
        Expression::Call { arguments, .. } => {
            assert_eq!(arguments.len(), 2);
            assert!(matches!(&arguments[0], Expression::NumericLiteral(1)));
            match &arguments[1] {
                Expression::SpreadElement(inner) => {
                    assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "args"));
                }
                other => panic!("expected SpreadElement, got {other:?}"),
            }
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn spread_in_object_literal() {
    let tree = parse_script("({a: 1, ...obj})");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert_eq!(properties.len(), 2);
            // First property: a: 1
            assert!(!properties[0].shorthand);
            // Second property: spread
            assert!(properties[1].shorthand);
            assert!(matches!(&properties[1].value, Expression::SpreadElement(_)));
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }
}

#[test]
fn spread_only_object_literal() {
    let tree = parse_script("({...defaults})");
    match first_expr(&tree) {
        Expression::ObjectLiteral(properties) => {
            assert_eq!(properties.len(), 1);
            match &properties[0].value {
                Expression::SpreadElement(inner) => {
                    assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "defaults"));
                }
                other => panic!("expected SpreadElement, got {other:?}"),
            }
        }
        other => panic!("expected ObjectLiteral, got {other:?}"),
    }
}

#[test]
fn spread_element_standalone() {
    let tree = parse_script("...x");
    match first_expr(&tree) {
        Expression::SpreadElement(inner) => {
            assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "x"));
        }
        other => panic!("expected SpreadElement, got {other:?}"),
    }
}

#[test]
fn spread_in_new_expression() {
    let tree = parse_script("new Foo(...args)");
    match first_expr(&tree) {
        Expression::New { arguments, .. } => {
            assert_eq!(arguments.len(), 1);
            assert!(matches!(&arguments[0], Expression::SpreadElement(_)));
        }
        other => panic!("expected New, got {other:?}"),
    }
}

#[test]
fn spread_multiple_in_array() {
    let tree = parse_script("[...a, ...b]");
    match first_expr(&tree) {
        Expression::ArrayLiteral(elements) => {
            assert_eq!(elements.len(), 2);
            assert!(matches!(
                elements[0]
                    .as_ref()
                    .expect("serde serialization should succeed"),
                Expression::SpreadElement(_)
            ));
            assert!(matches!(
                elements[1]
                    .as_ref()
                    .expect("serde serialization should succeed"),
                Expression::SpreadElement(_)
            ));
        }
        other => panic!("expected ArrayLiteral, got {other:?}"),
    }
}

#[test]
fn spread_canonical_hash_stability() {
    let tree1 = parse_script("[...x]");
    let tree2 = parse_script("[...x]");
    assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
}

// -- RegExp literal parsing tests --

#[test]
fn parse_regexp_literal_simple_pattern() {
    assert_eq!(
        parse_regexp_literal("/hello/"),
        Some(("hello".to_string(), String::new()))
    );
}

#[test]
fn parse_regexp_literal_with_flags() {
    assert_eq!(
        parse_regexp_literal("/hello/gi"),
        Some(("hello".to_string(), "gi".to_string()))
    );
}

#[test]
fn parse_regexp_literal_with_all_flags() {
    assert_eq!(
        parse_regexp_literal("/test/gimsuy"),
        Some(("test".to_string(), "gimsuy".to_string()))
    );
}

#[test]
fn parse_regexp_literal_escaped_slash() {
    assert_eq!(
        parse_regexp_literal(r"/a\/b/"),
        Some((r"a\/b".to_string(), String::new()))
    );
}

#[test]
fn parse_regexp_literal_char_class_with_slash() {
    assert_eq!(
        parse_regexp_literal("/[/]/"),
        Some(("[/]".to_string(), String::new()))
    );
}

#[test]
fn parse_regexp_literal_complex_pattern() {
    assert_eq!(
        parse_regexp_literal(r"/^[\w.+-]+@[\w-]+\.[\w.]+$/i"),
        Some((r"^[\w.+-]+@[\w-]+\.[\w.]+$".to_string(), "i".to_string()))
    );
}

#[test]
fn parse_regexp_literal_not_regex() {
    assert_eq!(parse_regexp_literal("hello"), None);
    assert_eq!(parse_regexp_literal("42"), None);
    assert_eq!(parse_regexp_literal(""), None);
    assert_eq!(parse_regexp_literal(r#"/ab/.test("xabz")"#), None);
}

#[test]
fn parse_regexp_literal_unclosed() {
    assert_eq!(parse_regexp_literal("/hello"), None);
}

#[test]
fn regexp_literal_parses_as_expression() {
    let tree = parse_script("/test/gi;");
    match first_expr(&tree) {
        Expression::RegExpLiteral { pattern, flags } => {
            assert_eq!(pattern, "test");
            assert_eq!(flags, "gi");
        }
        other => panic!("expected RegExpLiteral, got {other:?}"),
    }
}

#[test]
fn regexp_literal_receiver_member_call_parses_bd_wni4m() {
    let tree = parse_script(r#"/ab/.test("xabz");"#);
    match first_expr(&tree) {
        Expression::Call {
            callee, arguments, ..
        } => {
            assert_eq!(arguments.len(), 1);
            match callee.as_ref() {
                Expression::Member {
                    object,
                    property,
                    computed,
                    ..
                } => {
                    assert!(!computed);
                    assert!(matches!(
                        object.as_ref(),
                        Expression::RegExpLiteral { pattern, flags }
                            if pattern == "ab" && flags.is_empty()
                    ));
                    assert!(matches!(
                        property.as_ref(),
                        Expression::Identifier(name) if name == "test"
                    ));
                }
                other => panic!("expected member callee, got {other:?}"),
            }
        }
        other => panic!("expected Call, got {other:?}"),
    }
}

#[test]
fn regexp_literal_canonical_hash_stability() {
    let tree1 = parse_script("/test/gi;");
    let tree2 = parse_script("/test/gi;");
    assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
}

// bd-9vouw.41: a template literal is one opaque unit to every source
// scanner, including its `${ ... }` substitutions, nested templates and
// strings inside substitutions.

#[test]
fn quoted_byte_mask_spans_nested_templates_and_substitution_strings_bd_9vouw_41() {
    let src = "`a${`<${x}>`}b${\"`\"}c`, 2";
    let mask = quoted_byte_mask(src);
    let literal_end = src.find(", 2").expect("tail");
    assert!(mask[..literal_end].iter().all(|quoted| *quoted));
    assert!(mask[literal_end..].iter().all(|quoted| !*quoted));

    // A brace inside a substitution string does not end the substitution.
    let src = "`x${\"}\"}y` + 1";
    let mask = quoted_byte_mask(src);
    let literal_end = src.find(" + 1").expect("tail");
    assert!(mask[..literal_end].iter().all(|quoted| *quoted));
    assert!(mask[literal_end..].iter().all(|quoted| !*quoted));
}

#[test]
fn quoted_byte_mask_reads_regex_literals_in_substitutions() {
    // js-yaml: the `'` inside `/'/g` is pattern text, not a string.
    let src = "`'${v.replace(/'/g, \"''\")}'` + 1";
    let mask = quoted_byte_mask(src);
    let literal_end = src.find(" + 1").expect("tail");
    assert!(mask[..literal_end].iter().all(|quoted| *quoted));
    assert!(mask[literal_end..].iter().all(|quoted| !*quoted));

    // After an operand a `/` divides, so `/ 2}` closes the substitution.
    let src = "`${a / 2}` + `${b}`";
    let mask = quoted_byte_mask(src);
    let first_end = src.find(" + ").expect("operator");
    assert!(mask[..first_end].iter().all(|quoted| *quoted));
    assert!(!mask[first_end + 1]);

    // A class may hold `/`, `` ` `` and `}`.
    let src = "`${s.split(/[/`}]/)}`;x";
    let mask = quoted_byte_mask(src);
    let literal_end = src.find(";x").expect("tail");
    assert!(mask[..literal_end].iter().all(|quoted| *quoted));
    assert!(!mask[literal_end]);
}

#[test]
fn scanners_see_a_nested_template_as_one_literal_bd_9vouw_41() {
    // The inner template's `<`, `,`, `)` and `;` are template text, not
    // operators, separators, delimiters or statement ends.
    let parts: Vec<&str> =
        split_top_level_commas("`${[1,2].map(x=>`<${x}>`).join(\"\")}`, `a${\"`\"}b`")
            .into_iter()
            .map(str::trim)
            .collect();
    assert_eq!(
        parts,
        vec!["`${[1,2].map(x=>`<${x}>`).join(\"\")}`", "`a${\"`\"}b`"]
    );
    assert_eq!(find_matching_open_paren("f(`)${`(`}`)"), Some(1));
    assert_eq!(find_top_level_template_start("tag(`)`)`x`"), Some(8));
    // bd-9vouw.342: the last of chained templates.
    assert_eq!(find_top_level_template_start("rec`x``y``z`"), Some(9));
    assert_eq!(find_top_level_template_start("t`${`a`}``b`"), Some(9));
    // A template used as a tag: `a` closes before `b` opens.
    assert_eq!(find_top_level_template_start("`a``b`"), Some(3));
    assert_eq!(find_top_level_template_start("`a${`b`}c`"), Some(0));
    let segments: Vec<&str> = split_statement_segments("a(`;${`;`}`); b;")
        .into_iter()
        .map(|(_, _, text)| text)
        .collect();
    assert_eq!(segments, vec!["a(`;${`;`}`)", "b"]);
    // `//` inside a nested template is not a comment.
    assert_eq!(
        strip_comments_to_whitespace("f(`${`http://x`}`); // c"),
        "f(`${`http://x`}`);     "
    );
}

#[test]
fn parse_nested_template_literals_bd_9vouw_41() {
    for (source, statements) in [
        ("console.log(`${[1,2].map(x=>`<${x}>`).join(\"\")}`);", 1),
        (
            "const h = `<ul>${items.map(it => `<li class=\"${it.k}\">${it.v > 1 ? `big ${it.v}` : `small`}</li>`).join(\"\")}</ul>`;",
            1,
        ),
        ("console.log(`a${\"`\"}b`, `c${'`'.length}d`);", 1),
        ("const u = `${`http://x`}`; next();", 2),
        ("const v = `1${`2${`3${4}3`}2`}1`;\nconst w = 2;", 2),
    ] {
        let tree = parse_script(source);
        assert_eq!(tree.body.len(), statements, "{source}");
    }
}
