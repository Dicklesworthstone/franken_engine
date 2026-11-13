use std::collections::BTreeSet;
use std::io::Cursor;

use super::*;

#[test]
fn script_goal_rejects_import_declaration() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("import x from 'mod';", ParseGoal::Script)
        .expect_err("script goal should reject import");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
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
    let source = "await work";
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
        .parse("await   work", ParseGoal::Script)
        .expect("left parse");
    let right = parser
        .parse("await work", ParseGoal::Script)
        .expect("right parse");

    let left_expr = match &left.body[0] {
        Statement::Expression(expr) => &expr.expression,
        _ => panic!("expected expression statement"),
    };
    let right_expr = match &right.body[0] {
        Statement::Expression(expr) => &expr.expression,
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
fn string_literal_line_continuations_and_braced_astral_escape_bd_vltnh() {
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

    assert_eq!(
        parse_quoted_expression_string(r#""\u{1F600}""#, LegacyDecimalEscapeMode::Reject,)
            .expect("braced astral escape should cook")
            .code_units_vec(),
        [0xD83D, 0xDE00]
    );
    assert_eq!(
        parse_quoted_expression_string("\"\\0\\\n8\"", LegacyDecimalEscapeMode::Reject,)
            .expect("continuation separates zero from a later digit")
            .code_units_vec(),
        [0x0000, u16::from(b'8')]
    );
    assert_eq!(
        parse_quoted_expression_string("\"\\uD83D\\\n\\uDE00\"", LegacyDecimalEscapeMode::Reject,)
            .expect("continuation may separate a surrogate escape pair")
            .code_units_vec(),
        [0xD83D, 0xDE00]
    );
}

#[test]
fn malformed_quoted_expression_literals_fail_closed_bd_vltnh() {
    let parser = CanonicalEs2020Parser;
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
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed quoted source must fail closed");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
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
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
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
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
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
        .expect("a valid exact quoted literal may be a postfix base");
    assert!(matches!(
        first_expr(&tree),
        Expression::Member {
            object,
            property,
            computed: false,
        } if matches!(object.as_ref(), Expression::StringLiteral(value)
            if value.code_units_vec() == [0xD800])
            && matches!(property.as_ref(), Expression::Identifier(name) if name == "length")
    ));

    let optional = CanonicalEs2020Parser
        .parse(r#""\uD800"?.length"#, ParseGoal::Script)
        .expect("an exact quoted literal may be an optional-chain base");
    assert!(matches!(
        first_expr(&optional),
        Expression::OptionalMember { object, .. }
            if matches!(object.as_ref(), Expression::StringLiteral(value)
                if value.code_units_vec() == [0xD800])
    ));

    let with_trivia = CanonicalEs2020Parser
        .parse(
            r#""\uD800"/* preserved trivia */.length"#,
            ParseGoal::Script,
        )
        .expect("postfix parsing owns trivia after a quoted base");
    assert!(matches!(
        first_expr(&with_trivia),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::StringLiteral(value)
                if value.code_units_vec() == [0xD800])
    ));

    for source in [
        r#""\xZZ".length"#,
        r#""a"b".length"#,
        r#""a"."#,
        r#""a"["#,
        r#""a"("#,
        r#""a"."b""#,
    ] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err("a malformed quoted postfix base must fail closed");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }
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
fn await_expression_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("await fetch", ParseGoal::Script)
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
        (r"N\u0061N", "NaN"),
        (r"Inf\u0069nity", "Infinity"),
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
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
fn rest_element_initializer_rejected() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "var [...x = 1] = source",
        "function f(...args = []) {}",
        "var [a, ...[b] = []] = source",
    ] {
        let err = parser
            .parse(source, ParseGoal::Script)
            .expect_err("a rest element with an initializer must fail");
        assert!(
            format!("{err}").contains("rest element cannot have an initializer"),
            "{source}: {err}"
        );
    }
    for source in ["var [a = 1, ...rest] = source", "var [...[b = 1]] = source"] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|err| panic!("{source} must parse: {err}"));
    }
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
fn whole_pattern_defaults_parse_before_containers_bd_laab3() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "function objectDefault({ a = 5 } = {}) { return a; }",
            ParseGoal::Script,
        )
        .expect("whole object-pattern default should parse");
    let Statement::FunctionDeclaration(function) = &tree.body[0] else {
        panic!("expected function declaration");
    };
    let BindingPattern::AssignmentPattern { left, .. } = &function.params[0].pattern else {
        panic!("expected outer assignment pattern");
    };
    let BindingPattern::ObjectPattern(properties) = left.as_ref() else {
        panic!("expected object-pattern left side");
    };
    assert!(matches!(
        &properties[0].value,
        BindingPattern::AssignmentPattern { .. }
    ));

    let tree = parser
        .parse("let arrayDefault = ([a = 7] = []) => a;", ParseGoal::Script)
        .expect("whole array-pattern default should parse");
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected variable declaration");
    };
    let Some(Expression::ArrowFunction { params, .. }) =
        declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected arrow initializer");
    };
    let BindingPattern::AssignmentPattern { left, .. } = &params[0].pattern else {
        panic!("expected outer assignment pattern");
    };
    let BindingPattern::ArrayPattern(elements) = left.as_ref() else {
        panic!("expected array-pattern left side");
    };
    assert!(matches!(
        &elements[0],
        Some(BindingPattern::AssignmentPattern { .. })
    ));
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
fn object_binding_property_keys_are_semantic_ast_values_bd_h4esx() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"var {'v\x61lue': quoted, \u0076alue: escaped_identifier, 0x10: hex, 1e3: exponent, 9007199254740993: rounded_number, 0x10n: radix_bigint, 9007199254740993n: precise_bigint, π: unicode_name, \u03C0: escaped_unicode_name} = source"#,
            ParseGoal::Script,
        )
        .expect("static property names should parse to semantic key values");
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected variable declaration");
    };
    let BindingPattern::ObjectPattern(properties) = &declaration.declarations[0].pattern else {
        panic!("expected object binding pattern");
    };
    assert_eq!(properties.len(), 9);
    assert_eq!(properties[0].key, Expression::StringLiteral("value".into()));
    assert_eq!(
        properties[1].key,
        Expression::Identifier("value".to_string())
    );
    assert_eq!(properties[2].key, Expression::NumericLiteral(16));
    assert_eq!(properties[3].key, Expression::NumericLiteral(1000));
    assert_eq!(
        properties[4].key,
        Expression::NumericLiteral(9_007_199_254_740_992)
    );
    assert_eq!(properties[5].key, Expression::StringLiteral("16".into()));
    assert_eq!(
        properties[6].key,
        Expression::StringLiteral("9007199254740993".into())
    );
    assert_eq!(properties[7].key, Expression::Identifier("π".to_string()));
    assert_eq!(properties[8].key, Expression::Identifier("π".to_string()));
}

#[test]
fn binding_patterns_treat_comments_and_bom_as_trivia_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "let/* declaration */\u{FEFF}{/* lead */ value /* : , = } ] */: /* target */ x, \
             'quoted' /* : , = */: y, 1 /* : , = */: z, \
             [/* ] , : = */ 'computed' /* ] */] /* : */: computed, \
             shorthand /* = , */ = 5, ... /* rest */ rest} = source; \
             let [/* comment-only hole */, first /* , = ] } */ = 1, second] = values; \
             let empty = (/* no parameters */) => 1;",
            ParseGoal::Script,
        )
        .expect("comments and BOM are lexical trivia around binding-pattern tokens");

    let Statement::VariableDeclaration(object_declaration) = &tree.body[0] else {
        panic!("expected object-binding declaration");
    };
    let BindingPattern::ObjectPattern(properties) = &object_declaration.declarations[0].pattern
    else {
        panic!("expected object-binding pattern");
    };
    assert_eq!(properties.len(), 6);
    assert_eq!(properties[0].key, Expression::Identifier("value".into()));
    assert!(matches!(
        &properties[0].value,
        BindingPattern::Identifier(name) if name == "x"
    ));
    assert_eq!(
        properties[1].key,
        Expression::StringLiteral("quoted".into())
    );
    assert_eq!(properties[2].key, Expression::NumericLiteral(1));
    assert!(properties[3].computed);
    assert!(matches!(
        &properties[4].value,
        BindingPattern::AssignmentPattern { left, .. }
            if matches!(left.as_ref(), BindingPattern::Identifier(name) if name == "shorthand")
    ));
    assert!(matches!(
        &properties[5].value,
        BindingPattern::Rest(inner)
            if matches!(inner.as_ref(), BindingPattern::Identifier(name) if name == "rest")
    ));

    let Statement::VariableDeclaration(array_declaration) = &tree.body[1] else {
        panic!("expected array-binding declaration");
    };
    assert!(matches!(
        &array_declaration.declarations[0].pattern,
        BindingPattern::ArrayPattern(elements)
            if elements.len() == 3
                && elements[0].is_none()
                && matches!(&elements[1], Some(BindingPattern::AssignmentPattern { .. }))
                && matches!(&elements[2], Some(BindingPattern::Identifier(name)) if name == "second")
    ));

    let Statement::VariableDeclaration(arrow_declaration) = &tree.body[2] else {
        panic!("expected arrow declaration");
    };
    assert!(matches!(
        arrow_declaration.declarations[0].initializer.as_ref(),
        Some(Expression::ArrowFunction { params, .. }) if params.is_empty()
    ));

    parser
        .parse(
            "let {line // : , = ] }\n: renamed} = source",
            ParseGoal::Script,
        )
        .expect("a line comment may separate a property name from its colon");
    parser
        .parse(
            "let emptyObject = ({/* comment only */} = {}) => 1; \
             let trailingParameter = (value, /* trailing */) => value;",
            ParseGoal::Script,
        )
        .expect("comment-only empty patterns and trivia after a trailing comma remain valid");
    let tight_default_tree = parser
        .parse(
            "let {x/* tight */=1} = source; \
             let [y/* tight */=2] = values; \
             function defaults(value/* tight */=3) {} \
             let arrow = (value/* tight */=4) => value; \
             let {whole}/* tight */={whole: 5};",
            ParseGoal::Script,
        )
        .expect("a comment immediately before a default equals remains lexical trivia");
    assert_eq!(tight_default_tree.body.len(), 5);
    let comment_segment_tree = parser
        .parse(
            "let/* ; ' \" ` { [ ( */first = 1; \
             let second/* ; } ] ) */=2; \
             let third = 3/* ; } ] ) */, fourth = 4;",
            ParseGoal::Script,
        )
        .expect("comment punctuation cannot split or rebalance binding declarations");
    assert_eq!(comment_segment_tree.body.len(), 3);
    assert!(matches!(
        &comment_segment_tree.body[2],
        Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
    ));
    parser
        .parse(
            "var let = value; var counter = 1; let\n++counter; let\n(4);",
            ParseGoal::Script,
        )
        .expect("sloppy let preserves update ASI and call continuation across a line ending");
    parser
        .parse(
            "let {escaped = /\\//, matcher = /[,:=]/, product = /a/*factor} = source; \
             let re = /\\//, value = 1",
            ParseGoal::Script,
        )
        .expect("comment recognition must not consume RegExp literals or following multiply");
    let regexp_division_tree = parser
        .parse("let {x = /a/ / 2, y = /b/ / 3} = source", ParseGoal::Script)
        .expect("division after a RegExp literal must preserve the next binding property");
    let Statement::VariableDeclaration(regexp_declaration) = &regexp_division_tree.body[0] else {
        panic!("expected RegExp-default binding declaration");
    };
    assert!(matches!(
        &regexp_declaration.declarations[0].pattern,
        BindingPattern::ObjectPattern(properties) if properties.len() == 2
    ));
    parser
        .parse(
            "let {line = // trivia\n/\\//, bom = \u{FEFF}/\\//, \
             block = /* trivia */ /\\//} = source",
            ParseGoal::Script,
        )
        .expect("RegExp context survives line, block, and BOM binding trivia");
    parser
        .parse(
            "for (let/* trivia */[x] of values) {} \
             for (const\u{FEFF}{x} of values) {} \
             for (var/* trivia */{x} in source) {}",
            ParseGoal::Script,
        )
        .expect("for-in/of declaration bindings accept comment and BOM trivia");
    let for_comment_tree = parser
        .parse(
            "for (const {x /* } in */: y} of [{x: 7}]) { y; } \
             for (const matcher of / in /) {} \
             for (let x/* comment */of [1]) {} \
             for (let x\tin {a: 1}) {} \
             for (let x\u{FEFF}of [1]) {} \
             for (let x /* before */ in/* after */ {x: 1}) {} \
             for (let of of [1]) {} \
             for (let of in {x: 1}) {} \
             for (const [nested = 1] of [[]]) {} \
             for (let in {x: 1}) {}",
            ParseGoal::Script,
        )
        .expect("fake loop keywords inside comments and RegExp literals are ignored");
    assert!(matches!(
        &for_comment_tree.body[0],
        Statement::ForOf(statement)
            if matches!(&statement.binding, BindingPattern::ObjectPattern(properties) if properties.len() == 1)
    ));
    assert!(matches!(&for_comment_tree.body[1], Statement::ForOf(_)));
    for (index, expected_of) in [true, false, true, false, true, false, true, false]
        .into_iter()
        .enumerate()
    {
        let statement = &for_comment_tree.body[index + 2];
        assert_eq!(
            matches!(statement, Statement::ForOf(_)),
            expected_of,
            "unexpected loop kind at donor case {index}"
        );
    }
    let Statement::ForOf(contextual_of_loop) = &for_comment_tree.body[6] else {
        panic!("expected contextual `let of` declaration in for-of loop");
    };
    assert_eq!(
        contextual_of_loop.binding_kind,
        Some(VariableDeclarationKind::Let)
    );
    assert!(matches!(
        &contextual_of_loop.binding,
        BindingPattern::Identifier(name) if name == "of"
    ));
    let Statement::ForIn(bare_let_loop) = &for_comment_tree.body[9] else {
        panic!("expected sloppy bare-let for-in loop");
    };
    assert_eq!(bare_let_loop.binding_kind, None);
    assert!(matches!(
        &bare_let_loop.binding,
        BindingPattern::Identifier(name) if name == "let"
    ));
    let contextual_loop_tree = parser
        .parse(
            "for (async in {}) {} \
             for (let async of []) {} \
             for (var async of []) {} \
             for (let [...rest] of [[]]) {}",
            ParseGoal::Script,
        )
        .expect("for-head contextual names and nested rest follow ES2020 early errors");
    assert!(matches!(&contextual_loop_tree.body[0], Statement::ForIn(_)));
    assert!(
        contextual_loop_tree.body[1..]
            .iter()
            .all(|statement| matches!(statement, Statement::ForOf(_)))
    );

    let unparenthesized_arrow_tree = parser
        .parse(
            "let commented = value /* fake => */ => value; \
             let bom = item\u{FEFF}=> item; \
             let asynchronous = async value /* trivia */ => value; \
             let asyncComment = async/* trivia */value => value; \
             let asyncBom = async\u{FEFF}(value) => value; \
             let parenthesizedComment = (value)/* trivia */=> value; \
             let parenthesizedBom = (value)\u{FEFF}=> value; \
             let asyncBoth = async/**/(value)/* trivia */=> value;",
            ParseGoal::Script,
        )
        .expect("arrow bindings accept comment and BOM trivia around the arrow token");
    for (statement, expected_async) in unparenthesized_arrow_tree
        .body
        .iter()
        .zip([false, false, true, true, true, false, false, true])
    {
        let Statement::VariableDeclaration(declaration) = statement else {
            panic!("expected arrow variable declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::ArrowFunction { params, is_async, .. })
                if params.len() == 1 && *is_async == expected_async
        ));
    }

    let parameter_tree = parser
        .parse(
            "let arrow = (/* ) */ value) => value; \
             function regular(/* ( */ value) { return value; } \
             class C { first(/* ( */ value) {} second(other) {} }",
            ParseGoal::Script,
        )
        .expect("comment delimiters do not terminate or inflate parameter lists");
    let Statement::VariableDeclaration(arrow_declaration) = &parameter_tree.body[0] else {
        panic!("expected arrow declaration");
    };
    assert!(matches!(
        arrow_declaration.declarations[0].initializer.as_ref(),
        Some(Expression::ArrowFunction { params, .. }) if params.len() == 1
    ));
    let Statement::FunctionDeclaration(function) = &parameter_tree.body[1] else {
        panic!("expected function declaration");
    };
    assert_eq!(function.params.len(), 1);
    let Statement::ClassDeclaration(class) = &parameter_tree.body[2] else {
        panic!("expected class declaration");
    };
    assert_eq!(class.body.len(), 2);
    assert_eq!(class.body[0].params.len(), 1);
    assert_eq!(class.body[0].key, Expression::Identifier("first".into()));
    assert_eq!(class.body[1].key, Expression::Identifier("second".into()));

    let line_comment_declarations = parser
        .parse(
            "let// declaration trivia\nx = 1;\n\
             const// declaration trivia\ny = 2;\n\
             var// declaration trivia\nz = 3;\n\
             let/* closed block trivia */\nblockValue = 4;\n\
             const\u{FEFF}\nbomValue = 5;\n\
             var\nplainValue = 6;",
            ParseGoal::Script,
        )
        .expect("a line terminator may separate a declaration keyword from its binding");
    assert_eq!(line_comment_declarations.body.len(), 6);

    let continued_declarations = parser
        .parse(
            "const first // before initializer\n= 2; \
             let second // before initializer\n= 3; \
             const [third] // before initializer\n= [4]; \
             let fourth // before comma\n, fifth = 5;",
            ParseGoal::Script,
        )
        .expect("a declaration continues across trailing comment trivia before equals or comma");
    assert_eq!(continued_declarations.body.len(), 4);
    assert!(matches!(
        &continued_declarations.body[3],
        Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
    ));

    let array_edge_tree = parser
        .parse(
            "let [] = empty; let [/* comment only */] = alsoEmpty; \
             let [/* comment */,] = oneHole; let [,/* comment */] = anotherHole;",
            ParseGoal::Script,
        )
        .expect("comment trivia preserves empty arrays and exact elision counts");
    for (index, expected_elements) in [0, 0, 1, 1].into_iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = &array_edge_tree.body[index] else {
            panic!("expected array binding declaration");
        };
        let BindingPattern::ArrayPattern(elements) = &declaration.declarations[0].pattern else {
            panic!("expected array binding pattern");
        };
        assert_eq!(elements.len(), expected_elements);
        assert!(elements.iter().all(Option::is_none));
    }

    assert_eq!(
        split_pattern_elements("x = numerator /* trivia */ / denominator, y = left / right").len(),
        2,
        "division after a comment must not consume the next pattern comma as RegExp text"
    );
    assert_eq!(
        split_var_declarator_segments("x = 12 /* trivia */ / 3, y = /z/").len(),
        2,
        "division after a comment must preserve the next variable declarator"
    );
    assert_eq!(
        split_var_declarator_segments("x = /a/ / 2, y = /b/").len(),
        2,
        "a completed RegExp is an operand, so a following slash is division"
    );
    for source in [
        "x = obj.in / divisor, y = left / right",
        "x = obj.return / divisor, y = left / right",
        "x = obj.await / divisor, y = left / right",
        "x = value++ / divisor, y = left / right",
        "x = value-- / divisor, y = left / right",
        "x = value/* trivia */++ / divisor, y = left / right",
        "x = key in /[,]/, y = left / right",
        "x = key instanceof /[,]/, y = left / right",
    ] {
        assert_eq!(
            split_pattern_elements(source).len(),
            2,
            "member keywords and postfix updates remain operands before division: {source}"
        );
    }
    for identifier in ["await", "yield", "of"] {
        let source = format!("x = {identifier} / 2, y = /b/");
        assert_eq!(
            split_var_declarator_segments(&source).len(),
            2,
            "contextual identifier remains an operand before division: {source}"
        );
    }
    assert_eq!(
        extract_balanced("(x++ / y) / z", '(', ')'),
        Some(("x++ / y", " / z"))
    );
}

#[test]
fn merge_logical_lines_preserves_es_whitespace_before_regexp_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    let source = "let {x = \u{FEFF}/[}]/,\n y} = {};";
    let lines = merge_logical_lines(source);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.contains("\n y}"));

    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("BOM trivia must preserve the RegExp lexical goal across physical lines");
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if matches!(
                &declaration.declarations[0].pattern,
                BindingPattern::ObjectPattern(properties) if properties.len() == 2
            )
    ));

    let tree = parser
        .parse(
            r"let holder = async function y\u0069eld() {};",
            ParseGoal::Script,
        )
        .expect("valid async function-expression name should canonicalize");
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Function {
                    name: Some(name),
                    is_async: true,
                    is_generator: false,
                    ..
                }) if name == "yield"
            )
    ));

    let mut trivia_run = String::from("let\n");
    trivia_run.push_str(&"/* trivia-only physical line */\n".repeat(256));
    trivia_run.push_str("value = 1;");
    let trivia_lines = merge_logical_lines(&trivia_run);
    assert_eq!(trivia_lines.len(), 1);
    parser
        .parse(trivia_run.as_str(), ParseGoal::Script)
        .expect("long trivia-only runs preserve a pending declaration in linear scans");

    let declarators = (0..500)
        .map(|index| format!("x{index}"))
        .collect::<Vec<_>>()
        .join("\n,\n");
    let significant_run = format!("let\n{declarators};");
    let significant_lines = merge_logical_lines(&significant_run);
    assert_eq!(significant_lines.len(), 1);
    let significant_tree = parser
        .parse(significant_run.as_str(), ParseGoal::Script)
        .expect("significant multiline declarators use incremental continuation state");
    assert!(matches!(
        &significant_tree.body[0],
        Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 500
    ));

    for source in [
        "let\nx = `foo\nbar`\n,\ny = 1;",
        "let\nx =\n\"a\\\nb\"\n,\ny;",
        "let\nx = `foo\nbar`,\ny = 1;",
        "let\nx =\n\"a\\\nb\",\ny;",
    ] {
        assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("inherited literal state must survive an incremental line fragment");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if declaration.declarations.len() == 2
        ));
    }

    let mut else_if_run = String::from("if (false) {}");
    else_if_run.push_str(&"\nelse if (false) {}".repeat(500));
    else_if_run.push_str("\nelse {}");
    assert_eq!(merge_logical_lines(&else_if_run).len(), 1);
}

#[test]
fn merge_logical_lines_tracks_multiline_clause_phases_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;

    let standalone_else = "let x = 0;\nif (false) {}\nelse\nx = 2;\nx;";
    assert_eq!(merge_logical_lines(standalone_else).len(), 3);
    let standalone_tree = parser
        .parse(standalone_else, ParseGoal::Script)
        .expect("a standalone else may precede an arbitrary Statement");
    assert_eq!(standalone_tree.body.len(), 3);
    assert!(matches!(
        &standalone_tree.body[1],
        Statement::If(statement) if statement.alternate.is_some()
    ));

    let split_assignment = "let x = 0;\nif (false) {}\nelse\nx\n= 2;\nx;";
    assert_eq!(merge_logical_lines(split_assignment).len(), 3);
    assert_eq!(
        parser
            .parse(split_assignment, ParseGoal::Script)
            .expect("an alternate expression may continue with an assignment operator")
            .body
            .len(),
        3
    );

    for source in [
        "if (false) {}\nelse\nhit = ({})\ninstanceof\nObject;",
        "if (false) {}\nelse\nhit = typeof\nmissing;",
        "if (false) {}\nelse\n++\nx;",
        "if (false) {}\nelse\nwhile (x < 1) x\n= 1;",
        "if (false) {}\nelse\nif (true) x\n= 1;",
    ] {
        assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
        parser
            .parse(source, ParseGoal::Script)
            .expect("an alternate retains every required expression and inline body tail");
    }

    for alternate in ["obj.new", "obj.in", "/a/", "1."] {
        let source = format!("if (false) {{}}\nelse\n{alternate}\nx = 2;");
        assert_eq!(
            merge_logical_lines(&source).len(),
            2,
            "a complete operand must permit ASI before the next statement: {source:?}"
        );
        parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect("member, RegExp, and numeric operands remain complete alternate statements");
    }

    for alternate in ["1.0.", ".5.", "1e2.", "1e+2.", "1e-2.", "0x1."] {
        let source = format!("if (false) {{}}\nelse\n{alternate}\ntoString();");
        assert_eq!(
            merge_logical_lines(&source).len(),
            1,
            "a member-access dot after a numeric literal must retain its property: {source:?}"
        );
        parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect("a numeric member expression may continue after its member-access dot");
    }

    for next_statement in ["[1];", "(x = 10);", "`tag`;"] {
        let source = format!("let x = 0;\nif (false) {{}}\nelse\nx++\n{next_statement}\nx;");
        assert_eq!(
            merge_logical_lines(&source).len(),
            4,
            "a postfix update is ASI-separated from postfix-only syntax: {source:?}"
        );
        assert_eq!(
            parser
                .parse(source.as_str(), ParseGoal::Script)
                .expect("postfix update restricted productions permit ASI")
                .body
                .len(),
            4
        );
    }
    let postfix_division = "if (false) {}\nelse\nx++\n/ divisor;\ny = 2;";
    assert_eq!(
        merge_logical_lines(postfix_division).len(),
        2,
        "binary division may continue a completed postfix update without leaking lexical state"
    );
    let postfix_division_tree = parser
        .parse(postfix_division, ParseGoal::Script)
        .expect("postfix update followed by cross-line division remains a clause body");
    assert_eq!(postfix_division_tree.body.len(), 2);
    let Statement::If(if_statement) = &postfix_division_tree.body[0] else {
        panic!("expected the postfix division to remain the alternate statement");
    };
    assert!(matches!(
        if_statement.alternate.as_deref(),
        Some(Statement::Expression(ExpressionStatement {
            expression: Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                right,
            },
            ..
        })) if matches!(
            left.as_ref(),
            Expression::Update {
                operator: UpdateOperator::Increment,
                argument,
                prefix: false,
            } if matches!(argument.as_ref(), Expression::Identifier(name) if name == "x")
        ) && matches!(right.as_ref(), Expression::Identifier(name) if name == "divisor")
    ));

    for source in [
        "if (false) {}\nelse\n/[{]/;\nx = 2;",
        "if (false) {}\nelse\n/=/;\nx = 2;",
        "if (false) {}\nelse\n/=/\nlet x = 2;",
        "if (false) {} else /[{]/;\nx = 2;",
        "if (false) {}\nelse\nif (true)\n/[{]/;\nx = 2;",
        "if (false) {}\nelse\nwhile (false) /[{]/;\nx = 2;",
        "if (false) {}\nelse\ndo /[{]/; while (false);\nx = 2;",
        "if (false) {} else while (false) /[{]/;\nx = 2;",
        "if (false) {}\nelse {\nwhile (false) /[{]/;\n}\nx = 2;",
    ] {
        assert_eq!(
            merge_logical_lines(source).len(),
            2,
            "a RegExp statement body must not leak character-class delimiters: {source:?}"
        );
        assert_eq!(
            parser
                .parse(source, ParseGoal::Script)
                .expect("a pending clause statement starts with the RegExp lexical goal")
                .body
                .len(),
            2,
            "source: {source:?}"
        );
    }
    let regexp_after_else_block = "if (false) {}\nelse {} /[{]/;\nx = 2;";
    assert_eq!(merge_logical_lines(regexp_after_else_block).len(), 2);
    assert_eq!(
        parser
            .parse(regexp_after_else_block, ParseGoal::Script)
            .expect("a RegExp after an else block remains an independent statement")
            .body
            .len(),
        3,
        "the if statement, RegExp expression, and assignment are distinct statements"
    );
    for member in ["obj.do", "obj.else", "obj.in"] {
        let source = format!("if (false) {{}}\nelse\n{member} / divisor;\nx = 2;");
        assert_eq!(
            merge_logical_lines(&source).len(),
            2,
            "a keyword-named member remains an operand before division: {source:?}"
        );
    }
    for source in [
        "if (false) {}\nelse\n/a/ / 2;\ny = 2;",
        "if (false) {}\nelse\n/a/\n/ 2;\ny = 2;",
    ] {
        assert_eq!(
            merge_logical_lines(source).len(),
            2,
            "a completed RegExp is an operand before division: {source:?}"
        );
    }
    for operator in ["++", "--"] {
        let source = format!("if (false) {{}}\nelse\n{operator}\n/a/.lastIndex;\ny = 2;");
        assert_eq!(
            merge_logical_lines(&source).len(),
            2,
            "a LineTerminator forces an update at statement start to be prefix: {source:?}"
        );
        parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect("a split prefix update retains the RegExp lexical goal");
    }
    for block_prefix_update in [
        "{ x\n++/[{]/.lastIndex; }\ny = 2;",
        "{ x// comment\n++/[{]/.lastIndex; }\ny = 2;",
        "{ x/* comment\n*/++/[{]/.lastIndex; }\ny = 2;",
    ] {
        assert_eq!(merge_logical_lines(block_prefix_update).len(), 2);
        parser
            .parse(block_prefix_update, ParseGoal::Script)
            .expect("LineTerminator-restricted updates remain prefix inside a block");
    }

    let regexp_equals = "let r = /=[{]/; let x = 2;";
    assert_eq!(merge_logical_lines(regexp_equals).len(), 1);
    assert_eq!(
        parser
            .parse(regexp_equals, ParseGoal::Script)
            .expect("slash-equals begins a RegExp in an expression lexical goal")
            .body
            .len(),
        2
    );

    let nested_else = "if (false) {}\nelse\nif (false) {}\nelse {}";
    assert_eq!(merge_logical_lines(nested_else).len(), 1);
    let nested_tree = parser
        .parse(nested_else, ParseGoal::Script)
        .expect("a dangling else binds to the nested if alternate");
    assert!(matches!(
        &nested_tree.body[0],
        Statement::If(statement)
            if matches!(
                statement.alternate.as_deref(),
                Some(Statement::If(nested)) if nested.alternate.is_some()
            )
    ));

    let multiline_else_if = "if (false) {}\nelse if (false) {\n  let value = 1;\n}\nelse {}";
    assert_eq!(merge_logical_lines(multiline_else_if).len(), 1);
    parser
        .parse(multiline_else_if, ParseGoal::Script)
        .expect("a multiline else-if body remains eligible for its else clause");

    for source in [
        "if (false) {}\nelse\nwhile (false)\nx++;",
        "if (false) {}\nelse\nwhile\n(false)\nx++;",
    ] {
        assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
        parser
            .parse(source, ParseGoal::Script)
            .expect("a control-statement alternate retains its required body");
    }

    let independent_while = "if (false) {}\nelse {}\nwhile (false) {}";
    assert_eq!(merge_logical_lines(independent_while).len(), 2);
    assert_eq!(
        parser
            .parse(independent_while, ParseGoal::Script)
            .expect("an independent while must not be absorbed by an else clause")
            .body
            .len(),
        2
    );

    for source in [
        "try {}\ncatch\n(error)\n{\n}\nfinally\n{\n}",
        "try {}\nfinally\n{\n}",
        "do {}\nwhile\n(false);",
    ] {
        assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
        parser
            .parse(source, ParseGoal::Script)
            .expect("required clause tails may span balanced physical fragments");
    }

    let mut malformed_else_if = String::from("if (false) {}\nelse\nif");
    malformed_else_if.push_str(
        &(0..512)
            .map(|index| format!("\nidentifier{index}"))
            .collect::<String>(),
    );
    assert_eq!(
        merge_logical_lines(&malformed_else_if).len(),
        513,
        "an impossible balanced if head must fail its clause phase immediately"
    );

    let deeply_nested_inline = format!("if (false) {{}}\nelse\n{}x = 1;", "if (true) ".repeat(512));
    assert_eq!(
        merge_logical_lines(&deeply_nested_inline).len(),
        1,
        "inline control-body descent must advance through strict suffixes"
    );

    let nested_divisions = format!(
        "if (false) {{}}\nelse\n{}{};",
        "if (true) ".repeat(256),
        std::iter::repeat_n("x", 256)
            .collect::<Vec<_>>()
            .join(" / ")
    );
    assert_eq!(
        merge_logical_lines(&nested_divisions).len(),
        1,
        "incremental lexical goals must not rescan nested control prefixes per division"
    );
}

#[test]
fn do_while_statement_boundaries_use_statement_phases_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "do /while/; while (false); x();",
        "if (false) {} else do /[{]/; while (false); x();",
        "if (false) {} else do {} while (false); x();",
        "if (false) {} else do switch (value) {} while (false); x();",
        "do do x(); while (a); while (b); y();",
        "do do x(); while (a)\nwhile (b); while (c) y();",
        "do do 0\nwhile (false); while (false); while (false) 1;",
        "do do 0\nwhile (false)\nwhile (false); while (false) 1;",
        "if (true) do 0\nwhile (false); while (false) 1;",
        "do if (q) do x(); while (a)\nwhile (b); while (c) y();",
        "do if (q) do x(); while (a); else y()\nwhile (b); while (c) y();",
        "do if (q) do x(); while (a); else while (z) y()\nwhile (b); while (c) y();",
        "do if (q) do x()\nwhile (a)\nwhile (b)\nwhile (c) y();",
        "do while (a) do x(); while (b); while (c); while (d) y();",
        "do while (a) x++; while (b); y();",
        "do while (a) x()\nwhile (b); y();",
        "do x()\nwhile (a)\nwhile (b) y();",
        "do if (condition) x(); else y(); while (false); z();",
        "if (condition) do x(); while (false); else y(); z();",
        "do object.while(); /* trailer */ \u{FEFF}while (false); x();",
        "do value\nwhile (false); while (other) y();",
    ] {
        assert_eq!(
            split_statement_segments(source).len(),
            2,
            "do-while body and trailer must remain one statement: {source:?}"
        );
        assert_eq!(
            parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!("phase-aware do-while segmentation must parse {source:?}: {error:?}")
                })
                .body
                .len(),
            2,
            "source: {source:?}"
        );
    }

    let nested_alternate_chain = "do if (false) x(); else do if (false) x(); else do y()\nwhile (a)\nwhile (b)\nwhile (c); z();";
    assert_eq!(split_statement_segments(nested_alternate_chain).len(), 2);
    let nested_alternate_first_trailer =
        "do if (false) x(); else do if (false) x(); else do y()\nwhile (a)";
    assert_eq!(
        split_statement_segments(nested_alternate_first_trailer).len(),
        1
    );
    assert!(!do_while_statement_is_complete(
        nested_alternate_first_trailer,
        ScanGrammarContext::SLOPPY_SCRIPT,
    ));
    assert!(!do_while_statement_is_complete(
        "do if (false) x(); else do if (false) x(); else do y()\nwhile (a)\nwhile (b)",
        ScanGrammarContext::SLOPPY_SCRIPT,
    ));
    let nested_alternate_lines = merge_logical_lines(nested_alternate_chain);
    assert_eq!(
        nested_alternate_lines
            .iter()
            .map(|line| split_statement_segments(&line.text).len())
            .sum::<usize>(),
        2,
        "logical lines: {:?}",
        nested_alternate_lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        parser
            .parse(nested_alternate_chain, ParseGoal::Script)
            .expect("nested alternate owners must retain their do-while trailers")
            .body
            .len(),
        2
    );

    let independent = "foo(); while (condition) bar();";
    assert_eq!(split_statement_segments(independent).len(), 2);
    assert_eq!(
        parser
            .parse(independent, ParseGoal::Script)
            .expect("an independent while remains a separate statement")
            .body
            .len(),
        2
    );

    let else_after_trailer = "do if (condition) x(); while (false); else y();";
    assert_eq!(
        split_statement_segments(else_after_trailer).len(),
        2,
        "an else after the do-while trailer cannot be merged back into its body"
    );

    let dangling_else_after_independent_while =
        "if (true) do 0\nwhile(false); while(false) 1; else 2;";
    assert_eq!(
        split_statement_segments(dangling_else_after_independent_while).len(),
        3,
        "an independent while cannot inherit the completed do's enclosing if clause"
    );

    for nested_depth in 1..=20 {
        let nested_chain = format!(
            "{}x()\n{}",
            "do ".repeat(nested_depth),
            "while (false)\n".repeat(nested_depth)
        );
        assert!(
            do_while_statement_is_complete(&nested_chain, ScanGrammarContext::SLOPPY_SCRIPT,),
            "memoized phase matching must keep depth {nested_depth} tractable: {nested_chain:?}"
        );
    }

    let explicit_depth = 64;
    let explicit_chain = format!(
        "{}x(); {}while (true) y();",
        "do ".repeat(explicit_depth),
        "while (false); ".repeat(explicit_depth)
    );
    assert_eq!(
        split_statement_segments(&explicit_chain).len(),
        2,
        "claimed trailers must retire incrementally across an explicit nested chain"
    );

    let asi_depth = 128;
    let asi_chain = format!(
        "{}x()\n{}while (true) y();",
        "do ".repeat(asi_depth),
        "while (false)\n".repeat(asi_depth)
    );
    assert_eq!(
        split_statement_segments(&asi_chain).len(),
        2,
        "ASI trailers must retire tractably across a nested chain"
    );
    assert_eq!(
        parser
            .parse(asi_chain.as_str(), ParseGoal::Script)
            .expect("a deep ASI trailer chain must remain parseable")
            .body
            .len(),
        2,
        "logical-line merging must preserve the same ASI boundaries"
    );

    let shallow_options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1024,
            max_recursion_depth: 1,
        },
    };
    let shallow_error = parser
        .parse_with_options(
            "do do x(); while (false); while (false);",
            ParseGoal::Script,
            &shallow_options,
        )
        .expect_err("nested do-while parsing must honor the configured recursion budget");
    assert_eq!(
        shallow_error.code,
        ParseErrorCode::BudgetExceeded,
        "statement preprocessing must not mask recursion exhaustion"
    );

    let regexp_named_do = "/do/; while (condition) bar();";
    assert_eq!(split_statement_segments(regexp_named_do).len(), 2);
    assert_eq!(
        parser
            .parse(regexp_named_do, ParseGoal::Script)
            .expect("a do token inside a RegExp does not arm a while trailer")
            .body
            .len(),
        2
    );

    for quoted_follower in [
        "do x(); while (false) /re/; y();",
        "do x(); while (false) \"next\"; y();",
        "do x(); while (false) `next`; y();",
    ] {
        assert_eq!(
            split_statement_segments(quoted_follower).len(),
            3,
            "a quoted token after a completed do-while begins a new statement: {quoted_follower:?}"
        );
        assert_eq!(
            parser
                .parse(quoted_follower, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!(
                        "quoted follower must remain parseable in {quoted_follower:?}: {error:?}"
                    )
                })
                .body
                .len(),
            3,
            "source: {quoted_follower:?}"
        );
    }
}

#[test]
fn outer_do_owner_survives_physical_else_after_inner_trailer_bd_l9mgs() {
    let source = "do if (q) do x()\nwhile (a)\nelse y()\nwhile (b); z();";
    assert_eq!(
        merge_logical_lines(source).len(),
        1,
        "the inner trailer must leave the enclosing if and outer do owners pending"
    );
    assert_eq!(split_statement_segments(source).len(), 2);

    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("the physical-line else must bind before the outer do trailer");
    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::DoWhile(outer)
            if matches!(&outer.condition, Expression::Identifier(name) if name == "b")
                && matches!(
                outer.body.as_ref(),
                Statement::If(inner)
                    if matches!(&inner.condition, Expression::Identifier(name) if name == "q")
                        && matches!(
                            inner.consequent.as_ref(),
                            Statement::DoWhile(inner_do)
                                if matches!(
                                    &inner_do.condition,
                                    Expression::Identifier(name) if name == "a"
                                )
                        )
                        && inner.alternate.is_some()
            )
    ));

    let split_conditions = "do if (q) do x()\nwhile\n(a)\nelse y()\nwhile\n(b);";
    assert_eq!(merge_logical_lines(split_conditions).len(), 1);
    assert_eq!(split_statement_segments(split_conditions).len(), 1);
    assert_eq!(
        CanonicalEs2020Parser
            .parse(split_conditions, ParseGoal::Script)
            .expect("split inner and outer trailers must retain their ordered owners")
            .body
            .len(),
        1
    );

    let trivia_gap = "do if (q) do x()\nwhile (a) /* inner */\n// owner gap\n\u{feff}else /* alternate */ y()\nwhile (b);";
    assert_eq!(merge_logical_lines(trivia_gap).len(), 1);
    assert_eq!(split_statement_segments(trivia_gap).len(), 1);
    CanonicalEs2020Parser
        .parse(trivia_gap, ParseGoal::Script)
        .expect("comments and BOM trivia must not retire pending statement owners");

    let nested_alternate =
        "do if (q) do x()\nwhile (a)\nelse if (r) do y()\nwhile (c)\nelse z()\nwhile (b);";
    assert_eq!(merge_logical_lines(nested_alternate).len(), 1);
    assert_eq!(split_statement_segments(nested_alternate).len(), 1);
    let nested_tree = CanonicalEs2020Parser
        .parse(nested_alternate, ParseGoal::Script)
        .expect("a nested alternate must expose owners in grammar order");
    assert!(matches!(
        &nested_tree.body[..],
        [Statement::DoWhile(outer)]
            if matches!(
                outer.body.as_ref(),
                Statement::If(first)
                    if matches!(
                        first.alternate.as_deref(),
                        Some(Statement::If(second))
                            if matches!(second.consequent.as_ref(), Statement::DoWhile(_))
                                && second.alternate.is_some()
                    )
            )
    ));

    let stacked_if_owners = "do if (q) do x()\nwhile (a)\nelse if (r) if (s) do y()\nwhile (c)\nelse z()\nelse w()\nwhile (b);";
    assert_eq!(merge_logical_lines(stacked_if_owners).len(), 1);
    assert_eq!(split_statement_segments(stacked_if_owners).len(), 1);
    CanonicalEs2020Parser
        .parse(stacked_if_owners, ParseGoal::Script)
        .expect("each directly nested if owner must survive its inner alternate");

    let independent_while = "do if (q) do x()\nwhile (a)\nelse y()\nwhile (b)\nwhile (c) z();";
    assert_eq!(merge_logical_lines(independent_while).len(), 2);
    assert_eq!(split_statement_segments(independent_while).len(), 2);
    assert!(matches!(
        &CanonicalEs2020Parser
            .parse(independent_while, ParseGoal::Script)
            .expect("the while after the completed outer trailer is independent")
            .body[..],
        [Statement::DoWhile(_), Statement::While(_)]
    ));

    for invalid in [
        "do do x()\nwhile (a)\nelse y()\nwhile (b);",
        "do if (q) do x()\nwhile (a)\nelse y()\nwhile (b)\nelse z();",
    ] {
        assert!(
            merge_logical_lines(invalid).len() > 1,
            "a mandatory do owner must block an unrelated else: {invalid:?}"
        );
    }
    assert!(
        CanonicalEs2020Parser
            .parse(
                "do do x()\nwhile (a)\nelse y()\nwhile (b);",
                ParseGoal::Script,
            )
            .is_err(),
        "an else cannot cross a mandatory outer do trailer"
    );
}

#[test]
fn wrapped_try_handlers_remain_owned_during_segmentation_bd_j7c6t() {
    let parser = CanonicalEs2020Parser;
    for (source, logical_line_count) in [
        ("while (a) try {}\ncatch (error) {}\nnext();", 2),
        (
            "for (; a;) try {} /* handler gap */\ncatch (error) {} // finalizer gap\nfinally {}\nnext();",
            2,
        ),
        (
            "while (a) try {}\n/* gap */\u{feff}catch\n(error)\n{}\nfinally\n{}\nnext();",
            2,
        ),
        ("if (a) try {} catch (error) {} else fallback(); next();", 1),
        (
            "if (a) while (b) try {} finally {} else fallback(); next();",
            1,
        ),
        ("while (a) try {} catch (error) {} finally {} next();", 1),
        (
            "while (a) try { try {} finally {} } catch (error) {} next();",
            1,
        ),
    ] {
        assert_eq!(
            merge_logical_lines(source).len(),
            logical_line_count,
            "physical-line merging must preserve the handler chain: {source:?}"
        );
        assert_eq!(
            split_statement_segments(source).len(),
            2,
            "a wrapped handler chain must remain one statement: {source:?}"
        );
        assert_eq!(
            parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!("wrapped try statement must parse in {source:?}: {error:?}")
                })
                .body
                .len(),
            2,
            "the adjacent statement must remain independent: {source:?}"
        );
    }

    let while_tree = parser
        .parse(
            "while (a) try {}\ncatch (error) {}\nnext();",
            ParseGoal::Script,
        )
        .expect("a wrapped multiline catch must parse");
    assert!(matches!(
        &while_tree.body[..],
        [Statement::While(statement), Statement::Expression(_)]
            if matches!(statement.body.as_ref(), Statement::TryCatch(_))
    ));

    let if_tree = parser
        .parse(
            "if (a) try {} catch (error) {} else fallback(); next();",
            ParseGoal::Script,
        )
        .expect("a try consequent must retain the enclosing else");
    assert!(matches!(
        &if_tree.body[..],
        [Statement::If(statement), Statement::Expression(_)]
            if matches!(statement.consequent.as_ref(), Statement::TryCatch(_))
                && statement.alternate.is_some()
    ));

    let do_source = "do try {} catch (error) {}\nwhile (a); next();";
    assert_eq!(merge_logical_lines(do_source).len(), 1);
    assert_eq!(split_statement_segments(do_source).len(), 2);
    let do_tree = parser
        .parse(do_source, ParseGoal::Script)
        .expect("a try body must remain attached to its outer do trailer");
    assert!(matches!(
        &do_tree.body[..],
        [Statement::DoWhile(statement), Statement::Expression(_)]
            if matches!(statement.body.as_ref(), Statement::TryCatch(_))
    ));

    let stacked_do_source = "do if (a) try {} catch (error) {} else fallback(); while (b); next();";
    assert_eq!(split_statement_segments(stacked_do_source).len(), 2);
    let stacked_do_tree = parser
        .parse(stacked_do_source, ParseGoal::Script)
        .expect("ordered do/if/try owners must retain every trailing clause");
    assert!(matches!(
        &stacked_do_tree.body[..],
        [Statement::DoWhile(statement), Statement::Expression(_)]
            if matches!(statement.body.as_ref(), Statement::If(if_statement)
                if matches!(if_statement.consequent.as_ref(), Statement::TryCatch(_))
                    && if_statement.alternate.is_some())
    ));

    for source in [
        "with (scope) try {}\ncatch (error) {}\nnext();",
        "if (a) try {}\ncatch (error) {}\nelse fallback(); next();",
        "if (a) while (b) try {}\nfinally {}\nelse fallback(); next();",
    ] {
        let segments = split_statement_segments(source);
        assert_eq!(
            segments.len(),
            2,
            "statement segmentation must retain wrapped try ownership: {source:?}"
        );
        assert!(
            segments[0].2.contains("catch") || segments[0].2.contains("finally"),
            "the handler must remain in the wrapped statement: {source:?}"
        );
        assert_eq!(segments[1].2.trim(), "next()");
    }

    for invalid in [
        "while (q) try {}\nnext();\ncatch (error) {}",
        "while (q) try {} catch {} catch {}",
        "if (q) try {} finally {} catch {}",
        "try {} finally {} finally {}",
    ] {
        assert!(
            split_statement_segments(invalid).len() > 1,
            "an exhausted handler phase must not claim another clause: {invalid:?}"
        );
        assert!(
            parser.parse(invalid, ParseGoal::Script).is_err(),
            "invalid handler ordering must fail closed: {invalid:?}"
        );
    }
}

#[test]
fn outer_do_owner_survives_multiline_try_body_bd_h19yb() {
    let parser = CanonicalEs2020Parser;
    for (source, has_handler, has_finalizer) in [
        (
            "do try {\n  body();\n}\ncatch (error) {\n  recover();\n}\nwhile (again);\nnext();",
            true,
            false,
        ),
        (
            "do try {\n  body();\n}\nfinally {\n  cleanup();\n}\nwhile (again);\nnext();",
            false,
            true,
        ),
        (
            "do try {\n  body();\n}\n/* handler gap */\u{feff}catch\n(error)\n{\n  recover();\n}\n// finalizer gap\n\u{feff}finally\n{\n  cleanup();\n}\n/* trailer gap */\u{feff}while\n(again);\nnext();",
            true,
            true,
        ),
        (
            "do try {\n  try { body(); } finally { innerCleanup(); }\n}\ncatch (error) { recover(); }\nfinally { cleanup(); }\nwhile (again);\nnext();",
            true,
            true,
        ),
        (
            "do try { body(); }\ncatch (error) { recover(); } finally { cleanup(); }\nwhile (again);\nnext();",
            true,
            true,
        ),
        (
            "do try { body(); } catch (error) { recover(); }\nfinally { cleanup(); }\nwhile (again);\nnext();",
            true,
            true,
        ),
        (
            "do try { body(); } catch\n(error) { recover(); }\nwhile (again);\nnext();",
            true,
            false,
        ),
        (
            "do try { body(); } finally\n{ cleanup(); }\nwhile (again);\nnext();",
            false,
            true,
        ),
    ] {
        let logical_lines = merge_logical_lines(source);
        assert_eq!(
            logical_lines.len(),
            2,
            "the completed handler must leave the outer do trailer pending: {:?}",
            logical_lines
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            split_statement_segments(source).len(),
            2,
            "the adjacent statement must remain independent: {source:?}"
        );
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("a multiline try body must remain owned by its outer do: {error:?}")
            });
        assert!(matches!(
            &tree.body[..],
            [Statement::DoWhile(statement), Statement::Expression(_)]
                if matches!(&statement.condition, Expression::Identifier(name) if name == "again")
                    && matches!(statement.body.as_ref(), Statement::TryCatch(try_statement)
                        if try_statement.handler.is_some() == has_handler
                            && try_statement.finalizer.is_some() == has_finalizer)
        ));
    }

    let same_line_adjacency = "do try { body(); } finally { cleanup(); } while (false) next();";
    assert_eq!(merge_logical_lines(same_line_adjacency).len(), 1);
    assert_eq!(split_statement_segments(same_line_adjacency).len(), 2);
    assert!(matches!(
        &parser
            .parse(same_line_adjacency, ParseGoal::Script)
            .expect("do-while ASI may separate a same-line adjacent statement")
            .body[..],
        [Statement::DoWhile(_), Statement::Expression(_)]
    ));

    let no_else =
        "do if (q) try { body(); }\ncatch (error) { recover(); }\nwhile (outer);\nnext();";
    assert_eq!(merge_logical_lines(no_else).len(), 2);
    assert_eq!(split_statement_segments(no_else).len(), 2);
    assert!(matches!(
        &parser
            .parse(no_else, ParseGoal::Script)
            .expect("a skipped dangling-else owner must expose the outer do trailer")
            .body[..],
        [Statement::DoWhile(outer), Statement::Expression(_)]
            if matches!(&outer.condition, Expression::Identifier(name) if name == "outer")
                && matches!(outer.body.as_ref(), Statement::If(inner)
                    if inner.alternate.is_none()
                        && matches!(inner.consequent.as_ref(), Statement::TryCatch(_)))
    ));

    let try_alternate = "do if (false) prior();\nelse try { body(); }\ncatch (error) { recover(); }\nwhile (false);\nnext();";
    let try_alternate_lines = merge_logical_lines(try_alternate);
    assert_eq!(
        try_alternate_lines.len(),
        2,
        "logical lines: {:?}",
        try_alternate_lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(split_statement_segments(try_alternate).len(), 2);
    assert!(matches!(
        &parser
            .parse(try_alternate, ParseGoal::Script)
            .expect("a try alternate must retain the outer do owner")
            .body[..],
        [Statement::DoWhile(outer), Statement::Expression(_)]
            if matches!(outer.body.as_ref(), Statement::If(if_statement)
                if matches!(if_statement.alternate.as_deref(), Some(Statement::TryCatch(_))))
    ));

    let ordered_owners = "do if (q) do try { body(); }\ncatch (error) { recover(); }\nfinally { cleanup(); }\nwhile (inner)\nelse alternate()\nwhile (outer);\nnext();";
    assert_eq!(merge_logical_lines(ordered_owners).len(), 2);
    assert_eq!(split_statement_segments(ordered_owners).len(), 2);
    assert!(matches!(
        &parser
            .parse(ordered_owners, ParseGoal::Script)
            .expect("try phases must preserve every ordered do/if owner")
            .body[..],
        [Statement::DoWhile(outer), Statement::Expression(_)]
            if matches!(&outer.condition, Expression::Identifier(name) if name == "outer")
                && matches!(outer.body.as_ref(), Statement::If(if_statement)
                    if if_statement.alternate.is_some()
                        && matches!(if_statement.consequent.as_ref(), Statement::DoWhile(inner)
                            if matches!(&inner.condition, Expression::Identifier(name) if name == "inner")
                                && matches!(inner.body.as_ref(), Statement::TryCatch(try_statement)
                                    if try_statement.handler.is_some()
                                        && try_statement.finalizer.is_some())))
    ));

    let nested_do = "do do try { body(); }\ncatch (error) { recover(); }\nwhile (inner)\nwhile (outer);\nnext();";
    assert_eq!(merge_logical_lines(nested_do).len(), 2);
    assert_eq!(split_statement_segments(nested_do).len(), 2);
    assert!(matches!(
        &parser
            .parse(nested_do, ParseGoal::Script)
            .expect("each nested do owner must claim exactly one trailer")
            .body[..],
        [Statement::DoWhile(outer), Statement::Expression(_)]
            if matches!(outer.body.as_ref(), Statement::DoWhile(inner)
                if matches!(inner.body.as_ref(), Statement::TryCatch(_)))
    ));

    let independent_while =
        "do try { body(); }\nfinally { cleanup(); }\nwhile (outer);\nwhile (other) next();";
    assert_eq!(merge_logical_lines(independent_while).len(), 2);
    assert_eq!(split_statement_segments(independent_while).len(), 2);
    assert!(matches!(
        &parser
            .parse(independent_while, ParseGoal::Script)
            .expect("a second while must remain independent")
            .body[..],
        [Statement::DoWhile(_), Statement::While(_)]
    ));

    for invalid in [
        "do try {}\nnext();\ncatch (error) {}\nwhile (outer);",
        "do try {}\ncatch (error) {}\nnext();\nwhile (outer);",
        "do try {}\ncatch (error) {};\nwhile (outer);",
        "do try {}\ncatch (error) {}\ncatch (other) {}\nwhile (outer);",
        "do try {}\nfinally {}\ncatch (error) {}\nwhile (outer);",
        "do try {}\nfinally {}\nwhile (outer);\nfinally {}",
        "try {};\ncatch (error) {}",
        "try {} catch (error) {};\nfinally {}",
    ] {
        assert!(
            merge_logical_lines(invalid).len() > 1,
            "an adjacent statement or exhausted phase must retire the outer owner: {invalid:?}"
        );
        assert!(
            split_statement_segments(invalid).len() > 1,
            "invalid clause ordering must not become one segment: {invalid:?}"
        );
        assert!(
            parser.parse(invalid, ParseGoal::Script).is_err(),
            "invalid outer-do handler ownership must fail closed: {invalid:?}"
        );
    }
}

#[test]
fn unmatched_second_else_fails_closed_bd_9fakj() {
    let parser = CanonicalEs2020Parser;
    let second_else = "do if (q) do x()\nwhile (a)\nelse y()\nwhile (b)\nelse z();";
    let logical_lines = merge_logical_lines(second_else);
    assert_eq!(
        logical_lines.len(),
        2,
        "the completed outer do must retire every dangling-if owner"
    );
    assert_eq!(split_statement_segments(second_else).len(), 2);
    let error = parser
        .parse(second_else, ParseGoal::Script)
        .expect_err("a second else has no matching if statement");
    assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    assert!(error.message.contains("matching if statement"));

    for invalid in [
        "else fallback();",
        "else;",
        "else();",
        "else.foo;",
        "else if (q) x();",
        "if (q) x(); else y(); else z();",
        "if (q) x(); next(); else z();",
        "do if (q) x(); else y(); while (false); else z();",
        "/* gap */\u{feff}else fallback();",
    ] {
        assert!(
            parser.parse(invalid, ParseGoal::Script).is_err(),
            "an unmatched else must fail closed: {invalid:?}"
        );
    }

    for valid in [
        "if (q) x(); else y();",
        "if (q) if (r) x(); else y();",
        "if (q) x(); else if (r) y(); else z();",
        "do if (q) do x()\nwhile (a)\nelse y()\nwhile (b);",
    ] {
        parser
            .parse(valid, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("valid dangling-else binding failed: {error:?}"));
    }

    let keyword_boundaries = parser
        .parse(
            r#"elsewhere(); else$foo(); elseπ(); else\u0066oo(); object.else(); object["else"];"#,
            ParseGoal::Script,
        )
        .expect("identifiers and member names containing else remain ordinary expressions");
    assert_eq!(keyword_boundaries.body.len(), 6);
}

#[test]
fn deep_do_while_asi_merging_is_incremental_bd_rcnxf() {
    let depth = 128usize;
    let source = format!(
        "{}x()\n{}while (true) y();",
        "do ".repeat(depth),
        "while (false)\n".repeat(depth)
    );
    assert_eq!(
        merge_logical_lines(&source).len(),
        2,
        "logical-line completion must retire direct ASI trailers incrementally"
    );
}

#[test]
fn deep_wrapped_do_while_asi_is_incremental_bd_rcnxf() {
    let depth = 128usize;
    let source = format!(
        "{}do x()\n{}while (true) y();",
        "do if (true) ".repeat(depth.saturating_sub(1)),
        "while (false)\n".repeat(depth)
    );
    assert_eq!(
        split_statement_segments(&source).len(),
        2,
        "wrapped ASI trailers must retire one parent statement at a time"
    );
    assert_eq!(
        merge_logical_lines(&source).len(),
        2,
        "logical-line completion must retain the wrapped-chain fast path"
    );

    let parse_depth = 64usize;
    let parse_source = format!(
        "{}do x()\n{}while (true) y();",
        "do if (true) ".repeat(parse_depth.saturating_sub(1)),
        "while (false)\n".repeat(parse_depth)
    );
    assert_eq!(
        CanonicalEs2020Parser
            .parse(parse_source.as_str(), ParseGoal::Script)
            .expect("a wrapped ASI trailer chain within budget must parse")
            .body
            .len(),
        2
    );
}

/// bd-47ae4: the recursion budget must be backed by provisioned stack —
/// a within-budget chain must parse even when the CALLER runs on a tiny
/// thread stack (the class that SIGABRTed 1–2 MiB harness threads).
#[test]
fn wrapped_do_while_parses_from_a_tiny_caller_stack_bd_47ae4() {
    let depth = 64usize;
    let source = format!(
        "{}do x()\n{}while (true) y();",
        "do if (true) ".repeat(depth.saturating_sub(1)),
        "while (false)\n".repeat(depth)
    );
    let handle = std::thread::Builder::new()
        .name("bd-47ae4-tiny-caller".to_string())
        .stack_size(256 * 1024)
        .spawn(move || {
            CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Script)
                .expect("a within-budget chain must parse regardless of caller stack")
                .body
                .len()
        })
        .expect("tiny caller thread should spawn");
    assert_eq!(handle.join().expect("caller thread must not abort"), 2);
}

/// bd-47ae4: a chain beyond a tight recursion budget must fail closed
/// with the recoverable budget error, never a native stack abort.
/// (Depth 16 keeps the budget-limited segment rescans cheap while still
/// exceeding the depth-8 budget.)
#[test]
fn tight_recursion_budget_fails_closed_not_abort_bd_47ae4() {
    let depth = 16usize;
    let source = format!(
        "{}do x()\n{}while (true) y();",
        "do if (true) ".repeat(depth.saturating_sub(1)),
        "while (false)\n".repeat(depth)
    );
    let options = ParserOptions {
        budget: ParserBudget {
            max_recursion_depth: 8,
            ..ParserBudget::default()
        },
        ..ParserOptions::default()
    };
    let error = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "bd-47ae4-tight.js".to_string(),
                text: source,
            },
            ParseGoal::Script,
            &options,
        )
        .expect_err("a chain beyond the tight budget must be rejected");
    assert_eq!(error.code, ParseErrorCode::BudgetExceeded);
    assert!(
        error.message.contains("statement nesting budget exceeded"),
        "unexpected rejection: {}",
        error.message
    );
}

#[test]
fn postfix_updates_remain_binary_operands_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for (source, binary_operator, update_operator) in [
        ("x++ + y;", BinaryOperator::Add, UpdateOperator::Increment),
        (
            "x++/* comment */+y;",
            BinaryOperator::Add,
            UpdateOperator::Increment,
        ),
        (
            "x-- - y;",
            BinaryOperator::Subtract,
            UpdateOperator::Decrement,
        ),
        ("x+++y;", BinaryOperator::Add, UpdateOperator::Increment),
        ("x++==y;", BinaryOperator::Equal, UpdateOperator::Increment),
        (
            "x++===y;",
            BinaryOperator::StrictEqual,
            UpdateOperator::Increment,
        ),
        (
            "x++!=y;",
            BinaryOperator::NotEqual,
            UpdateOperator::Increment,
        ),
        (
            "x++!==y;",
            BinaryOperator::StrictNotEqual,
            UpdateOperator::Increment,
        ),
        (
            "x++<y;",
            BinaryOperator::LessThan,
            UpdateOperator::Increment,
        ),
        (
            "x++<=y;",
            BinaryOperator::LessThanOrEqual,
            UpdateOperator::Increment,
        ),
        (
            "x++>y;",
            BinaryOperator::GreaterThan,
            UpdateOperator::Increment,
        ),
        (
            "x++>=y;",
            BinaryOperator::GreaterThanOrEqual,
            UpdateOperator::Increment,
        ),
        ("x--==y;", BinaryOperator::Equal, UpdateOperator::Decrement),
        (
            "x--===y;",
            BinaryOperator::StrictEqual,
            UpdateOperator::Decrement,
        ),
        (
            "x--!=y;",
            BinaryOperator::NotEqual,
            UpdateOperator::Decrement,
        ),
        (
            "x--!==y;",
            BinaryOperator::StrictNotEqual,
            UpdateOperator::Decrement,
        ),
        (
            "x--<y;",
            BinaryOperator::LessThan,
            UpdateOperator::Decrement,
        ),
        (
            "x--<=y;",
            BinaryOperator::LessThanOrEqual,
            UpdateOperator::Decrement,
        ),
        (
            "x-->y;",
            BinaryOperator::GreaterThan,
            UpdateOperator::Decrement,
        ),
        (
            "x-->=y;",
            BinaryOperator::GreaterThanOrEqual,
            UpdateOperator::Decrement,
        ),
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("a postfix update is a complete binary operand");
        let Statement::Expression(ExpressionStatement {
            expression:
                Expression::Binary {
                    operator,
                    left,
                    right,
                },
            ..
        }) = &tree.body[0]
        else {
            panic!(
                "expected a binary expression for {source:?}: {:?}",
                tree.body
            );
        };
        assert_eq!(*operator, binary_operator, "source: {source:?}");
        assert!(matches!(
            left.as_ref(),
            Expression::Update {
                operator,
                argument,
                prefix: false,
            } if *operator == update_operator
                && matches!(argument.as_ref(), Expression::Identifier(name) if name == "x")
        ));
        assert!(matches!(
            right.as_ref(),
            Expression::Identifier(name) if name == "y"
        ));
    }
}

#[test]
fn outer_expressions_dispatch_nested_arrows_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "async => async;",
        "asyncName => asyncName;",
        "async/**/=> 1;",
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("an async-prefixed binding identifier remains an ordinary arrow head");
        assert!(matches!(
            &tree.body[0],
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrowFunction {
                    is_async: false,
                    ..
                },
                ..
            })
        ));
    }

    for (source, expected_operator) in [
        ("this.self = () => 1;", AssignmentOperator::Assign),
        ("target += () => 1;", AssignmentOperator::AddAssign),
    ] {
        let assignment = parser
            .parse(source, ParseGoal::Script)
            .expect("an assignment parser recursively owns its arrow RHS");
        assert!(matches!(
            &assignment.body[0],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment { operator, right, .. },
                ..
            }) if *operator == expected_operator
                && matches!(right.as_ref(), Expression::ArrowFunction { .. })
        ));
    }

    for (source, arrow_in_consequent) in [
        ("true ? () => 1 : 0;", true),
        ("true ? 0 : () => 1;", false),
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("a conditional parser recursively owns arrows in either branch");
        let Statement::Expression(ExpressionStatement {
            expression:
                Expression::Conditional {
                    consequent,
                    alternate,
                    ..
                },
            ..
        }) = &tree.body[0]
        else {
            panic!("expected a conditional expression for {source:?}");
        };
        let branch = if arrow_in_consequent {
            consequent
        } else {
            alternate
        };
        assert!(
            matches!(branch.as_ref(), Expression::ArrowFunction { .. }),
            "expected an arrow branch for {source:?}"
        );
    }

    let nested = parser
        .parse("x => y => x + y;", ParseGoal::Script)
        .expect("a direct arrow body may itself be another arrow");
    assert!(matches!(
        &nested.body[0],
        Statement::Expression(ExpressionStatement {
            expression:
                Expression::ArrowFunction {
                    body: ArrowBody::Expression(body),
                    ..
                },
            ..
        }) if matches!(body.as_ref(), Expression::ArrowFunction { .. })
    ));

    let yielded = parser
        .parse(
            "function* direct() { return yield x => x; } \
             function* delegated() { return yield* async => async; } \
             function* contextual() { return yield async => async; }",
            ParseGoal::Script,
        )
        .expect("yield recursively owns an arrow argument in a generator body");
    for (statement, expected_delegate) in yielded.body.iter().zip([false, true, false]) {
        let Statement::FunctionDeclaration(function) = statement else {
            panic!("expected a generator function declaration");
        };
        let Statement::Return(return_statement) = &function.body.body[0] else {
            panic!("expected a generator return statement");
        };
        assert!(matches!(
            return_statement.argument.as_ref(),
            Some(Expression::Yield {
                argument: Some(argument),
                delegate,
            }) if *delegate == expected_delegate
                && matches!(argument.as_ref(), Expression::ArrowFunction { .. })
        ));
    }

    for malformed_head in [
        "a + b => c",
        "a || b => c",
        "a.b => c",
        "a() => c",
        "1 => c",
        "{a} => c",
        "a ?? b => c",
        "a ? b => c",
        "a = 1 => c",
        "async x = y => y",
        "async x ? y => y : z",
        "async/* line\nterminator */x => x",
    ] {
        let source = format!("let bad = {malformed_head};");
        parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect_err("a malformed direct arrow head must remain a parse error");
    }
}

#[test]
fn sloppy_let_trivia_selects_expression_or_declaration_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for expression in [
        "let",
        "let/**/(4)",
        "let\u{FEFF}(4)",
        "let/**/.x",
        "let/**/+2",
        "let\n=1",
        "let\nin object",
        "let\n, 2",
    ] {
        assert_eq!(
            parse_variable_declaration_kind(expression),
            None,
            "sloppy IdentifierReference expression was misclassified: {expression:?}"
        );
    }
    assert_eq!(
        parse_variable_declaration_kind("let/**/x = 9"),
        Some(VariableDeclarationKind::Let)
    );

    let trivia_tree = parser
        .parse(
            "var let = value => value + 1; \
             let/**/(4); let\u{FEFF}(4); let/**/.x; let/**/+2; let/**/x = 9;",
            ParseGoal::Script,
        )
        .expect("comment and BOM trivia must not force sloppy let expressions into declarations");
    assert_eq!(trivia_tree.body.len(), 6);
    assert!(matches!(
        &trivia_tree.body[5],
        Statement::VariableDeclaration(declaration)
            if declaration.kind == VariableDeclarationKind::Let
    ));

    let continuation_tree = parser
        .parse(
            "var let = 0; let\n= 1; \
             var object = {x: 1}; let\nin object; let\n, 2;",
            ParseGoal::Script,
        )
        .expect("sloppy let assignment, in, and comma expressions continue across a line ending");
    assert_eq!(continuation_tree.body.len(), 5);
    assert!(matches!(
        &continuation_tree.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Assignment { .. },
            ..
        })
    ));
    assert!(matches!(
        &continuation_tree.body[3],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Binary {
                operator: BinaryOperator::In,
                ..
            },
            ..
        })
    ));

    let call_tree = parser
        .parse("var let = value => value + 1; let\n(4);", ParseGoal::Script)
        .expect("a line ending before call arguments does not trigger ASI");
    assert_eq!(call_tree.body.len(), 2);
    assert!(matches!(
        &call_tree.body[1],
        Statement::Expression(ExpressionStatement {
            expression: Expression::Call { .. },
            ..
        })
    ));

    let reserved_word_tree = parser
        .parse("var let = 1; let\ntrue; let\nnull; let;", ParseGoal::Script)
        .expect("reserved-word statements after bare sloppy let remain ASI-separated");
    assert_eq!(reserved_word_tree.body.len(), 6);

    let trailing_declaration_tree = parser
        .parse(
            "let a = 1; const // before binding\n b = 2; \
             let d = 1; const e // before equals\n = 2; \
             let f = 1; let g // before comma\n , h = 2; \
             a + b + d + e + f + h;",
            ParseGoal::Script,
        )
        .expect("continuation analysis must inspect the final top-level statement segment");
    assert_eq!(trailing_declaration_tree.body.len(), 7);
    assert!(matches!(
        &trailing_declaration_tree.body[5],
        Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
    ));
}

#[test]
fn comment_only_statement_segments_are_lexical_trivia_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    let trailing = parser
        .parse("let x = 1; /* trailing */", ParseGoal::Script)
        .expect("a trailing block comment is not an expression statement");
    assert_eq!(trailing.body.len(), 1);

    let between = parser
        .parse(
            "let x = 1; /* block only */ ; // line only\n x;",
            ParseGoal::Script,
        )
        .expect("comment-only segments between statements are lexical trivia");
    assert_eq!(between.body.len(), 2);

    let comment_only = parser
        .parse("/* block only */\n// line only", ParseGoal::Script)
        .expect("a comment-only Script has an empty statement list");
    assert!(comment_only.body.is_empty());

    for (source, expected_start, expected_end) in [("/*\n*/x;", 5, 6), ("/*\r\n*/x;", 6, 7)] {
        let span_tree = parser
            .parse(source, ParseGoal::Script)
            .expect("leading multiline comment trivia preserves physical coordinates");
        let Statement::Expression(expression) = &span_tree.body[0] else {
            panic!("expected expression after leading comment trivia");
        };
        assert_eq!(expression.span.start_offset, expected_start);
        assert_eq!(expression.span.end_offset, expected_end);
        assert_eq!(expression.span.start_line, 2);
        assert_eq!(expression.span.start_column, 3);
        assert_eq!(expression.span.end_line, 2);
        assert_eq!(expression.span.end_column, 4);
    }

    let leading = parser
        .parse("/* leading */ let x = 1; x;", ParseGoal::Script)
        .expect("leading comment trivia must not hide declaration dispatch");
    assert!(matches!(
        &leading.body[0],
        Statement::VariableDeclaration(declaration)
            if declaration.kind == VariableDeclarationKind::Let
    ));

    let between_declarations = parser
        .parse(
            "let a = 1; /* before declaration */ const b = 2; a + b;",
            ParseGoal::Script,
        )
        .expect("comment trivia after a semicolon must not hide declaration dispatch");
    assert!(matches!(
        &between_declarations.body[1],
        Statement::VariableDeclaration(declaration)
            if declaration.kind == VariableDeclarationKind::Const
    ));

    let leading_function = parser
        .parse(
            "/* leading */ function f() {} let x = 1; x;",
            ParseGoal::Script,
        )
        .expect("leading trivia must not hide a block statement split boundary");
    assert_eq!(leading_function.body.len(), 3);
    assert!(matches!(
        &leading_function.body[0],
        Statement::FunctionDeclaration(_)
    ));

    let clause_tree = parser
        .parse(
            "let x = 0; if (false) { x = 1; }/* clause */else { x = 2; } x;",
            ParseGoal::Script,
        )
        .expect("comment trivia between if and else preserves the clause boundary");
    assert_eq!(clause_tree.body.len(), 3);
    assert!(matches!(
        &clause_tree.body[1],
        Statement::If(statement) if statement.alternate.is_some()
    ));

    let clause_prefix_tree = parser
        .parse(
            "var else$foo = 7; var x = 0; \
             if (false) { x = 1; } else$foo; x + else$foo;",
            ParseGoal::Script,
        )
        .expect("an identifier beginning with else is not an else clause");
    assert_eq!(clause_prefix_tree.body.len(), 5);
    assert!(matches!(
        &clause_prefix_tree.body[2],
        Statement::If(statement) if statement.alternate.is_none()
    ));
    for identifier in ["else$foo", "elseπ", r"else\u0066oo"] {
        assert!(
            !starts_with_keyword(identifier, "else"),
            "IdentifierName continuation was mistaken for a clause keyword: {identifier}"
        );
    }

    parser
        .parse(
            "try {}/* clause */catch (error) {} \
             try {}// clause\nfinally {} \
             do {}/* clause */while (false);",
            ParseGoal::Script,
        )
        .expect("comment trivia preserves catch, finally, and do-while clauses");
}

#[test]
fn binding_pattern_trivia_does_not_join_tokens_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    assert!(!is_binding_pattern_whitespace('\u{0085}'));
    assert_eq!(
        parse_variable_declaration_kind("let\u{0085}value = 1"),
        None
    );
    assert_eq!(
        trim_binding_pattern_trivia("\u{0085}value\u{0085}"),
        Some("\u{0085}value\u{0085}")
    );
    assert_eq!(
        trim_binding_pattern_trivia("\u{FEFF}/* lead */ value /* tail */"),
        Some("value")
    );
    assert_eq!(
        trim_binding_pattern_trivia("va/* internal */lue"),
        Some("va/* internal */lue")
    );
    assert_eq!(trim_binding_pattern_trivia("value /* unterminated"), None);
    parser
        .parse(
            "let string = '\u{0085}'; let regexp = /\u{0085}/; \
             let commented = /* \u{0085} */ 1;",
            ParseGoal::Script,
        )
        .expect("non-ES whitespace remains valid inside lexical literals and comments");
    for source in [
        "var {va/* c */lue: picked} = source",
        "var {'value' /* c */ junk: picked} = source",
        "var {1 /* c */ 2: picked} = source",
        "let {\u{0085}value: picked} = source",
        "let {value\u{0085}: picked} = source",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("comments cannot splice separate tokens into one property name");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(error.message.contains("object-binding property key"));
    }
    for source in [
        "var \u{0085}value = 1",
        "const \u{0085}value = 1",
        "let value = \u{0085}1",
        "let value = 1\u{0085} + 2",
        "let value = first\u{0085}second",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("non-ECMAScript whitespace cannot act as declaration trivia");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
    for source in [
        "let {[key] /* c */ junk: value} = source",
        "let {...re/* c */st} = source",
        "let {[key]/* c */: va/* c */lue} = source",
    ] {
        assert!(
            parser.parse(source, ParseGoal::Script).is_err(),
            "binding trivia cannot hide residual or token-spliced syntax: {source}"
        );
    }
    for source in [
        "let invalid = (/* c */, ) => 1",
        "let invalid = (/* c */, value) => value",
        "let invalid = (value, /* c */, ) => value",
        "let invalid = value/*\n*/=> value",
        "let invalid = async value/*\n*/=> value",
        "let invalid = (value)\n=> value",
        "let invalid = (value)/*\n*/=> value",
        "for (let value = 1 of [2]) {}",
        "for (const value = 1 in {x: 1}) {}",
        "for (var value = 1 of [2]) {}",
        "for (let [value] = [1] of [[2]]) {}",
        "for (var [value] = [1] in {x: 1}) {}",
        "'use strict'; for (var value = 1 in {x: 1}) {}",
        "for (let of values) {}",
        "'use strict'; for (let in {x: 1}) {}",
        "for (async of []) {}",
        "for (async/* comment */of []) {}",
        "for (let ...rest of []) {}",
        "for (const ...rest in {}) {}",
        "for (var ...rest of []) {}",
        "for (...rest of []) {}",
        "function invalid(/* c */, ) {}",
        "let {/* c */, value} = source",
        "let {value, /* c */, other} = source",
        "let [...rest, /* c */] = source",
        "let {...rest, /* c */} = source",
        "function invalid(...rest, /* c */) {}",
    ] {
        assert!(
            parser.parse(source, ParseGoal::Script).is_err(),
            "comment-only leading or interior slots stay syntax errors: {source}"
        );
    }
}

#[test]
fn object_binding_numeric_keys_use_ecmascript_number_spelling_bd_h4esx() {
    for (value, expected) in [
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (f64::from_bits(1), "5e-324"),
        (667_082_108_456_853.2, "667082108456853.2"),
    ] {
        assert_eq!(js_number_property_key(value), expected);
    }
    assert_eq!(
        js_number_property_key(
            "9007199254740993"
                .parse::<f64>()
                .expect("numeric boundary should parse")
        ),
        "9007199254740992"
    );
    assert_eq!(
        js_number_property_key(
            "18446744073709551615"
                .parse::<f64>()
                .expect("wide numeric boundary should parse")
        ),
        "18446744073709552000"
    );
}

#[test]
fn object_binding_identifier_names_use_unicode_identifier_classes_bd_h4esx() {
    let parser = CanonicalEs2020Parser;
    parser
        .parse(r"var {a\u203F: connector} = source", ParseGoal::Script)
        .expect("connector punctuation is valid after an identifier start");
    parser
        .parse(
            r"var {\u037A: id_start, a\u037A: id_continue} = source",
            ParseGoal::Script,
        )
        .expect("ECMAScript uses Unicode ID classes rather than XID classes");

    for source in [
        "var {a½: value} = source",
        "var {\u{0345}bad: value} = source",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("invalid Unicode identifier class must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(error.message.contains("object-binding property key"));
    }
}

#[test]
fn unicode_and_escaped_binding_names_canonicalize_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r"var {π, \u0076alue, a\u037A} = source; var [\u03C0] = values; var \u0064irect = 1",
            ParseGoal::Script,
        )
        .expect("literal and escaped binding names should parse");

    let Statement::VariableDeclaration(object_declaration) = &tree.body[0] else {
        panic!("expected object-binding declaration");
    };
    let BindingPattern::ObjectPattern(properties) = &object_declaration.declarations[0].pattern
    else {
        panic!("expected object-binding pattern");
    };
    assert_eq!(properties.len(), 3);
    for (property, expected) in properties.iter().zip(["π", "value", "aͺ"]) {
        assert!(property.shorthand);
        assert!(matches!(
            &property.key,
            Expression::Identifier(name) if name == expected
        ));
        assert!(matches!(
            &property.value,
            BindingPattern::Identifier(name) if name == expected
        ));
    }

    let Statement::VariableDeclaration(array_declaration) = &tree.body[1] else {
        panic!("expected array-binding declaration");
    };
    assert!(matches!(
        &array_declaration.declarations[0].pattern,
        BindingPattern::ArrayPattern(elements)
            if matches!(
                &elements[0],
                Some(BindingPattern::Identifier(name)) if name == "π"
            )
    ));

    let Statement::VariableDeclaration(direct_declaration) = &tree.body[2] else {
        panic!("expected direct binding declaration");
    };
    assert!(matches!(
        &direct_declaration.declarations[0].pattern,
        BindingPattern::Identifier(name) if name == "direct"
    ));
}

#[test]
fn unicode_and_escaped_identifier_references_canonicalize_bd_t4947() {
    let tree = parse_script(r"π + \u0076alue");
    let Expression::Binary { left, right, .. } = first_expr(&tree) else {
        panic!("expected binary expression");
    };
    assert!(matches!(
        left.as_ref(),
        Expression::Identifier(name) if name == "π"
    ));
    assert!(matches!(
        right.as_ref(),
        Expression::Identifier(name) if name == "value"
    ));

    let tree = parse_script(r"\u0066n(π)");
    let Expression::Call { callee, arguments } = first_expr(&tree) else {
        panic!("expected call expression");
    };
    assert!(matches!(
        callee.as_ref(),
        Expression::Identifier(name) if name == "fn"
    ));
    assert!(matches!(
        &arguments[0],
        Expression::Identifier(name) if name == "π"
    ));
}

#[test]
fn unicode_and_escaped_arrow_parameters_canonicalize_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    for (source, expected, expected_async) in [
        (r"let arrow = \u03C0 => ({π})", "π", false),
        (r"let arrow = (\u0076alue) => ({value})", "value", false),
        ("let arrow = async π => ({π})", "π", true),
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("`{source}` should parse: {error:?}"));
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected arrow variable declaration");
        };
        let Some(Expression::ArrowFunction {
            params, is_async, ..
        }) = declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected arrow initializer for `{source}`");
        };
        assert_eq!(*is_async, expected_async);
        assert!(matches!(
            &params[0].pattern,
            BindingPattern::Identifier(name) if name == expected
        ));
    }
}

#[test]
fn binding_names_apply_goal_reserved_word_rules_after_decoding_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    parser
        .parse(
            "var {await, static, yield} = source; var let = 1; (let) => let",
            ParseGoal::Script,
        )
        .expect("sloppy Script bindings should allow contextual names");

    for source in [
        "var {if} = source",
        r"var {\u0069f} = source",
        "var if = 1",
        r"var \u0069f = 1",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("reserved binding name must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }

    for source in [
        "var {await} = source",
        r"var {\u0061wait} = source",
        "var {static} = source",
        "var eval = 1",
        "var arguments = 1",
        "import eval from 'pkg'",
        "import * as arguments from 'pkg'",
        "import {value as eval} from 'pkg'",
    ] {
        let error = parser
            .parse(source, ParseGoal::Module)
            .expect_err("Module bindings must apply strict identifier restrictions");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn declaration_catch_and_import_names_canonicalize_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;

    let tree = parser
        .parse(r"function v\u0061lue() {}", ParseGoal::Script)
        .expect("escaped function declaration name should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::FunctionDeclaration(function)
            if function.name.as_deref() == Some("value")
    ));

    let tree = parser
        .parse(r"let holder = function n\u0061med() {};", ParseGoal::Script)
        .expect("escaped function expression name should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Function { name: Some(name), .. }) if name == "named"
            )
    ));

    let tree = parser
        .parse(r"class V\u0061lue {}", ParseGoal::Script)
        .expect("escaped class declaration name should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::ClassDeclaration(class) if class.name.as_deref() == Some("Value")
    ));

    let tree = parser
        .parse(r"let holder = class N\u0061med {};", ParseGoal::Script)
        .expect("escaped class expression name should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::ClassExpression { name: Some(name), .. }) if name == "Named"
            )
    ));

    let tree = parser
        .parse(
            r"try { throw 1 } catch (e\u0072r) { err }",
            ParseGoal::Script,
        )
        .expect("escaped catch binding should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::TryCatch(statement)
            if statement.handler.as_ref().and_then(|handler| handler.parameter.as_deref())
                == Some("err")
    ));

    let tree = parser
        .parse(
            r"import v\u0061lue, {d\u0065fault as f\u0061llback, st\u0061tic as alias} from 'pkg';
               import * as n\u0061mes from 'other';",
            ParseGoal::Module,
        )
        .expect("escaped import IdentifierNames and bindings should parse");
    assert!(matches!(
        &tree.body[0],
        Statement::Import(import)
            if matches!(
                &import.clause,
                ImportClause::DefaultAndNamed { default, specifiers }
                    if default == "value"
                        && specifiers[0].import_name == "default"
                        && specifiers[0].local_name == "fallback"
                        && specifiers[1].import_name == "static"
                        && specifiers[1].local_name == "alias"
            )
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Import(import)
            if matches!(&import.clause, ImportClause::Namespace { local } if local == "names")
    ));
}

#[test]
fn module_declarations_respect_expression_continuation_boundaries_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "import value from 'pkg'\n[0];",
        "import 'pkg'\n[0];",
        "export {value}\n[0];",
    ] {
        let tree = parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("module declaration must permit ASI: {error:?}"));
        assert_eq!(tree.body.len(), 2, "{source:?}");
        assert!(matches!(
            &tree.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ));
    }

    let default_export = parser
        .parse("export default value\n[0];", ParseGoal::Module)
        .expect("a default export expression may continue with computed member access");
    assert!(matches!(
        &default_export.body[..],
        [Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Member { computed: true, .. }),
            ..
        })]
    ));

    for source in ["import\n('pkg');", "import /* boundary */\n('pkg');"] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("dynamic import may cross a line: {error:?}"));
        assert_eq!(tree.body.len(), 1, "{source:?}");
    }
}

#[test]
fn binding_names_allow_only_boundary_lexical_trivia_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "function value/* trailing */() {}",
        "function value\u{FEFF}() {}",
        "class Value/* trailing */ {}",
        "class Value\u{FEFF} {}",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("boundary lexical trivia should remain valid in `{source}`: {error:?}")
            });
    }

    for source in [
        "import value/* trailing */ from 'pkg';",
        "import * as names/* trailing */ from 'pkg';",
        "import {source/* trailing */ as local, other as alias/* trailing */} from 'pkg';",
        "import value/**/from 'pkg';",
        "import * as names/**/from 'pkg';",
        "import {source as local}/**/from 'pkg';",
        "import value\u{FEFF}from 'pkg';",
        "import from from 'pkg';",
        "import value, /* boundary */ {source as local} from 'pkg';",
        "import value, /* boundary */ * as names from 'pkg';",
    ] {
        parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| {
                panic!("import boundary trivia should remain valid in `{source}`: {error:?}")
            });
    }

    for source in [
        "function va/* internal */lue() {}",
        "class Va/* internal */lue {}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("internal trivia cannot splice one binding identifier");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }

    for source in [
        "import va/* internal */lue from 'pkg';",
        "import {sou/* internal */rce as local} from 'pkg';",
    ] {
        let error = parser
            .parse(source, ParseGoal::Module)
            .expect_err("internal trivia cannot splice one import identifier");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn async_function_expression_line_terminator_boundary_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;

    for (source, expected_name, expected_generator) in [
        (
            "async/**/function declared() {} let observed = declared;",
            "declared",
            false,
        ),
        (
            "async\u{FEFF}function bomDeclared() {}",
            "bomDeclared",
            false,
        ),
        ("async/**/function/**/ * generated() {}", "generated", true),
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("trivia-separated async declaration should parse: {error:?}")
            });
        assert!(matches!(
            &tree.body[0],
            Statement::FunctionDeclaration(function)
                if function.name.as_deref() == Some(expected_name)
                    && function.is_async
                    && function.is_generator == expected_generator
        ));
    }

    let tree = parser
        .parse(
            "let holder = async/**/function named() {};",
            ParseGoal::Script,
        )
        .expect("a block comment without a line terminator remains async-function trivia");
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(declaration)
            if matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Function {
                    name: Some(name),
                    is_async: true,
                    is_generator: false,
                    ..
                }) if name == "named"
            )
    ));

    for (asi_source, expected_name) in [
        ("let holder = async/*\n*/function named() {};", "named"),
        (
            "let holder = a\\u0073ync/*\n*/function escapedNamed() {};",
            "escapedNamed",
        ),
        (
            "let holder = a\\u{73}ync/*\n*/function bracedNamed() {};",
            "bracedNamed",
        ),
    ] {
        assert_eq!(split_statement_segments(asi_source).len(), 2);
        let tree = parser
            .parse(asi_source, ParseGoal::Script)
            .expect("a line terminator before a named function declaration triggers ASI");
        assert!(matches!(
            &tree.body[..],
            [
                Statement::VariableDeclaration(declaration),
                Statement::FunctionDeclaration(function)
            ] if matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::Identifier(name)) if name == "async"
            ) && function.name.as_deref() == Some(expected_name)
        ));
    }

    for source in [
        "let holder = async/*\n*/function() {};",
        "let holder = (async/*\n*/function named() {});",
        "let holder = a\\u0073ync/*\n*/function() {};",
        "let holder = a\\u0073ync/**/function named() {};",
        "let holder = (a\\u0073ync/*\n*/function named() {});",
        "let holder = a\\u{73}ync/*\n*/function() {};",
        "let holder = a\\u{73}ync/**/function named() {};",
        "let holder = (a\\u{73}ync/*\n*/function named() {});",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("a function expression cannot cross an async line terminator");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn canonical_reserved_bindings_fail_across_carriers_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;
    for source in [
        r"var r\u0065turn = 1",
        r"function invalid(r\u0065turn) {}",
        r"var {return: r\u0065turn} = source",
        r"try {} catch (r\u0065turn) {}",
        r"for (var r\u0065turn = 0; ; ) {}",
        r"for (var r\u0065turn in source) {}",
        r"for (var r\u0065turn of source) {}",
        r"function r\u0065turn() {}",
        r"let holder = function r\u0065turn() {};",
        r"class r\u0065turn {}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("canonical reserved binding must be rejected");
        assert_eq!(
            error.code,
            ParseErrorCode::UnsupportedSyntax,
            "wrong rejection for `{source}`"
        );
    }

    for source in [
        r"import r\u0065turn from 'pkg'",
        r"import {value as r\u0065turn} from 'pkg'",
        r"import {value as local, other as l\u006fcal} from 'pkg'",
        r"import {st\u0061tic} from 'pkg'",
        r"function aw\u0061it() {}",
        r"class aw\u0061it {}",
        r"try {} catch (aw\u0061it) {}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Module)
            .expect_err("invalid canonical module binding must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn binding_name_contexts_do_not_conflate_properties_bd_7vm4l() {
    let parser = CanonicalEs2020Parser;
    for source in [
        r"async function aw\u0061it() {}",
        r"function* y\u0069eld() {}",
        r"let ordinaryAwait = function aw\u0061it() {};",
        r"let ordinaryYield = function y\u0069eld() {};",
        r"let asyncYield = async function y\u0069eld() {};",
        r"class aw\u0061it {}",
        r"try {} catch (l\u0065t) {}",
        r"'use strict'; try {} catch (aw\u0061it) {}",
        r"try {} catch ({r\u0065turn: value}) {}",
        r"function duplicate(value, v\u0061lue) { return value; }",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("`{source}` should retain its grammar-specific acceptance: {error:?}")
            });
    }

    for source in [
        r"function st\u0061tic() {'use strict';}",
        r"let named = function* y\u0069eld() {};",
        r"class st\u0061tic {}",
        r"async function outer() { function aw\u0061it() {} }",
        r"function* outer() { function y\u0069eld() {} }",
        r"try {} catch ({value: r\u0065turn}) {}",
        r"function duplicate(value, v\u0061lue) {'use strict';}",
        r"let duplicate = (value, v\u0061lue) => value;",
        r"function duplicate([value, v\u0061lue]) {}",
        r"try {} catch ([value, v\u0061lue]) {}",
        r"function ev\u0061l() {'use strict';}",
        r"class ev\u0061l {}",
        r"'use strict'; try {} catch (ev\u0061l) {}",
        r"let invalid = async function aw\u0061it() {};",
        r"let invalid = async function* aw\u0061it() {};",
        r"let invalid = async function* y\u0069eld() {};",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("binding grammar restriction must be enforced");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn binding_names_apply_lexical_and_function_context_rules_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "let let = 1",
        "let {let} = source",
        "const {let} = source",
        "for (let let of values) {}",
        "for (const {let} of values) {}",
        "let arrow = async await => 1",
        r"let arrow = async (\u0061wait) => 1",
        "async function invalid(value = await 1) {}",
        r"async function invalid(value = \u0061wait(1)) {}",
        "let arrow = async (value = await(1)) => value",
        "async function outer() { let invalid = (value = await 1) => value; }",
        "function* generator(yield) {}",
        "function* invalid(value = yield 1) {}",
        r"function* invalid(value = \u0079ield(1)) {}",
        "let generator = function*(value = yield(1)) {}",
        "function* outer() { let invalid = (value = yield 1) => value; }",
        "function* invalid() { let value = (yield\n1); }",
        "function* invalid() { let value = (yield\n*items); }",
        "function* invalid() { let value = (yield/* line\nterm */1); }",
        r"let generator = function*(\u0079ield) {}",
        "function strict(eval) {'use strict';}",
        "function strictDefault(value = 1) {'use strict';}",
        "let strictArrow = (value = 1) => {'use strict';}",
        "class StrictMethod { method(value = 1) {'use strict';} }",
        "'use strict'; var static = 1",
        "'use strict'; var arguments = 1",
        "function strictAsi() {\n'use strict'\nvar static = 1;\n}",
        "function strictLeading() { /* lead */ 'use strict'; var static = 1; }",
        "function strictTrailing() { 'use strict' /* tail */; var static = 1; }",
        "/* lead */ 'use strict' /* tail */; var static = 1",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("binding name must honor its lexical and function context");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn identifier_references_track_strict_async_and_generator_context_bd_4d60a() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "'use strict'; ({static})",
        r"'use strict'; ({\u0073tatic})",
        "'not strict'; 'use strict'; ({static})",
        "'use strict'\n++value; ({static})",
        "let arrow = async () => ({await})",
        r"let arrow = async () => ({\u0061wait})",
        "function* generator() { return {yield}; }",
        r"function* generator() { return {\u0079ield}; }",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("identifier reference must honor its grammar context");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }

    parser
        .parse(r#""\x75se strict"; ({static})"#, ParseGoal::Script)
        .expect("escaped directive text must not enable strict mode");
    parser
        .parse("\"use strict\"\n({static})", ParseGoal::Script)
        .expect("a continued string-literal expression is not a directive");
    parser
        .parse(
            r#"function notStrict() { "use \
strict"; var static = 1; }"#,
            ParseGoal::Script,
        )
        .expect("a string containing a LineContinuation is not a use strict directive");
    for continued in [
        "\"use strict\"\nin({})",
        "\"use strict\"\ninstanceof/* comment */ value",
        "\"use strict\"\n!= value",
    ] {
        assert!(
            !has_use_strict_directive(continued),
            "continued expression must not become a directive: {continued}"
        );
    }

    parser
        .parse(
            "var await = value => value; var yield = 3; await(yield)",
            ParseGoal::Script,
        )
        .expect("sloppy Script should treat await and yield as identifier references");
    parser
        .parse(
            "async function wait(value) { return await value; } function* items() { yield 1; }",
            ParseGoal::Script,
        )
        .expect("async and generator bodies should parse their contextual expressions");
    parser
        .parse(
            "async function waits() { return await[1]; } \
             async function waitsOnObject() { return await{value: 1}; } \
             function* yields() { yield(1); yield[1]; yield{value: 1}; }",
            ParseGoal::Script,
        )
        .expect("contextual expressions should accept adjacent primary-expression forms");
    parser
        .parse(
            "async function outerAsync() { function inner(await) { return await; } } \
             function* outerGenerator() { function inner(yield) { return yield; } } \
             function* splitYield() { yield\n1; yield/* line\nterm */2; \
                 yield/* line\u{2028}separator */3; } \
             function* commaYield() { let first = (yield, 1); \
                 let second = (yield\n, 2); }",
            ParseGoal::Script,
        )
        .expect("nested functions reset grammar parameters and bare yield honors restricted ASI");
    for member_expression in [
        "return obj.yield /* line\nterm */ + 1",
        "return obj . yield /* line\nterm */ * 2",
        "return obj?.yield /* line\nterm */ + 1",
        "return obj.yield /* line\nterm */ (1)",
        "return obj. /* member */ yield /* line\nterm */ (1)",
        "return obj?. /* member */ yield /* line\nterm */ (1)",
        "return obj.\u{00A0}yield /* line\nterm */ (1)",
        "return obj.\u{FEFF}yield /* line\nterm */ (1)",
    ] {
        assert!(
            top_level_yield_asi_split(member_expression).is_none(),
            "member property `yield` is not a YieldExpression: {member_expression}"
        );
    }
    parser
        .parse(
            "function* memberYield() { return obj.yield /* line\nterm */ + 1; \
                return obj . yield /* line\nterm */ * 2; \
                return obj.yield /* line\nterm */ (1); \
                return obj. /* member */ yield /* line\nterm */ (1); }",
            ParseGoal::Script,
        )
        .expect("member properties named yield must not trigger restricted-production ASI");
}

#[test]
fn malformed_unicode_binding_names_fail_closed_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    for source in [
        r"var {\u0030bad} = source",
        r"var {\x61} = source",
        r"var \u{110000} = 1",
        r"\u0030bad => 1",
        r"\x61 => 1",
        r"let value = \u0030bad",
        r"let value = \x61",
        r"let value = \u{110000}",
        r"let value = \u{+61}",
        r"let value = a\u{61-}",
        "let value = \u{0300}bad",
        "let value = \u{200C}bad",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed binding name must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    }
}

#[test]
fn unsupported_raw_expressions_remain_compatible_bd_t4947() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "let bigint = 1n; let dynamic = import('pkg'); \
             let generator = function*(){ yield 1; }; \
             let commented = function /* function marker */ * /* params */ () { yield 2; }; \
             let product = obj . function * 2",
            ParseGoal::Script,
        )
        .expect("legacy valid-expression carriers should remain parse-compatible");
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected variable declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::Raw(source)) if source == "1n"
    ));

    let Statement::VariableDeclaration(declaration) = &tree.body[1] else {
        panic!("expected dynamic-import declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::Call { callee, .. })
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == "import")
    ));

    let Statement::VariableDeclaration(declaration) = &tree.body[2] else {
        panic!("expected generator declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::Function {
            is_generator: true,
            ..
        })
    ));

    let Statement::VariableDeclaration(declaration) = &tree.body[3] else {
        panic!("expected trivia-separated generator declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::Function {
            is_generator: true,
            ..
        })
    ));

    let Statement::VariableDeclaration(declaration) = &tree.body[4] else {
        panic!("expected member-product declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::Binary {
            operator: BinaryOperator::Multiply,
            ..
        })
    ));

    assert!(generator_function_marker_prefix(
        "function /* function marker */ "
    ));
    for property_prefix in ["obj. /* member */ function ", "obj.function // function\n "] {
        assert!(
            !generator_function_marker_prefix(property_prefix),
            "property named function is not a generator marker: {property_prefix:?}"
        );
    }
}

#[test]
fn postfix_operands_preserve_comment_trivia_bd_56geo() {
    let tree = parse_script(
        "let blockProduct = obj. /* member */ function * 2; \
         let lineProduct = obj.function // trailing member trivia\n * 2; \
         let memberCall = obj. /* member . */ function /* callee */ \
             (/* argument ) , */ 2 /* trailing argument */); \
         let directCall = callback /* callee */ \
             (/* argument */ 3 /* trailing argument */); \
         let optionalMember = obj?. /* member . */ function; \
         let computedMember = obj[/* property ] */ 'function']; \
         let commentOnlyCall = callback(/**/); \
         let punctuatedArguments = callback(/* delimiters ) , */ 1, 2); \
         let trailingComment = callback(1, /* trailing */);",
    );
    let initializer = |index: usize| {
        let Statement::VariableDeclaration(declaration) = &tree.body[index] else {
            panic!("expected variable declaration at index {index}");
        };
        declaration.declarations[0]
            .initializer
            .as_ref()
            .unwrap_or_else(|| panic!("missing initializer at index {index}"))
    };

    for index in [0, 1] {
        assert!(
            matches!(
                initializer(index),
                Expression::Binary {
                    operator: BinaryOperator::Multiply,
                    left,
                    right,
                } if matches!(left.as_ref(), Expression::Member {
                    object,
                    property,
                    computed: false,
                } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                    && matches!(property.as_ref(), Expression::Identifier(name) if name == "function"))
                    && matches!(right.as_ref(), Expression::NumericLiteral(2))
            ),
            "unexpected product initializer at index {index}: {:?}",
            initializer(index)
        );
    }

    assert!(matches!(
        initializer(2),
        Expression::Call { callee, arguments }
            if matches!(arguments.as_slice(), [Expression::NumericLiteral(2)])
                && matches!(callee.as_ref(), Expression::Member {
                    object,
                    property,
                    computed: false,
                } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                    && matches!(property.as_ref(), Expression::Identifier(name) if name == "function"))
    ));
    assert!(matches!(
        initializer(3),
        Expression::Call { callee, arguments }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                && matches!(arguments.as_slice(), [Expression::NumericLiteral(3)])
    ));
    assert!(matches!(
        initializer(4),
        Expression::OptionalMember {
            object,
            property,
            computed: false,
        } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
            && matches!(property.as_ref(), Expression::Identifier(name) if name == "function")
    ));
    assert!(matches!(
        initializer(5),
        Expression::Member {
            object,
            property,
            computed: true,
        } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
            && matches!(property.as_ref(), Expression::StringLiteral(name) if name == "function")
    ));
    assert!(matches!(
        initializer(6),
        Expression::Call { callee, arguments }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                && arguments.is_empty()
    ));
    assert!(matches!(
        initializer(7),
        Expression::Call { callee, arguments }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                && matches!(arguments.as_slice(), [
                    Expression::NumericLiteral(1),
                    Expression::NumericLiteral(2),
                ])
    ));
    assert!(matches!(
        initializer(8),
        Expression::Call { callee, arguments }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                && matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
    ));
}

#[test]
fn unterminated_postfix_comment_trivia_fails_closed_bd_56geo() {
    let parser = CanonicalEs2020Parser;
    for source in ["obj./*", "obj[/*]", "callback(/*)"] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("unterminated postfix comment must fail closed");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }

    for source in ["obj? .value", "obj?\n.value", "obj?/* trivia */.value"] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("lexical trivia must not be joined into the `?.` punctuator");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }
}

#[test]
fn postfix_comment_trivia_does_not_hide_invalid_delimiters_bd_56geo() {
    let parser = CanonicalEs2020Parser;
    for source in ["callback(/* trivia */, 1)", "callback(1, /* trivia */, 2)"] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("comment trivia must not hide invalid postfix delimiters");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }

    for source in ["callback(1))", "obj['value']]"] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("an unmatched final delimiter must fail closed");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }
}

#[test]
fn malformed_static_object_binding_keys_fail_closed_bd_h4esx() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "var {0_1: value} = source",
        "var {a-b: value} = source",
        r#"var {"a""b": value} = source"#,
        r"var {'a''b': value} = source",
        "var {'a\nb': value} = source",
        "var {'a\rb': value} = source",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed static property key must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            error.message.contains("object-binding property key"),
            "{source:?}: {}",
            error.message
        );
    }

    let source = r"var {\u0030bad: value} = source";
    let error = parser
        .parse(source, ParseGoal::Script)
        .expect_err("escaped non-IdentifierStart binding key must be rejected");
    assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    assert!(
        error
            .message
            .contains("unterminated comment or quoted literal in binding pattern"),
        "{source:?}: {}",
        error.message
    );
}

#[test]
fn static_object_literal_keys_use_canonical_ast_forms_bd_y74cd() {
    let tree = parse_script(r#"({"v\x61lue": 1, 1e3: 2, 0x10n: 3, \u03C0: 4})"#);
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 4);
    assert!(matches!(
        &properties[0].key,
        Expression::StringLiteral(key) if key == "value"
    ));
    assert!(matches!(
        &properties[1].key,
        Expression::NumericLiteral(1000)
    ));
    assert!(matches!(
        &properties[2].key,
        Expression::StringLiteral(key) if key == "16"
    ));
    assert!(matches!(
        &properties[3].key,
        Expression::Identifier(key) if key == "π"
    ));
}

#[test]
fn static_property_keys_preserve_exact_utf16_bd_b12xs_6() {
    let expected = [0xD800];

    let object_tree = parse_script(r#"({"\uD800": 1})"#);
    let Expression::ObjectLiteral(properties) = first_expr(&object_tree) else {
        panic!("expected object literal");
    };
    assert!(matches!(
        &properties[0].key,
        Expression::StringLiteral(key) if key.code_units_vec() == expected
    ));

    let binding_tree = parse_script(r#"let {"\uD800": value} = source;"#);
    let Statement::VariableDeclaration(declaration) = &binding_tree.body[0] else {
        panic!("expected object-binding declaration");
    };
    let BindingPattern::ObjectPattern(properties) = &declaration.declarations[0].pattern else {
        panic!("expected object-binding pattern");
    };
    assert!(matches!(
        &properties[0].key,
        Expression::StringLiteral(key) if key.code_units_vec() == expected
    ));

    let class_tree = parse_script(r#"class Exact { "\uD800"() {} }"#);
    let Statement::ClassDeclaration(class) = &class_tree.body[0] else {
        panic!("expected class declaration");
    };
    assert!(matches!(
        &class.body[0].key,
        Expression::StringLiteral(key) if key.code_units_vec() == expected
    ));
}

#[test]
fn computed_object_literal_key_parses_the_inner_expression_bd_y74cd() {
    let tree = parse_script("({[null]: 7})");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    assert!(properties[0].computed);
    assert!(matches!(&properties[0].key, Expression::NullLiteral));
}

#[test]
fn object_literal_methods_preserve_explicit_method_kind_bd_gqaa4() {
    let methods = parse_script(
        r#"({ next(value) { return value; }, [Symbol.iterator]() { return this; }, "x("() { return 3; }, 1() { return 4; } })"#,
    );
    let Expression::ObjectLiteral(properties) = first_expr(&methods) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 4);
    assert!(!properties[0].computed);
    assert!(properties[1].computed);
    assert!(properties.iter().all(|property| !property.shorthand));
    assert!(
        properties
            .iter()
            .all(|property| property.kind == ObjectPropertyKind::Method)
    );
    let Expression::Function {
        name,
        params,
        body,
        is_async,
        is_generator,
    } = &properties[0].value
    else {
        panic!("plain method value must be a function");
    };
    assert!(name.is_none());
    assert_eq!(params.len(), 1);
    assert!(matches!(body.body.as_slice(), [Statement::Return(_)]));
    assert!(!is_async);
    assert!(!is_generator);
    assert!(matches!(
        &properties[1].value,
        Expression::Function {
            name: None,
            params,
            is_async: false,
            is_generator: false,
            ..
        } if params.is_empty()
    ));
    assert!(
        properties[2..]
            .iter()
            .all(|property| matches!(&property.value, Expression::Function { .. }))
    );

    let explicit_functions = parse_script(
        r#"({ next: function(value) { return value; }, [Symbol.iterator]: function() { return this; }, "x(": function() { return 3; }, 1: function() { return 4; } })"#,
    );
    let Expression::ObjectLiteral(explicit_properties) = first_expr(&explicit_functions) else {
        panic!("expected explicit-function object literal");
    };
    assert!(
        explicit_properties
            .iter()
            .all(|property| property.kind == ObjectPropertyKind::Data)
    );
    assert_ne!(
        first_expr(&methods).canonical_value(),
        first_expr(&explicit_functions).canonical_value(),
        "concise methods must remain canonically distinct from function-valued data properties"
    );
}

#[test]
fn object_literal_method_headers_accept_lexical_trivia_bd_vjmy7() {
    let tree = parse_script(
        "({ plain/* key */\u{feff}()/* body */\u{feff}{ return 1; }, /* leading */\u{feff}[Symbol.iterator]/* computed */\u{feff}() { return this; } })",
    );
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 2);
    assert!(!properties[0].computed);
    assert!(properties[1].computed);
    assert!(
        properties
            .iter()
            .all(|property| property.kind == ObjectPropertyKind::Method
                && matches!(&property.value, Expression::Function { .. }))
    );
}

#[test]
fn object_literal_method_names_use_property_name_grammar_bd_vjmy7() {
    let parser = CanonicalEs2020Parser;
    for (source, goal, expected_name) in [
        ("'use strict'; ({ yield() {} })", ParseGoal::Script, "yield"),
        ("({ await() {} })", ParseGoal::Module, "await"),
    ] {
        let tree = parser
            .parse(source, goal)
            .expect("reserved words remain valid static PropertyNames");
        let Statement::Expression(statement) =
            tree.body.last().expect("expected object expression")
        else {
            panic!("expected object expression");
        };
        let Expression::ObjectLiteral(properties) = &statement.expression else {
            panic!("expected object literal");
        };
        assert!(matches!(
            &properties[0].key,
            Expression::Identifier(name) if name == expected_name
        ));
        assert_eq!(properties[0].kind, ObjectPropertyKind::Method);
    }
}

#[test]
fn object_literal_async_and_generator_methods_remain_explicitly_unsupported_bd_vjmy7() {
    let named_like_modifiers = parse_script("({ get() {}, set() {}, async() {} })");
    let Expression::ObjectLiteral(properties) = first_expr(&named_like_modifiers) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 3);
    assert!(
        properties
            .iter()
            .all(|property| property.kind == ObjectPropertyKind::Method
                && matches!(&property.value, Expression::Function { .. }))
    );

    let parser = CanonicalEs2020Parser;
    for supported in [
        "({ async next() {} })",
        "({ async [key]() {} })",
        "({ get value() {} })",
        "({ set value(next) {} })",
    ] {
        parser
            .parse(supported, ParseGoal::Script)
            .unwrap_or_else(|err| {
                panic!("supported object method/accessor failed: {supported}: {err:?}")
            });
    }
    for source in [
        "({ *next() {} })",
        "({ *[key]() {} })",
        "({ async *next() {} })",
        "({ async *[key]() {} })",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("unsupported generator method form must not be approximated as ordinary");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
    }
}

#[test]
fn object_literal_methods_require_unique_parameter_bindings_bd_vjmy7() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("({ method(value, value) {} })", ParseGoal::Script)
        .expect_err("concise methods require UniqueFormalParameters");
    assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    assert!(error.message.contains("duplicate object-method parameter"));
}

#[test]
fn computed_object_method_keys_preserve_strict_boundaries_bd_vjmy7() {
    let tree =
        parse_script("({ [Symbol.iterator]() {}, [nested[key]]() {}, [']']() {}, [`]`]() {} })");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected computed-method object literal");
    };
    assert_eq!(properties.len(), 4);
    assert!(properties.iter().all(|property| property.computed));
    assert!(
        properties
            .iter()
            .all(|property| property.kind == ObjectPropertyKind::Method)
    );
    assert!(matches!(
        &properties[0].key,
        Expression::Member {
            object,
            property,
            computed: false,
        } if matches!(object.as_ref(), Expression::Identifier(name) if name == "Symbol")
            && matches!(property.as_ref(), Expression::Identifier(name) if name == "iterator")
    ));
    assert!(matches!(
        &properties[1].key,
        Expression::Member {
            object,
            property,
            computed: true,
        } if matches!(object.as_ref(), Expression::Identifier(name) if name == "nested")
            && matches!(property.as_ref(), Expression::Identifier(name) if name == "key")
    ));
    assert!(matches!(
        &properties[2].key,
        Expression::StringLiteral(value) if value.as_str() == Some("]")
    ));
    assert!(matches!(
        &properties[3].key,
        Expression::TemplateLiteral { quasis, expressions }
            if quasis == &["]"] && expressions.is_empty()
    ));

    let parser = CanonicalEs2020Parser;
    for source in [
        "({ []() {} })",
        "({ [key] trailing() {} })",
        "({ [1, 2]() {} })",
        "({ [...items]() {} })",
        "({ next() {} trailing })",
        "({ [key]() {} trailing })",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("invalid computed/trailing method syntax must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
    }
}

#[test]
fn computed_object_method_key_calls_are_preserved_once_in_source_order_bd_gqaa4() {
    let tree = parse_script(r#"({ [record("first")]() {}, [record("second")]() {} })"#);
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected computed-method object literal");
    };

    assert_eq!(properties.len(), 2);
    for (property, expected_argument) in properties.iter().zip(["first", "second"]) {
        assert!(property.computed);
        assert_eq!(property.kind, ObjectPropertyKind::Method);
        assert!(matches!(
            &property.key,
            Expression::Call { callee, arguments }
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "record")
                    && matches!(arguments.as_slice(), [Expression::StringLiteral(value)]
                        if value.as_str() == Some(expected_argument))
        ));
    }
}

#[test]
fn object_literal_shorthand_uses_canonical_identifier_bd_y74cd() {
    let tree = parse_script(r"({\u0076alue, await, static})");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 3);
    for (property, expected) in properties.iter().zip(["value", "await", "static"]) {
        assert!(property.shorthand);
        assert!(matches!(
            &property.key,
            Expression::Identifier(name) if name == expected
        ));
        assert!(matches!(
            &property.value,
            Expression::Identifier(name) if name == expected
        ));
    }
}

#[test]
fn reserved_words_remain_valid_static_object_literal_keys_bd_y74cd() {
    let tree = parse_script("({if: 1, true: 2, null: 3})");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    for (property, expected) in properties.iter().zip(["if", "true", "null"]) {
        assert!(!property.shorthand);
        assert!(matches!(
            &property.key,
            Expression::Identifier(name) if name == expected
        ));
    }
}

#[test]
fn malformed_static_object_literal_keys_fail_closed_bd_y74cd() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "let value = {0_1: 7}",
        "let value = {a-b: 7}",
        r#"let value = {"a""b": 7}"#,
        r"let value = {'a''b': 7}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed static object key must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(error.message.contains("object-literal property key"));
    }
}

#[test]
fn malformed_computed_object_literal_keys_fail_closed_bd_y74cd() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "let value = {[]: 7}",
        "let value = {[key] trailing: 7}",
        "let value = {[1, 2]: 7}",
        "let value = {[...items]: 7}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed computed object key must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            error
                .message
                .contains("computed object-literal property key")
        );
    }
}

#[test]
fn computed_object_literal_key_scans_are_regexp_aware_bd_egjks() {
    let tree = parse_script(r"({[/]/]: 7, [/[/]/]: 8, [/\]/]: 9, [/[:,\]]/g]: 10})");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected object literal");
    };
    assert_eq!(properties.len(), 4);
    for (property, (pattern, flags, value)) in properties.iter().zip([
        ("]", "", 7),
        ("[/]", "", 8),
        (r"\]", "", 9),
        (r"[:,\]]", "g", 10),
    ]) {
        assert!(property.computed);
        assert!(matches!(
            &property.key,
            Expression::RegExpLiteral {
                pattern: actual_pattern,
                flags: actual_flags,
            } if actual_pattern == pattern && actual_flags == flags
        ));
        assert!(matches!(
            &property.value,
            Expression::NumericLiteral(actual) if *actual == value
        ));
    }

    let tree = parse_script("({[left / right]: 1, [nested[key]]: 2, [']']: 3, [`]`]: 4})");
    let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
        panic!("expected mixed computed-key object literal");
    };
    assert!(matches!(
        &properties[0].key,
        Expression::Binary {
            operator: BinaryOperator::Divide,
            ..
        }
    ));
    assert!(matches!(
        &properties[1].key,
        Expression::Member { computed: true, .. }
    ));
    assert!(matches!(
        &properties[2].key,
        Expression::StringLiteral(value) if value == "]"
    ));
    assert!(matches!(
        &properties[3].key,
        Expression::TemplateLiteral { quasis, expressions }
            if matches!(quasis.as_slice(), [value] if value == "]")
                && expressions.is_empty()
    ));
}

#[test]
fn malformed_object_literal_shorthand_fails_closed_bd_y74cd() {
    let parser = CanonicalEs2020Parser;

    let source = "let value = {[key: 7}";
    let error = parser
        .parse(source, ParseGoal::Script)
        .expect_err("unbalanced computed property key must be rejected");
    assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
    assert!(
        error
            .message
            .contains("initializer has unterminated lexical trivia"),
        "{source:?}: {}",
        error.message
    );

    for source in [
        r#"let value = {"key"}"#,
        "let value = {1}",
        "let value = {if}",
        "let value = {class}",
        "let value = {null}",
        "let value = {true}",
        "let value = {this}",
        "let value = {return}",
        "let value = {super}",
        r"let value = {\u0069f}",
        r"let value = {\u0063lass}",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("non-identifier shorthand must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            error.message.contains("object-literal shorthand property"),
            "{source:?}: {}",
            error.message
        );
    }

    for source in ["({await})", "({static})"] {
        let error = parser
            .parse(source, ParseGoal::Module)
            .expect_err("module shorthand must apply strict identifier restrictions");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(error.message.contains("object-literal shorthand property"));
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
fn import_sources_keep_d800_and_dc00_distinct_bd_lfq44() {
    let parser = CanonicalEs2020Parser;
    let d800_tree = parser
        .parse(r#"import "\uD800""#, ParseGoal::Module)
        .expect("D800 import should parse");
    let dc00_tree = parser
        .parse(r#"import "\uDC00""#, ParseGoal::Module)
        .expect("DC00 import should parse");
    let Statement::Import(d800) = &d800_tree.body[0] else {
        panic!("expected D800 import statement");
    };
    let Statement::Import(dc00) = &dc00_tree.body[0] else {
        panic!("expected DC00 import statement");
    };

    assert_eq!(d800.source.code_units_vec(), vec![0xD800]);
    assert_eq!(dc00.source.code_units_vec(), vec![0xDC00]);
    assert_ne!(d800.source, dc00.source);
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
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_named_clause_with_invalid_alias_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import { run as } from 'pkg'", ParseGoal::Module)
        .expect_err("invalid named import alias must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_default_binding_keyword_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import for from 'pkg'", ParseGoal::Module)
        .expect_err("keyword default import binding must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_namespace_binding_keyword_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import * as for from 'pkg'", ParseGoal::Module)
        .expect_err("keyword namespace import binding must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn import_named_clause_keyword_binding_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import { run as for } from 'pkg'", ParseGoal::Module)
        .expect_err("keyword named import binding must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
fn export_named_clause_parsed() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export { a, b }", ParseGoal::Module)
        .expect("parse");
    match &tree.body[0] {
        Statement::Export(export) => match &export.kind {
            ExportKind::NamedClause(clause) => {
                assert_eq!(clause.canonical_head(), "{ a, b }");
                assert_eq!(clause.source(), None);
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
                assert_eq!(
                    clause.historical_wire_text().as_deref(),
                    Some("{ default as dep, run as start } from \"pkg\"")
                );
            }
            _ => panic!("expected named clause export"),
        },
        _ => panic!("expected export statement"),
    }
}

#[test]
fn named_reexport_sources_keep_d800_and_dc00_distinct_bd_lfq44() {
    let parser = CanonicalEs2020Parser;
    let d800_tree = parser
        .parse(r#"export { value } from "\uD800""#, ParseGoal::Module)
        .expect("D800 re-export should parse");
    let dc00_tree = parser
        .parse(r#"export { value } from "\uDC00""#, ParseGoal::Module)
        .expect("DC00 re-export should parse");
    let Statement::Export(d800_export) = &d800_tree.body[0] else {
        panic!("expected D800 export statement");
    };
    let Statement::Export(dc00_export) = &dc00_tree.body[0] else {
        panic!("expected DC00 export statement");
    };
    let ExportKind::NamedClause(d800_clause) = &d800_export.kind else {
        panic!("expected D800 named export");
    };
    let ExportKind::NamedClause(dc00_clause) = &dc00_export.kind else {
        panic!("expected DC00 named export");
    };
    let d800 = d800_clause.source().expect("D800 source");
    let dc00 = dc00_clause.source().expect("DC00 source");

    assert_eq!(d800.code_units_vec(), vec![0xD800]);
    assert_eq!(dc00.code_units_vec(), vec![0xDC00]);
    assert_ne!(d800, dc00);
}

#[test]
fn export_named_clause_cooks_source_without_collapsing_inner_space_bd_vltnh() {
    let tree = CanonicalEs2020Parser
        .parse(r#"export { value } from "a  \u0062""#, ParseGoal::Module)
        .expect("escaped re-export source should parse");
    let Statement::Export(export) = &tree.body[0] else {
        panic!("expected export statement");
    };
    let ExportKind::NamedClause(clause) = &export.kind else {
        panic!("expected named export clause");
    };
    assert_eq!(
        clause.historical_wire_text().as_deref(),
        Some(r#"{ value } from "a  b""#)
    );
}

#[test]
fn export_named_clause_invalid_specifier_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export { run as }", ParseGoal::Module)
        .expect_err("invalid named export alias must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn export_named_clause_unquoted_source_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export { run } from pkg", ParseGoal::Module)
        .expect_err("export source must be quoted");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn export_non_named_non_default_clause_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("export run", ParseGoal::Module)
        .expect_err("unsupported export clause must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
    let json = serde_json::to_string(&err).unwrap();
    let decoded: ParseError = serde_json::from_str(&json).unwrap();
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
    let source = "await await work";
    let left = parser
        .parse_with_options(source, ParseGoal::Script, &options)
        .expect_err("left parse should fail");
    let right = parser
        .parse_with_options(source, ParseGoal::Script, &options)
        .expect_err("right parse should fail");
    assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
    assert_eq!(left, right);
}

fn parse_with_binding_pattern_limit_bd_ogiqj(
    source: &str,
    max_recursion_depth: u64,
) -> ParseResult<SyntaxTree> {
    CanonicalEs2020Parser.parse_with_options(
        source,
        ParseGoal::Script,
        &ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1 << 20,
                max_token_count: 1 << 20,
                max_recursion_depth,
            },
        },
    )
}

fn binding_pattern_position_sources_bd_ogiqj(pattern: &str) -> [(&'static str, String); 5] {
    [
        ("variable", format!("let {pattern} = source;")),
        ("parameter", format!("function f({pattern}) {{}}")),
        ("catch", format!("try {{}} catch ({pattern}) {{}}")),
        ("for-in", format!("for (let {pattern} in source) {{}}")),
        ("for-of", format!("for (let {pattern} of source) {{}}")),
    ]
}

#[test]
fn deep_binding_patterns_are_bounded_in_every_position_bd_ogiqj() {
    let depth = 2000;
    let patterns = [
        (
            "array",
            format!("{}value{}", "[".repeat(depth), "]".repeat(depth)),
        ),
        (
            "object",
            format!("{}value{}", "{key:".repeat(depth), "}".repeat(depth)),
        ),
    ];

    for (pattern_kind, pattern) in patterns {
        for (position, source) in binding_pattern_position_sources_bd_ogiqj(&pattern) {
            let error = parse_with_binding_pattern_limit_bd_ogiqj(&source, 32)
                .expect_err("deep binding pattern must exhaust its recursion budget");
            assert_eq!(
                error.code,
                ParseErrorCode::BudgetExceeded,
                "{pattern_kind} pattern in {position} must retain its budget diagnostic: {error:?}"
            );
            assert_eq!(
                error.message,
                "binding-pattern nesting budget exceeded: depth=33 max=32"
            );
            let witness = error
                .witness
                .as_deref()
                .expect("binding-pattern exhaustion must carry deterministic evidence");
            assert_eq!(witness.budget_kind, Some(ParseBudgetKind::RecursionDepth));
            assert_eq!(witness.max_recursion_observed, 33);
            assert_eq!(witness.max_recursion_depth, 32);
        }
    }
}

#[test]
fn shallow_binding_patterns_parse_in_every_position_bd_ogiqj() {
    for pattern in ["[a, [b, [c, [d]]]]", "{a: {b: {c: d}}}"] {
        for (position, source) in binding_pattern_position_sources_bd_ogiqj(pattern) {
            parse_with_binding_pattern_limit_bd_ogiqj(&source, 32).unwrap_or_else(|error| {
                panic!("shallow pattern in {position} must remain valid: {error:?}")
            });
        }
    }
}

#[test]
fn binding_pattern_depth_unwinds_after_budget_refusal_bd_ogiqj() {
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1 << 20,
            max_token_count: 1 << 20,
            max_recursion_depth: 32,
        },
    };
    let deep_pattern = format!("{}value{}", "[".repeat(2000), "]".repeat(2000));
    let span = SourceSpan::new(0, deep_pattern.len() as u64, 1, 1, 1, 1);
    let mut context = ParseExecutionContext {
        source_label: "bd-ogiqj-pattern.js",
        options: &options,
        goal: ParseGoal::Script,
        strict_mode: false,
        await_identifier_reserved: false,
        yield_identifier_reserved: false,
        allow_await_expression: false,
        allow_yield_expression: false,
        source_bytes: deep_pattern.len() as u64,
        token_count: count_lexical_tokens(&deep_pattern),
        max_recursion_observed: 0,
        statement_depth: 0,
        pattern_depth: 0,
    };
    let grammar_context = ScanGrammarContext::SLOPPY_SCRIPT.expression();

    let error = parse_binding_pattern(&deep_pattern, &span, &mut context, grammar_context)
        .expect_err("deep direct pattern must exhaust its recursion budget");
    assert_eq!(error.code, ParseErrorCode::BudgetExceeded);
    assert_eq!(context.pattern_depth, 0);
    assert_eq!(context.max_recursion_observed, 33);

    parse_binding_pattern("[a, [b]]", &span, &mut context, grammar_context)
        .expect("a refused deep pattern must not poison the next parse");
    assert_eq!(context.pattern_depth, 0);
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
        let json = serde_json::to_string(&code).unwrap();
        let restored: ParseErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, restored);
    }
}

#[test]
fn parser_mode_serde_roundtrip() {
    let mode = ParserMode::ScalarReference;
    let json = serde_json::to_string(&mode).unwrap();
    let restored: ParserMode = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&kind).unwrap();
        let restored: ParseBudgetKind = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&status).unwrap();
        let restored: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, restored);
    }
}

// -----------------------------------------------------------------------
// Enrichment: struct serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn parser_budget_serde_roundtrip() {
    let budget = ParserBudget::default();
    let json = serde_json::to_string(&budget).unwrap();
    let restored: ParserBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, restored);
}

#[test]
fn parser_options_serde_roundtrip() {
    let opts = ParserOptions::default();
    let json = serde_json::to_string(&opts).unwrap();
    let restored: ParserOptions = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&witness).unwrap();
    let restored: ParseFailureWitness = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&gfc).unwrap();
    let restored: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&summary).unwrap();
    let restored: GrammarCompletenessSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn grammar_completeness_matrix_serde_roundtrip() {
    let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let restored: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&err).unwrap();
    assert!(!json.contains("witness"));
    let restored: ParseError = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("witness"));
    let restored: ParseError = serde_json::from_str(&json).unwrap();
    assert!(restored.witness.is_some());
    assert_eq!(restored.witness.unwrap().source_bytes, 2_000_000);
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
    let json = serde_json::to_string(&left).unwrap();
    let restored: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&kind).unwrap();
        let restored: ParseEventKind = serde_json::from_str(&json).unwrap();
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
    let source = "await work";
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
    let json = serde_json::to_string(&ir).unwrap();
    let restored: ParseEventIr = serde_json::from_str(&json).unwrap();
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
    let source = "await work";
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
    let json = serde_json::to_string(&rule).unwrap();
    let restored: ParseDiagnosticRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, restored);
}

#[test]
fn parse_diagnostic_taxonomy_serde_roundtrip() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    let json = serde_json::to_string(&taxonomy).unwrap();
    let restored: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
    assert_eq!(taxonomy, restored);
}

#[test]
fn parse_event_materialization_error_serde_roundtrip() {
    let err = ParseEventMaterializationError::new(
        ParseEventMaterializationErrorCode::InvalidEventSequence,
        "bad seq".to_string(),
        Some(3),
    );
    let json = serde_json::to_string(&err).unwrap();
    let restored: ParseEventMaterializationError = serde_json::from_str(&json).unwrap();
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
    assert_eq!(line_count("a\rb\r\nc\u{2028}d\u{2029}e"), 5);
}

#[test]
fn line_count_trailing_newline() {
    assert_eq!(line_count("a\n"), 2);
    assert_eq!(line_count("a\r"), 2);
    assert_eq!(line_count("a\u{2028}"), 2);
    assert_eq!(line_count("a\u{2029}"), 2);
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
        ("alpha\u{2028}beta", 2, 5),
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
    assert!(canonical_module_binding_identifier("for").is_none());
    assert!(canonical_module_binding_identifier("await").is_none());
    assert!(canonical_module_binding_identifier("interface").is_none());
}

#[test]
fn module_binding_identifier_accepts_valid_names() {
    assert!(canonical_module_binding_identifier("dep").is_some());
    assert!(canonical_module_binding_identifier("_local1").is_some());
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
        let json = serde_json::to_string(&cat).unwrap();
        let back: ParseDiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn parse_diagnostic_severity_serde_roundtrip() {
    for sev in [
        ParseDiagnosticSeverity::Error,
        ParseDiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: ParseDiagnosticSeverity = serde_json::from_str(&json).unwrap();
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
        assert_eq!(rule.unwrap().parse_error_code, *code);
    }
}

#[test]
fn taxonomy_rule_for_severity_matches_code_method() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in &ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(*code).unwrap();
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
        let json = serde_json::to_string(v).unwrap();
        let back: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&fam).unwrap();
    let back: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
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
    assert_eq!(parse_quoted_string("'abc'"), Some("abc".into()));
    assert_eq!(parse_quoted_string("\"xyz\""), Some("xyz".into()));
    assert_eq!(parse_quoted_string("''"), Some(JsString::empty()));
    assert_eq!(parse_quoted_string("'a\\\nb'"), Some("ab".into()));
    assert_eq!(
        parse_quoted_string("'a\u{2028}b'"),
        Some("a\u{2028}b".into()),
        "ES2020 permits unescaped line and paragraph separators in string literals"
    );
    assert_eq!(
        parse_quoted_string(r"'a\nb'"),
        Some("a\nb".into()),
        "module sources still use the shared escape cooking"
    );
}

#[test]
fn parse_quoted_string_preserves_lone_surrogate_module_names_bd_lfq44() {
    let d800 = parse_quoted_string(r#""\uD800""#).expect("D800 source");
    let dc00 = parse_quoted_string(r"'\uDC00'").expect("DC00 source");
    assert_eq!(d800.code_units_vec(), vec![0xD800]);
    assert_eq!(dc00.code_units_vec(), vec![0xDC00]);
    assert_ne!(d800, dc00);
    assert_eq!(
        parse_quoted_string(r#""\uD83D\uDE00""#),
        Some("😀".into()),
        "well-formed surrogate pairs remain valid UTF-8 module names"
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
fn parse_f64_numeric_literal_special_values() {
    assert_eq!(parse_f64_numeric_literal("Infinity"), None);
    assert_eq!(parse_f64_numeric_literal("-Infinity"), None);
    assert_eq!(parse_f64_numeric_literal("NaN"), None);
}

#[test]
fn parse_f64_numeric_literal_with_separators() {
    assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
    assert_eq!(parse_f64_numeric_literal("1.5_00"), Some(1.5));
}

#[test]
fn parse_f64_numeric_literal_integer_without_dot_or_exp_returns_none() {
    // Pure integers should be handled by parse_i64_numeric_literal
    assert!(parse_f64_numeric_literal("42").is_none());
    assert!(parse_f64_numeric_literal("0xFF").is_none());
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
        statement_kind_label(&Statement::Labeled(LabeledStatement {
            label: "outer".to_string(),
            body: Box::new(Statement::Block(BlockStatement {
                body: Vec::new(),
                span: span.clone(),
            })),
            span: span.clone(),
        })),
        "labeled"
    );
    assert_eq!(
        statement_kind_label(&Statement::Expression(ExpressionStatement {
            expression: Expression::NullLiteral,
            span,
            raw_directive: None,
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
    let json = serde_json::to_string(&e).unwrap();
    let back: ParseEvent = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&e).unwrap();
    let back: ParseEvent = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&n).unwrap();
    let back: MaterializedStatementNode = serde_json::from_str(&json).unwrap();
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
    let json = serde_json::to_string(&tree).unwrap();
    let back: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
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

fn first_expr(tree: &SyntaxTree) -> &Expression {
    match &tree.body[0] {
        Statement::Expression(es) => &es.expression,
        other => panic!("expected Expression statement, got {:?}", other),
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

// Donor parity for bd-fbexl was checked against Node 20.19.4 and Bun
// 1.3.14: both reject the unparenthesized mixtures below and accept the
// corresponding parenthesized, assignment-boundary, and optional-chain
// forms. Keep the matrix local to the parser regression so precedence
// changes cannot silently re-admit the early-error cases.
#[test]
fn nullish_and_logical_mixtures_require_parentheses_bd_fbexl() {
    let parser = CanonicalEs2020Parser;

    for source in [
        "a ?? b || c;",
        "a || b ?? c;",
        "a ?? b && c;",
        "a && b ?? c;",
        "a ?? b || c && d;",
        "(a ?? b || c);",
        "call(a ?? b || c);",
        "[a && b ?? c];",
        "({ value: a ?? b || c });",
        "a ? b ?? c || d : e;",
        "target = a && b ?? c;",
        "x => a ?? b || c;",
        "`${a ?? b || c}`;",
        "a ?? /* gap */ b || c;",
        "a ?? b\n|| c;",
        "obj?.value ?? fallback || other;",
        "if (a ?? b || c) run();",
        "while (a && b ?? c) run();",
        "for (; a ?? b || c; ) run();",
        "a ?? b || c, d;",
        "a, b && c ?? d;",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("unparenthesized mixtures must be syntax errors");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        assert!(
            error.message.contains("cannot be mixed"),
            "unexpected error for {source:?}: {error:?}"
        );
    }

    for source in [
        "(a ?? b) || c;",
        "a ?? (b || c);",
        "(a && b) ?? c;",
        "a && (b ?? c);",
        "a ?? b ?? c;",
        "a && b || c;",
        "obj?.value ?? fallback;",
        "a ??= b || c;",
        "a ||= b ?? c;",
        "call((a ?? b) || c);",
        "`${(a ?? b) || c}`;",
        "(a ?? b)\n|| c;",
        "a ?? b ? c || d : e && f;",
        "if ((a ?? b) || c) run();",
        "while (a && (b ?? c)) run();",
        "for (; a ?? (b || c); ) run();",
        "a ?? b, c || d;",
        "(a && b, c ?? d);",
        "for (a ?? b, c || d;;) run();",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("valid grouped expression failed: {source:?}: {error:?}")
            });
    }

    for source in [
        "a ?? b ||",
        "a ?? /* gap */ || c",
        "a ?? (b || c",
        "call(a && b ??)",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed mixtures must remain syntax errors");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }

    let left_grouped = parse_script("(a ?? b) || c;");
    assert!(matches!(
        first_expr(&left_grouped),
        Expression::Binary {
            operator: BinaryOperator::LogicalOr,
            left,
            right,
        } if matches!(left.as_ref(), Expression::Binary {
            operator: BinaryOperator::NullishCoalescing,
            ..
        }) && matches!(right.as_ref(), Expression::Identifier(name) if name == "c")
    ));

    let right_grouped = parse_script("a ?? (b || c);");
    assert!(matches!(
        first_expr(&right_grouped),
        Expression::Binary {
            operator: BinaryOperator::NullishCoalescing,
            left,
            right,
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "a")
            && matches!(right.as_ref(), Expression::Binary {
                operator: BinaryOperator::LogicalOr,
                ..
            })
    ));
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
        } => {
            assert_eq!(*operator, AssignmentOperator::Assign);
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
fn assignment_requires_both_operands() {
    let parser = CanonicalEs2020Parser;
    for operator in [
        "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=",
        "||=", "??=",
    ] {
        for source in [
            format!("value {operator};"),
            format!("{operator} 1;"),
            format!("value {operator} /* missing value */;"),
        ] {
            let error = parser
                .parse(source.as_str(), ParseGoal::Script)
                .expect_err("an assignment with a missing operand must fail during parsing");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
        }
        let source = format!("value {operator} 1;");
        let tree = parser
            .parse(source.as_str(), ParseGoal::Script)
            .expect("complete assignment operands remain valid");
        assert!(matches!(first_expr(&tree), Expression::Assignment { .. }));
    }
    assert!(parser.parse("let = ;", ParseGoal::Script).is_err());
    assert!(matches!(
        first_expr(&parse_script("let = 1;")),
        Expression::Assignment { .. }
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
fn ternary_conditional_skips_both_nullish_operator_bytes_bd_56geo() {
    let consequent_nullish = parse_script("a ? b ?? c : d");
    assert!(matches!(
        first_expr(&consequent_nullish),
        Expression::Conditional { consequent, .. }
            if matches!(consequent.as_ref(), Expression::Binary {
                operator: BinaryOperator::NullishCoalescing,
                ..
            })
    ));

    let test_nullish = parse_script("a ?? b ? c : d");
    assert!(matches!(
        first_expr(&test_nullish),
        Expression::Conditional { test, .. }
            if matches!(test.as_ref(), Expression::Binary {
                operator: BinaryOperator::NullishCoalescing,
                ..
            })
    ));

    let decimal_consequent = parse_script("true?.3:0");
    assert!(matches!(
        first_expr(&decimal_consequent),
        Expression::Conditional { consequent, .. }
            if matches!(consequent.as_ref(), Expression::FloatLiteral(bits)
                if f64::from_bits(*bits) == 0.3)
    ));

    let nested_decimal_consequent = parse_script("a ? b?.3:c : d");
    assert!(matches!(
        first_expr(&nested_decimal_consequent),
        Expression::Conditional { consequent, .. }
            if matches!(consequent.as_ref(), Expression::Conditional { .. })
    ));

    let postfix_source = "let x = 0; x++\n?.3:0;";
    assert_eq!(merge_logical_lines(postfix_source).len(), 1);
    let postfix_test = parse_script(postfix_source);
    assert!(matches!(
        &postfix_test.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Conditional {
                    test,
                    consequent,
                    alternate,
                },
                ..
            })
        ] if matches!(test.as_ref(), Expression::Update {
            operator: UpdateOperator::Increment,
            argument,
            prefix: false,
        } if matches!(argument.as_ref(), Expression::Identifier(name) if name == "x"))
            && matches!(consequent.as_ref(), Expression::FloatLiteral(bits)
                if f64::from_bits(*bits) == 0.3)
            && matches!(alternate.as_ref(), Expression::NumericLiteral(0))
    ));

    let arrow_alternate = parse_script("true?.3: x => x");
    assert!(matches!(
        first_expr(&arrow_alternate),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } if matches!(test.as_ref(), Expression::BooleanLiteral(true))
            && matches!(consequent.as_ref(), Expression::FloatLiteral(bits)
                if f64::from_bits(*bits) == 0.3)
            && matches!(alternate.as_ref(), Expression::ArrowFunction {
                params,
                body: ArrowBody::Expression(body),
                is_async: false,
            } if matches!(&params[..], [FunctionParam {
                pattern: BindingPattern::Identifier(name),
                ..
            }] if name == "x")
                && matches!(body.as_ref(), Expression::Identifier(name) if name == "x"))
    ));

    let nested_alternate = parse_script("a ? b : c ? d : e");
    assert!(matches!(
        first_expr(&nested_alternate),
        Expression::Conditional { alternate, .. }
            if matches!(alternate.as_ref(), Expression::Conditional { .. })
    ));

    let optional_member = parse_script("obj?.prop");
    assert!(matches!(
        first_expr(&optional_member),
        Expression::OptionalMember { .. }
    ));

    for source in ["true\n?\n1\n:\n2;", "true ?\n1\n:\n2;"] {
        assert_eq!(merge_logical_lines(source).len(), 1, "{source:?}");
        assert!(matches!(
            first_expr(&parse_script(source)),
            Expression::Conditional { .. }
        ));
    }

    let split_postfix = parse_script("let x = 0; x++\n?\n.3\n:\n0;");
    assert!(matches!(
        &split_postfix.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Conditional { test, .. },
                ..
            })
        ] if matches!(test.as_ref(), Expression::Update {
            operator: UpdateOperator::Increment,
            prefix: false,
            ..
        })
    ));

    let decimal_asi = parse_script("x\n.3; const y = 1\n.4;");
    assert!(matches!(
        &decimal_asi.body[..],
        [
            Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier(name),
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::FloatLiteral(first),
                ..
            }),
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::FloatLiteral(second),
                ..
            })
        ] if name == "x"
            && f64::from_bits(*first) == 0.3
            && f64::from_bits(*second) == 0.4
    ));

    assert!(matches!(
        first_expr(&parse_script("x\n.foo")),
        Expression::Member {
            computed: false,
            ..
        }
    ));

    for source in [
        "if (a) x\n+ y\nelse z;",
        "if (a) var x\n= 1;",
        "if (true) var x = 1\n+\n2;",
        "while (false) var y = 1\n?\n2\n:\n3;",
        "if (true) var a,\nb = (\n1\n)\n+\n2;",
        "while (a) if (b) x\nelse y;",
    ] {
        assert_eq!(merge_logical_lines(source).len(), 1, "{source:?}");
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("nested statement owner was lost: {error:?}"));
    }
    assert_eq!(
        merge_logical_lines("while (a) try {}\ncatch (error) {}").len(),
        1,
        "the logical-line owner must survive even though nested try segmentation is deferred"
    );

    let declaration_clause_tail = parse_script("if (true) var x =\nfoo; bar\n[0];");
    assert!(matches!(
        &declaration_clause_tail.body[..],
        [
            Statement::If(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Member { computed: true, .. },
                ..
            })
        ]
    ));

    let declaration_clause_else = parse_script("if (true) var x =\n1;\nelse y;");
    assert!(matches!(
        &declaration_clause_else.body[..],
        [Statement::If(IfStatement {
            alternate: Some(_),
            ..
        })]
    ));

    let same_line_declaration_clause_else =
        parse_script("if (true) var x =\n1; else if (false)\ny;");
    assert!(matches!(
        &same_line_declaration_clause_else.body[..],
        [Statement::If(IfStatement {
            alternate: Some(alternate),
            ..
        })] if matches!(alternate.as_ref(), Statement::If(_))
    ));

    let expression_then_declaration = parse_script("foo +\nbar; var y\n[1];");
    assert!(matches!(
        &expression_then_declaration.body[..],
        [
            Statement::Expression(ExpressionStatement {
                expression: Expression::Binary {
                    operator: BinaryOperator::Add,
                    ..
                },
                ..
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                declarations,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ] if declarations[0].initializer.is_none()
    ));

    let parser = CanonicalEs2020Parser;
    for source in ["a ? b : c : d", "a ? b", "a ? : c", "a ? b :"] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("malformed conditional punctuation must fail closed");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
    }
}

#[test]
fn initialized_declarations_preserve_multiline_operator_state_bd_56geo() {
    let tree = parse_script(
        "const add = 1\n+\n2;\n\
         const nullish = null\n??\n3;\n\
         const conditional = true\n?\n1\n:\n2;\n\
         const object = {p: 4};\n\
         const member = object\n?.\np;\n\
         const fallback = object\n?.p\n??\n7;",
    );
    assert_eq!(tree.body.len(), 6);
    let initializer = |index: usize| {
        let Statement::VariableDeclaration(declaration) = &tree.body[index] else {
            panic!("expected declaration at index {index}");
        };
        declaration.declarations[0]
            .initializer
            .as_ref()
            .unwrap_or_else(|| panic!("missing initializer at index {index}"))
    };
    assert!(matches!(
        initializer(0),
        Expression::Binary {
            operator: BinaryOperator::Add,
            ..
        }
    ));
    assert!(matches!(
        initializer(1),
        Expression::Binary {
            operator: BinaryOperator::NullishCoalescing,
            ..
        }
    ));
    assert!(matches!(initializer(2), Expression::Conditional { .. }));
    assert!(matches!(initializer(4), Expression::OptionalMember { .. }));
    assert!(matches!(
        initializer(5),
        Expression::Binary {
            operator: BinaryOperator::NullishCoalescing,
            left,
            ..
        } if matches!(left.as_ref(), Expression::OptionalMember { .. })
    ));

    let asi_guard = parse_script("let y = 1; const x = y\n++y;");
    assert!(matches!(
        &asi_guard.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Update { prefix: true, .. },
                ..
            })
        ]
    ));

    let lexical_asi = parse_script("let\nx\n[1];");
    assert!(matches!(
        &lexical_asi.body[..],
        [
            Statement::VariableDeclaration(VariableDeclaration {
                declarations,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ] if declarations[0].initializer.is_none()
    ));

    let split_initializer = parse_script("const x =\nfoo()\n+\nbar;");
    assert!(matches!(
        &split_initializer.body[..],
        [Statement::VariableDeclaration(VariableDeclaration {
            declarations,
            ..
        })] if matches!(declarations[0].initializer.as_ref(), Some(Expression::Binary {
            operator: BinaryOperator::Add,
            ..
        }))
    ));

    let declarator_asi = parse_script("let a = 1,\nx\n[1];");
    assert!(matches!(
        &declarator_asi.body[..],
        [
            Statement::VariableDeclaration(VariableDeclaration {
                declarations,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ] if declarations.len() == 2 && declarations[1].initializer.is_none()
    ));

    let semicolon_asi = parse_script("const x =\nfoo; let y\n[1];");
    assert!(matches!(
        &semicolon_asi.body[..],
        [
            Statement::VariableDeclaration(VariableDeclaration {
                declarations: first,
                ..
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                declarations: second,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ] if first[0].initializer.is_some() && second[0].initializer.is_none()
    ));

    let trailing_expression = parse_script("const x =\nfoo; bar\n[0];");
    assert!(matches!(
        &trailing_expression.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Member { computed: true, .. },
                ..
            })
        ]
    ));

    let balanced_trailing_expression = parse_script("const x =\nfoo; bar(\n2\n)\n+ 3;");
    assert!(matches!(
        &balanced_trailing_expression.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Binary {
                    operator: BinaryOperator::Add,
                    left,
                    ..
                },
                ..
            })
        ] if matches!(left.as_ref(), Expression::Call { .. })
    ));

    let trailing_control = parse_script("const x =\nfoo; if (true)\nbar;");
    assert!(matches!(
        &trailing_control.body[..],
        [
            Statement::VariableDeclaration(_),
            Statement::If(IfStatement { consequent, .. })
        ] if matches!(consequent.as_ref(), Statement::Expression(_))
    ));

    let balanced_initializer = parse_script("let a = 1,\nb = (\n2\n)\n+ 3;");
    assert!(
        matches!(
            &balanced_initializer.body[..],
            [Statement::VariableDeclaration(VariableDeclaration {
                declarations,
                ..
            })] if declarations.len() == 2
                && matches!(declarations[1].initializer.as_ref(), Some(Expression::Binary {
                    operator: BinaryOperator::Add,
                    ..
                }))
        ),
        "unexpected balanced initializer AST: {:?}",
        balanced_initializer.body
    );

    let comment_initializer = parse_script(
        "let a = 1,\n\
         b = foo /*\n\
         , */\n\
         .baz\n\
         + bar;",
    );
    assert!(matches!(
        &comment_initializer.body[..],
        [Statement::VariableDeclaration(VariableDeclaration {
            declarations,
            ..
        })] if declarations.len() == 2
            && matches!(declarations[1].initializer.as_ref(), Some(Expression::Binary {
                operator: BinaryOperator::Add,
                left,
                ..
            }) if matches!(left.as_ref(), Expression::Member { .. }))
    ));

    let later_initializer = parse_script("const a = 1,\nb = true\n?\n2\n:\n3;");
    assert!(matches!(
        &later_initializer.body[..],
        [Statement::VariableDeclaration(VariableDeclaration {
            declarations,
            ..
        })] if declarations.len() == 2
            && matches!(declarations[1].initializer.as_ref(), Some(Expression::Conditional { .. }))
    ));

    let mut long_conditional = String::from("const x = true\n?\n");
    long_conditional.push_str(&"/* trivia-only physical line */\n".repeat(256));
    long_conditional.push_str("1\n:\n2;");
    assert_eq!(merge_logical_lines(&long_conditional).len(), 1);
    let long_conditional = parse_script(&long_conditional);
    assert!(matches!(
        &long_conditional.body[..],
        [Statement::VariableDeclaration(VariableDeclaration {
            declarations,
            ..
        })] if matches!(declarations[0].initializer.as_ref(), Some(Expression::Conditional { .. }))
    ));

    let declaration_asi = parse_script("let x\n[1]; var y\n+1; const z = foo\n[0];");
    assert!(
        matches!(
            &declaration_asi.body[..],
            [
            Statement::VariableDeclaration(VariableDeclaration {
                declarations: first,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                declarations: second,
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Raw(raw),
                ..
            }),
                Statement::VariableDeclaration(VariableDeclaration {
                    declarations: third,
                    ..
                })
            ] if first[0].initializer.is_none()
                && second[0].initializer.is_none()
                && raw == "+1"
                && matches!(third[0].initializer.as_ref(), Some(Expression::Member { .. }))
        ),
        "unexpected declaration ASI AST: {:?}",
        declaration_asi.body
    );

    let let_expressions = parse_script("let\n+1; let\n(foo); let\n?.x;");
    assert!(matches!(
        &let_expressions.body[..],
        [
            Statement::Expression(ExpressionStatement {
                expression: Expression::Binary {
                    operator: BinaryOperator::Add,
                    ..
                },
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Call { .. },
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::OptionalMember { .. },
                ..
            })
        ]
    ));

    let restricted_labels = parse_script("break done\n[0]; continue next\n[1];");
    assert!(matches!(
        &restricted_labels.body[..],
        [
            Statement::Break(BreakStatement {
                label: Some(first),
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            }),
            Statement::Continue(ContinueStatement {
                label: Some(second),
                ..
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrayLiteral(_),
                ..
            })
        ] if first == "done" && second == "next"
    ));
}

#[test]
fn call_expression_no_args() {
    let tree = parse_script("foo()");
    match first_expr(&tree) {
        Expression::Call { callee, arguments } => {
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
        Expression::Call { callee, arguments } => {
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
        } => {
            assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "arr"));
            assert!(matches!(property.as_ref(), Expression::NumericLiteral(0)));
            assert!(computed);
        }
        other => panic!("expected Member, got {other:?}"),
    }
}

#[test]
fn this_expression() {
    let tree = parse_script("this");
    assert!(matches!(first_expr(&tree), Expression::This));
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
        } => {
            assert!(!computed);
            assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "c"));
            match object.as_ref() {
                Expression::Member {
                    object: inner_obj,
                    property: inner_prop,
                    computed: inner_computed,
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
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(err.message.contains("binding name"));
}

#[test]
fn anonymous_generator_function_statement_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("function* () { yield 1 }", ParseGoal::Script)
        .expect_err("anonymous generator statement must fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
fn merge_logical_lines_preserves_string_line_continuations_bd_4d60a() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "var {'a\\\nb': value} = source;",
        "var {'a\\\r\nb': value} = source;",
    ] {
        let lines = merge_logical_lines(source);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains('\\'));
        parser
            .parse(source, ParseGoal::Script)
            .expect("string token cooking should consume the preserved continuation");
    }

    let lines = merge_logical_lines("var {'a\nb': value} = source;");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.contains("'a\nb'"));
}

#[test]
fn merge_logical_lines_preserves_template_line_continuation_bd_h4esx() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "let value = `a\\\nb`;",
        "let value = `a\\\r\nb`;",
        "let value = `a\\\rb`;",
        "let value = `a\\\u{2028}b`;",
        "let value = `a\\\u{2029}b`;",
    ] {
        let lines = merge_logical_lines(source);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].text.contains('\\'),
            "merge must preserve the escape for literal cooking: {source:?}"
        );
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("template LineContinuations are cooked by the literal parser");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::TemplateLiteral { quasis, .. }) if quasis == &["ab"]
                )
        ));
    }
}

#[test]
fn template_line_continuation_preserves_following_statement_span_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "let t = `a\\\nb`; x;",
        "let t = `a\\\r\nb`; x;",
        "let t = `a\\\rb`; x;",
        "let t = `a\\\u{2028}b`; x;",
        "let t = `a\\\u{2029}b`; x;",
    ] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("a statement after a template continuation must retain its source span");
        let Statement::Expression(expression) = &tree.body[1] else {
            panic!("expected the trailing identifier expression");
        };
        let x_offset = source.rfind('x').expect("the source contains x") as u64;
        assert_eq!(expression.span.start_offset, x_offset);
        assert_eq!(expression.span.end_offset, x_offset + 1);
        assert_eq!(expression.span.start_line, 2);
        assert_eq!(expression.span.start_column, 5);
        assert_eq!(expression.span.end_line, 2);
        assert_eq!(expression.span.end_column, 6);
    }
}

#[test]
fn template_text_normalizes_cr_and_crlf_to_lf_bd_rcnxf() {
    let parser = CanonicalEs2020Parser;
    for source in ["let value = `a\rb`;", "let value = `a\r\nb`;"] {
        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("template source text accepts every ECMAScript LineTerminator");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::TemplateLiteral { quasis, .. }) if quasis == &["a\nb"]
                )
        ));
    }
}

#[test]
fn merge_logical_lines_block() {
    // A block spanning multiple lines should be merged into one logical line.
    let lines = merge_logical_lines("if (x) {\n  y;\n}");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.contains("if (x) {"));
    assert!(
        lines[0].text.contains('\n'),
        "balanced logical lines must retain LineTerminator provenance"
    );
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
fn parse_script_with_regex_brace_before_block_keeps_two_statements() {
    let tree = parse_script("var r = /{/;\nif (x) {\n  y;\n}");
    assert_eq!(tree.body.len(), 2);
}

// -----------------------------------------------------------------------
// extract_balanced helper (PearlTower 2026-03-02)
// -----------------------------------------------------------------------

#[test]
fn extract_balanced_simple_parens() {
    let (inner, rest) = extract_balanced("(abc)def", '(', ')').unwrap();
    assert_eq!(inner, "abc");
    assert_eq!(rest, "def");
}

#[test]
fn extract_balanced_nested() {
    let (inner, rest) = extract_balanced("((a))", '(', ')').unwrap();
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
fn sequence_operands_keep_generator_suspensions_in_the_caller() {
    let tree = parse_script("function* items() { yield, 1; return yield 2, 3; }");
    let Statement::FunctionDeclaration(function) = &tree.body[0] else {
        panic!("expected a generator declaration");
    };
    let Statement::Expression(statement) = &function.body.body[0] else {
        panic!("expected a bare sequence statement");
    };
    let Expression::Call { arguments, .. } = &statement.expression else {
        panic!("expected a sequence carrying its operands as caller arguments");
    };
    assert!(matches!(
        arguments.as_slice(),
        [
            Expression::Yield {
                argument: None,
                delegate: false
            },
            Expression::NumericLiteral(1)
        ]
    ));

    let Statement::Return(statement) = &function.body.body[1] else {
        panic!("expected a return sequence");
    };
    let Some(Expression::Call { arguments, .. }) = &statement.argument else {
        panic!("expected return operands in the generator scope");
    };
    assert!(matches!(
        arguments.as_slice(),
        [Expression::Yield { argument: Some(argument), delegate: false }, Expression::NumericLiteral(3)]
            if matches!(argument.as_ref(), Expression::NumericLiteral(2))
    ));
}

#[test]
fn sequence_scanning_keeps_async_regex_template_and_arrow_boundaries() {
    let tree = parse_script(
        r#"async function work() {
            return await /[,]/.test(","), /* comma, trivia */ `x${1, 2}`,
                async (first, second) => first + second;
        }"#,
    );
    let Statement::FunctionDeclaration(function) = &tree.body[0] else {
        panic!("expected an async function declaration");
    };
    let Statement::Return(statement) = &function.body.body[0] else {
        panic!("expected a return statement");
    };
    let Some(Expression::Call { arguments, .. }) = &statement.argument else {
        panic!("expected a three-operand sequence");
    };
    assert_eq!(arguments.len(), 3);
    assert!(matches!(
        &arguments[0],
        Expression::Await(argument) if matches!(argument.as_ref(), Expression::Call { .. })
    ));
    assert!(matches!(
        &arguments[1],
        Expression::TemplateLiteral { expressions, .. }
            if matches!(expressions.as_slice(), [Expression::Call { arguments, .. }]
                if matches!(arguments.as_slice(), [Expression::NumericLiteral(1), Expression::NumericLiteral(2)]))
    ));
    assert!(matches!(
        &arguments[2],
        Expression::ArrowFunction { params, is_async: true, .. } if params.len() == 2
    ));

    let sloppy_tree = parse_script("var yield = 8; var await = 12; yield / 2, await / 3;");
    let Statement::Expression(statement) = &sloppy_tree.body[2] else {
        panic!("expected sloppy identifier divisions in a sequence");
    };
    assert!(matches!(
        &statement.expression,
        Expression::Call { arguments, .. }
            if matches!(arguments.as_slice(),
                [Expression::Binary { operator: BinaryOperator::Divide, .. },
                 Expression::Binary { operator: BinaryOperator::Divide, .. }])
    ));
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

// -----------------------------------------------------------------------
// Labelled statements (§14.13) — bd-t9n3s
// -----------------------------------------------------------------------

#[test]
fn parse_labeled_loop_preserves_break_label_bd_t9n3s() {
    let tree = parse_script("outer: while (false) { break outer; }");
    let Statement::Labeled(labeled) = &tree.body[0] else {
        panic!("expected labeled statement, got {:?}", tree.body[0]);
    };
    assert_eq!(labeled.label, "outer");
    let Statement::While(while_statement) = labeled.body.as_ref() else {
        panic!("expected labeled while statement");
    };
    let Statement::Block(block) = while_statement.body.as_ref() else {
        panic!("expected while block body");
    };
    let Statement::Break(break_statement) = &block.body[0] else {
        panic!("expected break statement, got {:?}", block.body[0]);
    };
    assert_eq!(break_statement.label.as_deref(), Some("outer"));
}

#[test]
fn nested_labels_wrap_for_of_and_preserve_continue_label_bd_t9n3s() {
    let tree = parse_script("outer: inner: for (const value of values) { continue outer; }");
    let Statement::Labeled(outer) = &tree.body[0] else {
        panic!("expected outer labeled statement");
    };
    let Statement::Labeled(inner) = outer.body.as_ref() else {
        panic!("expected inner labeled statement");
    };
    let Statement::ForOf(for_of) = inner.body.as_ref() else {
        panic!("expected labeled for-of statement");
    };
    let Statement::Block(block) = for_of.body.as_ref() else {
        panic!("expected for-of block body");
    };
    let Statement::Continue(continue_statement) = &block.body[0] else {
        panic!("expected continue statement");
    };
    assert_eq!(outer.label, "outer");
    assert_eq!(inner.label, "inner");
    assert_eq!(continue_statement.label.as_deref(), Some("outer"));
}

#[test]
fn labeled_compound_statement_splits_before_following_statement_bd_t9n3s() {
    let source = "outer: for (;;) { break outer; } tail;";
    let segments = split_statement_segments(source);
    assert_eq!(segments.len(), 2, "segments: {segments:?}");
    assert_eq!(segments[0].2, "outer: for (;;) { break outer; }");
    assert_eq!(segments[1].2, "tail");

    let tree = parse_script(source);
    assert_eq!(tree.body.len(), 2);
    assert!(matches!(tree.body[0], Statement::Labeled(_)));
    assert!(matches!(tree.body[1], Statement::Expression(_)));
}

#[test]
fn conditional_expression_is_not_a_labeled_statement_bd_t9n3s() {
    let tree = parse_script("flag ? left : right;");
    assert!(matches!(tree.body[0], Statement::Expression(_)));
}

#[test]
fn labelled_jumps_canonicalize_escaped_and_unicode_identifiers_bd_t9n3s() {
    let escaped = parse_script(r"outer: while (false) { break \u006futer; }");
    let Statement::Labeled(escaped_label) = &escaped.body[0] else {
        panic!("expected escaped-label statement");
    };
    let Statement::While(escaped_loop) = escaped_label.body.as_ref() else {
        panic!("expected escaped-label loop");
    };
    let Statement::Block(escaped_body) = escaped_loop.body.as_ref() else {
        panic!("expected escaped-label loop body");
    };
    let Statement::Break(escaped_break) = &escaped_body.body[0] else {
        panic!("expected escaped break");
    };
    assert_eq!(escaped_break.label.as_deref(), Some("outer"));

    let unicode = parse_script("π: while (false) { continue π; }");
    let Statement::Labeled(unicode_label) = &unicode.body[0] else {
        panic!("expected Unicode-label statement");
    };
    let Statement::While(unicode_loop) = unicode_label.body.as_ref() else {
        panic!("expected Unicode-label loop");
    };
    let Statement::Block(unicode_body) = unicode_loop.body.as_ref() else {
        panic!("expected Unicode-label loop body");
    };
    let Statement::Continue(unicode_continue) = &unicode_body.body[0] else {
        panic!("expected Unicode continue");
    };
    assert_eq!(unicode_label.label, "π");
    assert_eq!(unicode_continue.label.as_deref(), Some("π"));
}

#[test]
fn invalid_nonempty_jump_label_is_not_silently_unlabelled_bd_t9n3s() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "outer: while (false) { break for; }",
        "outer: while (false) { continue outer extra; }",
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("invalid nonempty jump label must fail");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
        assert!(error.message.contains("IdentifierReference"), "{source}");
    }
}

#[test]
fn reserved_or_contextual_label_is_rejected_bd_t9n3s() {
    let parser = CanonicalEs2020Parser;
    for (source, goal) in [
        ("for: value;", ParseGoal::Script),
        ("\"use strict\"; let: value;", ParseGoal::Script),
        ("await: value;", ParseGoal::Module),
    ] {
        let error = parser
            .parse(source, goal)
            .expect_err("invalid contextual label must fail");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
        assert!(error.message.contains("IdentifierReference"), "{source}");
    }
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
            assert!(s.pre_loop_initializer.is_none());
        }
        other => panic!("expected ForIn, got {other:?}"),
    }
}

#[test]
fn legacy_var_for_in_initializer_has_distinct_ast_bd_1tafi() {
    let tree = parse_script("for (var value = init() in object) {}");
    let Statement::ForIn(stmt) = &tree.body[0] else {
        panic!("expected legacy var ForIn, got {:?}", tree.body[0]);
    };
    assert_eq!(stmt.binding, BindingPattern::Identifier("value".into()));
    assert_eq!(stmt.binding_kind, Some(VariableDeclarationKind::Var));
    let Some(Expression::Call { callee, arguments }) = &stmt.pre_loop_initializer else {
        panic!(
            "expected distinct call initializer, got {:?}",
            stmt.pre_loop_initializer
        );
    };
    assert_eq!(callee.as_ref(), &Expression::Identifier("init".into()));
    assert!(arguments.is_empty());
    assert_eq!(stmt.object, Expression::Identifier("object".into()));

    let trivia_tree = parse_script(
        "for (var/* head */\u{FEFF}value/* name */=/* eq */init()/* init */in object) {}",
    );
    let Statement::ForIn(trivia_stmt) = &trivia_tree.body[0] else {
        panic!("expected trivia-separated legacy var ForIn");
    };
    assert_eq!(trivia_stmt.binding, stmt.binding);
    assert_eq!(trivia_stmt.pre_loop_initializer, stmt.pre_loop_initializer);
    assert_eq!(trivia_stmt.object, stmt.object);

    let candidate_tree = parse_script("for (var value = seed() in lhs() in rhs()) {}");
    let Statement::ForIn(candidate_stmt) = &candidate_tree.body[0] else {
        panic!("expected first viable top-level `in` to form a ForIn head");
    };
    assert!(matches!(
        &candidate_stmt.pre_loop_initializer,
        Some(Expression::Call { callee, arguments })
            if arguments.is_empty()
                && callee.as_ref() == &Expression::Identifier("seed".into())
    ));
    assert!(matches!(
        &candidate_stmt.object,
        Expression::Binary {
            operator: BinaryOperator::In,
            left,
            right,
        } if matches!(left.as_ref(), Expression::Call { callee, arguments }
            if arguments.is_empty()
                && callee.as_ref() == &Expression::Identifier("lhs".into()))
            && matches!(right.as_ref(), Expression::Call { callee, arguments }
                if arguments.is_empty()
                    && callee.as_ref() == &Expression::Identifier("rhs".into()))
    ));
}

#[test]
fn legacy_var_for_in_initializer_rejects_non_annex_b_heads_bd_1tafi() {
    let parser = CanonicalEs2020Parser;
    for source in [
        "'use strict'; for (var value = 1 in object) {}",
        "for (var value = 1 of values) {}",
        "for (let value = 1 in object) {}",
        "for (const value = 1 in object) {}",
        "for (value = 1 in object) {}",
        "for (var [value] = [1] in object) {}",
        "for (var {value} = source in object) {}",
        "for (var value = 1, other in object) {}",
        "for (var value = 1, in object) {}",
        "for (var value = ; in object) {}",
        "for (var value = @ in object) {}",
    ] {
        assert!(
            parser.parse(source, ParseGoal::Script).is_err(),
            "non-Annex-B loop head must be rejected: {source}"
        );
    }
    assert!(
        parser
            .parse("for (var value = 1 in object) {}", ParseGoal::Module,)
            .is_err(),
        "module code is strict and must reject the Annex-B extension"
    );
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
fn postfix_chain_binds_to_new_result_bd_7rj0t() {
    let member = parse_script("new Foo(1).bar");
    assert!(matches!(
        first_expr(&member),
        Expression::Member {
            object,
            property,
            computed: false,
        } if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
            && matches!(property.as_ref(), Expression::Identifier(name) if name == "bar")
    ));

    let method = parse_script("new Foo(1).bar()");
    assert!(matches!(
        first_expr(&method),
        Expression::Call { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                    if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1))
    ));

    let computed = parse_script("new Foo(1)[0]");
    assert!(matches!(
        first_expr(&computed),
        Expression::Member {
            object,
            property,
            computed: true,
        } if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
            && matches!(property.as_ref(), Expression::NumericLiteral(0))
    ));

    let called_result = parse_script("new Foo(1)()");
    assert!(matches!(
        first_expr(&called_result),
        Expression::Call { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
    ));
}

#[test]
fn new_result_regrouping_preserves_existing_forms_bd_7rj0t() {
    assert!(matches!(
        first_expr(&parse_script("(new Foo()).bar")),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
    ));
    assert!(matches!(
        first_expr(&parse_script("new (factory())(1)")),
        Expression::New { callee, arguments }
            if arguments.len() == 1 && matches!(callee.as_ref(), Expression::Call { .. })
    ));
    assert!(matches!(
        first_expr(&parse_script("new (factory())(1).value")),
        Expression::Member { object, computed: false, .. }
            if matches!(object.as_ref(), Expression::New { callee, arguments }
                if arguments.len() == 1 && matches!(callee.as_ref(), Expression::Call { .. }))
    ));
    assert!(matches!(
        first_expr(&parse_script("new (factory()).value")),
        Expression::New { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                    if matches!(object.as_ref(), Expression::Call { .. }))
    ));
    assert!(matches!(
        first_expr(&parse_script("new Foo()?.value")),
        Expression::OptionalMember { object, computed: false, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
    ));
    assert!(matches!(
        first_expr(&parse_script("new Foo()?.[0]")),
        Expression::OptionalMember { object, computed: true, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
    ));
    assert!(matches!(
        first_expr(&parse_script("new Foo()?.()")),
        Expression::OptionalCall { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
    ));
    assert!(matches!(
        first_expr(&parse_script("new new Foo().value")),
        Expression::New { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::Member { object, .. }
                    if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty()))
    ));
    assert!(matches!(
        first_expr(&parse_script("new new Foo()(1).value")),
        Expression::Member { object, computed: false, .. }
            if matches!(object.as_ref(), Expression::New { callee, arguments }
                if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                    && matches!(callee.as_ref(), Expression::New { arguments, .. }
                        if arguments.is_empty()))
    ));
    assert!(matches!(
        first_expr(&parse_script("new new (Foo)(1).value")),
        Expression::New { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                    if matches!(object.as_ref(), Expression::New { callee, arguments }
                        if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                            && matches!(callee.as_ref(), Expression::Identifier(name) if name == "Foo")))
    ));
    assert!(matches!(
        first_expr(&parse_script("new new (factory())(1).value")),
        Expression::New { callee, arguments }
            if arguments.is_empty()
                && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                    if matches!(object.as_ref(), Expression::New { callee, arguments }
                        if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                            && matches!(callee.as_ref(), Expression::Call { .. })))
    ));

    let invalid_optional_constructor = CanonicalEs2020Parser
        .parse("new Foo?.()", ParseGoal::Script)
        .expect_err("optional chaining in constructor position must fail");
    assert_eq!(
        invalid_optional_constructor.code,
        ParseErrorCode::UnsupportedSyntax
    );
    assert_eq!(
        invalid_optional_constructor.message,
        "optional chaining cannot be used in constructor position"
    );
}

#[test]
fn new_result_regrouping_ignores_argument_delimiters_bd_7rj0t() {
    assert!(matches!(
        first_expr(&parse_script("new Foo(\")\").value")),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. }
                if matches!(arguments.as_slice(), [Expression::StringLiteral(value)] if value == ")"))
    ));
    assert!(matches!(
        first_expr(&parse_script(r"new Foo(/\)/).value")),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. }
                if matches!(arguments.as_slice(), [Expression::RegExpLiteral { pattern, .. }] if pattern == r"\)"))
    ));
    assert!(matches!(
        first_expr(&parse_script(r"new Foo(`${`)`}`).value")),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. }
                if matches!(arguments.as_slice(), [Expression::TemplateLiteral { expressions, .. }]
                    if expressions.len() == 1))
    ));
    assert!(matches!(
        first_expr(&parse_script(
            r"new Foo(function(){ return /\)/; }).value"
        )),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. }
                if matches!(arguments.as_slice(), [Expression::Function { .. }]))
    ));
    assert!(matches!(
        first_expr(&parse_script(
            r"new Foo(function(){ let x=1; /\)/.test(x); }).value"
        )),
        Expression::Member { object, .. }
            if matches!(object.as_ref(), Expression::New { arguments, .. }
                if matches!(arguments.as_slice(), [Expression::Function { .. }]))
    ));
    assert!(matches!(
        first_expr(&parse_script("new Foo() /* gap */ .value")),
        Expression::Member { object, property, computed: false }
            if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
                && matches!(property.as_ref(), Expression::Identifier(name) if name == "value")
    ));
}

#[test]
fn new_in_variable_decl() {
    let tree = parse_script("const m = new Map()");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            let init = decl.declarations[0].initializer.as_ref().unwrap();
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
            let init = decl.declarations[0].initializer.as_ref().unwrap();
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
            let init = decl.declarations[0].initializer.as_ref().unwrap();
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
            let init = decl.declarations[0].initializer.as_ref().unwrap();
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
            let init = decl.declarations[0].initializer.as_ref().unwrap();
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
fn tagged_template_expression_is_rejected_as_unsupported() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("render`hello ${name}`", ParseGoal::Script)
        .expect_err("tagged template expressions should be rejected");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(
        err.message.contains("tagged template"),
        "error message should mention tagged templates: {}",
        err.message
    );
}

#[test]
fn tagged_template_member_expression_is_rejected_as_unsupported() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("view.render`ok`", ParseGoal::Script)
        .expect_err("tagged template member expressions should be rejected");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert!(
        err.message.contains("tagged template"),
        "error message should mention tagged templates: {}",
        err.message
    );
}

#[test]
fn template_literal_unbalanced_interpolation_is_rejected() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `value: ${name`", ParseGoal::Script)
        .expect_err("unbalanced interpolation should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

// Donor parity for bd-8fzl3 was checked against Node 20.19.4 and Bun
// 1.3.14: both accept the valid sloppy/async/generator/for/control/
// nested-template cases below and reject the malformed delimiter and
// formal-parameter cases. Keep the matrix local to the regressions so a
// future lexical-goal change cannot silently shed its donor evidence.
#[test]
fn template_interpolation_uses_grammar_aware_slash_goals_bd_8fzl3() {
    let tree = parse_script(r#"const value = `${await / 2}:${yield / 3}:${of / 5}:${/[}]/}`;"#);
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected template variable declaration");
    };
    let Some(Expression::TemplateLiteral {
        quasis,
        expressions,
    }) = declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected template initializer");
    };
    assert_eq!(quasis, &["", ":", ":", ":", ""]);
    assert_eq!(expressions.len(), 4);
    for (expression, identifier, divisor) in [
        (&expressions[0], "await", 2),
        (&expressions[1], "yield", 3),
        (&expressions[2], "of", 5),
    ] {
        assert!(matches!(
            expression,
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == identifier)
                && matches!(right.as_ref(), Expression::NumericLiteral(value) if *value == divisor)
        ));
    }
    assert!(matches!(
        &expressions[3],
        Expression::RegExpLiteral { pattern, flags }
            if pattern == "[}]" && flags.is_empty()
    ));

    let chained =
        parse_script(r#"const value = `${await / 2 / /}/}:${yield / 3 / /}/}:${of / 5 / /}/}`;"#);
    let Statement::VariableDeclaration(declaration) = &chained.body[0] else {
        panic!("expected chained template variable declaration");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) =
        declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected chained template initializer");
    };
    assert_eq!(expressions.len(), 3);
    for expression in expressions {
        assert!(matches!(
            expression,
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Binary {
                operator: BinaryOperator::Divide,
                ..
            }) && matches!(right.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));
    }

    let token_boundaries = parse_script(
        r#"const value = `${π / 2 / /}/}:${\u0061wait / 3 / /}/}:${\u{61}wait / 4 / /}/}:${1. / 2 / /}/}`;"#,
    );
    let Statement::VariableDeclaration(declaration) = &token_boundaries.body[0] else {
        panic!("expected token-boundary template declaration");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) =
        declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected token-boundary template initializer");
    };
    assert_eq!(expressions.len(), 4);
    for expression in expressions {
        assert!(matches!(
            expression,
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Binary {
                operator: BinaryOperator::Divide,
                ..
            }) && matches!(right.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));
    }

    let strict_property_names =
        parse_script(r#""use strict"; const value = ({yield: 1, await: 2});"#);
    let Statement::VariableDeclaration(declaration) = &strict_property_names.body[1] else {
        panic!("expected strict object declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::ObjectLiteral(properties)) if properties.len() == 2
    ));

    assert_eq!(
        find_top_level_template_start(
            r#"/`/`tail`"#,
            ScanGrammarContext::SLOPPY_SCRIPT.expression(),
        ),
        Some(3),
        "a backtick inside a RegExp literal is not a template opener",
    );
    let regexp_backtick = parse_script(r#"const value = `${/`/.test("`")}`;"#);
    let Statement::VariableDeclaration(declaration) = &regexp_backtick.body[0] else {
        panic!("expected RegExp-backtick template declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::TemplateLiteral { expressions, .. })
            if matches!(&expressions[..], [Expression::Call { .. }])
    ));
}

#[test]
fn binding_patterns_preserve_async_and_generator_slash_context_bd_8fzl3() {
    let async_tree = parse_script(
        r#"async function f(source) {
            const { [await /=/]: eq, [await /]/]: close, value = await /:/ } = source;
            const [item = await /}/,] = source;
        }"#,
    );
    assert!(matches!(
        &async_tree.body[..],
        [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
    ));

    let generator_tree = parse_script(
        r#"function* g(source) {
            const { [yield /=/]: eq, [yield /]/]: close, value = yield /:/ } = source;
            const [item = yield /}/,] = source;
        }"#,
    );
    assert!(matches!(
        &generator_tree.body[..],
        [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
    ));
}

#[test]
fn postfix_arguments_and_constructors_preserve_slash_context_bd_8fzl3() {
    let async_tree = parse_script(
        r#"async function f(C, g) {
            const call = g(await /}/);
            const construct = new C(await /}/);
            const member = (await /}/).test("}");
            const computed = (await /}/)[0];
        }"#,
    );
    let [Statement::FunctionDeclaration(function)] = &async_tree.body[..] else {
        panic!("expected async function declaration");
    };
    let [
        Statement::VariableDeclaration(call),
        Statement::VariableDeclaration(construct),
        Statement::VariableDeclaration(member),
        Statement::VariableDeclaration(computed),
    ] = &function.body.body[..]
    else {
        panic!("expected four async-context declarations");
    };
    assert!(matches!(
        call.declarations[0].initializer.as_ref(),
        Some(Expression::Call { arguments, .. })
            if matches!(&arguments[..], [Expression::Await(argument)]
                if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
    ));
    assert!(matches!(
        construct.declarations[0].initializer.as_ref(),
        Some(Expression::New { arguments, .. })
            if matches!(&arguments[..], [Expression::Await(argument)]
                if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
    ));
    assert!(matches!(
        member.declarations[0].initializer.as_ref(),
        Some(Expression::Call { callee, .. })
            if matches!(callee.as_ref(), Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::Await(_)))
    ));
    assert!(matches!(
        computed.declarations[0].initializer.as_ref(),
        Some(Expression::Member { object, computed: true, .. })
            if matches!(object.as_ref(), Expression::Await(_))
    ));

    let generator_tree = parse_script(
        r#"function* g(C, f) {
            const call = f(yield /}/);
            const construct = new C(yield /}/);
        }"#,
    );
    let [Statement::FunctionDeclaration(function)] = &generator_tree.body[..] else {
        panic!("expected generator function declaration");
    };
    for statement in &function.body.body {
        let Statement::VariableDeclaration(declaration) = statement else {
            panic!("expected generator-context declaration");
        };
        let expression = declaration.declarations[0]
            .initializer
            .as_ref()
            .expect("expected initializer");
        let arguments = match expression {
            Expression::Call { arguments, .. } | Expression::New { arguments, .. } => arguments,
            other => panic!("expected call or constructor, got {other:?}"),
        };
        assert!(matches!(
            &arguments[..],
            [Expression::Yield {
                argument: Some(argument),
                delegate: false,
            }] if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));
    }
}

#[test]
fn logical_line_continuations_preserve_slash_context_bd_8fzl3() {
    for source in [
        "async function f() { const value =\nawait /}/;\nif (\nawait /[)}]/\n) /}/; }",
        "function* g() { const value =\nyield /}/;\nif (\nyield /[)}]/\n) /}/; }",
    ] {
        let tree = parse_script(source);
        assert!(matches!(
            &tree.body[..],
            [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
        ));
    }
}

#[test]
fn template_interpolation_scopes_async_generator_and_nested_functions_bd_8fzl3() {
    let async_tree = parse_script(
        r#"async function outer() {
            function normal(await) { return `${await / 2}:${/[}]/}`; }
            return `${await /[}]/}`;
        }"#,
    );
    let Statement::FunctionDeclaration(async_outer) = &async_tree.body[0] else {
        panic!("expected async function declaration");
    };
    let Statement::FunctionDeclaration(normal) = &async_outer.body.body[0] else {
        panic!("expected nested ordinary function");
    };
    let Statement::Return(normal_return) = &normal.body.body[0] else {
        panic!("expected nested return statement");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &normal_return.argument else {
        panic!("expected nested template return");
    };
    assert!(matches!(
        &expressions[0],
        Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await")
    ));
    assert!(matches!(&expressions[1], Expression::RegExpLiteral { .. }));

    let Statement::Return(async_return) = &async_outer.body.body[1] else {
        panic!("expected async return statement");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &async_return.argument else {
        panic!("expected async template return");
    };
    assert!(matches!(
        &expressions[0],
        Expression::Await(inner)
            if matches!(inner.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "[}]")
    ));

    let generator_tree = parse_script(
        r#"function* outer() {
            function normal(yield) { return `${yield / 3}:${/[}]/}`; }
            return `${yield /[}]/}`;
        }"#,
    );
    let Statement::FunctionDeclaration(generator_outer) = &generator_tree.body[0] else {
        panic!("expected generator function declaration");
    };
    let Statement::FunctionDeclaration(normal) = &generator_outer.body.body[0] else {
        panic!("expected nested ordinary function");
    };
    let Statement::Return(normal_return) = &normal.body.body[0] else {
        panic!("expected nested generator-context reset return");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &normal_return.argument else {
        panic!("expected nested generator-context reset template");
    };
    assert!(matches!(
        &expressions[0],
        Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "yield")
    ));

    let Statement::Return(generator_return) = &generator_outer.body.body[1] else {
        panic!("expected generator return statement");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &generator_return.argument else {
        panic!("expected generator template return");
    };
    assert!(matches!(
        &expressions[0],
        Expression::Yield {
            argument: Some(argument),
            delegate: false,
        } if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "[}]")
    ));
}

#[test]
fn template_interpolation_scopes_arrow_and_class_method_bodies_bd_8fzl3() {
    let async_arrow = parse_script(r#"const value = `${async(x) => await /}/}`;"#);
    let Statement::VariableDeclaration(declaration) = &async_arrow.body[0] else {
        panic!("expected async-arrow declaration");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) =
        declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected async-arrow template");
    };
    assert!(matches!(
        &expressions[0],
        Expression::ArrowFunction {
            is_async: true,
            body: ArrowBody::Expression(body),
            ..
        } if matches!(body.as_ref(), Expression::Await(argument)
            if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
    ));

    let nested_arrow = parse_script(
        r#"async function outer() {
            return `${true ? () => await / 2 : await /}/}`;
        }"#,
    );
    let Statement::FunctionDeclaration(outer) = &nested_arrow.body[0] else {
        panic!("expected async outer function");
    };
    let Statement::Return(return_statement) = &outer.body.body[0] else {
        panic!("expected async outer return");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &return_statement.argument else {
        panic!("expected nested-arrow template");
    };
    let Expression::Conditional {
        consequent,
        alternate,
        ..
    } = &expressions[0]
    else {
        panic!("expected conditional containing an ordinary arrow");
    };
    assert!(matches!(
        consequent.as_ref(),
        Expression::ArrowFunction {
            is_async: false,
            body: ArrowBody::Expression(body),
            ..
        } if matches!(body.as_ref(), Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await"))
    ));
    assert!(matches!(
        alternate.as_ref(),
        Expression::Await(argument)
            if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
    ));

    let class_method = parse_script(
        r#"async function outer() {
            class C { method() { return `${await / 2}`; } }
        }"#,
    );
    let Statement::FunctionDeclaration(outer) = &class_method.body[0] else {
        panic!("expected async outer function around class");
    };
    let Statement::ClassDeclaration(class) = &outer.body.body[0] else {
        panic!("expected nested class declaration");
    };
    let Statement::Return(return_statement) = &class.body[0].body.body[0] else {
        panic!("expected class-method return");
    };
    let Some(Expression::TemplateLiteral { expressions, .. }) = &return_statement.argument else {
        panic!("expected class-method template");
    };
    assert!(matches!(
        &expressions[0],
        Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await")
    ));
}

#[test]
fn delimiter_cursor_distinguishes_for_heads_blocks_and_expression_bodies_bd_8fzl3() {
    let for_tree = parse_script("if (false) for (let of of /r/) {}");
    let Statement::If(if_statement) = &for_tree.body[0] else {
        panic!("expected guarding if statement");
    };
    let Statement::ForOf(for_of) = if_statement.consequent.as_ref() else {
        panic!("expected contextual for-of statement");
    };
    assert!(matches!(
        &for_of.binding,
        BindingPattern::Identifier(name) if name == "of"
    ));
    assert!(matches!(
        &for_of.iterable,
        Expression::RegExpLiteral { pattern, .. } if pattern == "r"
    ));

    let destructuring_for = parse_script("if (false) for (let [x] of /}/) {}");
    let Statement::If(if_statement) = &destructuring_for.body[0] else {
        panic!("expected guarding if for destructuring for-of");
    };
    let Statement::ForOf(for_of) = if_statement.consequent.as_ref() else {
        panic!("expected destructuring for-of statement");
    };
    assert!(matches!(
        &for_of.iterable,
        Expression::RegExpLiteral { pattern, .. } if pattern == "}"
    ));

    let if_tree = parse_script("if (true) /}/;");
    let Statement::If(if_statement) = &if_tree.body[0] else {
        panic!("expected if statement");
    };
    assert!(matches!(
        if_statement.consequent.as_ref(),
        Statement::Expression(statement)
            if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
    ));

    let else_tree = parse_script("if (false) 0; else /}/;");
    let Statement::If(if_statement) = &else_tree.body[0] else {
        panic!("expected if/else statement");
    };
    assert!(matches!(
        if_statement.alternate.as_deref(),
        Some(Statement::Expression(statement))
            if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
    ));

    let do_tree = parse_script("do /}/; while (false);");
    let Statement::DoWhile(do_while) = &do_tree.body[0] else {
        panic!("expected do/while statement");
    };
    assert!(matches!(
        do_while.body.as_ref(),
        Statement::Expression(statement)
            if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
    ));

    let block_tree = parse_script("{} /}/;");
    assert_eq!(block_tree.body.len(), 2);
    assert!(matches!(&block_tree.body[0], Statement::Block(_)));
    assert!(matches!(
        &block_tree.body[1],
        Statement::Expression(statement)
            if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
    ));

    for (source, expected_left) in [
        ("({value: 12}) / 3", "object"),
        ("(function(){}) / 2", "function"),
        ("(class{}) / 2", "class"),
    ] {
        let tree = parse_script(source);
        let Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } = first_expr(&tree)
        else {
            panic!("expected division after {expected_left} expression");
        };
        let correct_left = match expected_left {
            "object" => matches!(left.as_ref(), Expression::ObjectLiteral(_)),
            "function" => matches!(left.as_ref(), Expression::Function { .. }),
            "class" => matches!(left.as_ref(), Expression::ClassExpression { .. }),
            _ => false,
        };
        assert!(correct_left, "wrong left operand for {source:?}: {left:?}");
    }
}

#[test]
fn nested_templates_share_the_grammar_aware_delimiter_cursor_bd_8fzl3() {
    let tree = parse_script(r#"const value = `A${`B${of / 3}:${/[}]/}C`}D`;"#);
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected nested-template declaration");
    };
    let Some(Expression::TemplateLiteral {
        quasis,
        expressions,
    }) = declaration.declarations[0].initializer.as_ref()
    else {
        panic!("expected outer template");
    };
    assert_eq!(quasis, &["A", "D"]);
    let [
        Expression::TemplateLiteral {
            quasis: nested_quasis,
            expressions: nested_expressions,
        },
    ] = expressions.as_slice()
    else {
        panic!("expected one nested template expression");
    };
    assert_eq!(nested_quasis, &["B", ":", "C"]);
    assert!(matches!(
        &nested_expressions[0],
        Expression::Binary {
            operator: BinaryOperator::Divide,
            left,
            ..
        } if matches!(left.as_ref(), Expression::Identifier(name) if name == "of")
    ));
    assert!(matches!(
        &nested_expressions[1],
        Expression::RegExpLiteral { pattern, .. } if pattern == "[}]"
    ));

    let multiline = parse_script(
        r#"const value = `A${`B
${/[}]/}C`}D`;"#,
    );
    assert_eq!(multiline.body.len(), 1);
    let Statement::VariableDeclaration(declaration) = &multiline.body[0] else {
        panic!("expected multiline nested-template declaration");
    };
    assert!(matches!(
        declaration.declarations[0].initializer.as_ref(),
        Some(Expression::TemplateLiteral { expressions, .. })
            if matches!(&expressions[0], Expression::TemplateLiteral { expressions, .. }
                if matches!(&expressions[0], Expression::RegExpLiteral { pattern, .. } if pattern == "[}]"))
    ));
}

#[test]
fn malformed_grammar_aware_delimiters_fail_closed_bd_8fzl3() {
    let parser = CanonicalEs2020Parser;
    for source in [
        r#"const value = `${/unterminated}`;"#,
        r#"const value = `${/[}]/.test("}")`;"#,
        r#"const value = `${]}`;"#,
        "const value = `${/unterminated\n/}`;",
        "const value = /x/z;",
        "for (let of /r/) {}",
        "async function bad(await) {}",
        "function* bad(yield) {}",
        "const bad = async (await) => 0;",
        "async function bad({[await /]/]: value}) {}",
        "function* bad({[yield /]/]: value}) {}",
    ] {
        let error = match parser.parse(source, ParseGoal::Script) {
            Ok(tree) => panic!("malformed source parsed as {tree:?}: {source:?}"),
            Err(error) => error,
        };
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
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
                elements[0].as_ref().unwrap(),
                Expression::NumericLiteral(1)
            ));
            match elements[1].as_ref().unwrap() {
                Expression::SpreadElement(inner) => {
                    assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "arr"));
                }
                other => panic!("expected SpreadElement, got {other:?}"),
            }
            assert!(matches!(
                elements[2].as_ref().unwrap(),
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
                elements[0].as_ref().unwrap(),
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
                elements[0].as_ref().unwrap(),
                Expression::SpreadElement(_)
            ));
            assert!(matches!(
                elements[1].as_ref().unwrap(),
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

// Donor parity for bd-ngkuz was checked against Node 20.19.4 and Bun
// 1.3.14: both accept the unique `dgimsuy` combinations and reject the
// duplicate, unsupported, escaped, Unicode, template, and control-head
// cases below. `v` remains outside this parser's existing flag contract
// and is tested separately from that donor matrix.
#[test]
fn regexp_literal_flags_are_complete_and_unique_bd_ngkuz() {
    let parser = CanonicalEs2020Parser;

    for source in [
        "/x/;",
        "/x/g;",
        "/x/dgimsuy;",
        "/x/yusmigd;",
        "/x/g / 2;",
        "/[}]/gi.test(\"}\");",
        "`${/[}]/gi}`;",
        "if (ready) /[)]/gi;",
        "while (false) /[}]/y;",
        "for (; /[;]/g.test(value); ) step();",
    ] {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("valid RegExp flags failed: {source:?}: {error:?}"));
    }

    for flag in ['d', 'g', 'i', 'm', 's', 'u', 'y'] {
        let source = format!("/x/{flag}{flag};");
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("a duplicate RegExp flag must be rejected");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            error.message.contains("duplicate RegExp literal flag"),
            "unexpected duplicate diagnostic: {error:?}"
        );
    }

    for (source, diagnostic) in [
        ("/x/z;", "unsupported RegExp literal flag `z`"),
        ("/x/gz;", "unsupported RegExp literal flag `z`"),
        ("/x/gfoo;", "unsupported RegExp literal flag `f`"),
        ("/x/1;", "unsupported RegExp literal flag `1`"),
        ("/x/$;", "unsupported RegExp literal flag `$`"),
        ("/x/π;", "unsupported RegExp literal flag `π`"),
        (r"/x/\u0067;", "unsupported RegExp literal flag `\\`"),
        (r"/x/\u{67};", "unsupported RegExp literal flag `\\`"),
        (
            "/x/g\u{0301};",
            "unsupported RegExp literal flag `\u{0301}`",
        ),
        (
            "/x/g\u{200c};",
            "unsupported RegExp literal flag `\u{200c}`",
        ),
        ("`${/[}]/gg}`;", "duplicate RegExp literal flag `g`"),
        ("if (ready) /[)]/gg;", "duplicate RegExp literal flag `g`"),
        (
            "while (ready) /[}]/gz;",
            "unsupported RegExp literal flag `z`",
        ),
        (
            "for (; /[;]/gz.test(value); ) step();",
            "unsupported RegExp literal flag `z`",
        ),
    ] {
        let error = parser
            .parse(source, ParseGoal::Script)
            .expect_err("invalid RegExp flags must fail in every expression context");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        assert!(
            error.message.contains(diagnostic),
            "unexpected error for {source:?}: {error:?}"
        );
    }

    let version_extension = parser
        .parse("/x/v;", ParseGoal::Script)
        .expect_err("the post-contract `v` flag must not enter the existing flag set implicitly");
    assert!(
        version_extension
            .message
            .contains("unsupported RegExp literal flag `v`")
    );

    for malformed in [
        "/[abc/gg;",
        "/abc\n/gg;",
        "`${/[}]/gg`;",
        "if (/[(]/gg.test(x)) run();",
    ] {
        let error = parser
            .parse(malformed, ParseGoal::Script)
            .expect_err("malformed RegExp delimiters must remain syntax errors");
        assert_eq!(
            error.code,
            ParseErrorCode::UnsupportedSyntax,
            "{malformed:?}"
        );
    }

    let complete_invalid = parse_regexp_literal_prefix("/x/gz + tail")
        .expect("a malformed flag tail still has a complete lexical extent");
    assert_eq!(complete_invalid.pattern, "x");
    assert_eq!(complete_invalid.flags, "gz");
    assert_eq!(complete_invalid.consumed, "/x/gz".len());
    assert_eq!(
        complete_invalid.flag_error,
        Some(RegExpFlagError::Unsupported('z'))
    );

    let escaped = parse_regexp_literal_prefix(r"/x/\u0067 + tail")
        .expect("an escaped flag spelling must be consumed as one lexical tail");
    assert_eq!(escaped.flags, r"\u0067");
    assert_eq!(escaped.consumed, r"/x/\u0067".len());
    assert_eq!(escaped.flag_error, Some(RegExpFlagError::Unsupported('\\')));

    assert_eq!(
        parse_regexp_literal("/x/yusmigd"),
        Some(("x".to_string(), "yusmigd".to_string()))
    );
    assert_eq!(parse_regexp_literal("/x/gg"), None);
    assert_eq!(parse_regexp_literal("/x/gz"), None);
}

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
    assert_eq!(parse_regexp_literal("/x/.test('x')"), None);
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
fn regexp_literal_canonical_hash_stability() {
    let tree1 = parse_script("/test/gi;");
    let tree2 = parse_script("/test/gi;");
    assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
}
