#![forbid(unsafe_code)]

//! Unsupported native class elements must not disappear or become bogus
//! methods. TypeScript's supported fields are lowered before reaching here.

use frankenengine_core::ast::{Expression, MethodKind, ParseGoal, Statement};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

#[test]
fn unsupported_fields_and_private_elements_are_rejected_instead_of_dropped() {
    for member in [
        "field;",
        "field = 7;",
        "static field = 7;",
        "field = make();",
        "field = function() { return 7; };",
        "field = () => { return 7; };",
        "field = { method() { return 7; } };",
        "field = class { method() {} };",
        "['field'] = 7;",
        "[key()] = 7;",
        "#field = 7;",
        "#method() { return 7; }",
        "get #field() { return 7; }",
        "static #field = 7;",
        "static { effect(); }",
        "field\nmethod() {}",
        "method() {} field = 7;",
    ] {
        let source = format!("class C {{ {member} }}");
        let error = CanonicalEs2020Parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_err();
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
    }
}

#[test]
fn complete_methods_keep_contextual_names_comments_and_empty_semicolons() {
    let tree = CanonicalEs2020Parser
        .parse(
            r#"class C {
                ; /* empty element */ ;
                // Another empty element.
                ;
                constructor(value) { this.value = value; }
                method(value = /[{};]/) /* body trivia */ { return value; }
                static /* modifier trivia */ named() { return 1; }
                get value() { return 2; }
                set value(value) {}
                get() { return 3; }
                set() { return 4; }
                static /* name trivia */ () { return 5; }
                async /*
                name trivia */ () { return 6; }
                async namedAsync() { return 7; }
                ; /* trailing empty element */ ;
            }"#,
            ParseGoal::Script,
        )
        .expect("complete class methods must retain their boundaries");
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("class declaration expected");
    };
    assert_eq!(class.body.len(), 10);
    assert_eq!(class.body[0].kind, MethodKind::Constructor);
    assert!(class.body[2].is_static);
    assert_eq!(class.body[3].kind, MethodKind::Get);
    assert_eq!(class.body[4].kind, MethodKind::Set);
    for (method, name) in class.body[5..9]
        .iter()
        .zip(["get", "set", "static", "async"])
    {
        assert_eq!(method.kind, MethodKind::Method);
        assert_eq!(method.key, Expression::Identifier(name.into()));
        assert!(!method.is_static);
    }
    assert_eq!(class.body[9].kind, MethodKind::AsyncMethod);
}

#[test]
fn computed_method_keys_keep_calls_and_nested_braces_inside_the_key() {
    let tree = CanonicalEs2020Parser
        .parse(
            r#"class C {
                [key()]() {}
                [({name: 'method'}).name]() {}
                [(function() { return 'method'; })()]() {}
                [(class { method() {} })]() {}
                "name(with parentheses)"() {}
            }"#,
            ParseGoal::Script,
        )
        .expect("computed key expressions must not split their enclosing method");
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("class declaration expected");
    };
    assert_eq!(class.body.len(), 5);
    assert!(class.body[..4].iter().all(|method| method.computed));
    assert_eq!(
        class.body[4].key,
        Expression::StringLiteral("name(with parentheses)".into())
    );
}

#[test]
fn quoted_and_escaped_constructor_names_remain_constructors() {
    for spelling in [
        "constructor",
        "'constructor'",
        r#""constr\u0075ctor""#,
        r"constr\u0075ctor",
    ] {
        let source = format!("class C {{ {spelling}(value) {{ this.value = value; }} }}");
        let tree = CanonicalEs2020Parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        let Statement::ClassDeclaration(class) = &tree.body[0] else {
            panic!("class declaration expected");
        };
        assert_eq!(class.body.len(), 1);
        assert_eq!(class.body[0].kind, MethodKind::Constructor, "{source}");
    }
}

#[test]
fn reserved_words_remain_valid_method_property_names() {
    for name in [
        "yield", "await", "return", "let", "null", "true", "function", "class",
    ] {
        let source =
            format!("class C {{ {name}() {{}} static {name}() {{}} async {name}() {{}} }}");
        let tree = CanonicalEs2020Parser
            .parse(source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        let Statement::ClassDeclaration(class) = &tree.body[0] else {
            panic!("class declaration expected");
        };
        assert_eq!(class.body.len(), 3, "{source}");
        assert_eq!(class.body[0].kind, MethodKind::Method);
        assert!(class.body[1].is_static);
        assert_eq!(class.body[2].kind, MethodKind::AsyncMethod);
        for method in &class.body {
            assert_eq!(method.key, Expression::Identifier(name.into()), "{source}");
        }
    }
}
