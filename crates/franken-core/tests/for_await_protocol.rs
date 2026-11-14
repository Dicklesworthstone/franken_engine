//! Shared for-await grammar, labels and AST-only protocol operations.

use frankenengine_core::ast::{Expression, Statement};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser, ParseGoal};
use frankenengine_core::ts_normalization::for_await;
use serde_json::Value;

fn identifiers(value: &Value, result: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(name)) = fields.get("Identifier") {
                result.push(name.clone());
            }
            assert!(
                !fields.contains_key("Raw"),
                "generated syntax must parse completely: {value}"
            );
            for value in fields.values() {
                identifiers(value, result);
            }
        }
        Value::Array(values) => {
            for value in values {
                identifiers(value, result);
            }
        }
        _ => {}
    }
}

#[test]
fn ordinary_shadowed_globals_cannot_replace_the_authenticated_initializers() {
    let tree = CanonicalEs2020Parser.parse(
        "async function consume(Symbol, Reflect, TypeError, Promise, source) { for await (const value of source) {} }",
        ParseGoal::Script,
    ).unwrap();
    let Statement::FunctionDeclaration(function) = &tree.body[0] else {
        panic!("function");
    };
    let Statement::Block(block) = &function.body.body[0] else {
        panic!("lowered loop block");
    };
    for (index, (intrinsic, arity)) in [
        (for_await::CALL_INTRINSIC, 2),
        (for_await::TYPE_ERROR_INTRINSIC, 1),
        (for_await::ASYNC_ITERATOR_INTRINSIC, 0),
        (for_await::ITERATOR_INTRINSIC, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let Statement::VariableDeclaration(declaration) = &block.body[index] else {
            panic!("intrinsic declaration");
        };
        let mut expression = declaration.declarations[0].initializer.as_ref().unwrap();
        if let Expression::Function { body, .. } = expression {
            let Statement::Return(statement) = &body.body[0] else {
                panic!("intrinsic return");
            };
            expression = statement.argument.as_ref().unwrap();
        }
        let Expression::Call { callee, arguments } = expression else {
            panic!("intrinsic call");
        };
        assert!(matches!(callee.as_ref(), Expression::Identifier(name) if name == intrinsic));
        assert_eq!(arguments.len(), arity);
    }
}

#[test]
fn labels_name_the_while_inside_the_cleanup_region() {
    let tree = CanonicalEs2020Parser.parse(
        "outer: inner: for await (const value of source) { if (value) continue outer; break inner; }",
        ParseGoal::Module,
    ).unwrap();
    let Statement::Block(block) = &tree.body[0] else {
        panic!("lowered block");
    };
    let Some(Statement::TryCatch(continuation)) = block.body.last() else {
        panic!("cleanup region");
    };
    let Statement::Labeled(outer) = &continuation.block.body[0] else {
        panic!("outer label");
    };
    assert_eq!(outer.label, "outer");
    let Statement::Labeled(inner) = outer.body.as_ref() else {
        panic!("inner label");
    };
    assert_eq!(inner.label, "inner");
    assert!(matches!(inner.body.as_ref(), Statement::While(_)));
    assert!(continuation.finalizer.is_some());
}

#[test]
fn for_await_requires_an_await_context_and_valid_iteration_grammar() {
    for source in [
        "for await (const value of source) {}",
        "function consume() { for await (const value of source) {} }",
        "async function consume() { function sync() { for await (const value of source) {} } }",
        "async function consume() { for await (const value in source) {} }",
        "async function consume() { for await (;;) {} }",
        "async function consume() { for await (var value = 1 of source) {} }",
        "async function consume() { for await (let x, y of source) {} }",
        "async function consume() { for await (const value of source, other) {} }",
        "async function consume() { for await (x ? y : z of source) {} }",
        "async function consume() { for await (target?.value of source) {} }",
        "async function consume() { for await (const value of source) const x = 1; }",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "{source}"
        );
    }
}

#[test]
fn compact_patterns_nested_loops_and_contextual_async_parse_without_raw_nodes() {
    for source in [
        "for await (const[k,v]of source) {}",
        "for await (let{a:x=1}of source) {}",
        "for await (const of of source) {}",
        "let async; for await (async of source) {}",
        "for await (const value of source) { for await (const inner of value) {} }",
        "async function consume() { for await (var value of source) {} }",
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let mut names = Vec::new();
        identifiers(&serde_json::to_value(tree).unwrap(), &mut names);
        assert!(
            names.iter().any(|name| name == for_await::CALL_INTRINSIC),
            "{source}"
        );
    }
}

#[test]
fn generated_names_avoid_escaped_identifiers_and_template_references() {
    let tree = CanonicalEs2020Parser.parse(
        r#"for await (const value of source) { consume(__franken_fa_0_src, __franken_fa_\u0031_next, `${__franken_fa_2_value}`); }"#,
        ParseGoal::Module,
    ).unwrap();
    let Statement::Block(block) = &tree.body[0] else {
        panic!("lowered block");
    };
    let Statement::VariableDeclaration(declaration) = &block.body[0] else {
        panic!("helper");
    };
    assert_eq!(
        declaration.declarations[0].name(),
        Some("__franken_fa_3_apply")
    );
}

#[test]
fn guest_spelling_cannot_create_an_intrinsic_identifier() {
    // Core may retain unsupported expressions as Raw; neither a rejection nor
    // that representation authorizes the AST-only operation at lowering time.
    for name in [
        for_await::CALL_INTRINSIC,
        for_await::TYPE_ERROR_INTRINSIC,
        for_await::ASYNC_ITERATOR_INTRINSIC,
        for_await::ITERATOR_INTRINSIC,
    ] {
        if let Ok(tree) = CanonicalEs2020Parser.parse(
            format!("{name}(target, receiver);").as_str(),
            ParseGoal::Module,
        ) {
            let encoded = serde_json::to_value(tree).unwrap();
            fn has_private_identifier(value: &Value, name: &str) -> bool {
                match value {
                    Value::Object(fields) => {
                        fields.get("Identifier").and_then(Value::as_str) == Some(name)
                            || fields
                                .values()
                                .any(|value| has_private_identifier(value, name))
                    }
                    Value::Array(values) => values
                        .iter()
                        .any(|value| has_private_identifier(value, name)),
                    _ => false,
                }
            }
            assert!(!has_private_identifier(&encoded, name), "{name}");
        }
    }
}
