//! bd-9vouw.28 (third cluster): generator and async methods in object
//! literals (ES2020 14.4-14.7 MethodDefinition forms).
//!
//! `{ *foo(a) { ... } }` failed to parse ("invalid object shorthand
//! property"): the method parser took `*foo` as the property name. Twelve
//! Node-passing Test262 sample tests use these forms. `async` alone still names
//! an ordinary property or method. Expected strings are what Node v22.2.0
//! prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

/// A method named by a numeric literal (`{ 1(a) {} }`, mobx's error-message
/// table) failed to parse ("invalid object shorthand property"): only
/// identifier and quoted names were methods. The key is ToPropertyKey of
/// the number (`0x10` names "16").
#[test]
fn numeric_literal_method_names() {
    check(
        "var o = { 1(a) { return a + 1; }, 0x10() { return 'hex'; }, 1.5() { return 'f'; }, \
         get 2() { return 'g'; } }; \
         [o[1](1), o[16](), o['1.5'](), o[2], o[1].name, o[16].name, Object.keys(o).join()].join(' ');",
        "2 hex f g 1 16 1,2,16,1.5",
    );
}

#[test]
fn generator_methods() {
    check(
        "var obj = { *foo(a) { yield a + 1; return; } }; var g = obj.foo(3); \
         g.next().value + ':' + g.next().done;",
        "4:true",
    );
    check(
        "var o = { *[Symbol.iterator]() { yield 1; yield 2; } }; [...o].join();",
        "1,2",
    );
}

#[test]
fn async_and_async_generator_methods() {
    check(
        "var o = { async m() { return 7; } }; typeof o.m().then;",
        "function",
    );
    check(
        "var o = { async *g() { yield 1; } }; typeof o.g().next;",
        "function",
    );
}

#[test]
fn async_alone_is_still_a_property_name() {
    check(
        "var o = { async() { return 'named async'; } }; o.async();",
        "named async",
    );
    check("var o = { async: 5 }; o.async;", "5");
}
