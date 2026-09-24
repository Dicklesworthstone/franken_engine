//! bd-9vouw.17 (first slice): functions are objects and hold own properties.
//!
//! Before this change every write of a non-`prototype` property to a user
//! function value (`F.x = 1`, class `static` members, Test262's own
//! `Test262Error.thrower = ...` in harness/sta.js) failed with
//! "type error: expected object, got function", so no harness-based Test262
//! test could run. Expected strings are what Node v22.2.0 prints for the same
//! programs.
//!
//! No mocks: real source through parse -> IR0->IR3 lowering -> QuickJsLane.

use frankenengine_engine::baseline_interpreter::QuickJsLane;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "function_own_properties_bd_9vouw_17.js");
    let context = LoweringContext::new("fop-trace", "fop-decision", "fop-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    match QuickJsLane::new().execute(&module, "fop-trace") {
        Ok(result) => result.value.to_string(),
        Err(err) => format!("ERROR: {err}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(eval_to_string(source), node, "`{source}` must match Node v22.2.0");
}

#[test]
fn declared_function_holds_own_properties() {
    check("function F() {} F.x = 1; F.x;", "1");
    check("function F() {} F.x = 1; F.x = F.x + 41; F.x;", "42");
    check("function F() {} F.missing;", "undefined");
}

#[test]
fn function_expression_and_arrow_hold_own_properties() {
    check("const g = function () {}; g.tag = 'k'; g.tag;", "k");
    check("const h = () => 1; h.meta = 7; h.meta + h();", "8");
}

#[test]
fn distinct_function_objects_have_distinct_properties() {
    // Two closures created from the same function source are distinct objects.
    check(
        "function mk() { return function () {}; } const a = mk(); const b = mk(); a.x = 1; b.x;",
        "undefined",
    );
    check(
        "function mk() { return function () {}; } const a = mk(); const b = mk(); a.x = 1; b.x = 2; a.x;",
        "1",
    );
}

#[test]
fn function_valued_property_is_callable_as_a_method() {
    // The Test262 sta.js shape: a static helper that throws an instance.
    check(
        "function E(m) { this.message = m; } \
         E.thrower = function (m) { throw new E(m); }; \
         let r; try { E.thrower('boom'); } catch (e) { r = (e instanceof E) + ':' + e.message; } r;",
        "true:boom",
    );
}

#[test]
fn class_static_members_install_on_the_constructor() {
    check("class C { static s() { return 3; } } C.s();", "3");
    check(
        "class C { static get v() { return 5; } } C.v;",
        "5",
    );
    check(
        "class C { static make() { return new C(); } hi() { return 'hi'; } } C.make().hi();",
        "hi",
    );
}

#[test]
fn functions_expose_name_and_length() {
    check("function foo(a, b) {} foo.length + ':' + foo.name;", "2:foo");
    check("function rest(a, ...more) {} rest.length;", "1");
    // `name` / `length` are non-writable: a sloppy assignment is ignored.
    check("function F() {} F.length = 5; F.length;", "0");
    check("function F() {} F.name = 'x'; F.name;", "F");
}

#[test]
fn prototype_path_is_unchanged() {
    check(
        "function F() {} F.prototype.m = function () { return 7; }; F.x = 1; new F().m() + F.x;",
        "8",
    );
    // An own property on the function is not visible on instances.
    check("function F() {} F.x = 1; new F().x;", "undefined");
}
