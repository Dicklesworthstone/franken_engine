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

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::HybridRouter;
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
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
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
    check("class C { static get v() { return 5; } } C.v;", "5");
    check(
        "class C { static make() { return new C(); } hi() { return 'hi'; } } C.make().hi();",
        "hi",
    );
}

#[test]
fn functions_expose_name_and_length() {
    check(
        "function foo(a, b) {} foo.length + ':' + foo.name;",
        "2:foo",
    );
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

// Second slice: own-property reflection on function values. Before it,
// `Object.getOwnPropertyDescriptor(fn, 'length')` was undefined, `delete`,
// `Object.defineProperty` and `Object.defineProperties` on a function threw
// "expected object", `Object.keys` / `getOwnPropertyNames` of a function were
// empty, and built-in functions (`Math.max`, `[].push`, ...) had no `length`
// or `name` at all and refused own properties.

/// The public eval path (built-ins granted), as the other bd-9vouw.17 suites.
fn router_check(source: &str, node: &str) {
    let got = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(got, node, "`{source}` must match Node v22.2.0");
}

/// Console lines of a real `frankenctl run` (for `console.log` formatting).
fn frankenctl_console(source: &str) -> Vec<String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_fnprops17_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    let input = dir.join("program.js");
    let report = dir.join("report.json");
    fs::write(&input, source).expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "fnprops17",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
    report["console_output"]
        .as_array()
        .expect("console")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect()
}

#[test]
fn function_length_and_name_have_standard_descriptors() {
    router_check(
        "function foo(a, b) {} JSON.stringify(Object.getOwnPropertyDescriptor(foo, 'length'));",
        r#"{"value":2,"writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "function foo(a, b) {} JSON.stringify(Object.getOwnPropertyDescriptor(foo, 'name'));",
        r#"{"value":"foo","writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "function f(a, b, c) {} var g = f.bind(null, 1); \
         g.length + ':' + g.name + ':' + JSON.stringify(Object.getOwnPropertyDescriptor(g, 'length'));",
        r#"2:bound f:{"value":2,"writable":false,"enumerable":false,"configurable":true}"#,
    );
}

#[test]
fn function_own_properties_can_be_deleted() {
    // `length` and `name` are configurable; once deleted, the inherited
    // Function.prototype values (0 and "") show through.
    router_check(
        "function foo(a, b) {} var d = delete foo.length; \
         d + ':' + foo.hasOwnProperty('length') + ':' + foo.length;",
        "true:false:0",
    );
    router_check(
        "function foo() {} delete foo.name; JSON.stringify(foo.name) + ':' + foo.hasOwnProperty('name');",
        r#""":false"#,
    );
    router_check(
        "function F() {} F.x = 1; var d = delete F.x; d + ':' + F.x;",
        "true:undefined",
    );
}

#[test]
fn function_own_property_names_and_keys() {
    router_check(
        "'use strict'; function f() {} f.x = 1; Object.getOwnPropertyNames(f).join();",
        "length,name,prototype,x",
    );
    router_check(
        "class C {} C.x = 1; Object.getOwnPropertyNames(C).join();",
        "length,name,prototype,x",
    );
    // Arrow functions have no `prototype`.
    router_check(
        "var f = (a) => a; f.x = 1; Object.getOwnPropertyNames(f).join();",
        "length,name,x",
    );
    router_check(
        "function F() {} F.x = 1; F.y = 2; Object.keys(F).join();",
        "x,y",
    );
}

#[test]
fn define_property_on_functions() {
    router_check(
        "function F() {} Object.defineProperty(F, 'answer', { value: 42 }); \
         F.answer + ':' + Object.keys(F).length + ':' + F.propertyIsEnumerable('answer');",
        "42:0:false",
    );
    router_check(
        "function F() {} Object.defineProperties(F, { a: { value: 1, enumerable: true }, b: { value: 2 } }); \
         Object.keys(F).join() + ':' + F.b;",
        "a:2",
    );
    router_check(
        "function F() {} Object.defineProperty(F, 'name', { value: 'G' }); F.name;",
        "G",
    );
    // Babel >= 7.16 `_createClass` ends with this call.
    router_check(
        "function C() { this.v = 1; } C.prototype.m = function () { return this.v; }; \
         Object.defineProperty(C, 'prototype', { writable: false }); \
         (new C() instanceof C) + ':' + new C().m();",
        "true:1",
    );
    router_check(
        "class A { static name() { return 'm'; } } typeof A.name;",
        "function",
    );
}

#[test]
fn builtin_functions_have_length_and_name() {
    router_check(
        "[Math.max.length, Math.max.name, [].push.length, Array.prototype.slice.name, \
         'x'.padStart.length, Date.prototype.getDay.length, Date.prototype.getDay.name, \
         Object.keys.length, JSON.stringify.length].join();",
        "2,max,1,slice,1,0,getDay,1,3",
    );
    router_check(
        "JSON.stringify(Object.getOwnPropertyDescriptor(Math.max, 'length')) + \
         JSON.stringify(Object.getOwnPropertyDescriptor([].map, 'name'));",
        r#"{"value":2,"writable":false,"enumerable":false,"configurable":true}{"value":"map","writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "Object.getOwnPropertyNames(Math.max).join() + ':' + Math.max.hasOwnProperty('length');",
        "length,name:true",
    );
}

/// `Date` and `Promise` keep their statics on a property object of their own;
/// that object had no `length` or `name`, so `Date.name` was undefined.
#[test]
fn materialized_constructors_have_length_and_name() {
    router_check(
        "const d = Object.getOwnPropertyDescriptor(Date, 'name'); \
         const p = Object.getOwnPropertyDescriptor(Promise, 'length'); \
         [Date.name, Date.length, Promise.name, Promise.length, d.writable, d.enumerable, \
         d.configurable, p.value, p.writable, Object.keys(Date).length, \
         Object.keys(Promise).length, new Promise(() => {}).constructor.name, \
         Promise.resolve(1).constructor === Promise].join(' ');",
        "Date 7 Promise 1 false false true 1 false 0 0 Promise true",
    );
}

#[test]
fn builtin_functions_hold_and_delete_own_properties() {
    router_check(
        "var d = delete Math.min.name; d + ':' + JSON.stringify(Math.min.name) + ':' + Math.min.hasOwnProperty('name');",
        r#"true:"":false"#,
    );
    router_check(
        "Math.abs.tag = 'k'; Math.abs.length = 9; Math.abs.tag + ':' + Math.abs.length + ':' + Math.abs(-3);",
        "k:1:3",
    );
    router_check(
        "Math.round.extra = 1; Object.keys(Math.round).join();",
        "extra",
    );
}

/// A `new Function` body is lowered as its own module, so its `length` and
/// `name` come from that module's function table; they were read from the
/// caller's, which has no entry (or another function's) at that index.
#[test]
fn function_constructor_results_have_their_own_length() {
    router_check(
        "const f = new Function('a', 'b', 'return a + b'); \
         const g = Function('x', 'y', 'z', 'return 1'); const h = new Function('return this'); \
         [f.length, f.name, g.length, h.length, f(2, 3), \
         (new Function('...r', 'return r.length')).length].join();",
        "2,anonymous,3,0,5,0",
    );
}

#[test]
fn inspect_keeps_hiding_non_enumerable_function_properties() {
    assert_eq!(
        frankenctl_console(
            "function F() {} F.x = 1; Object.getOwnPropertyDescriptor(F, 'length'); \
             console.log(F); console.log(Math.max);"
        ),
        vec![
            "[Function: F] { x: 1 }".to_string(),
            "[Function: max]".to_string()
        ],
    );
}
