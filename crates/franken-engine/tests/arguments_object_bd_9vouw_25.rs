//! bd-9vouw.25: non-arrow functions have an `arguments` object (ES2020
//! 9.4.4, unmapped form): every actual argument (not just declared
//! parameters), a non-enumerable `length`, and arrows see their enclosing
//! function's object.
//!
//! Before this, every read threw "arguments is not defined", which also
//! stopped the Test262 propertyHelper.js `verifyProperty` (it opens with
//! `assert(arguments.length > 2, ...)`). Expected strings are what Node
//! v22.2.0 prints for the same programs.
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

#[test]
fn arguments_holds_every_actual_argument() {
    check("function f() { return arguments.length; } f(1, 2, 3);", "3");
    check(
        "function f(a) { return arguments[1] + arguments.length; } f(1, 10);",
        "12",
    );
    // Fewer arguments than parameters: length counts actual arguments.
    check("function f(a, b) { return arguments.length; } f(1);", "1");
    check(
        "function f() { return Array.prototype.slice.call(arguments).join('-'); } f('a', 'b');",
        "a-b",
    );
    check("function f() { return typeof arguments; } f();", "object");
}

/// A generator's body runs at its first `next()`, after the call that only
/// created the generator; no call setup staged its arguments object, so
/// the body saw an empty one (Test262 arguments-object/
/// gen-meth-args-trailing-comma-multiple and relatives).
#[test]
fn generator_bodies_see_their_invocation_arguments() {
    check(
        "var o = { *g() { yield arguments.length; yield arguments[1]; } }; \
         var it = o.g(1, 'x',); [it.next().value, it.next().value].join();",
        "2,x",
    );
    check(
        "class C { *m() { yield arguments.length; } static *s() { yield arguments.length; } } \
         [new C().m(1, 2, 3).next().value, C.s(1).next().value].join();",
        "3,1",
    );
    check(
        "function* g2(a) { return arguments.length + ':' + a; } g2(1, 2).next().value;",
        "2:1",
    );
    check(
        "function* g3() { yield 1; yield arguments[0]; } var it3 = g3('late'); it3.next(); \
         it3.next().value;",
        "late",
    );
    check(
        "function* g4(a, ...r) { yield arguments.length + ':' + r.length; } \
         g4(1, 2, 3).next().value;",
        "3:2",
    );
}

#[test]
fn length_is_not_enumerable() {
    check(
        "function f() { var ks = []; for (var k in arguments) ks.push(k); return ks.join(); } \
         f('x', 'y');",
        "0,1",
    );
}

#[test]
fn every_call_path_stages_arguments() {
    check(
        "var o = { m: function () { return arguments.length; } }; o.m(1, 2);",
        "2",
    );
    check(
        "var n = 0; [1].forEach(function () { n = arguments.length; }); n;",
        "3",
    );
    check(
        "function C() { this.n = arguments.length; } new C(1, 2).n;",
        "2",
    );
    check(
        "function f() { return arguments.length; } f.apply(null, [1, 2, 3, 4]);",
        "4",
    );
    check(
        "class C { m() { return arguments.length; } } new C().m(1, 2, 3);",
        "3",
    );
    check(
        "function outer() { function inner() { return arguments.length; } \
         return inner(1) + ':' + arguments.length; } outer(1, 2);",
        "1:2",
    );
}

#[test]
fn arrows_use_the_enclosing_arguments_and_bindings_shadow() {
    check(
        "function f() { var g = () => arguments[0]; return g(); } f(7);",
        "7",
    );
    check(
        "function f() { var arguments = 5; return arguments; } f(1);",
        "5",
    );
    // A function with free variables pushes its scope before declaring it.
    check(
        "var captured = 'x'; function f() { return captured + arguments[0]; } f('y');",
        "xy",
    );
}

// bd-9vouw.372: every non-arrow invocation owns its arguments binding;
// ordinary var redeclarations and arrow captures must keep that binding's identity.

#[test]
fn each_non_arrow_function_owns_arguments_despite_outer_source_bindings() {
    check(
        "var arguments = 'outer'; function f() { return arguments[0] + ':' + arguments.length; \
         } f('inner', 2);",
        "inner:2",
    );
    check(
        "let arguments = 'outer'; const f = function () { return arguments[0]; }; \
         f('expression');",
        "expression",
    );
    check(
        "var arguments = 'outer'; var o = { m() { return arguments[0]; } }; o.m('method');",
        "method",
    );
    check(
        "function outer(arguments) { return function () { return arguments[0]; }; } \
         outer('outer')('inner');",
        "inner",
    );
    check(
        "var arguments = 'outer'; function* g() { yield arguments[0]; } \
         g('generator').next().value;",
        "generator",
    );
    check(
        "var arguments = 'outer'; class C { constructor() { this.x = arguments[0]; } m() { \
         return arguments[0]; } } var c = new C('ctor'); c.x + ':' + c.m('method');",
        "ctor:method",
    );
    check(
        "var arguments = 'outer'; var C = class { constructor() { this.x = arguments[0]; } m() \
         { return arguments[0]; } }; var c = new C('ctor'); c.x + ':' + c.m('method');",
        "ctor:method",
    );
    check(
        "var f = function arguments() { return arguments[0]; }; f('own');",
        "own",
    );
}

#[test]
fn var_arguments_redeclarations_preserve_the_entry_object() {
    check(
        "function f() { return typeof arguments; var arguments = 1; } f('x');",
        "object",
    );
    check(
        "function f() { var arguments; return arguments[0]; } f('kept');",
        "kept",
    );
    check(
        "function f() { if (false) { var arguments; } return arguments[0]; } f('block');",
        "block",
    );
    check(
        "function f() { var arguments = 7; var arguments; return arguments; } f(1);",
        "7",
    );
    check(
        "function f() { var [arguments] = [8]; return arguments; } f(1);",
        "8",
    );
    check(
        "function f() { var n = arguments.length; var arguments = 9; return n + ':' + \
         arguments; } f(1, 2);",
        "2:9",
    );
    check(
        "function f() { arguments = 6; var arguments; return arguments; } f();",
        "6",
    );
}

#[test]
fn arrows_and_their_parent_share_the_arguments_binding() {
    check(
        "function f() { const g = () => arguments; arguments = 7; return g(); } f(1);",
        "7",
    );
    check(
        "function f() { const g = () => { arguments = 8; }; g(); return arguments; } f(1);",
        "8",
    );
    check(
        "function f() { const g = () => () => arguments; const h = g(); arguments = 9; return \
         h(); } f(1);",
        "9",
    );
    check(
        "function f() { const g = () => () => { arguments = 10; }; g()(); return arguments; } \
         f(1);",
        "10",
    );
    check(
        "function f() { const g = () => arguments; var arguments = 11; return g(); } f(1);",
        "11",
    );
    check(
        "function f() { let g; { let arguments = 'block'; g = () => arguments; } return g() + \
         ':' + arguments[0]; } f('own');",
        "block:own",
    );
    check(
        "var arguments = 'outer'; const g = () => arguments; function f() { return (() => \
         arguments[0])(); } g() + ':' + f('own');",
        "outer:own",
    );
    check(
        "function f() { const g = arguments => () => arguments; return g('arrow')() + ':' + \
         arguments[0]; } f('own');",
        "arrow:own",
    );
}

#[test]
fn parameter_and_function_declarations_still_shadow_arguments() {
    check(
        "function f(arguments) { var arguments; return arguments; } f('parameter');",
        "parameter",
    );
    check(
        "function f({ arguments }) { return arguments; } f({ arguments: 'destructured' });",
        "destructured",
    );
    check(
        "function f(arguments = 'default') { return arguments; } f();",
        "default",
    );
    check(
        "function f() { return arguments(); function arguments() { return 'declaration'; } } \
         f(1);",
        "declaration",
    );
    check(
        "function f() { let arguments = 'lexical'; return arguments; } f(1);",
        "lexical",
    );
    check(
        "function f() { const g = (arguments) => arguments; return g('arrow') + ':' + \
         arguments[0]; } f('own');",
        "arrow:own",
    );
}

#[test]
fn parameter_defaults_resolve_the_functions_own_arguments() {
    check(
        "var arguments = 'outer'; function f(a = arguments[1]) { return a; } f(undefined, \
         'default');",
        "default",
    );
    check(
        "var arguments = 'outer'; function f({ a = arguments[1] } = {}) { return a; } \
         f(undefined, 'destructured');",
        "destructured",
    );
    check(
        "function f(read = () => arguments) { return read()[1]; } f(undefined, 'arrow');",
        "arrow",
    );
    check(
        "function f(a = arguments[1]) { function arguments() { return 'body'; } return a + ':' \
         + arguments(); } f(undefined, 'default');",
        "default:body",
    );
    check(
        "var arguments = 'outer'; function f(read = () => arguments) { return read()[1]; } \
         f(undefined, 'own');",
        "own",
    );
    check(
        "function f(read = () => arguments) { arguments = 7; return read(); } f();",
        "7",
    );
    check(
        "function f(change = () => { arguments = 8; }) { change(); return arguments; } f();",
        "8",
    );
    check(
        "function f(value = (arguments = 9)) { return arguments + ':' + value; } f();",
        "9:9",
    );
}

#[test]
fn body_var_arguments_preserves_the_parameter_environment() {
    check(
        "function f(a = 1) { var arguments; return arguments[1]; } f(undefined, 'body');",
        "body",
    );
    check(
        "function f(read = () => arguments) { var arguments = 7; return read()[1] + ':' + \
         arguments; } f(undefined, 'parameter');",
        "parameter:7",
    );
    check(
        "function f(read = () => arguments) { var arguments; const change = () => { arguments \
         = 8; }; change(); return read()[1] + ':' + arguments; } f(undefined, 'parameter');",
        "parameter:8",
    );
    check(
        "function f(value = (arguments = 9)) { var arguments; return arguments + ':' + value; \
         } f();",
        "9:9",
    );
    check(
        "function f(read = () => arguments) { var arguments; const same = () => arguments; \
         arguments = 7; return same() + ':' + read()[1]; } f(undefined, 'parameter');",
        "7:parameter",
    );
    check(
        "function f(read = () => arguments) { var arguments; arguments[1] = 'changed'; return \
         read()[1]; } f(undefined, 'parameter');",
        "changed",
    );
    check(
        "function f(read = () => arguments) { var arguments; const old = read(); arguments = \
         7; return old === read(); } f();",
        "true",
    );
    check(
        "function f(read = () => arguments) { let arguments = 'body'; return read()[1] + ':' + \
         arguments; } f(undefined, 'parameter');",
        "parameter:body",
    );
    check(
        "function f(change = () => { arguments = 11; }, read = () => arguments) { var \
         arguments; change(); return typeof arguments + ':' + read(); } f();",
        "object:11",
    );
    check(
        "function* f(read = () => arguments) { var arguments = 7; yield read()[1] + ':' + \
         arguments; } f(undefined, 'parameter').next().value;",
        "parameter:7",
    );
}

#[test]
fn generator_body_arguments_is_instantiated_before_the_first_resume() {
    check(
        "var change; function* g(x = (change = () => { arguments = 17; })) { var arguments; \
         yield typeof arguments; } var it = g(); change(); it.next().value;",
        "object",
    );
    check(
        "var change; const g = function* (x = (change = () => { arguments = 23; })) { var \
         arguments; yield typeof arguments; }; const it = g(); change(); it.next().value;",
        "object",
    );
}
