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
