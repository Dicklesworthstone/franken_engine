//! `f.call(thisArg, ...args)` on an ordinary same-module function.
//!
//! Such calls used to run through an isolated activation that cloned the
//! whole module and snapshotted the execution state on every call (about
//! 13x the cost of a direct call). They are now re-dispatched in place as
//! the call `thisArg.f(...args)`. These tests pin the semantics that
//! re-dispatch must keep: receiver, `arguments`, lexical `this` of arrows,
//! exceptions reaching the caller's `try`, recursion and `super`. (Calling a
//! class constructor without `new` does not throw on either path yet; that
//! gap predates this change.) Expected strings are what Node v22.2.0 prints
//! for `String(eval(source))`.
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
fn receiver_arguments_and_strict_this() {
    check(
        "function f(a, b) { return this.k + a + b + arguments.length; } \
         f.call({k: 1}, 2, 3) + ',' + f.call({k: 10}, 1, 1, 99)",
        "8,15",
    );
    check(
        "'use strict'; function g() { return typeof this; } \
         [g.call(undefined), g.call(null), g.call(5), g.call('s')].join()",
        "undefined,object,number,string",
    );
    check(
        "var o = {k: 5, m: function () { var arrow = () => this.k; return arrow.call({k: 99}); }}; \
         o.m()",
        "5",
    );
}

#[test]
fn exceptions_recursion_and_super() {
    check(
        "function thrower(x) { throw new Error('bad ' + x); } var r; \
         try { thrower.call(null, 7); } catch (e) { r = e.message; } r",
        "bad 7",
    );
    check(
        "function fact(n) { return n <= 1 ? 1 : n * fact.call(null, n - 1); } fact.call(null, 10)",
        "3628800",
    );
    check(
        "class A { hi() { return 'A:' + this.n; } } \
         class B extends A { hi() { return 'B>' + super.hi(); } } B.prototype.hi.call({n: 3})",
        "B>A:3",
    );
    check(
        "var s = 0; function add(x) { s += x; } for (var i = 0; i < 100; i++) add.call(null, i); s",
        "4950",
    );
}
