//! bd-9vouw.46: an unparenthesized function expression followed by a call or
//! member suffix keeps that suffix (`function (x) {...}(5)`,
//! `function () {...}.call(o)`).
//!
//! The parser's function arm used to consume the whole text and discard
//! everything after the body, so TypeScript's ES5 class emit
//! (`var Dog = (function (_super) {...}(Animal))`) and UMD wrappers bound the
//! function itself instead of its result. Expected strings are what Node
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
fn immediately_called_function_expressions() {
    check("var D = (function (s) { return s + 1; }(5)); D;", "6");
    check("var D = function (s) { return s + 1; }(5); D;", "6");
    check(
        "var out = []; !function (o) { o.push('ran'); }(out); out.join();",
        "ran",
    );
    check(
        "var p = async function (x) { return x; }(1); typeof p.then;",
        "function",
    );
}

#[test]
fn member_suffix_after_a_function_expression() {
    check(
        "var x = function () { return this.v; }.call({v: 3}); x;",
        "3",
    );
}

#[test]
fn umd_wrapper_runs_its_factory() {
    check(
        "var root = {}; (function (r, factory) { r.lib = factory(); }(root, \
         function () { return {v: 42}; })); root.lib.v;",
        "42",
    );
}
