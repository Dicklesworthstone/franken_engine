//! Regression: a named function declaration must be able to reference itself
//! (self-recursion). Before the fix, `function f(n){...f(n-1)...}` faulted with
//! "expected function, got undefined" because the closure captured its own name
//! while that binding still held `undefined`.
//!
//! Bead: bd-g0aok. FIX (SilverPeak): after AzureFinch's `free_var_ids` lowering
//! fix (aec7387b), the IR3 body resolves its recursive callee via
//! `LoadScoped(name)` from the captured scope chain (not the old register/
//! `LoadBinding` path OliveLake instrumented), so self-binding the function's own
//! name in `captured_env` at `CreateClosure` to the freshly-created closure makes
//! self-recursion and named-function-expression recursion resolve. The three
//! self-recursion cases below are now active. Mutual recursion (`ev`/`od`) still
//! needs by-reference capture / declaration hoisting (siblings are captured before
//! they are assigned) and remains `#[ignore]`d.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn self_recursive_factorial() {
    assert_eq!(
        eval_value("function f(n){ return n <= 1 ? 1 : n * f(n - 1); } f(5)"),
        "120"
    );
}

#[test]
fn self_recursive_fibonacci() {
    assert_eq!(
        eval_value("function fib(n){ return n < 2 ? n : fib(n - 1) + fib(n - 2); } fib(10)"),
        "55"
    );
}

#[test]
fn self_recursive_countdown_returns_base() {
    assert_eq!(
        eval_value("function down(n){ return n === 0 ? 0 : down(n - 1); } down(7)"),
        "0"
    );
}

#[test]
#[ignore = "bd-g0aok: mutual recursion needs function-declaration hoisting in lowering (separate from the self-binding fix)"]
fn mutual_recursion_even_odd() {
    assert_eq!(
        eval_value(
            "function ev(n){ return n === 0 ? true : od(n - 1); } \
             function od(n){ return n === 0 ? false : ev(n - 1); } ev(10)"
        ),
        "true"
    );
}
