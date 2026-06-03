//! Regression: a named function declaration must be able to reference itself
//! (self-recursion). Before the fix, `function f(n){...f(n-1)...}` faulted with
//! "expected function, got undefined" because the closure captured its own name
//! while that binding still held `undefined`.
//!
//! Bead: bd-g0aok. VERIFIED DIAGNOSIS (OliveLake): the function's own name IS
//! captured into the closure's `captured_env` (innermost frame), and rebinding
//! that binding to the freshly-created closure in `CreateClosure` works (dumped:
//! `down` becomes `Closure(0)/init=true`). But the body's self-reference STILL
//! resolves `undefined` — so the body does NOT read the name from its captured
//! scope chain at call time. The fix therefore needs the closure capture-
//! RESOLUTION model, not a `CreateClosure` self-binding alone — the same deep
//! by-value-capture / scope-restore issue as bd-p89tp. (The self-binding rebind
//! is the necessary complement once capture/resolution reads the captured env.)
//! All cases `#[ignore]`d until that lands; un-ignore them then. Mutual recursion
//! (`ev`/`od`) additionally needs function-declaration hoisting in lowering.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-g0aok: blocked on closure capture-resolution model (body does not read its captured self-binding); see bead"]
fn self_recursive_factorial() {
    assert_eq!(
        eval_value("function f(n){ return n <= 1 ? 1 : n * f(n - 1); } f(5)"),
        "120"
    );
}

#[test]
#[ignore = "bd-g0aok: blocked on closure capture-resolution model (body does not read its captured self-binding); see bead"]
fn self_recursive_fibonacci() {
    assert_eq!(
        eval_value("function fib(n){ return n < 2 ? n : fib(n - 1) + fib(n - 2); } fib(10)"),
        "55"
    );
}

#[test]
#[ignore = "bd-g0aok: blocked on closure capture-resolution model (body does not read its captured self-binding); see bead"]
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
