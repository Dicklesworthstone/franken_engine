//! Regression: a closure that ASSIGNS to a captured outer binding must write
//! back to that binding — the mutation persists across calls and is visible to
//! the enclosing scope.
//!
//! Bead: bd-p89tp. The original repro (`HybridRouter::eval`) was
//! `let c = 0; let inc = () => c = c + 1; inc(); inc(); c;`, which yielded
//! `"0"` instead of `"2"`: the closure captured a value copy, so its
//! assignment did not reach the enclosing binding.
//!
//! Fixed by bd-x0ld5: lowering now gives each exact lexical binding a canonical
//! capture cell and routes enclosing and deferred reads/writes through that same
//! live cell. These tests remain in the normal suite to prevent a return to the
//! old register-to-scope value-copy bridge.
//!
//! They assert VALUES (silent stale-value bug the eval==Ok harness cannot see).

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn arrow_closure_assignment_persists() {
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); inc(); c"),
        "2"
    );
}

#[test]
fn function_expression_closure_assignment_persists() {
    assert_eq!(
        eval_value("let a = 0; let f = function () { a = a + 1; }; f(); f(); f(); a"),
        "3"
    );
}

#[test]
fn counter_factory_keeps_private_state() {
    // A returned closure over a function-local `let` must accumulate state.
    assert_eq!(
        eval_value(
            "function makeCounter() { let n = 0; return () => { n = n + 1; return n; }; } \
             let c = makeCounter(); c(); c(); c()"
        ),
        "3"
    );
}
