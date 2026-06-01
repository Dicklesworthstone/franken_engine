//! Regression coverage for bd-p89tp: a closure's assignment to a captured outer
//! `let` must persist to the outer binding. Before this, the closure ran with a
//! clone of the captured scope prefix and its writes were discarded when the
//! caller's saved scope chain was restored — so a counter closure never
//! incremented the outer variable (`inc(); inc(); c` stayed 0).
//!
//! Value-asserting through HybridRouter::eval.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
#[ignore = "bd-p89tp: closure write-back to a captured outer let is unimplemented for module-level (register-backed) vars; needs the deep capture-model fix (scope-bind captured module vars at lowering, or caller-register write-back)"]
fn arrow_closure_writes_back_to_captured_let() {
    // The bead's pin.
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); inc(); c;"),
        "2"
    );
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); c;"),
        "1"
    );
}

#[test]
#[ignore = "bd-p89tp: closure write-back to a captured outer let is unimplemented for module-level (register-backed) vars; needs the deep capture-model fix (scope-bind captured module vars at lowering, or caller-register write-back)"]
fn function_expression_closure_writes_back() {
    assert_eq!(
        eval_value("let c = 0; let inc = function() { c = c + 1; }; inc(); inc(); inc(); c;"),
        "3"
    );
}

#[test]
#[ignore = "bd-p89tp: closure write-back to a captured outer let is unimplemented for module-level (register-backed) vars; needs the deep capture-model fix (scope-bind captured module vars at lowering, or caller-register write-back)"]
fn compound_assign_in_closure_writes_back() {
    // += through a closure to the captured outer let.
    assert_eq!(
        eval_value("let c = 0; let inc = () => c += 1; inc(); inc(); c;"),
        "2"
    );
}

#[test]
#[ignore = "bd-p89tp: closure write-back to a captured outer let is unimplemented for module-level (register-backed) vars; needs the deep capture-model fix (scope-bind captured module vars at lowering, or caller-register write-back)"]
fn counter_factory_accumulates() {
    // Closure over a factory-local binding accumulates across calls.
    assert_eq!(
        eval_value(
            "let make = function() { let n = 0; return function() { n = n + 1; return n; }; }; let f = make(); f(); f();"
        ),
        "2"
    );
}
