//! bd-umee4 — array destructuring assignment to existing lvalues.
//!
//! `[a, b] = [b, a]` (and `[x, y] = arr`, member targets, nesting) was rejected
//! at lowering with FE-LOWER-ASSIGN-0001 ("assignment to non-lvalue target").
//! The lowering Assignment arm now handles an `ArrayLiteral` target: the RHS is
//! evaluated once into a temp (so swaps read pre-assignment values) and each
//! element target is assigned from `temp[index]` (identifier/member targets reuse
//! existing paths; nested array patterns recurse). The expression evaluates to
//! the RHS, per ES2020 §13.15.5.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pin: swap ------------------------------------------------------

#[test]
fn swap_first() {
    assert_eq!(eval("let a = 1; let b = 2; [a, b] = [b, a]; a;"), "2");
}

#[test]
fn swap_second() {
    assert_eq!(eval("let a = 1; let b = 2; [a, b] = [b, a]; b;"), "1");
}

// ---- basic destructuring -------------------------------------------------

#[test]
fn basic_first() {
    assert_eq!(eval("let x = 0; let y = 0; [x, y] = [10, 20]; x;"), "10");
}

#[test]
fn basic_second() {
    assert_eq!(eval("let x = 0; let y = 0; [x, y] = [10, 20]; y;"), "20");
}

// ---- member-expression element target ------------------------------------

#[test]
fn member_target() {
    assert_eq!(eval("let o = { p: 0 }; [o.p] = [9]; o.p;"), "9");
}

// ---- nested array pattern (recurses) -------------------------------------

#[test]
fn nested_inner() {
    assert_eq!(eval("let a = 0; let b = 0; [[a], b] = [[1], 2]; a;"), "1");
}

#[test]
fn nested_outer() {
    assert_eq!(eval("let a = 0; let b = 0; [[a], b] = [[1], 2]; b;"), "2");
}

// ---- elision / hole skips the slot ---------------------------------------

#[test]
fn hole_is_skipped() {
    assert_eq!(eval("let a = 0; let c = 0; [a, , c] = [1, 2, 3]; c;"), "3");
}

// ---- the assignment expression evaluates to the RHS ----------------------

#[test]
fn result_is_rhs() {
    assert_eq!(eval("let a = 0; let b = 0; ([a, b] = [7, 8])[1];"), "8");
}
