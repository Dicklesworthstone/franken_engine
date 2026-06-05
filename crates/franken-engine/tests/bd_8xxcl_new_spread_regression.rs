//! Regression coverage for bd-8xxcl: spread arguments in a `new` expression
//! (`new F(...xs)`) were not expanded — a `SpreadElement` at expression level
//! evaluates only to the inner value, so the plain `Construct` path passed the
//! array as a single positional argument. The New lowering arm now detects a
//! spread argument and desugars to `builtin:ReflectConstruct(target, argsArray)`
//! (mirroring the call-spread `ReflectApply` desugar, bd-hsv77), expanding the
//! iterable across the constructor's parameters.
//!
//! NOTE on ordering: a separate pre-existing bug (bd-jr2be) clobbers a
//! `function`/`class` declaration's binding when a `let`/`const` is declared
//! AFTER it (the declaration's value lives in reg0 and the later binding's init
//! overwrites it) — that breaks *any* later use of the name (plain calls too,
//! not just `new`/spread). To exercise the spread feature in isolation, the
//! variable-spread cases below declare the array BEFORE the constructor (or use
//! inline-array spreads), which is unaffected by bd-jr2be.

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => format!("{}", outcome.value),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn new_with_variable_spread_expands_into_params() {
    // Array declared before the function decl (collision-free per bd-jr2be).
    assert_eq!(
        eval("let xs = [2, 3]; function F(a, b) { this.s = a + b; } new F(...xs).s;"),
        "5"
    );
}

#[test]
fn new_with_inline_pure_spread() {
    assert_eq!(
        eval("function F(a, b) { this.s = a + b; } new F(...[2, 3]).s;"),
        "5"
    );
}

#[test]
fn new_with_leading_fixed_args_then_inline_spread() {
    assert_eq!(
        eval("function F(a, b, c) { this.t = a + b + c; } new F(1, ...[10, 20]).t;"),
        "31"
    );
}

#[test]
fn new_with_multiple_inline_spreads() {
    assert_eq!(
        eval(
            "function F(a, b, c, d) { this.s = '' + a + b + c + d; } new F(...[1, 2], ...[3, 4]).s;"
        ),
        "1234"
    );
}

#[test]
fn new_with_empty_spread_constructs_with_no_args() {
    assert_eq!(
        eval("function F() { this.ok = 42; } new F(...[]).ok;"),
        "42"
    );
}

#[test]
fn new_class_with_variable_spread_expands_into_constructor() {
    // Array declared before the class decl (collision-free per bd-jr2be).
    assert_eq!(
        eval("let xs = [4, 5]; class C { constructor(a, b) { this.p = a * b; } } new C(...xs).p;"),
        "20"
    );
}
