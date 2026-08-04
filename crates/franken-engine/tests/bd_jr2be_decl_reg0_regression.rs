//! Regression coverage for bd-jr2be: a `function`/`class` declaration's binding
//! lives in register 0, which also serves as the module completion register. A
//! following `let`/`const`/`var` declaration recorded its initializer as the
//! module completion value (`Pop` → `Move dst:0`), CLOBBERING the earlier
//! declaration. Any later use of that name then read the declaration's value
//! (an object) and faulted — even for a plain call. Fixed by lowering a
//! declaration's completion as `Discard` (empty completion per spec), matching
//! how class declarations already behave (bd-62un6).

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => outcome.value.to_string(),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn function_decl_then_let_then_plain_call() {
    // The minimal repro: plain call, no spread, no `new`.
    assert_eq!(eval("function F(){return 42;} let xs=[2,3]; F();"), "42");
}

#[test]
fn function_decl_then_let_then_new() {
    assert_eq!(
        eval("function F(a,b){this.s=a+b;} let xs=[2,3]; new F(2,3).s;"),
        "5"
    );
}

#[test]
fn function_decl_then_const_then_call() {
    assert_eq!(
        eval("function add(a,b){return a+b;} const k=10; add(k,5);"),
        "15"
    );
}

#[test]
fn function_decl_then_let_then_call_spread() {
    // bd-hsv77 call-spread was also defeated by the clobber.
    assert_eq!(
        eval("function f(a,b){return a+b;} let xs=[2,3]; f(...xs);"),
        "5"
    );
}

#[test]
fn function_decl_then_let_then_new_spread() {
    // bd-8xxcl new-spread, in the previously-clobbered ordering.
    assert_eq!(
        eval("function F(a,b){this.s=a+b;} let xs=[2,3]; new F(...xs).s;"),
        "5"
    );
}

#[test]
fn multiple_lets_after_function_decl() {
    assert_eq!(
        eval("function g(x){return x*2;} let a=1; let b=2; let c=3; g(a+b+c);"),
        "12"
    );
}
