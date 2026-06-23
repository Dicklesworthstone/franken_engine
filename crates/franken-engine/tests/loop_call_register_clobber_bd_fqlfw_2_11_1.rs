//! Regression for bd-fqlfw.2.11.1 — IR3 register-allocation clobber.
//!
//! Any call to a user-defined function or a class method from inside a loop
//! body failed with `type error: expected function, got boolean`. Root cause:
//! the IR2→IR3 lowering started binding/temporary register allocation at
//! register 0, the slot the interpreter reserves for the script completion
//! value (returned via `read_reg(0)` on Halt) and that the expression-statement
//! `Pop` handler keeps fresh by emitting `Move { dst: 0, .. }`. The
//! first-declared binding (a top-level `function` closure, or the `class`
//! binding) was therefore pinned to r0 and silently clobbered by the loop's
//! condition/body Pops before the `Call`/`CallMethod` could read it — so the
//! callee register held the loop-condition boolean instead of the function.
//!
//! The fix reserves register 0 for the completion value and starts allocation
//! at register 1 (see `lowering_pipeline.rs`). These cases run the exact bead
//! repros end-to-end through the HybridRouter and assert the correct output.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval(source: &str) -> EvalOutcome {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|err| panic!("HybridRouter::eval failed for {source:?}: {err}"))
}

fn console_text(outcome: &EvalOutcome) -> String {
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn function_call_in_while_loop_prints_sum() {
    let outcome = eval(
        "function add(a,b){return a+b;} var s=0;var i=0;\
         while(i<10){ s=s+add(i,1); i=i+1;} console.log(s);",
    );
    assert_eq!(console_text(&outcome).trim(), "55");
}

#[test]
fn function_call_in_for_loop_prints_sum() {
    let outcome = eval(
        "function add(a,b){return a+b;} var s=0;\
         for(var i=0;i<10;i=i+1){ s=s+add(i,1);} console.log(s);",
    );
    assert_eq!(console_text(&outcome).trim(), "55");
}

#[test]
fn unused_call_result_in_loop_does_not_clobber_callee() {
    let outcome = eval(
        "function f(a){return a;} var i=0;\
         while(i<3){ f(i); i=i+1;} console.log('ok');",
    );
    assert_eq!(console_text(&outcome).trim(), "ok");
}

#[test]
fn class_method_call_in_loop_prints_sum() {
    let outcome = eval(
        "class C{constructor(v){this.value=v;} bump(){return this.value+1;}}\
         var s=0;var i=0;\
         while(i<10){ var c=new C(i); s=s+c.bump(); i=i+1;} console.log(s);",
    );
    assert_eq!(console_text(&outcome).trim(), "55");
}

// --- Controls: these always worked; pin them against regression. ---

#[test]
fn control_bare_call_outside_loop() {
    let outcome = eval("function add(a,b){return a+b;} console.log(add(2,3));");
    assert_eq!(console_text(&outcome).trim(), "5");
}

#[test]
fn control_loop_without_call() {
    let outcome = eval("var s=0;var i=0;while(i<10){ s=s+i; i=i+1;} console.log(s);");
    assert_eq!(console_text(&outcome).trim(), "45");
}

#[test]
fn control_bare_class_method_outside_loop() {
    let outcome = eval(
        "class C{constructor(v){this.value=v;} bump(){return this.value+1;}}\
         console.log(new C(5).bump());",
    );
    assert_eq!(console_text(&outcome).trim(), "6");
}
