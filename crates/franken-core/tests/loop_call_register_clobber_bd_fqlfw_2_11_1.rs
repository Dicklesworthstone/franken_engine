//! Regression tests for bd-fqlfw.2.11.1 — IR3 register-allocation clobber.
//!
//! Before the fix, the IR2→IR3 lowering started binding/temporary register
//! allocation at register 0, the same slot the interpreter reserves for the
//! script completion value (read on Halt) and that the expression-statement
//! `Pop` handler keeps fresh via `Move { dst: 0, .. }`. The first-declared
//! binding (a top-level `function` closure, or a `class`/method binding) was
//! therefore pinned to r0 and silently clobbered by every later
//! expression-statement Pop — so any call that read that binding from inside a
//! loop dispatched against the clobbered (boolean) loop-condition value and
//! failed with "expected function, got boolean".
//!
//! The fix reserves register 0 for the completion value and starts allocation
//! at register 1. These tests pin the four originally-failing repros (plus
//! controls that always passed) at the source→IR3→execute boundary.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse → IR0 → IR3 → execute on the QuickJS lane with the minimal execution
/// capabilities, returning the full execution result (completion value +
/// captured console output).
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_fqlfw_2_11_1");
    let context = LoweringContext::new(
        "bd-fqlfw-2-11-1-trace",
        "bd-fqlfw-2-11-1-decision",
        "bd-fqlfw-2-11-1-policy",
    );
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-fqlfw-2-11-1-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

#[test]
fn function_call_in_while_loop_accumulates() {
    // The canonical repro: sum of add(i, 1) for i in 0..10 == 1+2+...+10 == 55.
    let src = "function add(a,b){return a+b;} var s=0;var i=0;\
               while(i<10){ s=s+add(i,1); i=i+1;} s;";
    assert_eq!(completion(src), Value::Int(55));
}

#[test]
fn function_call_in_for_loop_accumulates() {
    let src = "function add(a,b){return a+b;} var s=0;\
               for(var i=0;i<10;i=i+1){ s=s+add(i,1);} s;";
    assert_eq!(completion(src), Value::Int(55));
}

#[test]
fn unused_call_result_in_loop_does_not_clobber_callee() {
    // Call result is discarded each iteration; the callee binding must survive.
    let src = "function f(a){return a;} var i=0;\
               while(i<3){ f(i); i=i+1;} i;";
    assert_eq!(completion(src), Value::Int(3));
}

// NOTE: the bead's class-method repro (#4) and console.log repro are verified
// against the franken-engine HybridRouter (see
// `crates/franken-engine/tests/loop_call_register_clobber_bd_fqlfw_2_11_1.rs`),
// not here: the bare `QuickJsLane` harness used in this crate does not wire the
// `console` global, and franken-core has a *separate* pre-existing
// class-`this`/property gap (`new C(5); c.bump()` returns NaN even with no loop
// and is independent of this register-allocation fix). Both engine repros pass
// once the same register-0 reservation lands in the engine lowering copy.

// --- Controls: these always passed; pin them so the fix doesn't regress them. ---

#[test]
fn control_loop_without_call_still_sums() {
    let src = "var s=0;var i=0;while(i<10){ s=s+i; i=i+1;} s;";
    assert_eq!(completion(src), Value::Int(45));
}

#[test]
fn control_bare_call_still_works() {
    let src = "function add(a,b){return a+b;} add(2,3);";
    assert_eq!(completion(src), Value::Int(5));
}
