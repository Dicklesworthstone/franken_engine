//! Regression coverage for bd-8enww.4.4 (YTBG-D4): assignments to a closure-
//! captured (scope-allocated) variable must be stored back via `StoreScoped`,
//! not dropped into a dead register.
//!
//! Root cause: the module-level `Ir1Op::AssignOp` handler in `lower_ir2_to_ir3`
//! did not consult `scoped_runtime_binding_ids`, so an assignment expression to a
//! captured variable lowered to a throwaway register `Move` while reads of the
//! same variable correctly lowered to `LoadScoped`. Reads and writes desynced,
//! so every assignment after the capture was silently lost. This surfaced as a
//! "finally" failure in `exception_semantics_conformance` because the
//! `return-clears-finally-frame` case uses a captured `log` accumulator — but the
//! bug has nothing to do with try/catch/finally (see `no_try_finally_*` below).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|err| panic!("eval failed for {source:?}: {err:?}"))
        .value
}

/// The minimal repro: a closure captures `log`, the caller reassigns it after the
/// call. No try/catch/finally anywhere.
#[test]
fn no_try_finally_captured_var_reassignment_after_call_is_observed() {
    assert_eq!(
        eval(r#"let log=""; function f(){ log=log+"t"; } f(); log=log+":a"; log;"#),
        "t:a"
    );
}

/// Merely *defining* a closure that captures the variable (never calling it) must
/// not break subsequent writes.
#[test]
fn no_try_finally_captured_var_reassignment_without_call_is_observed() {
    assert_eq!(
        eval(r#"let log=""; function f(){ log=log+"t"; } log=log+":a"; log;"#),
        ":a"
    );
}

/// A read-only capture (`return log`) must also not freeze the variable.
#[test]
fn read_only_capture_does_not_freeze_outer_writes() {
    assert_eq!(
        eval(r#"let log="z"; function f(){ return log; } f(); log=log+":a"; log;"#),
        "z:a"
    );
}

/// Plain re-assignment (not just `+`) to a captured numeric must take effect.
#[test]
fn captured_var_plain_and_numeric_reassignment() {
    assert_eq!(eval(r#"let n=0; function f(){ n=5; } f(); n=7; n;"#), "7");
    assert_eq!(
        eval(r#"let n=0; function f(){ n=n+1; } f(); n=n+10; n;"#),
        "11"
    );
}

/// Compound assignment (`+=`, `*=`) to a captured variable must read the current
/// scope value, apply the op, and store it back.
#[test]
fn compound_assignment_to_captured_var() {
    assert_eq!(
        eval(r#"let n=0; function f(){ n=n+1; } f(); n+=10; n;"#),
        "11"
    );
    assert_eq!(
        eval(r#"let n=3; function f(){ return n; } f(); n*=4; n;"#),
        "12"
    );
}

/// The `exception_semantics_conformance` case that exposed the bug: a `return`
/// through a `finally` in `f()` (which captures `log`), then the caller appends to
/// `log` and runs an unrelated throw/catch.
#[test]
fn return_through_finally_with_captured_accumulator() {
    assert_eq!(
        eval(
            r#"let log=""; function f(){ try{ log=log+"try"; return "ret"; } finally{ log=log+":finally"; } } let result=f(); log=log+":"+result; try{ throw "x"; }catch(e){ log=log+":caught:"+e; } log;"#
        ),
        "try:finally:ret:caught:x"
    );
}

/// Non-captured variables must still use the register fast path unchanged.
#[test]
fn non_captured_var_register_path_unchanged() {
    assert_eq!(eval(r#"let log=""; log=log+":a"; log+=":b"; log;"#), ":a:b");
    assert_eq!(eval(r#"let n=1; n=n+2; n*=3; n;"#), "9");
}
