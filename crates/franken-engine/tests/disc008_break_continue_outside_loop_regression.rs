//! Regression (bd-bg9l1.27.6 / DISC-008): a bare (unlabeled) `break` or
//! `continue` outside any loop or switch is an ES2020 early `SyntaxError`
//! (§13.x EarlyErrors) and MUST surface from the real eval pipeline as an
//! error — not silently lower and execute.
//!
//! BACKGROUND. `static_semantics::analyze` has always detected
//! `BreakOutsideLoop` / `ContinueOutsideLoop`, but it was only ever called
//! from `tests/lowering_coverage_integration.rs` — never from the live eval
//! pipeline (`eval_via_native_pipeline` in `lib.rs`). So programs with these
//! early errors used to lower and run instead of throwing. The fix wires the
//! false-positive-free `Break/ContinueOutsideLoop` subset of `analyze` into
//! `eval_via_native_pipeline`, between a successful parse and IR0 lowering.
//!
//! The pre-existing `static_semantics_integration` suites assert `analyze`
//! itself; this suite is the missing END-TO-END guard proving the analyzer is
//! actually CONNECTED to `HybridRouter::eval`. Per FoggyCastle's harness note,
//! the iteration_statements_test262 conformance harness keys Pass on
//! `eval == Ok`, so a correct throw can never flip a case there — the only way
//! to lock this behavior is a negative-case test asserting `eval()` returns
//! `Err`, which is exactly what these tests do.

use frankenengine_engine::HybridRouter;

/// `Ok(stringified value)` on success, or `Err(display string)` on fault.
fn eval(source: &str) -> Result<String, String> {
    let mut engine = HybridRouter::default();
    engine
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// Negative cases: must be rejected (the regression these tests guard).
// ---------------------------------------------------------------------------

#[test]
fn bare_break_at_top_level_is_rejected() {
    let result = eval("break;");
    assert!(
        result.is_err(),
        "bare top-level `break;` must be a SyntaxError, got Ok({:?})",
        result.ok()
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("FE-STATIC-DIAG-BREAK-OUTSIDE-0014"),
        "error must come from the wired static-semantics check (break-outside-loop \
         diagnostic code), got: {msg}"
    );
}

#[test]
fn bare_continue_at_top_level_is_rejected() {
    let result = eval("continue;");
    assert!(
        result.is_err(),
        "bare top-level `continue;` must be a SyntaxError, got Ok({:?})",
        result.ok()
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("FE-STATIC-DIAG-CONTINUE-OUTSIDE-0015"),
        "error must come from the wired static-semantics check (continue-outside-loop \
         diagnostic code), got: {msg}"
    );
}

#[test]
fn break_inside_a_plain_block_but_outside_any_loop_is_rejected() {
    // A bare block does not introduce a loop, so the `break` is still outside
    // any iteration/switch construct and remains an early SyntaxError.
    let result = eval("{ let x = 1; break; }");
    assert!(
        result.is_err(),
        "`break` in a plain block (no enclosing loop) must be a SyntaxError, got Ok({:?})",
        result.ok()
    );
    assert!(
        result
            .unwrap_err()
            .contains("FE-STATIC-DIAG-BREAK-OUTSIDE-0014"),
        "must surface the break-outside-loop early error"
    );
}

// ---------------------------------------------------------------------------
// Positive cases: must NOT be rejected (no false positives — every loop form
// sets `in_loop`, so a `break`/`continue` inside one is valid).
// ---------------------------------------------------------------------------

#[test]
fn break_inside_a_for_loop_is_accepted() {
    // `i = i + 1` (not `i++`) deliberately: postfix `++` is unimplemented
    // (bd-um9a3) and would mask this test behind a budget-exhaustion fault.
    let result = eval("let n = 0; for (let i = 0; i < 5; i = i + 1) { n = i; break; } n;");
    assert!(
        result.is_ok(),
        "`break` inside a for-loop is valid and must not be rejected, got {:?}",
        result.err()
    );
    assert_eq!(
        result.unwrap(),
        "0",
        "loop should break on the first iteration"
    );
}

#[test]
fn continue_inside_a_while_loop_is_accepted() {
    let result = eval("let n = 0; while (n < 3) { n = n + 1; continue; } n;");
    assert!(
        result.is_ok(),
        "`continue` inside a while-loop is valid and must not be rejected, got {:?}",
        result.err()
    );
    assert_eq!(result.unwrap(), "3", "loop should run to completion");
}
