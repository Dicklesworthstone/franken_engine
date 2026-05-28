//! bd-bg9l1.27.2 (DISC-004) — for-of binding destructuring lowering conformance.
//!
//! The iteration_statements_test262_conformance.rs harness classifies
//! `for-of-destructuring-nested`, `-defaults`, and `-rest` as KNOWN_FAILING
//! under DISC-004 ("for-of binding destructuring"). But every one of those
//! three case sources carries a multi-line body AND a trailing `// Should be …`
//! comment, while the *passing* `for-of-destructuring-basic` case is a single
//! line with no comment. That makes DISC-004 indistinguishable from the
//! DISC-001 comment-leak (bd-bg9l1.27.1) in the original harness.
//!
//! This test isolates the two failure modes. Every source here is the SAME
//! destructuring construct as the conformance case, rewritten on a single line
//! with no `//` comment so the comment-leak path (parser merge_logical_lines)
//! cannot be the cause. All four pass today, which proves the destructuring
//! lowering in `lowering_pipeline.rs::lower_destructuring_to_ir1` is correct and
//! the three conformance cases are blocked SOLELY on bd-bg9l1.27.1; once that
//! lands they can move into EXPECTED_PASS. If any later regresses, the residual
//! is a genuine lowering gap to repair in `lowering_pipeline.rs`.

use frankenengine_engine::HybridRouter;

/// Evaluate `source` and return the completion value string, or the error
/// rendered as `ERR: …` so a diagnostic dump can show what actually happened.
fn eval_value(source: &str) -> String {
    let mut router = HybridRouter::default();
    match router.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR: {err}"),
    }
}

/// Control: single-line basic array destructuring (the conformance case that
/// already passes). Pins the comment-free baseline so a regression in basic
/// destructuring is distinguishable from the nested/defaults/rest gaps.
#[test]
fn for_of_destructuring_basic_single_line() {
    let source = "let seen = 0; let entries = [[1, 2]]; \
         for (const [key, value] of entries) { seen = key + value; } seen;";
    assert_eq!(eval_value(source), "3");
}

/// Nested destructuring: `for (const { coords: [x, y] } of data)`.
/// Mirror of `for-of-destructuring-nested`, comment-free, single line.
/// Expected: (1+2) + (3+4) = 10.
#[test]
fn for_of_destructuring_nested_single_line() {
    let source = "let result = 0; let data = [{ coords: [1, 2] }, { coords: [3, 4] }]; \
         for (const { coords: [x, y] } of data) { result = result + x + y; } result;";
    assert_eq!(eval_value(source), "10");
}

/// Default values: `for (const { a = 5, b = 10 } of items)`.
/// Mirror of `for-of-destructuring-defaults`, comment-free, single line.
/// Expected: (1+10) + (5+2) + (5+10) = 33.
#[test]
fn for_of_destructuring_defaults_single_line() {
    let source = "let result = 0; let items = [{ a: 1 }, { b: 2 }, {}]; \
         for (const { a = 5, b = 10 } of items) { result = result + a + b; } result;";
    assert_eq!(eval_value(source), "33");
}

/// Rest pattern: `for (const [first, ...rest] of arrays)`.
/// Mirror of `for-of-destructuring-rest`, comment-free, single line.
/// Expected: (1 + rest.length 3) + (5 + rest.length 1) = 4 + 6 = 10.
#[test]
fn for_of_destructuring_rest_single_line() {
    let source = "let result = 0; let arrays = [[1, 2, 3, 4], [5, 6]]; \
         for (const [first, ...rest] of arrays) { result = result + first + rest.length; } result;";
    assert_eq!(eval_value(source), "10");
}

/// Diagnostic dump — never fails. Prints the actual completion value (or error)
/// for every form so a swarm agent reading test output can see at a glance
/// which destructuring shapes the engine handles today, independent of the
/// pass/fail tests above. Run with `--nocapture` to see the output.
#[test]
fn for_of_destructuring_diagnostic_dump() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "basic",
            "let seen = 0; let entries = [[1, 2]]; \
             for (const [key, value] of entries) { seen = key + value; } seen;",
            "3",
        ),
        (
            "nested",
            "let result = 0; let data = [{ coords: [1, 2] }, { coords: [3, 4] }]; \
             for (const { coords: [x, y] } of data) { result = result + x + y; } result;",
            "10",
        ),
        (
            "defaults",
            "let result = 0; let items = [{ a: 1 }, { b: 2 }, {}]; \
             for (const { a = 5, b = 10 } of items) { result = result + a + b; } result;",
            "33",
        ),
        (
            "rest",
            "let result = 0; let arrays = [[1, 2, 3, 4], [5, 6]]; \
             for (const [first, ...rest] of arrays) { result = result + first + rest.length; } result;",
            "10",
        ),
    ];

    println!("\nfor-of destructuring lowering diagnostic (bd-bg9l1.27.2 / DISC-004):");
    for (label, source, expected) in cases {
        let got = eval_value(source);
        let verdict = if &got == expected { "OK  " } else { "GAP " };
        println!("  [{verdict}] {label:<9} expected={expected:<4} got={got}");
    }
}
