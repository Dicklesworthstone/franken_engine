//! Regression for bd-fqlfw.2.11.2 — `String.prototype.substr` was missing.
//!
//! `'abc'.substr(...)` resolved to `undefined` (the property was absent from the
//! string-method dispatch) and calling it failed with
//! "type error: expected function, got undefined", even though `substring` and
//! `slice` worked. `substr(start, length)` is legacy (ES2020 Annex B B.2.3.1)
//! but normative: a negative `start` counts from the end (`max(len + start, 0)`),
//! an omitted `length` takes the rest, and a non-positive result length yields
//! "". It is distinct from `substring`, which clamps both args to [0, len] and
//! swaps them. These cases run end-to-end through the HybridRouter.

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

fn substr_eq(expr: &str, expected: &str) {
    let outcome = eval(&format!("console.log({expr});"));
    assert_eq!(console_text(&outcome).trim(), expected, "{expr}");
}

#[test]
fn substr_basic_start_and_length() {
    // The bead repro.
    substr_eq("'abcdefg'.substr(1,3)", "bcd");
}

#[test]
fn substr_omitted_length_takes_rest() {
    substr_eq("'abcdefg'.substr(2)", "cdefg");
}

#[test]
fn substr_negative_start_counts_from_end() {
    substr_eq("'abcdefg'.substr(-2,3)", "fg");
    substr_eq("'abcdefg'.substr(-3)", "efg");
}

#[test]
fn substr_very_negative_start_clamps_to_zero() {
    substr_eq("'abcdefg'.substr(-100,2)", "ab");
}

#[test]
fn substr_nonpositive_or_out_of_range_yields_empty() {
    substr_eq("'abcdefg'.substr(0,0)", "");
    substr_eq("'abcdefg'.substr(3,-1)", "");
    substr_eq("'abcdefg'.substr(10)", "");
    substr_eq("'abcdefg'.substr(2).length === 5", "true");
}

#[test]
fn substr_length_overflows_clamped_to_remaining() {
    substr_eq("'abcdefg'.substr(5,100)", "fg");
}

// --- Controls: substring/slice were already correct; keep them pinned. ---

#[test]
fn control_substring_and_slice_still_work() {
    substr_eq("'abcdefg'.substring(1,4)", "bcd");
    substr_eq("'abcdefg'.slice(1,4)", "bcd");
    // substr is NOT substring: substr(1,4) takes 4 chars from index 1.
    substr_eq("'abcdefg'.substr(1,4)", "bcde");
}
