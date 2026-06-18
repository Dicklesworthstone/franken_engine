//! bd-9a8cz.1 — receiver-aware `String.prototype` index/slice/build methods.
//!
//! Part 2 of the `string_property_value` seam (part 1 = f7916616:
//! toUpperCase/toLowerCase/trim/split/includes/startsWith/endsWith). Adds
//! indexOf/lastIndexOf/slice/substring/replace/repeat/padStart/padEnd and the
//! optional position arguments for includes/startsWith/endsWith (treated as 0
//! in part 1).
//!
//! Receivers are strings held in VARIABLES (`let s = "..."; s.slice(...)`),
//! not string literals — literal receivers (`"abc".slice()`) are a separate
//! gap tracked by bd-bulsc.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- indexOf -------------------------------------------------------------

#[test]
fn index_of_first_occurrence() {
    assert_eq!(eval(r#"let s = "hello world"; s.indexOf("o");"#), "4");
}

#[test]
fn index_of_honors_from_position() {
    assert_eq!(eval(r#"let s = "hello world"; s.indexOf("o", 5);"#), "7");
}

#[test]
fn index_of_absent_returns_minus_one() {
    assert_eq!(eval(r#"let s = "hello"; s.indexOf("z");"#), "-1");
}

// ---- lastIndexOf ---------------------------------------------------------

#[test]
fn last_index_of_returns_highest_match() {
    assert_eq!(eval(r#"let s = "hello"; s.lastIndexOf("l");"#), "3");
}

#[test]
fn last_index_of_absent_returns_minus_one() {
    assert_eq!(eval(r#"let s = "hello"; s.lastIndexOf("z");"#), "-1");
}

// ---- slice (negative indices count from the end) -------------------------

#[test]
fn slice_start_and_end() {
    assert_eq!(eval(r#"let s = "hello"; s.slice(1, 3);"#), "el");
}

#[test]
fn slice_negative_start() {
    assert_eq!(eval(r#"let s = "hello"; s.slice(-3);"#), "llo");
}

#[test]
fn slice_inverted_range_is_empty() {
    assert_eq!(eval(r#"let s = "hello"; s.slice(3, 1);"#), "");
}

// ---- substring (clamps negatives to 0, swaps when start > end) -----------

#[test]
fn substring_start_and_end() {
    assert_eq!(eval(r#"let s = "hello"; s.substring(1, 3);"#), "el");
}

#[test]
fn substring_swaps_when_start_greater_than_end() {
    assert_eq!(eval(r#"let s = "hello"; s.substring(3, 1);"#), "el");
}

#[test]
fn substring_clamps_negative_to_zero() {
    assert_eq!(eval(r#"let s = "hello"; s.substring(-2, 2);"#), "he");
}

// ---- replace (string search, first occurrence only) ----------------------

#[test]
fn replace_first_occurrence_only() {
    assert_eq!(eval(r#"let s = "a-b-c"; s.replace("-", "+");"#), "a+b-c");
}

// ---- repeat --------------------------------------------------------------

#[test]
fn repeat_concatenates_copies() {
    assert_eq!(eval(r#"let s = "ab"; s.repeat(3);"#), "ababab");
}

#[test]
fn repeat_zero_is_empty() {
    assert_eq!(eval(r#"let s = "ab"; s.repeat(0);"#), "");
}

#[test]
fn repeat_negative_count_is_range_error_bd_8tsdh() {
    // ES2020 21.1.3.16 step 4: a negative count throws RangeError (not ""), matching
    // the stdlib path. Previously the IR-dispatch path clamped to 0 and returned "".
    let out = eval(r#"let s = "x"; s.repeat(-1);"#);
    assert!(
        out.contains("range error") && out.contains("non-negative"),
        "repeat(-1) should be a RangeError, got {out:?}"
    );
}

#[test]
fn repeat_oversize_is_range_error_bd_8tsdh() {
    // An oversize result fails closed with RangeError (previously TypeError): receiver
    // length 2 * count 10_000_000 exceeds the result-size guard.
    let out = eval(r#"let s = "ab"; s.repeat(10000000);"#);
    assert!(
        out.contains("range error") && out.contains("exceeds maximum"),
        "oversize repeat should be a RangeError, got {out:?}"
    );
}

// ---- padStart / padEnd ---------------------------------------------------

#[test]
fn pad_start_with_pad_string() {
    assert_eq!(eval(r#"let s = "5"; s.padStart(3, "0");"#), "005");
}

#[test]
fn pad_start_noop_when_already_long_enough() {
    assert_eq!(eval(r#"let s = "555"; s.padStart(2, "0");"#), "555");
}

#[test]
fn pad_end_with_pad_string() {
    assert_eq!(eval(r#"let s = "5"; s.padEnd(3, "0");"#), "500");
}

// ---- position args for includes / startsWith / endsWith ------------------

#[test]
fn includes_honors_position() {
    assert_eq!(eval(r#"let s = "hello"; s.includes("lo", 3);"#), "true");
    assert_eq!(eval(r#"let s = "hello"; s.includes("he", 1);"#), "false");
}

#[test]
fn starts_with_honors_position() {
    assert_eq!(eval(r#"let s = "hello"; s.startsWith("ll", 2);"#), "true");
    assert_eq!(eval(r#"let s = "hello"; s.startsWith("ll", 0);"#), "false");
}

#[test]
fn ends_with_honors_end_position() {
    // Treat the string as if it were only its first 4 chars ("hell"), which
    // ends with "ell".
    assert_eq!(eval(r#"let s = "hello"; s.endsWith("ell", 4);"#), "true");
    assert_eq!(eval(r#"let s = "hello"; s.endsWith("llo", 4);"#), "false");
}
