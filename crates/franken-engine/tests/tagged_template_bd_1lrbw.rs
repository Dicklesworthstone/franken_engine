//! bd-1lrbw — tagged template literals invoke the tag with the cooked strings
//! array + substitutions.
//!
//! `` tag`a${x}b` `` must call `tag(["a","b"], x)` (ES2020 §12.2.9). The parser
//! previously desugared it to `tag(`a${x}b`)` — a single concatenated-string
//! argument — so `` t`hello` `` yielded `undefined`. The desugar now produces
//! `Call{ callee, arguments: [ArrayLiteral(cooked quasis), ...substitutions] }`.
//! Scope: cooked strings; the array's `.raw` property (String.raw) is a
//! follow-up.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pins (cooked) --------------------------------------------------

#[test]
fn tag_receives_cooked_first_string() {
    assert_eq!(eval("function t(s) { return s[0]; } t`hello`;"), "hello");
}

#[test]
fn strings_array_splits_on_substitution_first() {
    assert_eq!(eval("function t(s) { return s[0]; } t`a${1}b`;"), "a");
}

#[test]
fn strings_array_splits_on_substitution_second() {
    assert_eq!(eval("function t(s) { return s[1]; } t`a${1}b`;"), "b");
}

// ---- substitutions passed as trailing arguments --------------------------

#[test]
fn substitution_is_passed_to_tag() {
    assert_eq!(eval("function t(s, x) { return x; } t`a${42}b`;"), "42");
}

#[test]
fn strings_array_length_counts_quasis() {
    // `a${1}b${2}c` -> quasis ["a","b","c"]
    assert_eq!(eval("function t(s) { return s.length; } t`a${1}b${2}c`;"), "3");
}

// ---- member-expression tag ----------------------------------------------

#[test]
fn member_tag_receives_strings_array() {
    assert_eq!(
        eval("let o = { f: function(s) { return s[0]; } }; o.f`hi`;"),
        "hi"
    );
}
