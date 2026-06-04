//! bd-vl55w — tagged-template strings array carries a `.raw` sibling array.
//!
//! Follow-up to bd-1lrbw (cooked strings). The desugar now wraps the cooked
//! array in `((__tt_strings) => { __tt_strings.raw = [<raw>]; return
//! __tt_strings; })([<cooked>])`, so `s.raw[i]` holds the raw (un-cooked)
//! quasis. `.length` distinguishes raw from cooked without escaped-string
//! assertions. Sources use raw Rust strings so `\n` reaches the engine as the
//! two-character template escape, not a literal newline.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn raw_array_present_no_escape() {
    // No escapes: raw[0] == cooked[0] == "hello".
    assert_eq!(
        eval(r#"function t(s) { return s.raw[0]; } t`hello`;"#),
        "hello"
    );
}

#[test]
fn cooked_processes_escape() {
    // `a\nb` cooked = a,<LF>,b -> length 3.
    assert_eq!(
        eval(r#"function t(s) { return s[0].length; } t`a\nb`;"#),
        "3"
    );
}

#[test]
fn raw_keeps_escape_literal() {
    // `a\nb` raw = a,\,n,b -> length 4 (backslash + n kept literal).
    assert_eq!(
        eval(r#"function t(s) { return s.raw[0].length; } t`a\nb`;"#),
        "4"
    );
}

#[test]
fn raw_length_matches_quasi_count() {
    assert_eq!(
        eval(r#"function t(s) { return s.raw.length; } t`a${1}b${2}c`;"#),
        "3"
    );
}

#[test]
fn cooked_still_works_alongside_raw() {
    // bd-1lrbw behavior preserved: cooked s[0] still accessible.
    assert_eq!(eval(r#"function t(s) { return s[0]; } t`hi`;"#), "hi");
}

#[test]
fn substitution_still_passed_after_raw_wrap() {
    assert_eq!(eval(r#"function t(s, x) { return x; } t`a${42}b`;"#), "42");
}
