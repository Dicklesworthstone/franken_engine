//! Regression coverage for bd-dbosg: CanonicalEs2020Parser must accept
//! `\uXXXX` / `\u{X..}` UnicodeEscapeSequences in an IdentifierName (ES2020
//! §11.6) and treat the escaped spelling as the SAME binding as the decoded
//! one (`net` ≡ `net`). Found by the now-real metamorphic parser oracle
//! (bd-x9t1n.2 / parser_unicode_escape_equivalence).
//!
//! The `\\u` in these Rust string literals emits a literal backslash-u into the
//! JavaScript source. Value-asserting through HybridRouter::eval.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn escaped_identifier_parses_and_evaluates() {
    // The bead's primary repro: escaped spelling on both sides.
    assert_eq!(eval_value("let \\u006eet = 4 + 5; \\u006eet;"), "9");
    // Minimized acceptance.
    assert_eq!(eval_value("let \\u006eet = 4; \\u006eet;"), "4");
}

#[test]
fn escaped_and_plain_spellings_are_the_same_binding() {
    // Bind with the escaped spelling, read with the plain spelling.
    assert_eq!(eval_value("let \\u006eet = 4 + 5; net;"), "9");
    // Bind plain, read escaped.
    assert_eq!(eval_value("let net = 4 + 5; \\u006eet;"), "9");
}

#[test]
fn braced_unicode_escape_form() {
    // `\u{6e}` is the braced form of the same code point ('n').
    assert_eq!(eval_value("let \\u{6e}et = 7; net;"), "7");
    assert_eq!(eval_value("let net = 7; \\u{6e}et;"), "7");
}

#[test]
fn plain_identifier_unchanged() {
    // Baseline: the non-escaped form is unaffected by the decode path.
    assert_eq!(eval_value("let net = 4 + 5; net;"), "9");
}
