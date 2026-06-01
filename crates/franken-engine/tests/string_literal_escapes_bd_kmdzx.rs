//! bd-kmdzx — double-quoted (and single-quoted) string-literal escape sequences
//! are processed into their character values.
//!
//! Before this, `parse_quoted_string` returned the inner content raw, so escapes
//! stayed literal: `"a\"b".length` was 4 (a, \, ", b) instead of 3. The fix adds
//! ES2020 escape translation (`\" \n \t \\ \xHH \uHHHH \u{..}` + identity for
//! NonEscapeCharacter). Tests use the bead's `let x = …; x.op` form so they do
//! not depend on string-literal-receiver postfix parsing.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pins -----------------------------------------------------------

#[test]
fn escaped_double_quote_length() {
    assert_eq!(eval(r#"let x = "a\"b"; x.length;"#), "3");
}

#[test]
fn escaped_double_quote_equals_single_quoted() {
    assert_eq!(eval(r#"let x = "a\"b"; x === 'a"b';"#), "true");
}

#[test]
fn newline_escape_length() {
    assert_eq!(eval(r#"let x = "x\ny"; x.length;"#), "3");
}

#[test]
fn newline_escape_is_line_feed() {
    assert_eq!(eval(r#"let x = "x\ny"; x.charCodeAt(1);"#), "10");
}

#[test]
fn tab_escape_is_real_tab() {
    // "tab\there" = t,a,b,<TAB>,h,e,r,e — index 3 is U+0009.
    assert_eq!(eval(r#"let x = "tab\there"; x.charCodeAt(3);"#), "9");
}

#[test]
fn tab_escape_length() {
    assert_eq!(eval(r#"let x = "tab\there"; x.length;"#), "8");
}

#[test]
fn lone_backslash_escape_length() {
    assert_eq!(eval(r#"let x = "\\"; x.length;"#), "1");
}

// ---- single quotes share the same escape semantics ------------------------

#[test]
fn single_quoted_escaped_apostrophe() {
    assert_eq!(eval(r#"let x = 'a\'b'; x.length;"#), "3");
}

// ---- unicode / hex escapes -----------------------------------------------

#[test]
fn unicode_brace_escape_to_A() {
    assert_eq!(eval(r#"let x = "\u{41}"; x === 'A';"#), "true");
}

#[test]
fn hex_escape_to_A() {
    assert_eq!(eval(r#"let x = "\x41"; x === 'A';"#), "true");
}

// ---- no-escape strings are unchanged (fast path) --------------------------

#[test]
fn plain_string_unchanged() {
    assert_eq!(eval(r#"let x = "hello"; x.length;"#), "5");
}
