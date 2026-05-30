//! Regression coverage for bd-9a8cz (part 1): receiver-aware String.prototype
//! methods resolved through the HybridRouter `string_property_value` seam —
//! toUpperCase, toLowerCase, trim, split, includes, startsWith, endsWith.
//! Before this, these resolved to `undefined` ("expected function, got
//! undefined") even on a string in a variable (only `charAt`/`charCodeAt` and
//! the `length` property were wired).
//!
//! Variable receivers are used throughout (string-literal receivers like
//! `"abc".split()` are blocked by the separate parser gap bd-bulsc).
//! Value-asserting through HybridRouter::eval.

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
fn case_transforms() {
    assert_eq!(eval_value("let s = \"abc\"; s.toUpperCase();"), "ABC");
    assert_eq!(eval_value("let s = \"ABC\"; s.toLowerCase();"), "abc");
    assert_eq!(eval_value("let s = \"Mixed\"; s.toUpperCase();"), "MIXED");
}

#[test]
fn trim_strips_surrounding_whitespace() {
    assert_eq!(eval_value("let s = \"  hi  \"; s.trim();"), "hi");
    assert_eq!(eval_value("let s = \"nopad\"; s.trim();"), "nopad");
}

#[test]
fn includes_starts_ends() {
    assert_eq!(
        eval_value("let s = \"hello\"; s.includes(\"ell\");"),
        "true"
    );
    assert_eq!(
        eval_value("let s = \"hello\"; s.includes(\"xyz\");"),
        "false"
    );
    assert_eq!(
        eval_value("let s = \"hello\"; s.startsWith(\"he\");"),
        "true"
    );
    assert_eq!(
        eval_value("let s = \"hello\"; s.startsWith(\"lo\");"),
        "false"
    );
    assert_eq!(eval_value("let s = \"hello\"; s.endsWith(\"lo\");"), "true");
    assert_eq!(
        eval_value("let s = \"hello\"; s.endsWith(\"he\");"),
        "false"
    );
}

#[test]
fn split_on_separator() {
    assert_eq!(
        eval_value("let s = \"a,b,c\"; let r = s.split(\",\"); r[0];"),
        "a"
    );
    assert_eq!(
        eval_value("let s = \"a,b,c\"; let r = s.split(\",\"); r[2];"),
        "c"
    );
    assert_eq!(
        eval_value("let s = \"a,b,c\"; let r = s.split(\",\"); r.length;"),
        "3"
    );
    // trailing empty piece is preserved.
    assert_eq!(
        eval_value("let s = \"a,b,\"; let r = s.split(\",\"); r.length;"),
        "3"
    );
}

#[test]
fn split_empty_separator_is_per_character() {
    assert_eq!(
        eval_value("let s = \"abc\"; let r = s.split(\"\"); r[1];"),
        "b"
    );
    assert_eq!(
        eval_value("let s = \"abc\"; let r = s.split(\"\"); r.length;"),
        "3"
    );
}

#[test]
fn split_undefined_separator_yields_whole_string() {
    assert_eq!(
        eval_value("let s = \"abc\"; let r = s.split(); r[0];"),
        "abc"
    );
    assert_eq!(
        eval_value("let s = \"abc\"; let r = s.split(); r.length;"),
        "1"
    );
}
