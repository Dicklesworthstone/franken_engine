//! Regression coverage for bd-dbosg.1: unicode-escaped identifier names in
//! member-property and object-literal-key position canonicalize to the same
//! name as the plain spelling (ES2020 §11.6), completing bd-dbosg (which
//! handled binding + identifier-reference position).
//!
//! `\\u` in these Rust literals emits a literal backslash-u into the JS source.

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
fn member_access_with_escaped_property_name() {
    // Read a plain-keyed property via an escaped member access.
    assert_eq!(eval_value("let o = {prop: 7}; o.\\u0070rop;"), "7");
}

#[test]
fn object_literal_escaped_key() {
    // Define via an escaped key, read via the plain spelling.
    assert_eq!(eval_value("let o = {\\u0070rop: 7}; o.prop;"), "7");
}

#[test]
fn object_shorthand_escaped_name() {
    // `{ prop }` shorthand means `{ prop: prop }` — both key and the
    // value reference canonicalize to `prop`.
    assert_eq!(
        eval_value("let prop = 5; let o = {\\u0070rop}; o.prop;"),
        "5"
    );
}
