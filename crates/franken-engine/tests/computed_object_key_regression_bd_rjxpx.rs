//! Regression: computed object-literal keys must be evaluated and assigned
//! under the resulting key (bd-rjxpx).
//!
//! Before the fix, `parse_object_literal` kept the surrounding brackets of a
//! computed key, so `{ ["a"+"b"]: 1 }` parsed the key as the array literal
//! `["ab"]` (the property key became an array object, not the string "ab"),
//! and `o.ab` was `undefined`. The parser now strips the computed-key
//! brackets and parses the inner expression as the key.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e:?}"))
        .value
}

#[test]
fn computed_key_string_concat_assigns_under_resulting_key() {
    // The canonical bd-rjxpx repro.
    assert_eq!(eval_value(r#"let o = { ["a"+"b"]: 1 }; o.ab;"#), "1");
}

#[test]
fn computed_key_identifier_expression() {
    assert_eq!(eval_value(r#"let k = "x"; let o = { [k]: 5 }; o.x;"#), "5");
}

#[test]
fn computed_key_numeric_expression() {
    // `[1 + 2]` => key 3; numeric keys stringify, accessed via bracket index.
    assert_eq!(eval_value(r#"let o = { [1 + 2]: 7 }; o[3];"#), "7");
}

#[test]
fn static_string_key_still_works() {
    // Guard: the non-computed key path is unchanged.
    assert_eq!(eval_value(r#"let o = { ab: 9 }; o.ab;"#), "9");
}
