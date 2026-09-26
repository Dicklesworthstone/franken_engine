//! `typeof`, `void` and `delete` are operators whether or not whitespace
//! follows the keyword.
//!
//! The parser only recognized them with a trailing space, so `typeof(x)` and
//! `void(0)` parsed as calls to undefined `typeof`/`void` functions ("typeof
//! is not defined"; 4 Test262 sample failures, and a common style in real
//! code). Identifiers that merely start with a keyword (`typeofValue`) stay
//! names.
//!
//! Expected strings are what Node v22.2.0 prints for `String(<program>)`, each
//! run in a fresh context.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn keyword_operators_take_parenthesized_operands() {
    check(
        "var x = 1; [typeof(x), typeof (JSON), typeof(undefinedVar), typeof(1 + 1), void(0), \
         typeof(x) === 'number'].join()",
        "number,object,undefined,number,,true",
    );
    check(
        "var o = {a: 1}; var r = delete(o.a); [r, 'a' in o].join()",
        "true,false",
    );
}

#[test]
fn keyword_operators_end_at_any_non_identifier_character() {
    check(
        "[typeof!0, typeof\"s\", typeof[1], typeof{}, typeof`t`].join()",
        "boolean,string,object,object,string",
    );
    check(
        "var typeofValue = 5, voidish = 6, deleted = 7; [typeofValue, voidish, deleted].join()",
        "5,6,7",
    );
}
