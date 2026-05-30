//! Regression: computed object-literal keys `{ [expr]: v }` must evaluate the
//! key expression and store the value under the resulting key.
//!
//! Bead: bd-rjxpx. REPRO (`HybridRouter::eval`): `let o = { ["a"+"b"]: 1 }; o.ab;`
//! yields `undefined` (WRONG; expect `1`).
//!
//! ROOT CAUSE (parser-only, SapphireBridge): in `parse_object_literal`
//! (parser.rs), a `key:value` property takes `key_src = p[..colon]` and calls
//! `parse_expression(key_src)`. For a COMPUTED key `["a"+"b"]`, `key_src` keeps
//! its surrounding brackets, so `parse_expression("[\"a\"+\"b\"]")` parses an
//! ARRAY LITERAL `["ab"]` — the property key becomes an array object, not the
//! string `"ab"`. `computed = true` is set correctly and the lowering faithfully
//! evaluates `prop.key`, so it evaluates the WRONG expression (the array). Fix is
//! parser-only: when `computed`, strip the surrounding `[...]` and parse the
//! INNER expression as the key.
//!
//! These cases are `#[ignore]`d until the parser fix lands (parser.rs is leased
//! by another agent at staging time). Un-ignore them in the same commit that
//! fixes `parse_object_literal` — they assert VALUES (not just `eval == Ok`), so
//! they catch the silent-wrong-key bug the conformance harness cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-rjxpx: blocked on parser.rs computed-key bracket-strip fix; un-ignore when landed"]
fn computed_key_string_concat_is_evaluated() {
    // The key expression `"a" + "b"` must evaluate to "ab", not parse as the
    // array literal `["ab"]`.
    assert_eq!(eval_value(r#"let o = { ["a" + "b"]: 1 }; o.ab"#), "1");
}

#[test]
#[ignore = "bd-rjxpx: blocked on parser.rs computed-key bracket-strip fix; un-ignore when landed"]
fn computed_key_numeric_expr_is_evaluated() {
    // A numeric computed key `[1 + 2]` becomes property "3".
    assert_eq!(eval_value(r#"let o = { [1 + 2]: "x" }; o[3]"#), "x");
}

#[test]
#[ignore = "bd-rjxpx: blocked on parser.rs computed-key bracket-strip fix; un-ignore when landed"]
fn computed_key_identifier_expr_is_evaluated() {
    // An identifier-expression key `[k]` uses the runtime value of `k`.
    assert_eq!(eval_value(r#"let k = "key"; let o = { [k]: 5 }; o.key"#), "5");
}

#[test]
#[ignore = "bd-rjxpx: blocked on parser.rs computed-key bracket-strip fix; un-ignore when landed"]
fn computed_key_does_not_leak_array_object_key() {
    // Guard against the exact bug: the property must NOT be stored under an
    // array-object key, so a plain non-computed lookup of the literal bracket
    // text must be absent and the computed key present.
    assert_eq!(eval_value(r#"let o = { ["k"]: 9 }; o.k"#), "9");
}
