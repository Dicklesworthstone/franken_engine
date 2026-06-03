//! Regression coverage for bd-s6t65: `String.prototype.at` must resolve through
//! the receiver-aware `string_property_value` seam instead of returning
//! `undefined` for the method lookup.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn string_at_positive_index_returns_utf16_code_unit() {
    assert_eq!(eval_value(r#"let s = "abc"; s.at(1);"#), "b");
}

#[test]
fn string_at_negative_index_counts_from_end() {
    assert_eq!(eval_value(r#"let s = "abc"; s.at(-1);"#), "c");
}

#[test]
fn string_at_out_of_range_returns_undefined() {
    assert_eq!(eval_value(r#"let s = "abc"; s.at(5);"#), "undefined");
    assert_eq!(eval_value(r#"let s = "abc"; s.at(-5);"#), "undefined");
}

#[test]
fn string_at_defaults_missing_index_to_zero() {
    assert_eq!(eval_value(r#"let s = "abc"; s.at();"#), "a");
}

#[test]
fn string_at_uses_utf16_code_units() {
    assert_eq!(
        eval_value(r#"let s = "a" + String.fromCharCode(55357, 56613) + "b"; s.at(3);"#),
        "b"
    );
}
