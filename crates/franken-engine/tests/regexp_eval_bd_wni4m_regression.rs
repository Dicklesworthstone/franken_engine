//! Regression: RegExp literals must be usable through the default eval path.
//!
//! Bead: bd-wni4m. Before the fix, regex literals lowered to the denied
//! `regexp:create` hostcall, so `/ab/.test("xabz")`, `String.prototype.match`,
//! and regex-backed `replace` faulted before reaching the runtime RegExp object.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn regexp_literal_test_is_allowed_in_eval() {
    assert_eq!(eval_value(r#"/ab/.test("xabz")"#), "true");
}

#[test]
fn string_match_accepts_regexp_literal() {
    assert_eq!(eval_value(r#"let m = "a1b2".match(/[0-9]/); m[0]"#), "1");
}

#[test]
fn string_replace_accepts_global_regexp_literal() {
    assert_eq!(eval_value(r#""a1b2".replace(/[0-9]/g, "X")"#), "aXbX");
}
