//! Regression for bd-9j3zw: BigInt literals must not fall through to the raw
//! string fallback (`typeof 1n` was previously `"string"`).

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(output) => format!("{}", output.value),
        Err(err) => format!("ERR={}", err.to_string().lines().next().unwrap_or("")),
    }
}

#[test]
fn bigint_literal_typeof_is_bigint() {
    assert_eq!(eval("typeof 1n;"), "bigint");
    assert_eq!(eval("let x = 0n; typeof x;"), "bigint");
}

#[test]
fn bigint_addition_preserves_bigint_identity() {
    assert_eq!(eval("1n + 1n === 2n;"), "true");
    assert_eq!(eval("typeof (1n + 1n);"), "bigint");
}

#[test]
fn bigint_literal_string_concat_uses_primitive_decimal_text() {
    assert_eq!(eval("'id:' + 7n;"), "id:7");
}
