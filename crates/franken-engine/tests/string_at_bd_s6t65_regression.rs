use frankenengine_engine::HybridRouter;
fn ev(s: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(s) {
        Ok(o) => o.value,
        Err(x) => format!("ERR:{x}"),
    }
}
#[test]
fn string_at_positive() {
    assert_eq!(ev(r#""abc".at(0)"#), "a");
}
#[test]
fn string_at_negative() {
    assert_eq!(ev(r#""abc".at(-1)"#), "c");
}
#[test]
fn string_at_oob() {
    assert_eq!(ev(r#""abc".at(9)"#), "undefined");
}
#[test]
fn string_at_default() {
    assert_eq!(ev(r#""xy".at()"#), "x");
}
