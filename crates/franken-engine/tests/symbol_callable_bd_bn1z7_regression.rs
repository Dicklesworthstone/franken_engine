//! Regression for bd-bn1z7 (Symbol() callable): the bare `Symbol([description])`
//! global had no eval-scope binding, so `typeof Symbol()` / `Symbol('a')` faulted
//! ("expected function, got undefined"). The `builtin:Symbol` execution handler
//! already allocated a unique `__type:"symbol"` value and `typeof` already types
//! it as "symbol"; only the lowering call-recognition was missing. This covers
//! the constructor-call surface; `Symbol.for`/`Symbol.keyFor` (a global registry)
//! is a separate follow-up.
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => o.value.to_string(),
        Err(err) => format!("ERR={}", err.to_string().lines().next().unwrap_or("")),
    }
}

#[test]
fn symbol_typeof_is_symbol() {
    assert_eq!(eval("typeof Symbol();"), "symbol");
    assert_eq!(eval("typeof Symbol('a');"), "symbol");
}

#[test]
fn symbol_calls_are_unique() {
    // Two distinct Symbol() calls are never equal.
    assert_eq!(eval("Symbol('a') === Symbol('a');"), "false");
    assert_eq!(eval("Symbol() === Symbol();"), "false");
}

#[test]
fn symbol_is_identity_stable_when_bound() {
    // The same symbol value compares equal to itself.
    assert_eq!(eval("let s = Symbol('x'); s === s;"), "true");
    assert_eq!(eval("let s = Symbol('tag'); typeof s;"), "symbol");
}
