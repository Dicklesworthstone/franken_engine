//! bd-hitj1 — Symbol.for / Symbol.keyFor global registry.
//!
//! `Symbol.for(key)` interns one symbol per string key (so two calls with the
//! same key are identical), while a fresh `Symbol()` is never registry-interned.
//! `Symbol.keyFor(sym)` returns the registry key, or undefined for a
//! non-registered symbol. Follow-up to bd-bn1z7 (Symbol() + typeof).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn for_same_key_is_identical() {
    assert_eq!(eval("Symbol.for('x') === Symbol.for('x');"), "true");
}

#[test]
fn for_different_keys_differ() {
    assert_eq!(eval("Symbol.for('a') === Symbol.for('b');"), "false");
}

#[test]
fn fresh_symbol_is_not_registry_interned() {
    assert_eq!(eval("Symbol.for('y') === Symbol('y');"), "false");
}

#[test]
fn key_for_returns_registry_key() {
    assert_eq!(eval("Symbol.keyFor(Symbol.for('z'));"), "z");
}

#[test]
fn key_for_unregistered_is_undefined() {
    assert_eq!(eval("typeof Symbol.keyFor(Symbol('w'));"), "undefined");
}

#[test]
fn registered_symbol_is_a_symbol() {
    assert_eq!(eval("typeof Symbol.for('t');"), "symbol");
}
