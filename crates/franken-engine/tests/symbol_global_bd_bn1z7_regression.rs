//! Regression: the `Symbol` global must be a callable that produces unique
//! symbol values, with `typeof` `"symbol"` and a `Symbol.for` global registry.
//!
//! Bead: bd-bn1z7. REPRO (`HybridRouter::eval`): `typeof Symbol();` faults
//! "expected function, got undefined" — the `Symbol` global is not callable.
//! (`Symbol.iterator` IS specially recognized at lowering, but `Symbol()` /
//! `Symbol.for` / `Symbol.keyFor` / `typeof Symbol()` are not.)
//!
//! SCOPE: needs a `Symbol` builtin — `Symbol([desc])` returning a unique symbol
//! value (a new `Value::Symbol` variant or interned object), `Symbol.for` /
//! `keyFor` backed by a global registry, and `typeof symbol === "symbol"`. That
//! is interpreter (+ a lowering member/call interception like Math/JSON), and
//! those files are leased by other agents at staging time. These cases are
//! `#[ignore]`d until it lands; un-ignore them then.
//!
//! They assert VALUES, including symbol uniqueness and registry interning, which
//! the eval==Ok conformance harness cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn typeof_symbol_is_symbol() {
    assert_eq!(eval_value("typeof Symbol()"), "symbol");
}

#[test]
fn symbols_are_unique() {
    // Two freshly-created symbols with the same description are NOT equal.
    assert_eq!(eval_value("Symbol('a') === Symbol('a')"), "false");
}

#[test]
#[ignore = "bd-bn1z7: Symbol.for global registry not yet implemented (33839ef8 added Symbol()/typeof/uniqueness only); un-ignore when Symbol.for lands"]
fn symbol_for_interns_in_global_registry() {
    // `Symbol.for(key)` returns the same symbol for the same key.
    assert_eq!(eval_value("Symbol.for('x') === Symbol.for('x')"), "true");
}

#[test]
#[ignore = "bd-bn1z7: Symbol.for global registry not yet implemented (33839ef8 added Symbol()/typeof/uniqueness only); un-ignore when Symbol.for lands"]
fn symbol_for_differs_from_plain_symbol() {
    // A registry symbol is distinct from an un-registered one of the same desc.
    assert_eq!(eval_value("Symbol.for('y') === Symbol('y')"), "false");
}
