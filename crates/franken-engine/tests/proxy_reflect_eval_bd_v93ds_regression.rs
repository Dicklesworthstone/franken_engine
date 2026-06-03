//! Regression: the `Reflect` and `Proxy` meta-globals must be usable from
//! `HybridRouter::eval`.
//!
//! Bead: bd-v93ds (found by OliveLake eval-probe2). REPRO (`HybridRouter::eval`):
//! `Reflect.has({a:1},"a")` faulted "expected object, got undefined" (Reflect
//! undefined); `Reflect.ownKeys({a:1,b:2}).length` likewise; `new Proxy({x:5},{})`
//! faulted "expected function, got undefined" (Proxy not a constructor). Same
//! bare-global-resolution family as Date (bd-cseei) / Symbol / Map/Set.
//!
//! The Reflect/Proxy machinery already existed in the baseline interpreter
//! (`builtin:Reflect*`, `builtin:Proxy`, `proxy_aware_*`); the fix wires the
//! lowering interception so eval reaches it.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn reflect_has_detects_own_property() {
    assert_eq!(eval_value(r#"Reflect.has({a:1}, "a")"#), "true");
}

#[test]
fn reflect_has_false_for_missing_property() {
    assert_eq!(eval_value(r#"Reflect.has({a:1}, "b")"#), "false");
}

#[test]
fn reflect_own_keys_counts_own_properties() {
    assert_eq!(eval_value("Reflect.ownKeys({a:1, b:2}).length"), "2");
}

#[test]
fn proxy_empty_handler_passes_through_get() {
    assert_eq!(eval_value("new Proxy({x:5}, {}).x"), "5");
}
