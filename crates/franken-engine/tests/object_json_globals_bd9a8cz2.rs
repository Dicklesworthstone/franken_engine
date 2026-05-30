//! Regression coverage for bd-9a8cz.2: the `Object.*` / `JSON.*` static-method
//! globals are now reachable in eval. `Object`/`JSON` have no eval-scope
//! binding, so — like `Math.*` and the bare global functions — the bare
//! member-call is recognized at lowering (object_json_builtin_call_capability)
//! and routed to the canonical `builtin:*` hostcall whose impl already existed
//! in dispatch_builtin_hostcall_inner. Before this, `Object.keys(o)` /
//! `JSON.parse(...)` faulted with "expected object, got undefined".
//!
//! Value-asserting through HybridRouter::eval. (Note: `typeof Object/JSON`
//! stays `undefined` — there is still no scope binding, matching how `Math`
//! behaves; this wires the method calls, which is the actual fault.)

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn object_keys_returns_own_property_names() {
    assert_eq!(
        eval_value("let o = {x: 1, y: 2, z: 3}; Object.keys(o).length;"),
        "3"
    );
    assert_eq!(eval_value("let o = {}; Object.keys(o).length;"), "0");
}

#[test]
fn object_values_and_entries() {
    assert_eq!(eval_value("let o = {x: 10}; Object.values(o)[0];"), "10");
    assert_eq!(eval_value("let o = {x: 5}; Object.entries(o).length;"), "1");
}

#[test]
fn json_stringify_primitive() {
    // A primitive stringifies without embedded quotes (keeps the eval-value
    // extraction simple).
    assert_eq!(eval_value("JSON.stringify(5);"), "5");
}

#[test]
fn json_round_trips_a_primitive() {
    // stringify -> parse is reachable and round-trips a primitive. (Full
    // object serialization is a separate pre-existing builtin limitation —
    // JsonStringify emits "{}" for any object; tracked as a bd-9a8cz.2
    // follow-up — so the object round-trip is deliberately not asserted here.)
    assert_eq!(eval_value("JSON.parse(JSON.stringify(42));"), "42");
    assert_eq!(eval_value("JSON.parse(JSON.stringify(true));"), "true");
}
