//! Regression: a class that `extends` a BUILTIN constructor (Error, Array, Map,
//! Set, ...) must link to that builtin's prototype and construct correctly.
//!
//! Bead: bd-e8wrf. REPRO (`HybridRouter::eval`):
//! `class E extends Error {} let e = new E('m'); e instanceof Error;` faults
//! "expected object, got undefined". User-class-extends-user-class works
//! (bd-ppfds); extending a builtin does not.
//!
//! ROOT CAUSE (JadeHarbor, sharpened): `extends Error` uses `Error` as a BARE
//! IDENTIFIER value in the super_class slot, but bare globals (Error/Array/Map/
//! Symbol/...) resolve to `undefined` in the eval lane (only member-access /
//! new-expression lowering interception recognizes them). So super_class is
//! `undefined` → `GetProperty(undefined, 'prototype')` faults. The fix is the
//! broad "builtins as first-class values" gap PLUS exposing a real `.prototype`
//! object per builtin for the subclass to link to (interpreter + lowering, both
//! leased by other agents at staging time). These cases stay active because
//! builtin subclassing is easy to regress while broad builtin lowering evolves.
//!
//! They assert VALUES: instanceof, inherited `.message`, throw/catch, and
//! builtin collection method behavior the eval==Ok harness cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn subclass_of_error_is_instanceof_error() {
    assert_eq!(
        eval_value("class E extends Error {} let e = new E('m'); e instanceof Error"),
        "true"
    );
}

#[test]
fn subclass_of_error_inherits_message() {
    assert_eq!(
        eval_value("class E extends Error {} let e = new E('boom'); e.message"),
        "boom"
    );
}

#[test]
fn subclass_of_error_is_throwable_and_catchable() {
    assert_eq!(
        eval_value(
            "class E extends Error {} \
             let caught = false; \
             try { throw new E('x'); } catch (x) { caught = (x instanceof Error); } \
             caught"
        ),
        "true"
    );
}

#[test]
fn subclass_of_array_uses_array_storage_and_methods() {
    assert_eq!(
        eval_value(
            "class A extends Array {} \
             let a = new A(); \
             a.push(1); \
             a.push(2); \
             Array.isArray(a) ? a.length : -1"
        ),
        "2"
    );
}

#[test]
fn subclass_of_map_keeps_map_methods() {
    assert_eq!(
        eval_value(
            "class M extends Map {} \
             let m = new M(); \
             m.set('a', 1); \
             (m instanceof Map) ? m.get('a') : -1"
        ),
        "1"
    );
}

#[test]
fn subclass_of_set_keeps_set_methods() {
    assert_eq!(
        eval_value(
            "class S extends Set {} \
             let s = new S(); \
             s.add(1); \
             s.add(1); \
             (s instanceof Set) ? s.size : -1"
        ),
        "1"
    );
}
