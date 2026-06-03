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
//! leased by other agents at staging time). These cases are `#[ignore]`d until
//! it lands; un-ignore them then.
//!
//! They assert VALUES — instanceof, inherited `.message`, and throw/catch — the
//! canonical custom-error pattern the eval==Ok harness cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-e8wrf: blocked on builtins-as-values + per-builtin prototype (interpreter + lowering); un-ignore when landed"]
fn subclass_of_error_is_instanceof_error() {
    assert_eq!(
        eval_value("class E extends Error {} let e = new E('m'); e instanceof Error"),
        "true"
    );
}

#[test]
#[ignore = "bd-e8wrf: blocked on builtins-as-values + per-builtin prototype; un-ignore when landed"]
fn subclass_of_error_inherits_message() {
    assert_eq!(
        eval_value("class E extends Error {} let e = new E('boom'); e.message"),
        "boom"
    );
}

#[test]
#[ignore = "bd-e8wrf: blocked on builtins-as-values + per-builtin prototype; un-ignore when landed"]
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
