//! Regression: object-literal accessor properties `{ get v(){...} }` /
//! `{ set v(x){...} }` must install accessor descriptors and be invoked on
//! property GET / SET.
//!
//! Bead: bd-semhe. REPRO (`HybridRouter::eval`):
//! `let o = { get v() { return 11; } }; o.v;` yields `undefined` (WRONG; expect
//! `11`). The accessor is parsed but never installed/invoked — property GET
//! reads a data slot that was never set, so it returns `undefined`.
//!
//! SCOPE (per JadeHarbor/DustyStork/SapphireBridge scoping): this is a 3-4 file,
//! end-to-end accessor feature — parser `get`/`set` in object literals → an AST
//! accessor kind on `ObjectProperty` → lowering that installs an accessor
//! descriptor (object_model `PropertyDescriptor::Accessor` already exists) →
//! interpreter `GetProperty` invoking the getter (and `SetProperty` the setter)
//! with correct `this`-binding. It must land ATOMICALLY (a getter is only
//! observable once all layers are wired), so these cases are `#[ignore]`d until
//! the feature lands; the interpreter half needs `baseline_interpreter.rs`,
//! leased by another agent at staging time.
//!
//! These assert VALUES (not just `eval == Ok`), so they catch the silent
//! wrong-value bug the eval==Ok conformance harness cannot see. Un-ignore them
//! in the same commit that lands the accessor mechanism.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-semhe: blocked on accessor feature (parser/ast/lowering/interpreter); un-ignore when landed"]
fn object_literal_getter_returns_computed_value() {
    assert_eq!(eval_value("let o = { get v() { return 11; } }; o.v"), "11");
}

#[test]
#[ignore = "bd-semhe: blocked on accessor feature; un-ignore when landed"]
fn object_literal_getter_binds_this_to_receiver() {
    // The getter runs with the object as `this`, so it can read sibling props.
    assert_eq!(
        eval_value("let o = { x: 5, get d() { return this.x + 1; } }; o.d"),
        "6"
    );
}

#[test]
#[ignore = "bd-semhe: blocked on accessor feature; un-ignore when landed"]
fn object_literal_setter_side_effect_is_observable() {
    // The setter runs with the object as `this` and its side effect persists.
    assert_eq!(
        eval_value("let o = { _x: 0, set s(v) { this._x = v; } }; o.s = 9; o._x"),
        "9"
    );
}

#[test]
#[ignore = "bd-semhe: blocked on accessor feature; un-ignore when landed"]
fn data_properties_coexist_with_accessors_unchanged() {
    // A plain data property alongside a getter must keep its normal value.
    assert_eq!(
        eval_value("let o = { a: 1, get b() { return 2; } }; o.a"),
        "1"
    );
}

#[test]
#[ignore = "bd-semhe: blocked on accessor feature; un-ignore when landed"]
fn absent_property_on_accessor_object_is_undefined() {
    // Accessing a key with no data prop and no accessor still yields undefined.
    assert_eq!(
        eval_value("let o = { get v() { return 1; } }; o.w"),
        "undefined"
    );
}
