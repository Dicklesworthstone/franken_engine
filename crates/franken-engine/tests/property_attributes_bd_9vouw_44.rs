//! bd-9vouw.44: own properties carry writable/enumerable/configurable
//! attributes (ES2020 6.1.7.1), and `Object.defineProperty` applies
//! ValidateAndApplyPropertyDescriptor (ES2020 9.1.6.3).
//!
//! Before this, every property reported all-true attributes, absent
//! descriptor fields did not default to `false`, non-enumerable properties
//! leaked into `Object.keys`/for-in/JSON, and class methods were enumerable.
//! Expected strings are what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn absent_descriptor_fields_default_to_false() {
    check(
        "var o = {}; Object.defineProperty(o, 'x', {value: 1}); \
         var d = Object.getOwnPropertyDescriptor(o, 'x'); \
         [d.value, d.writable, d.enumerable, d.configurable].join();",
        "1,false,false,false",
    );
}

#[test]
fn non_enumerable_properties_are_skipped_by_enumeration() {
    check(
        "var o = {a: 1}; Object.defineProperty(o, 'h', {value: 2}); \
         var ks = []; for (var k in o) ks.push(k); \
         Object.keys(o).join() + '|' + ks.join() + '|' + JSON.stringify(o) + '|' + \
         o.propertyIsEnumerable('h');",
        "a|a|{\"a\":1}|false",
    );
}

#[test]
fn non_writable_properties_reject_assignment() {
    check(
        "'use strict'; var o = {}; Object.defineProperty(o, 'x', {value: 1}); var r; \
         try { o.x = 2; r = 'no throw'; } catch (e) { r = (e instanceof TypeError) + ':' + o.x; } r;",
        "true:1",
    );
    // An inherited non-writable data property blocks creating an own one.
    check(
        "'use strict'; var p = {}; Object.defineProperty(p, 'x', {value: 1}); \
         var o = Object.create(p); var r; \
         try { o.x = 2; r = 'no'; } catch (e) { r = (e instanceof TypeError) + ':' + o.hasOwnProperty('x'); } r;",
        "true:false",
    );
}

#[test]
fn non_configurable_properties_survive_delete() {
    check(
        "var o = {}; Object.defineProperty(o, 'x', {value: 1}); (delete o.x) + ':' + o.x;",
        "false:1",
    );
}

#[test]
fn redefinition_is_validated() {
    // Non-configurable, non-writable: a different value is rejected, the
    // same value is accepted.
    check(
        "var o = {}; Object.defineProperty(o, 'x', {value: 1}); var r; \
         try { Object.defineProperty(o, 'x', {value: 2}); r = 'no'; } \
         catch (e) { r = String(e instanceof TypeError); } \
         Object.defineProperty(o, 'x', {value: 1}); r + ':' + o.x;",
        "true:1",
    );
    // Configurable properties may change even when non-writable.
    check(
        "var o = {}; Object.defineProperty(o, 'x', {value: 1, configurable: true}); \
         Object.defineProperty(o, 'x', {value: 2}); o.x;",
        "2",
    );
    // Data -> accessor keeps enumerable/configurable.
    check(
        "var o = {}; Object.defineProperty(o, 'x', {value: 1, configurable: true, enumerable: true}); \
         Object.defineProperty(o, 'x', {get: function () { return 5; }}); \
         var d = Object.getOwnPropertyDescriptor(o, 'x'); \
         o.x + ':' + d.enumerable + ':' + d.configurable + ':' + ('value' in d);",
        "5:true:true:false",
    );
    // A non-configurable accessor keeps its getter.
    check(
        "var o = {}; Object.defineProperty(o, 'x', {get: function () { return 1; }, configurable: false}); \
         var r; try { Object.defineProperty(o, 'x', {get: function () { return 2; }}); r = 'no'; } \
         catch (e) { r = String(e instanceof TypeError); } r + ':' + o.x;",
        "true:1",
    );
    check(
        "var o = Object.preventExtensions({}); var r; \
         try { Object.defineProperty(o, 'x', {value: 1}); r = 'no'; } \
         catch (e) { r = String(e instanceof TypeError); } r;",
        "true",
    );
}

#[test]
fn descriptor_fields_are_read_with_get() {
    // Inherited descriptor fields count (HasProperty, not own-only).
    check(
        "var proto = {enumerable: true}; var desc = Object.create(proto); desc.value = 3; \
         var o = {}; Object.defineProperty(o, 'x', desc); Object.keys(o).join() + o.x;",
        "x3",
    );
    // Getter-backed descriptor fields are invoked.
    check(
        "var desc = {}; Object.defineProperty(desc, 'value', {get: function () { return 9; }}); \
         var o = {}; Object.defineProperty(o, 'y', desc); o.y;",
        "9",
    );
}

#[test]
fn object_create_applies_full_descriptors() {
    check(
        "var o = Object.create({}, {a: {value: 1, enumerable: true}, \
         b: {get: function () { return 2; }}}); Object.keys(o).join() + ':' + o.b;",
        "a:2",
    );
    check(
        "var r; try { Object.create(1); r = 'no'; } catch (e) { r = String(e instanceof TypeError); } r;",
        "true",
    );
}

#[test]
fn class_members_are_non_enumerable_but_literal_members_are_not() {
    check(
        "class A { m() {} get g() { return 1; } static s() {} } var a = new A(); \
         var ks = []; for (var k in a) ks.push(k); \
         ks.length + ':' + Object.keys(A.prototype).length + ':' + \
         Object.getOwnPropertyDescriptor(A.prototype, 'm').enumerable + ':' + \
         Object.getOwnPropertyDescriptor(A.prototype, 'g').enumerable;",
        "0:0:false:false",
    );
    check(
        "var o = {m() {}, get g() { return 1; }}; Object.keys(o).join();",
        "m,g",
    );
}

#[test]
fn frozen_properties_report_frozen_attributes() {
    check(
        "var o = Object.freeze({x: 1}); var d = Object.getOwnPropertyDescriptor(o, 'x'); \
         d.writable + ':' + d.configurable + ':' + d.enumerable;",
        "false:false:true",
    );
}
