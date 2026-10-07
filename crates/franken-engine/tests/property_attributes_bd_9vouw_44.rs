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

/// propertyIsEnumerable reads a Symbol-keyed property's [[Enumerable]] too; it
/// reported every existing Symbol key enumerable.
#[test]
fn property_is_enumerable_reads_symbol_key_attributes() {
    check(
        "var o = {}; Object.defineProperty(o, Symbol.iterator, { value: 1, enumerable: false }); \
         var s = Symbol('s'); o[s] = 2; \
         [o.propertyIsEnumerable(Symbol.iterator), o.propertyIsEnumerable(s), \
         Object.prototype.propertyIsEnumerable.call(Set.prototype, Symbol.toStringTag), \
         o.propertyIsEnumerable('nope')].join(' ')",
        "false true false false",
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

/// bd-9vouw.235: ObjectDefineProperties (Object.create, Object.defineProperties)
/// takes ToObject of a primitive properties argument, so a non-empty string's
/// index properties (strings, not descriptors) are a TypeError while other
/// primitives define nothing; and ToPropertyDescriptor takes any object,
/// a function included (its own `value` / `enumerable` are read; an empty one
/// defines an undefined, non-writable property). Node v22.2.0 gives this
/// value; Bun 1.4.2 agrees.
#[test]
fn properties_arguments_and_function_descriptors_bd_9vouw_235() {
    check(
        "function attempt(f) { try { var r = f(); return 'ok:' + Object.keys(r).join('+'); } catch (e) { return e.constructor.name; } }\nvar fd = function () {}; fd.value = 7; fd.enumerable = true;\nvar viaFn = Object.create({}, { a: fd, b: function () {} });\n[attempt(() => Object.create({}, 'abc')), attempt(() => Object.create({}, '')), attempt(() => Object.create({}, 5)),\n attempt(() => Object.defineProperties({}, 'x')), attempt(() => Object.defineProperties({}, true)),\n attempt(() => Object.create({}, { a: 1 })), attempt(() => Object.create({}, { a: null })),\n Object.keys(viaFn).join('+'), viaFn.a, 'b' in viaFn, viaFn.b, Object.getOwnPropertyDescriptor(viaFn, 'b').writable,\n attempt(() => Object.defineProperty({}, 'k', function () {})), attempt(() => Object.create({}, { a: { get: 5 } }))].join(' ');\n",
        "TypeError ok: ok: TypeError ok: TypeError TypeError a 7 true  false ok: TypeError",
    );
}

/// bd-9vouw.279: a key argument goes through ToPropertyKey: an object key
/// converts through its toString / valueOf (which may throw), after the
/// target's own type check for defineProperty / getOwnPropertyDescriptor /
/// hasOwn and before the receiver check for hasOwnProperty /
/// propertyIsEnumerable; a missing key is "undefined". Expected lines:
/// Node v22.2.0's output, captured programmatically.
#[test]
fn builtin_key_arguments_go_through_to_property_key_bd_9vouw_279() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var key = { toString: function () { return 'abc'; } };
var o = { abc: 1, undefined: 0 };
console.log(k(function () { return o.hasOwnProperty(key); }), k(function () { return o.propertyIsEnumerable(key); }), k(function () { return Object.hasOwn(o, key); }), k(function () { return JSON.stringify(Object.getOwnPropertyDescriptor(o, key)); }), k(function () { return JSON.stringify(Reflect.getOwnPropertyDescriptor(o, key)); }), k(function () { return o.hasOwnProperty(); }));
var d = {};
Object.defineProperty(d, [1, 2], { value: 1, enumerable: true });
Object.defineProperty(d, { toString: function () { return 'xyz'; } }, { value: 2, enumerable: true });
Object.defineProperty(d, { valueOf: function () { return 9; }, toString: null }, { value: 3, enumerable: true });
console.log(Object.keys(d).join(), k(function () { return Reflect.defineProperty(d, key, { value: 4 }); }), d.abc);
var order = [];
var k2 = { toString: function () { order.push('key'); return 'z'; } };
[function () { Object.defineProperty(1, k2, {}); }, function () { Object.getOwnPropertyDescriptor(null, k2); }, function () { Object.prototype.hasOwnProperty.call(null, k2); }, function () { Object.prototype.propertyIsEnumerable.call(undefined, k2); }, function () { Object.hasOwn(null, k2); }, function () { Object.defineProperty({}, { toString: function () { throw new RangeError('k'); } }, {}); }].forEach(function (f) { try { f(); order.push('none'); } catch (e) { order.push(e.constructor.name); } });
console.log(order.join());
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "true true true {\"value\":1,\"writable\":true,\"enumerable\":true,\"configurable\":true} {\"value\":1,\"writable\":true,\"enumerable\":true,\"configurable\":true} true",
            "9,1,2,xyz true 4",
            "TypeError,TypeError,key,TypeError,key,TypeError,TypeError,RangeError",
        ]
    );
}
