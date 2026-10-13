//! bd-9vouw.284: Object.prototype.__proto__ is an accessor property
//! (Annex B.2.2.1): its descriptor has `get __proto__` and `set __proto__`,
//! which run on any receiver (ToObject for the getter; a primitive or a
//! non-object value is a no-op for the setter; undefined/null, a cycle, a
//! non-extensible object and Object.prototype itself are TypeErrors);
//! `in`, getOwnPropertyNames, Reflect.get/set with a distinct receiver and
//! __lookupGetter__ see it; a redefinition is used by ordinary reads and
//! writes, and after `delete` a write makes an own data property. The
//! descriptor was undefined. The lines are Node v22.2.0's output for the
//! same program.

use frankenengine_engine::HybridRouter;

#[test]
fn object_prototype_proto_is_an_accessor_with_getter_and_setter() {
    let source = r#"
function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var d = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__');
console.log(k(function () { return [typeof d.get, typeof d.set, d.enumerable, d.configurable, 'value' in d].join(); }), k(function () { return d.get.name + '|' + d.set.name + '|' + d.get.length + '|' + d.set.length; }));
var o = {};
console.log(k(function () { return d.get.call(o) === Object.prototype; }), k(function () { return d.get.call(1) === Number.prototype; }), k(function () { return d.get.call('s') === String.prototype; }), k(function () { return d.get.call(function () {}) === Function.prototype; }), k(function () { return d.get.call(undefined); }), k(function () { return d.get.call(null); }));
var p = { tag: 'p' };
console.log(k(function () { return d.set.call(o, p); }), Object.getPrototypeOf(o) === p, k(function () { return d.set.call(o, 3); }), Object.getPrototypeOf(o) === p, k(function () { return d.set.call(undefined, p); }), k(function () { return d.set.call(1, p); }));
console.log(k(function () { d.set.call(p, o); }), k(function () { d.set.call(Object.preventExtensions({}), {}); }), k(function () { return d.set.call(Object.preventExtensions({}), Object.prototype); }), k(function () { d.set.call(Object.prototype, {}); }));
console.log(k(function () { return Object.getOwnPropertyNames(Object.prototype).indexOf('__proto__') >= 0; }), k(function () { return ({}).hasOwnProperty('__proto__'); }), k(function () { return '__proto__' in {}; }), k(function () { return '__proto__' in Object.create(null); }), k(function () { return Object.keys(Object.prototype).length; }));
var r = {}, target = {};
console.log(k(function () { return Reflect.get({}, '__proto__') === Object.prototype; }), k(function () { return Reflect.get(Object.prototype, '__proto__', [1]) === Array.prototype; }), k(function () { return Reflect.set(target, '__proto__', p, r) + ',' + (Object.getPrototypeOf(r) === p) + ',' + (Object.getPrototypeOf(target) === Object.prototype); }));
console.log(k(function () { return ({}).__lookupGetter__('__proto__') === d.get; }), k(function () { var c = { __proto__: p }; return Object.getPrototypeOf(c) === p && !c.hasOwnProperty('__proto__'); }));
var n = Object.create(null);
n.__proto__ = p;
console.log(Object.getPrototypeOf(n) === null, n.__proto__ === p, Object.keys(n).join());
var log = [];
Object.defineProperty(Object.prototype, '__proto__', { get: function () { log.push('get'); return 'G'; }, set: function (v) { log.push('set:' + (v === p)); }, configurable: true });
var s = {};
console.log(s.__proto__, (s.__proto__ = p, Object.getPrototypeOf(s) === Object.prototype), log.join());
delete Object.prototype.__proto__;
var q = {};
q.__proto__ = p;
console.log(Object.getPrototypeOf(q) === Object.prototype, q.hasOwnProperty('__proto__'), Object.getOwnPropertyDescriptor(Object.prototype, '__proto__'));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "function,function,false,true,false get __proto__|set __proto__|0|1",
            "true true true true TypeError TypeError",
            "undefined true undefined true TypeError undefined",
            "TypeError TypeError undefined TypeError",
            "true false true false 0",
            "true true true,true,true",
            "true true",
            "true true __proto__",
            "G true get,set:true",
            "true true undefined",
        ]
    );
}
