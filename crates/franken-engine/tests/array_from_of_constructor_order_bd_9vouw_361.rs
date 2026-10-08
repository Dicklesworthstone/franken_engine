//! bd-9vouw.361: Array.from and Array.of with a constructor `this` other
//! than %Array% (a subclass, `Array.from.call(C, ...)`) follow the
//! specification's order (ES2020 22.1.2.1, 22.1.2.3):
//! - `new C()` runs before an iterable's @@iterator;
//! - `new C(len)` runs after an array-like's length is read;
//! - Array.of runs `new C(items.length)`;
//! - each element is defined through [[DefineOwnProperty]] (a Proxy's
//!   trap) as it is mapped, and a failing definition closes the iterator;
//! - Set(A, "length", len, true) runs a `length` setter and throws for a
//!   refusal.
//!
//! The result was a finished plain array copied into `new C()`: C ran last
//! and saw no length, setters and traps were skipped, and a built-in
//! constructor `this` (Object) gave a plain array. The line is Node
//! v22.2.0's; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn array_from_and_of_construct_this_in_specification_order() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name + (e.message === 'boom' ? ':boom' : '')); } }
function iterable(values, log) {
  var o = {};
  o[Symbol.iterator] = function () { log.push('iter'); var i = 0; return { next: function () { log.push('next'); return i < values.length ? { value: values[i++], done: false } : { done: true }; }, return: function () { log.push('return'); return {}; } }; };
  return o;
}
t('iter-order', function () { var log = []; function C() { log.push('new:' + arguments.length); } var r = Array.from.call(C, iterable(['a', 'b'], log), function (v, k) { log.push('map' + k); return v + k; }); return [log.join(' '), r.length, r[0], r[1], r instanceof C].join(); });
t('arraylike-order', function () { var log = []; var src = { get length() { log.push('len'); return 2; }, get 0() { log.push('get0'); return 'x'; }, get 1() { log.push('get1'); return 'y'; } }; function C(n) { log.push('new:' + n); } var r = Array.from.call(C, src); return [log.join(' '), r[0], r[1], r.length].join(); });
t('define-interleaved', function () { var log = []; function C() { return new Proxy({}, { defineProperty: function (target, key, desc) { log.push('def' + key); return Reflect.defineProperty(target, key, desc); }, set: function (target, key, value) { log.push('set' + key + '=' + value); target[key] = value; return true; } }); } Array.from.call(C, iterable([1, 2], []), function (v) { log.push('map' + v); return v; }); return log.join(' '); });
t('define-fails-closes', function () { var log = []; function C() { return Object.freeze({}); } try { Array.from.call(C, iterable([1, 2], log)); } catch (e) { log.push(e.constructor.name); } return log.join(' '); });
t('length-setter', function () { var seen = []; function C() { Object.defineProperty(this, 'length', { set: function (n) { seen.push(n); } }); } Array.from.call(C, [5, 6, 7]); Array.from.call(C, { length: 1, 0: 'z' }); Array.of.call(C, 1, 2); return seen.join(); });
t('length-setter-throws', function () { function C() {} Object.defineProperty(C.prototype, 'length', { set: function () { throw new Error('boom'); } }); Array.from.call(C, []); return 'no throw'; });
t('ctor-throws', function () { function C() { throw new Error('boom'); } Array.from.call(C, [1]); return 'no throw'; });
t('of-args', function () { var args; function C() { args = [].slice.call(arguments); } var r = Array.of.call(C, 'p', 'q', 'r'); return [args.join(), r[2], r.length, r instanceof C].join(); });
t('of-proxy-define-throws', function () { function C() { return new Proxy({}, { defineProperty: function () { throw new Error('boom'); } }); } Array.of.call(C, 1); return 'no throw'; });
t('object-ctor', function () { var a = Array.from.call(Object, []); var b = Array.of.call(Object, 1); return [a.constructor === Object, Array.isArray(a), a.length, b.constructor === Object, b[0], b.length].join(); });
t('subclass', function () { class L extends Array {} var a = L.from(new Set([1, 2])); var b = L.of(7, 8, 9); var c = L.from('hé', function (ch) { return ch.toUpperCase(); }); return [a instanceof L, Array.isArray(a), a.length, a.join(), b instanceof L, b.length, c.join(''), c instanceof L].join(); });
t('subclass-map', function () { class L extends Array {} return L.from(new Map([['k', 1]])).map(function (e) { return e.join(':'); }).join() + ':' + (L.from([1]).map(String) instanceof L); });
t('plain', function () { var a = Array.from({ length: 2 }, function (v, i) { return i * 2; }); var b = Array.of(3); return [a.join(), Array.isArray(a), b.length, b[0]].join(); });
t('non-ctor-this', function () { var a = Array.from.call({}, [1]); var b = Array.of.call(Math.max, 2); return [Array.isArray(a), a[0], Array.isArray(b), b[0]].join(); });
t('arrow-this', function () { var f = function () {}; var arrow = () => {}; return [Array.isArray(Array.from.call(arrow, [1])), Array.from.call(f, [1]) instanceof f].join(); });
console.log(out.join(' | '));
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
            "iter-order=new:0 iter next map0 next map1 next,2,a0,b1,true | arraylike-order=len new:2 get0 get1,x,y,2 | define-interleaved=map1 def0 map2 def1 setlength=2 | define-fails-closes=iter next return TypeError | length-setter=3,1,2 | length-setter-throws!Error:boom | ctor-throws!Error:boom | of-args=3,r,3,true | of-proxy-define-throws!Error:boom | object-ctor=true,false,0,false,1,1 | subclass=true,true,2,1,2,true,3,HÉ,true | subclass-map=k:1:true | plain=0,2,true,1,3 | non-ctor-this=true,1,true,2 | arrow-this=true,true",
        ]
    );
}
