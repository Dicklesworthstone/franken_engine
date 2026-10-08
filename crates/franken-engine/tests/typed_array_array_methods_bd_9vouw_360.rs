//! bd-9vouw.360: Array.prototype's methods that write run on a typed
//! array `this` through [[Get]]/[[Set]]/[[Delete]]: fill, copyWithin,
//! reverse and sort write into the buffer (converted, clamped, BigInt
//! checked), and push, pop, shift, unshift and splice throw the TypeError
//! that Set(O, "length") or DeletePropertyOrThrow gives, after the element
//! writes the algorithm already made. They wrote nothing and threw nothing.
//! concat keeps a typed array `this` as one element. A typed array's
//! `length`, `byteOffset` and `buffer`, an ArrayBuffer's and a DataView's
//! `byteLength` are getter-only prototype accessors: a write fails (a
//! TypeError in strict code, false from Reflect.set) instead of replacing
//! the value later reads see. Array.prototype.keys/entries over a typed
//! array whose resizable buffer shrank below it throw a TypeError from
//! next, as ta.keys() does. The lines are Node v22.2.0's (Bun 1.4.2
//! agrees on the first two; it runs the file as strict code, so its
//! sloppy writes in the third throw).

use frankenengine_engine::HybridRouter;

#[test]
fn array_prototype_methods_on_typed_arrays() {
    let source = r#"
var A = Array.prototype;
function show(v) { return Object.prototype.toString.call(v).slice(8, -1) + '[' + Array.prototype.join.call(v) + ']'; }
function ta() { return new Uint8Array([3, 1, 2, 1]); }
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name); } }
t('fill', function () { var a = ta(); A.fill.call(a, 7, 1, 3); return show(a); });
t('copyWithin', function () { var a = ta(); A.copyWithin.call(a, 0, 2); return show(a); });
t('reverse', function () { var a = ta(); return show(A.reverse.call(a)) + (A.reverse.call(a) === a); });
t('sort', function () { var a = ta(); A.sort.call(a); return show(a); });
t('sort-cmp', function () { var a = ta(); A.sort.call(a, function (x, y) { return y - x; }); return show(a); });
t('clamped', function () { var a = new Uint8ClampedArray(2); A.fill.call(a, 300); return show(a); });
t('float', function () { var a = new Float32Array(2); A.fill.call(a, 0.5); return show(a); });
t('bigint', function () { var a = new BigInt64Array(2); A.fill.call(a, 5n); return show(a); });
t('bigint-number', function () { A.fill.call(new BigInt64Array(1), 5); return 'no throw'; });
t('subarray', function () { var b = new Uint8Array([1, 2, 3, 4, 5]); A.reverse.call(b.subarray(1, 4)); return show(b); });
console.log(out.join(' '));
out = [];
function mut(name, f) { var a = ta(); try { f(a); out.push(name + '=no throw:' + show(a)); } catch (e) { out.push(name + '!' + e.constructor.name + ':' + show(a)); } }
mut('push', function (a) { A.push.call(a, 5); });
mut('pop', function (a) { A.pop.call(a); });
mut('shift', function (a) { A.shift.call(a); });
mut('unshift', function (a) { A.unshift.call(a, 0); });
mut('splice', function (a) { A.splice.call(a, 0, 1); });
mut('splice-same-length', function (a) { A.splice.call(a, 1, 2, 8, 9); });
t('concat', function () { var a = ta(); var r = A.concat.call(a, [9]); return [r.length, r[0] === a, r[1]].join(); });
t('concat-arg', function () { var r = [0].concat(ta()); return [r.length, r[1] instanceof Uint8Array].join(); });
console.log(out.join(' '));
out = [];
t('length', function () { var a = ta(); a.length = 0; return [a.length, Object.keys(a).length, Reflect.set(a, 'length', 1)].join(); });
t('length-strict', function () { 'use strict'; var a = ta(); a.length = 0; return a.length; });
t('byteOffset', function () { 'use strict'; var a = ta(); a.byteOffset = 2; return a.byteOffset; });
t('buffer', function () { var a = ta(); var b = a.buffer; a.buffer = null; return a.buffer === b; });
t('arraybuffer', function () { var b = new ArrayBuffer(4); b.byteLength = 1; return [b.byteLength, Reflect.set(b, 'byteLength', 2)].join(); });
t('dataview', function () { 'use strict'; var d = new DataView(new ArrayBuffer(4), 1); d.byteLength = 1; return d.byteLength; });
t('element', function () { var a = ta(); a[0] = 9; a.extra = 'x'; return [show(a), a.extra].join(); });
var rab = new ArrayBuffer(4, { maxByteLength: 8 });
var fixed = new Uint8Array(rab, 0, 4);
var tracking = new Uint8Array(rab);
fixed.set([1, 2, 3, 4]);
var early = A.values.call(tracking);
early.next();
rab.resize(3);
t('entries-oob', function () { return [...A.entries.call(fixed)].join(';'); });
t('keys-oob', function () { return [...A.keys.call(fixed)].join(); });
t('values-tracking', function () { return [...A.values.call(tracking)].join(); });
t('values-shrunk', function () { return [early.next().value, early.next().value, early.next().done].join(); });
rab.resize(8);
t('values-regrown', function () { return [...A.values.call(fixed)].join(); });
console.log(out.join(' '));
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
            "fill=Uint8Array[3,7,7,1] copyWithin=Uint8Array[2,1,2,1] reverse=Uint8Array[1,2,1,3]true sort=Uint8Array[1,1,2,3] sort-cmp=Uint8Array[3,2,1,1] clamped=Uint8ClampedArray[255,255] float=Float32Array[0.5,0.5] bigint=BigInt64Array[5,5] bigint-number!TypeError subarray=Uint8Array[1,4,3,2,5]",
            "push!TypeError:Uint8Array[3,1,2,1] pop!TypeError:Uint8Array[3,1,2,1] shift!TypeError:Uint8Array[1,2,1,1] unshift!TypeError:Uint8Array[0,3,1,2] splice!TypeError:Uint8Array[1,2,1,1] splice-same-length!TypeError:Uint8Array[3,8,9,1] concat=2,true,9 concat-arg=2,true",
            "length=4,4,false length-strict!TypeError byteOffset!TypeError buffer=true arraybuffer=4,false dataview!TypeError element=Uint8Array[9,1,2,1],x entries-oob!TypeError keys-oob!TypeError values-tracking=1,2,3 values-shrunk=2,3,true values-regrown=1,2,3,0",
        ]
    );
}
