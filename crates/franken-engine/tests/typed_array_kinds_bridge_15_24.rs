//! BRIDGE-15.24 (slice): all nine non-BigInt ES2020 TypedArray kinds, with
//! their element conversions, and the binary-data constructors as values.
//!
//! Only Uint8/Int32/Uint32 existed; `Float64Array` & co. were "not defined",
//! which failed every Test262 test that includes harness/testTypedArray.js at
//! load (it lists all nine constructors). Expected strings are what Node
//! v22.2.0 prints for the same programs.
//!
//! The kind tests read elements back by index; `typed_arrays_have_the_array_methods`
//! covers the %TypedArray%.prototype methods, which all used to throw
//! "unsupported TypedArray method".
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
fn float_arrays_store_numbers() {
    check(
        "const a = new Float64Array(3); a[1] = 1.5; a.length + ':' + a[1] + ':' + a[0];",
        "3:1.5:0",
    );
    // Float32 rounds through single precision.
    check("new Float32Array([1.1])[0];", "1.100000023841858");
}

#[test]
fn integer_arrays_wrap_modulo_their_width() {
    check(
        "const a = new Int8Array([127, 128, -129, 1.9]); [a[0], a[1], a[2], a[3]].join();",
        "127,-128,127,1",
    );
    check(
        "const i = new Int16Array([70000, -32769]); const u = new Uint16Array([-1, 65536]); \
         [i[0], i[1]].join() + '|' + [u[0], u[1]].join();",
        "4464,32767|65535,0",
    );
}

#[test]
fn uint8_clamped_rounds_half_to_even_and_clamps() {
    check(
        "const c = new Uint8ClampedArray([-5, 300, 1.5, 2.5, 254.5]); [c[0], c[1], c[2], c[3], c[4]].join();",
        "0,255,2,2,254",
    );
}

#[test]
fn binary_constructors_are_values() {
    check(
        "[typeof Float64Array, typeof Uint8ClampedArray, typeof ArrayBuffer, typeof DataView].join();",
        "function,function,function,function",
    );
    check("const C = Uint8Array; new C([1, 2, 300])[2];", "44");
    // The shape of harness/testTypedArray.js: constructors held in an array.
    check(
        "const cs = [Float64Array, Float32Array, Int32Array, Int16Array, Int8Array, \
         Uint32Array, Uint16Array, Uint8Array, Uint8ClampedArray]; \
         cs.map(C => new C(2).length).join();",
        "2,2,2,2,2,2,2,2,2",
    );
    check(
        "Float64Array.name + ':' + Float64Array.length + ':' + Int8Array.BYTES_PER_ELEMENT;",
        "Float64Array:3:1",
    );
}

/// ES2020 22.2.3: join / toString / indexOf / lastIndexOf / includes / at /
/// forEach / reduce / reduceRight / find / findIndex / some / every behave as
/// their Array.prototype namesakes; map and filter build a typed array of the
/// receiver's kind (map converts: 300 wraps to 44 in a Uint8Array); reverse
/// and sort reorder in place (a subarray view only its own window), and sort
/// without a comparator is numeric (-0 before 0, NaN last).
/// %TypedArray%.prototype.some and its siblings that share an Array.prototype
/// algorithm are distinct functions that ValidateTypedArray(this): another
/// receiver is a TypeError (Test262 TypedArray/prototype/some/
/// this-is-not-object and this-is-not-typedarray-instance). They were
/// Array.prototype's functions themselves; `toString` still is.
#[test]
fn typed_array_methods_require_a_typed_array() {
    check(
        "var TA = Object.getPrototypeOf(Int8Array.prototype); var r = []; \
         for (const v of [42, 'x', {}, [1]]) { try { TA.some.call(v, () => true); r.push('none'); } \
         catch (e) { r.push(e.constructor.name); } } \
         [r.join(), new Int8Array([1, 2]).some(x => x > 1), \
         Int8Array.prototype.indexOf === Array.prototype.indexOf, \
         Int8Array.prototype.toString === Array.prototype.toString, \
         Array.prototype.some.call(42, () => true), new Uint8Array([3, 4]).join('-')].join(' ')",
        "TypeError,TypeError,TypeError,TypeError true false true false 3-4",
    );
}

#[test]
fn typed_arrays_have_the_array_methods() {
    check(
        r#"const a = new Uint8Array([3, 1, 2]);
const r = [];
r.push(a.join('-'), a.toString(), String(a), `${a}`, a + '', a.indexOf(1), a.lastIndexOf(9), a.includes(2), a.at(-1));
let s = 0; a.forEach((x, i, o) => { s += x * (i + 1); r.push(o === a); });
r.push(s, a.reduce((p, x) => p + x, 0), a.reduceRight((p, x) => p + String(x), ''), a.find(x => x < 3), a.findIndex(x => x === 2), a.some(x => x > 2), a.every(x => x > 0));
const m = a.map(x => x * 100);
r.push(Object.prototype.toString.call(m), m.join(), a.filter(x => x !== 1).join(), Object.prototype.toString.call(a.filter(() => true)));
r.push(a.reverse() === a, a.join(), a.sort().join(), new Uint8Array([10, 9, 1, 100]).sort().join(), new Int8Array([5, -3, 0]).sort((x, y) => y - x).join());
const f = new Float64Array([2.5, NaN, -0, 0, -1]);
r.push(Array.from(f.sort()).map(x => Object.is(x, -0) ? '-0' : String(x)).join(), new Float32Array([1.5, 2]).map(x => x / 2).join());
const big = new Uint8Array([1, 2, 3, 4, 5]); big.subarray(1, 4).reverse(); r.push(big.join());
let threw; try { a.map(0); threw = 'no'; } catch (e) { threw = e instanceof TypeError; } r.push(threw);
r.join(' ');"#,
        "3-1-2 3,1,2 3,1,2 3,1,2 3,1,2 1 -1 true 2 true true true 11 6 213 1 2 true true \
         [object Uint8Array] 44,100,200 3,2 [object Uint8Array] true 2,1,3 1,2,3 1,9,10,100 5,0,-3 \
         -1,-0,0,2.5,NaN 0.75,1 1,4,3,2,5 true",
    );
}

#[test]
fn a_symbol_or_bigint_from_index_throws_a_type_error() {
    // ToIntegerOrInfinity(fromIndex) throws for a Symbol or BigInt. Arrays
    // read it as 0; typed arrays reach the same generic search methods, and
    // Test262 TypedArray/prototype/indexOf/return-abrupt-tointeger-fromindex-symbol
    // expects the throw.
    let probe = |call: &str| {
        format!(
            "(() => {{ try {{ {call}; return 'no throw'; }} catch (e) {{ return e.name; }} }})()"
        )
    };
    for call in [
        "[1, 2].indexOf(7, Symbol('1'))",
        "[1, 2].includes(7, Symbol('1'))",
        "[1, 2].lastIndexOf(7, Symbol('1'))",
        "[1, 2].indexOf(7, 1n)",
        "new Float64Array(1).indexOf(7, Symbol('1'))",
    ] {
        check(&probe(call), "TypeError");
    }
    check("[1, 2, 1].indexOf(1, 1)", "2");
    // lastIndexOf searches backward from fromIndex (it used to ignore it).
    check(
        "[[1, 2, 1].lastIndexOf(1, 1), [1, 2, 1].lastIndexOf(1, -2), [1, 2, 1].lastIndexOf(1, -4), \
         [1, 2, 1].lastIndexOf(1, -Infinity), [1, 2, 1].lastIndexOf(1, 99), [].lastIndexOf(1), \
         [1, 2, 1].lastIndexOf(1, '1'), [1, 2, 1].lastIndexOf(1, 1.7)].join()",
        "0,0,-1,-1,2,-1,0,0",
    );
}

/// A typed array's own keys are its indices (ES2020 9.4.5.6); `length`,
/// `buffer`, `byteLength` and the rest are %TypedArray%.prototype accessors.
/// Object.keys, JSON.stringify, for-in, spread and getOwnPropertyNames listed
/// the engine's slots (`__type`, `__typedArrayKind`, `byteLength`, ...)
/// instead of the elements.
#[test]
fn typed_array_own_keys_are_its_indices() {
    check(
        r#"const r = [];
const t = new Uint8Array([5, 6]);
r.push(Object.keys(t).join(), JSON.stringify(t), Object.entries(t).join('|'), JSON.stringify({ ...t }), Object.getOwnPropertyNames(t).join());
const k = []; for (const i in new Float64Array(2)) k.push(i); r.push(k.join());
r.push(String(t.hasOwnProperty('length')), String('length' in t), t.length, t.byteLength, String(Object.getOwnPropertyDescriptor(t, 'length')));
r.push(Reflect.ownKeys(new Int16Array(3)).join(), JSON.stringify(Object.assign({}, new Uint8Array([9]))), Object.values(new Int8Array([-1, 2])).join());
r.join(' ; ');"#,
        r#"0,1 ; {"0":5,"1":6} ; 0,5|1,6 ; {"0":5,"1":6} ; 0,1 ; 0,1 ; false ; true ; 2 ; 2 ; undefined ; 0,1,2 ; {"0":9} ; -1,2"#,
    );
}

/// `%TypedArray%.from` and `%TypedArray%.of` (ES2020 22.2.2.1-2): `typeof
/// Uint8Array.from` was "undefined" and `Uint8Array.from([1, 2])` threw
/// "expected function, got undefined". The element type is the `this`
/// constructor's; `from` takes iterables, array-likes and a mapper.
#[test]
fn typed_array_from_and_of() {
    check(
        "[Uint8Array.from([1, 2, 3]).join(), Uint8Array.of(4, 5, 300).join(), \
         Float64Array.from('12', Number).join(), \
         Int16Array.from(new Set([7, 8]), (x) => x * 2).join(), \
         Int8Array.from({ length: 2, 0: 9 }).join(), BigInt64Array.of(1n, 2n).join(), \
         BigUint64Array.from([3n]).join(), Uint8Array.from.name, Uint8Array.from.length, \
         Uint8Array.of.length, Uint8Array.from([1]) instanceof Uint8Array, \
         Int32Array.from.call(Float32Array, [1.5])[0]].join(' ')",
        "1,2,3 4,5,44 1,2 14,16 9,0 1,2 3 from 1 0 true 1.5",
    );
    check(
        "let r = []; for (const f of [() => { const g = Uint8Array.from; g([1]); }, \
         () => Uint8Array.from([1], 5), () => BigInt64Array.of(1)]) { \
         try { f(); r.push('ok'); } catch (e) { r.push(e.constructor.name); } } r.join()",
        "TypeError,TypeError,TypeError",
    );
}

/// %TypedArray% (ES2020 22.2.1): `Object.getPrototypeOf(Int8Array)` was a
/// plain object, so Test262's testTypedArray.js harness
/// (`var TypedArray = Object.getPrototypeOf(Int8Array)`) failed on
/// `TypedArray.prototype`. It is now the abstract constructor the nine
/// concrete ones inherit from, and its prototype serves the shared methods.
#[test]
fn typed_array_intrinsic() {
    check(
        "const TA = Object.getPrototypeOf(Int8Array); \
         [typeof TA, TA.name, TA.length, Object.getPrototypeOf(Int8Array.prototype) === TA.prototype, \
         Object.getPrototypeOf(TA.prototype) === Object.prototype, TA.prototype.constructor === TA, \
         new Int8Array(2) instanceof TA, \
         Object.getPrototypeOf(Int8Array) === Object.getPrototypeOf(BigUint64Array), \
         typeof TA.prototype.fill, typeof Int8Array.prototype.map, \
         Int8Array.prototype.hasOwnProperty('map'), TA.prototype.hasOwnProperty('map'), \
         Uint8Array.prototype.fill === TA.prototype.fill].join(' ')",
        "function TypedArray 0 true true true true true function function false true true",
    );
    check(
        "const TA = Object.getPrototypeOf(Int8Array); const r = []; \
         for (const f of [() => new TA(), () => TA(), () => TA.from([1])]) { \
         try { f(); r.push('ok'); } catch (e) { r.push(e.constructor.name); } } r.join()",
        "TypeError,TypeError,TypeError",
    );
}

/// A typed array inherits from its constructor's prototype (ES2020
/// 22.2.4.2.1 AllocateTypedArray), whichever way it was made: `new`,
/// `from`/`of`, over a buffer, `subarray`, `map`, `slice`, `filter`. Before
/// this every typed array's [[Prototype]] was %Object.prototype%, so
/// `instanceof Uint8Array` was false and `constructor` was Object.
#[test]
fn typed_arrays_inherit_from_their_constructor_prototype() {
    check(
        "var TA = Object.getPrototypeOf(Int8Array); \
         var a = new Int8Array(2), f = Float64Array.from([1]), u = Uint8Array.of(1), \
         s = new Int16Array(new ArrayBuffer(4)), sub = new Uint8Array([1, 2, 3]).subarray(1), \
         big = new BigInt64Array(1); var m = new Int8Array([1, 2]); \
         [a instanceof Int8Array, Object.getPrototypeOf(a) === Int8Array.prototype, \
         a.constructor === Int8Array, f instanceof Float64Array, u instanceof Uint8Array, \
         s instanceof Int16Array, sub instanceof Uint8Array, sub.constructor.name, \
         big instanceof BigInt64Array, a instanceof Object, a instanceof TA, \
         Int8Array.prototype.isPrototypeOf(a), a instanceof Uint8Array, \
         m.map((x) => x * 2) instanceof Int8Array, m.slice(1).constructor.name, \
         m.filter(Boolean) instanceof Int8Array, Object.prototype.toString.call(a), a.length, \
         a[Symbol.iterator] === Int8Array.prototype[Symbol.iterator]].join();",
        "true,true,true,true,true,true,true,Uint8Array,true,true,true,true,false,true,Int8Array,\
         true,[object Int8Array],2,true",
    );
}

/// A typed array constructed from an iterable reads it with the iteration
/// protocol (ES2020 22.2.4.4 step 6): a Set, a Map's keys, a generator, a
/// user iterable. Array-likes, arrays and typed arrays keep their indexed
/// read. A Set gave an empty typed array and a generator or iterator was
/// taken for a length (RangeError).
#[test]
fn typed_arrays_from_iterables() {
    check(
        "function* g() { yield 5; yield 6; } \
         var it = { [Symbol.iterator]() { var i = 0; return { next() { \
         return i < 2 ? { value: 10 + i++, done: false } : { done: true }; } }; } }; \
         [new Uint8Array(new Set([1, 2, 3])).join(), new Float64Array(new Map([[1.5, 2]]).keys()).join(), \
         new Int16Array(g()).join(), new Uint8Array(it).join(), new Uint8Array({ length: 2, 0: 7 }).join(), \
         new Uint8Array([1, 2]).join(), new Int8Array(new Int8Array([3, 4])).join()].join(' | ');",
        "1,2,3 | 1.5 | 5,6 | 10,11 | 7,0 | 1,2 | 3,4",
    );
}

/// A canonical numeric string that is not a valid index ("1.1", "-0",
/// "Infinity", an index past the end) is never an element and is not looked
/// up on the prototype (ES2020 9.4.5.2 and 9.4.5.4); "01" is an ordinary
/// key. With typed arrays inheriting %TypedArray%.prototype, a "1.1" defined
/// there answered `in` and reads (Test262 internals/HasProperty/BigInt/
/// key-is-not-integer).
#[test]
fn canonical_numeric_keys_skip_the_prototype() {
    check(
        "var ta = new Int8Array(2); var TAProto = Object.getPrototypeOf(Int8Array.prototype); \
         TAProto['1.1'] = 1; TAProto['-0'] = 1; TAProto['01'] = 1; TAProto['Infinity'] = 1; \
         TAProto['5'] = 1; \
         [('1.1' in ta), ('-0' in ta), ('0' in ta), ('1' in ta), ('5' in ta), ('Infinity' in ta), \
          ('01' in ta), Reflect.has(ta, '1.1'), ta['1.1'], ta['01'], ta['5']].join();",
        "false,false,true,true,false,false,true,false,,1,",
    );
}

/// bd-9vouw.267: a typed array's numeric keys follow the integer-indexed
/// exotic object methods (ES2024 10.4.5). [[Set]] on the array converts the
/// value (valueOf runs and may throw; a BigInt for a Number array or a
/// Symbol is a TypeError) and writes only a valid index: "-0", "1.1", "-1",
/// "Infinity" and indices past the end create no property. Through another
/// receiver a valid index defines the receiver's own property and an
/// invalid one does nothing. [[DefineOwnProperty]] writes a given value and
/// refuses invalid indices and non-configurable, non-enumerable,
/// non-writable or accessor descriptors; [[GetOwnProperty]] describes an
/// element as a writable, enumerable, configurable data property. Expected
/// lines are Node v22.2.0's output, captured programmatically; Bun 1.4.2
/// agrees except on line 8, where it creates `viaProto[3]` against
/// 10.4.5.5 step 1.b.ii.
#[test]
fn typed_array_numeric_keys_are_integer_indexed_bd_9vouw_267() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var ta = new Float64Array(2);
ta['-0'] = 1; ta['1.1'] = 2; ta['-1'] = 3; ta['2'] = 4; ta['Infinity'] = 5; ta['01'] = 6;
console.log(JSON.stringify(Object.keys(ta)), ta.hasOwnProperty('-0'), ta.hasOwnProperty('1.1'), ta.hasOwnProperty('2'), ta['01'], ta['-0'], '1.1' in ta, String(ta));
var calls = 0;
var counted = { valueOf: function () { calls++; return 7; } };
ta['5'] = counted; ta['-0'] = counted; ta[0] = counted;
console.log(calls, ta[0]);
console.log(kind(function () { ta[1] = 1n; }), kind(function () { ta['9'] = Symbol(); }), kind(function () { ta[0] = { valueOf: function () { throw new RangeError('v'); } }; }));
var big = new BigInt64Array(1);
console.log(kind(function () { big[0] = 1; }), kind(function () { big['-0'] = 2; }), kind(function () { big[0] = '7'; return big[0]; }), kind(function () { big[0] = { valueOf: function () { return 9n; } }; return big[0]; }));
var d = new Int32Array(2);
console.log(Reflect.defineProperty(d, '0', { value: 8 }), d[0], Reflect.defineProperty(d, '0', { value: 9, configurable: true, enumerable: true, writable: true }), d[0]);
console.log(Reflect.defineProperty(d, '2', { value: 1 }), Reflect.defineProperty(d, '-0', { value: 1 }), Reflect.defineProperty(d, '0.5', { value: 1 }), Reflect.defineProperty(d, '0', { value: 1, configurable: false }), Reflect.defineProperty(d, '0', { value: 1, enumerable: false }), Reflect.defineProperty(d, '0', { value: 1, writable: false }), Reflect.defineProperty(d, '0', { get: function () { return 1; } }), d[0]);
console.log(kind(function () { Object.defineProperty(d, '5', { value: 1 }); }), kind(function () { Object.defineProperty(d, '1', { value: { valueOf: function () { throw new RangeError('d'); } } }); }), Reflect.defineProperty(d, 'x', { value: 3 }), d.x, JSON.stringify(Object.getOwnPropertyDescriptor(d, '1')));
var target = new Int32Array([5]);
var viaProto = Object.create(target);
viaProto[0] = 11; viaProto[3] = 12;
console.log(target[0], viaProto.hasOwnProperty('0'), viaProto[0], viaProto.hasOwnProperty('3'), viaProto[3]);
var receiver = {};
console.log(Reflect.set(target, 0, 13, receiver), target[0], receiver[0], Reflect.set(target, 4, 14, receiver), receiver.hasOwnProperty('4'));
var inner = new Int32Array(10);
var outer = Object.create(inner);
calls = 0;
console.log(Reflect.set(outer, 100, counted, inner), calls, inner.hasOwnProperty('100'));
var d = new Int32Array(2);
console.log(JSON.stringify(Object.getOwnPropertyDescriptor(d, '1')), JSON.stringify(Object.getOwnPropertyDescriptor(d, '2')), JSON.stringify(Object.getOwnPropertyDescriptor(d, '-0')), d.hasOwnProperty(1), d.hasOwnProperty(2), 1 in d, 2 in d, '-0' in d, delete d[2], delete d['-0']);
console.log(Reflect.deleteProperty(d, '0'), d.propertyIsEnumerable(0), JSON.stringify(Reflect.ownKeys(d)));
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
            "[\"0\",\"1\",\"01\"] false false false 6 undefined false 0,0",
            "3 7",
            "TypeError TypeError RangeError",
            "TypeError TypeError 7 9",
            "true 8 true 9",
            "false false false false false false false 9",
            "TypeError RangeError true 3 {\"value\":0,\"writable\":true,\"enumerable\":true,\"configurable\":true}",
            "5 true 11 false undefined",
            "true 5 13 true false",
            "true 1 false",
            "{\"value\":0,\"writable\":true,\"enumerable\":true,\"configurable\":true} undefined undefined true false true false false true true",
            "false true [\"0\",\"1\"]",
        ]
    );
}

/// bd-9vouw.269: `%TypedArray%.prototype.join` converts its separator with
/// ToString (a separator object's toString runs once; a Symbol throws) after
/// taking the length, so elements past a shrink the conversion caused join
/// as "" (ES2024 23.2.3.18). `%TypedArray%.prototype.set` from an
/// array-like (SetTypedArrayFromArrayLike, 23.2.3.26.2) is ToObject of the
/// source, LengthOfArrayLike, the range check, then Get, conversion and
/// write per element in order: a string source sets its characters, an
/// abrupt Get or valueOf leaves the earlier elements written, a hole reads
/// undefined. Expected lines are Node v22.2.0's output, captured
/// programmatically; Bun 1.4.2 agrees.
#[test]
fn typed_array_join_and_set_convert_observably_bd_9vouw_269() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var calls = [];
var sep = { toString: function () { calls.push('sep'); return '|'; } };
var ta = new Float64Array([1, -0, 2.5, NaN]);
console.log(ta.join(sep), calls.join(), ta.join(), ta.join(''), ta.join(undefined), ta.join(null), new BigInt64Array([1n, -2n]).join(sep));
console.log(kind(function () { return ta.join(Symbol()); }), kind(function () { return ta.join({ toString: function () { throw new RangeError('s'); } }); }), JSON.stringify(new Uint8Array(0).join(sep)));
var rab = new ArrayBuffer(4, { maxByteLength: 8 });
var tracking = new Uint8Array(rab);
console.log(JSON.stringify(tracking.join({ toString: function () { rab.resize(2); return '.'; } })), JSON.stringify(new Uint8Array(new ArrayBuffer(4, { maxByteLength: 8 })).join({ toString: function () { return '-'; } })));
var rab2 = new ArrayBuffer(3, { maxByteLength: 8 });
var grow = new Uint8Array(rab2);
console.log(JSON.stringify(grow.join({ toString: function () { rab2.resize(6); return ','; } })));
var order = [];
var target = new Float64Array(4);
var source = { length: 3, get 0() { order.push('get0'); return { valueOf: function () { order.push('conv0'); return 7; } }; }, get 1() { order.push('get1'); return '8'; }, get 2() { order.push('get2'); throw new RangeError('g'); } };
console.log(kind(function () { target.set(source); }), order.join(), String(target));
var t2 = new Int8Array(4);
console.log(kind(function () { t2.set([1, { valueOf: function () { throw new TypeError('c'); } }, 3]); }), String(t2), kind(function () { t2.set([Symbol()]); }), kind(function () { t2.set([1n]); }));
var t3 = new Uint8Array(5);
t3.set('123', 1); t3.set(42); t3.set(true);
console.log(String(t3), kind(function () { t3.set('123456'); }), kind(function () { t3.set({ length: 2, 0: 5, 1: 6 }, 4); }), kind(function () { t3.set(undefined); }));
var big = new BigInt64Array(3);
big.set([1n, { valueOf: function () { return 2n; } }, '3']);
console.log(String(big), kind(function () { big.set([1]); }), kind(function () { big.set(new Uint8Array(1)); }));
var t4 = new Uint8Array([9, 9, 9]);
t4.set([1, 2]); t4.set(new Uint16Array([300]), 2);
console.log(String(t4), String(new Float32Array([1.5, 2.5]).subarray(0)), String((function () { var a = new Int16Array(4); a.set([1, , 3]); return a; })()));
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
            "1|0|2.5|NaN sep 1,0,2.5,NaN 102.5NaN 1,0,2.5,NaN 1null0null2.5nullNaN 1|-2",
            "TypeError RangeError \"\"",
            "\"0.0..\" \"0-0-0-0\"",
            "\"0,0,0\"",
            "RangeError get0,conv0,get1,get2 7,8,0,0",
            "TypeError 1,0,0,0 TypeError TypeError",
            "0,1,2,3,0 RangeError RangeError TypeError",
            "1,2,3 TypeError TypeError",
            "1,2,44 1.5,2.5 1,0,3,0",
        ]
    );
}

/// bd-9vouw.273: constructing a builtin through Reflect.construct reads
/// Get(newTarget, "prototype") first and falls
/// back to the builtin's own intrinsic prototype when that is not an object;
/// ArrayBuffer, DataView and the typed array constructors called without
/// `new` throw a TypeError; and a typed array built from a list, an
/// iterable, an array-like, `from` or `of` converts each element with
/// ToNumber/ToBigInt (valueOf runs; a Symbol or a BigInt for a Number array
/// throws), collecting an iterable's values before converting any, and
/// allocating an array-like's length (a RangeError when impossible) before
/// reading its elements. Expected lines are Node v22.2.0's output, captured
/// programmatically; Bun 1.4.2 agrees.
#[test]
fn builtin_construction_reads_new_target_and_converts_elements_bd_9vouw_273() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var log = [];
var obj = function (n) { return { valueOf: function () { log.push('v' + n); return n; } }; };
console.log(String(new Float64Array([obj(1), 2, obj(3)])), log.join());
log = [];
var values = [0, { valueOf: function () { values.length = 0; return 100; } }, 2];
console.log(String(new Float64Array(values)), String(new Int8Array(new Set([1, obj(2)]))), log.join());
log = [];
var arrayLike = { length: 2, get 0() { log.push('g0'); return obj(5); }, get 1() { log.push('g1'); return 6; } };
console.log(String(new Uint8Array(arrayLike)), log.join(), kind(function () { return new Uint8Array([{ valueOf: function () { throw new RangeError('x'); } }]); }), kind(function () { return new Uint8Array([Symbol()]); }), kind(function () { return new Uint8Array([1n]); }));
console.log(kind(function () { return new Uint8Array({ length: Math.pow(2, 53) - 1 }); }), kind(function () { return Uint8Array([1]); }), kind(function () { return Float64Array(2); }), kind(function () { return ArrayBuffer(8); }), kind(function () { return DataView(new ArrayBuffer(1)); }));
function F() {}
F.prototype = null;
var viaNull = Reflect.construct(Float64Array, [2], F);
var map = Reflect.construct(Map, [], (function () { var G = function () {}; G.prototype = 1; return G; })());
console.log(Object.getPrototypeOf(viaNull) === Float64Array.prototype, viaNull.length, Object.getPrototypeOf(map) === Map.prototype);
class Bytes extends Uint8Array { first() { return this[0]; } }
var b = new Bytes([7, 8]);
console.log(b.first(), b.length, b instanceof Uint8Array, String(Uint8Array.from([1, obj(2)])), String(Uint8Array.of(3, obj(4))), String(new Uint8Array(3)), String(b.subarray(1)), String(new Uint16Array(new Uint8Array([1, 2]))));
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
            "1,2,3 v1,v3",
            "0,100,2 1,2 v2",
            "5,6 g0,v5,g1 RangeError TypeError TypeError",
            "RangeError TypeError TypeError TypeError TypeError",
            "true 2 true",
            "7 2 true 1,2 3,4 0,0,0 8 1,2",
        ]
    );
}
