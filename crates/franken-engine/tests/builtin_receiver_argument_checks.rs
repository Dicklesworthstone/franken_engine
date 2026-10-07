#![forbid(unsafe_code)]

//! Receiver and argument checks of built-ins that were lenient (Test262
//! TypeError-expected cases, land33 census): collection constructors called
//! without new and their adder protocol (Get(collection, "set"/"add") must be
//! callable and a replaced or overriding adder is called per element, closing
//! the iterator when it throws); Object.getOwnPropertyNames / Symbols ToObject;
//! Error message and Error.prototype.toString ToString; String.raw's
//! ToObject / LengthOfArrayLike / ToString steps; Array.prototype keys /
//! values / entries on null or undefined; and Map / Set iterator next on an
//! incompatible receiver.

use frankenengine_engine::HybridRouter;

/// One line per group (A-J). Expected lines are Node v22.2.0's output,
/// captured programmatically from the same source.
#[test]
fn builtin_receiver_and_argument_checks_match_node() {
    let source = r#"function k(f) { try { var r = f(); return 'ok:' + typeof r; } catch (e) { return e.constructor.name; } }
console.log('A', k(function () { return Map(); }), k(function () { return Set(); }), k(function () { return WeakMap(); }), k(function () { return WeakSet(); }), k(function () { return Promise(function () {}); }));
console.log('A2', k(function () { var s = Map.prototype.set; Map.prototype.set = 1; try { return new Map([[1, 2]]); } finally { Map.prototype.set = s; } }), k(function () { var a = Set.prototype.add; Set.prototype.add = 1; try { return new Set([1]); } finally { Set.prototype.add = a; } }));
console.log('B', k(function () { return Object.getOwnPropertyNames(undefined); }), k(function () { return Object.getOwnPropertyNames(null); }), k(function () { return Object.getOwnPropertySymbols(undefined); }), k(function () { return Object.getOwnPropertyNames('ab'); }));
var sym = Symbol('s');
var bad = { toString: function () { throw new RangeError('x'); } };
console.log('C', k(function () { return new Error(sym); }), k(function () { return new TypeError(sym); }), k(function () { return new Error(bad); }), k(function () { return new AggregateError([], sym); }));
var e = new Error('m'); e.message = sym;
console.log('C2', k(function () { return e.toString(); }), k(function () { return Error.prototype.toString.call({ name: sym }); }));
console.log('D', k(function () { return String.raw(); }), k(function () { return String.raw({}); }), k(function () { return String.raw({ raw: { length: sym } }); }), k(function () { return String.raw({ raw: ['a', 'b'] }, sym); }));
console.log('E', k(function () { return Array.prototype.keys.call(undefined); }), k(function () { return Array.prototype.values.call(null); }), k(function () { return Array.prototype.entries.call(undefined); }));
var frozen = Object.freeze([1]);
var fixed = [1, 2]; Object.defineProperty(fixed, 'length', { writable: false });
console.log('F', k(function () { return frozen.push(2); }), k(function () { return fixed.pop(); }), k(function () { return fixed.shift(); }), k(function () { return fixed.unshift(0); }), k(function () { return fixed.push(3); }), JSON.stringify(fixed));
console.log('G', k(function () { return new Map().entries().next.call({}); }), k(function () { return new Set().values().next.call(new Map().entries()); }));
var log = [];
class M extends Map { set(k, v) { log.push(k); return super.set(k, v * 2); } }
var m = new M([[1, 2], [3, 4]]);
console.log('H', m.get(1), m.get(3), m.size, log.join(','));
var originalAdd = Set.prototype.add, added = [];
Set.prototype.add = function (v) { added.push(v); return originalAdd.call(this, v); };
var s2 = new Set(['a', 'b']);
Set.prototype.add = originalAdd;
var returned = 0;
var iterable = {}; iterable[Symbol.iterator] = function () { var i = 0; return { next: function () { return { value: [i, i++], done: false }; }, return: function () { returned++; return {}; } }; };
var originalSet = Map.prototype.set;
Map.prototype.set = function () { throw new RangeError('no'); };
var closeResult = k(function () { return new Map(iterable); });
Map.prototype.set = originalSet;
console.log('H2', added.join(','), s2.size, closeResult, returned);
console.log('I', String.raw({ raw: 'abc' }, 1, 2, 3), String.raw({ raw: { length: 2, 0: 'x', 1: 'y' } }, 9), String.raw({ raw: [] }), String.raw`a${1}b`, JSON.stringify(Object.getOwnPropertyNames('ab')));
console.log('J', new Error({ toString: function () { return 'custom'; } }).message, String(new TypeError(12)), k(function () { return Error.prototype.toString.call({ message: { toString: function () { throw new RangeError('m'); } } }); }));
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
            "A TypeError TypeError TypeError TypeError TypeError",
            "A2 TypeError TypeError",
            "B TypeError TypeError TypeError ok:object",
            "C TypeError TypeError RangeError TypeError",
            "C2 TypeError TypeError",
            "D TypeError TypeError TypeError TypeError",
            "E TypeError TypeError TypeError",
            "F TypeError TypeError TypeError TypeError TypeError [0,null]",
            "G TypeError TypeError",
            "H 4 8 2 1,3",
            "H2 a,b 2 RangeError 1",
            "I a1b2c x9y  a1b [\"0\",\"1\",\"length\"]",
            "J custom TypeError: 12 RangeError",
        ]
    );
}
