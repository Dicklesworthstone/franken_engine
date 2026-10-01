//! ES2020 19.1.3.6 Object.prototype.toString: the builtinTag of Dates,
//! RegExps and Errors and the standard @@toStringTag of Map, Set, WeakMap,
//! WeakSet, ArrayBuffer, DataView and typed arrays. FrankenEngine answered
//! "[object Object]" for every object except arrays, which broke the classic
//! `Object.prototype.toString.call(x) === '[object Date]'` type checks and made
//! isPlainObject-style checks accept Dates and Maps. Expected string is Node
//! v22.2.0's output.
//!
//! A String-valued data @@toStringTag on the object or its prototype chain
//! replaces the builtinTag (Math, JSON, transpiled modules' 'Module'), and the
//! engine's own string conversion of an object (`+`, templates, join) goes
//! through the same tag, or RegExp.prototype.toString for a RegExp.
//!
//! No-claim: guest-defined @@toStringTag getters and Arguments still answer
//! "[object Object]".

use frankenengine_engine::HybridRouter;

#[test]
fn builtin_objects_report_their_tags() {
    let source = "const t = x => Object.prototype.toString.call(x);\n\
                  class M extends Map {} class E extends Error {}\n\
                  [t(new Date(0)), t(/x/), t(new Map()), t(new Set()), t(new WeakMap()), t(new WeakSet()), \
                  t(new Error('e')), t(new TypeError('e')), t(new E('x')), t(new M()), t(new Uint8Array(1)), \
                  t(new Float64Array(1)), t(new ArrayBuffer(1)), t(new DataView(new ArrayBuffer(1))), t({}), \
                  t([]), t(Object.create(null)), t(Error.prototype)].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "[object Date] [object RegExp] [object Map] [object Set] [object WeakMap] [object WeakSet] \
         [object Error] [object Error] [object Error] [object Map] [object Uint8Array] \
         [object Float64Array] [object ArrayBuffer] [object DataView] [object Object] \
         [object Array] [object Object] [object Object]"
    );
}

/// The prototypes own their @@toStringTag data property (writable false,
/// enumerable false, configurable true); `Set.prototype[Symbol.toStringTag]`
/// was undefined (Test262 built-ins/Set/prototype/Symbol.toStringTag and
/// relatives), though Object.prototype.toString already named the tag.
#[test]
fn prototypes_carry_their_to_string_tag() {
    let source = "var names = ['Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'ArrayBuffer', \
                  'DataView', 'Symbol', 'BigInt', 'WeakRef', 'FinalizationRegistry'];\n\
                  var d = Object.getOwnPropertyDescriptor(Set.prototype, Symbol.toStringTag);\n\
                  [names.map(n => globalThis[n].prototype[Symbol.toStringTag]).join(), \
                  [d.value, d.writable, d.enumerable, d.configurable].join(), \
                  Object.prototype.toString.call(Object.create(Set.prototype)), \
                  Reflect.ownKeys(Map.prototype).includes(Symbol.toStringTag), \
                  Object.keys(Map.prototype).length].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "Map,Set,WeakMap,WeakSet,Promise,ArrayBuffer,DataView,Symbol,BigInt,WeakRef,\
         FinalizationRegistry Set,false,false,true [object Set] true 0"
    );
}

#[test]
fn data_to_string_tags_replace_the_builtin_tag() {
    let source = r#"const t = (x) => Object.prototype.toString.call(x);
const mod = {}; Object.defineProperty(mod, Symbol.toStringTag, { value: 'Module' });
const inherit = Object.create(mod);
const own = { [Symbol.toStringTag]: 'Own' };
const nonString = { [Symbol.toStringTag]: 42 };
const d = Object.getOwnPropertyDescriptor(Math, Symbol.toStringTag);
[t(Math), t(JSON), String(Math), `${JSON}`, t(mod), t(inherit), t(own), t(nonString), t([]), t(new Map()),
  `${own}`, own + '', d.value, d.writable, d.enumerable, d.configurable].join(' ');"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "[object Math] [object JSON] [object Math] [object JSON] [object Module] [object Module] \
         [object Own] [object Object] [object Array] [object Map] [object Own] [object Own] Math \
         false false true"
    );
}

/// RegExp.prototype.toString (ES2020 21.2.5.14) did not exist, so a RegExp
/// printed "[object RegExp]" through String() and "[object Object]" through
/// `+`; Maps, Sets and buffers converted to "[object Object]" through `+`,
/// templates and join.
#[test]
fn engine_string_conversion_uses_regexp_to_string_and_tags() {
    let source = r#"const re = /a+b/gi;
[re.toString(), String(re), '' + re, `${/x\/y/m}`, new RegExp('').toString(), [/q/y].join(), RegExp.prototype.toString.call(/z/),
  '' + new Map(), `${new Set()}`, String(new WeakMap()), '' + new ArrayBuffer(2), '' + new DataView(new ArrayBuffer(1)), [new Map()].join(), ({}) + '', typeof RegExp.prototype.toString].join(' ');"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "/a+b/gi /a+b/gi /a+b/gi /x\\/y/m /(?:)/ /q/y /z/ [object Map] [object Set] [object WeakMap] \
         [object ArrayBuffer] [object DataView] [object Map] [object Object] function"
    );
}

/// Promises, generator objects, async generator objects and iterators have
/// no property storage of their own, and ToPrimitive threw a TypeError for
/// them ("property-key carrier with native conversion methods"), so
/// `String(promise)` failed; `gen + ''` and templates said "[object Object]",
/// and a generator object had no Object.prototype members (`it.toString`
/// was undefined). They now convert through @@toPrimitive / toString /
/// valueOf read like any [[Get]] (own properties first). Iterators convert
/// too; their tag ("[object Array Iterator]" in Node) is not asserted here.
#[test]
fn exotic_values_convert_through_their_methods() {
    let source = "function* g() {} async function* ag() {}\n\
                  const it = g(); const own = g(); own.toString = () => 'mine';\n\
                  const p = Promise.resolve(1); p[Symbol.toPrimitive] = (hint) => 'P:' + hint;\n\
                  [String(g()), `${g()}`, g() + '', String(Promise.resolve(1)), `${Promise.resolve(1)}`, \
                  String(ag()), typeof it.toString, it.toString(), it.hasOwnProperty('next'), \
                  String(own), `${p}|${p + ''}`, typeof String([1][Symbol.iterator]()), \
                  typeof String(new Map().keys())].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "[object Generator] [object Generator] [object Generator] [object Promise] \
         [object Promise] [object AsyncGenerator] function [object Generator] false mine \
         P:string|P:default string string"
    );
}

/// Object.prototype.toLocaleString (ES2020 19.1.3.5) is Invoke(this,
/// "toString"); it did not exist, so `obj.toLocaleString` was undefined on
/// every object and function.
#[test]
fn object_prototype_to_locale_string_invokes_to_string() {
    let source = "let e; try { Object.prototype.toLocaleString.call(null); } catch (x) { e = x.constructor.name; }\n\
                  [({ toString() { return 'x'; } }).toLocaleString(), Object.prototype.toLocaleString.call(5), \
                  Object.prototype.toLocaleString.call('s'), typeof Object.prototype.toLocaleString, \
                  Object.prototype.toLocaleString.length, Object.prototype.toLocaleString.name, \
                  ({}).toLocaleString(), (function f() {}).toLocaleString === Object.prototype.toLocaleString, \
                  e].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "x 5 s function 0 toLocaleString [object Object] true TypeError"
    );
}
