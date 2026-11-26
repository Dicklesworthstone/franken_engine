//! An object whose prototype chain goes through an array inherits the
//! Array.prototype builtins (`F.prototype = [...]`, `Object.create([])`).
//!
//! Only an array itself exposed them: the engine serves Array.prototype's
//! methods without allocating that object, and the fallback looked at the
//! root object only, so `new F().reduce(...)` was "expected function, got
//! undefined" (Test262 Array/prototype/reduce/15.4.4.21-10-6 and relatives).
//! Expected lines are Node v22.2.0's (`node -e`).

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "constructor_prototype_is_an_array",
        r#"function foo() {} foo.prototype = [1, 2, 3, 4]; const f = new foo(); console.log(f.reduce((a, b) => a + b, -1), f.length, 'map' in f, f.constructor === Array, Array.isArray(f));"#,
        "9 4 true true false",
    ),
    (
        "object_create_array",
        r#"const o = Object.create(['x', 'y']); console.log(o.join('-'), o.indexOf('y'), o.slice(1).length, typeof o.push);"#,
        "x-y 1 1 function",
    ),
    (
        "own_property_still_wins",
        r#"function Stack() {} Stack.prototype = []; Stack.prototype.push = function (v) { return 'custom ' + v; }; const s = new Stack(); console.log(s.push(1), typeof s.pop);"#,
        "custom 1 function",
    ),
    // The generic methods read `length` and the elements through the chain
    // ([[Get]]), not the receiver's own properties only.
    (
        "generic_methods_read_inherited_elements",
        r#"const o = Object.create(['x', 'y']); console.log(Array.prototype.join.call(o, '-'), Array.prototype.slice.call(o).length, [].concat(Array.prototype.map.call(o, (v) => v + v)).join());"#,
        "x-y 2 xx,yy",
    ),
    (
        "push_on_an_inherited_length_writes_own_properties",
        r#"function foo() {} foo.prototype = [1, 2, 3, 4]; const f = new foo(); f.push(5); console.log(f.length, Object.keys(f).join(), f.reduce((a, b) => a + b), f.lastIndexOf(2), f.includes(4));"#,
        "5 4,length 15 1 true",
    ),
    (
        "array_like_prototype",
        r#"const o = Object.create({ length: 2, 0: 'a', 1: 'b' }); console.log(Array.prototype.join.call(o), Array.from(o).join('|'));"#,
        "a,b a|b",
    ),
    // %Array.prototype%[@@iterator] is %Array.prototype.values%, read from
    // Array.prototype itself and from objects inheriting from it; it was
    // undefined there, so `[...Object.create(Array.prototype)]` threw.
    (
        "array_prototype_iterator",
        r#"const o = Object.create(Array.prototype); o.length = 2; o[0] = 'a'; o[1] = 'b'; console.log([typeof Array.prototype[Symbol.iterator], Array.prototype[Symbol.iterator] === Array.prototype.values, [][Symbol.iterator] === Array.prototype.values, typeof o[Symbol.iterator], [...o].join('+'), Array.from(o).length].join(' '));"#,
        "function true true function a+b 2",
    ),
    // ToLength of a primitive `length`: a string is StringToNumber and a
    // boolean 0 or 1; a string length read as 0.
    (
        "string_and_boolean_lengths",
        r#"var o1 = { 229: 229, 230: 230, length: '2.3E2' }, o2 = { 0: 12, 1: 11, 2: 9, length: '2.5' }, o3 = { 0: 11, 1: 9, 2: 12, length: '0x0002' }, o4 = { 0: 'a', 1: 'b', length: true }, o5 = { 0: 'a', length: -3 }, o6 = { 0: 'a', 1: 'b', length: ' 2 ' }, o7 = { 0: 'a', length: 'abc' }; console.log([Array.prototype.lastIndexOf.call(o1, 229), Array.prototype.lastIndexOf.call(o1, 230), Array.prototype.every.call(o2, (v) => v > 10), Array.prototype.map.call(o3, (v) => v < 10).length, Array.prototype.join.call(o4), JSON.stringify(Array.prototype.join.call(o5)), Array.prototype.slice.call(o6).join(''), Array.from(o6).length, Array.prototype.indexOf.call(o7, 'a')].join(' '));"#,
        r#"229 -1 true 2 a "" ab 2 -1"#,
    ),
    (
        "hole_reads_object_prototype_index",
        r#"const a = [1, , 3]; Object.prototype[1] = 'P'; console.log(a.join('-'), a.indexOf('P')); delete Object.prototype[1];"#,
        "1-P-3 1",
    ),
    // On an object that is not an Array the methods run over [[Get]]: a
    // `length` getter or an element getter was read as missing (length 0),
    // and a getter shadowing an inherited length was skipped for it (Test262
    // Array/prototype/some/15.4.4.17-2-8 and relatives).
    (
        "array_like_getters",
        r#"var o = { 1: 'y' }; Object.defineProperty(o, '0', { get() { return 'x'; } }); Object.defineProperty(o, 'length', { get() { return 2; } }); var c = Object.create({ length: 3 }); Object.defineProperty(c, 'length', { get() { return 2; } }); c[0] = 9; c[1] = 11; c[2] = 12; console.log(Array.prototype.some.call(o, (v) => v === 'y'), Array.prototype.indexOf.call(o, 'y'), Array.prototype.join.call(o), Array.prototype.map.call(o, (v) => v + v).join(), Array.prototype.some.call(c, (v) => v > 11));"#,
        "true 1 x,y xx,yy false",
    ),
    // A primitive `this` is ToObject'd: `map.call('abc', f)` and a boolean
    // or number receiver were TypeErrors; a String wrapper's length bounds
    // an inherited index; toString without a callable join is
    // Object.prototype.toString.
    (
        "primitive_receivers",
        r#"String.prototype[3] = '3'; console.log(Array.prototype.map.call('abc', (c) => c.toUpperCase()).join(''), Array.prototype.forEach.call(true, (x) => x), JSON.stringify(Array.prototype.join.call(5)), Array.prototype.toString.call(true), Array.prototype.toString.call({ join: 1 }), Array.prototype.lastIndexOf.call(new String('012'), '2'), Array.prototype.lastIndexOf.call(new String('012'), '3')); delete String.prototype[3];"#,
        r#"ABC undefined "" [object Boolean] [object Object] 2 -1"#,
    ),
    // IsConcatSpreadable: a defined @@isConcatSpreadable decides over IsArray.
    (
        "is_concat_spreadable",
        r#"var re = /abc/; re[Symbol.isConcatSpreadable] = true; re.length = 2; re[0] = 1; re[1] = 2; var a = [1, 2]; a[Symbol.isConcatSpreadable] = false; var al = { length: 1, 0: 'z', [Symbol.isConcatSpreadable]: true }; console.log(JSON.stringify([0].concat(re)), [].concat(a).length, JSON.stringify([9].concat(a)), JSON.stringify(Array.prototype.concat.call(al, al)));"#,
        r#"[0,1,2] 1 [9,[1,2]] ["z","z"]"#,
    ),
    // An Array's index/count arguments and join's separator are ToNumber'd /
    // ToString'd with guest calls: an object argument's valueOf/toString
    // runs (the element-storage paths read it as NaN / "[object Object]").
    (
        "object_index_arguments",
        r#"var n = { valueOf() { return 1; } }; console.log([1, 2, 3].slice(n).join(), [1, 2, 3].indexOf(2, n), [1, 2, 3].at(n), new Array(3).fill(0, n).join(), [3, 2, 1].includes(3, n), [1, 2].join({ toString() { return '+'; } }), [1, 2, 3].splice(n, n).join(), [1, 2].with(n, 9).join(), [{ a: 1 }].indexOf({ a: 1 }));"#,
        "2,3 1 2 ,0,0 false 1+2 2 1,9 -1",
    ),
    // A hole-skipping method over a huge sparse array-like visits the
    // present indices only (the generic path probed every one of 2^32 and
    // ran out of budget). Node v22.2.0 prints the same values; for the first
    // (not-found) case it takes tens of seconds, probing each index.
    (
        "huge_sparse_array_likes",
        r#"console.log(Array.prototype.indexOf.call({ length: 4294967296 }, 1), Array.prototype.indexOf.call({ length: 2 ** 32, 7: 'x' }, 'x'), Array.prototype.some.call({ length: 2 ** 32, 3: 1 }, (v) => v === 1), Array.prototype.lastIndexOf.call({ length: 2 ** 17, 5: 'a', 9: 'a' }, 'a'), Array.prototype.reduce.call({ length: 2 ** 20, 1: 'p', 100: 'q' }, (acc, v, i) => acc + v + i, ''));"#,
        "-1 7 true 9 p1q100",
    ),
    (
        "arguments_and_plain_array_likes",
        r#"function f() { return Array.prototype.slice.call(arguments, 1).concat(Array.prototype.map.call(arguments, (x) => x * 10)); } var o2 = { length: 2 }; Array.prototype.push.call(o2, 'a'); var s = { length: 2, 0: 'b', 1: 'a' }; Array.prototype.sort.call(s); var sorted = s[0] + s[1]; Array.prototype.reverse.call(s); console.log(f(1, 2, 3).join(), JSON.stringify(o2), sorted, s[0] + s[1], Array.prototype.reduceRight.call({ length: 3, 0: 'a', 1: 'b', 2: 'c' }, (acc, v) => acc + v));"#,
        r#"2,3,10,20,30 {"2":"a","length":3} ab ba cba"#,
    ),
    // Array.prototype.toLocaleString (ES2020 22.1.3.27) and the typed array
    // one (22.2.3.28): each element's toLocaleString, "," between. The first
    // did not exist; the second was an "unsupported TypedArray method".
    (
        "to_locale_string",
        r#"let e; try { Uint8Array.prototype.toLocaleString.call([1]); } catch (x) { e = x.constructor.name; } console.log([[1234, 'a', null, undefined, 5.5].toLocaleString(), [{ toLocaleString() { return 'X'; } }, [1, 2]].toLocaleString(), Array.prototype.toLocaleString.call('ab'), new Uint8Array([1, 200]).toLocaleString(), typeof Array.prototype.toLocaleString, [].toLocaleString() === '', Array.prototype.toLocaleString.call({ length: 2, 0: 3 }), [1234567.891].toLocaleString(), e].join(' | '));"#,
        "1,234,a,,,5.5 | X,1,2 | a,b | 1,200 | function | true | 3, | 1,234,567.891 | TypeError",
    ),
    // `class T extends Array {}`: `new T(1, 2, 3)` (a non-spread super call
    // or the implicit constructor) gets its elements and `length` (it had
    // neither), `new T(3)` an empty array of length 3. indexOf, lastIndexOf
    // and includes find functions and other non-heap objects by identity
    // (`[f].includes(f)` was false), which Redux Toolkit's
    // `finalEnhancers.includes(middlewareEnhancer)` check relies on.
    (
        "array_subclass_construction_and_identity_search",
        r#"class T extends Array {} const f = () => 1; const a = new T(1, 2, 3), b = new T(3), c = new T('a'), d = new T(); class U extends Array { constructor(x, y) { super(x, y); } } console.log([a.length, a[1], b.length, b[0] === undefined, c.length, c[0], d.length, a instanceof T, Array.isArray(a), new U(7, 8).length, [f].includes(f), [f].indexOf(f), [1, f].lastIndexOf(f), [Promise].indexOf(Promise), a.includes(2)].join(' '));"#,
        "3 2 3 true 1 a 0 true true 2 true 0 1 0 true",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    console_output_with_config(source, InterpreterConfig::quickjs_defaults(), None)
}

fn lower_source(source: &str) -> Result<Ir3Module, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "arrayproto.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    Ok(lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "arrayproto.js"),
        &LoweringContext::new(
            "arrayproto-trace",
            "arrayproto-decision",
            "arrayproto-policy",
        ),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3)
}

fn console_output_with_config(
    source: &str,
    mut config: InterpreterConfig,
    stress: Option<u64>,
) -> Result<String, String> {
    let module = lower_source(source)?;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "arrayproto");
    core.set_gc_stress_interval(stress);
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    let result = result.map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn array_prototype_through_the_chain_matches_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

#[test]
fn ordinary_and_borrowed_join_preserve_exact_units_and_observable_order() {
    let source = r#"
function units(text) {
  let output = '';
  for (let i = 0; i < text.length; i++) {
    if (i !== 0) output += ',';
    output += text.charCodeAt(i);
  }
  return output;
}
const high = '\ud800', low = '\udc00';
console.log(units(['a', 'é' + high + '🚀'].join('')));
console.log(units(Array.prototype.join.call({0:'a', 1:'é' + high + '🚀', length:2}, '')));
console.log(units([high, low].join('')), units([high, low].join('\udfff')));
console.log(units([[high], [low]].join('')), units([high, null, undefined, low].join('')));
console.log(units(String([high])));
const cycle = [high]; cycle.push(cycle, null);
console.log(units(cycle.join('')));
const order = [], token = {};
const source = {length:3,
  get 0() {order.push('0'); return high;},
  get 1() {order.push('1'); throw token;},
  get 2() {order.push('2'); return low;}};
let caught = false;
try { Array.prototype.join.call(source, {toString() {order.push('S'); return low;}}); }
catch (error) {caught = error === token;}
console.log(caught, order.join(''));
const converted = [{toString() {return high;}}, {toString() {return low;}}];
console.log(units(converted.join({toString() {return '';}})));
"#;
    let expected = "97,233,55296,55357,56960\n97,233,55296,55357,56960\n55296,56320 55296,57343,56320\n55296,56320 55296,56320\n55296\n55296\ntrue S01\n55296,56320";
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for stress in [None, Some(1), Some(7)] {
            assert_eq!(
                console_output_with_config(source, config.clone(), stress).as_deref(),
                Ok(expected),
                "GC={stress:?}"
            );
        }
    }
}

fn assert_locale_output(source: &str, expected: &str) {
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for stress in [None, Some(1), Some(7)] {
            assert_eq!(
                console_output_with_config(source, config.clone(), stress).as_deref(),
                Ok(expected),
                "GC={stress:?}: {source}"
            );
        }
    }
}

// The locale regression outputs below were observed with Node v24.22.3.
#[test]
fn locale_string_forwards_two_uncoerced_arguments_to_each_element() {
    let source = r#"
const locales = {mustStayOpaque:true}, options = {mustStayOpaque:true}, calls = [];
const element = {toLocaleString(l, o) {
  calls.push([this === element, arguments.length, l === locales, o === options].join('/'));
  return 'X';
}};
console.log([element, null, undefined, [element]].toLocaleString(locales, options, 'ignored'));
console.log(calls.join('|'));
let defaults = '';
console.log([{toLocaleString(l, o) {
  defaults = [arguments.length, l === undefined, o === undefined].join('/');
  return 7;
}}].toLocaleString(), defaults);
const inaccessible = new Proxy({}, {get() {throw 'read options';}});
console.log([null, undefined].toLocaleString(inaccessible, inaccessible) === ',');
console.log([1234.5, 2].toLocaleString('de-DE', {useGrouping:false, minimumFractionDigits:2}));
console.log(new Float64Array([1234.5, 2]).toLocaleString('de-DE', {useGrouping:false, minimumFractionDigits:2}));
console.log([1234n, 2n].toLocaleString('en-US', {useGrouping:false}));
console.log(new BigInt64Array([1234n, 2n]).toLocaleString('en-US', {useGrouping:false}));
"#;
    assert_locale_output(
        source,
        "X,,,X\ntrue/2/true/true|true/2/true/true\n7 2/true/true\ntrue\n1234,50,2,00\n1234,50,2,00\n1234,2\n1234,2",
    );
}

#[test]
fn locale_string_is_generic_on_callable_and_exotic_receivers() {
    let source = r#"
const order = [];
function callable(a,b) {}
Object.defineProperty(callable, 'length', {get() {
  order.push(this === callable ? 'length' : 'bad');
  return {valueOf() {order.push('coerce'); return 2;}};
}});
Object.defineProperty(callable, '0', {get() {
  order.push(this === callable ? '0' : 'bad');
  return {toLocaleString() {
    order.push('call0'); callable[1] = 'changed'; callable[2] = 'late'; return 'first';
  }};
}});
callable[1] = 'old';
console.log(Array.prototype.toLocaleString.call(callable), order.join('/'));
const bound = function(a,b) {}.bind(null); bound[0] = 'B'; bound[1] = 'C';
console.log(Array.prototype.toLocaleString.call(bound));
const proxyOrder = [];
const target = function(a,b) {}; target[0] = 'P'; target[1] = 'Q';
const proxy = new Proxy(target, {get(t,k,r) {
  proxyOrder.push(String(k) + ':' + (r === proxy)); return Reflect.get(t,k,r);
}});
console.log(Array.prototype.toLocaleString.call(proxy), proxyOrder.join('/'));
const promise = Promise.resolve(0); promise.length = 2; promise[0] = 'promise'; promise[1] = null;
const generator = (function* () {})(); generator.length = 1; generator[0] = 'generator';
const iterator = [1].values(); iterator.length = 1; iterator[0] = 'iterator';
console.log(Array.prototype.toLocaleString.call(promise), Array.prototype.toLocaleString.call(generator), Array.prototype.toLocaleString.call(iterator));
console.log(Array.prototype.toLocaleString.call('ab'), Array.prototype.toLocaleString.call(true) === '');
"#;
    assert_locale_output(
        source,
        "first,changed length/coerce/0/call0\nB,C\nP,Q length:true/0:true/1:true\npromise, generator iterator\na,b true",
    );
}

#[test]
fn locale_string_preserves_exact_utf16_across_guest_conversions() {
    let source = r#"
function units(text) {
  const output = [];
  for (let i=0;i<text.length;i++) output.push(text.charCodeAt(i));
  return output.join(',');
}
const high = '\ud800', low = '\udc00';
const a = {toLocaleString() {return high;}}, b = {toLocaleString() {return low;}};
console.log(units([a, b].toLocaleString()));
console.log(units([['é' + high + '🚀'], [low]].toLocaleString()));
console.log(units(Array.prototype.toLocaleString.call(high + low)));
console.log(units(Array.prototype.toLocaleString.call({0:a, 2:b, length:3})));
const order = [];
const value = {get toLocaleString() {
  order.push('get');
  return function() {
    order.push(this === value ? 'call' : 'bad');
    return {[Symbol.toPrimitive](hint) {order.push(hint); return high;}};
  };
}};
console.log(units([value].toLocaleString()), order.join('/'));
const old = Number.prototype.toLocaleString;
try {
  Number.prototype.toLocaleString = function() {return Number(this) === 1 ? high : low;};
  console.log(units(new Uint8Array([1,2]).toLocaleString()));
} finally {Number.prototype.toLocaleString = old;}
"#;
    assert_locale_output(
        source,
        "55296,44,56320\n233,55296,55357,56960,44,56320\n55296,44,56320\n55296,44,44,56320\n55296 get/call/string\n55296,44,56320",
    );
}

#[test]
fn typed_locale_string_uses_internal_length_and_observes_mid_call_resize() {
    let source = r#"
const own = new Uint8Array([1,2]); let reads = 0;
Object.defineProperty(own, 'length', {get() {reads++; return 1;}});
console.log(own.toLocaleString(), Array.prototype.toLocaleString.call(own), reads);
const throwLength = new Uint8Array([3,4]), token = {};
Object.defineProperty(throwLength, 'length', {get() {throw token;}});
let caught = false;
try {Array.prototype.toLocaleString.call(throwLength);} catch(error) {caught = error === token;}
console.log(throwLength.toLocaleString(), caught);
const buffer = new ArrayBuffer(3, {maxByteLength:3}), view = new Uint8Array(buffer);
view.set([1,2,3]); const locales = {}, options = {}; let calls = '';
const old = Number.prototype.toLocaleString;
try {
  Number.prototype.toLocaleString = function(l,o) {
    calls += [Number(this), arguments.length, l === locales, o === options].join('/') + ';';
    buffer.resize(1); return String(Number(this));
  };
  console.log(view.toLocaleString(locales, options), calls, view.length);
} finally {Number.prototype.toLocaleString = old;}
const fixedBuffer = new ArrayBuffer(3, {maxByteLength:3}), fixed = new Uint8Array(fixedBuffer, 0, 3);
fixedBuffer.resize(1);
let invalid = '';
for (const receiver of [[], new Proxy(new Uint8Array([1]), {}), fixed]) {
  try {Uint8Array.prototype.toLocaleString.call(receiver); invalid += 'miss/';}
  catch(error) {invalid += error.constructor.name + '/';}
}
console.log(invalid, Array.prototype.toLocaleString.call(fixed) === '');
"#;
    assert_locale_output(
        source,
        "1,2 1 1\n3,4 true\n1,, 1/2/true/true; 1\nTypeError/TypeError/TypeError/ true",
    );
}

#[test]
fn locale_string_stops_at_abrupt_completions_and_releases_output_capacity() {
    let source = r#"
const traces = [], thrown = {};
let lengthReads = 0;
const source = {
  get length() {lengthReads++; return 3;},
  get 0() {
    traces.push('0');
    return {get toLocaleString() {
      traces.push('method');
      return function() {
        traces.push('call'); return {toString() {traces.push('string'); throw thrown;}};
      };
    }};
  },
  get 1() {traces.push('1'); return 'bad';}
};
let same = false;
try {Array.prototype.toLocaleString.call(source);} catch(error) {same = error === thrown;}
console.log(same, lengthReads, traces.join('/'));
let negative = '';
for (const receiver of [null, undefined]) {
  try {Array.prototype.toLocaleString.call(receiver); negative += 'miss/';}
  catch(error) {negative += error.constructor.name + '/';}
}
for (const element of [
  {toLocaleString:1}, {toLocaleString(){return Symbol();}},
  {get toLocaleString(){throw thrown;}}, {toLocaleString(){throw thrown;}}
]) {
  try {[element].toLocaleString(); negative += 'miss/';}
  catch(error) {negative += (error === thrown ? 'token' : error.constructor.name) + '/';}
}
const revoked = Proxy.revocable({length:1, 0:'bad'}, {}); revoked.revoke();
try {Array.prototype.toLocaleString.call(revoked.proxy);}
catch(error) {negative += error.constructor.name;}
console.log(negative);
let released = false;
try {
  [{toLocaleString() {return '\ud800'.repeat(300);}},
   {toLocaleString() {throw thrown;}}].toLocaleString();
} catch(error) {released = error === thrown;}
console.log(released, ['after'].toLocaleString());
"#;
    assert_locale_output(
        source,
        "true 1 0/method/call/string\nTypeError/TypeError/TypeError/TypeError/token/token/TypeError\ntrue after",
    );
}

#[test]
fn locale_string_native_work_and_output_share_runtime_budgets() {
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 4096;
        let source = "try { Array.prototype.toLocaleString.call({length:10000}); } catch(error) { console.log('caught'); }";
        let error = console_output_with_config(source, config.clone(), None).expect_err(source);
        assert!(error.contains("BudgetExhausted"), "{error}");

        config.instruction_budget = 1_000_000;
        config.max_string_size = 1024;
        for source in [
            "Array.prototype.toLocaleString.call({length:2 ** 53 - 1});",
            "const item = {toLocaleString() {return '\\ud800'.repeat(200);}}; [item,item].toLocaleString();",
        ] {
            let error = console_output_with_config(source, config.clone(), None).expect_err(source);
            assert!(error.contains("StringLimitExceeded"), "{source}: {error}");
        }
    }
}

#[test]
fn locale_string_retains_observed_labels_across_later_callbacks_and_catch() {
    let cases = [
        (
            "const array = ['label-marker', {toLocaleString() {return 'public';}}]; array.toLocaleString();",
            Value::str("secret"),
            "secret,public",
        ),
        (
            "function source(a) {} Object.defineProperty(source, 'length', {value:'label-marker'}); source[0] = {toLocaleString() {return 'public';}}; Array.prototype.toLocaleString.call(source);",
            Value::Int(1),
            "public",
        ),
        (
            "const array = ['label-marker', {toLocaleString() {throw 'public';}}]; let caught = ''; try {array.toLocaleString();} catch(error) {caught = error;} caught;",
            Value::str("secret"),
            "public",
        ),
    ];
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        for (source, input, expected) in &cases {
            let input_register = config.max_registers - 1;
            let mut module = lower_source(source).expect("locale label source lowers");
            let pool_index = module
                .constant_pool
                .iter()
                .position(|text| text == "label-marker")
                .expect("unique labelled input literal") as u32;
            let mut replacements = 0;
            for instruction in &mut module.instructions {
                if let Ir3Instruction::LoadStr {
                    dst,
                    pool_index: index,
                } = instruction
                    && *index == pool_index
                {
                    *instruction = Ir3Instruction::Move {
                        dst: *dst,
                        src: input_register,
                    };
                    replacements += 1;
                }
            }
            assert_eq!(replacements, 1, "only the input literal is labelled");
            for stress in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config.clone(), "locale-label");
                core.seed_register(input_register, input.clone()).unwrap();
                core.set_register_label(input_register, Label::Secret)
                    .unwrap();
                core.set_gc_stress_interval(stress);
                let execution = core.execute(&module).expect("locale label execution");
                assert_eq!(execution.value, Value::str(*expected), "{source}");
                assert_eq!(execution.completion_label, Label::Secret, "{source}");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "GC={stress:?}: {source}"
                );
            }
        }
    }
}

/// An array-like's length is guest-chosen, up to 2^53 - 1. Methods that
/// copy the elements sized a buffer by it unchecked, so
/// `splice.call({ length: 2 ** 53 + 2 }, ...)` aborted the whole process
/// (Test262 splice/length-and-deleteCount-exceeding-integer-limit). Methods
/// that copy every element charge the buffer to the memory budget first:
/// the run ends with a budget error instead. splice on an array-like copies
/// only what it removes and moves, and returns Node's two-element array.
/// `push` past 2^53 - 1 is Node's TypeError. A change-by-copy method's
/// ArrayCreate rejects a length past 2^32 - 1 first, with Node's RangeError
/// (bd-9vouw.354); one within it still copies, so it is budgeted.
#[test]
fn huge_array_like_lengths_are_budgeted_not_fatal() {
    assert_eq!(
        console_output(
            "var arrayLike = { '9007199254740989': 'a', length: 2 ** 53 + 2 }; var r = Array.prototype.splice.call(arrayLike, 9007199254740989, 2 ** 53 + 4); console.log(r.length, r[0], r[1], 1 in r, arrayLike.length, 9007199254740989 in arrayLike);"
        ),
        Ok("2 a undefined false 9007199254740989 false".to_string())
    );
    for source in [
        "Array.prototype.sort.call({ length: 2 ** 53 - 1 });",
        "Array.prototype.toSorted.call({ length: 2 ** 32 - 1 });",
    ] {
        let error = console_output(source).expect_err(source);
        assert!(
            error.contains("MemoryBudgetExceeded"),
            "`{source}` must end with a budget error, got {error}"
        );
    }
    assert_eq!(
        console_output(
            "try { Array.prototype.toSorted.call({ length: 2 ** 40 }); } catch (e) { console.log(e.constructor.name); }"
        ),
        Ok("RangeError".to_string())
    );
    assert_eq!(
        console_output(
            "var o = { length: 2 ** 53 - 1 }; try { Array.prototype.push.call(o, 1); console.log('none'); } catch (e) { console.log(e.constructor.name, o.length); }"
        ),
        Ok("TypeError 9007199254740991".to_string())
    );
}

#[test]
fn array_to_string_preserves_getter_labels_through_call_fallback_and_catch() {
    let cases = [
        (
            "const selected = 'label-marker'; const object = {get join() {return selected ? function() {return 'public';} : null;}}; Array.prototype.toString.call(object);",
            Value::Bool(true),
            "public",
        ),
        (
            "const tag = 'label-marker'; const object = {join:null, get [Symbol.toStringTag]() {return tag;}}; Array.prototype.toString.call(object);",
            Value::str("Tagged"),
            "[object Tagged]",
        ),
        (
            "const selected = 'label-marker'; const object = {get join() {if (selected) throw 'public'; return null;}}; let caught = ''; try {Array.prototype.toString.call(object);} catch(error) {caught = error;} caught;",
            Value::Bool(true),
            "public",
        ),
    ];
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        for (source, input, expected) in &cases {
            let input_register = config.max_registers - 1;
            let mut module = lower_source(source).expect("array conversion label source lowers");
            let pool_index = module
                .constant_pool
                .iter()
                .position(|text| text == "label-marker")
                .expect("unique labelled input literal") as u32;
            let mut replacements = 0;
            for instruction in &mut module.instructions {
                if let Ir3Instruction::LoadStr {
                    dst,
                    pool_index: index,
                } = instruction
                    && *index == pool_index
                {
                    *instruction = Ir3Instruction::Move {
                        dst: *dst,
                        src: input_register,
                    };
                    replacements += 1;
                }
            }
            assert_eq!(replacements, 1, "only the input literal is labelled");
            for stress in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config.clone(), "array-conversion-label");
                core.seed_register(input_register, input.clone()).unwrap();
                core.set_register_label(input_register, Label::Secret)
                    .unwrap();
                core.set_gc_stress_interval(stress);
                let execution = core.execute(&module).expect("array conversion label execution");
                assert_eq!(execution.value, Value::str(*expected), "{source}");
                assert_eq!(execution.completion_label, Label::Secret, "{source}");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "GC={stress:?}: {source}"
                );
            }
        }
    }
}
