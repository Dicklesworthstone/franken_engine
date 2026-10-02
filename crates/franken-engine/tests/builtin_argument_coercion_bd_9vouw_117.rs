//! bd-9vouw.117: builtins convert object arguments through ToPrimitive.
//!
//! String, Array, Number and BigInt builtins converted a numeric or string
//! argument without calling the object's valueOf/toString:
//! `'abc'.indexOf({ toString() { return 'b' } })` was -1 (Node 1),
//! `'ab'.repeat({ valueOf() { return 2 } })` was '', and
//! `[1, 2, 3].slice({ valueOf() { return 1 } })` returned the whole array.
//! PROGRAM covers the String search and position arguments, padStart's
//! fill, the Array index arguments, Number digits and radix, BigInt radix,
//! argument conversion order, Symbol and BigInt arguments (TypeError), and a
//! throwing valueOf/toString propagating. It also covers lastIndexOf with a
//! NaN position, which searches from the end. NODE_OUTPUT is Node v22.2.0's
//! output.
//!
//! PROGRAM_BINARY_AND_STRINGS covers the TypedArray, ArrayBuffer, DataView
//! and Buffer index and value arguments, the String methods that take a
//! position, form, separator or pattern (charAt, charCodeAt, at, normalize,
//! split, replace, replaceAll, search, match, matchAll), Date.parse and the
//! URI functions, and an object whose valueOf/toString returns undefined
//! (NaN or "undefined", not an absent argument).
//!
//! PROGRAM_TO_INDEX covers ES2020 7.1.22 ToIndex for ArrayBuffer,
//! TypedArray and DataView lengths, offsets and indices: NaN and undefined
//! are 0, fractions truncate, a value below 0 or above 2^53 - 1 is a
//! RangeError, and a Symbol or BigInt is a TypeError.
//!
//! No-claim: an indexed element write (`u8[0] = obj`) does not call valueOf.
//! The Function constructor's arguments are another path.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const two = { valueOf() { return 2; } };
const one = { valueOf() { return 1; } };
const b = { toString() { return 'b'; } };
const log = [];
const tracked = function (name, value) { return { valueOf() { log.push(name); return value; } }; };
console.log('abc'.indexOf(b), 'abcb'.lastIndexOf(b), 'abc'.includes(b), 'abc'.startsWith({ toString() { return 'ab'; } }), 'abc'.endsWith({ toString() { return 'bc'; } }));
console.log('ab'.repeat(two), 'abcdef'.slice(one, { valueOf() { return 3; } }), 'abcdef'.substring(two), 'abcdef'.substr(one, two), 'abc'.codePointAt(one), 'abc'.indexOf('c', one));
console.log('5'.padStart(two, { toString() { return '0'; } }), 'x'.padEnd({ valueOf() { return 3; } }, '-'), 'aXbX'.lastIndexOf('X', NaN), 'aXbX'.lastIndexOf('X', 'nope'), 'aXbX'.lastIndexOf('X', one));
console.log([1, 2, 3].slice(one).join(), [1, 2, 3, 2].indexOf(2, two), [1, 2, 3, 2].lastIndexOf(2, one), [1, 2, 3].includes(1, one), [1, 2, 3].at(two), [0, 0, 0].fill(9, one, two).join());
console.log([1, 2, 3, 4].copyWithin(0, two).join(), [1, 2, 3].splice(one, one).join(), [[1, [2]]].flat(two).join(), [1, 2, 3].with(one, 'x').join(), [1, 2, 3].toSpliced(one, one).join());
console.log((12.345).toFixed(two), (255).toString({ valueOf() { return 16; } }), (1234.5).toPrecision(two), (1234.5).toExponential(one), (255n).toString({ valueOf() { return 16; } }));
'abcdef'.slice(tracked('start', 1), tracked('end', 3)); [1, 2, 3].slice(tracked('slice-start', 0), tracked('slice-end', 1));
console.log(log.join());
for (const [label, run] of [
  ['indexOf symbol', function () { return 'abc'.indexOf(Symbol('s')); }],
  ['slice symbol', function () { return 'abc'.slice(Symbol('s')); }],
  ['repeat symbol', function () { return 'a'.repeat(Symbol('s')); }],
  ['array slice symbol', function () { return [1].slice(Symbol('s')); }],
  ['at bigint', function () { return [1].at(1n); }],
  ['toFixed symbol', function () { return (1).toFixed(Symbol('s')); }],
  ['padStart symbol fill', function () { return 'a'.padStart(3, Symbol('s')); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e instanceof TypeError); }
}
try { (1).toFixed({ valueOf() { throw new RangeError('from valueOf'); } }); } catch (e) { console.log('abrupt valueOf', e instanceof RangeError, e.message); }
try { 'abc'.indexOf({ toString() { throw new SyntaxError('from toString'); } }); } catch (e) { console.log('abrupt toString', e instanceof SyntaxError, e.message); }"#;

const NODE_OUTPUT: &str = r#"1 3 true true true
abab bc cdef bc 98 2
05 x-- 3 3 1
2,3 3 1 false 3 0,9,0
3,4,3,4 2 1,2 1,x,3 1,3
12.35 ff 1.2e+3 1.2e+3 ff
start,end,slice-start,slice-end
indexOf symbol true
slice symbol true
repeat symbol true
array slice symbol true
at bigint true
toFixed symbol true
padStart symbol fill true
abrupt valueOf true from valueOf
abrupt toString true from toString"#;

const PROGRAM_BINARY_AND_STRINGS: &str = r#"const one = { valueOf() { return 1; } };
const two = { valueOf() { return 2; } };
const three = { valueOf() { return 3; } };
const undef = { valueOf() { return undefined; } };
const u = new Uint8Array([10, 20, 30, 40]);
console.log(Array.from(u.subarray(one, three)).join(), Array.from(u.slice(one, three)).join(), Array.from(new Uint8Array(4).fill(7, one, three)).join(), Array.from(new Uint8Array([1, 2, 3, 4]).copyWithin(0, two)).join());
console.log(u.at(one), u.includes(10, one), u.indexOf(10, one), u.lastIndexOf(40, two), Array.from(Buffer.from([1, 2, 3, 4]).slice(one, three)).join());
console.log(new Uint8Array(new ArrayBuffer(8).slice(one, three)).length, new ArrayBuffer(two).byteLength, new Uint8Array(new ArrayBuffer(8), two, three).length);
const dv = new DataView(new ArrayBuffer(8), one, three);
dv.setInt8(one, { valueOf() { return 5; } });
console.log(dv.byteOffset, dv.byteLength, dv.getInt8(one), dv.getUint8(1));
const big = new DataView(new ArrayBuffer(8));
big.setBigInt64(0, { valueOf() { return 7n; } });
console.log(String(big.getBigInt64(0)), Array.from(new Uint8Array(4).fill(two)).join(), Array.from(new Uint8Array(2).fill('5')).join(), Array.from(new Float64Array(2).fill({ valueOf() { return 1.5; } })).join(), String(new BigInt64Array(2).fill({ valueOf() { return 3n; } })[1]));
const target = new Uint8Array(4); target.set([8, 9], one);
console.log(Array.from(target).join());
const str = (v) => ({ toString() { return v; } });
console.log('a,b,c'.split(str(',')).length, 'a,b,c'.split(',', two).length, 'a,b'.split(',', undef).length, Date.parse(str('2020-01-01T00:00:00Z')), encodeURIComponent(str('a b')), encodeURI(str('a b')), decodeURIComponent(str('a%20b')), decodeURI(str('a%20b')));
console.log('abc'.charAt(one), 'abc'.charCodeAt(one), 'abc'.at(two), 'abc'.normalize(str('NFC')), 'abc'.replace(str('b'), str('X')), 'abcb'.replaceAll(str('b'), 'Y'), 'abc'.search(str('c')), String('abc'.match(str('b'))), Array.from('abab'.matchAll(str('b'))).length);
const log = [];
const t = (name, v) => ({ valueOf() { log.push(name); return v; } });
u.slice(t('s', 0), t('e', 1)); new Uint8Array(4).fill(t('fv', 1), t('fs', 0), t('fe', 1)); new DataView(new ArrayBuffer(4)).setUint8(t('di', 0), t('dv', 1)); new Uint8Array(4).set([1], t('so', 0));
console.log(log.join());
console.log(JSON.stringify(['abcdef'.slice(0, undef), [1, 2, 3].slice(0, undef).length, 'abcdef'.substring(1, undef), 'abcdef'.substr(1, undef), Array.from(u.subarray(0, undef)).length, Array.from(new Uint8Array(2).fill(1, 0, undef)).join(), 'a'.padEnd(4, { toString() { return undefined; } }), 'xundefinedy'.indexOf({ toString() { return undefined; } })]));
for (const [label, run] of [
  ['subarray symbol', () => u.subarray(Symbol('x'))],
  ['fill symbol value', () => new Uint8Array(2).fill(Symbol('x'))],
  ['fill bigint into numbers', () => new Uint8Array(2).fill(1n)],
  ['fill number into bigints', () => new BigInt64Array(2).fill(1)],
  ['ab slice bigint', () => new ArrayBuffer(4).slice(1n)],
  ['dataview set symbol value', () => new DataView(new ArrayBuffer(4)).setUint8(0, Symbol('x'))],
  ['copyWithin bigint', () => new Uint8Array(2).copyWithin(1n)],
  ['split symbol separator', () => 'a'.split(Symbol('x'))],
  ['encodeURIComponent symbol', () => encodeURIComponent(Symbol('x'))],
  ['normalize undefined form', () => 'a'.normalize({ toString() { return undefined; } })],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}
try { new Uint8Array(4).fill(0, { valueOf() { throw new SyntaxError('from valueOf'); } }); } catch (e) { console.log('abrupt valueOf', e instanceof SyntaxError, e.message); }"#;

const NODE_OUTPUT_BINARY_AND_STRINGS: &str = r#"20,30 20,30 0,7,7,0 3,4,3,4
20 false -1 -1 2,3
2 2 3
1 3 5 5
7 2,2,2,2 5,5 1.5,1.5 3
0,8,9,0
3 2 0 1577836800000 a%20b a%20b a b a b
b 98 c abc aXc aYcY 2 b 2
s,e,fv,fs,fe,di,dv,so
["",0,"a","",0,"0,0","aund",1]
subarray symbol TypeError
fill symbol value TypeError
fill bigint into numbers TypeError
fill number into bigints TypeError
ab slice bigint TypeError
dataview set symbol value TypeError
copyWithin bigint TypeError
split symbol separator TypeError
encodeURIComponent symbol TypeError
normalize undefined form RangeError
abrupt valueOf true from valueOf"#;

const PROGRAM_TO_INDEX: &str = r#"const lines = [
  () => [new ArrayBuffer(1.5).byteLength, new ArrayBuffer(NaN).byteLength, new ArrayBuffer('2.9').byteLength, new ArrayBuffer(undefined).byteLength, new ArrayBuffer(null).byteLength, new ArrayBuffer(true).byteLength, new ArrayBuffer(-0.5).byteLength],
  () => [new Uint8Array(1.5).length, new Uint8Array(new ArrayBuffer(8), 2.9).byteOffset, new Uint8Array(new ArrayBuffer(8), 0, 2.5).length, new Uint8Array(NaN).length],
  () => { const dv = new DataView(new ArrayBuffer(8), 1.5, NaN); return [dv.byteOffset, dv.byteLength]; },
  () => { const dv = new DataView(new ArrayBuffer(4)); dv.setUint8(1.9, 7); dv.setUint8(0, 3); return [dv.getUint8(1), dv.getUint8('1'), dv.getUint8('x'), dv.getUint8(NaN), dv.getUint8(-0.5)]; },
  () => { const u = new Uint8Array(4); u.set([5], 1.9); return [Array.from(u).join()]; },
];
lines.forEach(function (run, i) { try { console.log(i, ...run()); } catch (e) { console.log(i, 'threw', e.constructor.name); } });
for (const [label, run] of [
  ['ArrayBuffer -1', () => new ArrayBuffer(-1)],
  ['ArrayBuffer Infinity', () => new ArrayBuffer(Infinity)],
  ['ArrayBuffer 2^53', () => new ArrayBuffer(2 ** 53)],
  ['ArrayBuffer 1n', () => new ArrayBuffer(1n)],
  ['ArrayBuffer symbol', () => new ArrayBuffer(Symbol('s'))],
  ['Uint8Array -1', () => new Uint8Array(-1)],
  ['Uint8Array symbol', () => new Uint8Array(Symbol('s'))],
  ['DataView offset -1', () => new DataView(new ArrayBuffer(4), -1)],
  ['getUint8 -1', () => new DataView(new ArrayBuffer(4)).getUint8(-1)],
  ['getUint8 1n', () => new DataView(new ArrayBuffer(4)).getUint8(1n)],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}"#;

const NODE_OUTPUT_TO_INDEX: &str = r#"0 1 0 2 0 0 1 0
1 1 2 2 0
2 1 0
3 7 7 3 3 3
4 0,5,0,0
ArrayBuffer -1 RangeError
ArrayBuffer Infinity RangeError
ArrayBuffer 2^53 RangeError
ArrayBuffer 1n TypeError
ArrayBuffer symbol TypeError
Uint8Array -1 RangeError
Uint8Array symbol TypeError
DataView offset -1 RangeError
getUint8 -1 RangeError
getUint8 1n TypeError"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "builtin-argument-coercion.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "builtin-argument-coercion.js"),
        &LoweringContext::new("coerce-trace", "coerce-decision", "coerce-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "builtin-argument-coercion");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift"
    );
    let result = result.map_err(|error| format!("execute: {error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn builtin_arguments_convert_like_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

#[test]
fn binary_data_and_string_arguments_convert_like_node() {
    let output = console_output(PROGRAM_BINARY_AND_STRINGS).expect("the program runs");
    for (index, (actual, expected)) in output
        .lines()
        .zip(NODE_OUTPUT_BINARY_AND_STRINGS.lines())
        .enumerate()
    {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(
        output.lines().count(),
        NODE_OUTPUT_BINARY_AND_STRINGS.lines().count()
    );
}

#[test]
fn lengths_offsets_and_indices_use_to_index_like_node() {
    let output = console_output(PROGRAM_TO_INDEX).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT_TO_INDEX.lines()).enumerate()
    {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT_TO_INDEX.lines().count());
}
