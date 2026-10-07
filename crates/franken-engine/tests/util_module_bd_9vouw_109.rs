//! bd-9vouw.109: `require('util')` and `require('node:util')`.
//!
//! `require` was refused for every module but the few lowered member by
//! member (path, querystring, os, url, fs), so a program or package that
//! loads util did not run. Lowering now rewrites each `require('util')` whose
//! `require` is the global one into the engine's util module
//! (lowering_pipeline/util_module.rs). PROGRAM exercises it; NODE_OUTPUT is
//! Node v22.2.0's stdout for it, line by line:
//! - format and formatWithOptions: directives, a missing argument, extra
//!   arguments, no arguments;
//! - inspect: the default depth 2, `depth: 0`, `depth: null` and Infinity
//!   (Node's compact-3 line breaking), primitives and collections;
//! - inherits (`super_` non-enumerable, the prototype link,
//!   ERR_INVALID_ARG_TYPE and its message);
//! - promisify (settling through a timer, rejection, util.promisify.custom,
//!   the copied name and length), callbackify (the value, a falsy rejection
//!   as ERR_FALSY_VALUE_REJECTION, a thrown error, name and length),
//!   deprecate, debuglog;
//! - util.types across dates, regexps, collections, promises, buffers,
//!   errors, boxed primitives, generator and async functions and proxies;
//! - isDeepStrictEqual (nested data, Maps, Sets, NaN, -0, dates, regexps,
//!   prototypes, cycles);
//! - one module object for every call, destructuring, inline and nested
//!   `require` calls.
//!
//! No-claim: inspect options other than depth (colors, showHidden, compact,
//! breakLength, sorted, ...) and `[util.inspect.custom]` methods are not
//! honoured; deprecate prints no DeprecationWarning (Node writes it to
//! stderr); Map and Set members that are objects compare by identity in
//! isDeepStrictEqual; `import ... from 'util'` is not covered.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const util = require('util');
console.log(util.format('%s=%d %j', 'a', 42, { x: 1 }), util.format('a', 'b', 3), util.format('%i%%', 7.9));
console.log('format', util.format('%s and %s', 'one'), util.format(1, { a: [2] }, 'z'), util.formatWithOptions({}, 'x %s', 'y'), JSON.stringify(util.format()));
console.log(util.inspect({ a: [1, { b: 2 }] }), util.inspect('str'), util.inspect(new Map([[1, 2]])));
console.log(util.inspect({ a: { b: { c: { d: 1 } } } }), util.inspect({ a: { b: 1 } }, { depth: 0 }));
console.log(util.inspect({ a: { b: { c: { d: {} } } } }, { depth: null }), util.inspect({ a: { b: { c: { d: {} } } } }, { depth: Infinity }));
console.log(util.inspect([1, 'two', [3]]), util.inspect(new Set(['s'])), util.inspect(null), util.inspect(undefined), util.inspect(5n), util.inspect(-0));
function Parent(n) { this.n = n; }
Parent.prototype.hi = function () { return 'hi ' + this.n; };
function Child(n) { Parent.call(this, n); }
util.inherits(Child, Parent);
const c = new Child(3);
console.log(c.hi(), c instanceof Parent, Child.super_ === Parent, Object.keys(Child).length, Object.getPrototypeOf(Child.prototype) === Parent.prototype);
try { util.inherits(Child, null); } catch (e) { console.log(e instanceof TypeError, e.code, e.message); }
try { util.promisify('a long string that is longer than the limit'); } catch (e) { console.log(e.message); }
const cbNamed = util.callbackify(async function load(a) { return a; }); const pNamed = util.promisify(function read(a, cb) { cb(null, a); });
console.log(cbNamed.name, cbNamed.length, pNamed.name, pNamed.length, util.promisify(pNamed) === pNamed);
const pf = util.promisify((x, cb) => setTimeout(() => cb(null, x * 2), 0));
pf(21).then(v => console.log('promisify', v));
util.promisify((cb) => cb(new Error('boom')))().catch(e => console.log('rejected', e.message));
function withCustom() {}
withCustom[util.promisify.custom] = () => Promise.resolve('custom');
console.log(util.promisify(withCustom) === withCustom[util.promisify.custom], util.promisify.custom === Symbol.for('nodejs.util.promisify.custom'));
const cbf = util.callbackify(async (x) => x + 1);
cbf(1, (err, v) => console.log('callbackify', err, v));
util.callbackify(() => Promise.reject(null))((err) => console.log('falsy', err instanceof Error, err.code, err.reason));
util.callbackify(async () => { throw new Error('async boom'); })((err) => console.log('callbackify error', err.message));
const dep = util.deprecate((a) => a * 3, 'old api');
console.log(dep(5), typeof dep);
const dbg = util.debuglog('franken');
dbg('not printed');
console.log(typeof dbg, dbg.enabled, typeof util.debug);
const t = util.types;
console.log(t.isDate(new Date()), t.isRegExp(/a/), t.isPromise(Promise.resolve()), t.isMap(new Map()), t.isSet(new Set()), t.isTypedArray(new Uint8Array(1)), t.isUint8Array(new Uint8Array(1)), t.isArrayBuffer(new ArrayBuffer(1)), t.isNativeError(new TypeError()), t.isBoxedPrimitive(Object(1)), t.isDate({}));
console.log(t.isGeneratorFunction(function* () {}), t.isAsyncFunction(async () => {}), t.isAsyncFunction(function () {}), t.isProxy(new Proxy({}, {})), t.isWeakMap(new WeakMap()), t.isWeakSet(new WeakSet()), t.isDataView(new DataView(new ArrayBuffer(1))));
console.log(t.isNumberObject(new Number(1)), t.isStringObject(new String('s')), t.isBooleanObject(true), t.isGeneratorObject((function* () {})()), t.isFloat64Array(new Float64Array(1)), t.isUint8Array(new Int8Array(1)), t.isArrayBufferView(new DataView(new ArrayBuffer(1))), t.isMap(new Proxy(new Map(), {})));
console.log(util.isDeepStrictEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), util.isDeepStrictEqual([1], ['1']), util.isDeepStrictEqual(new Map([[1, { x: 1 }]]), new Map([[1, { x: 1 }]])), util.isDeepStrictEqual({ a: 1 }, { a: 1, b: undefined }));
const cyc1 = { v: 1 }; cyc1.self = cyc1; const cyc2 = { v: 1 }; cyc2.self = cyc2;
class Point { constructor() { this.x = 1; } }
console.log(util.isDeepStrictEqual(NaN, NaN), util.isDeepStrictEqual(new Date(5), new Date(5)), util.isDeepStrictEqual(new Date(5), new Date(6)), util.isDeepStrictEqual(new Set([1, 2]), new Set([2, 1])), util.isDeepStrictEqual(new Point(), { x: 1 }), util.isDeepStrictEqual(cyc1, cyc2), util.isDeepStrictEqual(/a/g, /a/g), util.isDeepStrictEqual(/a/g, /a/i), util.isDeepStrictEqual(0, -0));
console.log(util.TextEncoder === TextEncoder, typeof util.TextDecoder, util.isArray([1]), typeof util.inspect.custom, util.inspect.custom === Symbol.for('nodejs.util.inspect.custom'));
console.log(require('util') === util, require('node:util') === util, typeof util.inspect, util.inspect.name, util.format.length);
const { inspect, format } = require('util');
console.log(inspect === util.inspect, format('%d-%d', 1, 2), require('util').format('%s!', 'inline'));
function inner() { const u = require('util'); return u === util && u.format('%s', 'scoped'); }
console.log(inner(), (() => require('node:util'))() === util);
console.log(require('util/types') === util.types, require('node:util/types').isDate(new Date()));"#;

const NODE_OUTPUT: &str = r#"a=42 {"x":1} a b 3 7%
format one and %s 1 { a: [ 2 ] } z x y ""
{ a: [ 1, { b: 2 } ] } 'str' Map(1) { 1 => 2 }
{ a: { b: { c: [Object] } } } { a: [Object] }
{
  a: { b: { c: { d: {} } } }
} {
  a: { b: { c: { d: {} } } }
}
[ 1, 'two', [ 3 ] ] Set(1) { 's' } null undefined 5n -0
hi 3 true true 0 true
true ERR_INVALID_ARG_TYPE The "superCtor" argument must be of type function. Received null
The "original" argument must be of type function. Received type string ('a long string that is lon...')
loadCallbackified 2 read 2 true
true true
15 function
function false function
true true true true true true true true true true false
true true false true true true true
true true false true true false true false
true false true false
true true false true false true true false false
true function true symbol true
true true function inspect 0
true 1-2 inline!
scoped true
true true
rejected boom
callbackify null 2
falsy true ERR_FALSY_VALUE_REJECTION null
callbackify error async boom
promisify 42"#;

fn lower(source: &str) -> Result<Ir3Module, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "util-module.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    Ok(lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "util-module.js"),
        &LoweringContext::new("util-trace", "util-decision", "util-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3)
}

fn console_output(source: &str) -> Result<String, String> {
    let module = lower(source)?;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        RuntimeCapability::Timer,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "util-module");
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
fn util_module_matches_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

/// A `require` the program declares is its own function, as in Node.
#[test]
fn a_declared_require_is_called_not_rewritten() {
    assert_eq!(
        console_output("var require = (name) => 'mine:' + name; console.log(require('util'));")
            .as_deref(),
        Ok("mine:util")
    );
    assert_eq!(
        console_output(
            "function load(require) { return require('node:util'); } \
             console.log(load((name) => name + '!'));"
        )
        .as_deref(),
        Ok("node:util!")
    );
}

/// The module reads standard globals by name. A program's own top-level
/// binding of such a name (`const { TextEncoder } = require('util')`, a
/// `Promise` of its own) must not capture the module's reference: those
/// bound `TextEncoder` to the program's const, which was still undefined
/// while the module was built. Node v22.2.0's output.
#[test]
fn program_bindings_named_like_globals_do_not_capture_the_module() {
    assert_eq!(
        console_output(
            "const { TextEncoder, TextDecoder } = require('util'); const Promise = 'mine'; \
             const util = require('util'); \
             util.promisify((cb) => cb(null, 7))().then((v) => console.log(v, Promise, \
             new TextEncoder().encode('hi').length, \
             new TextDecoder().decode(new TextEncoder().encode('ok'))));"
        )
        .as_deref(),
        Ok("7 mine 2 ok")
    );
}

/// The module declaration runs only engine code, so it is not a
/// predeclaration hazard for the lowering-only module aliases after it,
/// which a call before their declaration disables: `url` and `zlib` stay
/// aliased behind a `require('util')`. Node v22.2.0's output.
#[test]
fn module_aliases_after_util_keep_working() {
    assert_eq!(
        console_output(
            "const util = require('util'); const url = require('url'); \
             const zlib = require('zlib'); \
             console.log(url.parse('http://a.b/c?d=1').pathname, \
             zlib.gunzipSync(zlib.gzipSync('hi')).toString(), util.format('%d', 2));"
        )
        .as_deref(),
        Ok("/c hi 2")
    );
}

/// Only util is served: other modules and `require` as a value keep the
/// ambient-authority refusal.
#[test]
fn other_requires_are_still_refused() {
    for source in [
        "const pad = require('left-pad'); pad('a', 3);",
        "const util = require('util'); const r = require; r('fs');",
        "const util = require('util'); console.log(require('util/other'));",
    ] {
        let error = lower(source).expect_err(source);
        assert!(error.contains("require"), "{source}: {error}");
    }
}

/// Found through promisify, which copies a function's own properties: a
/// function is an object, so Reflect.ownKeys lists its keys (it threw a
/// TypeError), Object.getOwnPropertySymbols its Symbol keys (it gave none),
/// and getOwnPropertyDescriptor describes `prototype` (it gave undefined).
/// Node v22.2.0's output.
#[test]
fn a_function_s_own_keys_and_prototype_are_described() {
    assert_eq!(
        console_output(
            "const sym = Symbol('k'); const arrow = () => {}; arrow[sym] = 1; arrow.extra = 2; \
             console.log(Reflect.ownKeys(arrow).map(String).join(), \
             Object.getOwnPropertySymbols(arrow).length, Reflect.ownKeys(class K {}).join(), \
             Object.getOwnPropertySymbols(() => {}).length);"
        )
        .as_deref(),
        Ok("length,name,extra,Symbol(k) 1 length,name,prototype 0")
    );
    assert_eq!(
        console_output(
            "function f() {} const d = Object.getOwnPropertyDescriptor(f, 'prototype'); \
             function o() {} o.prototype = 5; \
             console.log(d.value === f.prototype, d.writable, d.enumerable, d.configurable, \
             Object.getOwnPropertyDescriptor(o, 'prototype').value, \
             Object.getOwnPropertyDescriptor(() => {}, 'prototype'));"
        )
        .as_deref(),
        Ok("true true false false 5 undefined")
    );
}

/// `{ k: { deep: text } }` formatted by `capability`, with `text` in a
/// register labelled `label` and the object in Public registers. The
/// labels are set directly, so this checks the runtime result label without
/// the static analysis, which refuses `console.log(util.inspect(secret))`
/// on its own.
fn format_nested(capability: &str, text: &str, label: Label) -> (Value, Label) {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "util-labels");
    core.seed_register(0, Value::Str(text.into())).unwrap();
    core.set_register_label(0, label).unwrap();
    core.seed_register(1, Value::Str("deep".into())).unwrap();
    core.seed_register(3, Value::Str("k".into())).unwrap();
    let mut module = lower("0;").expect("lowers");
    let mut instructions = vec![
        Ir3Instruction::NewObject { dst: 2 },
        Ir3Instruction::SetProperty {
            obj: 2,
            key: 1,
            val: 0,
        },
        Ir3Instruction::NewObject { dst: 4 },
        Ir3Instruction::SetProperty {
            obj: 4,
            key: 3,
            val: 2,
        },
    ];
    let argument = if capability == "builtin:UtilFormat" {
        instructions.push(Ir3Instruction::NewArray { dst: 6 });
        instructions.push(Ir3Instruction::ArrayPush {
            array: 6,
            element: 4,
        });
        6
    } else {
        4
    };
    instructions.push(Ir3Instruction::HostCall {
        capability: CapabilityTag(capability.into()),
        args: RegRange {
            start: argument,
            count: 1,
        },
        dst: 5,
    });
    instructions.push(Ir3Instruction::Return { value: 5 });
    module.instructions = instructions;
    let result = core.execute(&module).expect("formats");
    (result.value, result.completion_label)
}

/// util.inspect and util.format return text showing a nested Secret: the
/// text is labelled Secret, though the object reached them through Public
/// registers. Public data stays Public.
#[test]
fn formatted_text_carries_the_label_of_what_it_shows() {
    for capability in ["builtin:UtilInspect", "builtin:UtilFormat"] {
        let (value, label) = format_nested(capability, "hunter2", Label::Secret);
        assert_eq!(
            value,
            Value::Str("{ k: { deep: 'hunter2' } }".into()),
            "{capability}"
        );
        assert!(label >= Label::Secret, "{capability}: {label:?}");
        let (_, label) = format_nested(capability, "public", Label::Public);
        assert_eq!(label, Label::Public, "{capability}");
    }
}

/// The engine's own module functions print as native code, as they did
/// before bd-9vouw.184 gave every function its source text: theirs is the
/// engine-owned module source, which spells the placeholder names lowering
/// renames (`return __franken_util_format(args)`). Expected: the main
/// 71918379f frankenctl's output for the same program.
#[test]
fn engine_module_functions_print_as_native_code() {
    let output = console_output(
        "const util = require('util'); console.log(String(util.format)); \
         console.log([util.inspect, util.format].map(String).some((text) => text.includes('__franken')));",
    )
    .expect("the program runs");
    assert_eq!(output, "function format() { [native code] }\nfalse");
}
