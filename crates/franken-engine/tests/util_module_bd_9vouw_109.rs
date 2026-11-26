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
//! Explicit util.inspect calls honor custom hooks and their depth/options
//! contract. Console/format do not yet invoke those hooks. Ordinary rendering
//! options other than depth (colors, showHidden, compact, breakLength, sorted,
//! ...) are not honoured; deprecate prints no DeprecationWarning (Node writes it to
//! stderr); Map and Set members that are objects compare by identity in
//! isDeepStrictEqual; `import ... from 'util'` is not covered.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
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

#[test]
fn custom_inspect_receives_receiver_depth_options_and_canonical_inspector() {
    let source = r#"
        const util = require('util');
        const seen = [];
        const item = {
            tag: 'item',
            [util.inspect.custom](depth, options, inspect) {
                seen.push([this === item, depth, options.depth, options.customInspect,
                    inspect === util.inspect, typeof options.stylize, options.extra].join(':'));
                options.extra = 99;
                return 'Item<' + this.tag + '>';
            }
        };
        console.log(util.inspect(item, { depth: 3, extra: 7 }));
        console.log(util.inspect({ item, other: item }, { depth: 0, extra: 7 }));
        console.log(seen.join('|'));
        const unlimited = {
            [util.inspect.custom](depth, options) {
                return String(depth) + ':' + String(options.depth);
            }
        };
        console.log(util.inspect(unlimited, { depth: null }),
            util.inspect(unlimited, { depth: Infinity }));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "Item<item>\n",
            "{ item: Item<item>, other: Item<item> }\n",
            "true:3:3:true:true:function:7|true:-1:0:true:true:function:7|",
            "true:-1:0:true:true:function:7\n",
            "null:null Infinity:Infinity"
        ))
    );
}

#[test]
fn custom_inspect_preserves_fractional_and_nonfinite_depth_options() {
    let source = r#"
        const util = require('util');
        const value = {
            [util.inspect.custom](depth, options) {
                return String(depth) + ':' + String(options.depth);
            }
        };
        for (const depth of [1.5, NaN, -Infinity, Infinity, null, -0.5]) {
            console.log(util.inspect(value, { depth }), util.inspect({ value }, { depth }));
        }
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "1.5:1.5 { value: 0.5:1.5 }\n",
            "NaN:NaN { value: NaN:NaN }\n",
            "-Infinity:-Infinity [Object]\n",
            "Infinity:Infinity { value: Infinity:Infinity }\n",
            "null:null { value: null:null }\n",
            "-0.5:-0.5 [Object]"
        ))
    );
}

#[test]
fn custom_inspect_options_stylize_honors_colors_and_runtime_style_overrides() {
    let source = r#"
        const util = require('util');
        const value = {
            [util.inspect.custom](depth, options) {
                return options.stylize('42', 'number') + '|' + options.stylize('name', 'name');
            }
        };
        console.log(JSON.stringify(util.inspect(value)),
            JSON.stringify(util.inspect(value, { colors: true })));
        util.inspect.styles.number = 'red';
        console.log(JSON.stringify(util.inspect(value, { colors: true })));
        util.inspect.colors.red = [91, 39];
        console.log(JSON.stringify(util.inspect(value, { colors: true })));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "\"42|name\" \"\\u001b[33m42\\u001b[39m|name\"\n",
            "\"\\u001b[31m42\\u001b[39m|name\"\n",
            "\"\\u001b[91m42\\u001b[39m|name\""
        ))
    );
}

#[test]
fn custom_inspect_can_be_disabled_and_observes_getters_and_inherited_hooks() {
    let source = r#"
        const util = require('node:util');
        let reads = 0;
        const value = { plain: 1 };
        Object.defineProperty(value, util.inspect.custom, {
            get() { reads++; return function() { return 'hook'; }; }
        });
        console.log(util.inspect(value, { customInspect: false }), reads);
        console.log(util.inspect(value), reads);
        util.inspect.defaultOptions.customInspect = false;
        console.log(util.inspect(value), reads);
        util.inspect.defaultOptions.customInspect = true;
        const inherited = Object.create({
            [util.inspect.custom](depth) { return 'inherited:' + depth; }
        });
        console.log(util.inspect(inherited));
        const delegated = {
            [util.inspect.custom](depth, options, inspect) {
                return 'wrapped ' + inspect({ a: 1 }, options);
            }
        };
        console.log(util.inspect(delegated));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "{ plain: 1 } 0\nhook 1\n{ plain: 1 } 1\n",
            "inherited:2\nwrapped { a: 1 }"
        ))
    );
}

#[test]
fn custom_inspect_preserves_replacement_cycles_self_returns_and_guest_exceptions() {
    let source = r#"
        const util = require('util');
        const replacement = { visible: 2 };
        replacement.self = replacement;
        console.log(util.inspect({ [util.inspect.custom]() { return replacement; } }));
        console.log(util.inspect({ value: { [util.inspect.custom]() { return 'one\ntwo'; } } }));
        let count = 0;
        const self = { visible: 3, [util.inspect.custom]() { count++; return this; } };
        const rendered = util.inspect(self);
        console.log(rendered.includes('visible: 3'), count);
        const marker = { code: 7 };
        try { util.inspect({ [util.inspect.custom]() { throw marker; } }); }
        catch (error) { console.log(error === marker); }
        const getter = {};
        Object.defineProperty(getter, util.inspect.custom, { get() { throw marker; } });
        try { util.inspect(getter); } catch (error) { console.log(error === marker); }
        console.log(util.inspect({ after: 1 }));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "<ref *1> { visible: 2, self: [Circular *1] }\n",
            "{\n  value: one\n  two\n}\n",
            "true 1\ntrue\ntrue\n{ after: 1 }"
        ))
    );
}

#[test]
fn custom_inspect_uses_proxy_target_hooks_and_skips_constructor_prototypes() {
    let source = r#"
        const util = require('util');
        let traps = 0;
        let receiver;
        const target = { [util.inspect.custom]() { return this === receiver ? 'proxy' : 'target'; } };
        receiver = new Proxy(target, { get(target, key, receiver) {
            traps++; return Reflect.get(target, key, receiver);
        } });
        console.log(util.inspect(receiver), traps);
        function Example() {}
        let calls = 0;
        Example.prototype[util.inspect.custom] = function() { calls++; return 'instance'; };
        util.inspect(Example.prototype);
        console.log(calls, util.inspect(new Example()), calls);
        const revoked = Proxy.revocable(target, {});
        revoked.revoke();
        console.log(util.inspect(revoked.proxy));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok("proxy 0\n0 instance 1\n<Revoked Proxy>")
    );
}

#[test]
fn custom_inspect_returned_data_keeps_its_confidentiality_label() {
    for (result_expression, expected) in [
        ("globalThis.__inspectPayload", "classified payload"),
        (
            "{ nested: { value: globalThis.__inspectPayload } }",
            "{ nested: { value: 'classified payload' } }",
        ),
        ("settled", "Promise { 'classified payload' }"),
    ] {
        for label in [Label::Public, Label::Secret] {
            let source = format!(
                r#"
                const util = require('util');
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                let resolve;
                const settled = new Promise(done => {{ resolve = done; }});
                resolve(globalThis.__inspectPayload);
                const value = {{ [util.inspect.custom]() {{ return {result_expression}; }} }};
                util.inspect(value);
            "#
            );
            assert_eq!(
                custom_inspect_seeded_value(&source, label.clone()),
                (Value::str(expected), label)
            );
        }
    }
}

#[test]
fn custom_inspect_observes_promise_settlement_after_an_earlier_hook() {
    let source = r#"
        const util = require('util');
        globalThis.__inspectPayload = '__inspect_callback_payload__';
        let resolve;
        const settled = new Promise(done => { resolve = done; });
        const value = {
            first: { [util.inspect.custom]() {
                resolve(globalThis.__inspectPayload);
                return 'ready';
            } },
            settled
        };
        util.inspect(value);
    "#;
    for label in [Label::Public, Label::Secret] {
        assert_eq!(
            custom_inspect_seeded_value(source, label.clone()),
            (
                Value::str("{ first: ready, settled: Promise { 'classified payload' } }"),
                label
            )
        );
    }
}

#[test]
fn custom_inspect_caught_guest_and_native_errors_keep_their_labels() {
    for (operation, caught, expected) in [
        (
            "throw globalThis.__inspectPayload",
            "error",
            "classified payload",
        ),
        (
            "throw { value: globalThis.__inspectPayload }",
            "error.value",
            "classified payload",
        ),
        (
            "return JSON.parse(globalThis.__inspectPayload)",
            "error.name",
            "SyntaxError",
        ),
        (
            "return globalThis.__inspectPayload.repeat(-1)",
            "error.name",
            "RangeError",
        ),
    ] {
        for label in [Label::Public, Label::Secret] {
            let source = format!(
                r#"
                const util = require('util');
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                const value = {{ [util.inspect.custom]() {{ {operation}; }} }};
                let caught;
                try {{ util.inspect(value); }} catch (error) {{ caught = {caught}; }}
                caught;
            "#
            );
            assert_eq!(
                custom_inspect_seeded_value(&source, label.clone()),
                (Value::str(expected), label)
            );
        }
    }
}

#[test]
fn custom_inspect_direct_string_result_preserves_exact_utf16() {
    let source = r#"
        const util = require('util');
        for (const text of [String.fromCharCode(0xd800), String.fromCharCode(0xdc00),
            String.fromCharCode(0xd800, 10, 0xdc00), 'pair:' + String.fromCodePoint(0x1f600)]) {
            const result = util.inspect({ [util.inspect.custom]() { return text; } });
            console.log(result === text, result.length, result.charCodeAt(0));
        }
        const raw = String.fromCharCode(0xd800);
        console.log(util.inspect({ [util.inspect.custom]() {
            return { [util.inspect.custom]() { return raw; } };
        } }) === raw);
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok("true 1 55296\ntrue 1 56320\ntrue 3 55296\ntrue 7 112\ntrue")
    );
}

#[test]
fn custom_inspect_multiline_indentation_obeys_the_string_limit() {
    let source = r#"
        const util = require('util');
        const value = { nested: { [util.inspect.custom]() { return '\n'.repeat(200); } } };
        util.inspect(value);
    "#;
    let module = lower(source).expect("custom inspector lowers");
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_string_size = 512;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "inspect-custom-string-limit");
    assert!(matches!(
        core.execute(&module),
        Err(InterpreterError::StringLimitExceeded {
            length: 600,
            max: 512
        })
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn inspected_promises_detect_self_mutual_and_object_cycles_at_unlimited_depth() {
    let source = r#"
        const util = require('util');
        let reject;
        const self = new Promise((_, fail) => { reject = fail; });
        self.catch(() => {});
        reject(self);
        console.log(util.inspect(self, { depth: null }));
        console.log(util.inspect({ [util.inspect.custom]() { return self; } }, { depth: null }));
        let rejectA;
        let rejectB;
        const a = new Promise((_, fail) => { rejectA = fail; });
        const b = new Promise((_, fail) => { rejectB = fail; });
        a.catch(() => {});
        b.catch(() => {});
        rejectA(b);
        rejectB(a);
        console.log(util.inspect(a, { depth: null }));
        console.log(util.inspect(a, { depth: 0 }));
        let resolve;
        const q = new Promise(done => { resolve = done; });
        resolve({ q });
        console.log(util.inspect(q, { depth: null }));
        console.log(util.inspect(q, { depth: 0 }));
    "#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "<ref *1> Promise { <rejected> [Circular *1] }\n",
            "<ref *1> Promise { <rejected> [Circular *1] }\n",
            "<ref *1> Promise { <rejected> Promise { <rejected> [Circular *1] } }\n",
            "Promise { <rejected> [Promise] }\n",
            "<ref *1> Promise { { q: [Circular *1] } }\n",
            "Promise { [Object] }"
        ))
    );
}

/// Inject only the input label into otherwise production-lowered source, so
/// success, return values and caught errors exercise the real callback path.
fn custom_inspect_seeded_value(source: &str, label: Label) -> (Value, Label) {
    let mut module = lower(source).expect("custom inspector lowers");
    let mut patched = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str()
                == Some("__inspect_callback_payload__")
        {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            patched += 1;
        }
    }
    assert_eq!(patched, 1, "seed the input, not the hook result");
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "inspect-custom-label");
    core.seed_register(255, Value::str("classified payload"))
        .unwrap();
    core.set_register_label(255, label).unwrap();
    let outcome = core.execute(&module).expect("custom inspector executes");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    (outcome.value, outcome.completion_label)
}

#[test]
fn native_error_ifc_labels_survive_nested_callbacks_iterators_events_buffers_and_generated_code() {
    for (name, source, expected) in [
        (
            "nested_callback_builtin_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                let caught;
                try { [globalThis.__inspectPayload].map((s) => s.repeat(-1)); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "RangeError",
        ),
        (
            "nested_callback_non_builtin_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                let caught;
                try { [globalThis.__inspectPayload].forEach(() => { null.boom; }); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "TypeError",
        ),
        (
            "iterator_helper_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                let caught;
                try { [1].values().map(() => globalThis.__inspectPayload.repeat(-1)).toArray(); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "RangeError",
        ),
        (
            "event_target_listener_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                const target = new EventTarget();
                target.addEventListener('ping', () => globalThis.__inspectPayload.repeat(-1));
                let caught;
                try { target.dispatchEvent(new Event('ping')); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "RangeError",
        ),
        (
            "buffer_binary_storage_label_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                const buf = Buffer.alloc(4);
                buf.write(globalThis.__inspectPayload);
                let caught;
                try { buf.readUInt32BE(999); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "RangeError",
        ),
        (
            "generated_function_native_error",
            r#"
                globalThis.__inspectPayload = '__inspect_callback_payload__';
                const gen = new Function('s', 'return s.repeat(-1)');
                let caught;
                try { gen(globalThis.__inspectPayload); }
                catch (error) { caught = error.name; }
                caught;
            "#,
            "RangeError",
        ),
    ] {
        for label in [Label::Public, Label::Secret] {
            let mut module = lower(source).unwrap_or_else(|err| panic!("{name} lowers: {err}"));
            let mut patched = 0;
            for instruction in &mut module.instructions {
                if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
                    && module.constant_pool[pool_index as usize].as_str()
                        == Some("__inspect_callback_payload__")
                {
                    *instruction = Ir3Instruction::Move { dst, src: 255 };
                    patched += 1;
                }
            }
            assert_eq!(patched, 1, "{name}: seed the input payload once");
            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::IrLowering,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, name);
            core.seed_register(255, Value::str("classified payload"))
                .unwrap();
            core.set_register_label(255, label.clone()).unwrap();
            let outcome = core
                .execute(&module)
                .unwrap_or_else(|err| panic!("{name} ({label:?}) executes: {err}"));
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "{name} ({label:?}) memory accounting drift"
            );
            assert_eq!(
                (outcome.value, outcome.completion_label),
                (Value::str(expected), label),
                "{name}: caught native error lost IFC label"
            );
        }
    }
}

#[test]
fn inspect_exotic_proxy_targets_preserves_native_format_and_single_hook_lookup() {
    let source = r#"
const util = require('node:util');
console.log([
  util.inspect(new Proxy(Promise.resolve(7), {})),
  util.inspect(new Proxy((function* () {})(), {})),
  util.inspect(new Proxy([1].values(), {})),
  util.inspect(new Proxy((async function* () {})(), {}))
].join('|'));
const target = Promise.resolve(8);
let reads = 0;
let calls = 0;
let traps = 0;
let getterReceiver;
let mode = 0;
const handler = {get(target, key, receiver) {
  traps++;
  return Reflect.get(target, key, receiver);
}};
const proxy = new Proxy(target, handler);
Object.defineProperty(target, util.inspect.custom, {get() {
  reads++;
  getterReceiver = this;
  if (mode === 0) return undefined;
  return function(depth, options, inspect) {
    calls++;
    if (mode === 2) return this;
    return [this === proxy, getterReceiver === target, depth, inspect === util.inspect].join(':');
  };
}});
console.log(util.inspect(proxy), reads, calls, getterReceiver === target, traps);
mode = 1; reads = 0; calls = 0;
console.log(util.inspect(proxy, {depth: 1}), reads, calls, traps);
mode = 2; reads = 0; calls = 0;
console.log(util.inspect(proxy), reads, calls, getterReceiver === target, traps);
reads = 0; calls = 0;
console.log(util.inspect(proxy, {customInspect: false}), reads, calls, traps);
"#;
    assert_eq!(
        console_output(source).as_deref(),
        Ok(concat!(
            "Promise { 7 }|Object [Generator] {}|Object [Array Iterator] {}|Object [AsyncGenerator] {}\n",
            "Promise { 8 } 1 0 true 0\n",
            "true:true:1:true 1 1 0\n",
            "Promise { 8 } 1 1 true 0\n",
            "Promise { 8 } 0 0 0"
        ))
    );
}
