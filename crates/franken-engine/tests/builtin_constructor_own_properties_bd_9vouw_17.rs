//! bd-9vouw.17: the standard constructors' own properties on the
//! reflection paths.
//!
//! Reading `Object.keys` or `Number.MAX_SAFE_INTEGER` worked, but
//! `Object.hasOwnProperty('keys')` was false and
//! `Object.getOwnPropertyDescriptor(Object, 'keys')` undefined, as for
//! `Error.prototype`, `Symbol.iterator`, `Date.parse` (hasOwnProperty only)
//! and %Function.prototype%'s own `length` and `name`. PROGRAM checks
//! hasOwnProperty, Object.hasOwn, the descriptors' values and attributes,
//! own-key lists, keys a constructor only inherits (`call`, a concrete
//! typed array's `from`), Proxy's missing `prototype`, and a static added by
//! the program next to the built-in ones. NODE_OUTPUT is Node v22.2.0's
//! output.
//!
//! No-claim: deleting a built-in static (`delete Object.assign`) removes it
//! from the reflection paths, but a read still finds the built-in.
//! Own-key order follows the engine's table (alphabetical), not V8's.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"function d(o, k) { var x = Object.getOwnPropertyDescriptor(o, k); return x ? [typeof x.value, x.writable, x.enumerable, x.configurable].join(',') : 'none'; }
console.log(Error.hasOwnProperty('prototype'), d(Error, 'prototype'), d(ReferenceError, 'prototype'), Object.getOwnPropertyDescriptor(Error, 'prototype').value === Error.prototype);
console.log(Function.prototype.hasOwnProperty('length'), d(Function.prototype, 'length'), d(Function.prototype, 'name'), Function.prototype.length, JSON.stringify(Function.prototype.name));
console.log(d(Symbol, 'keyFor'), d(Symbol, 'split'), d(Symbol, 'iterator'), Object.getOwnPropertyDescriptor(Symbol, 'iterator').value === Symbol.iterator);
console.log(Date.hasOwnProperty('parse'), d(Date, 'parse'), Date.hasOwnProperty('UTC'), Date.hasOwnProperty('prototype'), d(Date, 'prototype'));
console.log(d(Object, 'keys'), Object.hasOwnProperty('keys'), Object.hasOwn(Object, 'keys'), d(Math, 'max'), d(JSON, 'stringify'));
console.log(d(Array, 'isArray'), d(Promise, 'resolve'), d(Number, 'MAX_SAFE_INTEGER'), Object.getOwnPropertyDescriptor(Number, 'MAX_SAFE_INTEGER').value === Number.MAX_SAFE_INTEGER);
console.log(Object.hasOwnProperty('call'), Object.hasOwnProperty('nope'), Uint8Array.hasOwnProperty('from'), Object.getPrototypeOf(Uint8Array).hasOwnProperty('from'), d(Uint8Array, 'BYTES_PER_ELEMENT'), Proxy.hasOwnProperty('prototype'));
console.log(Object.getOwnPropertyDescriptor(Object, 'keys').value === Object.keys, Object.getOwnPropertyNames(Number).includes('MAX_SAFE_INTEGER'), Object.getOwnPropertyNames(Object).includes('assign'), Object.keys(Object).length, Object.keys(Number).length);
Object.extraStatic = 1;
console.log(Object.hasOwnProperty('extraStatic'), Object.hasOwnProperty('keys'), d(Object, 'extraStatic'), d(Object, 'keys'));
console.log(Object.prototype.hasOwnProperty.call(Symbol, 'asyncIterator'), Object.prototype.hasOwnProperty.call(Error, 'captureStackTrace'), Reflect.ownKeys(BigInt).includes('asUintN'));"#;

const NODE_OUTPUT: &str = r#"true object,false,false,false object,false,false,false true
true number,false,false,true string,false,false,true 0 ""
function,true,false,true symbol,false,false,false symbol,false,false,false true
true function,true,false,true true true object,false,false,false
function,true,false,true true true function,true,false,true function,true,false,true
function,true,false,true function,true,false,true number,false,false,false true
false false false true number,false,false,false false
true true true 0 0
true true number,true,true,true function,true,false,true
true true true"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "constructor-own-properties.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "constructor-own-properties.js"),
        &LoweringContext::new("ctor-own-trace", "ctor-own-decision", "ctor-own-policy"),
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
    let mut core = InterpreterCore::new(config, "constructor-own-properties");
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
fn constructor_own_properties_reflect_like_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
