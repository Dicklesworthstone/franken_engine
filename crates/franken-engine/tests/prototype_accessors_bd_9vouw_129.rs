//! bd-9vouw.129: built-in prototype accessors have descriptors.
//!
//! `Object.getOwnPropertyDescriptor(Map.prototype, 'size')` was undefined,
//! as was every built-in accessor: the engine serves the values from each
//! instance and never described the prototype's getter. object-inspect (via
//! qs and side-channel) reads `Map.prototype.size`'s getter to recognize
//! Maps, so it printed `Map [Map] {}` for `new Map([[1, 2]])`.
//!
//! PROGRAM describes Map/Set `size`, ArrayBuffer and DataView `byteLength`
//! (and DataView `buffer`/`byteOffset`), %TypedArray% `buffer`,
//! `byteLength`, `byteOffset` and `length`, RegExp `flags`, `global` and
//! `source`, and Symbol `description`, then calls the getters on instances
//! and on wrong receivers. NODE_OUTPUT is Node v22.2.0's output.
//!
//! No-claim: the accessors are described, not installed as properties, so
//! `Object.getOwnPropertyNames(Map.prototype)` does not list `size`
//! (bd-9vouw.122 territory); reading `Map.prototype.size` directly still
//! gives undefined where Node throws.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const tap = Object.getPrototypeOf(Uint8Array.prototype);
const rows = [[Map.prototype, 'size'], [Set.prototype, 'size'], [ArrayBuffer.prototype, 'byteLength'], [DataView.prototype, 'buffer'], [DataView.prototype, 'byteLength'], [DataView.prototype, 'byteOffset'], [tap, 'buffer'], [tap, 'byteLength'], [tap, 'byteOffset'], [tap, 'length'], [RegExp.prototype, 'flags'], [RegExp.prototype, 'global'], [RegExp.prototype, 'source'], [Symbol.prototype, 'description']];
console.log(rows.map(function (row) { var d = Object.getOwnPropertyDescriptor(row[0], row[1]); return [row[1], typeof d.get, d.set, d.enumerable, d.configurable, d.get.name, d.get.length].join(':'); }).join(' '));
const mapSize = Object.getOwnPropertyDescriptor(Map.prototype, 'size').get;
console.log(mapSize.call(new Map([[1, 2], [3, 4]])), Object.getOwnPropertyDescriptor(Set.prototype, 'size').get.call(new Set([1])));
try { mapSize.call(new Set()); } catch (e) { console.log('set receiver', e instanceof TypeError); }
try { mapSize.call({}); } catch (e) { console.log('plain receiver', e instanceof TypeError); }
const ta = new Uint8Array(new ArrayBuffer(8), 2, 3);
console.log(Object.getOwnPropertyDescriptor(tap, 'length').get.call(ta), Object.getOwnPropertyDescriptor(tap, 'byteOffset').get.call(ta), Object.getOwnPropertyDescriptor(tap, 'byteLength').get.call(ta), Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get.call(ta.buffer), Object.getOwnPropertyDescriptor(tap, 'buffer').get.call(ta) === ta.buffer);
const dv = new DataView(new ArrayBuffer(6), 1, 4);
console.log(Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get.call(dv), Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get.call(dv));
console.log(Object.getOwnPropertyDescriptor(RegExp.prototype, 'flags').get.call(/a/gi), Object.getOwnPropertyDescriptor(RegExp.prototype, 'global').get.call(/a/g), Object.getOwnPropertyDescriptor(RegExp.prototype, 'source').get.call(/a+b/), Object.getOwnPropertyDescriptor(Symbol.prototype, 'description').get.call(Symbol('d')));
try { Object.getOwnPropertyDescriptor(tap, 'length').get.call([1, 2]); } catch (e) { console.log('array receiver', e instanceof TypeError); }
console.log(Object.getOwnPropertyDescriptor(Map.prototype, 'nope'), typeof Object.getOwnPropertyDescriptor(Map.prototype, 'get').value);"#;

const NODE_OUTPUT: &str = r#"size:function::false:true:get size:0 size:function::false:true:get size:0 byteLength:function::false:true:get byteLength:0 buffer:function::false:true:get buffer:0 byteLength:function::false:true:get byteLength:0 byteOffset:function::false:true:get byteOffset:0 buffer:function::false:true:get buffer:0 byteLength:function::false:true:get byteLength:0 byteOffset:function::false:true:get byteOffset:0 length:function::false:true:get length:0 flags:function::false:true:get flags:0 global:function::false:true:get global:0 source:function::false:true:get source:0 description:function::false:true:get description:0
2 1
set receiver true
plain receiver true
3 2 3 8 true
4 1
gi true a+b d
array receiver true
undefined function"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "prototype-accessors.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "prototype-accessors.js"),
        &LoweringContext::new("accessor-trace", "accessor-decision", "accessor-policy"),
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
    let mut core = InterpreterCore::new(config, "prototype-accessors");
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
fn builtin_prototype_accessors_match_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
