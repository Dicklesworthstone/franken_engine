//! An array's `length` is not enumerable: for-in over an array visited it
//! after the indices (`for (var i in [1, 2, 3]) s += +i` gave NaN), for
//! array subclasses and objects inheriting from an array as well, and its
//! descriptor reported enumerable and configurable. ES2020 9.4.2.2 creates
//! it { writable, not enumerable, not configurable }; the effective
//! attributes now say so, and for-in, Object.keys, descriptors and delete
//! read them. Expected lines are Node v22.2.0's (`node -e`).

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "literal",
        r#"const a = []; for (const i in [1, 2, 3]) a.push(i); console.log(a.join());"#,
        "0,1,2",
    ),
    (
        "extra_named_property",
        r#"const a = []; const arr = [1, 2]; arr.x = 1; for (const i in arr) a.push(i); console.log(a.join());"#,
        "0,1,x",
    ),
    (
        "after_push",
        r#"const a = []; const arr = [1, 2]; arr.push(3); for (var i in arr) a.push(i); console.log(a.join());"#,
        "0,1,2",
    ),
    (
        "sparse",
        r#"const a = []; const arr = new Array(3); arr[1] = 1; for (const i in arr) a.push(i); console.log(a.join());"#,
        "1",
    ),
    (
        "sum_of_indices",
        r#"let s = 0; for (var i in [1, 2, 3]) s += +i; console.log(s);"#,
        "3",
    ),
    (
        "object_create_array",
        r#"const a = []; for (const i in Object.create([1, 2])) a.push(i); console.log(a.join());"#,
        "0,1",
    ),
    (
        "array_subclass",
        r#"class A extends Array {} const b = new A(); b.push(1); const a = []; for (const i in b) a.push(i); console.log(a.join());"#,
        "0",
    ),
    (
        "descriptor",
        r#"const d = Object.getOwnPropertyDescriptor([1, 2], 'length'); console.log([d.value, d.writable, d.enumerable, d.configurable].join());"#,
        "2,true,false,false",
    ),
    (
        "delete_and_property_is_enumerable",
        r#"const a = [1]; console.log(delete a.length, a.length, a.propertyIsEnumerable('length'));"#,
        "false 1 false",
    ),
    (
        "plain_object_length_stays",
        r#"const a = []; for (const i in { length: 5, x: 1 }) a.push(i); console.log(a.join());"#,
        "length,x",
    ),
    (
        "after_truncation",
        r#"const a = [1, 2]; a.length = 1; const k = []; for (const i in a) k.push(i); console.log(k.join(), a.length, Object.keys(a).join());"#,
        "0 1 0",
    ),
    (
        "non_writable_length",
        r#"const a = []; const arr = [1, 2]; Object.defineProperty(arr, 'length', { writable: false }); for (const i in arr) a.push(i); const d = Object.getOwnPropertyDescriptor(arr, 'length'); console.log(a.join(), d.writable, d.enumerable);"#,
        "0,1 false false",
    ),
    (
        "define_length_validates_the_value_first",
        r#"const r = []; for (const d of [{ value: -1, configurable: true }, { value: 1.5 }, { value: 1, configurable: true }, { value: 0 }]) { const a = [1, 2]; try { Object.defineProperty(a, 'length', d); r.push('ok ' + a.length); } catch (e) { r.push(e.constructor.name); } } console.log(r.join());"#,
        "RangeError,RangeError,TypeError,ok 0",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "arraylength.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "arraylength.js"),
        &LoweringContext::new(
            "arraylength-trace",
            "arraylength-decision",
            "arraylength-policy",
        ),
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
    let mut core = InterpreterCore::new(config, "arraylength");
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
fn array_length_is_not_enumerable() {
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
