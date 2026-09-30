//! The `in` operator on function values.
//!
//! It answered from a fixed list (`name`, `prototype`) for user functions,
//! ignored their own properties, class statics and everything they inherit
//! (`'call' in f` was false), claimed a `prototype` for arrows, and failed
//! with "expected object, got function" on builtins (`'from' in Array`).
//! Expected lines are Node v22.2.0's (`node -e`).
//!
//! The same held for promises, generators, async generators and builtin
//! iterators, which are objects in JS but not heap objects here: `in` threw
//! "expected object, got object". lodash's getTag evaluates
//! `Symbol.toStringTag in Object(value)` for every value it inspects, so any
//! lodash call that saw a promise threw.

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
        "in_fn_own",
        r#"function f() {} f.x = 1; console.log('x' in f, 'y' in f, 'name' in f, 'call' in f, 'toString' in f);"#,
        "true false true true true",
    ),
    (
        "in_builtin",
        r#"console.log('prototype' in Map, 'from' in Array, 'isArray' in Array, 'x' in Math);"#,
        "true true true false",
    ),
    (
        "in_class_static",
        r#"class A { static s() {} } console.log('s' in A, 'prototype' in A, 'length' in A);"#,
        "true true true",
    ),
    (
        "in_arrow",
        r#"const g = () => 1; g.tag = 2; console.log('tag' in g, 'prototype' in g, 'bind' in g);"#,
        "true false true",
    ),
];

/// Object-like values without a heap object: what they supply themselves
/// (promise methods, generator next/return/throw and @@iterator, iterator
/// methods) and what they inherit from Object.prototype.
const OBJECT_LIKE_CASES: &[(&str, &str, &str)] = &[
    (
        "in_promise",
        r#"var p = Promise.resolve(); console.log(['then' in p,'catch' in p,'finally' in p,'x' in p,'hasOwnProperty' in p,'constructor' in p].join());"#,
        "true,true,true,false,true,true",
    ),
    (
        "in_generator",
        r#"function* g() { yield 1; } var it = g(); console.log(['next' in it,'return' in it,'throw' in it, Symbol.iterator in it,'x' in it,'toString' in it].join());"#,
        "true,true,true,true,false,true",
    ),
    (
        "in_async_generator",
        r#"async function* ag() { yield 1; } var a = ag(); console.log(['next' in a, Symbol.asyncIterator in a, 'x' in a, 'hasOwnProperty' in a].join());"#,
        "true,true,false,true",
    ),
    (
        "in_builtin_iterators",
        r#"var it = [1, 2][Symbol.iterator](); var m = new Map([[1, 2]]).entries(); console.log(['next' in it, Symbol.iterator in it, 'x' in it, 'next' in m, 'toString' in m].join());"#,
        "true,true,false,true,true",
    ),
    (
        "lodash_get_tag_probe",
        r#"var tag = Symbol.toStringTag in Object(Promise.resolve()); console.log(typeof tag);"#,
        "boolean",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "infn.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "infn.js"),
        &LoweringContext::new("infn-trace", "infn-decision", "infn-policy"),
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
    let mut core = InterpreterCore::new(config, "infn");
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

fn assert_cases_match_node(cases: &[(&str, &str, &str)]) {
    let mut mismatches = Vec::new();
    for (name, source, node) in cases {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}

#[test]
fn in_operator_on_functions_matches_node() {
    assert_cases_match_node(CASES);
}

#[test]
fn in_operator_on_object_like_values_matches_node() {
    assert_cases_match_node(OBJECT_LIKE_CASES);
}
