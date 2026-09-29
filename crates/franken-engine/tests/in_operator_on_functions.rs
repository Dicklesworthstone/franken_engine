//! The `in` operator on function values.
//!
//! It answered from a fixed list (`name`, `prototype`) for user functions,
//! ignored their own properties, class statics and everything they inherit
//! (`'call' in f` was false), claimed a `prototype` for arrows, and failed
//! with "expected object, got function" on builtins (`'from' in Array`).
//! Expected lines are Node v22.2.0's (`node -e`).

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

#[test]
fn in_operator_on_functions_matches_node() {
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
