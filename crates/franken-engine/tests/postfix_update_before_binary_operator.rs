//! A postfix `++`/`--` followed by a binary `+`/`-`.
//!
//! The parser's operator scan took the first `+` of `a++` as the split point
//! and skipped the next `+` as a sign, so `a++ + 2` parsed as `a + (+(+2))`:
//! the sum was right but `a` was never incremented. `a+++2` and `a---1`
//! failed with "invalid update target". Expected lines are Node v22.2.0's
//! (`node -e`).

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
        "update_then_binary",
        r#"let a = 1; let b = a+++2; let c = a++ + 3; let d = a---1; let e = a - --a; let f = (a++) - 1; let o = { v: 1 }; let g = o.v++ + 10; console.log(a, b, c, d, e, f, g, o.v);"#,
        "2 3 5 2 1 0 11 2",
    ),
    (
        "loop_with_update_in_sum",
        r#"const xs = [1, 2, 3, 4]; let i = 0; let total = 0; while (i < xs.length) { total = total + xs[i++] * 10 + i-- - i++; } console.log(total, i);"#,
        "104 4",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "update.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "update.js"),
        &LoweringContext::new("update-trace", "update-decision", "update-policy"),
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
    let mut core = InterpreterCore::new(config, "update");
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
fn postfix_update_before_binary_operator_matches_node() {
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
