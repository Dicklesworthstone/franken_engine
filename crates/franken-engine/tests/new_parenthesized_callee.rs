//! `new (Callee)(args)` followed by a member access or call.
//!
//! The parser took the parenthesised callee for the argument list and the
//! last `(...)` for the arguments, so `new (K)().m()` constructed
//! `(K)().m` (calling K without `new`) and failed with "expected object,
//! got undefined". The `new (Function.bind.apply(P, args))()` shape is
//! Babel's construct helper. Expected lines are Node v22.2.0's (`node -e`).

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
        "parenthesized_callees_with_trailing_access",
        r#"class K { m() { return 4; } } const o = { K }; function F() { this.x = 3; } console.log(new (K)().m(), new (o.K)().m(), new (F)().x, new (function () { this.y = 2; })().y, typeof new (K), new (class { constructor(a) { this.a = a; } })(5)['a']);"#,
        "4 4 3 2 object 5",
    ),
    (
        "class_from_a_field_initializer",
        r#"class C { k = class { m() { return arguments.length; } }; } console.log(new (new C().k)().m(1, 2));"#,
        "2",
    ),
    (
        "bind_apply_construct_helper",
        r#"function P(a, b) { this.s = a + b; } const args = [null, 2, 3]; const inst = new (Function.bind.apply(P, args))(); console.log(inst.s, inst instanceof P);"#,
        "5 true",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "newparen.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "newparen.js"),
        &LoweringContext::new("newparen-trace", "newparen-decision", "newparen-policy"),
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
    let mut core = InterpreterCore::new(config, "newparen");
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
fn new_with_parenthesized_callee_matches_node() {
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
