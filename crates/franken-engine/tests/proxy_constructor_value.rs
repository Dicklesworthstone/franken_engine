//! `Proxy` is a first-class constructor value.
//!
//! `new Proxy(t, h)` worked (intercepted at lowering), but a bare `Proxy`
//! had no binding: `typeof Proxy` was "undefined", so libraries that feature
//! detect it (immer, Vue, MobX) took their no-Proxy paths, and the
//! constructor could not be stored or passed. Expected lines are Node
//! v22.2.0's for the same programs (`node -e`).

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
        "typeof_and_alias",
        r#"const P = Proxy; const p = new P({}, { get: (t, k) => k + '!' }); console.log(typeof Proxy, p.hello, typeof P);"#,
        "function hello! function",
    ),
    (
        "name_length_prototype",
        r#"console.log(Proxy.name, Proxy.length, Proxy.prototype);"#,
        "Proxy 2 undefined",
    ),
    (
        "revocable_through_alias",
        r#"const P = Proxy; const r = P.revocable({ a: 1 }, {}); console.log(r.proxy.a); r.revoke(); let threw = false; try { r.proxy.a; } catch (e) { threw = e instanceof TypeError; } console.log(threw);"#,
        "1\ntrue",
    ),
    (
        "feature_detection",
        r#"const hasProxy = typeof Proxy !== 'undefined' && typeof Proxy === 'function'; console.log(hasProxy ? 'proxy' : 'fallback');"#,
        "proxy",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "proxy.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "proxy.js"),
        &LoweringContext::new("proxy-trace", "proxy-decision", "proxy-policy"),
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
    let mut core = InterpreterCore::new(config, "proxy");
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
fn proxy_constructor_value_matches_node() {
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
