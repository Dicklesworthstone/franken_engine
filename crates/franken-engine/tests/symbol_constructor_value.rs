//! `Symbol` is a first-class value.
//!
//! `Symbol('x')`, `Symbol.for` and `Symbol.iterator` worked (intercepted at
//! lowering), but a bare `Symbol` had no binding, so `const S = Symbol`
//! failed with "Symbol is not defined", `sym.constructor` was missing, and
//! the `root.Symbol` aliases libraries take at load (lodash) could not be
//! built. `new Symbol()` and `new BigInt(1)` are TypeErrors, as in Node.
//! Expected lines are Node v22.2.0's for the same programs (`node -e`).

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
        "symbol_as_value",
        r#"const S = Symbol; const a = S('x'); console.log(typeof S, typeof a, a.toString(), S === Symbol, S.iterator === Symbol.iterator, typeof S.for);"#,
        "function symbol Symbol(x) true true function",
    ),
    (
        "symbol_constructor_and_statics",
        r#"console.log(Symbol('q').constructor === Symbol, Symbol.name, Symbol.length, typeof Symbol.asyncIterator, Symbol.keyFor(Symbol.for('r')));"#,
        "true Symbol 0 symbol r",
    ),
    (
        "not_constructible",
        r#"const r = []; for (const f of [() => new Symbol(), () => new BigInt(1)]) { try { f(); r.push('no throw'); } catch (e) { r.push(e instanceof TypeError); } } console.log(r.join());"#,
        "true,true",
    ),
    (
        "root_symbol_alias",
        r#"var root = { Symbol: Symbol }; var Sym = root.Symbol; var symToStringTag = Sym ? Sym.toStringTag : undefined; console.log(typeof symToStringTag, Object.prototype.toString.call({ [symToStringTag]: 'Tagged' }));"#,
        "symbol [object Tagged]",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "symbol.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "symbol.js"),
        &LoweringContext::new("symbol-trace", "symbol-decision", "symbol-policy"),
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
    let mut core = InterpreterCore::new(config, "symbol");
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
fn symbol_constructor_value_matches_node() {
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
