//! `Promise.resolve(p)` returns `p`; `Promise.reject(p)` is a new promise
//! rejected with `p`; neither settles an existing promise.
//!
//! The static methods shared a hostcall with an internal "settle this promise
//! with the next argument" form. `Promise.resolve(p)` therefore tried to
//! fulfill `p` with undefined: a TypeError ("already settled") when `p` had
//! settled, as in `Promise.resolve(asyncFn())`, and a pending `p` was
//! fulfilled with undefined. `Promise.resolve(p, v)` and
//! `Promise.reject(p, r)` settled another party's pending promise, which only
//! its own resolving functions may do.
//!
//! Printed lines are Node v22.2.0's for the same programs; the
//! memory-accounting oracle must hold after each run.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "presolve.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "presolve.js"),
        &LoweringContext::new("presolve-trace", "presolve-decision", "presolve-policy"),
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
    let mut core = InterpreterCore::new(config, "presolve");
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

fn check_all(cases: &[(&str, &str)]) {
    let mismatches: Vec<String> = cases
        .iter()
        .filter_map(|(source, node)| match console_lines(source) {
            Ok(output) if output == *node => None,
            other => Some(format!("`{source}`: node {node:?}, got {other:?}")),
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}

#[test]
fn promise_resolve_returns_a_promise_argument_itself() {
    check_all(&[
        (
            "const p = Promise.resolve(7); console.log(Promise.resolve(p) === p);",
            "true",
        ),
        (
            "const p = Promise.resolve(7); Promise.resolve(p).then((v) => console.log(v));",
            "7",
        ),
        (
            "async function f() { return 5; } Promise.resolve(f()).then((v) => console.log(v));",
            "5",
        ),
        (
            "Promise.resolve(Promise.resolve(Promise.resolve(2))).then((v) => console.log(v));",
            "2",
        ),
        (
            "let r; const p = new Promise((res) => { r = res; }); \
             Promise.resolve(p).then((v) => console.log('late', v)); console.log('before'); r(3);",
            "before\nlate 3",
        ),
        (
            "const p = Promise.reject(new Error('x')); \
             Promise.resolve(p).catch((e) => console.log('rej', e.message));",
            "rej x",
        ),
        (
            "const p = Promise.resolve(1); (async () => { console.log(await Promise.resolve(p)); })();",
            "1",
        ),
        // Spread call: the apply path reaches the same hostcall.
        (
            "const p = Promise.resolve(4); console.log(Promise.resolve(...[p]) === p);",
            "true",
        ),
    ]);
}

#[test]
fn promise_reject_of_a_promise_is_a_new_rejection() {
    check_all(&[(
        "const p = Promise.resolve(1); Promise.reject(p).catch((r) => console.log(r === p));",
        "true",
    )]);
}

#[test]
fn extra_arguments_do_not_settle_another_promise() {
    check_all(&[
        (
            "const p = new Promise(() => {}); const q = Promise.resolve(p, 'hijacked'); \
             p.then((v) => console.log('settled', v)); \
             Promise.resolve().then(() => Promise.resolve()).then(() => console.log('end', q === p));",
            "end true",
        ),
        (
            "const p = new Promise(() => {}); Promise.reject(p, 'x').catch((r) => console.log(r === p)); \
             p.then(() => console.log('p fulfilled'), () => console.log('p rejected')); \
             Promise.resolve().then(() => Promise.resolve()).then(() => console.log('end'));",
            "true\nend",
        ),
    ]);
}
