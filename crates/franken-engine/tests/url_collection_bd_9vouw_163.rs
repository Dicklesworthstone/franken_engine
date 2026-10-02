//! bd-9vouw.163: URL and URLSearchParams objects no longer disable garbage
//! collection.
//!
//! The collector refused to run while any URL or URLSearchParams state
//! existed (it was host state "not traced yet"), so one `new URL(...)` and
//! the program died at the 100,000-object budget. Their state is now traced
//! like an ephemeron (a reachable URL keeps its searchParams, a reachable
//! URLSearchParams its URL) and purged with its charge when the object is
//! reclaimed. Each run uses the default (QuickJS-profile) budgets, must
//! collect, and checks estimated == recomputed memory afterwards. Expected
//! strings are Node v22.2.0's output for the same programs.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn run(source: &str) -> String {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "url_gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "url_gc.js"),
        &LoweringContext::new("url-gc-trace", "url-gc-decision", "url-gc-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "url-gc");
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("`{source}` failed: {error:?}"));
    assert!(core.gc_stats().collections > 0, "the program collects");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift after collection"
    );
    match result.value {
        Value::Str(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

/// A live URL no longer blocks collection; it stays linked to its searchParams across collections.
#[test]
fn url_collection_garbage_after_a_url() {
    let source = "const u = new URL('http://h.example/p?a=1');\n\
         let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; }\n\
         u.searchParams.append('b', '2');\n\
         [s, u.href, u.searchParams.get('a')].join(' ');";
    assert_eq!(run(source), "125000 http://h.example/p?a=1&b=2 1");
}

/// Only the searchParams object is still referenced: its URL survives and is still updated.
#[test]
fn url_collection_garbage_after_url_search_params() {
    let source = "const p = new URL('http://h.example/?a=1').searchParams;\n\
         const standalone = new URLSearchParams('x=1');\n\
         let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; }\n\
         p.append('c', '3'); standalone.set('x', '2');\n\
         [s, p.toString(), standalone.toString()].join(' ');";
    assert_eq!(run(source), "125000 a=1&c=3 x=2");
}

/// URLs that become unreachable are reclaimed: 150,000 of them fit the 100,000-object budget.
#[test]
fn url_collection_urls_are_reclaimed() {
    let source = "let n = 0;\n\
         for (let i = 0; i < 150000; i++) { const u = new URL('http://h.example/' + i); n += u.pathname.length; }\n\
         [n].join(' ');";
    assert_eq!(run(source), "938890");
}
