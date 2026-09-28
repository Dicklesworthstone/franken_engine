//! Reclaiming collector on the baseline interpreter heap (bd-9vouw.57).
//!
//! Before the collector every allocation was permanent. Under the default
//! (QuickJS-profile) budget of 100,000 heap objects, a loop that creates one
//! short-lived object per iteration died at iteration 100,001 with "memory
//! budget exceeded", however small its live set.
//!
//! These tests run real source through the parser, the lowering and the
//! interpreter. Expected strings are what Node v22.2.0 prints for
//! `String(<program>)`. Every run also checks the memory-accounting
//! invariant (estimated == recomputed) after collections.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, GcStats, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

struct Run {
    result: Result<ExecutionResult, InterpreterError>,
    gc: GcStats,
}

fn run(source: &str, stress_interval: Option<u64>) -> Run {
    try_run(source, stress_interval).expect("source must parse and lower")
}

/// `None` when the source does not parse or lower (e.g. a probe that the
/// capability policy rejects at lowering).
fn try_run(source: &str, stress_interval: Option<u64>) -> Option<Run> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .ok()?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "gc.js"),
        &LoweringContext::new("gc-trace", "gc-decision", "gc-policy"),
    )
    .ok()?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "gc");
    core.set_gc_stress_interval(stress_interval);
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift after collection: {source}"
    );
    Some(Run {
        result,
        gc: core.gc_stats(),
    })
}

fn value_of(run: &Run, source: &str) -> String {
    match &run.result {
        Ok(result) => match &result.value {
            Value::Str(text) => text.to_string(),
            other => format!("{other:?}"),
        },
        Err(error) => panic!("`{source}` failed: {error:?}"),
    }
}

/// Each loop allocates about 250,000 short-lived objects, 2.5x the default
/// 100,000-object budget, and keeps an O(1) live set.
const GARBAGE_LOOPS: &[(&str, &str)] = &[
    (
        "let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; } String(s)",
        "125000",
    ),
    (
        "let s = 0; for (let i = 0; i < 250000; i++) { const a = [i, i]; s += a[1] & 1; } String(s)",
        "125000",
    ),
    (
        "let s = 0; for (let i = 0; i < 125000; i++) { const o = { inner: { v: i } }; s += o.inner.v & 1; } String(s)",
        "62500",
    ),
    (
        "class P { constructor(x) { this.x = x; } inc() { return this.x + 1; } } \
         let s = 0; for (let i = 0; i < 250000; i++) { s = (s + new P(i).inc()) % 1000003; } String(s)",
        "31250",
    ),
    (
        "const m = new Map(); for (let i = 0; i < 250000; i++) { m.set(i % 100, { i }); } \
         String(m.size + m.get(99).i)",
        "250099",
    ),
];

#[test]
fn garbage_loops_complete_past_the_object_budget() {
    for (source, node) in GARBAGE_LOOPS {
        let run = run(source, None);
        assert_eq!(value_of(&run, source), *node, "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
        assert!(
            run.gc.reclaimed_objects >= 150_000,
            "reclaimed only {} objects: {source}",
            run.gc.reclaimed_objects
        );
        assert_eq!(run.gc.skipped_collections, 0, "{source}");
    }
}

/// Closures are not heap objects, but each captures an environment that the
/// byte budget charges. The perf suite's `closures` workload died on the
/// 64 MiB budget near 100,000 closures before closures were reclaimed.
const CLOSURE_LOOPS: &[(&str, &str)] = &[
    (
        "let s = 0; for (let i = 0; i < 250000; i++) { const f = () => i; s += f() & 1; } String(s)",
        "125000",
    ),
    (
        "function mk(k) { return function (x) { return x + k; }; } \
         let s = 0; for (let i = 0; i < 150000; i++) s = mk(i)(s) % 1000003; String(s)",
        "891253",
    ),
];

#[test]
fn closure_garbage_loops_complete_past_the_byte_budget() {
    for (source, node) in CLOSURE_LOOPS {
        let run = run(source, None);
        assert_eq!(value_of(&run, source), *node, "{source}");
        assert!(
            run.gc.reclaimed_closures >= 50_000,
            "reclaimed only {} closures: {source}",
            run.gc.reclaimed_closures
        );
    }
}

/// A 300,000-iteration garbage loop runs after the live structures are built;
/// every structure must read back intact.
const CHURN: &str = "for (let i = 0; i < 300000; i++) { const g = { i }; }";

fn reachable_cases() -> Vec<(String, &'static str)> {
    let cases: &[(&str, &str, &str)] = &[
        (
            "retained array of objects",
            "const keep = []; for (let i = 0; i < 1000; i++) keep.push({ v: i });",
            "String(keep.reduce((sum, o) => sum + o.v, 0))",
        ),
        (
            "linked list",
            "let head = null; for (let i = 0; i < 1000; i++) head = { v: i, next: head };",
            "let s = 0; for (let n = head; n; n = n.next) s += n.v; String(s)",
        ),
        (
            "Map object keys held only by the map",
            "const m = new Map(); for (let i = 0; i < 50; i++) m.set({ id: i }, i);",
            "let s = 0; for (const [k, v] of m) s += k.id + v; String(s)",
        ),
        (
            "Set members",
            "const set = new Set(); for (let i = 0; i < 50; i++) set.add({ id: i });",
            "let s = 0; for (const o of set) s += o.id; String(s)",
        ),
        (
            "closure capture",
            "const f = (() => { const o = { v: 7 }; return () => o.v; })();",
            "String(f())",
        ),
        (
            "class instances and prototype methods",
            "class A { constructor() { this.n = 3; } twice() { return this.n * 2; } } const a = new A();",
            "String(a.twice())",
        ),
        (
            "accessor capturing an object",
            "const box = { v: 11 }; const o = { get v() { return box.v; } };",
            "String(o.v)",
        ),
        (
            "suspended generator holding an object",
            "function* g() { const o = { v: 5 }; yield 1; yield o.v; } const it = g(); it.next();",
            "String(it.next().value)",
        ),
        (
            "WeakMap value with a live key",
            "const wm = new WeakMap(); const key = {}; wm.set(key, { v: 42 });",
            "String(wm.get(key).v)",
        ),
        (
            "symbol-keyed property",
            "const sym = Symbol('s'); const o = { [sym]: { v: 9 } };",
            "String(o[sym].v)",
        ),
        (
            "typed array and its buffer",
            "const t = new Uint8Array([1, 2, 3]);",
            "String(t[0] + t[1] + t[2])",
        ),
        (
            "nested containers",
            "const m = new Map([['k', [{ v: 4 }]]]);",
            "String(m.get('k')[0].v)",
        ),
        (
            "bound function target",
            "const obj = { v: 6, get() { return this.v; } }; const b = obj.get.bind(obj);",
            "String(b())",
        ),
        (
            "array of closures",
            "const fns = []; for (let i = 0; i < 50; i++) fns.push(() => i * 2);",
            "String(fns.reduce((a, f) => a + f(), 0))",
        ),
        (
            "closure state behind an object",
            "function counter() { let c = 0; return { inc: () => ++c }; } \
             const k = counter(); for (let i = 0; i < 1000; i++) k.inc();",
            "String(k.inc())",
        ),
    ];
    let node = [
        "499500", "499500", "2450", "1225", "7", "6", "11", "5", "42", "9", "6", "4", "6", "2450",
        "1001",
    ];
    cases
        .iter()
        .zip(node)
        .map(|((_, setup, check), node)| (format!("{setup} {CHURN} {check}"), node))
        .collect()
}

#[test]
fn reachable_objects_survive_collection() {
    for (source, node) in reachable_cases() {
        let run = run(&source, None);
        assert_eq!(value_of(&run, &source), node, "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
    }
}

/// Root-coverage differential: collecting at (almost) every safe point must
/// not change any program's result or console output. A missed root changes
/// the output or fails the run.
#[test]
fn stress_collection_preserves_results_and_console_output() {
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/js_probe_corpus_v1.json"),
        )
        .expect("read probe corpus"),
    )
    .expect("probe corpus json");
    let mut sources: Vec<String> = corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| case["source"].as_str().expect("source").to_string())
        .collect();
    sources.extend(reachable_cases().into_iter().map(|(source, _)| {
        // The stress run collects at every safe point; a short churn keeps
        // the O(live) cost per instruction manageable.
        source.replace("300000", "200")
    }));
    let mut compared = 0;
    let mut collections_by_interval = [0u64; 3];
    for source in &sources {
        let Some(plain) = try_run(source, None) else {
            continue;
        };
        for (slot, interval) in [1, 7, 64].into_iter().enumerate() {
            let stressed = try_run(source, Some(interval)).expect("lowered once already");
            collections_by_interval[slot] += stressed.gc.collections;
            match (&plain.result, &stressed.result) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(actual.value, expected.value, "stress {interval}: {source}");
                    assert_eq!(
                        actual.console_output, expected.console_output,
                        "stress {interval}: {source}"
                    );
                    // Every program with a top-level instruction collects at
                    // interval 1; shorter programs may finish before the 7th
                    // or 64th safe point.
                    if interval == 1 {
                        assert!(stressed.gc.collections > 0, "stress 1: {source}");
                    }
                }
                (Err(expected), Err(actual)) => {
                    assert_eq!(
                        format!("{actual:?}"),
                        format!("{expected:?}"),
                        "stress {interval}: {source}"
                    );
                }
                (expected, actual) => panic!(
                    "stress {interval} changed the outcome of `{source}`: {expected:?} vs {actual:?}"
                ),
            }
            compared += 1;
        }
    }
    // 50 probes (a few are rejected at lowering) plus 15 reachability cases.
    assert!(compared >= 3 * 55, "compared only {compared} runs");
    assert!(
        collections_by_interval.iter().all(|total| *total > 0),
        "a stress interval never collected: {collections_by_interval:?}"
    );
}
