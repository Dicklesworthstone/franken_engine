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
    try_run_with_object_budget(source, stress_interval, None)
}

fn try_run_with_object_budget(
    source: &str,
    stress_interval: Option<u64>,
    max_heap_objects: Option<u32>,
) -> Option<Run> {
    try_run_with_budgets(source, stress_interval, max_heap_objects, None)
}

fn try_run_with_budgets(
    source: &str,
    stress_interval: Option<u64>,
    max_heap_objects: Option<u32>,
    max_total_memory_bytes: Option<u64>,
) -> Option<Run> {
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
    if let Some(max_heap_objects) = max_heap_objects {
        config.max_heap_objects = max_heap_objects;
    }
    if let Some(max_total_memory_bytes) = max_total_memory_bytes {
        config.max_total_memory_bytes = max_total_memory_bytes;
    }
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        RuntimeCapability::Timer,
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
/// 64 MiB budget near 100,000 closures before closures were reclaimed. Since
/// closures sharing a frame map are charged it once (bd-9vouw.154), 150,000
/// of these fit 64 MiB without a collection, so the loops run under 8 MiB:
/// they still allocate more closure environments than the budget holds.
const CLOSURE_LOOP_BYTE_BUDGET: u64 = 8 * 1024 * 1024;
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
        let run = try_run_with_budgets(source, None, None, Some(CLOSURE_LOOP_BYTE_BUDGET))
            .expect("source must parse and lower");
        assert_eq!(value_of(&run, source), *node, "{source}");
        assert!(
            run.gc.reclaimed_closures >= 50_000,
            "reclaimed only {} closures: {source}",
            run.gc.reclaimed_closures
        );
    }
}

/// Work done after the script, in timer and promise callbacks: each callback
/// allocates 1,000 short-lived objects, 300,000 in total (3x the budget).
/// Collection runs between event-loop jobs.
const EVENT_LOOP_LOOPS: &[(&str, &str)] = &[
    (
        "let s = 0; function step(n) { for (let j = 0; j < 1000; j++) { const o = { j }; \
         s += o.j & 1; } if (n > 1) { setTimeout(() => step(n - 1), 0); } else { console.log(s); } } \
         step(300);",
        "150000",
    ),
    (
        "let s = 0; let p = Promise.resolve(); for (let k = 0; k < 300; k++) { \
         p = p.then(() => { for (let j = 0; j < 1000; j++) { const o = { j }; s += o.j & 1; } }); } \
         p.then(() => console.log(s));",
        "150000",
    ),
];

#[test]
fn event_loop_garbage_completes_past_the_object_budget() {
    for (source, node) in EVENT_LOOP_LOOPS {
        let run = run(source, None);
        let result = run
            .result
            .as_ref()
            .unwrap_or_else(|error| panic!("`{source}` failed: {error:?}"));
        let printed: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(printed, vec![*node], "{source}");
        assert!(
            run.gc.reclaimed_objects >= 150_000,
            "reclaimed only {} objects: {source}",
            run.gc.reclaimed_objects
        );
    }
}

/// A 300,000-iteration garbage loop runs after the live structures are built;
/// every structure must read back intact.
const CHURN: &str = "for (let i = 0; i < 300000; i++) { const g = { i }; }";

/// The source promises leave their local scope before the checkpoint. Native
/// element jobs must retain their object values and rejection reasons while
/// the collector can reclaim those settled source promise records.
#[test]
fn native_combinator_jobs_keep_values_across_gc_bd_9vouw_295() {
    let source = r#"function all(values) { console.log('all:' + values.map(v => v.n).join(',')); }
function settled(values) { console.log('settled:' + values.map(v => (v.value || v.reason).n).join(',')); }
function any(value) { console.log('any:' + value.n); }
(function () {
 const p = Promise.resolve({ n: 7 });
 const q = Promise.resolve({ n: 11 });
 const r = Promise.reject({ n: 13 });
 Promise.all([p, q]).then(all);
 Promise.allSettled([p, r]).then(settled);
 Promise.any([r, q]).then(any);
})();
for (let i = 0; i < 128; i++) { const garbage = { i }; }
"#;
    let run = run(source, Some(1));
    let result = run.result.as_ref().expect("native jobs survive collection");
    let printed: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(printed, ["all:7,11", "settled:7,13", "any:11"]);
    assert!(run.gc.collections > 0);
    assert!(
        run.gc.reclaimed_promises > 0,
        "settled source promises can be reclaimed independently of queued values"
    );
}

/// Promise programs that hold promises, resolving functions, queued jobs and
/// suspended async code across a top-level churn of 300,000 garbage objects
/// (the `CHURN` placeholder). A settled promise may be reclaimed only when
/// nothing reachable names it. Expected lines are Node v22.2.0's.
const PROMISE_CASES: &[(&str, &str)] = &[
    (
        "const p = Promise.resolve({ v: 3 }); CHURN p.then(o => console.log(o.v));",
        "3",
    ),
    (
        "let res; new Promise(r => { res = r; }); res({ v: 1 }); CHURN res({ v: 2 }); \
         console.log('ok');",
        "ok",
    ),
    (
        "const ps = []; for (let i = 0; i < 20; i++) ps.push(Promise.resolve({ i })); CHURN \
         Promise.all(ps).then(a => console.log(a.reduce((s, o) => s + o.i, 0)));",
        "190",
    ),
    (
        "async function f(i) { return { i }; } (async () => { let s = 0; \
         for (let i = 0; i < 2000; i++) { s += (await f(i)).i; } console.log(s); })(); CHURN",
        "1999000",
    ),
    (
        "const p = new Promise(r => setTimeout(() => r({ v: 8 }), 0)); CHURN \
         p.then(o => console.log(o.v));",
        "8",
    ),
    (
        "async function* g() { for (let i = 0; i < 3; i++) yield { i }; } const gen = g(); \
         const first = gen.next(); CHURN (async () => { let s = (await first).value.i; \
         for await (const o of gen) s += o.i; console.log(s); })();",
        "3",
    ),
    (
        "const p = Promise.reject({ e: 5 }); CHURN p.catch(e => console.log(e.e));",
        "5",
    ),
    (
        "const t = { then(r) { r({ v: 12 }); } }; const p = Promise.resolve(t); CHURN \
         p.then(o => console.log(o.v));",
        "12",
    ),
    (
        "const p = Promise.resolve({ n: 1 }).then(o => ({ n: o.n + 1 })); CHURN \
         p.then(o => ({ n: o.n * 10 })).then(o => console.log(o.n));",
        "20",
    ),
    (
        "const holder = { p: Promise.resolve({ v: 21 }) }; CHURN \
         holder.p.then(o => console.log(o.v));",
        "21",
    ),
];

/// Iterator programs: an iterator must survive while a register, a bound
/// `next` method or a suspended `yield*` names it, including while its own
/// loop body churns (the `CHURN` placeholder). Expected values are Node
/// v22.2.0's `String(<program>)`.
const ITERATOR_CASES: &[(&str, &str)] = &[
    (
        "const it = [1, 2, 3][Symbol.iterator](); it.next(); CHURN String(it.next().value)",
        "2",
    ),
    (
        "const it = [1, 2, 3].values(); for (const x of it) { break; } CHURN \
         String([...it].length)",
        "2",
    ),
    (
        "function* inner() { yield 1; yield 2; } function* outer() { yield* inner(); } \
         const g = outer(); g.next(); CHURN String(g.next().value)",
        "2",
    ),
    (
        "let s = ''; for (const k in { a: 1, b: 2 }) { CHURN s += k; } s",
        "ab",
    ),
    (
        "let s = 0; for (const x of [1, 2, 3]) { CHURN s += x; } String(s)",
        "6",
    ),
    (
        "const it = new Set([4, 5]).values(); const next = it.next.bind(it); next(); CHURN \
         String(next().value)",
        "5",
    ),
];

fn iterator_case_sources() -> impl Iterator<Item = (String, &'static str)> {
    ITERATOR_CASES
        .iter()
        .map(|(source, node)| (source.replace("CHURN", CHURN), *node))
}

#[test]
fn iterators_survive_collection_until_unreachable() {
    for (source, node) in iterator_case_sources() {
        let run = run(&source, None);
        assert_eq!(value_of(&run, &source), node, "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
    }
}

/// Every `for...of` allocates an iterator-table entry (32+ bytes charged).
/// None was ever released: 16,000 loops need at least 512 KB, more than a
/// 256 KiB budget holds with nothing live. Unnamed iterators are reclaimed.
#[test]
fn for_of_loops_complete_past_the_byte_budget() {
    let source = "let s = 0; const a = [1, 2]; for (let i = 0; i < 16000; i++) { \
                  for (const x of a) { s += x & 1; } } String(s)";
    let run = try_run_with_budgets(source, None, None, Some(256 * 1024)).expect("lowers");
    assert_eq!(value_of(&run, source), "16000");
    assert!(
        run.gc.reclaimed_iterators >= 8_000,
        "reclaimed only {} iterators",
        run.gc.reclaimed_iterators
    );
}

/// Each iteration leaves a generator suspended at its first `yield`, holding
/// its execution snapshot. Nothing released generators: 8,000 of them (48+
/// bytes each before the snapshot) cannot fit a 256 KiB budget. A generator
/// nothing names can never resume, so it is reclaimed.
#[test]
fn abandoned_generators_complete_past_the_byte_budget() {
    let source = "function* g() { yield 1; yield 2; } let s = 0; \
                  for (let i = 0; i < 8000; i++) { const it = g(); s += it.next().value; } String(s)";
    let run = try_run_with_budgets(source, None, None, Some(256 * 1024)).expect("lowers");
    assert_eq!(value_of(&run, source), "8000");
    assert!(
        run.gc.reclaimed_generators >= 4_000,
        "reclaimed only {} generators",
        run.gc.reclaimed_generators
    );
}

/// Async-generator programs: an async generator must survive while a value
/// names it, while it awaits, and while a request promise waits on it,
/// including across a churn (the `CHURN` placeholder). Expected lines are
/// Node v22.2.0's.
const ASYNC_GENERATOR_CASES: &[(&str, &str)] = &[
    (
        "async function* g() { yield 1; yield 2; } const it = g(); CHURN \
         it.next().then(a => it.next()).then(b => console.log(b.value));",
        "2",
    ),
    (
        "async function* g() { const o = { v: 5 }; await null; yield o.v; } const it = g(); \
         const p = it.next(); CHURN p.then(r => console.log(r.value));",
        "5",
    ),
    (
        "async function* g() { yield { v: 3 }; } const p = g().next(); CHURN \
         p.then(r => console.log(r.value.v));",
        "3",
    ),
    (
        // The generator is unnamed: only the suspended `for await` holds it
        // while the top-level churn collects. (A churn inside the async body
        // would not collect at all: bd-9vouw.77.)
        "(async () => { let s = 0; for await (const x of (async function* () { yield 1; yield 2; \
         yield 3; })()) { s += x; } console.log(s); })(); CHURN",
        "6",
    ),
    (
        "const holder = { it: (async function* () { yield 7; })() }; CHURN \
         holder.it.next().then(r => console.log(r.value));",
        "7",
    ),
];

fn async_generator_case_sources() -> impl Iterator<Item = (String, &'static str)> {
    ASYNC_GENERATOR_CASES
        .iter()
        .map(|(source, node)| (source.replace("CHURN", CHURN), *node))
}

#[test]
fn async_generators_survive_collection_until_unreachable() {
    for (source, node) in async_generator_case_sources() {
        let run = run(&source, None);
        assert_eq!(console_lines(&run, &source), vec![node], "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
    }
}

/// Each iteration leaves an async generator suspended at its first `yield`
/// with its backing generator's saved frame. Async generators were roots, so
/// every one stayed live. One nothing names that neither runs, awaits nor
/// holds requests can never resume, so it is reclaimed with its generator.
#[test]
fn abandoned_async_generators_are_reclaimed() {
    let source = "async function* g() { yield 1; yield 2; } (async () => { let s = 0; \
                  for (let i = 0; i < 4000; i++) { const it = g(); s += (await it.next()).value; } \
                  console.log(s); })();";
    let run = try_run_with_budgets(source, None, None, Some(2 * 1024 * 1024)).expect("lowers");
    assert_eq!(console_lines(&run, source), vec!["4000"]);
    assert!(
        run.gc.reclaimed_async_generators >= 2_000,
        "reclaimed only {} async generators",
        run.gc.reclaimed_async_generators
    );
    assert!(
        run.gc.reclaimed_generators >= 2_000,
        "reclaimed only {} backing generators",
        run.gc.reclaimed_generators
    );
}

/// Garbage allocated inside one async function body, timer callback or
/// Promise reaction handler (bd-9vouw.77). Collection used to run only in the
/// top-level script's own loop and between event-loop jobs, so each of these
/// died at the 100,001st object. The map/sort case checks that builtin
/// callbacks inside an armed body stay correct. Expected lines are Node
/// v22.2.0's.
const TASK_CHURN_CASES: &[(&str, &str)] = &[
    (
        "(async () => { let s = 0; for (let i = 0; i < 300000; i++) { const g = { i }; \
         s += g.i & 1; } console.log(s); })();",
        "150000",
    ),
    (
        "(async () => { await null; let s = 0; for (let i = 0; i < 300000; i++) { \
         const g = { i }; s += g.i & 1; } console.log(s); })();",
        "150000",
    ),
    (
        "setTimeout(() => { let s = 0; for (let i = 0; i < 300000; i++) { const g = { i }; \
         s += g.i & 1; } console.log(s); }, 0);",
        "150000",
    ),
    (
        "Promise.resolve(7).then(v => { let s = v; for (let i = 0; i < 300000; i++) { \
         const g = { i }; s += g.i & 1; } console.log(s); });",
        "150007",
    ),
    (
        "async function inner(k) { await null; let s = k; for (let i = 0; i < 300000; i++) { \
         const g = { i }; s += g.i & 1; } return s; } \
         (async () => { const a = await inner(1); const b = await inner(2); console.log(a + b); })();",
        "300003",
    ),
    (
        "(async () => { await null; const keep = { tag: 'kept' }; \
         const arr = [3, 1, 2].map(x => ({ x })); let s = 0; \
         for (let i = 0; i < 300000; i++) { const g = { i }; s += g.i & 1; } \
         arr.sort((p, q) => p.x - q.x); console.log(keep.tag, arr.map(o => o.x).join(), s); })();",
        "kept 1,2,3 150000",
    ),
    (
        "let n = 0; const t = setInterval(() => { let s = 0; \
         for (let i = 0; i < 300000; i++) { const g = { i }; s += g.i & 1; } n++; \
         if (n === 3) { clearInterval(t); console.log(n, s); } }, 0);",
        "3 150000",
    ),
    // bd-9vouw.50: a 300-element spread stages its tail out of band. The rest
    // array and `arguments` built from it must survive the collections the
    // resumed body runs before it reads them.
    (
        "async function f(...r) { await null; let s = 0; for (let i = 0; i < 300000; i++) { \
         const g = { i }; s += g.i & 1; } return s + r.length + r[299].v + arguments[298].v; } \
         f(...Array.from({ length: 300 }, (_, v) => ({ v }))).then(t => console.log(t));",
        "150897",
    ),
    // Entered through builtin:ReflectApply (spread), Function.prototype.apply
    // and builtin:ReflectConstruct, the callee's own loop collects.
    (
        "function f(...r) { let s = 0; for (let i = 0; i < 150000; i++) { const g = { i }; \
         s += g.i & 1; } return s + r.length; } console.log(f(...[1, 2, 3]));",
        "75003",
    ),
    (
        "async function f(...r) { let s = 0; for (let i = 0; i < 150000; i++) { \
         const g = { i }; s += g.i & 1; } await null; return s + r.length; } \
         f(...[1, 2, 3]).then(v => console.log(v));",
        "75003",
    ),
    (
        "function f(a, b) { let s = 0; for (let i = 0; i < 150000; i++) { const g = { i }; \
         s += g.i & 1; } return s + a + b; } console.log(f.apply(null, [1, 2]));",
        "75003",
    ),
    (
        "class C { constructor(k) { let s = 0; for (let i = 0; i < 150000; i++) { \
         const g = { i }; s += g.i & 1; } this.s = s + k; } } \
         console.log(Reflect.construct(C, [1]).s, new C(...[2]).s);",
        "75001 75002",
    ),
    // Array callbacks collect; the array a builtin fills across calls
    // survives with every object put in it.
    (
        "const out = [1, 2, 3].map(x => { let s = 0; for (let i = 0; i < 150000; i++) { \
         const g = { i }; s += g.i & 1; } return { x, s }; }); \
         console.log(out.map(o => o.x + ':' + o.s).join());",
        "1:75000,2:75000,3:75000",
    ),
    (
        "const xs = [{ v: 1 }, { v: 2 }, { v: 3 }, { v: 4 }]; const kept = xs.filter(o => { \
         let s = 0; for (let i = 0; i < 150000; i++) { const g = { i }; s += g.i & 1; } \
         return o.v % 2 === 0; }); console.log(kept.map(o => o.v).join());",
        "2,4",
    ),
    (
        "const ys = [1, 2]; console.log(ys.flatMap(x => { let s = 0; \
         for (let i = 0; i < 150000; i++) { const g = { i }; s += g.i & 1; } \
         return [{ x }, { x: x * 10 }]; }).map(o => o.x).join());",
        "1,10,2,20",
    ),
    // One temporary per callback: collection runs between callbacks.
    (
        "let n = 0; const zs = Array.from({ length: 150000 }, (_, i) => i); \
         zs.forEach(i => { const g = { i }; n += g.i & 1; }); console.log(n);",
        "75000",
    ),
];

#[test]
fn garbage_inside_async_bodies_and_callbacks_is_collected() {
    for (source, node) in TASK_CHURN_CASES {
        let run = run(source, None);
        assert_eq!(console_lines(&run, source), vec![*node], "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
    }
}

fn promise_case_sources() -> impl Iterator<Item = (String, &'static str)> {
    PROMISE_CASES
        .iter()
        .map(|(source, node)| (source.replace("CHURN", CHURN), *node))
}

fn console_lines(run: &Run, source: &str) -> Vec<String> {
    run.result
        .as_ref()
        .unwrap_or_else(|error| panic!("`{source}` failed: {error:?}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

#[test]
fn promises_survive_collection_until_unreachable() {
    for (source, node) in promise_case_sources() {
        let run = run(&source, None);
        assert_eq!(console_lines(&run, &source), vec![node], "{source}");
        assert!(run.gc.collections > 0, "no collection ran: {source}");
    }
}

/// Settled promise values used to be roots, so an await loop kept every
/// awaited value alive: 1,000,000 awaits of `{ i }` died at 87,213 live
/// objects under the default budget. Settled promises nothing names are now
/// reclaimed with their values.
#[test]
fn await_loop_completes_past_the_object_budget() {
    let source = "async function f(i) { return { i }; } (async () => { let s = 0; \
                  for (let i = 0; i < 10000; i++) { s += (await f(i)).i; } console.log(s); })();";
    let run = try_run_with_object_budget(source, None, Some(3000)).expect("lowers");
    assert_eq!(console_lines(&run, source), vec!["49995000"]);
    // 10,000 awaited values cannot fit a 3,000-object budget unless at
    // least 7,000 settled promises (and their values) were reclaimed; the
    // ones settled after the last collection legitimately remain.
    assert!(
        run.gc.reclaimed_promises >= 7_000,
        "reclaimed only {} promises",
        run.gc.reclaimed_promises
    );
    // Each `f(i)` call leaves a completed async-function record; collections
    // every few hundred awaits release them.
    assert!(
        run.gc.reclaimed_async_functions >= 5_000,
        "reclaimed only {} async-function records",
        run.gc.reclaimed_async_functions
    );
}

/// An await loop's memory must not grow with its length. Minimal byte budget
/// measured for this loop (3k / 6k / 12k / 24k awaits):
/// - before: 2 / 4 / 6 / 16 MiB;
/// - with bounded witness logs (bd-9vouw.71) only: 1 / 1.5 / 3 / 4 MiB;
/// - with each resumed await's internal carrier promise released as well:
///   0.75 / 1 / 1.5 / 1.5 MiB, flat once the logs reach their bound.
///
/// 24,000 awaits under 2 MiB therefore fail on the old code and fit now.
#[test]
fn await_loop_completes_past_the_byte_budget() {
    let source = "async function f(i) { return i; } (async () => { let s = 0; \
                  for (let i = 0; i < 24000; i++) { s += await f(i); } console.log(s); })();";
    let run = try_run_with_budgets(source, None, None, Some(2 * 1024 * 1024)).expect("lowers");
    assert_eq!(console_lines(&run, source), vec!["287988000"]);
}

/// The microtask queue kept a consumed slot per job until a drain returned,
/// and a drain runs up to 10,000 jobs, so an await loop's resident size
/// followed the jobs run since the last compaction (bd-9vouw.71). With
/// compaction every 1,024 jobs, 24,000 awaits fit in 768 KiB: on the
/// previous build they needed at least 1,162,752 bytes; now they need
/// 508,032.
#[test]
fn await_loop_fits_a_small_byte_budget() {
    let source = "async function f(i) { return i; } (async () => { let s = 0; \
                  for (let i = 0; i < 24000; i++) { s += await f(i); } console.log(s); })();";
    let run = try_run_with_budgets(source, None, None, Some(768 * 1024)).expect("lowers");
    assert_eq!(console_lines(&run, source), vec!["287988000"]);
}

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
    sources.extend(
        reachable_cases()
            .into_iter()
            .chain(promise_case_sources())
            .chain(iterator_case_sources())
            .chain(async_generator_case_sources())
            .chain(
                TASK_CHURN_CASES
                    .iter()
                    .map(|(source, node)| (source.to_string(), *node)),
            )
            .map(|(source, _)| {
                // The stress run collects at every safe point; a short churn
                // keeps the O(live) cost per instruction manageable.
                source.replace("300000", "200").replace("150000", "200")
            }),
    );
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
    // 50 probes (a few are rejected at lowering), 15 reachability cases, 10
    // promise cases and 6 iterator cases.
    assert!(compared >= 3 * 71, "compared only {compared} runs");
    assert!(
        collections_by_interval.iter().all(|total| *total > 0),
        "a stress interval never collected: {collections_by_interval:?}"
    );
}
