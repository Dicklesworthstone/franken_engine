//! Promise settlement keeps every value exactly (bd-9vouw.69).
//!
//! The promise subsystem carries `object_model::JsValue`, which has no form
//! for closures, generators, iterators, builtin or bound functions, BigInt or
//! non-well-formed strings. Settling a promise with one of them stringified
//! it: `await Promise.resolve(() => 5)` produced a string, and calling it
//! threw "expected function, got string". Such values now travel as carrier
//! ids that the interpreter restores; the collector keeps a carrier while a
//! traced promise value or job names it.
//!
//! Each program runs as written and under collection at every (and every
//! seventh) safe point. The printed lines must equal Node v22.2.0's, and the
//! memory-accounting oracle must hold after the run.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str, stress_interval: Option<u64>) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "settle.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "settle.js"),
        &LoweringContext::new("settle-trace", "settle-decision", "settle-policy"),
    )
    .expect("lower")
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
    let mut core = InterpreterCore::new(config, "settle");
    core.set_gc_stress_interval(stress_interval);
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("`{source}` failed: {error:?}"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

/// Node v22.2.0 output for each program.
const CASES: &[(&str, &str)] = &[
    (
        "(async () => { const f = await Promise.resolve(() => 5); console.log(typeof f, f()); })();",
        "function 5",
    ),
    (
        "(async () => { const b = await Promise.resolve(10n); console.log(typeof b, String(b + 1n)); })();",
        "bigint 11",
    ),
    (
        "class A { v() { return 3; } } \
         (async () => { const C = await (async () => A)(); console.log(typeof C, new C().v()); })();",
        "function 3",
    ),
    (
        "(async () => { const g = await Promise.resolve((function* () { yield 7; })()); \
         console.log(g.next().value); })();",
        "7",
    ),
    (
        "(async () => { const s = await Promise.resolve('\\uD800x'); \
         console.log(s.length, s.charCodeAt(0)); })();",
        "2 55296",
    ),
    (
        "(async () => { const [a, b] = await Promise.all([() => 3, 4n]); console.log(a(), typeof b); })();",
        "3 bigint",
    ),
    (
        "Promise.resolve(Math.max).then(m => console.log(m(1, 2)));",
        "2",
    ),
    ("Promise.reject(() => 7).catch(f => console.log(f()));", "7"),
    (
        "(async () => { const x = await 5n; console.log(String(x * 2n)); })();",
        "10",
    ),
    (
        "const o = { v: 9, get() { return this.v; } }; \
         new Promise(r => r(o.get.bind(o))).then(f => console.log(f()));",
        "9",
    ),
    (
        "(async () => { const gf = await (async () => function* () { yield 1; yield 2; })(); \
         console.log([...gf()].length); })();",
        "2",
    ),
];

#[test]
fn settled_values_keep_their_type_and_identity() {
    for (source, node) in CASES {
        for stress in [None, Some(1), Some(7)] {
            assert_eq!(
                console_lines(source, stress),
                vec![node.to_string()],
                "stress {stress:?}: {source}"
            );
        }
    }
}

/// Carriers are released with the promises that name them: a long loop of
/// awaited closures keeps its memory flat and its accounting exact.
#[test]
fn carried_values_are_reclaimed() {
    let source = "(async () => { let s = 0; for (let i = 0; i < 3000; i++) { \
                  const f = await Promise.resolve(() => 1); s += f(); } console.log(s); })();";
    assert_eq!(console_lines(source, Some(64)), vec!["3000".to_string()]);
}

/// Promise.all, allSettled, race and any take any iterable (ES2020
/// 25.6.4.1 GetIterator): a Set, a generator, a Map's `values()`. A
/// non-iterable argument or a throwing iterator rejects the returned
/// promise. The combinators read an object's indexed properties instead,
/// so `Promise.all(set)` resolved to `[]`, a generator or iterator was one
/// input, and `Promise.all(5)` resolved to `[5]`. Node v22.2.0 output.
#[test]
fn combinators_take_any_iterable() {
    let cases = [
        (
            "Promise.all(new Set([1, Promise.resolve(2)])).then((v) => console.log('set', v.join()));",
            "set 1,2",
        ),
        (
            "function* g() { yield 1; yield Promise.resolve(2); } \
             Promise.all(g()).then((v) => console.log('gen', v.join()));",
            "gen 1,2",
        ),
        (
            "var m = new Map([['a', 1]]); Promise.allSettled(m.values()).then((v) => \
             console.log('settled', v.length, v[0].status, v[0].value));",
            "settled 1 fulfilled 1",
        ),
        (
            "Promise.race(new Set([new Promise(() => {}), 'now'])).then((v) => console.log('race', v));",
            "race now",
        ),
        (
            "Promise.any(new Set([Promise.reject(1), 2])).then((v) => console.log('any', v));",
            "any 2",
        ),
        (
            "Promise.all(5).catch((e) => console.log('not iterable', e instanceof TypeError));",
            "not iterable true",
        ),
        (
            "var it = { [Symbol.iterator]() { return { next() { throw new Error('boom'); } }; } }; \
             Promise.all(it).catch((e) => console.log('threw', e.message));",
            "threw boom",
        ),
    ];
    for (source, node) in cases {
        assert_eq!(console_lines(source, None).join("\n"), node, "`{source}`");
    }
}
