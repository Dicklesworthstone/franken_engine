//! bd-9vouw.77: native collection callbacks must collect while their Rust
//! traversal frames remain suspended. A small live collection must not fail
//! its heap budget merely because one forEach callback creates garbage.
//!
//! Exercise the real parser, lowering and interpreter with both profiles,
//! normal pressure and frequent collections. Current entries, receiver state,
//! thisArg and reentrant cursors must survive; genuinely live growth must
//! still fail the configured heap limit.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, GcStats, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const HEAP_LIMIT: u32 = 3000;

struct Run {
    result: Result<ExecutionResult, InterpreterError>,
    gc: GcStats,
}

fn run(source: String, stress_interval: Option<u64>, throughput: bool) -> Run {
    std::thread::Builder::new()
        .name("collection-for-each-gc".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let tree = CanonicalEs2020Parser
                .parse_with_options(
                    ParserSource {
                        label: "collection-for-each-gc.js".into(),
                        text: source,
                    },
                    ParseGoal::Script,
                    &ParserOptions::default(),
                )
                .expect("collection callback fixture parses");
            let module = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(tree, "collection-for-each-gc.js"),
                &LoweringContext::new("collection-for-each-gc", "bounded-heap", "builtin-only"),
            )
            .expect("collection callback fixture lowers")
            .ir3;
            let mut config = if throughput {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.max_heap_objects = HEAP_LIMIT;
            config.instruction_budget = 100_000_000;
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "collection-for-each-gc");
            core.set_gc_stress_interval(stress_interval);
            let result = core.execute(&module);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "memory accounting drift: throughput={throughput}, stress={stress_interval:?}"
            );
            Run {
                result,
                gc: core.gc_stats(),
            }
        })
        .expect("spawn collection callback fixture")
        .join()
        .expect("collection callback fixture panicked")
}

fn check(source: &str, expected: &str) {
    for throughput in [false, true] {
        for stress in [None, Some(1), Some(7)] {
            // Normal pressure exceeds the complete heap inside each callback.
            // Short stress runs collect around individual callback operations.
            let rounds = if stress.is_some() { 40 } else { 6000 };
            let source = format!(
                "function churn() {{ let total = 0; for (let i = 0; i < {rounds}; i++) {{ \
                 const garbage = {{i}}; total += garbage.i & 1; }} return total; }}\n{source}"
            );
            let run = run(source, stress, throughput);
            let result = run.result.unwrap_or_else(|error| {
                panic!("throughput={throughput}, stress={stress:?}: {error}")
            });
            assert_eq!(
                result.value,
                Value::str(expected),
                "throughput={throughput}, stress={stress:?}"
            );
            assert!(run.gc.collections > 0);
            assert!(run.gc.reclaimed_objects > 0);
            assert_eq!(run.gc.skipped_collections, 0);
        }
    }
}

#[test]
fn map_and_set_callbacks_collect_and_keep_deleted_current_entries() {
    check(
        r#"
        const seen = [];
        new Map([[{n: 1}, {n: 10}], [{n: 2}, {n: 20}]]).forEach(function (value, key, owner) {
            owner.delete(key);
            if (key.n === 1) owner.set({n: 3}, {n: 30});
            churn();
            seen.push(key.n + ':' + value.n + ':' + this.marker.tag + ':' + owner.size);
        }, {marker: {tag: 'map'}});
        new Set([{n: 1}, {n: 2}]).forEach(function (value, key, owner) {
            owner.delete(value);
            if (value.n === 1) owner.add({n: 3});
            churn();
            seen.push(value.n + ':' + (value === key) + ':' + this.marker.tag + ':' + owner.size);
        }, {marker: {tag: 'set'}});
        seen.join('|');
        "#,
        "1:10:map:2|2:20:map:1|3:30:map:0|1:true:set:2|2:true:set:1|3:true:set:0",
    );
}

#[test]
fn url_search_params_callbacks_collect_and_keep_live_url_state() {
    check(
        r#"
        const seen = [];
        new URL('http://example.test/?a=1&b=2&c=3').searchParams.forEach(function (value, name, owner) {
            if (name === 'a') {
                owner.delete('b');
            }
            churn();
            if (name === 'a') owner.append('d', '4');
            seen.push(name + value + ':' + this.marker.tag + ':' + owner.toString());
        }, {marker: {tag: 'params'}});
        seen.join('|');
        "#,
        "a1:params:a=1&c=3&d=4|c3:params:a=1&c=3&d=4|d4:params:a=1&c=3&d=4",
    );
}

#[test]
fn nested_and_throwing_callbacks_restore_cursors_and_collection() {
    check(
        r#"
        const seen = [];
        const set = new Set([{n: 1}, {n: 2}]);
        set.forEach(function (outer, unused, owner) {
            if (outer.n === 1) {
                try {
                    owner.forEach(function (inner) {
                        owner.delete(inner);
                        churn();
                        throw inner;
                    });
                } catch (error) {
                    seen.push('throw' + error.n);
                }
            }
            churn();
            seen.push('outer' + outer.n);
        });
        set.forEach(function (value, unused, owner) {
            churn();
            seen.push('again' + value.n);
            owner.delete(value);
        });
        const map = new Map([[{n: 3}, {n: 30}]]);
        try {
            map.forEach(function (value, key, owner) {
                owner.clear();
                churn();
                throw {key, value};
            });
        } catch (error) {
            seen.push(error.key.n + ':' + error.value.n);
        }
        map.set(4, 40);
        map.forEach(function (value, key) { churn(); seen.push(key + ':' + value); });
        const params = new URLSearchParams('a=1');
        const marker = {tag: 'caught'};
        try {
            params.forEach(function (value, name, owner) {
                owner.append('b', '2');
                churn();
                throw marker;
            });
        } catch (error) {
            seen.push(error === marker);
        }
        params.forEach(function (value, name) { churn(); seen.push(name + value); });
        seen.join('|');
        "#,
        "throw1|outer1|outer2|again2|3:30|4:40|true|a1|b2",
    );
}

#[test]
fn collection_callbacks_still_enforce_the_live_heap_limit() {
    for receiver in [
        "new Map([[0, 0]])",
        "new Set([0])",
        "new URLSearchParams('a=1')",
    ] {
        for throughput in [false, true] {
            let source = format!(
                "({receiver}).forEach(function () {{ const retained = []; \
                 for (let i = 0; i < 6000; i++) retained.push({{i}}); return retained; }});"
            );
            let run = run(source, None, throughput);
            assert!(
                matches!(run.result, Err(InterpreterError::MemoryBudgetExceeded {
                    requested_heap_objects, max_heap_objects: HEAP_LIMIT, ..
                }) if requested_heap_objects > HEAP_LIMIT),
                "{receiver}, throughput={throughput}: {:?}",
                run.result
            );
            assert!(run.gc.collections > 0);
        }
    }
}
