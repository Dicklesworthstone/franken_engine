//! Native execution coverage for lazy generic Array iterator creation.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "array-iterator-live.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("array iterator regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-iterator-live.js"),
        &LoweringContext::new(
            "array-iterator-trace",
            "array-iterator-decision",
            "array-iterator-policy",
        ),
    )
    .expect("array iterator regression source must lower")
    .ir3
}

fn configs() -> impl Iterator<Item = InterpreterConfig> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        config
    })
}

#[test]
fn generic_array_iterators_preserve_live_reads_and_abrupt_order() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/array_iterator_live.json"))
            .expect("iterator fixtures");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("name");
        let source = case["source"].as_str().expect("source");
        // expected is normative. A separately recorded Node discrepancy
        // must never weaken the native assertion or bless an extra Get.
        let expected = case["expected"].as_str().expect("expected");
        let outcome = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(outcome.value, expected, "{name}");

        let module = lower(source);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "array-iterator-live");
            let result = core
                .execute(&module)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(result.value, Value::str(expected), "{name}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "{name}"
            );
        }
    }
}

#[test]
fn live_array_iterators_root_callable_and_exotic_receivers() {
    let module = lower(
        r#"
        function makeFunction() {
            const saved = { n: 41 };
            function source(a) {}
            Object.defineProperty(source, "0", { get: function () { return saved; } });
            return Array.prototype.values.call(source);
        }
        function makePromise() {
            const source = Promise.resolve(null);
            source.length = 1;
            source[0] = { n: 42 };
            return Array.prototype.values.call(source);
        }
        function makeGenerator() {
            function* empty() {}
            const source = empty();
            source.length = 1;
            source[0] = { n: 43 };
            return Array.prototype.values.call(source);
        }
        function makeIterator() {
            const source = [].values();
            source.length = 1;
            source[0] = { n: 44 };
            return Array.prototype.values.call(source);
        }
        const callable = makeFunction(), promise = makePromise();
        const generator = makeGenerator(), iterator = makeIterator();
        for (let i = 0; i < 32; i++) { const garbage = { nested: { i: i } }; }
        callable.next().value.n + "|" + promise.next().value.n + "|" +
        generator.next().value.n + "|" + iterator.next().value.n + "|" +
        callable.next().done + "|" + promise.next().done + "|" +
        generator.next().done + "|" + iterator.next().done;
        "#,
    );
    for config in configs() {
        for interval in [1, 7] {
            let mut core = InterpreterCore::new(config.clone(), "array-iterator-gc");
            core.set_gc_stress_interval(Some(interval));
            let result = core
                .execute(&module)
                .expect("live iterator source survives GC");
            assert_eq!(result.value, Value::str("41|42|43|44|true|true|true|true"));
            assert!(core.gc_stats().collections > 0, "stress GC must run");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn array_iterator_length_conversion_uses_the_existing_instruction_budget() {
    let module = lower(
        r#"
        const source = {
            length: { valueOf: function () { while (true) {} } },
            0: "unreachable"
        };
        Array.prototype.values.call(source).next();
        "#,
    );
    for mut config in configs() {
        config.instruction_budget = 2_000;
        let mut core = InterpreterCore::new(config, "array-iterator-budget");
        let result = core.execute(&module);
        assert!(
            matches!(&result, Err(InterpreterError::BudgetExhausted { .. })),
            "length coercion must consume the caller's budget: {result:?}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
