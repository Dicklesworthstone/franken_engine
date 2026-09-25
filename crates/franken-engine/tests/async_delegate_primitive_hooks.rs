#![forbid(unsafe_code)]

//! Async yield* observes primitive prototype hooks through the native VM.
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "async-delegate-primitive-hooks.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("regression source must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "async-delegate-primitive-hooks.js"),
        &LoweringContext::new(
            "async-delegate-trace",
            "async-delegate-decision",
            "async-delegate-policy",
        ),
    )
    .expect("regression source must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
            RuntimeCapability::Timer,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "async-delegate-primitive-hooks");
        let result = core.execute(&module).expect("native execution must succeed");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn string_hook_preserves_strict_receivers_and_caches_next() {
    assert_output(
        r#"
        const log = console.log;
        let step = 0;
        const iterator = {
            get next() {
                log('get-next');
                return function(value) {
                    log('next', value, this === iterator);
                    step++;
                    return Promise.resolve({value: step * 10, done: step > 1});
                };
            }
        };
        Object.defineProperty(String.prototype, Symbol.asyncIterator, {
            get() {
                'use strict';
                log('get', typeof this, this === 'abc');
                return function() {
                    'use strict';
                    log('call', typeof this, this === 'abc');
                    return iterator;
                };
            }
        });
        String.prototype[Symbol.iterator] = function() { throw 'wrong sync path'; };
        async function* outer() { return yield* 'abc'; }
        const g = outer();
        g.next(99).then(r => {
            log('one', r.value, r.done);
            return g.next(7);
        }).then(r => log('two', r.value, r.done));
        log('sync');
        "#,
        &[
            "get string true",
            "call string true",
            "get-next",
            "next undefined true",
            "sync",
            "one 10 false",
            "next 7 true",
            "two 20 true",
        ],
    );
}

#[test]
fn non_string_primitives_observe_their_own_intrinsic_prototype() {
    for (prototype, value, kind) in [
        ("Number", "42", "number"),
        ("Boolean", "true", "boolean"),
        ("BigInt", "42n", "bigint"),
        ("Symbol", "Symbol('key')", "symbol"),
    ] {
        let source = format!(
            r#"
            {prototype}.prototype[Symbol.asyncIterator] = function() {{
                'use strict';
                console.log('receiver', typeof this);
                return {{ next() {{ return {{value: 41, done: true}}; }} }};
            }};
            async function* outer() {{ return yield* {value}; }}
            outer().next().then(r => console.log('done', r.value, r.done));
            console.log('sync');
            "#
        );
        let receiver = format!("receiver {kind}");
        assert_output(&source, &[receiver.as_str(), "sync", "done 41 true"]);
    }
}

#[test]
fn noncallable_async_hook_cannot_silently_select_string_iteration() {
    assert_output(
        r#"
        String.prototype[Symbol.asyncIterator] = 0;
        async function* outer() {
            try { yield* 'abc'; console.log('wrong'); }
            catch (error) { console.log(error.name); }
        }
        outer().next().then(r => console.log('done', r.done));
        console.log('sync');
        "#,
        &["TypeError", "sync", "done true"],
    );
}

#[test]
fn throwing_primitive_hook_keeps_exception_identity_and_single_lookup() {
    assert_output(
        r#"
        const failure = {code: 9};
        let reads = 0;
        Object.defineProperty(Number.prototype, Symbol.asyncIterator, {
            get() { reads++; throw failure; }
        });
        async function* outer() {
            try { yield* 3; console.log('wrong'); }
            catch (error) { console.log('caught', error === failure, reads); }
        }
        outer().next().then(r => console.log('done', r.done));
        console.log('sync');
        "#,
        &["caught true 1", "sync", "done true"],
    );
}

#[test]
fn nullish_async_hooks_retain_the_synchronous_string_fallback() {
    for absent in ["null", "undefined"] {
        let source = format!(
            r#"
            String.prototype[Symbol.asyncIterator] = {absent};
            async function* outer() {{ yield* 'ab'; }}
            const g = outer();
            g.next().then(r => {{
                console.log('one', r.value, r.done);
                return g.next();
            }}).then(r => {{
                console.log('two', r.value, r.done);
                return g.next();
            }}).then(r => console.log('three', r.value, r.done));
            console.log('sync');
            "#
        );
        assert_output(
            &source,
            &["sync", "one a false", "two b false", "three undefined true"],
        );
    }
}

#[test]
fn primitive_hook_must_return_an_object_iterator() {
    assert_output(
        r#"
        Boolean.prototype[Symbol.asyncIterator] = function() {
            'use strict';
            console.log('method', typeof this);
            return 0;
        };
        async function* outer() { yield* true; }
        outer().next().catch(error => console.log(error.name));
        console.log('sync');
        "#,
        &["method boolean", "sync", "TypeError"],
    );
}

#[test]
fn primitive_delegate_preserves_value_identity_and_forwards_throw() {
    assert_output(
        r#"
        const value = Promise.resolve(5);
        const iterator = {
            next() { return Promise.resolve({value, done: false}); },
            throw(value) {
                console.log('throw', this === iterator, value);
                return Promise.resolve({value: value + 1, done: true});
            }
        };
        Number.prototype[Symbol.asyncIterator] = function() { return iterator; };
        async function* outer() { return yield* 42; }
        const g = outer();
        g.next().then(r => {
            console.log('one', r.value === value, r.done);
            return g.throw(8);
        }).then(r => console.log('two', r.value, r.done));
        console.log('sync');
        "#,
        &["sync", "one true false", "throw true 8", "two 9 true"],
    );
}
