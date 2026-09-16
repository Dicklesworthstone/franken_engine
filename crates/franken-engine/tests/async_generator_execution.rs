//! Executable source-level async-generator regressions.
//!
//! Assertions describe observable behavior, not support-table claims. Expected
//! ordering was cross-checked with Node v22.16.0 before running this suite.

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
                label: "async-generator-execution.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("regression source must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "async-generator-execution.js"),
        &LoweringContext::new(
            "async-generator-trace",
            "async-generator-decision",
            "async-generator-policy",
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
        let mut core = InterpreterCore::new(config, "async-generator-execution");
        let result = core
            .execute(&module)
            .expect("native async-generator execution must succeed");
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
fn queued_next_requests_execute_real_body_and_await_in_fifo_order() {
    assert_output(
        r#"
        const log = console.log;
        async function* values(start) {
            log('body', start);
            const sent = yield Promise.resolve(start);
            log('sent', sent);
            await 0;
            return sent + 1;
        }
        const g = values(10);
        log('created', typeof g, g[Symbol.asyncIterator]() === g);
        g.next(99).then(r => log('first', r.value, r.done));
        g.next(20).then(r => log('second', r.value, r.done));
        g.next().then(r => log('third', r.value, r.done));
        log('sync');
    "#,
        &[
            "created object true",
            "body 10",
            "sync",
            "sent 20",
            "first 10 false",
            "second 21 true",
            "third undefined true",
        ],
    );
}

#[test]
fn return_awaits_argument_and_preserves_yielding_finally_activation() {
    assert_output(
        r#"
        const log = console.log;
        async function* values() {
            try { yield 1; yield 2; }
            finally { log('finally-enter'); await 0; yield 9; log('finally-exit'); }
        }
        const g = values();
        g.next().then(r => log('next', r.value, r.done));
        g.return(Promise.resolve(42)).then(r => log('return', r.value, r.done));
        g.next().then(r => log('after', r.value, r.done));
        log('sync');
    "#,
        &[
            "sync",
            "next 1 false",
            "finally-enter",
            "finally-exit",
            "return 9 false",
            "after 42 true",
        ],
    );
}

#[test]
fn throw_is_injected_into_suspended_catch_and_completed_throw_rejects() {
    assert_output(
        r#"
        const log = console.log;
        async function* values() {
            try { yield 1; }
            catch (error) { yield error + 1; }
            finally { log('finally'); }
            return 3;
        }
        const g = values();
        g.next().then(r => log('one', r.value, r.done));
        g.throw(8).then(r => log('caught', r.value, r.done));
        g.next().then(r => log('done', r.value, r.done));
        g.throw(99).catch(error => log('closed-throw', error));
        log('sync');
    "#,
        &[
            "sync",
            "one 1 false",
            "finally",
            "caught 9 false",
            "done 3 true",
            "closed-throw 99",
        ],
    );
}

#[test]
fn reentrant_next_enqueues_without_reentering_running_activation() {
    assert_output(
        r#"
        const log = console.log;
        let g;
        async function* values() {
            log('enter');
            g.next(7).then(r => log('queued', r.value, r.done));
            const sent = yield 1;
            yield sent;
        }
        g = values();
        g.next().then(r => log('first', r.value, r.done));
        log('sync');
    "#,
        &["enter", "sync", "first 1 false", "queued 7 false"],
    );
}

#[test]
fn pending_await_blocks_later_requests_until_real_settlement() {
    assert_output(
        r#"
        const log = console.log;
        let release;
        const awaited = { then(resolve) { release = resolve; } };
        async function* values() {
            log('start');
            const value = await awaited;
            yield value;
            return value + 1;
        }
        const g = values();
        g.next().then(r => log('one', r.value, r.done));
        g.next().then(r => log('two', r.value, r.done));
        Promise.resolve().then(() => {
            log('before-release');
            release(30);
            log('after-release');
        });
    "#,
        &[
            "start",
            "before-release",
            "after-release",
            "one 30 false",
            "two 31 true",
        ],
    );
}

#[test]
fn rejected_yield_is_thrown_back_into_body_instead_of_completing_request() {
    assert_output(
        r#"
        const log = console.log;
        async function* values() {
            try { yield Promise.reject(17); }
            catch (error) { log('caught', error); yield error + 1; }
            return 19;
        }
        const g = values();
        g.next().then(r => log('one', r.value, r.done));
        g.next().then(r => log('two', r.value, r.done));
        log('sync');
    "#,
        &["sync", "caught 17", "one 18 false", "two 19 true"],
    );
}
