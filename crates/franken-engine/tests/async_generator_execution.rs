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

#[test]
fn return_rejection_enters_the_generators_catch() {
    assert_output(
        r#"const log=console.log; async function* g(){try{return Promise.reject(17);}catch(e){log('caught',e);yield e+1;}return 19;} const it=g(); it.next().then(r=>log('first',r.value,r.done)); it.next().then(r=>log('second',r.value,r.done)); log('sync');"#,
        &["sync", "caught 17", "first 18 false", "second 19 true"],
    );
}

#[test]
fn return_waits_before_entering_finally() {
    assert_output(
        r#"const log=console.log; let release; const pending={then(resolve){release=resolve;}}; async function* g(){try {return pending;}finally{log('finally');yield 9;}} const it=g(); it.next().then(r=>log('first',r.value,r.done)); it.next().then(r=>log('second',r.value,r.done)); Promise.resolve().then(()=>{log('release');release(42);}); log('sync');"#,
        &[
            "sync",
            "release",
            "finally",
            "first 9 false",
            "second 42 true",
        ],
    );
}

#[test]
fn return_await_does_not_overwrite_the_original_binding() {
    assert_output(
        r#"const log=console.log; const p=Promise.resolve(42); async function* g(){const local=p;try{return local;}finally{log('identity',local===p,typeof local.then);yield 9;}} const it=g();it.next().then(r=>log('first',r.value,r.done));it.next().then(r=>log('second',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "identity true function",
            "first 9 false",
            "second 42 true",
        ],
    );
}

#[test]
fn rejection_during_finally_return_reaches_outer_catch() {
    assert_output(
        r#"const log=console.log;async function* g(){try{try{return 1;}finally{return Promise.reject(7);}}catch(e){log('caught',e);yield e;}return 8;}const it=g();it.next().then(r=>log('first',r.value,r.done));it.next().then(r=>log('second',r.value,r.done));log('sync');"#,
        &["sync", "caught 7", "first 7 false", "second 8 true"],
    );
}

#[test]
fn nested_async_yield_star_preserves_sent_and_completion_values() {
    assert_output(
        r#"const log=console.log;async function* inner(){const sent=yield Promise.resolve(1);log('sent',sent);return 3;}async function* outer(){const value=yield* inner();log('delegated',value);yield 4;return 5;}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.next(2).then(r=>log('two',r.value,r.done));g.next().then(r=>log('three',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "sent 2",
            "one 1 false",
            "delegated 3",
            "two 4 false",
            "three 5 true",
        ],
    );
}

#[test]
fn async_delegation_prefers_async_method_and_caches_next() {
    assert_output(
        r#"const log=console.log;let count=0;const iterator={get next(){log('get-next');return function(value){log('step',++count,value,this===iterator);return Promise.resolve({value:count*10,done:count>1});};}};const source={[Symbol.asyncIterator](){log('async');return iterator;},[Symbol.iterator](){throw 'sync must not run';}};async function* outer(){return yield* source;}const g=outer();g.next(99).then(r=>log('one',r.value,r.done));g.next(7).then(r=>log('two',r.value,r.done));log('sync');"#,
        &[
            "async",
            "get-next",
            "step 1 undefined true",
            "sync",
            "step 2 7 true",
            "one 10 false",
            "two 20 true",
        ],
    );
}

#[test]
fn async_delegated_return_can_yield_before_finishing() {
    assert_output(
        r#"const log=console.log;let n=0;const source={[Symbol.asyncIterator](){return this;},next(value){log('next',value);return Promise.resolve({value:++n,done:n>1});},return(value){log('return',value);return Promise.resolve({value:9,done:false});}};async function* outer(){try{return yield* source;}finally{log('finally');}}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.return(Promise.resolve(42)).then(r=>log('two',r.value,r.done));g.next(8).then(r=>log('three',r.value,r.done));log('sync');"#,
        &[
            "next undefined",
            "sync",
            "one 1 false",
            "return 42",
            "next 8",
            "two 9 false",
            "finally",
            "three 2 true",
        ],
    );
}

#[test]
fn async_delegated_throw_reaches_the_inner_iterator() {
    assert_output(
        r#"const log=console.log;let n=0;const source={[Symbol.asyncIterator](){return this;},next(value){return Promise.resolve({value:++n,done:n>1});},throw(value){log('throw',value);return Promise.resolve({value:value+1,done:false});}};async function* outer(){return yield* source;}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.throw(7).then(r=>log('two',r.value,r.done));g.next().then(r=>log('three',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "throw 7",
            "one 1 false",
            "two 8 false",
            "three 2 true",
        ],
    );
}

#[test]
fn missing_async_throw_awaits_close_without_observing_result_properties() {
    assert_output(
        r#"const log=console.log;const source={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve({value:1,done:false});},return(){log('close',arguments.length);return Promise.resolve({get done(){throw 'read done';},get value(){throw 'read value';}});}};async function* outer(){try{yield* source;}catch(e){log('caught',e.name);yield 2;}finally{log('finally');}}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.throw(7).then(r=>log('two',r.value,r.done));g.next().then(r=>log('three',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "close 0",
            "one 1 false",
            "caught TypeError",
            "finally",
            "two 2 false",
            "three undefined true",
        ],
    );
}

#[test]
fn async_cleanup_rejection_replaces_missing_throw_error() {
    assert_output(
        r#"const log=console.log;const source={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve({value:1,done:false});},return(){log('close');return Promise.reject(88);}};async function* outer(){try{yield* source;}catch(e){log('caught',e);yield 2;}}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.throw(7).then(r=>log('two',r.value,r.done));log('sync');"#,
        &["sync", "close", "one 1 false", "caught 88", "two 2 false"],
    );
}

#[test]
fn async_delegate_rejects_primitive_iteration_results_inside_body() {
    assert_output(
        r#"const log=console.log;const source={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve(4);}};async function* outer(){try{yield* source;}catch(e){log('caught',e.name);yield 2;}return 3;}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.next().then(r=>log('two',r.value,r.done));log('sync');"#,
        &["sync", "caught TypeError", "one 2 false", "two 3 true"],
    );
}

#[test]
fn async_delegate_forwards_promise_values_without_awaiting_them() {
    assert_output(
        r#"const log=console.log;const p=Promise.reject(17);const source={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve({value:p,done:false});},throw(){log('wrong-throw');return Promise.resolve({value:999,done:true});}};async function* outer(){try{yield* source;}catch(e){log('wrong-catch',e);yield 18;}}outer().next().then(r=>{log('promise',r.value===p,r.done);r.value.catch(e=>log('rejected',e));});log('sync');"#,
        &["sync", "promise true false", "rejected 17"],
    );
}

#[test]
fn async_yield_star_adapts_sync_iterators_and_awaits_done_values() {
    assert_output(
        r#"const log=console.log;function* inner(){const sent=yield Promise.resolve(1);log('sent',sent);return Promise.resolve(3);}async function* outer(){const value=yield* inner();log('delegated',value,typeof value);return value+1;}const g=outer();g.next().then(r=>log('one',r.value,r.done));g.next(2).then(r=>log('two',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "sent 2",
            "one 1 false",
            "delegated 3 number",
            "two 4 true",
        ],
    );
}

#[test]
fn true_async_delegate_completion_value_is_not_prematurely_unwrapped() {
    assert_output(
        r#"const log=console.log;const source={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve({value:Promise.resolve(42),done:true});}};async function* outer(){const value=yield* source;log('promise',typeof value.then);return value;}outer().next().then(r=>log('done',r.value,r.done));log('sync');"#,
        &["sync", "promise function", "done 42 true"],
    );
}

#[test]
fn noncallable_async_iterator_does_not_fall_back_to_sync() {
    assert_output(
        r#"const log=console.log;const source={[Symbol.asyncIterator]:1,[Symbol.iterator](){log('wrong-sync');return [1][Symbol.iterator]();}};async function* outer(){try{yield* source;}catch(e){log('caught',e.name);yield 2;}}outer().next().then(r=>log('done',r.value,r.done));log('sync');"#,
        &["caught TypeError", "sync", "done 2 false"],
    );
}

#[test]
fn async_delegate_observes_done_before_value_once() {
    assert_output(
        r#"const log=console.log;let n=0;const source={[Symbol.asyncIterator](){return this;},next(){const i=++n;return Promise.resolve({get done(){log('done-get',i);return i>1;},get value(){log('value-get',i);return Promise.resolve(i);}});}};async function* outer(){const v=yield* source;log('final-type',typeof v.then);return v;}const g=outer();g.next().then(r=>log('one',typeof r.value.then,r.done));g.next().then(r=>log('two',r.value,r.done));log('sync');"#,
        &[
            "sync",
            "done-get 1",
            "value-get 1",
            "one function false",
            "done-get 2",
            "value-get 2",
            "final-type function",
            "two 2 true",
        ],
    );
}

#[test]
fn awaited_thenable_uses_inherited_getter_once_with_original_receiver() {
    assert_output(
        r#"
        let gets = 0;
        const prototype = { get then() {
            console.log('get', ++gets, this.marker);
            return function(resolve) { console.log('call', this.marker); resolve(7); };
        } };
        const source = Object.create(prototype);
        source.marker = 'receiver';
        async function* values() { yield source; return 8; }
        const g = values();
        g.next().then(r => console.log('first', r.value, r.done));
        g.next().then(r => console.log('second', r.value, r.done, gets));
        console.log('sync');
        "#,
        &[
            "get 1 receiver",
            "sync",
            "call receiver",
            "first 7 false",
            "second 8 true 1",
        ],
    );
}

#[test]
fn awaited_then_getter_throw_preserves_identity_and_enters_generator_catch() {
    assert_output(
        r#"
        const original = { marker: 17 };
        const source = { get then() { console.log('get'); throw original; } };
        async function* values() {
            try { await source; console.log('wrong'); }
            catch (error) { console.log('caught', error === original); yield 18; }
            return 19;
        }
        const g = values();
        g.next().then(r => console.log('first', r.value, r.done));
        g.next().then(r => console.log('second', r.value, r.done));
        console.log('sync');
        "#,
        &[
            "get",
            "sync",
            "caught true",
            "first 18 false",
            "second 19 true",
        ],
    );
}

#[test]
fn noncallable_then_getter_preserves_the_awaited_object_identity() {
    assert_output(
        r#"
        let gets = 0;
        const source = { get then() { gets++; return 17; } };
        async function* values() { const value = await source; yield value === source; }
        values().next().then(r => console.log('result', r.value, r.done, gets));
        console.log('sync');
        "#,
        &["sync", "result true false 1"],
    );
}

#[test]
fn then_getter_reentry_queues_next_until_pending_await_really_resolves() {
    assert_output(
        r#"
        let g, release;
        const source = { get then() {
            console.log('get');
            g.next(9).then(r => console.log('reentrant', r.value, r.done));
            return function(resolve) { console.log('then'); release = resolve; };
        } };
        async function* values() {
            const value = await source;
            const sent = yield value;
            return sent;
        }
        g = values();
        g.next().then(r => console.log('first', r.value, r.done));
        Promise.resolve().then(() => { console.log('release'); release(7); });
        console.log('sync');
        "#,
        &[
            "get",
            "sync",
            "then",
            "release",
            "first 7 false",
            "reentrant 9 true",
        ],
    );
}

#[test]
fn completed_return_then_getter_cannot_drain_its_own_request_reentrantly() {
    assert_output(
        r#"
        let g, release;
        const source = { get then() {
            console.log('get-return');
            g.next().then(r => console.log('next', r.value, r.done));
            return function(resolve) { console.log('then'); release = resolve; };
        } };
        async function* values() { console.log('body-must-not-run'); }
        g = values();
        g.return(source).then(r => console.log('return', r.value, r.done));
        Promise.resolve().then(() => { console.log('release'); release(42); });
        console.log('sync');
        "#,
        &[
            "get-return",
            "sync",
            "then",
            "release",
            "return 42 true",
            "next undefined true",
        ],
    );
}

#[test]
fn return_argument_getter_rejection_is_injected_at_the_suspended_yield() {
    assert_output(
        r#"
        const original = { marker: 42 };
        const source = { get then() { console.log('get-return'); throw original; } };
        async function* values() {
            try { yield 1; }
            catch (error) { console.log('caught', error === original); yield 2; }
            return 3;
        }
        const g = values();
        g.next().then(r => console.log('first', r.value, r.done));
        g.return(source).then(r => console.log('return', r.value, r.done));
        g.next().then(r => console.log('last', r.value, r.done));
        console.log('sync');
        "#,
        &[
            "sync",
            "get-return",
            "first 1 false",
            "caught true",
            "return 2 false",
            "last 3 true",
        ],
    );
}

#[test]
fn return_thenable_getter_is_awaited_before_finally_runs() {
    assert_output(
        r#"
        let release;
        const source = { get then() {
            console.log('get-return');
            return function(resolve) { release = resolve; };
        } };
        async function* values() {
            try { return source; }
            finally { console.log('finally'); }
        }
        values().next().then(r => console.log('result', r.value, r.done));
        Promise.resolve().then(() => { console.log('release'); release(42); });
        console.log('sync');
        "#,
        &["get-return", "sync", "release", "finally", "result 42 true"],
    );
}

#[test]
fn await_uses_the_selected_then_callable_even_if_the_getter_replaces_itself() {
    assert_output(
        r#"
        let gets = 0;
        const source = { get then() {
            gets++;
            Object.defineProperty(source, 'then', {
                configurable: true,
                value(resolve) { console.log('wrong-replacement'); resolve(99); }
            });
            return function(resolve) { console.log('selected', this === source); resolve(7); };
        } };
        async function* values() { yield source; }
        values().next().then(r => console.log('result', r.value, r.done, gets));
        console.log('sync');
        "#,
        &["sync", "selected true", "result 7 false 1"],
    );
}
