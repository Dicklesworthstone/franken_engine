//! Executable async-generator source retains its kind, serializes requests,
//! and preserves activation ownership and abrupt completions across Promise jobs.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/modules")
        .canonicalize()
        .unwrap()
}

fn assert_output(source: &str, expected: &[&str]) {
    let root = fixture_root();
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse async-generator source");
    let ir0 = Ir0Module::from_syntax_tree(
        tree,
        root.join("async-generator-entry.mjs").display().to_string(),
    );
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("async-generator-source", "async-generator-source", "async-generator-source"),
    )
    .expect("lower async-generator source")
    .ir3;
    for throughput in [false, true] {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::ModuleLoad,
        ]);
        config.module_root = Some(root.display().to_string());
        let result = InterpreterCore::new(config, "async-generator-source")
            .execute(&module)
            .expect("execute async-generator source");
        let output: Vec<_> = result.console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn queued_requests_unwrap_yields_and_resume_values() {
    assert_output(
        r#"
        async function* values() {
            console.log('start');
            const sent = yield Promise.resolve(7);
            console.log('resume:' + sent);
            yield 9;
            return 11;
        }
        const iterator = values();
        console.log(iterator[Symbol.asyncIterator]() === iterator);
        iterator.next().then(result => console.log('a:' + result.value + ':' + result.done));
        iterator.next(8).then(result => console.log('b:' + result.value + ':' + result.done));
        iterator.next().then(result => console.log('c:' + result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["true", "start", "sync", "resume:8", "a:7:false", "b:9:false", "c:11:true"],
    );
}

#[test]
fn pending_awaits_keep_generators_and_callers_independent() {
    assert_output(
        r#"
        async function* read(value) {
            console.log('start:' + value);
            const result = await new Promise(resolve => setTimeout(resolve, 0, value));
            yield result;
            return result + 1;
        }
        const first = read(20);
        const second = read(40);
        first.next().then(result => console.log('a:' + result.value));
        first.next().then(result => console.log('b:' + result.value));
        second.next().then(result => console.log('c:' + result.value));
        console.log('sync');
        "#,
        &["start:20", "start:40", "sync", "a:20", "b:21", "c:40"],
    );
}

#[test]
fn queued_return_waits_and_runs_yielding_finally() {
    assert_output(
        r#"
        async function* values() {
            try { yield 1; yield 2; }
            finally {
                console.log('cleanup');
                yield 3;
                console.log('after cleanup');
            }
        }
        const iterator = values();
        iterator.next().then(result => console.log('a:' + result.value + ':' + result.done));
        iterator.return(Promise.resolve(9)).then(result => console.log('b:' + result.value + ':' + result.done));
        iterator.next().then(result => console.log('c:' + result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["sync", "a:1:false", "cleanup", "after cleanup", "b:3:false", "c:9:true"],
    );
}

#[test]
fn queued_throw_preserves_identity_and_finally_suspension() {
    assert_output(
        r#"
        const token = {};
        async function* values() {
            try { yield 1; }
            catch (error) { console.log(error === token); yield 2; }
            finally { await 0; console.log('finally'); }
        }
        const iterator = values();
        iterator.next().then(result => console.log('a:' + result.value));
        iterator.throw(token).then(result => console.log('b:' + result.value));
        iterator.next().then(result => console.log('c:' + result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["sync", "true", "a:1", "b:2", "finally", "c:undefined:true"],
    );
}

#[test]
fn rejected_yield_enters_catch_and_rejected_return_rejects_request() {
    assert_output(
        r#"
        const token = {};
        async function* values() {
            try { yield Promise.reject(token); }
            catch (error) { console.log(error === token); yield 42; }
            return Promise.reject(token);
        }
        const iterator = values();
        iterator.next().then(result => console.log(result.value));
        iterator.next().catch(error => console.log(error === token));
        console.log('sync');
        "#,
        &["sync", "true", "42", "true"],
    );
}

#[test]
fn return_expressions_await_before_finally_and_are_catchable() {
    assert_output(
        r#"
        const token = {};
        async function* values() {
            try { return Promise.reject(token); }
            catch (error) { console.log(error === token); return Promise.resolve(42); }
            finally { console.log('finally'); await 0; }
        }
        values().next().then(result => console.log(result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["sync", "true", "finally", "42:true"],
    );
}

#[test]
fn completed_requests_and_wrong_receivers_return_promises() {
    assert_output(
        r#"
        const token = {};
        async function* values() { throw token; }
        const iterator = values();
        iterator.next().catch(error => console.log('first:' + (error === token)));
        iterator.next().then(result => console.log('next:' + result.value + ':' + result.done));
        iterator.throw(token).catch(error => console.log('throw:' + (error === token)));
        iterator.return(Promise.resolve(42)).then(result => console.log('return:' + result.value + ':' + result.done));
        const detached = iterator.next;
        detached().catch(error => console.log(error.name));
        console.log('sync');
        "#,
        &["sync", "first:true", "next:undefined:true", "throw:true", "TypeError", "return:42:true"],
    );
}

#[test]
fn return_before_start_awaits_without_executing_body() {
    assert_output(
        r#"
        let calls = 0;
        async function* values() { calls += 1; yield 1; }
        const iterator = values();
        iterator.return(Promise.resolve(42)).then(result => console.log(result.value + ':' + result.done));
        iterator.next().then(result => console.log(result.value + ':' + result.done));
        console.log('calls:' + calls);
        "#,
        &["calls:0", "42:true", "undefined:true"],
    );
}

#[test]
fn thenable_getter_reentrancy_queues_a_request() {
    assert_output(
        r#"
        let iterator;
        let reads = 0;
        class Item {
            get then() {
                reads += 1;
                console.log('get:' + reads);
                iterator.next('queued').then(result => console.log('b:' + result.value + ':' + result.done));
                return resolve => resolve(5);
            }
        }
        async function* values() {
            const sent = yield new Item();
            console.log(sent);
            return 7;
        }
        iterator = values();
        iterator.next().then(result => console.log('a:' + result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["get:1", "sync", "queued", "a:5:false", "b:7:true"],
    );
}

#[test]
fn async_generator_expressions_preserve_receiver_and_identity() {
    assert_output(
        r#"
        const object = {
            base: 40,
            values: async function* (delta) { await 0; yield this.base + delta; }
        };
        console.log(typeof object.values);
        console.log(object.values == object.values);
        const iterator = object.values(2);
        console.log(iterator == iterator);
        console.log(typeof iterator);
        iterator.next().then(result => console.log(result.value));
        console.log('sync');
        "#,
        &["function", "true", "true", "object", "sync", "42"],
    );
}

#[test]
fn nested_named_async_generators_capture_their_private_self_cell() {
    assert_output(
        r#"
        function factory() {
            return async function* inner(count) {
                if (count === 0) { yield 1; return; }
                const previous = await inner(count - 1).next();
                yield previous.value + 1;
            };
        }
        factory()(2).next().then(result => console.log(result.value));
        console.log('sync');
        "#,
        &["sync", "3"],
    );
}

#[test]
fn rejected_return_arguments_reenter_catch_at_the_suspended_yield() {
    assert_output(
        r#"
        const token = {};
        async function* values() {
            try { yield 1; }
            catch (error) { console.log(error === token); yield 2; }
            finally { await 0; console.log('finally'); }
        }
        const iterator = values();
        iterator.next().then(result => console.log('a:' + result.value));
        iterator.return(Promise.reject(token)).then(result => console.log('b:' + result.value + ':' + result.done));
        iterator.next().then(result => console.log('c:' + result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["sync", "a:1", "true", "b:2:false", "finally", "c:undefined:true"],
    );
}

#[test]
fn parameters_initialize_before_the_first_request() {
    assert_output(
        r#"
        let calls = 0;
        function initial() { calls += 1; return 42; }
        async function* values(value = initial()) { yield value; }
        const iterator = values();
        console.log(calls);
        iterator.next().then(result => console.log(result.value));
        console.log('sync');
        "#,
        &["1", "sync", "42"],
    );
}

#[test]
fn native_body_errors_reject_after_suspended_finally() {
    assert_output(
        r#"
        async function* values() {
            try { await 0; yield undefined.missing; }
            finally { await 0; console.log('cleanup'); }
        }
        values().next().catch(error => console.log(error.name));
        console.log('sync');
        "#,
        &["sync", "cleanup", "TypeError"],
    );
}

#[test]
fn bare_returns_and_explicit_return_expressions_keep_job_order() {
    assert_output(
        r#"
        async function* bare() { return; }
        async function* explicit() { return undefined; }
        bare().next().then(result => console.log('bare:' + result.done));
        explicit().next().then(result => console.log('explicit:' + result.done));
        Promise.resolve().then(() => console.log('tick'));
        console.log('sync');
        "#,
        &["sync", "bare:true", "tick", "explicit:true"],
    );
}

#[test]
fn throw_before_start_skips_the_body() {
    assert_output(
        r#"
        let calls = 0;
        const token = {};
        async function* values() { calls += 1; yield 1; }
        const iterator = values();
        iterator.throw(token).catch(error => console.log(error === token));
        iterator.next().then(result => console.log(result.value + ':' + result.done));
        console.log('calls:' + calls);
        "#,
        &["calls:0", "true", "undefined:true"],
    );
}

#[test]
fn imported_async_generators_resume_with_their_defining_module() {
    assert_output(
        r#"
        import { importedValues } from './async_generators.mjs';
        function unrelated() { return 'wrong'; }
        const iterator = importedValues(40);
        iterator.next().then(result => console.log(result.value + ':' + result.done));
        iterator.next().then(result => console.log(result.value + ':' + result.done));
        console.log('sync');
        "#,
        &["sync", "owner:41:false", "42:true"],
    );
}
