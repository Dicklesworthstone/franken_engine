#![forbid(unsafe_code)]

//! A thenable is adopted whatever defines its `then` (bd-9vouw.174).
//!
//! Promise Resolve Functions (ES2020 25.6.1.3.2) read `then` once with the
//! full [[Get]], so a method a class or prototype defines, a getter, a Proxy
//! trap and any callable count. The engine used to adopt only an own closure
//! `then`, and a `then` handler's result, `await v`, an async function's
//! `return v` and the elements of Promise.all, allSettled, race and any were
//! never checked at all: each fulfilled with the object.
//!
//! The expected lines are Node v22.2.0's output for the same programs (Bun
//! 1.4.2 prints the same lines for the four promise programs, apart from its
//! own chaining-cycle message). A promise resolved with itself rejects with a
//! TypeError, which used to be a plain string. Each program
//! runs on both interpreter profiles, as written and with a collection at
//! every (and every seventh) safe point, and the memory-accounting oracle must
//! hold after each run.
//!
//! No-claim: the microtask turns `for await` over a sync iterable takes
//! against concurrent work differ from V8's (only its values are checked).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str, v8_profile: bool, stress_interval: Option<u64>) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "thenables.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "thenables.js"),
        &LoweringContext::new("thenable-trace", "thenable-decision", "thenable-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut config = if v8_profile {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "thenables");
    core.set_gc_stress_interval(stress_interval);
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift (v8 profile {v8_profile}, stress {stress_interval:?})"
    );
    result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

fn assert_lines(source: &str, expected: &[&str]) {
    for v8_profile in [false, true] {
        for stress_interval in [None, Some(1), Some(7)] {
            assert_eq!(
                console_lines(source, v8_profile, stress_interval),
                expected,
                "v8 profile {v8_profile}, stress {stress_interval:?}"
            );
        }
    }
}

/// A class method, an inherited method, a getter, a Proxy trap and a plain
/// function are each a thenable's `then`, through a handler's result, `await`,
/// the executor's resolve function, `Promise.resolve` and an async return.
#[test]
fn thenables_are_adopted_on_every_resolution_path() {
    assert_lines(
        r#"class T { constructor(v) { this.v = v; } then(resolve) { resolve(this.v); } }
Promise.resolve().then(() => new T('handler result')).then(v => console.log('then', v));
(async () => console.log('await', await new T('awaited')))();
new Promise(r => r(new T('executor'))).then(v => console.log('resolve fn', v));
Promise.resolve(new T('static')).then(v => console.log('Promise.resolve', v));
(async () => new T('returned'))().then(v => console.log('async return', v));
Promise.resolve(Object.create({ then(r) { r('inherited'); } })).then(v => console.log('proto', v));
Promise.resolve({ get then() { return r => r('getter'); } }).then(v => console.log('getter', v));
Promise.resolve(new Proxy({}, { get: (t, k) => k === 'then' ? (r => r('trap')) : undefined })).then(v => console.log('proxy', v));
function plainThen(r) { r('function decl'); }
Promise.resolve({ then: plainThen }).then(v => console.log('function', v));
Promise.resolve({ then: 5 }).then(v => console.log('non-callable', typeof v, v.then));
console.log('sync end');
"#,
        &[
            "sync end",
            "non-callable object 5",
            "await awaited",
            "resolve fn executor",
            "Promise.resolve static",
            "async return returned",
            "proto inherited",
            "getter getter",
            "proxy trap",
            "function function decl",
            "then handler result",
        ],
    );
}

/// A `then` that rejects, throws, or throws after resolving, and a `then`
/// getter that throws: the promise rejects with the thrown value itself.
#[test]
fn thenable_rejections_and_throwing_then_reject_with_the_thrown_value() {
    assert_lines(
        r#"class Bad { then(_, reject) { reject(new TypeError('rejected by then')); } }
class Throws { then() { throw new RangeError('then threw'); } }
const getterThrows = { get then() { throw new SyntaxError('getter threw'); } };
class Late { then(resolve) { resolve('first'); throw new Error('ignored'); } }
Promise.resolve(new Bad()).catch(e => console.log('reject', e.name, e.message));
Promise.resolve(new Throws()).catch(e => console.log('throw', e instanceof RangeError, e.message));
Promise.resolve(getterThrows).catch(e => console.log('getter', e.name, e.message));
Promise.resolve(new Late()).then(v => console.log('late', v));
(async () => { try { await new Throws(); } catch (e) { console.log('await catch', e.message); } })();
Promise.resolve().then(() => getterThrows).catch(e => console.log('handler result', e.message));
const cyclic = Promise.resolve().then(() => cyclic);
cyclic.catch(e => console.log('cycle', e instanceof TypeError, e.message));
let resolveSelf; const self = new Promise(res => { resolveSelf = res; }); resolveSelf(self);
self.catch(e => console.log('self', e.name, e.message));
"#,
        &[
            "getter SyntaxError getter threw",
            "self TypeError Chaining cycle detected for promise #<Promise>",
            "reject TypeError rejected by then",
            "throw true then threw",
            "late first",
            "await catch then threw",
            "handler result getter threw",
            "cycle true Chaining cycle detected for promise #<Promise>",
        ],
    );
}

/// Nested thenables resolve to the innermost value, and a thenable costs the
/// PromiseResolveThenableJob turn Node shows against plain values.
#[test]
fn thenable_adoption_takes_the_specified_microtask_turns() {
    assert_lines(
        r#"const log = [];
class Chain { constructor(n) { this.n = n; } then(r) { r(this.n > 0 ? new Chain(this.n - 1) : 'bottom'); } }
Promise.resolve(new Chain(3)).then(v => console.log('nested', v));
Promise.resolve(1).then(() => log.push('a'));
Promise.resolve(new Chain(0)).then(() => log.push('thenable'));
(async () => { await new Chain(0); log.push('await thenable'); })();
(async () => { await 0; log.push('await plain'); })();
Promise.resolve(2).then(() => log.push('b')).then(() => log.push('c')).then(() => log.push('d')).then(() => log.push('e')).then(() => console.log(log.join(',')));
"#,
        &[
            "nested bottom",
            "a,await plain,b,thenable,await thenable,c,d,e",
        ],
    );
}

/// Promise.all, allSettled, race and any resolve each element with
/// Promise.resolve, so a thenable element (own or inherited `then`) adopts.
#[test]
fn combinator_elements_go_through_promise_resolve() {
    assert_lines(
        r#"class T { constructor(v) { this.v = v; } then(r) { r(this.v); } }
const own = { then(r) { r('own'); } };
Promise.all([new T(1), own, 3]).then(v => console.log('all', JSON.stringify(v)));
Promise.allSettled([new T('s')]).then(v => console.log('allSettled', v[0].status, v[0].value));
Promise.race([new T('race')]).then(v => console.log('race', v));
Promise.any([new T('any')]).then(v => console.log('any', v));
"#,
        &[
            "all [1,\"own\",3]",
            "allSettled fulfilled s",
            "race race",
            "any any",
        ],
    );
}

/// `for await` over a sync iterable awaits each value, so a thenable value
/// adopts (the loop is rewritten to an `await`).
#[test]
fn for_await_over_a_sync_iterable_awaits_thenables() {
    assert_lines(
        r#"class T { constructor(v) { this.v = v; } then(r) { r(this.v); } }
(async () => { const out = []; for await (const x of [new T(1), 2, Promise.resolve(3), { then(r) { r(4); } }]) out.push(x); console.log('for await', out.join()); })();
"#,
        &["for await 1,2,3,4"],
    );
}

/// A resolving-function pair that resolved its promise to a pending promise
/// or a thenable is already resolved (ES2020 `alreadyResolved`): its later
/// resolve, reject or throw does nothing. A late reject used to settle the
/// promise and the adoption then ended the run ("already settled").
#[test]
fn resolving_functions_are_spent_once_they_adopt() {
    assert_lines(
        r#"let resolveLater;
const later = new Promise(r => { resolveLater = r; });
new Promise((resolve, reject) => { resolve(later); reject(new Error('late')); }).then(v => console.log('a', v), e => console.log('a rejected', e.message));
new Promise((resolve) => { resolve(later); resolve('second'); }).then(v => console.log('b', v));
new Promise((resolve) => { resolve(later); throw new Error('ignored'); }).then(v => console.log('c', v), e => console.log('c rejected', e.message));
class Twice { then(resolve, reject) { resolve(later); reject(new Error('no')); resolve('no'); } }
Promise.resolve(new Twice()).then(v => console.log('d', v), e => console.log('d rejected', e.message));
class ThenThrows { then(resolve) { resolve(later); throw new Error('ignored'); } }
Promise.resolve(new ThenThrows()).then(v => console.log('e', v), e => console.log('e rejected', e.message));
const { promise, resolve, reject } = Promise.withResolvers();
resolve(later); reject(new Error('no')); promise.then(v => console.log('f', v), e => console.log('f rejected', e.message));
new Promise((resolve, reject) => { resolve(new Twice()); reject(new Error('outer')); }).then(v => console.log('g', v), e => console.log('g rejected', e.message));
Promise.resolve().then(() => resolveLater('later value'));
"#,
        &[
            "a later value",
            "b later value",
            "c later value",
            "f later value",
            "d later value",
            "e later value",
            "g later value",
        ],
    );
}
