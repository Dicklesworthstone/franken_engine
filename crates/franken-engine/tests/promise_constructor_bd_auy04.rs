//! bd-auy04: `new Promise(executor)`.
//!
//! The global `Promise` used to be a plain object carrying only the statics,
//! so `new Promise(...)` failed with "expected constructor function, got
//! object". It is now a constructible builtin: the executor runs
//! synchronously with one-shot resolving functions, a throw rejects the
//! promise, and calling `Promise` without `new` throws a TypeError.
//!
//! Expected outputs are Node v22.2.0's for the same source.

use frankenengine_engine::HybridRouter;

fn eval_console(name: &str, source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("{name}: eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("|")
}

const CASES: &[(&str, &str, &str)] = &[
    ("typeof_promise", "console.log(typeof Promise);", "function"),
    (
        "statics_still_available",
        "console.log(typeof Promise.resolve, typeof Promise.all);",
        "function function",
    ),
    (
        "resolve_in_executor",
        "new Promise(r => r(1)).then(v => console.log(v));",
        "1",
    ),
    (
        "executor_runs_synchronously",
        "new Promise(() => console.log('exec')); console.log('after');",
        "exec|after",
    ),
    (
        "reject_in_executor",
        "new Promise((_, rej) => rej(new Error('x'))).catch(e => console.log('caught', e.message));",
        "caught x",
    ),
    (
        "executor_throw_rejects_with_the_thrown_error",
        "new Promise(() => { throw new Error('boom') }).catch(e => console.log('thrown', e.message, e instanceof Error));",
        "thrown boom true",
    ),
    (
        "resolving_functions_are_one_shot_and_a_late_throw_is_inert",
        "new Promise((res) => { res('first'); res('second'); throw new Error('late') }).then(v => console.log(v));",
        "first",
    ),
    (
        "reject_then_resolve_keeps_the_rejection",
        "new Promise((res, rej) => { rej('no'); res('yes') }).then(v => console.log('ok', v), e => console.log('err', e));",
        "err no",
    ),
    (
        "resolve_with_a_promise_adopts_it",
        "new Promise(res => res(Promise.resolve(5))).then(v => console.log('adopted', v));",
        "adopted 5",
    ),
    (
        "resolve_with_a_thenable_adopts_it",
        "new Promise(res => res({ then(f) { f(9) } })).then(v => console.log('thenable', v));",
        "thenable 9",
    ),
    (
        "calling_without_new_throws_type_error",
        "try { Promise(() => {}) } catch (e) { console.log(e instanceof TypeError) }",
        "true",
    ),
    (
        "non_callable_executor_throws_type_error",
        "try { new Promise(1) } catch (e) { console.log(e instanceof TypeError) }",
        "true",
    ),
    (
        "reaction_order_against_other_microtasks",
        "const log = []; new Promise(r => { log.push('executor'); r() }).then(() => { log.push('then'); console.log(log.join()) }); Promise.resolve().then(() => log.push('other')); log.push('sync');",
        "executor,sync,then",
    ),
    (
        "constructed_promises_compose_with_statics",
        "Promise.all([new Promise(r => r(1)), Promise.resolve(2)]).then(v => console.log(v.join()));",
        "1,2",
    ),
];

#[test]
fn promise_constructor_matches_node_bd_auy04() {
    for (name, source, expected) in CASES {
        assert_eq!(eval_console(name, source), *expected, "{name}: {source}");
    }
}
