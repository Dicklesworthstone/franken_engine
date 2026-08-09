//! bd-iio0f regression — `Promise.resolve(thenable)` assimilation and the
//! nested-microtask ordering it must preserve (ES2020 25.6.1.3 /
//! PromiseResolveThenableJob).
//!
//! Before the fix, `Promise.resolve(t)` for a thenable object wrapped the
//! object directly (completion `[object Object]`) and never called its `then`,
//! so nested microtasks the thenable scheduled never ran. These full-pipeline
//! checks pin thenable assimilation, the resolve/reject capabilities passed to
//! `then`, deterministic nested-microtask ordering, and the once-only settle
//! guard.
//!
//! The interpreter runs deep enough that this harness needs a provisioned
//! stack; the workspace test runner sets `RUST_MIN_STACK` accordingly.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval(source: &str) -> EvalOutcome {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|err| panic!("HybridRouter::eval failed for {source:?}: {err}"))
}

fn console_text(outcome: &EvalOutcome) -> String {
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn thenable_assimilation_preserves_nested_microtask_order() {
    let outcome = eval(
        "const t = { then(resolve) { Promise.resolve().then(() => console.log('nested')); \
         resolve('thenable'); } }; Promise.resolve(t).then(v => console.log(v));",
    );
    assert_eq!(
        console_text(&outcome).trim(),
        "nested\nthenable",
        "the thenable's nested microtask must drain before its resolution reaction"
    );
}

#[test]
fn thenable_resolve_forwards_its_value_to_downstream_then() {
    let outcome = eval(
        "const t = { then(resolve) { resolve(42); } }; \
         Promise.resolve(t).then(v => console.log('got:' + v));",
    );
    assert_eq!(console_text(&outcome).trim(), "got:42");
}

#[test]
fn thenable_reject_capability_routes_to_catch() {
    let outcome = eval(
        "const t = { then(resolve, reject) { reject('boom'); } }; \
         Promise.resolve(t).catch(e => console.log('caught:' + e));",
    );
    assert_eq!(console_text(&outcome).trim(), "caught:boom");
}

#[test]
fn thenable_then_that_throws_rejects_the_promise() {
    let outcome = eval(
        "const t = { then() { throw 'explode'; } }; \
         Promise.resolve(t).catch(e => console.log('rejected:' + e));",
    );
    assert_eq!(console_text(&outcome).trim(), "rejected:explode");
}

#[test]
fn thenable_second_settle_is_ignored_once_resolved() {
    // The resolve/reject capabilities settle at most once; the second call is
    // a silent no-op, so the downstream reaction observes only the first value.
    let outcome = eval(
        "const t = { then(resolve, reject) { resolve('first'); resolve('second'); reject('third'); } }; \
         Promise.resolve(t).then(v => console.log('value:' + v), e => console.log('error:' + e));",
    );
    assert_eq!(console_text(&outcome).trim(), "value:first");
}

#[test]
fn non_thenable_object_fulfills_with_the_object_itself() {
    // A plain object (no callable `then`) is not assimilated: the promise
    // fulfills with the object, unchanged behavior.
    let outcome =
        eval("Promise.resolve({ marker: 7 }).then(v => console.log('marker:' + v.marker));");
    assert_eq!(console_text(&outcome).trim(), "marker:7");
}
