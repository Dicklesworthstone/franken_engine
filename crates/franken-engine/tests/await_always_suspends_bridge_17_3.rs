//! BRIDGE-17.3 (slice): `await` always suspends (ES2020 6.2.3.1 Await).
//!
//! An async function awaiting an already-settled Promise (or a non-Promise
//! such as `await null`) must resume through a Promise-reaction job, after
//! the caller's remaining synchronous code and after earlier queued reactions.
//! Expected strings are the console output Node v22.2.0 prints for the same
//! programs.
//!
//! The runtime now executes async calls in isolated activations, snapshots an
//! activation at every AwaitValue, returns the async result Promise to the
//! caller, and resumes only from the Promise microtask queue. These cases are
//! ordinary CI regressions so that the original synchronous-continuation bug
//! cannot return unnoticed.
//!
//! No mocks: real source through the public `HybridRouter::eval` path, with
//! the microtask queue drained by the engine.

use frankenengine_engine::HybridRouter;

fn console_output(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome
            .console_output
            .iter()
            .map(|entry| entry.message.clone())
            .collect::<Vec<_>>()
            .join("\n"),
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        console_output(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn await_of_non_promise_yields_to_the_caller_and_queued_reactions() {
    check(
        "const log = []; \
         Promise.resolve().then(() => log.push('p1')).then(() => log.push('p2')) \
           .then(() => log.push('p3')).then(() => console.log(log.join())); \
         (async () => { log.push('a0'); await null; log.push('a1'); })(); \
         log.push('sync');",
        "a0,sync,p1,a1,p2,p3",
    );
}

#[test]
fn await_of_settled_promises_resumes_after_synchronous_code() {
    check(
        "const log = []; \
         (async () => { log.push('a'); await 1; log.push('b'); await Promise.resolve(2); log.push('c'); })() \
           .then(() => console.log(log.join())); \
         log.push('s');",
        "a,s,b,c",
    );
}

#[test]
fn await_of_rejected_promise_throws_after_suspension() {
    check(
        "const log = []; \
         async function f() { try { await Promise.reject(new Error('x')); } catch (e) { log.push('caught ' + e.message); } } \
         f().then(() => console.log(log.join())); \
         log.push('s');",
        "s,caught x",
    );
}
