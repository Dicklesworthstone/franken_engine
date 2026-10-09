//! bd-9vouw.323: resolving a promise with a native promise reads its
//! `then` at once and settles the promise two jobs later. The jobs are
//! PromiseResolveThenableJob, then the `then` reaction. The engine adopted
//! the state at once, two ticks early (an executor's resolve(p), an async
//! function returning p, a then callback returning p, a rejected p). It
//! never read `then`, so an own `then` was ignored. The program checks
//! those against a counting chain: an own `then` runs, the `then` read at
//! resolve time is the one called, and a pending source settles its
//! follower when it settles. Node v22.2.0 gives this line; Bun 1.4.2
//! agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn native_promise_resolution_takes_the_spec_jobs() {
    let source = r#"
const log = [];
Promise.resolve().then(() => log.push(1)).then(() => log.push(2)).then(() => log.push(3)).then(() => log.push(4)).then(() => log.push(5));
new Promise((r) => r(Promise.resolve())).then(() => log.push('adopt'));
(async function () { return Promise.resolve(); })().then(() => log.push('asyncret'));
Promise.resolve().then(() => Promise.resolve('v')).then((v) => log.push('thenret:' + v));
new Promise((r) => r(Promise.reject(new Error('no')))).catch((e) => log.push('rejadopt:' + e.message));
Promise.resolve(Promise.resolve()).then(() => log.push('static'));
const p = Promise.resolve(); p.then = function (res) { log.push('own-then'); res('x'); };
new Promise((r) => r(p)).then((v) => log.push('custom:' + v));
const q = Promise.resolve(); q.then = function (res) { res('first'); };
const late = new Promise((r) => r(q)); q.then = function (res) { res('late'); };
late.then((v) => log.push('captured:' + v));
let pendingResolve; const pending = new Promise((r) => { pendingResolve = r; });
new Promise((r) => r(pending)).then((v) => log.push('pending:' + v));
setTimeout(() => { pendingResolve('later'); setTimeout(() => console.log(log.join(' ')), 5); }, 5);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "1 static own-then 2 custom:x captured:first 3 adopt asyncret rejadopt:no 4 thenret:v 5 pending:later"
        ]
    );
}
