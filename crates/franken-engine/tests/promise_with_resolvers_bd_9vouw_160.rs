//! bd-9vouw.160: Promise.withResolvers (ES2024 27.2.4.8) returns
//! `{ promise, resolve, reject }` for a new promise of `this`: %Promise%, or
//! a Promise subclass through its constructor (bd-9vouw.137). It was
//! undefined. Expected output is Node v22.2.0's stdout for each program.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

/// The console output of `source`, its promise jobs and timers drained.
fn console_output(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The result's shape, the function's name and length, and once-only settlement.
#[test]
fn with_resolvers_shape_and_settlement() {
    assert_eq!(
        console_output(
            r#"const d = Promise.withResolvers();
console.log(typeof Promise.withResolvers, Promise.withResolvers.name, Promise.withResolvers.length,
  Object.keys(d).join(), d.promise instanceof Promise, typeof d.resolve, typeof d.reject);
d.promise.then(function (v) { console.log('resolved', v); });
d.resolve(42); d.resolve(43); d.reject(new Error('late'));
const e = Promise.withResolvers();
e.promise.catch(function (err) { console.log('rejected', err.message); });
e.reject(new Error('boom'));"#
        ),
        r#"function withResolvers 0 promise,resolve,reject true function function
resolved 42
rejected boom"#
    );
}

/// A subclass `this` gives a subclass promise; a non-constructor `this` throws.
#[test]
fn with_resolvers_subclass_and_receivers() {
    assert_eq!(
        console_output(
            r#"class Tracked extends Promise {}
const t = Tracked.withResolvers();
console.log(t.promise instanceof Tracked, t.promise instanceof Promise);
t.promise.then(function (v) { console.log('tracked', v); });
t.resolve('ok');
try { Promise.withResolvers.call({}); console.log('no throw'); } catch (err) { console.log(err.constructor.name); }
const { promise, resolve } = Promise.withResolvers();
setTimeout(function () { resolve('later'); }, 0);
promise.then(function (v) { console.log(v); });"#
        ),
        r#"true true
TypeError
tracked ok
later"#
    );
}
