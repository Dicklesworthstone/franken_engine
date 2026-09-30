//! A promise's properties come from %Promise.prototype%: members a program
//! adds to it (polyfills, extensions) are visible on every promise,
//! `constructor` is `Promise`, @@toStringTag is "Promise", and
//! Object.prototype members are inherited. A promise's properties used to be
//! a fixed table of `then`/`catch`/`finally`, so `q.myFn()` threw "expected
//! function, got undefined" and `p.constructor` was undefined. Expected
//! strings are Node v22.2.0's completion values for the same programs.
//!
//! No-claim: `Promise.prototype[Symbol.toStringTag]` read on the prototype
//! object itself is still undefined; `constructor` is `undefined` once a
//! program replaces the global `Promise`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn promise_constructor_and_to_string_tag() {
    check(
        "const p = Promise.resolve(1); [p.constructor === Promise, Promise.prototype.constructor === Promise, \
         typeof p.constructor, p[Symbol.toStringTag], Object.prototype.toString.call(p)].join(' ')",
        "true true function Promise [object Promise]",
    );
}

#[test]
fn members_added_to_promise_prototype_are_inherited() {
    check(
        "Promise.prototype.myFn = function () { return 'mine:' + (this instanceof Promise); }; \
         const q = Promise.resolve(2); [typeof q.myFn, q.myFn(), typeof q.then, q.hasOwnProperty('then'), \
         q.hasOwnProperty('myFn')].join(' ')",
        "function mine:true function false false",
    );
    check(
        "Object.prototype.tag = 'T'; const p = Promise.resolve(); [p.tag, typeof p.toString, typeof p.valueOf].join(' ')",
        "T function function",
    );
    check(
        "const Original = Promise; Promise.prototype.sentinel = 1; const p = Original.resolve(0); \
         [p.sentinel, p.constructor === Original].join(' ')",
        "1 true",
    );
}
