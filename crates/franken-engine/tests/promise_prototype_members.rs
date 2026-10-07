//! A promise's properties come from %Promise.prototype%: members a program
//! adds to it (polyfills, extensions) are visible on every promise,
//! `constructor` is `Promise`, @@toStringTag is "Promise", and
//! Object.prototype members are inherited. A promise's properties used to be
//! a fixed table of `then`/`catch`/`finally`, so `q.myFn()` threw "expected
//! function, got undefined" and `p.constructor` was undefined. Expected
//! strings are Node v22.2.0's completion values for the same programs.
//!
//! A promise also holds own properties (`p.cancel = fn`,
//! `Object.defineProperty(p, ...)`, an own `constructor`), as do generator
//! objects; they live on a backing object.
//!
//! No-claim: `constructor` is `undefined` once a program replaces the global
//! `Promise`.
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

/// Promises and generator objects had no storage for own properties: `p.cancel
/// = fn` (cancelable-promise helpers, promises carrying a child process),
/// `Object.defineProperty(p, ...)` and `Object.assign(promise, ...)` threw
/// "expected object, got object".
#[test]
fn promises_and_generator_objects_hold_own_properties() {
    check(
        "var p = Promise.resolve(1); p.cancel = () => 'c'; \
         Object.defineProperty(p, 'tag', { value: 't', enumerable: false }); \
         var q = new Promise(() => {}); q.constructor = function Fake() {}; \
         var r = Object.assign(Promise.resolve(2), { a: 1 }); \
         function* g() { yield 1; } var it = g(); it.extra = 5; \
         [typeof p.cancel, p.cancel(), Object.keys(p).join(), 'cancel' in p, p.hasOwnProperty('cancel'), \
         p.tag, Object.getOwnPropertyDescriptor(p, 'tag').enumerable, q.constructor.name, \
         q.hasOwnProperty('constructor'), r.a, it.extra, Object.keys(it).join(), it.next().value, \
         typeof p.then].join(' ')",
        "function c cancel true true t false Fake true 1 5 extra 1 function",
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

/// The executor's resolve and reject functions are anonymous built-ins
/// (ES2020 25.6.1.3, `name` ""); they were named "resolve" and "reject"
/// like the static Promise.resolve/reject.
#[test]
fn resolving_functions_are_anonymous() {
    check(
        "let r, j; new Promise((a, b) => { r = a; j = b; }); \
         [JSON.stringify(r.name), r.length, JSON.stringify(j.name), j.length, Promise.resolve.name, \
         Promise.reject.name, typeof r, r.hasOwnProperty('name')].join(' ')",
        r#""" 1 "" 1 resolve reject function true"#,
    );
}

/// bd-9vouw.274: Promise.prototype.catch and finally are Invoke(this,
/// "then", ...) (ES2020 25.6.5.1, 25.6.5.3): a thenable `this`, a primitive
/// whose prototype has a `then`, and a promise whose `then` was replaced
/// all have that `then` called (with undefined and onRejected, or the
/// finally wrappers, or a non-callable onFinally twice); a throwing `then`
/// getter or `then` propagates, finally refuses a non-object `this`, and a
/// promise with the intrinsic `then` keeps its settlement order. Both
/// demanded a promise. Expected lines are Node v22.2.0's output, captured
/// programmatically (Bun 1.4.2 runs the file as a strict module, where the
/// boolean `this` stays unboxed).
#[test]
fn promise_catch_and_finally_invoke_then_bd_9vouw_274() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var calls = [];
var thenable = { then: function (a, b) { calls.push('then:' + typeof a + ',' + typeof b + ':' + (this === thenable)); return 'thenResult'; } };
console.log(Promise.prototype.catch.call(thenable, function () {}), Promise.prototype.finally.call(thenable, function () {}), Promise.prototype.finally.call(thenable, 5), calls.join(' '));
Boolean.prototype.then = function () { return 'bool-then:' + typeof this; };
console.log(Promise.prototype.catch.call(true, null), kind(function () { return Promise.prototype.catch.call(undefined); }), kind(function () { return Promise.prototype.finally.call(true); }));
delete Boolean.prototype.then;
console.log(kind(function () { return Promise.prototype.catch.call({ get then() { throw new RangeError('g'); } }); }), kind(function () { return Promise.prototype.finally.call({ then: 1 }); }), kind(function () { return Promise.prototype.catch.call({ then: function () { throw new EvalError('t'); } }); }));
var p = Promise.reject(new Error('boom'));
var replaced = 0;
var q = Promise.resolve(1);
q.then = function (a, b) { replaced++; return Promise.prototype.then.call(this, a, b); };
q.catch(function () {});
q.finally(function () {});
console.log('replaced', replaced);
p.catch(function (e) { console.log('caught ' + e.message); }).finally(function () { console.log('finally'); }).then(function (v) { console.log('after ' + v); });
Promise.resolve(7).finally(function () { return 99; }).then(function (v) { console.log('value ' + v); });
Promise.reject(8).finally(function () {}).catch(function (e) { console.log('reason ' + e); });
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "thenResult thenResult thenResult then:undefined,function:true then:function,function:true then:number,number:true",
            "bool-then:object TypeError TypeError",
            "RangeError TypeError EvalError",
            "replaced 2",
            "caught boom",
            "finally",
            "value 7",
            "reason 8",
            "after undefined",
        ]
    );
}
