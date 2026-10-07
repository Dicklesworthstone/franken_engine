//! bd-9vouw.137: Promise can be subclassed.
//!
//! `new (class extends Promise {})(executor)` threw "expected object result
//! from constructible builtin target", and then/catch/finally and the
//! statics ignored the constructor. PROGRAM covers:
//! - a subclass instance (instanceof, getPrototypeOf, a subclass method,
//!   String());
//! - then/catch/finally returning the subclass through SpeciesConstructor
//!   and NewPromiseCapability;
//! - a constructor that wraps the executor;
//! - a species override back to Promise;
//! - resolve, reject, all, race, allSettled and any on the subclass, with
//!   PromiseResolve's same-constructor shortcut;
//! - the TypeErrors for a constructor that never calls the executor or
//!   that is not an object, and for a species that is not a constructor;
//! - the settled values, awaited.
//!
//! POISONED checks that a throwing `constructor` getter propagates from
//! then (Test262 Promise/prototype/then/ctor-poisoned). Both outputs are
//! Node v22.2.0's.
//!
//! No-claim: the combinators settle the subclass promise one job after
//! %Promise%'s result (they do not call `C.resolve` per element); class
//! fields on a Promise subclass are not covered.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

const PROGRAM: &str = r#"const log = [];
class MyPromise extends Promise { tag() { return 'mine'; } }
class Wrapped extends Promise {
  constructor(executor) { super((resolve, reject) => { log.push('wrapped-executor'); executor(resolve, reject); }); this.extra = 'x'; }
}
class Plain extends Promise { static get [Symbol.species]() { return Promise; } }
function ZeroArg() {}
const p = new MyPromise((resolve) => resolve(1));
console.log(p instanceof MyPromise, p instanceof Promise, Object.getPrototypeOf(p) === MyPromise.prototype, p.tag(), String(p));
const t = p.then((v) => v + 1);
console.log(t instanceof MyPromise, p.catch(() => 0) instanceof MyPromise, p.finally(() => 0) instanceof MyPromise);
const w = new Wrapped((resolve) => resolve(5));
console.log(w instanceof Wrapped, w.extra, w.then((v) => v) instanceof Wrapped, log.join());
console.log(new Plain((r) => r(1)).then((v) => v) instanceof Plain, MyPromise.resolve(2) instanceof MyPromise, MyPromise.reject(3).catch(() => 0) instanceof MyPromise, MyPromise.resolve(p) === p, MyPromise.resolve(Promise.resolve(1)) instanceof MyPromise);
console.log(MyPromise.all([1, 2]) instanceof MyPromise, MyPromise.race([1]) instanceof MyPromise, MyPromise.allSettled([1]) instanceof MyPromise, MyPromise.any([1]) instanceof MyPromise, Promise[Symbol.species] === Promise, MyPromise[Symbol.species] === MyPromise);
for (const [label, run] of [
  ['all on non-capability ctor', () => Promise.all.call(ZeroArg, [])],
  ['resolve on non-capability ctor', () => Promise.resolve.call(ZeroArg, 1)],
  ['then with constructor 1', () => { const q = Promise.resolve(1); q.constructor = 1; q.then(() => 0); }],
  ['then with species non-ctor', () => { const q = Promise.resolve(1); q.constructor = { [Symbol.species]: 1 }; q.then(() => 0); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}
(async () => {
  const results = [];
  results.push(await t);
  results.push(await MyPromise.reject(new Error('no')).catch((e) => e.message));
  results.push(await p.finally(() => 'ignored'));
  results.push(JSON.stringify(await MyPromise.all([1, Promise.resolve(2), MyPromise.resolve(3)])));
  results.push(await MyPromise.race([MyPromise.resolve('first'), new MyPromise(() => {})]));
  results.push(JSON.stringify((await MyPromise.allSettled([MyPromise.reject(1), 2])).map((r) => r.status)));
  results.push(await MyPromise.any([MyPromise.reject(1), MyPromise.resolve('any')]));
  results.push(await w.then((v) => v * 2));
  results.push(await new MyPromise((resolve) => resolve(MyPromise.resolve('adopted'))));
  console.log(results.join(' | '));
})();"#;

const NODE_OUTPUT: &str = r#"true true true mine [object Promise]
true true true
true x true wrapped-executor,wrapped-executor
false true true true true
true true true true true true
all on non-capability ctor TypeError
resolve on non-capability ctor TypeError
then with constructor 1 TypeError
then with species non-ctor TypeError
2 | no | 1 | [1,2,3] | first | ["rejected","fulfilled"] | any | 10 | adopted"#;

const POISONED: &str = r#"var p = Promise.resolve("foo");
Object.defineProperty(p, "constructor", { get: function () { throw new RangeError("poison"); } });
try { p.then(function () {}, function () {}); console.log("no throw"); } catch (e) { console.log(e.constructor.name, e.message); }"#;

fn console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(source).expect("the program runs");
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn promise_subclasses_behave_like_node() {
    let output = console(PROGRAM);
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

#[test]
fn then_propagates_a_throwing_constructor_getter() {
    assert_eq!(console(POISONED), "RangeError poison");
}

/// bd-9vouw.282: NewPromiseCapability accepts any constructor (a
/// NotPromise that calls the executor itself and returns an object); the
/// GetCapabilitiesExecutor (length 2, name "", no constructor) rejects a
/// second call once resolve or reject is set and non-callable functions;
/// a non-object this is a TypeError for every static; Promise.all,
/// allSettled and any call C.resolve and each element's then, with
/// once-only element functions (length 1, name "", no constructor);
/// withResolvers and then honor a custom capability. Asynchronous results
/// are printed sorted after a 20-step chain. Expected lines: Node v22.2.0's
/// output, captured programmatically (Bun 1.4.2 agrees).
#[test]
fn promise_capabilities_of_any_constructor_bd_9vouw_282() {
    let source = r#"var out = {};
function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var executorFn;
function NotPromise(executor) { executorFn = executor; executor(function (v) { out.np_resolved = String(v); }, function (r) { out.np_rejected = String(r); }); }
var r1 = Promise.resolve.call(NotPromise, 5);
console.log(r1 instanceof NotPromise, typeof executorFn, executorFn.length, JSON.stringify(executorFn.name), Object.isExtensible(executorFn), executorFn.hasOwnProperty('prototype'), k(function () { return new executorFn(function () {}, function () {}); }));
console.log(k(function () { return Promise.resolve.call(function (ex) { ex(undefined, undefined); ex(function () {}, function () {}); }, 1) instanceof Object; }), k(function () { Promise.resolve.call(function (ex) { ex(function () {}, undefined); ex(function () {}, function () {}); }, 1); }), k(function () { Promise.reject.call(function (ex) { ex(1, 2); }, 1); }));
console.log(['all', 'allSettled', 'any', 'race', 'reject', 'resolve', 'withResolvers'].map(function (n) { return k(function () { return Promise[n].call(undefined, []); }); }).join());
var elements = [];
function C(executor) { executor(function (v) { out.all_values = JSON.stringify(v); }, function (r) { out.all_rejected = String(r); }); }
C.resolve = function (v) { return { then: function (f, r) { elements.push(f); } }; };
Promise.all.call(C, [1, 2]);
console.log(elements.length, elements[0].length, JSON.stringify(elements[0].name), elements[0] !== elements[1], k(function () { return new elements[0](); }), elements[0].hasOwnProperty('prototype'));
elements[1]('b'); elements[0]('a'); elements[0]('again');
var resolveCalls = 0;
var orig = Promise.resolve;
Promise.resolve = function (v) { resolveCalls++; return orig.call(this, v); };
Promise.all([1, 2, 3]).then(function (v) { out.patched = v.join() + ':' + resolveCalls; });
Promise.resolve = orig;
var settled = [];
function S(executor) { executor(function (v) { out.settled = JSON.stringify(v); }, function () {}); }
S.resolve = function (v) { return { then: function (f, r) { settled.push([f, r]); } }; };
Promise.allSettled.call(S, [1, 2]);
settled[0][0]('x'); settled[1][1]('y'); settled[0][1]('ignored');
var anyRejects = [];
function A(executor) { executor(function () {}, function (e) { out.any = e.constructor.name + ':' + JSON.stringify(e.errors); }); }
A.resolve = function (v) { return { then: function (f, r) { anyRejects.push(r); } }; };
Promise.any.call(A, [1, 2]);
anyRejects[1]('e2'); anyRejects[0]('e1');
var wr = Promise.withResolvers.call(NotPromise);
console.log(wr.promise instanceof NotPromise, typeof wr.resolve, typeof wr.reject);
function Spec(executor) { executor(function (v) { out.species = 'resolved:' + v; }, function (r) { out.species = 'rejected:' + r; }); }
var p = Promise.resolve(41);
p.constructor = { [Symbol.species]: Spec };
var t = p.then(function (v) { return v + 1; });
console.log(t instanceof Spec);
var last = Promise.resolve();
for (var i = 0; i < 20; i++) last = last.then(function () {});
last.then(function () { console.log(Object.keys(out).sort().map(function (key) { return key + '=' + out[key]; }).join(' ')); });
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
            "true function 2 \"\" true false TypeError",
            "true TypeError TypeError",
            "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError",
            "2 1 \"\" true TypeError false",
            "true function function",
            "true",
            "all_values=[\"a\",\"b\"] any=AggregateError:[\"e1\",\"e2\"] np_resolved=5 patched=1,2,3:3 settled=[{\"status\":\"fulfilled\",\"value\":\"x\"},{\"status\":\"rejected\",\"reason\":\"y\"}] species=resolved:42",
        ]
    );
}
