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
