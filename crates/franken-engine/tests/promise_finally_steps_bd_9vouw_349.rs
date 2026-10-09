//! bd-9vouw.349: Promise.prototype.finally takes SpeciesConstructor(this,
//! %Promise%) when called, and Then Finally / Catch Finally resolve
//! onFinally's result with PromiseResolve(C, result) and return
//! Invoke(that promise, "then", <value thunk or thrower>) (ES2020 25.6.5.3,
//! 25.6.5.3.1-2). The engine chained a promise result internally (past its
//! own `then`) and passed any other result through at once, so a subclass
//! saw fewer constructions, a returned promise's own `then` never ran, and
//! finally's settlement jobs came earlier than Node's. The line below logs
//! the job order of fulfilled, rejected and throwing finally calls against
//! a five-step `then` chain, a subclass's construction count and the own
//! `then` of a returned promise. Node v22.2.0 gives it (Bun 1.4.2 orders
//! finally's jobs earlier; Test262 follows the specification, as Node does).

use frankenengine_engine::HybridRouter;

#[test]
fn finally_runs_the_specified_observable_steps() {
    let source = r#"
var log = [];
Promise.resolve(1).finally(function () { log.push('f1'); }).then(function (v) { log.push('v' + v); });
Promise.resolve().then(function () { log.push('t1'); }).then(function () { log.push('t2'); }).then(function () { log.push('t3'); }).then(function () { log.push('t4'); }).then(function () { log.push('t5'); });
Promise.reject(2).finally(function () { log.push('f2'); }).catch(function (e) { log.push('e' + e); });
Promise.resolve(4).finally(function () { throw 'x'; }).catch(function (e) { log.push('c' + e); });
var count = 0;
class Foo extends Promise { constructor(r, j) { count++; return super(r, j); } }
new Foo(function (r) { r(); }).finally(function () {}).then(function () { log.push('count' + count); });
var no = Promise.reject('n');
var thenCalls = 0;
no.then = function () { thenCalls++; return Promise.prototype.then.apply(this, arguments); };
Promise.resolve(5).finally(function () { return no; }).catch(function (e) { log.push('r' + e + thenCalls); });
setTimeout(function () { console.log(log.join(' ')); }, 0);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["f1 t1 f2 t2 cx t3 v1 t4 e2 count6 rn1 t5"]);
}

/// Resolving with a native promise adopts it directly only when the
/// PromiseResolveThenableJob's `then` call is unobservable. A Promise
/// subclass instance's `then` constructs the subclass (SpeciesConstructor),
/// for `resolve(sub)`, an async function returning `sub` and a `then`
/// callback returning it alike: three constructions before `b` logs. A
/// promise with an own property keeps the same job order. The adoption
/// skipped those constructions (0). Node v22.2.0's line (Bun 1.4.2 agrees).
#[test]
fn subclass_promise_resolution_runs_the_then_job() {
    let source = r#"
var log = [];
var made = 0;
class Sub extends Promise { constructor(executor) { made++; super(executor); } }
var tagged = Promise.resolve('p');
tagged.tag = 'own';
var sub = Sub.resolve('s');
var subMade = made;
new Promise(function (resolve) { resolve(tagged); }).then(function (v) { log.push('a' + v); });
new Promise(function (resolve) { resolve(sub); }).then(function (v) { log.push('b' + v + (made - subMade)); });
Promise.resolve().then(function () { log.push('t1'); }).then(function () { log.push('t2'); }).then(function () { log.push('t3'); }).then(function () { log.push('t4'); });
(async function () { return sub; })().then(function (v) { log.push('c' + v + (made - subMade)); });
Promise.resolve(1).then(function () { return sub; }).then(function (v) { log.push('d' + v + (made - subMade)); });
setTimeout(function () { console.log(log.join(' ')); }, 0);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["t1 t2 ap bs3 t3 cs3 t4 ds3",]);
}
