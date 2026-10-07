//! bd-9vouw.352: Await performs PromiseResolve(%Promise%, value) (ES2020
//! 6.2.3.1 step 2, 25.6.4.5.1), so awaiting a native promise reads its
//! `constructor` through [[Get]]. The engine awaited a native promise
//! as is: a redefined Promise.prototype.constructor getter never ran, an own
//! `constructor` getter that throws was not the await's throw, and a Promise
//! subclass instance was not adopted through its `then`. An async
//! generator's await turns an abrupt read into a rejected promise, so its
//! body sees the throw one job late: its test compares outcomes, not ticks.
//! The lines are Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

fn console_lines(source: &str) -> Vec<String> {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

#[test]
fn an_async_function_await_reads_the_promise_constructor() {
    let lines = console_lines(
        r#"
var log = [];
var p = Promise.resolve(0);
for (var i = 1; i <= 6; i++) { (function (n) { p = p.then(function () { log.push('t' + n); }); })(i); }
var broken = Promise.resolve(42);
Object.defineProperty(broken, 'constructor', { get: function () { throw new Error('broken'); } });
(async function () { try { await broken; log.push('a-no'); } catch (e) { log.push('a-' + e.message); } })();
(async function () { await broken; })().catch(function (e) { log.push('e-' + e.message); });
class Sub extends Promise { then(f, r) { log.push('sub-then'); return super.then(f, r); } }
var sub = Sub.resolve(7);
(async function () { var v = await sub; log.push('b' + v); })();
var own = Promise.resolve(3);
Object.defineProperty(own, 'constructor', { get: function () { log.push('c-get'); return Promise; } });
(async function () { var v = await own; log.push('c' + v); })();
setTimeout(function () { console.log(log.join(' ')); }, 0);
"#,
    );
    assert_eq!(
        lines,
        ["a-broken c-get t1 e-broken sub-then c3 t2 t3 b7 t4 t5 t6"]
    );
}

#[test]
fn a_redefined_promise_prototype_constructor_is_read_per_await() {
    let lines = console_lines(
        r#"
var log = [];
async function f() { var p = Promise.resolve(1); log.push('pre'); var v = await p; log.push('v' + v); await 2; log.push('post'); }
Promise.resolve(0).then(function () { log.push('tick1'); }).then(function () { log.push('tick2'); }).then(function () { log.push('tick3'); });
Object.defineProperty(Promise.prototype, 'constructor', { get: function () { log.push('constructor'); return Promise; }, configurable: true });
f();
setTimeout(function () { console.log(log.join(' ')); }, 0);
"#,
    );
    assert_eq!(lines, ["pre constructor tick1 v1 tick2 post tick3"]);
}

#[test]
fn async_generator_awaits_and_return_read_the_promise_constructor() {
    let lines = console_lines(
        r#"
var out = {};
var subThen = 0;
var broken = Promise.resolve(42);
Object.defineProperty(broken, 'constructor', { get: function () { throw new Error('broken'); } });
class Sub extends Promise { then(f, r) { subThen++; return super.then(f, r); } }
async function* g1() { try { await broken; out.g1 = 'no'; } catch (e) { out.g1 = e.message; } }
g1().next();
var ran2 = false;
async function* g2() { ran2 = true; }
g2().return(broken).then(function () { out.g2 = 'fulfilled'; }, function (e) { out.g2 = e.message + (ran2 ? '-ran' : ''); });
async function* g3() { try { yield 1; return 'never'; } catch (e) { out.g3c = e.message; return 9; } }
var it3 = g3();
it3.next().then(function () { return it3.return(broken); }).then(function (r) { out.g3 = r.value + '/' + r.done; });
async function* g4() { out.g4 = await Sub.resolve(7); }
g4().next();
async function* g5() { yield broken; }
g5().next().then(function () { out.g5 = 'fulfilled'; }, function (e) { out.g5 = e.message; });
setTimeout(function () { console.log(['g1=' + out.g1, 'g2=' + out.g2, 'g3c=' + out.g3c, 'g3=' + out.g3, 'g4=' + out.g4, 'g5=' + out.g5, 'subThen=' + subThen].join(' ')); }, 0);
"#,
    );
    assert_eq!(
        lines,
        ["g1=broken g2=broken g3c=broken g3=9/true g4=7 g5=broken subThen=1"]
    );
}
