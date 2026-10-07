//! bd-9vouw.351: an async generator's completion settles its request at
//! once (ES2024 27.6.3.2 AsyncGeneratorStart); only `return expr` awaits,
//! in the return statement (ES2020 13.10.1), so a rejection still reaches
//! the body's catch. The engine awaited every return operand (bare and
//! implicit ones too) and then the finished result again: `return;` and an
//! empty body settled two jobs late, `return expr` one. The line logs those
//! completions, a yield, a returned promise, a caught returned rejection and
//! a `return()` through a finally against an eight-step then chain. Node
//! v22.2.0 gives it (Bun 1.4.2 does not await a returned promise here).

use frankenengine_engine::HybridRouter;

#[test]
fn async_generator_completions_settle_without_extra_jobs() {
    let source = r#"
var actual = [];
async function* g1() {}
async function* g2() { return; }
async function* g3() { return undefined; }
async function* g4() { yield 1; }
async function* g5() { return Promise.resolve('p'); }
async function* g6() { try { return Promise.reject('r'); } catch (e) { return 'caught-' + e; } }
async function* g7() { try { yield 1; } finally { actual.push('fin7'); } }
var p = Promise.resolve(0);
for (var i = 1; i <= 8; i++) { (function (n) { p = p.then(function () { actual.push('t' + n); }); })(i); }
g1().next().then(function (r) { actual.push('g1' + r.done); });
g2().next().then(function (r) { actual.push('g2' + r.done); });
g3().next().then(function (r) { actual.push('g3' + r.done); });
g4().next().then(function (r) { actual.push('g4' + r.value); });
g5().next().then(function (r) { actual.push('g5' + r.value); });
g6().next().then(function (r) { actual.push('g6' + r.value); });
var it = g7();
it.next().then(function () { it.return('x').then(function (r) { actual.push('g7' + r.value + r.done); }); });
setTimeout(function () { console.log(actual.join(' ')); }, 0);
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
        ["t1 g1true g2true t2 g3true g41 g5p t3 g6caught-r fin7 t4 g7xtrue t5 t6 t7 t8"]
    );
}
