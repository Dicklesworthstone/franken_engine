//! `for await (x of iterable)` runs the async iteration protocol.
//!
//! The parser used to accept the header and lower the loop as a synchronous
//! for-of. An async generator's `next()` promise was then taken as the
//! iteration result, so the body never saw a value (JS probe corpus case 30
//! printed nothing). The loop now:
//! - uses `@@asyncIterator`, else the sync iterator with every value awaited;
//! - awaits `next()` on every step;
//! - awaits `return()` when the body exits early (break, throw).
//!
//! Expected console output is what Node v22.2.0 prints for the same program.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn console_of(source: &str) -> String {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn check(source: &str, node: &str) {
    assert_eq!(
        console_of(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn async_generators_and_async_iterables_are_awaited() {
    check(
        "(async () => { async function* g() { yield 1; yield 2; } let s = 0; \
         for await (const x of g()) s += x; console.log('sum', s); })();",
        "sum 3",
    );
    check(
        "const it = { [Symbol.asyncIterator]() { let i = 0; return { next() { i++; \
         return Promise.resolve({ value: i, done: i > 3 }); } }; } }; \
         (async () => { const seen = []; for await (const v of it) seen.push(v); \
         console.log(seen.join('|')); })();",
        "1|2|3",
    );
}

#[test]
fn sync_iterables_have_each_value_awaited() {
    check(
        "(async () => { const out = []; \
         for await (const v of [Promise.resolve(1), 2, Promise.resolve(3)]) out.push(v); \
         console.log(out.join()); })();",
        "1,2,3",
    );
}

#[test]
fn early_exits_close_the_iterator() {
    check(
        "(async () => { async function* g() { try { yield 1; yield 2; } \
         finally { console.log('closed'); } } \
         for await (const x of g()) { console.log('got', x); break; } \
         console.log('after'); })();",
        "got 1\nclosed\nafter",
    );
    check(
        "(async () => { async function* g() { try { yield 1; } finally { console.log('cleanup'); } } \
         try { for await (const x of g()) throw new Error('boom'); } \
         catch (e) { console.log('caught', e.message); } })();",
        "cleanup\ncaught boom",
    );
}

#[test]
fn targets_scoping_and_nesting() {
    // Destructuring declarations get a fresh binding per iteration.
    check(
        "(async () => { async function* g() { yield {a: 1, b: 2}; yield {a: 3, b: 4}; } \
         const fs = []; for await (const {a, b} of g()) fs.push(() => a + b); \
         console.log(fs.map(f => f()).join()); })();",
        "3,7",
    );
    check(
        "(async () => { async function* g(n) { for (let i = 0; i < n; i++) yield i; } \
         const out = []; for await (const a of g(2)) for await (const b of g(2)) \
         out.push('' + a + b); console.log(out.join()); })();",
        "00,01,10,11",
    );
    check(
        "(async () => { async function* g() { yield 'p'; yield 'q'; } let x; const got = []; \
         for await (x of g()) got.push(x); console.log(got.join() + ':' + x); })();",
        "p,q:q",
    );
}
