#![forbid(unsafe_code)]

//! ES2024 `Array.fromAsync` (bd-9vouw.172): a promise of the array of the
//! awaited values of an async iterable, a sync iterable or an array-like,
//! with an optional mapper whose results are awaited too.
//!
//! The expected lines are Node v22.2.0's output for the same programs (Bun
//! 1.4.2 prints the same lines), except `closing_when_return_fails`, where
//! V8 12.4 departs from the spec and the lines are Bun's. Each program runs
//! on both interpreter profiles, as written and with a collection at every
//! (and every seventh) safe point, and the memory-accounting oracle must
//! hold after each run.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str, v8_profile: bool, stress_interval: Option<u64>) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "from_async.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "from_async.js"),
        &LoweringContext::new(
            "from-async-trace",
            "from-async-decision",
            "from-async-policy",
        ),
    )
    .expect("source lowers")
    .ir3;
    let mut config = if v8_profile {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "from-async");
    core.set_gc_stress_interval(stress_interval);
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift (v8 profile {v8_profile}, stress {stress_interval:?})"
    );
    result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

fn assert_lines(source: &str, expected: &[&str]) {
    for v8_profile in [false, true] {
        for stress_interval in [None, Some(1), Some(7)] {
            assert_eq!(
                console_lines(source, v8_profile, stress_interval),
                expected,
                "v8 profile {v8_profile}, stress {stress_interval:?}"
            );
        }
    }
}

/// The static exists, reads as a value and returns a promise of an array.
#[test]
fn shape_and_value_reads() {
    assert_lines(
        "console.log(typeof Array.fromAsync, Array.fromAsync.length, Array.fromAsync.name);\nconst p = Array.fromAsync([]);\nconsole.log(p instanceof Promise, Object.prototype.toString.call(p));\np.then(a => console.log(Array.isArray(a), a.length));\nconst f = Array.fromAsync;\nf([7]).then(a => console.log('value call', a[0]));\n",
        &[
            "function 1 fromAsync",
            "true [object Promise]",
            "true 0",
            "value call 7",
        ],
    );
}

/// Sync iterables (their values awaited), async iterables, and array-likes.
#[test]
fn sources() {
    assert_lines(
        "(async () => {\n  console.log(JSON.stringify(await Array.fromAsync([1, Promise.resolve(2), 3])));\n  console.log(JSON.stringify(await Array.fromAsync('ab')));\n  console.log(JSON.stringify(await Array.fromAsync(new Set([4, 5]))));\n  console.log(JSON.stringify(await Array.fromAsync(new Map([[1, 'x']]))));\n  async function* gen() { yield 1; await null; yield Promise.resolve(2); yield 3; }\n  console.log(JSON.stringify(await Array.fromAsync(gen())));\n  function* syncGen() { yield 'a'; yield Promise.resolve('b'); }\n  console.log(JSON.stringify(await Array.fromAsync(syncGen())));\n  const custom = { [Symbol.asyncIterator]() { let i = 0; return { next() { i++; return Promise.resolve(i <= 3 ? { value: i * 10, done: false } : { value: 'ignored', done: true }); } }; } };\n  console.log(JSON.stringify(await Array.fromAsync(custom)));\n  const plain = { [Symbol.asyncIterator]() { let n = 0; return { next() { n++; return n < 3 ? { value: n, done: false } : { done: true }; } }; } };\n  console.log(JSON.stringify(await Array.fromAsync(plain)));\n  const arrayLike = await Array.fromAsync({ length: 3, 0: 'a', 1: Promise.resolve('b') });\n  console.log(JSON.stringify(arrayLike), arrayLike.length, 2 in arrayLike);\n  console.log(JSON.stringify(await Array.fromAsync(5)), JSON.stringify(await Array.fromAsync({})));\n})();\n",
        &[
            "[1,2,3]",
            "[\"a\",\"b\"]",
            "[4,5]",
            "[[1,\"x\"]]",
            "[1,2,3]",
            "[\"a\",\"b\"]",
            "[10,20,30]",
            "[1,2]",
            "[\"a\",\"b\",null] 3 true",
            "[] []",
        ],
    );
}

/// The mapper gets (value, index) and thisArg; its result is awaited.
#[test]
fn mapping() {
    assert_lines(
        "(async () => {\n  console.log(JSON.stringify(await Array.fromAsync([1, 2], function (x, i) { return x * this.m + i; }, { m: 10 })));\n  console.log(JSON.stringify(await Array.fromAsync([1, Promise.resolve(2)], async x => x * 2)));\n  async function* g() { yield 'a'; yield 'b'; }\n  console.log(JSON.stringify(await Array.fromAsync(g(), (x, i) => x + i)));\n  console.log(JSON.stringify(await Array.fromAsync({ length: 2, 0: 3, 1: Promise.resolve(4) }, x => Promise.resolve(x + 1))));\n})();\n",
        &["[10,21]", "[2,4]", "[\"a0\",\"b1\"]", "[4,5]"],
    );
}

/// Every abrupt completion rejects the promise; nothing throws synchronously.
#[test]
fn rejections() {
    assert_lines(
        "(async () => {\n  const show = e => e instanceof TypeError ? 'TypeError' : e instanceof Error ? e.constructor.name + ': ' + e.message : 'value ' + e;\n  try { await Array.fromAsync([Promise.reject(new Error('boom'))]); } catch (e) { console.log(1, show(e)); }\n  try { await Array.fromAsync([1], 5); } catch (e) { console.log(2, show(e)); }\n  try { await Array.fromAsync(null); } catch (e) { console.log(3, show(e)); }\n  try { await Array.fromAsync([1], x => { throw new RangeError('mapper'); }); } catch (e) { console.log(4, show(e)); }\n  try { await Array.fromAsync([1], async x => { throw new SyntaxError('async mapper'); }); } catch (e) { console.log(5, show(e)); }\n  try { await Array.fromAsync({ [Symbol.asyncIterator]() { return { next() { return 7; } }; } }); } catch (e) { console.log(6, show(e)); }\n  try { await Array.fromAsync({ length: 1, get 0() { throw new Error('getter'); } }); } catch (e) { console.log(7, show(e)); }\n  try { await Array.fromAsync({ [Symbol.asyncIterator]() { return 1; } }); } catch (e) { console.log(8, show(e)); }\n  let p;\n  try { p = Array.fromAsync(undefined); console.log(9, p instanceof Promise); } catch (e) { console.log(9, 'threw synchronously'); }\n  try { await p; } catch (e) { console.log(9, show(e)); }\n  try { await Array.fromAsync([1], () => { throw 42; }); } catch (e) { console.log(10, show(e)); }\n})();\n",
        &[
            "1 Error: boom",
            "2 TypeError",
            "3 TypeError",
            "4 RangeError: mapper",
            "5 SyntaxError: async mapper",
            "6 TypeError",
            "7 Error: getter",
            "8 TypeError",
            "9 true",
            "9 TypeError",
            "10 value 42",
        ],
    );
}

/// A mapper throw or rejection closes the iterator before the promise rejects,
/// and so does a rejected value of a sync iterator.
#[test]
fn closing() {
    assert_lines(
        "(async () => {\n  async function* gen() { try { yield 1; yield 2; } finally { console.log('cleanup'); } }\n  try { await Array.fromAsync(gen(), x => { throw new Error('stop at ' + x); }); } catch (e) { console.log('caught1', e.message); }\n  const it = { [Symbol.asyncIterator]() { return { next() { return Promise.resolve({ value: 1, done: false }); }, return() { console.log('return called'); return Promise.resolve({ done: true }); } }; } };\n  try { await Array.fromAsync(it, () => { throw new Error('m'); }); } catch (e) { console.log('caught2', e.message); }\n  try { await Array.fromAsync(it, async () => { throw new Error('async m'); }); } catch (e) { console.log('caught3', e.message); }\n  const syncIt = { [Symbol.iterator]() { return { next() { return { value: 1, done: false }; }, return() { console.log('sync return called'); return {}; } }; } };\n  try { await Array.fromAsync(syncIt, () => { throw new Error('s'); }); } catch (e) { console.log('caught4', e.message); }\n  const rejecting = { [Symbol.iterator]() { let i = 0; return { next() { i++; return i === 1 ? { value: Promise.reject(new Error('r')), done: false } : { value: i, done: i > 3 }; }, return() { console.log('rejected value closes'); return {}; } }; } };\n  try { await Array.fromAsync(rejecting); } catch (e) { console.log('caught5', e.message); }\n})();\n",
        &[
            "cleanup",
            "caught1 stop at 1",
            "return called",
            "caught2 m",
            "return called",
            "caught3 async m",
            "sync return called",
            "caught4 s",
            "rejected value closes",
            "caught5 r",
        ],
    );
}

/// ES2024 AsyncIteratorClose: a throwing or missing return() leaves the
/// mapper's error as the rejection, and a rejected next() is not followed by
/// return(). V8 12.4 (Node v22.2.0) departs from both: the first promise never
/// settles and return() runs after the rejected next(); these lines are Bun
/// 1.4.2's, which follow the spec.
#[test]
fn closing_when_return_fails() {
    assert_lines(
        "(async () => {\n  const throwingReturn = { [Symbol.asyncIterator]() { return { next() { return Promise.resolve({ value: 1, done: false }); }, return() { throw new Error('from return'); } }; } };\n  try { await Array.fromAsync(throwingReturn, () => { throw new Error('original'); }); } catch (e) { console.log('caught6', e.message); }\n  const noReturn = { [Symbol.asyncIterator]() { return { next() { return Promise.resolve({ value: 1, done: false }); } }; } };\n  try { await Array.fromAsync(noReturn, () => { throw new Error('no return'); }); } catch (e) { console.log('caught7', e.message); }\n  const failingNext = { [Symbol.asyncIterator]() { return { next() { return Promise.reject(new Error('next failed')); }, return() { console.log('must not run'); return {}; } }; } };\n  try { await Array.fromAsync(failingNext); } catch (e) { console.log('caught8', e.message); }\n})();\n",
        &[
            "caught6 original",
            "caught7 no return",
            "caught8 next failed",
        ],
    );
}

/// The spec's microtask ticks: two per sync-iterator step, one per awaited
/// element or mapped value.
#[test]
fn microtask_order() {
    assert_lines(
        "console.log('start');\nArray.fromAsync([1, 2]).then(a => console.log('sync iterable', JSON.stringify(a)));\nArray.fromAsync({ length: 2, 0: 'x', 1: 'y' }).then(a => console.log('array-like', JSON.stringify(a)));\nArray.fromAsync([3], x => x * 2).then(a => console.log('mapped', JSON.stringify(a)));\nPromise.resolve()\n  .then(() => console.log('tick 1')).then(() => console.log('tick 2')).then(() => console.log('tick 3'))\n  .then(() => console.log('tick 4')).then(() => console.log('tick 5')).then(() => console.log('tick 6'))\n  .then(() => console.log('tick 7')).then(() => console.log('tick 8')).then(() => console.log('tick 9'));\nconsole.log('end');\n",
        &[
            "start",
            "end",
            "tick 1",
            "tick 2",
            "array-like [\"x\",\"y\"]",
            "tick 3",
            "tick 4",
            "tick 5",
            "mapped [6]",
            "tick 6",
            "sync iterable [1,2]",
            "tick 7",
            "tick 8",
            "tick 9",
        ],
    );
}

/// A long async source keeps the call's state alive across collections.
#[test]
fn many_values() {
    assert_lines(
        "(async () => {\n  async function* many() { for (let i = 0; i < 400; i++) { const junk = { i, pad: [i, i + 1, i + 2] }; yield junk.i; } }\n  const out = await Array.fromAsync(many(), x => ({ v: x * 2 }).v);\n  console.log(out.length, out[0], out[399], out.reduce((a, b) => a + b, 0));\n  const fromSync = await Array.fromAsync(Array.from({ length: 300 }, (_, i) => Promise.resolve(i)));\n  console.log(fromSync.length, fromSync[299]);\n})();\n",
        &["400 0 798 159600", "300 299"],
    );
}
