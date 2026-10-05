#![forbid(unsafe_code)]

//! The `Array.prototype.reduce` mini-lane reads and writes properties with
//! the GetProperty / SetProperty semantics (bd-9vouw.175).
//!
//! A reducer used to read own data only (a getter gave the accessor itself,
//! an inherited member or a Proxy trap gave undefined) and to store raw data
//! (no setter call, no read-only, getter-only or frozen check). Reads now take
//! the full [[Get]]; a reducer that writes a property runs on the ordinary
//! callback path.
//!
//! The expected lines are Node v22.2.0's output for the same program. It runs
//! on both interpreter profiles, as written and with a collection at every
//! (and every seventh) safe point, and the memory-accounting oracle must hold
//! after each run.
//!
//! No-claim: a reducer's arithmetic still runs in the mini-lane without
//! register labels (its result carries the reduce call's label).

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
                label: "reduce.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "reduce.js"),
        &LoweringContext::new("reduce-trace", "reduce-decision", "reduce-policy"),
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
    let mut core = InterpreterCore::new(config, "reduce");
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

/// A reducer's reads see getters, inherited members and Proxy traps; its
/// writes call setters and respect read-only, getter-only and frozen targets.
#[test]
fn reducer_property_reads_and_writes_have_get_and_set_semantics() {
    assert_lines(
        r#"const g = { get v() { return 7; } };
console.log([1].reduce((m) => m.v, g));
class Item { constructor(p) { this._p = p; } get price() { return this._p * 2; } }
console.log([new Item(1), new Item(2)].reduce((s, i) => s + i.price, 0));
const proto = { inherited: 3 };
const child = Object.create(proto);
console.log([1, 2].reduce((s, x) => s + child.inherited + x, 0));
const p = new Proxy({}, { get: (t, k) => 'trap:' + String(k) });
console.log([1].reduce((m) => m.z, p));
const acc = Object.freeze({ a: 1 });
console.log(JSON.stringify([1, 2].reduce((m, x) => { m[x] = x; return m; }, acc)));
const getterOnly = { get v() { return 1; } };
[1].reduce((m) => { m.v = 5; return m; }, getterOnly);
console.log(getterOnly.v, typeof Object.getOwnPropertyDescriptor(getterOnly, 'v').get);
const calls = [];
class S { set x(v) { calls.push(v); } }
const s = new S();
[1, 2].reduce((m, v) => { m.x = v; return m; }, s);
console.log(calls.join(), Object.keys(s).length);
const ro = {}; Object.defineProperty(ro, 'a', { value: 1 });
try { [1].reduce((m) => { 'use strict'; m.a = 5; return m; }, ro); console.log('no throw', ro.a); } catch (e) { console.log(e.name, ro.a); }
const groups = [{ k: 'x', v: 1 }, { k: 'y', v: 2 }, { k: 'x', v: 3 }].reduce((m, e) => { m[e.k] = (m[e.k] || 0) + e.v; return m; }, {});
console.log(JSON.stringify(groups));
console.log([1, 2, 3].reduce((a, b) => a + b), [1, 2, 3].reduceRight((a, b) => a + '' + b));
"#,
        &[
            "7",
            "6",
            "9",
            "trap:z",
            "{\"a\":1}",
            "1 function",
            "1,2 0",
            "TypeError 1",
            "{\"x\":4,\"y\":2}",
            "6 321",
        ],
    );
}
