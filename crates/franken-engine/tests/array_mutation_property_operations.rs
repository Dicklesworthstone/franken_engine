//! Real native execution, not the Node reference host. Run before closing
//! bd-9vouw.473 or claiming semantic/performance verification.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        RuntimeConfig::default(),
    )
    .expect("ordinary runtime budgets");
    let package = ExtensionPackage {
        extension_id: "array-mutation-properties".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator
        .execute(&package)
        .map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect())
}

#[test]
fn mutators_preserve_property_operations_and_partial_effects_on_both_native_profiles() {
    let source = include_str!("fixtures/array_mutation/property_operations.js");
    let expected: Vec<_> = include_str!("fixtures/array_mutation/property_operations.expected")
        .lines()
        .collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("native mutation semantics"),
            expected
        );
    }
}

#[test]
fn sparse_mutations_cannot_run_billions_of_unmetered_hole_steps() {
    // Ordinary absent spans can be skipped. A Proxy has trap makes each
    // hole observable, so these programs must exhaust the DEFAULT budget.
    // Do not run them under Node as reference cases: Node has no guest budget.
    for method in ["shift", "unshift", "reverse"] {
        let source = format!(
            "const a = []; a.length = 4294967294; \
             const p = new Proxy(a, {{has() {{return false;}}}}); \
             try {{ Array.prototype.{method}.call(p, 1); }} \
             catch (e) {{ console.log('caught'); }} console.log('unreachable');"
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("sparse work must remain budget-bounded");
            assert!(
                error.to_ascii_lowercase().contains("budget"),
                "{method}: {error}"
            );
        }
    }
}

#[test]
fn ordinary_sparse_holes_preserve_lengths_keys_and_return_identity() {
    // Same huge spans as the refusal probes, without observable traps.
    // No resource settings differ between these positive and negative cases.
    let source = r#"
const n = 4294967294;
const a = []; a.length = n;
console.log('shift', a.shift() === undefined, a.length, Object.keys(a).length);
const b = []; b.length = n;
console.log('unshift', b.unshift(1), b.length, b[0], Object.keys(b).join(','));
const c = []; c.length = n;
console.log('reverse', c.reverse() === c, c.length, Object.keys(c).length);
const d = []; d.length = n;
d.constructor = {[Symbol.species]: function() {return {};}};
const removed = d.splice(0, n);
console.log('splice', d.length, removed.length, Object.keys(removed).join(','));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("bounded ordinary sparse mutations"),
            [
                "shift true 4294967293 0",
                "unshift 4294967295 4294967295 1 0",
                "reverse true 4294967294 0",
                "splice 0 4294967294 length",
            ]
        );
    }
}

#[test]
fn ordinary_dense_mutations_keep_values_holes_and_noop_lengths() {
    let source = r#"
const a = [3, 1, 2];
a.push(4, 5); console.log(a.pop(), a.shift());
a.unshift(8, 9); a.reverse(); a.fill(7, 1, 3);
console.log(a.join(','), a.length);
const b = [];
console.log(b.push(), b.unshift(), b.pop(), b.shift());
const token = {};
const c = [token, -0, NaN]; c.reverse();
console.log(Number.isNaN(c[0]), Object.is(c[1], -0), c[2] === token);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("dense paths"),
            [
                "5 3",
                "4,7,7,9,8 5",
                "0 0 undefined undefined",
                "true true true"
            ]
        );
    }
}

#[test]
fn splice_species_and_sort_comparators_cannot_stale_the_property_write_path() {
    let source = include_str!("fixtures/array_mutation/reentrant_operations.js");
    let expected: Vec<_> = include_str!("fixtures/array_mutation/reentrant_operations.expected")
        .lines()
        .collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("reentrant array operations"),
            expected
        );
    }
}

#[test]
fn sparse_splice_copy_delete_and_sort_scans_keep_default_resource_limits() {
    // A custom result avoids reserving a dense removed-items array. Splice
    // and sort can skip proven ordinary holes, so use a Proxy whose has trap
    // makes EVERY hole observable. Keep
    // the exact budget and uncatchable-refusal assertions, not a timing limit.
    for operation in [
        "Array.prototype.splice.call(new Proxy(a, {has() {return false;}}), 0, 4294967294)",
        "Array.prototype.sort.call(new Proxy(a, {has() {return false;}}), (x, y) => x - y)",
    ] {
        let source = format!(
            "const a = []; a.length = 4294967294; \
             a.constructor = {{[Symbol.species]: function() {{return {{}};}}}}; \
             try {{ {operation}; }} catch (e) {{ console.log('caught'); }} \
             console.log('unreachable');"
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("resource refusal is not a guest exception");
            assert!(
                error.to_ascii_lowercase().contains("budget"),
                "{operation}: {error}"
            );
        }
    }
}

#[test]
fn proxy_data_receivers_observe_descriptor_checks_and_definitions() {
    let source = r#"
const target = {x: 1}; let events = '';
const p = new Proxy(target, {
  getOwnPropertyDescriptor(t, k) {
    events += 'get:' + k + ';'; return Reflect.getOwnPropertyDescriptor(t, k);
  },
  defineProperty(t, k, d) {
    events += 'define:' + k + ':' + Object.keys(d).sort().join(',') + ';';
    return Reflect.defineProperty(t, k, d);
  }
});
console.log(Reflect.set(p, 'x', 2), target.x, events); events = '';
console.log(Reflect.set(p, 'y', 3), target.y, events); events = '';
console.log(Reflect.set({x: 9}, 'x', 4, p), target.x, events);
const refused = {x: 1};
const q = new Proxy(refused, {defineProperty() {return false;}});
console.log(Reflect.set(q, 'x', 2), refused.x, Reflect.set(q, 'y', 3), 'y' in refused);
let setterCalls = 0, definitions = 0;
const accessor = {};
Object.defineProperty(accessor, 'x', {set(v) {setterCalls++;}, configurable: true});
const r = new Proxy(accessor, {defineProperty() {definitions++; return true;}});
console.log(Reflect.set({x: 1}, 'x', 2, r), setterCalls, definitions);
const locked = new Proxy({x: 1}, {
  getOwnPropertyDescriptor() {return {value: 1, writable: false, configurable: true};},
  defineProperty() {definitions++; return true;}
});
console.log(Reflect.set({x: 1}, 'x', 2, locked), definitions);
let observedReceiver = false;
const parent = {set x(v) {observedReceiver = this === s && v === 7;}};
const s = new Proxy(Object.create(parent), {
  getOwnPropertyDescriptor() {throw new Error('unexpected descriptor');},
  defineProperty() {throw new Error('unexpected definition');}
});
console.log(Reflect.set(s, 'x', 7), observedReceiver);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("Proxy receiver [[Set]]"),
            [
                "true 2 get:x;define:x:value;",
                "true 3 get:y;define:y:configurable,enumerable,value,writable;",
                "true 4 get:x;define:x:value;",
                "false 1 false false",
                "false 0 0",
                "false 0",
                "true true",
            ]
        );
    }
}

#[test]
fn proxy_receiver_reentrancy_preserves_callable_identity_and_refusals() {
    let source = r#"
const target = function() {return 17;}; let definitions = '';
const callable = new Proxy(target, {
  defineProperty(t, k, d) {definitions += k + ';'; return Reflect.defineProperty(t, k, d);}
});
console.log('callable', Reflect.set(callable, 'extra', 5), callable.extra, callable(), definitions);
const backing = {}; let events = '';
const inner = new Proxy(backing, {
  getOwnPropertyDescriptor(t, k) {events += 'ig;'; return Reflect.getOwnPropertyDescriptor(t, k);},
  defineProperty(t, k, d) {events += 'id;'; return Reflect.defineProperty(t, k, d);}
});
const outer = new Proxy(inner, {
  getOwnPropertyDescriptor(t, k) {events += 'og;'; return Reflect.getOwnPropertyDescriptor(t, k);},
  defineProperty(t, k, d) {events += 'od;'; return Reflect.defineProperty(t, k, d);}
});
console.log('nested', Reflect.set({x: 1}, 'x', 2, outer), backing.x, events);
const preserved = {x: 1};
const revoked = Proxy.revocable(preserved, {
  getOwnPropertyDescriptor(t, k) {revoked.revoke(); return Reflect.getOwnPropertyDescriptor(t, k);}
});
let error = 'none';
try {Reflect.set({x: 9}, 'x', 2, revoked.proxy);} catch (e) {error = e.name;}
console.log('revoked', error, preserved.x);
const plain = {x: 1};
const transparent = new Proxy(plain, {});
Object.defineProperty(Object.prototype, 'get', {
  get() {throw new Error('inherited descriptor field');}, configurable: true
});
try {console.log('own-fields', Reflect.set(transparent, 'x', 2), plain.x);}
finally {delete Object.prototype.get;}
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("Proxy receiver reentrancy"),
            [
                "callable true 5 17 extra;",
                "nested true 2 og;ig;ig;od;id;ig;",
                "revoked TypeError 1",
                "own-fields true 2",
            ]
        );
    }
}

#[test]
fn string_casing_preserves_exact_units_and_rejects_nullish_receivers() {
    // Qualify the production receiver helper after removing its unused UTF-8
    // predecessor. Keep lone surrogates and expanding Unicode mappings exact.
    let source = r#"
function units(text) {
  const values = [];
  for (let i = 0; i < text.length; i++) values.push(text.charCodeAt(i));
  return values.join(',');
}
const text = String.fromCharCode(0xd800, 0x00df, 0xdc00, 0x0130, 0xd801, 0xdc28, 0xd800);
console.log('lower', units(text.toLowerCase()));
console.log('upper', units(text.toUpperCase()));
for (const receiver of [null, undefined]) {
  for (const method of ['toLowerCase', 'toUpperCase']) {
    try { String.prototype[method].call(receiver); console.log('unexpected'); }
    catch (error) { console.log(method, receiver === null ? 'null' : 'undefined', error.name); }
  }
}
console.log('primitive', String.prototype.toLowerCase.call(false), String.prototype.toUpperCase.call(-42));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("native primitive string receivers"),
            [
                "lower 55296,223,56320,105,775,55297,56360,55296",
                "upper 55296,83,83,56320,304,55297,56320,55296",
                "toLowerCase null TypeError",
                "toUpperCase null TypeError",
                "toLowerCase undefined TypeError",
                "toUpperCase undefined TypeError",
                "primitive false -42",
            ]
        );
    }
}
