//! Live sparse mutation through the production runtime, with ordinary budgets.
#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use std::collections::BTreeMap;

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        RuntimeConfig::default(),
    )
    .expect("ordinary execution budgets");
    let package = ExtensionPackage {
        extension_id: "sparse-array-mutations".into(),
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

// Also executed unchanged by the Node reference check. Deliberately use a
// bounded shared span: the maximum-length tests below are native-only.
const SHIFT_SOURCE: &str = r#"
var N = 131072;
var a = []; a.length = N; a[0] = 'first'; a[17] = 'middle'; a[N - 1] = 'last';
a['01'] = 'named'; a['4294967295'] = 'outside';
console.log(a.shift(), a.length, a[16], a[N - 2], 17 in a, 0 in a, a['01'], a['4294967295']);
var b = []; b.length = N; b[0] = 'first'; b[N - 1] = 'last';
console.log(b.unshift('x', 'y'), b[0], b[1], b[2], b[N + 1], 3 in b);
var o = {length: N, 7: 'stale', 100000: 'move'};
console.log(Array.prototype.shift.call(o), o.length, 7 in o, o[6], o[99999], 100000 in o);
var events = [];
var g = []; g.length = N;
Object.defineProperty(g, '0', {configurable: true, get: function () {
    events.push('first'); g[90000] = 'late'; return 'head';
}});
console.log(g.shift(), g[89999], 90000 in g, events.join(','));
var p = Object.create(Array.prototype);
Object.defineProperty(p, '40000', {configurable: true, get: function () {
    events.push('inherited'); this[100000] = 'created'; return 'prototype';
}});
var h = []; h.length = N; Object.setPrototypeOf(h, p); events = [];
console.log(h.shift(), h[39999], h[99999], Object.hasOwn(h, '40000'), events.join(','));
var c = []; c.length = N;
var proto = Object.create(Array.prototype);
Object.defineProperty(proto, '90001', {set: function (v) {
    events.push(v); this[40000] = 'backfilled';
}, configurable: true});
Object.setPrototypeOf(c, proto); c[90000] = 'setter'; events = [];
console.log(c.unshift('new'), c[40001], 40000 in c, events.join(','));
var q = []; q.length = N; q[100000] = 'later';
Object.defineProperty(q, '10', {value: 'locked', writable: true, configurable: false});
try { q.shift(); } catch (e) { console.log(e.name, q.length, q[9], q[10], q[100000]); }
var z = {length: N}; Object.defineProperty(z, 'length', {writable: false});
try { Array.prototype.unshift.call(z); } catch (e) { console.log(e.name, z.length); }
var t = []; var target = {0: 'a', 2: 'c', length: 4};
var proxy = new Proxy(target, {
    get: function (o, k, r) { t.push('g' + k); return Reflect.get(o, k, r); },
    has: function (o, k) { t.push('h' + k); return Reflect.has(o, k); },
    set: function (o, k, v) { t.push('s' + k); o[k] = v; return true; },
    deleteProperty: function (o, k) { t.push('d' + k); return Reflect.deleteProperty(o, k); }
});
console.log(Array.prototype.shift.call(proxy), t.join(','), JSON.stringify(target));
t = []; target = {0: 'a', 2: 'c', length: 4};
console.log(Array.prototype.unshift.call(new Proxy(target, {
    get: function (o, k, r) { t.push('g' + k); return Reflect.get(o, k, r); },
    has: function (o, k) { t.push('h' + k); return Reflect.has(o, k); },
    set: function (o, k, v) { t.push('s' + k); o[k] = v; return true; },
    deleteProperty: function (o, k) { t.push('d' + k); return Reflect.deleteProperty(o, k); }
}), 'x'), t.join(','), JSON.stringify(target));
"#;

#[test]
fn sparse_shift_unshift_preserve_live_reads_writes_and_abrupt_prefixes() {
    let expected = [
        "first 131071 middle last false false named outside",
        "131074 x y first last false",
        "undefined 131071 false stale move false",
        "head late false first",
        "undefined prototype created false inherited",
        "131073 backfilled false setter",
        "TypeError 131072 locked locked later",
        "TypeError 131072",
        "a glength,g0,h1,d0,h2,g2,s1,h3,d2,d3,slength {\"1\":\"c\",\"length\":3}",
        "5 glength,h3,d4,h2,g2,s3,h1,d2,h0,g0,s1,s0,slength {\"0\":\"x\",\"1\":\"a\",\"3\":\"c\",\"length\":5}",
    ];
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(SHIFT_SOURCE, lane).expect("native sparse mutations"), expected);
    }
}

#[test]
fn maximum_array_length_shifts_do_not_scan_logical_holes() {
    // Specification-derived limits, not claimed to be a Node timing result.
    let source = r#"
var a = []; a.length = 4294967295; var payload = {tag: 7};
a[0] = 'head'; a[5] = payload; a[4294967294] = 'tail'; a['4294967295'] = 'named';
console.log(a.shift(), a.length, a[4] === payload, a[4294967293], 5 in a, a['4294967295']);
var b = []; b.length = 4294967293; b[7] = payload; b[4294967292] = 'tail';
console.log(b.unshift('x', 'y'), b[0], b[1], b[9] === payload, b[4294967294], 7 in b);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("bounded indexed moves"), [
            "head 4294967294 true tail false named",
            "4294967295 x y true tail false",
        ]);
    }
}

#[test]
fn observable_shift_holes_still_exhaust_the_default_work_budget() {
    for method in ["shift", "unshift"] {
        let source = format!(
            "var a = []; a.length = 4294967294; \
             var p = new Proxy(a, {{has: function () {{ return false; }}}}); \
             try {{ Array.prototype.{method}.call(p, 'x'); }} \
             catch (e) {{ console.log('caught'); }} console.log('unreachable');"
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("observable holes cannot be skipped");
            assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
        }
    }
}
