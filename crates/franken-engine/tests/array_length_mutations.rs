//! Sparse length-changing methods through the production execution path.
//! Reference fixture outputs are not evidence that these native tests passed.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig { force_lane: Some(lane), ..OrchestratorConfig::default() },
        RuntimeConfig::default(),
    ).expect("ordinary runtime budgets");
    let package = ExtensionPackage {
        extension_id: "sparse-length-mutations".into(),
        source: source.into(), source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    let outcome = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(outcome.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn length_mutators_preserve_live_callbacks_and_partial_failures() {
    let source = include_str!("fixtures/array_storage/length_mutations.js");
    let expected: Vec<_> = include_str!("fixtures/array_storage/length_mutations.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("native length mutation"), expected);
    }
}

#[test]
fn maximum_length_sparse_arrays_and_wide_array_likes_do_not_scan_every_hole() {
    // These extreme spans are native-only; reference execution uses the
    // smaller fixed fixture rather than asking Node to scan 2^53 indices.
    let source = r#"
const x = {}, a = []; a.length = 4294967295; a[0] = x; a[4294967294] = x;
console.log(a.shift() === x, a.length, a[4294967293] === x, 4294967294 in a);
const b = []; b.length = 4294967293; b[5] = x; b[4000000000] = 3;
console.log(b.unshift(1, 2), b[7] === x, b[4000000002], Object.keys(b).join(','));
const o = {length: 9007199254740991, 0: 1, '9007199254740990': 2};
console.log(Array.prototype.shift.call(o), o.length, o['9007199254740989'],
  Object.hasOwn(o, '9007199254740990'));
const empty = []; empty.length = 4294967295;
console.log(empty.shift() === undefined, empty.length, empty.unshift());
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("bounded sparse movement"), [
            "true 4294967294 true false",
            "4294967295 true 3 0,1,7,4000000002",
            "1 9007199254740990 2 false",
            "true 4294967294 4294967294",
        ]);
    }
}

#[test]
fn observable_proxy_holes_still_exhaust_the_ordinary_work_budget() {
    for method in ["shift", "unshift"] {
        let source = format!(r#"
const a = []; a.length = 4294967294;
const p = new Proxy(a, {{has() {{ return false; }}}});
try {{ Array.prototype.{method}.call(p, 1); }} catch (e) {{ console.log('caught'); }}
console.log('unreachable');
"#);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("observable traps must remain metered");
            assert!(error.to_ascii_lowercase().contains("budget"), "{method}: {error}");
        }
    }
}

#[test]
fn splice_handles_huge_removed_ranges_and_both_tail_directions() {
    let source = r#"
const x = {}, a = []; a.length = 4294967295; a[5] = x; a[3000000000] = 9;
const r = a.splice(4, 2000000000, 7);
console.log(r.length, Object.keys(r).join(','), r[1] === x, a.length, a[4],
    a[1000000001], 3000000000 in a);
const b = []; b.length = 4294967293; b[5] = x; b[3000000000] = 9;
const q = b.splice(4, 0, 7, 8);
console.log(q.length, b.length, b[4], b[5], b[7] === x, b[3000000002]);
const empty = []; empty.length = 4294967295;
const holes = empty.splice(0, 4294967295);
console.log(empty.length, holes.length, Object.keys(holes).length);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("all sparse splice phases"), [
            "2000000000 1 true 2294967296 7 9 false",
            "0 4294967295 7 8 true 9",
            "0 4294967295 0",
        ]);
    }
}

#[test]
fn splice_cannot_skip_observable_proxy_deletions_or_catch_work_refusal() {
    let source = r#"
const target = []; target.length = 4294967295;
let deleted = 0;
const proxy = new Proxy(target, {deleteProperty(t, k) { deleted++; return true; }});
// One removed hole, shrinking by one, is enough to force observable
// movement. An always-empty source still invokes every destination delete.
try { Array.prototype.splice.call(proxy, 0, 1); } catch (e) { console.log('caught'); }
console.log('unreachable', deleted);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(source, lane).expect_err("proxy mutation is observable work");
        assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
    }
}
