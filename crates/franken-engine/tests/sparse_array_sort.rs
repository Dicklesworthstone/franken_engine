//! Execute sparse sorting on both native profiles with ordinary resource limits.
//! The shared fixture's Node output is an oracle, not execution of the candidate.
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
        extension_id: "sparse-array-sort".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn sort_allocates_for_captured_values_after_observable_reads() {
    let source = include_str!("fixtures/array_mutation/sparse_sort.js");
    let expected: Vec<_> = include_str!("fixtures/array_mutation/sparse_sort.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("demand-driven capture"), expected);
    }
}

#[test]
fn observing_every_proxy_hole_still_exhausts_the_default_work_budget() {
    // A proxy's HasProperty is observable even when always false. It must not
    // inherit any ordinary-array hole skipping, and resource refusal cannot
    // be caught as a JavaScript exception. Do not run this under Node.
    let source = r#"
const a = new Proxy({length: 4294967295}, {has() { return false; }});
try { Array.prototype.sort.call(a); } catch (error) { console.log('caught'); }
console.log('unreachable');
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(source, lane).expect_err("observable work remains bounded");
        assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
    }
}

#[test]
fn to_sorted_cannot_hide_materialized_holes_from_the_memory_budget() {
    // Unlike sort, toSorted must materialize a value for EVERY index. Demand
    // capture for skip-holes must not bypass its existing dense-result gate.
    let source = "const a = []; a.length = 4294967295; a.toSorted();";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(source, lane).expect_err("dense result remains bounded");
        assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
    }
}

#[test]
fn maximum_logical_length_needs_work_only_for_present_properties() {
    // Exact outputs follow sort's skip-holes and ascending-delete steps. This
    // maximum-length case is native-only: Node 22's empty-array scan exceeded
    // the reference timeout. The shared oracle uses the same shapes at 2^17.
    let source = r#"
const a = []; a.length = 4294967295;
console.log(a.sort((x, y) => x - y) === a, a.length, Object.keys(a).length);
a[7] = 3; a[50000] = 2; a[4294967294] = 1;
a.sort((x, y) => x - y);
console.log(a[0], a[1], a[2], a.length, 7 in a, 50000 in a, 4294967294 in a);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("bounded sparse work"), [
            "true 4294967295 0", "1 2 3 4294967295 false false false",
        ]);
    }
}
