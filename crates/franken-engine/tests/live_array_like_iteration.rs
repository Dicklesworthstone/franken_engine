//! Actual interpreter regressions; Node is only the shared fixture oracle.
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
        extension_id: "live-array-like-iteration".into(),
        source: source.into(), source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn callbacks_and_getters_observe_new_unvisited_indices_on_both_profiles() {
    let source = include_str!("fixtures/array_iteration/live_indices.js");
    let expected: Vec<_> = include_str!("fixtures/array_iteration/live_indices.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("live generic iteration"), expected);
    }
}

#[test]
fn maximum_safe_length_with_few_properties_does_not_require_a_length_sized_scan() {
    // Spec-derived extreme case, not run on Node: the generic reference host
    // may scan every absent index. Length is captured once; insertion below
    // that length is visited, insertion at the length is not.
    let source = r#"
const o = Object.create(null); o.length = 9007199254740991;
o[0] = 1; o[9007199254740990] = 3;
let seen = '';
Array.prototype.forEach.call(o, (value, index) => {
  seen += index + ':' + value + ';';
  if (index === 0) { o[4294967295] = 2; o[9007199254740991] = 9; }
});
console.log(seen);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("bounded live successor lookup"),
            ["0:1;4294967295:2;9007199254740990:3;"]);
    }
}

#[test]
fn observable_proxy_holes_and_find_family_steps_cannot_evade_resource_limits() {
    for expression in [
        "Array.prototype.forEach.call(new Proxy({length: 4294967295}, {has() { return false; }}), () => {})",
        "Array.prototype.reduce.call(new Proxy({length: 4294967295}, {has() { return false; }}), (a, b) => a + b, 0)",
        "Array.prototype.indexOf.call(new Proxy({length: 4294967295}, {has() { return false; }}), 1)",
        "Array.prototype.find.call({length: 4294967295}, () => false)",
    ] {
        let source = format!("try {{ {expression}; }} catch (e) {{ console.log('caught'); }} console.log('unreachable');");
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("host resource refusal is not catchable JS");
            assert!(error.to_ascii_lowercase().contains("budget"), "{expression}: {error}");
        }
    }
}
