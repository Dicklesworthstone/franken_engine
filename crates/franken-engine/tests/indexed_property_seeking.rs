//! Exercise ordered numeric-property seeking through the real native runtime.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

#[test]
fn sparse_callbacks_seek_numeric_storage_without_changing_observable_reads() {
    let source = include_str!("fixtures/array_storage/index_seek.js");
    let expected: Vec<_> = include_str!("fixtures/array_storage/index_seek.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig { force_lane: Some(lane), ..OrchestratorConfig::default() },
            RuntimeConfig::default(),
        ).expect("ordinary budgets");
        let package = ExtensionPackage {
            extension_id: "indexed-property-seeking".into(),
            source: source.into(), source_file: None, module_root: None,
            capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
                .into_iter().map(str::to_string).collect(),
            version: "1.0.0".into(), metadata: BTreeMap::new(),
        };
        let result = orchestrator.execute(&package).expect("bounded sparse callbacks");
        let actual: Vec<_> = result.console_output.into_iter().map(|entry| entry.message).collect();
        assert_eq!(actual, expected);
    }
}
