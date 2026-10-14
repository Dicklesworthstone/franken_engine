//! Exercise the shared indexed carrier through both real native profiles.
//! Node establishes fixture expectations; it does not execute this candidate.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

#[test]
fn holey_storage_preserves_array_and_object_operations_on_both_profiles() {
    let source = include_str!("fixtures/array_storage/holey.js");
    let expected: Vec<_> = include_str!("fixtures/array_storage/holey.expected").lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig { force_lane: Some(lane), ..OrchestratorConfig::default() },
            RuntimeConfig::default(),
        ).expect("ordinary budgets");
        let package = ExtensionPackage {
            extension_id: "holey-indexed-storage".into(),
            source: source.into(), source_file: None, module_root: None,
            capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
                .into_iter().map(str::to_string).collect(),
            version: "1.0.0".into(), metadata: BTreeMap::new(),
        };
        let result = orchestrator.execute(&package).expect("native storage semantics");
        let actual: Vec<_> = result.console_output.into_iter().map(|entry| entry.message).collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn forward_gaps_preserve_descriptors_prototypes_and_remote_sparse_writes() {
    let source = include_str!("fixtures/array_storage/forward_gaps.js");
    let expected: Vec<_> = include_str!("fixtures/array_storage/forward_gaps.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig { force_lane: Some(lane), ..OrchestratorConfig::default() },
            RuntimeConfig::default(),
        ).expect("ordinary budgets");
        let package = ExtensionPackage {
            extension_id: "indexed-forward-gaps".into(),
            source: source.into(), source_file: None, module_root: None,
            capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
                .into_iter().map(str::to_string).collect(),
            version: "1.0.0".into(), metadata: BTreeMap::new(),
        };
        let result = orchestrator.execute(&package).expect("native forward-gap semantics");
        let actual: Vec<_> = result.console_output.into_iter().map(|entry| entry.message).collect();
        assert_eq!(actual, expected);
    }
}
