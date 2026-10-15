//! Sparse movement semantics through both production execution profiles.
//! Reference-host fixtures do not substitute for these native executions.
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
    ).expect("ordinary budgets");
    let package = ExtensionPackage {
        extension_id: "sparse-array-moves".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn copy_within_keeps_overlap_callbacks_destination_deletes_and_exceptions_live() {
    let expected: Vec<_> = include_str!("fixtures/array_storage/copy_within.expected").lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(include_str!("fixtures/array_storage/copy_within.js"), lane)
            .expect("native copyWithin"), expected);
    }
}

#[test]
fn maximum_length_sparse_copy_within_does_not_scan_or_buffer_every_hole() {
    // Spec-derived extreme case; the shared Node fixture uses smaller lengths.
    let source = r#"
const a = []; a.length = 4294967295; a[5] = 'erase'; a[3000000000] = 'x';
a.copyWithin(0,2147483648);
console.log(a.length, 5 in a, a[852516352], a[3000000000], Object.keys(a).join(','));
const b = []; b.length = 4294967295; b[7] = 'first'; b[4000000000] = 'last';
b.copyWithin(1,0,4294967294);
console.log(b.length, 7 in b, 4000000000 in b, b[8], b[4000000001]);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("bounded sparse moves"), [
            "4294967295 false x x 852516352,3000000000",
            "4294967295 false false first last",
        ]);
    }
}

#[test]
fn proxy_missing_deletes_keep_the_default_uncatchable_work_limit() {
    let source = "const a = []; a.length = 4294967295; \
        const p = new Proxy(a, {has() {return false;}, deleteProperty() {return true;}}); \
        try {Array.prototype.copyWithin.call(p,0,1);} catch(e) {console.log('caught');} \
        console.log('unreachable');";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(source, lane).expect_err("observable proxy work must remain metered");
        assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
    }
}
