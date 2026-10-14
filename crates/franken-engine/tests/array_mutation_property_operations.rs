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
        OrchestratorConfig { force_lane: Some(lane), ..OrchestratorConfig::default() },
        RuntimeConfig::default(),
    ).expect("ordinary runtime budgets");
    let package = ExtensionPackage {
        extension_id: "array-mutation-properties".into(),
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
fn mutators_preserve_property_operations_and_partial_effects_on_both_native_profiles() {
    let source = include_str!("fixtures/array_mutation/property_operations.js");
    let expected: Vec<_> = include_str!("fixtures/array_mutation/property_operations.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("native mutation semantics"), expected);
    }
}

#[test]
fn sparse_mutations_cannot_run_billions_of_unmetered_hole_steps() {
    // These programs intentionally exhaust the DEFAULT budget. They neither
    // allocate a dense backing nor depend on a callback to meter the loop.
    // Do not run them under Node as reference cases: Node has no guest budget.
    for method in ["shift", "unshift", "reverse"] {
        let source = format!(
            "const a = []; a.length = 4294967294; a.{method}(1); console.log('unreachable');"
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(&source, lane).expect_err("sparse work must remain budget-bounded");
            assert!(error.to_ascii_lowercase().contains("budget"), "{method}: {error}");
        }
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
            ["5 3", "4,7,7,9,8 5", "0 0 undefined undefined", "true true true"]
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
        assert_eq!(run(source, lane).expect("reentrant array operations"), expected);
    }
}

#[test]
fn sparse_splice_copy_delete_and_sort_scans_keep_default_resource_limits() {
    // A custom result avoids reserving a dense removed-items array. Splice
    // still scans its absent source indices. Sort can now skip proven ordinary
    // holes, so use a Proxy whose has trap makes EVERY hole observable. Keep
    // the exact budget and uncatchable-refusal assertions, not a timing limit.
    for operation in [
        "a.splice(0, 4294967294)",
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
            assert!(error.to_ascii_lowercase().contains("budget"), "{operation}: {error}");
        }
    }
}
