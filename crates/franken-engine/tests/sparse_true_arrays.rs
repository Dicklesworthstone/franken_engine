//! Exercise sparse true-Array callbacks through the production orchestrator.
//! Node verifies the shared expectations, not the modified Rust implementation.
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
    ).expect("ordinary execution budgets");
    let package = ExtensionPackage {
        extension_id: "sparse-true-array-iteration".into(),
        source: source.into(), source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn sparse_array_callbacks_species_and_prototypes_stay_live_on_both_profiles() {
    let source = include_str!("fixtures/array_storage/sparse_array_callbacks.js");
    let expected: Vec<_> = include_str!("fixtures/array_storage/sparse_array_callbacks.expected")
        .lines().collect();
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("native sparse Array behavior"), expected);
    }
}

#[test]
fn maximum_length_sparse_arrays_complete_without_logical_length_scans() {
    // The sparse logical span must not become a dense scratch allocation or
    // billions of probes. Expectations are specification-derived; the shared
    // Node fixture uses a smaller span so reference execution stays bounded.
    let source = r#"
const a = []; a.length = 4294967295; a[5] = 2; a[3000000000] = 3;
a['4294967295'] = 99; a['01'] = 100;
const seen = [];
a.forEach((value, k) => { seen.push(k); if (k === 5) a[2000000000] = 4; });
console.log(seen.join(','), a.length);
const mapped = a.map(value => value * 2);
console.log(Object.keys(mapped).join(','), mapped.length, mapped[2000000000], 6 in mapped);
console.log(a.filter(value => value >= 3).join(','));
console.log(a.reduce((sum, value) => sum + value), a.reduceRight((sum, value) => sum + value));
console.log(a.indexOf(4), a.lastIndexOf(3), a.some(value => value === 3), a.every(value => value >= 2));
const empty = []; empty.length = 4294967295;
console.log(empty.some(() => true), empty.every(() => false));
try { empty.reduce((sum, value) => sum + value); } catch (error) { console.log(error.name); }
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("indexed sparse traversal"), [
            "5,2000000000,3000000000 4294967295",
            "5,2000000000,3000000000 4294967295 8 false",
            "4,3", "9 9", "2000000000 3000000000 true true", "false true", "TypeError",
        ]);
    }
}

#[test]
fn observable_proxy_holes_and_find_family_keep_the_default_resource_boundary() {
    // Do not run these under Node, which has no guest work budget. Array
    // identity cannot permit skipping a proxy's has trap or find's callback.
    for source in [
        "const a = []; a.length = 4294967295; \
         Object.setPrototypeOf(a, new Proxy(Array.prototype, {has() { return false; }})); \
         try { Array.prototype.forEach.call(a, () => {}); } catch (e) { console.log('caught'); } \
         console.log('unreachable');",
        "const a = []; a.length = 4294967295; \
         try { a.find(() => false); } catch (e) { console.log('caught'); } \
         console.log('unreachable');",
    ] {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(source, lane).expect_err("observable work cannot be skipped or caught");
            assert!(error.to_ascii_lowercase().contains("budget"), "{error}");
        }
    }
}
