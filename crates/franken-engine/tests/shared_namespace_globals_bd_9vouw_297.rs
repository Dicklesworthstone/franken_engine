#![forbid(unsafe_code)]

//! bd-9vouw.297: the modules of a program share one `console`,
//! `performance`, `JSON`, `Reflect` and `Atomics`, as Node's do. Each module
//! evaluation made its own copies, so a member one module added (here a
//! minimal reflect-metadata: `Reflect.defineMetadata` / `getMetadata` on the
//! global `Reflect`) was undefined in every other module, and not even the
//! entry module's `console` was `globalThis.console`.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

const LIB: &str = "const store = new WeakMap();
Reflect.defineMetadata = function (key, value, target) { let m = store.get(target); if (!m) { m = new Map(); store.set(target, m); } m.set(key, value); };
Reflect.getMetadata = function (key, target) { const m = store.get(target); return m && m.get(key); };
console.marker = 'set-in-lib';
JSON.extra = 1;
module.exports = { libConsole: console, libJSON: JSON, libReflect: Reflect, libPerformance: performance, libAtomics: Atomics };
";

const ENTRY: &str = "const lib = require('./lib.cjs');
class Service {}
Reflect.defineMetadata('design:paramtypes', ['A', 'B'], Service);
console.log(lib.libConsole === console, lib.libJSON === JSON, lib.libReflect === Reflect, lib.libPerformance === performance, lib.libAtomics === Atomics, globalThis.console === console, globalThis.Reflect === Reflect);
console.log(console.marker, JSON.extra, typeof Reflect.getMetadata, Reflect.getMetadata('design:paramtypes', Service).join());
";

/// Runs ENTRY as a CommonJS entry file next to LIB, as Node runs
/// `node entry.cjs`, on both lanes.
fn run_entry() -> Vec<String> {
    let root = tempfile::tempdir().expect("module root");
    let entry = root.path().join("entry.cjs");
    std::fs::write(&entry, ENTRY).expect("entry file");
    std::fs::write(root.path().join("lib.cjs"), LIB).expect("lib file");
    let mut outputs = [LaneChoice::QuickJs, LaneChoice::V8].map(|lane| {
        let package = ExtensionPackage {
            extension_id: "shared-namespace-globals".to_string(),
            source: ENTRY.to_string(),
            source_file: Some(entry.display().to_string()),
            module_root: Some(root.path().display().to_string()),
            capabilities: vec!["module_load".to_string(), "builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            commonjs_entry: true,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect::<Vec<_>>()
    });
    assert_eq!(outputs[0], outputs[1], "lanes disagree");
    std::mem::take(&mut outputs[0])
}

/// Expected lines are Node v22.2.0's output for `node entry.cjs` with the
/// same two files, captured programmatically.
#[test]
fn modules_share_one_console_json_reflect_performance_and_atomics() {
    assert_eq!(
        run_entry(),
        [
            "true true true true true true true",
            "set-in-lib 1 function A,B",
        ]
    );
}
