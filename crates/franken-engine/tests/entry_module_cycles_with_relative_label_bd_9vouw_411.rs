//! bd-9vouw.411: an import that cycles back to the entry module finds the
//! entry's record also when the entry's path was given in a non-canonical
//! form (`app.mjs`, `./app.mjs`, `/dir/./app.mjs`, as `frankenctl run
//! --input` passes it on). The entry is recorded under that label while
//! imports resolve to canonical paths, so the cycle loaded the entry a
//! second time: its top-level code ran twice, and the first run called
//! into the dependency before the entry's exported function was visible
//! there ("expected function, got undefined"). The lines are Node v22.2.0's
//! for the same file tree.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, entry_label: &str) -> Result<Vec<String>, String> {
    let package = ExtensionPackage {
        extension_id: "esm-probe".to_string(),
        source: std::fs::read_to_string(root.join("main.mjs")).expect("entry source"),
        source_file: Some(entry_label.to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .map(|result| {
        result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect()
    })
    .map_err(|error| error.to_string())
}

#[test]
fn a_cycle_back_to_a_non_canonical_entry_evaluates_it_once() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "helper.mjs",
            r#"import { base } from './main.mjs';
console.log('helper evaluated', typeof base);
export function helper() { return base() + 2; }
"#,
        ),
        (
            "main.mjs",
            r#"import { helper } from './helper.mjs';
import * as self from './main.mjs';
export function base() { return 40; }
console.log('main evaluated', helper(), typeof self.base, Object.keys(self).join());
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let canonical_root = root.path().canonicalize().expect("canonical root");
    let expected = [
        "helper evaluated function",
        "main evaluated 42 function base",
    ];
    // The canonical label already worked; the non-canonical one loaded the
    // entry twice.
    for label in [
        canonical_root.join("main.mjs").display().to_string(),
        format!("{}/./main.mjs", canonical_root.display()),
    ] {
        let lines = run(&canonical_root, &label)
            .unwrap_or_else(|error| panic!("run failed for {label}: {error}"));
        assert_eq!(lines, expected, "entry label {label}");
    }
}
