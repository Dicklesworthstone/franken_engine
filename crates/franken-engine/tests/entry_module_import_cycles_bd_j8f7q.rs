#![forbid(unsafe_code)]

//! bd-j8f7q: an import that cycles back to the entry module (a module the
//! entry imports importing the entry, or the entry importing itself) is
//! checked against the entry's own flow label ceiling, which the
//! orchestrator now computes from the entry's lowering and hands to the
//! interpreter. Without it a bounded importer refused the edge ("module
//! flow label ceiling is not known yet"), and with the module evaluation
//! order of bd-9vouw.388 the cycle sees the entry's exported function. The
//! line is Node v22.2.0's for the same file tree.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, entry: &str) -> Result<Vec<String>, String> {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "esm-probe".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
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
fn imports_cycling_back_to_the_entry_are_checked_against_its_ceiling() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "a.mjs",
            r#"import { base } from "./main.mjs";
export function helper() { return base() + 2; }
"#,
        ),
        (
            "main.mjs",
            r#"import { helper } from "./a.mjs";
import * as self from "./main.mjs";
export function base() { return 40; }
console.log(helper(), typeof self.base, Object.keys(self).join());
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(lines, ["42 function base",]);
}
