#![forbid(unsafe_code)]

//! bd-9vouw.386: an anonymous function, class or parenthesized function
//! exported as default is named "default" (ES2020 15.2.3.11), and a static
//! field of the class reads that name through `this.name`. The engine left
//! the names empty. The line is Node v22.2.0's for the same file tree.

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
fn anonymous_default_exports_are_named_default() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "f.mjs",
            r#"export default function () { return 1; }
"#,
        ),
        (
            "c.mjs",
            r#"export default class { static n = this.name; }
"#,
        ),
        (
            "p.mjs",
            r#"export default (function () {});
"#,
        ),
        (
            "main.mjs",
            r#"import f from "./f.mjs"; import c from "./c.mjs"; import p from "./p.mjs";
console.log(JSON.stringify([f.name, c.name, c.n, p.name]));
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        ["[\"default\",\"default\",\"default\",\"default\"]",]
    );
}
