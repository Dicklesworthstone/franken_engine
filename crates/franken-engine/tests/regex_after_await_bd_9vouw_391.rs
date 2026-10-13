#![forbid(unsafe_code)]

//! bd-9vouw.391: a `/` right after `await` starts a regular expression
//! literal, in module code (top-level await) and in async functions:
//! `typeof await /x.y/g`. It was read as division ("`await` is reserved
//! here and needs an operand"). The line is Node v22.2.0's for the same
//! file tree.

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
fn slash_after_await_starts_a_regular_expression() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[(
        "main.mjs",
        r#"var r = [typeof await /x.y/g, String(await /a/.exec("a"))];
async function f(s) { return (await /b+/.exec(s))[0]; }
f("abbbc").then((m) => console.log(r.join(), m));
"#,
    )];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(lines, ["object,a bbb",]);
}
