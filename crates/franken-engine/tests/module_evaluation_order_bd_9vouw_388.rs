#![forbid(unsafe_code)]

//! bd-9vouw.388: a module's exported function declarations are visible to
//! the modules it imports before any of its code runs, and every module it
//! requests is evaluated before its body, wherever the import statement is
//! written (ES2020 15.2.1.16.4 InitializeEnvironment, InnerModuleEvaluation).
//! Here b.mjs, imported by a.mjs, calls a.mjs's exported `hello` while
//! a.mjs is still being evaluated, and a.mjs imports c.mjs at its end. The
//! engine ran each import where it was written and published `hello` only
//! when its export statement ran, so b's call failed ("expected function,
//! got undefined"). The lines are Node v22.2.0's for the same file tree.

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
fn requested_modules_and_function_exports_precede_the_body() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "main.mjs",
            r#"import { run } from "./a.mjs";
console.log(run());
"#,
        ),
        (
            "a.mjs",
            r#"import { fromB } from "./b.mjs";
console.log("a body", typeof late);
export function hello() { return "hi"; }
export function run() { return fromB + "/" + late(); }
import { late } from "./c.mjs";
"#,
        ),
        (
            "b.mjs",
            r#"import { hello } from "./a.mjs";
export const fromB = hello();
console.log("b evaluated", fromB);
"#,
        ),
        (
            "c.mjs",
            r#"console.log("c evaluated");
export function late() { return "late"; }
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        [
            "b evaluated hi",
            "c evaluated",
            "a body function",
            "hi/late",
        ]
    );
}
