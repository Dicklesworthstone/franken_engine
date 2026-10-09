#![forbid(unsafe_code)]

//! bd-9vouw.392: in a module, a top-level `return` and an import binding
//! named `eval` or `arguments` (module code is strict) are SyntaxErrors, so
//! `import()` of such a module rejects with one; `return` inside a
//! module's function or arrow is fine. The engine accepted all four.
//! The line is Node v22.2.0's for the same file tree.

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
fn top_level_return_and_eval_arguments_imports_are_syntax_errors() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "dep.mjs",
            r#"export const v = 1;
"#,
        ),
        (
            "ret.mjs",
            r#"return;
"#,
        ),
        (
            "imparg.mjs",
            r#"import { v as arguments } from "./dep.mjs";
"#,
        ),
        (
            "impeval.mjs",
            r#"import eval from "./dep.mjs";
"#,
        ),
        (
            "impns.mjs",
            r#"import * as arguments from "./dep.mjs";
"#,
        ),
        (
            "fine.mjs",
            r#"import { v } from "./dep.mjs";
export function f() { if (v) { return v + 1; } return 0; }
export const g = () => { return 2; };
"#,
        ),
        (
            "main.mjs",
            r#"const specs = ["./ret.mjs", "./imparg.mjs", "./impeval.mjs", "./impns.mjs", "./fine.mjs"];
Promise.all(specs.map((s) => import(s).then((m) => "loaded:" + (m.f ? m.f() + m.g() : ""), (e) => e.name))).then((r) => console.log(r.join()));
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        ["SyntaxError,SyntaxError,SyntaxError,SyntaxError,loaded:4",]
    );
}
