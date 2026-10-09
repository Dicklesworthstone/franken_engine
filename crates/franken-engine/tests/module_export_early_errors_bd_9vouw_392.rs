#![forbid(unsafe_code)]

//! bd-9vouw.392: a module that exports one name twice (`export { a };
//! export { a }`, two default exports, `export * as ns` beside `export {
//! ns }`) or that nests an import or export declaration in a block or a
//! branch is a SyntaxError: `import()` of it rejects with one. Duplicate
//! plain `export *` and distinct names still load. The engine accepted the
//! duplicates and crashed lowering on the nested declarations. The line is
//! Node v22.2.0's for the same file tree.

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
fn duplicate_exports_and_nested_module_declarations_are_syntax_errors() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "ok.mjs",
            r#"export const ok = 1;
"#,
        ),
        (
            "dup1.mjs",
            r#"var a; export { a }; export { a };
"#,
        ),
        (
            "dup2.mjs",
            r#"var x; export default 1; export { x as default };
"#,
        ),
        (
            "dup3.mjs",
            r#"export * as ns from "./ok.mjs"; var ns; export { ns };
"#,
        ),
        (
            "nested1.mjs",
            r#"{ export var b = 1; }
"#,
        ),
        (
            "nested2.mjs",
            r#"if (true) import "./ok.mjs";
"#,
        ),
        (
            "fine.mjs",
            r#"export * from "./ok.mjs"; export * from "./ok.mjs"; var a, b; export { a, b as c };
"#,
        ),
        (
            "main.mjs",
            r#"const specs = ["./dup1.mjs", "./dup2.mjs", "./dup3.mjs", "./nested1.mjs", "./nested2.mjs", "./fine.mjs"];
Promise.all(specs.map((s) => import(s).then((m) => "loaded:" + Object.keys(m).join("."), (e) => e.name))).then((r) => console.log(r.join()));
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        ["SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError,loaded:a.c.ok",]
    );
}
