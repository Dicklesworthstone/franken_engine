#![forbid(unsafe_code)]

//! bd-9vouw.387: an ES module imports a JSON file with an import attribute
//! (`import data from './data.json' with { type: 'json' }`, ES2025 16.2.2):
//! the module is a JSON module whose only export is `default`, the value
//! `JSON.parse` gives for the text (an own `__proto__` key stays a data
//! property), for default, namespace and side-effect imports, string or
//! identifier keys and a trailing comma. The parser rejected the clause
//! ("import source must be quoted") and the loader parsed a `.json` file
//! as JavaScript. The lines are Node v22.2.0's for the same file tree.

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
fn json_imports_with_type_attribute_load_json_modules() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "data.json",
            r#"{"a": 1, "nested": {"b": [true, null]}, "__proto__": 7}
"#,
        ),
        (
            "arr.json",
            r#"[1, "two", 3.5]
"#,
        ),
        (
            "str.json",
            r#""just a string"
"#,
        ),
        (
            "app.mjs",
            r#"import data from "./data.json" with { type: "json" };
import * as ns from './data.json' with { type: 'json' };
import arr from './arr.json' with { type: 'json', };
import str from './str.json' with { 'type': 'json' };
import './arr.json' with { type: 'json' };
console.log(data.a, JSON.stringify(data.nested), Object.getPrototypeOf(data) === Object.prototype, Object.prototype.hasOwnProperty.call(data, "__proto__"));
console.log(ns.default === data, Object.keys(ns).join(), Array.isArray(arr), JSON.stringify(arr), typeof str, str);
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "app.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        [
            "1 {\"b\":[true,null]} true true",
            "true default true [1,\"two\",3.5] string just a string",
        ]
    );
}
