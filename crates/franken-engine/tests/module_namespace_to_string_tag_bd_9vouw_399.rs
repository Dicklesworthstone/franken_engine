//! bd-9vouw.399: a module namespace object has the @@toStringTag data
//! property "Module" (not writable, enumerable or configurable), after its
//! exports in Reflect.ownKeys, on both the static and the dynamic import.
//! Expected lines are Node v22.2.0's output for the same file tree.

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
fn module_namespace_objects_are_tagged_module() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "dep.mjs",
            r#"export const x = 1;
export default function f() {}
"#,
        ),
        (
            "app.mjs",
            r#"import * as ns from "./dep.mjs";
const d = Object.getOwnPropertyDescriptor(ns, Symbol.toStringTag);
console.log(ns[Symbol.toStringTag], Object.prototype.toString.call(ns), d && d.value, d && d.writable, d && d.enumerable, d && d.configurable);
console.log(Object.keys(ns).join(), Reflect.ownKeys(ns).length, String(Reflect.ownKeys(ns)[2]), Symbol.toStringTag in ns);
import("./dep.mjs").then((m) => console.log(m === ns, m[Symbol.toStringTag]));
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
            "Module [object Module] Module false false false",
            "default,x 3 Symbol(Symbol.toStringTag) true",
            "true Module",
        ]
    );
}
