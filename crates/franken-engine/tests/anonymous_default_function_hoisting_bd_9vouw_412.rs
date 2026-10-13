//! bd-9vouw.412: `export default function () {}` (and its generator and
//! async forms) is a hoistable declaration whose binding is *default*
//! (ES2020 15.2.3), created before any module request is evaluated, as a
//! named exported function is. The engine evaluated the anonymous form in
//! body order, so a module in an import cycle that linked or called it
//! during its own evaluation saw undefined ("expected function, got
//! undefined"). The lines are Node v22.2.0's for the same file tree.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path) -> Result<Vec<String>, String> {
    let entry = root.join("main.mjs");
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
fn an_anonymous_default_function_is_callable_through_an_import_cycle() {
    let root = tempfile::tempdir().expect("module root");
    let root = root.path().canonicalize().expect("canonical root");
    let files: &[(&str, &str)] = &[
        (
            "main.mjs",
            r#"import b from './b.mjs';
import gen from './g.mjs';
export default function () { return 'a'; }
console.log('cycle', b(), [...gen()].join(''));
"#,
        ),
        (
            "b.mjs",
            r#"import a from './main.mjs';
console.log('b sees', typeof a);
export default function () { return 'b' + a(); }
"#,
        ),
        (
            "g.mjs",
            r#"import a from './main.mjs';
export default function* () { yield a(); yield 'g'; }
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.join(name), source).expect("fixture file");
    }
    let lines = run(&root).unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(lines, ["b sees function", "cycle ba ag"]);
}
