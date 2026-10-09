//! bd-9vouw.411: an import that cycles back to the entry module finds the
//! entry's record also when the entry's path was given in a non-canonical
//! form (`app.mjs`, `./app.mjs`, `/dir/./app.mjs`, as `frankenctl run
//! --input` passes it on). The entry is recorded under that label while
//! imports resolve to canonical paths, so the cycle loaded the entry a
//! second time: its top-level code ran twice, and the first run called
//! into the dependency before the entry's exported function was visible
//! there ("expected function, got undefined"). The same held for a
//! CommonJS `require` cycling back to the entry (`frankenctl run --goal
//! commonjs`). The lines are Node v22.2.0's for the same file trees.

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

#[test]
fn a_require_cycle_back_to_a_non_canonical_commonjs_entry_loads_it_once() {
    let root = tempfile::tempdir().expect("module root");
    let root = root.path().canonicalize().expect("canonical root");
    std::fs::write(
        root.join("a.js"),
        "exports.early = 'a-early';\nconsole.log('a start');\nconst b = require('./b.js');\nconsole.log('a sees b', b.done, b.sawA);\nexports.done = true;\n",
    )
    .expect("a.js");
    std::fs::write(
        root.join("b.js"),
        "console.log('b start');\nconst a = require('./a.js');\nexports.sawA = a.early + '/' + a.done;\nexports.done = true;\n",
    )
    .expect("b.js");
    let report = root.join("report.json");
    let entry = format!("{}/./a.js", root.display());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.as_str(),
            "--goal",
            "commonjs",
            "--extension-id",
            "cjs-cycle",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(
        lines,
        ["a start", "b start", "a sees b true a-early/undefined"]
    );
}
