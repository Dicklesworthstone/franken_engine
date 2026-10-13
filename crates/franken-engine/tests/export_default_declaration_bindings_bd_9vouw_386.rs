#![forbid(unsafe_code)]

//! bd-9vouw.386: `export default function A() {}` (and `function*`, `async
//! function`, `async function*`, `class A {}`) declares the local binding A
//! and exports it as `default` (ES2020 15.2.3.5: LocalName "A", as `export
//! { A as default }`): the function is hoisted, the class can name itself,
//! a reassignment of A is what importers see, and an anonymous default
//! function is named "default". Every reference to A failed with "A is not
//! defined". The lines are Node v22.2.0's for the same file tree.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, entry: &str) -> Result<Vec<String>, String> {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "export-default-bindings".to_string(),
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
fn named_default_declarations_bind_their_names() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "fn.mjs",
            r#"console.log(typeof A, A());
export default function A() { return "fn"; }
A.tag = "t";
"#,
        ),
        (
            "gen.mjs",
            r#"export default function* G() { yield 1; yield 2; }
console.log(typeof G, G.name, [...G()].join());
"#,
        ),
        (
            "afn.mjs",
            r#"export default async function F() { return 2; }
console.log(typeof F, F.name);
"#,
        ),
        (
            "agen.mjs",
            r#"export default async function* AG() {}
console.log(typeof AG, AG.name);
"#,
        ),
        (
            "cls.mjs",
            r#"export default class K { static make() { return new K(); } }
K.tag = "k";
console.log(typeof K, K.name, K.make() instanceof K);
"#,
        ),
        (
            "anon.mjs",
            r#"export default function () { return "anon"; }
"#,
        ),
        (
            "live.mjs",
            r#"export default function L() { return 1; }
L = 5;
"#,
        ),
        (
            "app.mjs",
            r#"import A from "./fn.mjs";
import G from "./gen.mjs";
import F from "./afn.mjs";
import AG from "./agen.mjs";
import K from "./cls.mjs";
import anon from "./anon.mjs";
import L from "./live.mjs";
console.log(A.name, A.tag, G.name, F.name, AG.name, K.tag, anon(), anon.name, typeof L, L === 5);
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
            "function fn",
            "function G 1,2",
            "function F",
            "function AG",
            "function K true",
            "A t G F AG k anon default number true",
        ]
    );
}
