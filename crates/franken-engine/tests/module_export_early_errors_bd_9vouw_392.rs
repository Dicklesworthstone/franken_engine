#![forbid(unsafe_code)]

//! bd-9vouw.392: a module that exports one name twice (`export { a };
//! export { a }`, two default exports, `export * as ns` beside `export {
//! ns }`) or that nests an import or export declaration in a block or a
//! branch is a SyntaxError: `import()` of it rejects with one. Duplicate
//! plain `export *` and distinct names still load. The engine accepted the
//! duplicates and crashed lowering on the nested declarations. The line is
//! Node v22.2.0's for the same file tree.

use std::path::Path;

#[path = "support/persistent_scratch_dir.rs"]
mod persistent_scratch_dir;

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
    let root = persistent_scratch_dir::ScratchDir::new("bd_9vouw_392_export");
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

#[test]
fn split_module_clauses_link_and_execute_across_files() {
    let root = persistent_scratch_dir::ScratchDir::new("multiline_module_clauses");
    for (name, source) in [
        (
            "leaf.mjs",
            "export\tconst answer = 42;\nexport\ndefault\n7;\n",
        ),
        (
            "barrel.mjs",
            "export {default as seven}\nfrom\n'./leaf.mjs';\nexport*as\nns\nfrom './leaf.mjs';",
        ),
        (
            "main.mjs",
            "function from() { console.log('boundary'); }\n\
             import\n{seven, ns}\n// source below\nfrom\n'./barrel.mjs'\n\
             from();\nexport {seven};\nfrom();\nconsole.log(seven, ns.answer);",
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("module fixture");
    }
    assert_eq!(
        run(root.path(), "main.mjs").expect("execute"),
        ["boundary", "boundary", "7 42"]
    );
}

#[test]
fn multiline_export_initializers_publish_the_completed_expression() {
    let root = persistent_scratch_dir::ScratchDir::new("multiline_export_initializers");
    std::fs::write(
        root.path().join("values.mjs"),
        r#"const api = { default: x => x + 1 };
function tag(parts) { return parts[0]; }
export const tagged = tag
`continued`;
export const half = 84
/ 2;
export const pick = ['a', 'b']
[1];
export let initialized = 1, unset
(99);
export default api.default
(41);
"#,
    )
    .expect("exporting module");
    std::fs::write(
        root.path().join("main.mjs"),
        "import result, { tagged, half, pick, unset } from './values.mjs'\n\
         (99);\nconsole.log(result, tagged, half, pick, typeof unset);",
    )
    .expect("importing module");
    assert_eq!(
        run(root.path(), "main.mjs").expect("execute"),
        ["42 continued 42 b undefined"]
    );
}

#[test]
fn dynamic_import_and_import_meta_continue_as_expressions() {
    use frankenengine_engine::ast::{Expression, Statement};
    use frankenengine_engine::parser_api_stability::parse_module;

    for source in ["import('./values.mjs')\n['then'];", "import.meta\n['url'];"] {
        let tree = parse_module(source).expect(source);
        let [Statement::Expression(statement)] = tree.body.as_slice() else {
            panic!("expected one expression statement for {source}");
        };
        assert!(matches!(
            statement.expression,
            Expression::Member { computed: true, .. }
        ));
    }
}
