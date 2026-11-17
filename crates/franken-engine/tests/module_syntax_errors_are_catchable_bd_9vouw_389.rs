#![forbid(unsafe_code)]

//! bd-9vouw.389: a module whose source is invalid rejects `import()` with
//! a SyntaxError the importer can catch, every time it is imported: a
//! duplicate `let`, a parse error, and (module code only, ES2020 15.2.1.1)
//! a top-level function declaration that clashes with a `var`. The engine
//! aborted the whole program at the first one ("failed to lower module"),
//! and accepted the function/var clash. A valid module still loads. The
//! line is Node v22.2.0's for the same file tree.

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

struct PersistentDir(std::path::PathBuf);

impl PersistentDir {
    fn new(prefix: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("persistent module root");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[test]
fn invalid_modules_reject_import_with_a_syntax_error() {
    let root = PersistentDir::new("bd_9vouw_389_syntax");
    let files: &[(&str, &str)] = &[
        (
            "dup.mjs",
            r#"let a; let a;
"#,
        ),
        (
            "clash.mjs",
            r#"var smoosh; function smoosh() {}
"#,
        ),
        (
            "broken.mjs",
            r#"export const x = ;
"#,
        ),
        (
            "ok.mjs",
            r#"export const ok = "ok";
"#,
        ),
        (
            "main.mjs",
            r#"const specs = ["./dup.mjs", "./dup.mjs", "./clash.mjs", "./broken.mjs", "./ok.mjs"];
Promise.all(specs.map((s) => import(s).then((m) => "loaded:" + (m.ok || ""), (e) => e.name))).then((r) => console.log(r.join()));
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "main.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        ["SyntaxError,SyntaxError,SyntaxError,SyntaxError,loaded:ok",]
    );
}
