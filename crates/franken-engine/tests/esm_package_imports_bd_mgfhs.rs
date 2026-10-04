#![forbid(unsafe_code)]

//! bd-mgfhs: an ES module imports npm packages by bare specifier, resolved
//! from node_modules with the `import` condition, on both lanes. Expected
//! lines are Node v22.2.0's output for the same file trees. (Values computed
//! by calling package functions are bounded by bd-j8f7q; these cases print
//! exported constants.)

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, lane: LaneChoice) -> Result<Vec<String>, String> {
    let entry = root.join("app.mjs");
    let package = ExtensionPackage {
        extension_id: "esm-package-imports".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
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

fn assert_output(files: &[(&str, &str)], expected: &[&str]) {
    let root = tempfile::tempdir().expect("module root");
    for (name, source) in files {
        let path = root.path().join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let actual = run(root.path(), lane).unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(actual, expected, "{lane:?}");
    }
}

/// An exports map with import and require conditions: an ES module gets the import target.
#[test]
fn exports_map_prefers_the_import_condition() {
    assert_output(
        &[
            (
                "node_modules/dual/package.json",
                "{\"name\":\"dual\",\"exports\":{\"import\":\"./esm.mjs\",\"require\":\"./cjs.cjs\"}}",
            ),
            ("node_modules/dual/esm.mjs", "export const kind = 'esm';\n"),
            ("node_modules/dual/cjs.cjs", "exports.kind = 'cjs';\n"),
            (
                "app.mjs",
                "import { kind } from 'dual';\nconsole.log(kind);\n",
            ),
        ],
        &["esm"],
    );
}

/// A main-only CommonJS package: module.exports is the default import, its properties named imports.
#[test]
fn main_only_commonjs_package_imports_as_default_and_named() {
    assert_output(
        &[
            (
                "node_modules/legacy/package.json",
                "{\"name\":\"legacy\",\"main\":\"lib/index.js\"}",
            ),
            (
                "node_modules/legacy/lib/index.js",
                "exports.answer = 42;\nexports.name = 'legacy';\n",
            ),
            (
                "app.mjs",
                "import legacy from 'legacy';\nimport { answer } from 'legacy';\nconsole.log(legacy.name, answer);\n",
            ),
        ],
        &["legacy 42"],
    );
}

/// A `"type": "module"` package's .js main is an ES module.
#[test]
fn type_module_package_with_a_js_main() {
    assert_output(
        &[
            (
                "node_modules/modern/package.json",
                "{\"name\":\"modern\",\"type\":\"module\",\"main\":\"index.js\"}",
            ),
            (
                "node_modules/modern/index.js",
                "export const greeting = 'hi';\n",
            ),
            (
                "app.mjs",
                "import { greeting } from 'modern';\nconsole.log(greeting);\n",
            ),
        ],
        &["hi"],
    );
}

/// A scoped package's root and subpath exports.
#[test]
fn scoped_package_root_and_subpath_exports() {
    assert_output(
        &[
            (
                "node_modules/@acme/tools/package.json",
                "{\"name\":\"@acme/tools\",\"exports\":{\".\":\"./main.mjs\",\"./feature\":\"./feature.mjs\"}}",
            ),
            (
                "node_modules/@acme/tools/main.mjs",
                "export const main = 'main';\n",
            ),
            (
                "node_modules/@acme/tools/feature.mjs",
                "export const feature = 'feature';\n",
            ),
            (
                "app.mjs",
                "import { main } from '@acme/tools';\nimport { feature } from '@acme/tools/feature';\nconsole.log(main, feature);\n",
            ),
        ],
        &["main feature"],
    );
}

/// A module in a nested directory finds the root node_modules.
#[test]
fn lookup_walks_up_from_a_nested_module() {
    assert_output(
        &[
            (
                "node_modules/dual/package.json",
                "{\"name\":\"dual\",\"exports\":{\"import\":\"./esm.mjs\",\"require\":\"./cjs.cjs\"}}",
            ),
            ("node_modules/dual/esm.mjs", "export const kind = 'esm';\n"),
            ("node_modules/dual/cjs.cjs", "exports.kind = 'cjs';\n"),
            (
                "src/deep/entry.mjs",
                "import { kind } from 'dual';\nconsole.log('nested', kind);\n",
            ),
            ("app.mjs", "import './src/deep/entry.mjs';\n"),
        ],
        &["nested esm"],
    );
}
