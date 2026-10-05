#![forbid(unsafe_code)]

//! bd-j8f7q: a value computed by an imported local module's code can reach a
//! console sink when that module's own flow ceiling allows it. The importer is
//! lowered assuming each local import yields at most Internal (only when it is
//! refused without that assumption), and the interpreter checks the imported
//! module's ceiling against the assumption before running it; a module loaded
//! under the contract bounds its own imports the same way. Expected lines
//! are Node v22.2.0's output for the same file trees; the refusals are the
//! planted negatives.

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
        extension_id: "ifc-bounded-imports".to_string(),
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

fn with_tree<T>(files: &[(&str, &str)], check: impl Fn(&Path) -> T) -> T {
    let root = tempfile::tempdir().expect("module root");
    for (name, source) in files {
        let path = root.path().join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
    check(root.path())
}

fn assert_output(files: &[(&str, &str)], expected: &[&str]) {
    with_tree(files, |root| {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let actual = run(root, lane).unwrap_or_else(|error| panic!("{lane:?}: {error}"));
            assert_eq!(actual, expected, "{lane:?}");
        }
    });
}

fn assert_refused(files: &[(&str, &str)], diagnostic: &str) {
    with_tree(files, |root| {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run(root, lane).expect_err("the program must be refused");
            assert!(error.contains(diagnostic), "{lane:?}: {error}");
        }
    });
}

/// Results of imported functions and arrows print (refused before: TopSecret -> Internal).
#[test]
fn imported_function_result_prints() {
    assert_output(
        &[
            (
                "lib.mjs",
                "export function add(a, b) { return a + b; }\nexport const add2 = (a, b) => a + b;\n",
            ),
            (
                "app.mjs",
                "import { add, add2 } from './lib.mjs';\nconsole.log(add(2, 3), add2(4, 5));\n",
            ),
        ],
        &["5 9"],
    );
}

/// Imported generators and a namespace member call print.
#[test]
fn imported_generators_and_namespace_calls_print() {
    assert_output(
        &[
            (
                "lib.mjs",
                "export function* count(n) { for (let i = 0; i < n; i++) yield i; }\nexport function f() { return 'f'; }\n",
            ),
            (
                "app.mjs",
                "import { count } from './lib.mjs';\nimport * as m from './lib.mjs';\nconst g = count(3);\nconsole.log(g.next().value, g.next().value, [...count(4)].join(), m.f());\n",
            ),
        ],
        &["0 1 0,1,2,3 f"],
    );
}

/// A local module that itself imports and calls another local module.
#[test]
fn transitively_imported_calls_print() {
    assert_output(
        &[
            ("util.mjs", "export const twice = (x) => x * 2;\n"),
            (
                "lib.mjs",
                "import { twice } from './util.mjs';\nexport function quad(x) { return twice(twice(x)); }\nconsole.log('lib', twice(1));\n",
            ),
            (
                "app.mjs",
                "import { quad } from './lib.mjs';\nconsole.log(quad(3));\n",
            ),
        ],
        &["lib 2", "12"],
    );
}

/// An importer that passes without the contract keeps working when the
/// imported module's ceiling is TopSecret: loaded without a bound, lib.mjs is
/// lowered without the contract, so its own import of other.mjs is opaque.
#[test]
fn side_effect_only_import_of_an_opaque_module_still_runs() {
    assert_output(
        &[
            (
                "lib.mjs",
                "import { x } from './other.mjs';\nexport function touch(list) { list.push(x); }\n",
            ),
            ("other.mjs", "export const x = 1;\n"),
            (
                "app.mjs",
                "import { touch } from './lib.mjs';\nconst list = [];\ntouch(list);\n",
            ),
        ],
        &[],
    );
}

/// Planted negative: the imported module can produce a TopSecret value (it
/// imports a Node core module the engine does not model, whose code is
/// outside any IR), so the importer that prints its result is refused at the
/// import edge, before the module runs.
#[test]
fn importing_a_module_above_the_contract_is_refused() {
    assert_refused(
        &[
            (
                "lib.mjs",
                "import * as threads from 'node:worker_threads';\nexport function f() { return 1; }\nconsole.log('lib ran');\n",
            ),
            (
                "app.mjs",
                "import { f } from './lib.mjs';\nconsole.log(f());\n",
            ),
        ],
        "bounded-import contract",
    );
}

/// Planted negative: a Node core module has no module code to check and
/// stays opaque, so a program that prints after importing one is still
/// refused at lowering.
#[test]
fn a_core_module_import_stays_opaque() {
    assert_refused(
        &[
            ("lib.mjs", "export function f() { return 1; }\n"),
            (
                "app.mjs",
                "import { f } from './lib.mjs';\nimport * as threads from 'node:worker_threads';\nconsole.log(f());\n",
            ),
        ],
        "unauthorized flow",
    );
}

/// A package (bd-mgfhs) is bounded like a local file: its function results
/// print (Node prints 5 7).
#[test]
fn imported_package_function_results_print() {
    assert_output(
        &[
            (
                "node_modules/calc/package.json",
                "{\"name\":\"calc\",\"exports\":\"./index.mjs\"}",
            ),
            (
                "node_modules/calc/index.mjs",
                "export function add(a, b) { return a + b; }\nexport default (x) => x + 6;\n",
            ),
            (
                "app.mjs",
                "import plus, { add } from 'calc';\nconsole.log(add(2, 3), plus(1));\n",
            ),
        ],
        &["5 7"],
    );
}

/// Planted negative: a package whose code can produce a TopSecret value is
/// refused at the import edge when the importer prints its result.
#[test]
fn importing_a_package_above_the_contract_is_refused() {
    assert_refused(
        &[
            (
                "node_modules/leaky/package.json",
                "{\"name\":\"leaky\",\"exports\":\"./index.mjs\"}",
            ),
            (
                "node_modules/leaky/index.mjs",
                "import * as threads from 'node:worker_threads';\nexport function f() { return 1; }\n",
            ),
            ("app.mjs", "import { f } from 'leaky';\nconsole.log(f());\n"),
        ],
        "bounded-import contract",
    );
}

/// Planted negative: the bound holds transitively. The app prints an
/// imported call's result, so it runs under the contract; a barrel
/// re-exporting a module above the contract is lowered under the contract
/// itself (so its own ceiling passes the app's edge), and its edge to that
/// module is refused before the module runs (Node prints 1).
#[test]
fn a_barrel_over_a_module_above_the_contract_is_refused() {
    assert_refused(
        &[
            (
                "a.mjs",
                "import * as threads from 'node:worker_threads';\nexport function f() { return 1; }\n",
            ),
            ("index.mjs", "export * from './a.mjs';\n"),
            (
                "app.mjs",
                "import { f } from './index.mjs';\nconsole.log(f());\n",
            ),
        ],
        "bounded-import contract",
    );
}
