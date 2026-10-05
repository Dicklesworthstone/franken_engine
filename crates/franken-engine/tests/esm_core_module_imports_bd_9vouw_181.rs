#![forbid(unsafe_code)]

//! bd-9vouw.181: ES module imports of Node core modules whose `require`
//! aliases lowering recognizes (path, os, url, querystring, util, zlib,
//! crypto, timers, events). Before, such an import loaded nothing at run time
//! and its opaque result was TopSecret, so no program that printed anything
//! derived from it ran. Expected lines are Node v22.2.0's output for the same
//! file trees, captured programmatically; the refusals are planted negatives.

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
        extension_id: "esm-core-imports".to_string(),
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
        std::fs::write(root.path().join(name), source).expect("fixture file");
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

/// Default and namespace imports of path call its members and read its constants.
#[test]
fn path_default_and_namespace_imports() {
    assert_output(
        &[(
            "app.mjs",
            "import path from 'node:path';\nimport * as posix from 'path';\nconsole.log(path.join('a', 'b', '../c'), path.basename('/x/y.js', '.js'), path.sep, posix.extname('f.ts'));\n",
        )],
        &["a/c y / .ts"],
    );
}

/// EventEmitter as the default export and as a named import, including a subclass.
#[test]
fn events_default_and_named_imports() {
    assert_output(
        &[(
            "app.mjs",
            "import EventEmitter from 'events';\nimport { EventEmitter as Named } from 'node:events';\nclass Bus extends Named {}\nconst e = new EventEmitter();\ne.on('x', (v) => console.log('got', v));\ne.emit('x', 3);\nconst b = new Bus();\nb.on('y', (v) => console.log('bus', v));\nb.emit('y', 4);\n",
        )],
        &["got 3", "bus 4"],
    );
}

/// An imported name the program never uses does not keep the used one from working.
#[test]
fn unused_named_import_does_not_block_the_others() {
    assert_output(
        &[(
            "app.mjs",
            "import { once, EventEmitter } from 'node:events';\nconst e = new EventEmitter();\ne.on('x', (v) => console.log('got', v));\ne.emit('x', 5);\n",
        )],
        &["got 5"],
    );
}

/// util members through named and default imports.
#[test]
fn util_named_and_default_imports() {
    assert_output(
        &[(
            "app.mjs",
            "import util, { format, inspect } from 'node:util';\nconsole.log(format('%s=%d', 'a', 1), inspect({ a: [1, 2] }), util.format('%s!', 'hi'));\n",
        )],
        &["a=1 { a: [ 1, 2 ] } hi!"],
    );
}

/// The other pure core modules with recognized member calls.
#[test]
fn os_url_querystring_crypto_imports() {
    assert_output(
        &[(
            "app.mjs",
            "import os from 'node:os';\nimport { fileURLToPath } from 'node:url';\nimport qs from 'querystring';\nimport crypto from 'node:crypto';\nconsole.log(typeof os.EOL, fileURLToPath('file:///a/b'), qs.stringify({ a: 1, b: 'x y' }), crypto.createHash('sha256').update('a').digest('hex').slice(0, 8));\n",
        )],
        &["string /a/b a=1&b=x%20y ca978112"],
    );
}

/// A side-effect-only import of a core module runs the program.
#[test]
fn side_effect_import_of_a_core_module() {
    assert_output(
        &[("app.mjs", "import 'node:path';\nconsole.log('ok');\n")],
        &["ok"],
    );
}

/// A local module that imports path: its results reach the importer's console.
#[test]
fn imported_module_uses_a_core_module() {
    assert_output(
        &[
            (
                "lib.mjs",
                "import path from 'node:path';\nexport function rel(file) { return path.join('src', file); }\n",
            ),
            (
                "app.mjs",
                "import { rel } from './lib.mjs';\nconsole.log(rel('main.js'));\n",
            ),
        ],
        &["src/main.js"],
    );
}

/// Planted negative: the rewrite never routes an import through a `require` the program declares, so the import stays opaque and its result is refused at the console (Node prints a/b).
#[test]
fn a_program_with_its_own_require_keeps_the_import_opaque() {
    assert_refused(
        &[(
            "app.mjs",
            "import path from 'node:path';\nconst require = (specifier) => specifier;\nconsole.log(path.join('a', 'b'), require('x'));\n",
        )],
        "unauthorized flow",
    );
}

/// Planted negative: a use the path facade does not recognize (the module object escapes into a call) is still refused, now as the ambient-authority refusal of the rewritten require (Node prints a/b).
#[test]
fn an_unrecognized_use_keeps_failing_closed() {
    assert_refused(
        &[(
            "app.mjs",
            "import path from 'node:path';\nconst use = (p) => p.join('a', 'b');\nconsole.log(use(path));\n",
        )],
        "ambient authority",
    );
}
