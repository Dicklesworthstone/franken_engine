#![forbid(unsafe_code)]

//! `export * from m` and `export * as ns from m` (bd-332pq) through the
//! shipped module pipeline: real files under a module root, executed on both
//! lanes. Expected lines are Node v22.2.0's output for the same file trees.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Modules every case can re-export.
const LIBRARY: &[(&str, &str)] = &[
    ("lib/a.mjs", "export const a = 1;\nexport default 'A';\n"),
    (
        "lib/b.mjs",
        "export const b = 2;\nexport function f() { return 'f'; }\n",
    ),
];

fn run(root: &Path, lane: LaneChoice) -> Result<Vec<String>, String> {
    let entry = root.join("app.mjs");
    let package = ExtensionPackage {
        extension_id: "esm-star-reexport".to_string(),
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
    for (name, source) in LIBRARY.iter().chain(files) {
        let path = root.path().join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let actual = run(root.path(), lane).unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(actual, expected, "{lane:?}");
    }
}

/// A barrel re-exports every name of each source; `default` is not re-exported.
#[test]
fn barrel_named_and_namespace() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export * from './a.mjs';\nexport * from './b.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a, b, f } from './lib/index.mjs';\nimport * as ns from './lib/index.mjs';\nconsole.log(a, b, f());\nconsole.log(Object.keys(ns).sort().join(','), 'default' in ns);\n",
            ),
        ],
        &["1 2 f", "a,b,f false"],
    );
}

/// `export * as A` binds A to the source's namespace object, default included.
#[test]
fn star_as_namespace() {
    assert_output(
        &[
            ("lib/index.mjs", "export * as A from './a.mjs';\n"),
            (
                "app.mjs",
                "import { A } from './lib/index.mjs';\nconsole.log(A.a, A.default);\n",
            ),
        ],
        &["1 A"],
    );
}

/// The module's own export wins over a star name declared before it.
#[test]
fn own_export_shadows_star_after() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export * from './a.mjs';\nexport const a = 'own';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["own"],
    );
}

/// The module's own export wins over a star name declared after it.
#[test]
fn own_export_shadows_star_before() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export const a = 'own';\nexport * from './a.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["own"],
    );
}

/// Two star sources with different `dup` bindings: the name is ambiguous and not exported.
#[test]
fn ambiguous_name_is_not_exported() {
    assert_output(
        &[
            ("lib/x.mjs", "export const dup = 1;\n"),
            (
                "lib/y.mjs",
                "export const dup = 2;\nexport const y = 'y';\n",
            ),
            (
                "lib/index.mjs",
                "export * from './x.mjs';\nexport * from './y.mjs';\n",
            ),
            (
                "app.mjs",
                "import * as ns from './lib/index.mjs';\nconsole.log('dup' in ns, ns.y);\n",
            ),
        ],
        &["false y"],
    );
}

/// One binding reached through two star paths is not ambiguous.
#[test]
fn diamond_is_not_ambiguous() {
    assert_output(
        &[
            ("lib/d1.mjs", "export * from './a.mjs';\n"),
            ("lib/d2.mjs", "export * from './a.mjs';\n"),
            (
                "lib/index.mjs",
                "export * from './d1.mjs';\nexport * from './d2.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["1"],
    );
}

/// Minified star exports (no spaces) as bundlers emit them.
#[test]
fn minified_star_exports() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export*from'./a.mjs';export*as B from\"./b.mjs\"\n",
            ),
            (
                "app.mjs",
                "import{a,B}from'./lib/index.mjs';console.log(a,B.b,B.f())\n",
            ),
        ],
        &["1 2 f"],
    );
}

/// bd-9vouw.218: a named import or export list may end with one comma, as
/// prettier lays out every multi-line list (`import {\n  a,\n  b,\n} from`);
/// the parser read the trailing comma as an empty entry, so date-fns 4 and
/// superjson did not parse. Expected line is Node v22.2.0's output.
#[test]
fn named_import_and_export_lists_take_a_trailing_comma_bd_9vouw_218() {
    assert_output(
        &[
            (
                "lib/c.mjs",
                "const x = 1, y = 2;\nexport {\n  x,\n  y as why,\n};\nexport { a as aa, } from './a.mjs';\n",
            ),
            (
                "app.mjs",
                "import {\n  x,\n  why,\n  aa,\n} from './lib/c.mjs';\nimport A, { a, } from './lib/a.mjs';\nimport { b, f, } from './lib/b.mjs';\nconsole.log(x, why, aa, A, a, b, f());\n",
            ),
        ],
        &["1 2 1 A 1 2 f"],
    );
}
