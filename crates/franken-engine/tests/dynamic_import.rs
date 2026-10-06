#![forbid(unsafe_code)]

//! ES2020 ImportCall: `import(specifier)` returns a promise for the module
//! namespace, from ES modules and CommonJS alike, and every guest-visible
//! failure is a rejection rather than a throw at the call site. Expected
//! lines are Node v22's output for the same file trees.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, entry: &str, goal: ParseGoal, lane: LaneChoice) -> Result<Vec<String>, String> {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "dynamic-import".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: goal,
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

fn assert_output(files: &[(&str, &str)], entry: &str, goal: ParseGoal, expected: &[&str]) {
    let root = tempfile::tempdir().expect("module root");
    for (name, source) in files {
        let path = root.path().join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let actual =
            run(root.path(), entry, goal, lane).unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(actual, expected, "{lane:?}");
    }
}

const COUNTER_MODULE: &str = "export const x = 41;
export default function hello() { return 'hi'; }
export let counter = 0;
export function bump() { counter++; }
";

/// The call returns a promise; it fulfills with the namespace, and a second
/// import of the same module yields the same namespace object.
#[test]
fn es_module_imports_an_es_module_namespace() {
    assert_output(
        &[
            ("m.mjs", COUNTER_MODULE),
            (
                "app.mjs",
                "const p = import('./m.mjs');
console.log(p instanceof Promise);
p.then(ns => {
  console.log(ns.x, ns.default(), Object.keys(ns).join());
  return import('./m.mjs').then(again => console.log(again === ns));
});
",
            ),
        ],
        "app.mjs",
        ParseGoal::Module,
        &["true", "41 hi bump,counter,default,x", "true"],
    );
}

/// From CommonJS: a `.js` CommonJS file's namespace holds `default:
/// module.exports` and its properties, and a call inside a required module
/// resolves against that module's directory, not the entry's.
#[test]
fn commonjs_imports_commonjs_and_resolves_against_the_calling_module() {
    assert_output(
        &[
            ("c.js", "exports.y = 7;\nexports.name = 'c';\n"),
            ("lib/helper.mjs", "export const where = 'lib/helper';\n"),
            ("lib/util.js", "exports.load = () => import('./helper.mjs');\n"),
            (
                "app.js",
                "import('./c.js').then(ns => console.log(ns.default.y, ns.y, ns.name, typeof ns.default));
require('./lib/util.js').load().then(ns => console.log(ns.where));
",
            ),
        ],
        "app.js",
        ParseGoal::Script,
        &["7 7 c object", "lib/helper"],
    );
}

/// Failures reject the returned promise and never throw at the call site: a
/// missing module (Node's `ERR_MODULE_NOT_FOUND`), the value a module's
/// evaluation threw (and an Error on a later import of the failed module),
/// and a specifier whose ToString throws. An object specifier converts
/// through its `toString`.
#[test]
fn failures_reject_the_promise_with_the_error() {
    assert_output(
        &[
            (
                "boom.mjs",
                "const error = new Error('boom');\nerror.tag = 'from-module';\nthrow error;\n",
            ),
            ("m.mjs", "export const ok = 'ok';\n"),
            (
                "app.mjs",
                "let threw = false;
let missing;
try { missing = import('./nope.mjs'); } catch (e) { threw = true; }
console.log(threw, missing instanceof Promise);
async function main() {
  await missing.then(() => console.log('fulfilled'), e => console.log('missing', e instanceof Error, e.code));
  await import('./boom.mjs').catch(e => console.log('boom', e.message, e.tag));
  await import('./boom.mjs').catch(e => console.log('boom again', e instanceof Error));
  await import({ toString() { return './m.mjs'; } }).then(ns => console.log('coerced', ns.ok));
  await import(Symbol('s')).catch(e => console.log('symbol', e instanceof TypeError));
}
main();
",
            ),
        ],
        "app.mjs",
        ParseGoal::Module,
        &[
            "false true",
            "missing true ERR_MODULE_NOT_FOUND",
            "boom boom from-module",
            "boom again true",
            "coerced ok",
            "symbol true",
        ],
    );
}

/// `await import()` in an async function: a module suspended at a top-level
/// await fulfills the promise only once its evaluation has finished, and a
/// rejection is catchable with try/catch.
#[test]
fn awaited_import_waits_for_top_level_await_and_rejections_are_catchable() {
    assert_output(
        &[
            (
                "tla.mjs",
                "export let value = 'before';\nawait Promise.resolve();\nvalue = 'after';\n",
            ),
            (
                "app.mjs",
                "async function main() {
  const ns = await import('./tla.mjs');
  console.log(ns.value);
  try { await import('./missing.mjs'); } catch (e) { console.log('caught', e.code); }
}
main();
",
            ),
        ],
        "app.mjs",
        ParseGoal::Module,
        &["after", "caught ERR_MODULE_NOT_FOUND"],
    );
}
