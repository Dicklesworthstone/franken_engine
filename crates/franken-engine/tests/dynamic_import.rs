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
/// evaluation threw (the same value on every later import of that module),
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
  let original;
  await import('./boom.mjs').catch(e => { original = e; console.log('boom', e.message, e.tag); });
  await import('./boom.mjs').catch(e => console.log('boom again', e === original, e.message, e.tag));
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
            "boom again true boom from-module",
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

#[test]
fn dynamic_import_defers_evaluation_but_not_specifier_coercion() {
    assert_output(
        &[
            (
                "dep.mjs",
                "console.log('dependency'); export const answer = 42;",
            ),
            (
                "entry.mjs",
                "console.log('start');
const pending = import({ toString() { console.log('coerce'); return './dep.mjs'; } });
pending.then(ns => console.log(ns.answer));
Promise.resolve().then(() => console.log('microtask'));
console.log('end');",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["start", "coerce", "end", "microtask", "dependency", "42"],
    );
}

#[test]
fn dynamic_import_coercion_throw_is_a_rejection_and_does_not_queue_a_load() {
    assert_output(
        &[(
            "entry.mjs",
            "const marker = {};
let threw = false;
let pending;
try { pending = import({ toString() { console.log('coerce'); throw marker; } }); }
catch (error) { threw = true; }
console.log(threw, pending instanceof Promise);
pending.catch(error => console.log(error === marker));
console.log('end');",
        )],
        "entry.mjs",
        ParseGoal::Module,
        &["coerce", "false true", "end", "true"],
    );
}

#[test]
fn queued_imports_share_evaluation_and_namespace_after_the_current_job() {
    assert_output(
        &[
            ("dep.mjs", "console.log('once'); export const value = 7;"),
            (
                "entry.mjs",
                "const first = import('./dep.mjs');
const second = import('./dep.mjs');
Promise.all([first, second]).then(values => console.log(values[0] === values[1], values[1].value));
console.log('scheduled');",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["scheduled", "once", "true 7"],
    );
}

#[test]
fn top_level_await_drives_the_deferred_import_task() {
    assert_output(
        &[
            (
                "dep.mjs",
                "await Promise.resolve(); console.log('dependency'); export const value = 9;",
            ),
            (
                "entry.mjs",
                "console.log('before'); const ns = await import('./dep.mjs'); console.log('after', ns.value);",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["before", "dependency", "after 9"],
    );
}

#[test]
fn concurrent_and_later_imports_share_the_original_throw_and_evaluate_once() {
    assert_output(
        &[
            (
                "failed.mjs",
                "console.log('evaluate once'); throw { tag: 'original' };",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  let second;
  await Promise.all([
    import('./failed.mjs').catch(error => { first = error; }),
    import('./failed.mjs').catch(error => { second = error; })
  ]);
  console.log(first === second, first.tag, second.tag);
  await import('./failed.mjs').catch(error => console.log(error === first, error.tag));
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["evaluate once", "true original original", "true original"],
    );
}

#[test]
fn failed_static_dependencies_keep_the_same_throw_across_importers() {
    assert_output(
        &[
            (
                "failed.mjs",
                "console.log('dependency once'); throw { tag: 'dependency' };",
            ),
            (
                "left.mjs",
                "import './failed.mjs'; console.log('left must not execute');",
            ),
            (
                "right.mjs",
                "import './failed.mjs'; console.log('right must not execute');",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  await import('./left.mjs').catch(error => { first = error; console.log(error.tag); });
  await import('./right.mjs').catch(error => console.log(error === first, error.tag));
  await import('./failed.mjs').catch(error => console.log(error === first, error.tag));
  await import('./left.mjs').catch(error => console.log(error === first, error.tag));
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &[
            "dependency once",
            "dependency",
            "true dependency",
            "true dependency",
            "true dependency",
        ],
    );
}

#[test]
fn cached_module_throws_preserve_primitives_including_undefined_and_negative_zero() {
    for (expression, expected) in [
        ("'failure'", "string true"),
        ("23", "number true"),
        ("null", "object true"),
        ("undefined", "undefined true"),
        ("-0", "number true"),
        ("NaN", "number true"),
    ] {
        let failed = format!("console.log('once'); throw {expression};");
        let entry = format!(
            "async function main() {{
  const expected = {expression};
  await import('./failed.mjs').catch(error => console.log(typeof error, Object.is(error, expected)));
  await import('./failed.mjs').catch(error => console.log(typeof error, Object.is(error, expected)));
}}
main();"
        );
        assert_output(
            &[("failed.mjs", &failed), ("entry.mjs", &entry)],
            "entry.mjs",
            ParseGoal::Module,
            &["once", expected, expected],
        );
    }
}

#[test]
fn top_level_await_rejection_keeps_original_object_on_every_import() {
    assert_output(
        &[
            (
                "failed.mjs",
                "console.log('evaluate once'); await Promise.resolve(); throw { tag: 'original' };",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  try { await import('./failed.mjs'); } catch (error) { first = error; console.log(error.tag); }
  try { await import('./failed.mjs'); } catch (error) { console.log(error === first, error.tag); }
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["evaluate once", "original", "true original"],
    );
}

#[test]
fn async_dependency_rejection_reaches_importers_without_replacing_its_value() {
    assert_output(
        &[
            (
                "failed.mjs",
                "console.log('dependency once'); await Promise.resolve(); throw { tag: 'dependency' };",
            ),
            (
                "middle.mjs",
                "import './failed.mjs'; console.log('middle must not execute'); export const value = 1;",
            ),
            (
                "outer.mjs",
                "import './middle.mjs'; console.log('outer must not execute'); export const value = 2;",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  try { await import('./outer.mjs'); } catch (error) { first = error; console.log(error.tag); }
  try { await import('./failed.mjs'); } catch (error) { console.log(error === first, error.tag); }
  try { await import('./middle.mjs'); } catch (error) { console.log(error === first, error.tag); }
  try { await import('./outer.mjs'); } catch (error) { console.log(error === first, error.tag); }
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &[
            "dependency once",
            "dependency",
            "true dependency",
            "true dependency",
            "true dependency",
        ],
    );
}

#[test]
fn rejected_await_preserves_undefined_instead_of_an_error_description() {
    assert_output(
        &[
            (
                "failed.mjs",
                "console.log('undefined once'); await Promise.reject(undefined);",
            ),
            (
                "entry.mjs",
                "async function main() {
  try { await import('./failed.mjs'); } catch (error) { console.log(error === undefined); }
  try { await import('./failed.mjs'); } catch (error) { console.log(error === undefined); }
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["undefined once", "true", "true"],
    );
}

#[test]
fn top_level_await_preserves_callable_rejection_carriers() {
    assert_output(
        &[
            ("failed.mjs", "await Promise.resolve(); throw () => 42;"),
            (
                "entry.mjs",
                "async function main() {
  let first;
  try { await import('./failed.mjs'); } catch (error) { first = error; console.log(error()); }
  try { await import('./failed.mjs'); } catch (error) { console.log(error === first, error()); }
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["42", "true 42"],
    );
}

#[test]
fn native_module_errors_keep_their_type_and_identity_across_imports() {
    for prefix in ["", "await Promise.resolve(); "] {
        for (fault, name) in [
            ("null.field;", "TypeError"),
            ("missingModuleBinding;", "ReferenceError"),
        ] {
            let failed = format!("console.log('native once'); {prefix}{fault}");
            let repeated = format!("true {name} retained");
            assert_output(
                &[
                    ("failed.mjs", &failed),
                    (
                        "entry.mjs",
                        "async function main() {
  let first;
  try { await import('./failed.mjs'); } catch (error) {
    first = error;
    error.marker = 'retained';
    console.log(error.name);
  }
  try { await import('./failed.mjs'); } catch (error) {
    console.log(error === first, error.name, error.marker);
  }
}
main();",
                    ),
                ],
                "entry.mjs",
                ParseGoal::Module,
                &["native once", name, &repeated],
            );
        }
    }
}

#[test]
fn native_dependency_failure_is_shared_with_every_importer() {
    for prefix in ["", "await Promise.resolve(); "] {
        let failed = format!("console.log('native dependency once'); {prefix}null.field;");
        assert_output(
            &[
                ("failed.mjs", &failed),
                (
                    "outer.mjs",
                    "import './failed.mjs'; console.log('importer must not execute');",
                ),
                (
                    "entry.mjs",
                    "async function main() {
  let first;
  try { await import('./outer.mjs'); } catch (error) { first = error; console.log(error.name); }
  try { await import('./failed.mjs'); } catch (error) { console.log(error === first, error.name); }
  try { await import('./outer.mjs'); } catch (error) { console.log(error === first, error.name); }
}
main();",
                ),
            ],
            "entry.mjs",
            ParseGoal::Module,
            &[
                "native dependency once",
                "TypeError",
                "true TypeError",
                "true TypeError",
            ],
        );
    }
}

#[test]
fn handled_promise_reactions_cannot_replace_the_module_failure() {
    for (fault, expected) in [
        ("throw { tag: 'original' };", "original"),
        ("null.field;", "TypeError"),
    ] {
        let failed = format!(
            "console.log('evaluate once');
globalThis.nestedHandled = false;
Promise.resolve().then(() => {{ throw {{ tag: 'other' }}; }}).catch(() => {{
  globalThis.nestedHandled = true;
}});
{fault}"
        );
        let repeated = format!("true {expected}");
        assert_output(
            &[
                ("failed.mjs", &failed),
                (
                    "entry.mjs",
                    "async function main() {
  let first;
  try { await import('./failed.mjs'); } catch (error) {
    first = error;
    console.log(error.tag || error.name);
  }
  try { await import('./failed.mjs'); } catch (error) {
    console.log(error === first, error.tag || error.name);
  }
  await Promise.resolve();
  console.log(globalThis.nestedHandled);
}
main();",
                ),
            ],
            "entry.mjs",
            ParseGoal::Module,
            &["evaluate once", expected, &repeated, "true"],
        );
    }
}
