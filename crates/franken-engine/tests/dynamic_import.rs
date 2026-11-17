#![forbid(unsafe_code)]

//! ES2020 ImportCall: `import(specifier)` returns a promise for the module
//! namespace, from ES modules and CommonJS alike, and every guest-visible
//! failure is a rejection rather than a throw at the call site. The original
//! one-argument fixtures use Node v22's output for the same file trees.
//!
//! The import-options/JSON fixtures below cover the separately supported
//! modern import-attributes extension, checked against Node v24.22.1. Two
//! documented assertions follow the ECMAScript algorithm and the existing
//! reject-before-cache contract where that Node version behaves differently.

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

#[test]
fn dynamic_options_json_shares_static_and_require_identity_and_snapshots_attributes() {
    assert_output(
        &[
            ("data.json", r#"{"answer":42}"#),
            ("fresh.json", r#"[1,"x",{"k":"v"}]"#),
            ("use.cjs", r#"module.exports = require('./data.json');"#),
            (
                "entry.mjs",
                r#"import data from './data.json' with { type: 'json' };
import required from './use.cjs';
const options = { with: { type: 'json' } };
const pending = import('./data.json', options);
options.with.type = 'javascript';
async function main() {
  const ns = await pending;
  console.log(ns.default === data, ns.default === required, Object.keys(ns).join(), data.answer);
  ns.default.answer = 43;
  console.log(required.answer);
  JSON.parse = () => { throw new Error('guest JSON.parse must not run'); };
  const fresh = await import('./fresh.json', { with: { type: 'json' } });
  console.log(Array.isArray(fresh.default), fresh.default.length, fresh.default[1], fresh.default[2].k);
}
main();"#,
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["true true default 42", "43", "true 3 x v"],
    );
}

#[test]
fn dynamic_options_accepts_empty_options_and_callable_attribute_objects() {
    assert_output(
        &[
            ("data.json", r#"{"answer":42}"#),
            ("value.mjs", r#"export const value = 7;"#),
            (
                "entry.mjs",
                r#"async function main() {
  const first = await import('./value.mjs', undefined);
  const empty = await import('./value.mjs', {});
  const absent = await import('./value.mjs', { with: undefined });
  const noAttributes = await import('./value.mjs', { with: {} });
  console.log(empty === first, absent === first, noAttributes === first);
  function attributes() {}
  attributes.type = 'json';
  Object.defineProperty(attributes, 'hidden', { get() { throw new Error('nonenumerable'); } });
  Object.defineProperty(attributes, Symbol('ignored'), {
    enumerable: true, get() { throw new Error('symbol'); }
  });
  let reads = 0;
  function options() {}
  Object.defineProperty(options, 'with', { get() { reads++; return attributes; } });
  const ns = await import('./data.json', options);
  console.log(ns.default.answer, reads);
  const inherited = Object.create({ get with() { reads++; return { type: 'json' }; } });
  console.log((await import('./data.json', inherited)) === ns, reads);
}
main();"#,
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["true true true", "42 1", "true 2"],
    );
}

#[test]
fn dynamic_options_collects_values_in_order_and_preserves_the_original_getter_throw() {
    // ES2025 EvaluateImportCall calls EnumerableOwnProperties(key+value):
    // each enumerable descriptor is followed by its Get before the next
    // descriptor. Node 24.22.1 instead batches these two descriptor traps.
    // https://tc39.es/ecma262/2025/multipage/abstract-operations.html#sec-enumerableownproperties
    assert_output(
        &[
            ("data.json", r#"{"answer":42}"#),
            (
                "entry.mjs",
                r#"const order = [];
const marker = { tag: 'original getter value' };
const ignored = Symbol('ignored');
const attributes = new Proxy({}, {
  ownKeys() { order.push('keys'); return ['type', 'later', ignored]; },
  getOwnPropertyDescriptor(target, key) {
    order.push('desc:' + String(key));
    return { enumerable: true, configurable: true, value: 0 };
  },
  get(target, key) {
    order.push('get:' + String(key));
    if (key === 'type') return 7;
    throw marker;
  }
});
function options() {
  order.push('options-expr');
  return { get with() { order.push('with'); return attributes; } };
}
let synchronous = false;
let pending;
try {
  pending = import({ toString() { order.push('specifier'); return './data.json'; } }, options());
} catch (error) { synchronous = true; }
order.push('returned');
console.log(synchronous, pending instanceof Promise);
console.log(order.join());
pending.catch(error => console.log(error === marker, error.tag));"#,
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &[
            "false true",
            "options-expr,specifier,with,keys,desc:type,get:type,desc:later,get:later,returned",
            "true original getter value",
        ],
    );
}

#[test]
fn dynamic_options_getter_and_coercion_failures_are_promise_rejections() {
    assert_output(
        &[
            ("data.json", r#"{"answer":42}"#),
            (
                "entry.mjs",
                r#"async function main() {
  const marker = { original: true };
  let reads = 0;
  const throwing = { get with() { reads++; throw marker; } };
  let synchronous = false;
  let pending;
  try { pending = import('./data.json', throwing); } catch (error) { synchronous = true; }
  console.log(synchronous, pending instanceof Promise, reads);
  await pending.catch(error => console.log(error === marker));
  const coercion = { toString() { throw marker; } };
  await import(coercion, throwing).catch(error => console.log(error === marker, reads));
  for (const options of [null, 1, 'text', { with: null }, { with: 1 }, { with: { type: 1 } }]) {
    try { await import('./data.json', options); console.log('unexpected'); }
    catch (error) { console.log(error instanceof TypeError); }
  }
  let later = 0;
  await import('./data.json', { with: {
    type: 1, get extra() { later++; return 'value'; }
  } }).catch(error => console.log(error instanceof TypeError, later));
}
main();"#,
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &[
            "false true 1",
            "true",
            "true 1",
            "true",
            "true",
            "true",
            "true",
            "true",
            "true",
            "true 1",
        ],
    );
}

#[test]
fn dynamic_options_validate_each_request_after_cache_hits_and_preserve_format_errors() {
    // Unknown attributes must still reject a cached request. Node 24.22.1
    // accepts the cached JSON/integrity request below; this loader deliberately
    // retains static import's validation-before-cache contract for ImportCall.
    assert_output(
        &[
            ("data.json", r#"{"answer":42}"#),
            ("value.mjs", r#"export const value = 7;"#),
            (
                "entry.mjs",
                r#"async function main() {
  const first = await import('./data.json', { with: { type: 'json' } });
  for (const options of [undefined, {}, { with: { type: 'javascript' } },
                         { with: { type: 'json', integrity: 'opaque' } }]) {
    try { await import('./data.json', options); console.log('unexpected'); }
    catch (error) { console.log(error instanceof TypeError, error.code); }
  }
  const js = await import('./value.mjs');
  await import('./value.mjs', { with: { type: 'json' } })
    .catch(error => console.log(error instanceof TypeError, error.code));
  await import('node:path', { with: { type: 'json' } })
    .catch(error => console.log(error instanceof TypeError, error.code));
  console.log((await import('./data.json', { with: { type: 'json' } })) === first,
              (await import('./value.mjs', { with: {} })) === js);
}
main();"#,
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &[
            "true ERR_IMPORT_ATTRIBUTE_MISSING",
            "true ERR_IMPORT_ATTRIBUTE_MISSING",
            "true ERR_IMPORT_ATTRIBUTE_UNSUPPORTED",
            "true ERR_IMPORT_ATTRIBUTE_UNSUPPORTED",
            "true ERR_IMPORT_ATTRIBUTE_TYPE_INCOMPATIBLE",
            "true ERR_IMPORT_ATTRIBUTE_TYPE_INCOMPATIBLE",
            "true true",
        ],
    );
}

/// Missing required bindings are guest SyntaxErrors of the importing module.
/// The provider may already have evaluated: this is a binding-validation
/// regression, not proof of graph-wide linking before all module side effects.
#[test]
fn required_export_failures_reject_dynamic_import_and_keep_the_same_error() {
    assert_output(
        &[
            ("provider.mjs", "export const available = 7;"),
            (
                "bad.mjs",
                "import { missing } from './provider.mjs'; console.log('bad body must not run');",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  let second;
  await Promise.all([
    import('./bad.mjs').catch(error => { first = error; }),
    import('./bad.mjs').catch(error => { second = error; })
  ]);
  console.log(first instanceof SyntaxError, first === second);
  await import('./bad.mjs').catch(error => console.log(error === first, error.name));
  const valid = await import('./provider.mjs');
  console.log(valid.available, valid.missing === undefined);
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["true true", "true SyntaxError", "7 true"],
    );
}

#[test]
fn invalid_indirect_export_keeps_its_syntax_error_across_dynamic_importers() {
    assert_output(
        &[
            ("provider.mjs", "export const available = 7;"),
            ("bad.mjs", "export { missing as renamed } from './provider.mjs';"),
            (
                "left.mjs",
                "import * as ns from './bad.mjs'; console.log('left body must not run');",
            ),
            (
                "right.mjs",
                "import './bad.mjs'; console.log('right body must not run');",
            ),
            (
                "entry.mjs",
                "async function main() {
  let first;
  await import('./left.mjs').catch(error => { first = error; console.log(error instanceof SyntaxError); });
  await import('./right.mjs').catch(error => console.log(error === first, error.name));
  await import('./bad.mjs').catch(error => console.log(error === first));
}
main();",
            ),
        ],
        "entry.mjs",
        ParseGoal::Module,
        &["true", "true SyntaxError", "true"],
    );
}
