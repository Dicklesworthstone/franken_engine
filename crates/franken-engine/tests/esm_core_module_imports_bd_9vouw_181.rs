#![forbid(unsafe_code)]

//! bd-9vouw.181: ES module imports of Node core modules whose `require`
//! aliases lowering recognizes (path, os, url, querystring, util, zlib,
//! crypto, timers, events), and the path module object for the `require`
//! forms the path facade does not recognize. Before, such an import loaded
//! nothing at run time and its opaque result was TopSecret, so no program
//! that printed anything derived from it ran. The original fixtures use Node
//! v22.2.0 output captured for the same file trees; refusals are planted
//! negatives. The ordinary native import fixtures additionally exercise the
//! engine's runtime provider identity and authority contracts.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Runs `app.mjs` as an ES module, or `app.cjs` as Node runs a CommonJS
/// entry.
fn run(root: &Path, lane: LaneChoice) -> Result<Vec<String>, String> {
    run_with_capabilities(root, lane, &["module_load", "builtin", "timer"])
}

fn run_with_capabilities(
    root: &Path,
    lane: LaneChoice,
    capabilities: &[&str],
) -> Result<Vec<String>, String> {
    let commonjs = root.join("app.cjs").is_file();
    let entry = root.join(if commonjs { "app.cjs" } else { "app.mjs" });
    let package = ExtensionPackage {
        extension_id: "esm-core-imports".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: capabilities.iter().map(|grant| (*grant).to_string()).collect(),
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: if commonjs {
            ParseGoal::Script
        } else {
            ParseGoal::Module
        },
        commonjs_entry: commonjs,
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

/// bd-9vouw.300: a module-level `const path = require('path')` that a
/// function, an arrow or a method reads (picomatch, every package that uses
/// `path` inside its functions). With no use outside functions the alias
/// stayed a runtime `require('path')`, which finds no module; with one, the
/// facade claimed the alias and the function read an unbound `path`.
#[test]
fn path_alias_read_inside_functions() {
    assert_output(
        &[
            (
                "lib.cjs",
                r#"'use strict';
const path = require('path');
const SEP = path.sep;
function base(x) { return path.basename(x, '.js'); }
const isWin = () => path.sep === '\\';
class P { dir(x) { return path.dirname(x); } }
module.exports = { SEP, base, isWin, dir: (x) => new P().dir(x) };
"#,
            ),
            (
                "app.cjs",
                r#"const lib = require('./lib.cjs');
const path = require('path');
function joined(a, b) { return path.join(a, '..', b); }
console.log(lib.SEP, lib.base('/a/b.js'), lib.isWin(), lib.dir('/q/r/s.txt'), joined('x/y', 'z'));
"#,
            ),
        ],
        &["/ b false /q/r x/z"],
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

/// Named path imports (the path module object): Node's join, resolve and argument errors.
#[test]
fn path_named_imports() {
    assert_output(
        &[(
            "app.mjs",
            "import { join, dirname, basename, resolve, relative, sep, posix } from 'node:path';\nconsole.log(join('a', 'b', '../c'), dirname('/x/y/z.js'), basename('/x/y.js', '.js'), resolve('/a', 'b', '../c'), relative('/a/b', '/a/c/d'), sep, posix.join('p', 'q'));\ntry { join('a', 1); } catch (error) { console.log(error.code, error.message); }\ntry { resolve('a', 1, 'b'); } catch (error) { console.log(error.code, error.message); }\n",
        )],
        &[
            "a/c /x/y y /a/c ../c/d / p/q",
            "ERR_INVALID_ARG_TYPE The \"path\" argument must be of type string. Received type number (1)",
            "ERR_INVALID_ARG_TYPE The \"paths[1]\" argument must be of type string. Received type number (1)",
        ],
    );
}

/// CommonJS: a destructured require, a require inside a function and an inline read of a function get the path module object; the facade's alias still works.
#[test]
fn path_module_object_in_commonjs() {
    assert_output(
        &[(
            "app.cjs",
            "const { join, extname } = require('path');\nfunction nested() { const p = require('node:path'); return p.dirname('/q/r.txt'); }\nconst parse = require('path').parse;\nconst path = require('path');\nconsole.log(join('x', 'y'), extname('f.md'), nested(), parse('/home/u/f.txt').name, path.join('m', 'n'));\n",
        )],
        &["x/y .md /q f m/n"],
    );
}

/// Named exports that are realm globals (URL, Buffer, atob, performance, the timers) read the globals, aliased or not.
#[test]
fn named_imports_of_realm_globals() {
    assert_output(
        &[(
            "app.mjs",
            "import { URL, fileURLToPath } from 'node:url';\nimport { Buffer as B, atob } from 'node:buffer';\nimport { performance } from 'node:perf_hooks';\nimport { setTimeout as later } from 'node:timers';\nconsole.log(new URL('https://a.b/c?d=1').searchParams.get('d'), fileURLToPath('file:///x'), B.from('hi').toString('hex'), atob('aGk='), typeof performance.now());\nlater(() => console.log('later'), 1);\n",
        )],
        &["1 /x 6869 hi number", "later"],
    );
}

/// Named imports from modules whose facade lowers member calls on an alias (crypto, os, querystring, timers/promises, zlib); a local of the same name shadows the import.
#[test]
fn named_imports_of_member_modules() {
    assert_output(
        &[(
            "app.mjs",
            "import { createHash } from 'node:crypto';\nimport { EOL, platform } from 'node:os';\nimport { stringify } from 'node:querystring';\nimport { setTimeout as sleep } from 'node:timers/promises';\nimport { gzipSync, gunzipSync } from 'node:zlib';\nconsole.log(createHash('sha256').update('a').digest('hex').slice(0, 8), EOL === '\\n', typeof platform(), stringify({ a: 1 }), gunzipSync(gzipSync('z')).toString());\nfunction inner() { const createHash = () => 'shadowed'; return createHash(); }\nfor (const stringify of ['loop']) console.log(stringify);\nconsole.log(inner());\nawait sleep(1);\nconsole.log('slept');\n",
        )],
        &["ca978112 true string a=1 z", "loop", "shadowed", "slept"],
    );
}

/// A local require disables the legacy facade rewrite. The real static
/// import still loads the native provider without calling that guest binding.
#[test]
fn a_program_with_its_own_require_uses_the_native_import_provider() {
    assert_output(
        &[(
            "app.mjs",
            "import path from 'node:path';\nfunction require(specifier) { return specifier; }\nconsole.log(path.join('a', 'b'), require('local'));\n",
        )],
        &["a/b local"],
    );
}

/// An imported path alias passed as a value (the path module object since
/// the gate19 follow-up; before, a known gap refused as the ambient-authority
/// refusal of the rewritten require). Node prints a/b.
#[test]
fn an_imported_path_alias_passed_as_a_value_works() {
    assert_output(
        &[(
            "app.mjs",
            "import path from 'node:path';\nconst use = (p) => p.join('a', 'b');\nconsole.log(use(path));\n",
        )],
        &["a/b"],
    );
}

/// bd-9vouw.221: `export { ... } from` and `export * as ns from` a core
/// module the rewrite handles lower like the import of each name and a local
/// export, so an importer of the re-exporting module runs (vfile's
/// `lib/minpath.js` is the first file). Before, the re-export loaded the
/// module at run time and made the re-exporting module TopSecret, refused at
/// the importer's bounded-import contract. Node prints these two lines.
#[test]
fn reexports_of_core_modules_bd_9vouw_221() {
    assert_output(
        &[
            (
                "minpath.mjs",
                "export {default as minpath} from 'node:path'\n",
            ),
            (
                "re.mjs",
                "export { join, sep as separator, default } from 'node:path';\nexport * as posix from 'path';\nexport { format } from 'node:util';\nexport { URL as Url } from 'node:url';\n",
            ),
            (
                "app.mjs",
                "import { minpath } from './minpath.mjs';\nimport p, { join, separator, posix, format, Url } from './re.mjs';\nconsole.log(minpath.join('x', 'y'), join('a', 'b'), separator, p.basename('/q/r.txt'), posix.extname('s.md'));\nconsole.log(format('%s-%d', 'n', 4), new Url('https://e.org/p?q=1').pathname, Url === URL);\n",
            ),
        ],
        &["x/y a/b / r.txt .md", "n-4 /p true"],
    );
}

/// Planted negative for bd-9vouw.221: a re-export of a core module no facade
/// serves stays opaque, so the importer that prints a result of the
/// re-exporting module is still refused at its bounded-import contract
/// (Node prints 1).
#[test]
fn a_reexport_of_an_unmodeled_core_module_stays_refused_bd_9vouw_221() {
    assert_refused(
        &[
            (
                "lib.mjs",
                "export { Worker } from 'node:worker_threads';\nexport function f() { return 1; }\n",
            ),
            (
                "app.mjs",
                "import { f } from './lib.mjs';\nconsole.log(f());\n",
            ),
        ],
        "bounded-import contract",
    );
}


/// Exercise runtime module loading, deliberately avoiding the legacy literal
/// require rewrites. The same provider must serve both spellings and both
/// import forms, including source-backed factories and callable CJS exports.
#[test]
fn ordinary_native_imports_share_runtime_require_identity() {
    for (alias, key) in [
        ("buffer", "Buffer"),
        ("crypto", "createHash"),
        ("zlib", "gzipSync"),
        ("module", "createRequire"),
        ("events", "EventEmitter"),
        ("os", "platform"),
        ("querystring", "stringify"),
        ("url", "URL"),
        ("timers", "setTimeout"),
        ("perf_hooks", "performance"),
        ("path", "join"),
        ("path/posix", "join"),
        ("path/win32", "join"),
        ("util", "format"),
        ("util/types", "isDate"),
        ("assert", "ok"),
        ("assert/strict", "ok"),
        ("string_decoder", "StringDecoder"),
        ("timers/promises", "setTimeout"),
        ("stream", "Readable"),
        ("stream/promises", "pipeline"),
    ] {
        let commonjs = format!(
            r#"
const load = require;
const commonjs = load('{alias}');
import('node:{alias}').then(async function(namespace) {{
    const again = await import('{alias}');
    console.log(namespace === again, namespace.default === commonjs,
        commonjs === load('node:{alias}'),
        namespace['{key}'] === commonjs['{key}'],
        typeof namespace['{key}'] !== 'undefined');
}});
"#
        );
        assert_output(&[("app.cjs", &commonjs)], &["true true true true true"]);

        let esm = format!(
            r#"
import load from './load.cjs';
import * as namespace from '{alias}';
import * as prefixed from 'node:{alias}';
function require(specifier) {{ return 'local:' + specifier; }}
const commonjs = load('node:{alias}');
import('{alias}').then(function(again) {{
    console.log(namespace === prefixed, namespace === again,
        namespace.default === commonjs,
        namespace['{key}'] === commonjs['{key}'],
        typeof namespace['{key}'] !== 'undefined', require('sentinel'));
}});
"#
        );
        assert_output(
            &[
                ("app.mjs", &esm),
                ("load.cjs", "module.exports = function(name) { return require(name); };"),
            ],
            &["true true true true true local:sentinel"],
        );
    }
}

/// These operations cross module boundaries; checking only import success or
/// typeof would miss unusable function values and mismatched Buffer storage.
#[test]
fn ordinary_dynamic_imports_execute_crypto_compression_and_path_operations() {
    assert_output(
        &[(
            "app.cjs",
            r#"
async function main() {
    const buffer = await import('node:buffer');
    const crypto = await import('crypto');
    const zlib = await import('node:zlib');
    const path = await import('path');
    const bytes = buffer.Buffer.from('native');
    console.log(bytes.toString('hex'));
    console.log(crypto.createHash('sha256').update('abc').digest('hex'));
    console.log(zlib.gunzipSync(zlib.gzipSync(bytes)).toString());
    console.log(path.join('a', 'b', '..', 'c'));
}
main();
"#,
        )],
        &[
            "6e6174697665",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "native",
            "a/c",
        ],
    );
}

/// Namespace exports snapshot the first load; the default export remains the
/// mutable runtime CJS object. Neither assignment nor reflection can replace a
/// namespace export, and a guest's @@toStringTag does not grant exotic behavior.
#[test]
fn ordinary_native_namespaces_keep_snapshots_and_reject_export_mutation() {
    for (alias, key) in [
        ("buffer", "Buffer"),
        ("crypto", "createHash"),
        ("zlib", "gzipSync"),
        ("path", "join"),
    ] {
        let source = format!(
            r#"
const load = require;
const commonjs = load('{alias}');
import('node:{alias}').then(async function(namespace) {{
    const original = namespace['{key}'];
    const replacement = function() {{ return 'changed'; }};
    commonjs['{key}'] = replacement;
    commonjs.guestAdded = true;
    const again = await import('{alias}');
    console.log(again === namespace, again.default === commonjs,
        again['{key}'] === original, again.default['{key}'](),
        'guestAdded' in again);
    console.log(Reflect.set(namespace, '{key}', replacement),
        Reflect.defineProperty(namespace, '{key}', {{value: replacement}}),
        Reflect.deleteProperty(namespace, '{key}'),
        namespace['{key}'] === original,
        Object.getPrototypeOf(namespace) === null, Object.isExtensible(namespace),
        Object.getOwnPropertyDescriptor(namespace, '{key}').writable);
    const fake = {{value: original}};
    fake[Symbol.toStringTag] = 'Module';
    console.log(Reflect.set(fake, 'value', replacement),
        Reflect.defineProperty(fake, 'value', {{value: original}}),
        Reflect.deleteProperty(fake, 'value'));
}});
"#
        );
        assert_output(
            &[("app.cjs", &source)],
            &[
                "true true true changed false",
                "false false false true true false true",
                "true true true",
            ],
        );
    }
}

/// Ordinary dynamic imports cannot acquire scheduling authority merely by
/// reaching a native factory. The same contract is enforced for static imports.
#[test]
fn ordinary_native_imports_require_the_provider_capabilities() {
    for alias in ["timers", "timers/promises", "stream", "stream/promises"] {
        for (name, source) in [
            ("app.cjs", format!("import('node:{alias}');")),
            (
                "app.mjs",
                format!("import * as namespace from 'node:{alias}';\nfunction require(name) {{ return name; }}\n"),
            ),
        ] {
            with_tree(&[(name, &source)], |root| {
                for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                    let error = run_with_capabilities(root, lane, &["module_load", "builtin"])
                        .expect_err("native import must not confer Timer authority");
                    assert!(
                        error.to_ascii_lowercase().contains("timer"),
                        "{lane:?} {alias} {name}: {error}"
                    );
                }
            });
        }
    }
}
