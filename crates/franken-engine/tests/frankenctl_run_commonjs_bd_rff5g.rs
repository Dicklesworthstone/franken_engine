#![forbid(unsafe_code)]

//! `frankenctl run --goal commonjs` (bd-rff5g): the entry runs as a CommonJS
//! module, as Node runs a `.js` entry outside a "type": "module" package, so
//! a program can require its sibling files. The orchestrator gained the
//! `commonjs_entry` opt-in on 2026-09-26; the CLI never set it, so every
//! relative `require` in a `frankenctl run` entry was refused at lowering.
//!
//! Expected lines are Node v22.2.0's output for the same file trees.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{name}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

fn utf8(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn console_messages(report: &Path) -> Vec<String> {
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(report).expect("read report")).expect("report json");
    report["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str().map(str::to_string))
        .collect()
}

/// app.js requires lib/math.js (which requires lib/c.js) and lib/a.js, which
/// requires lib/b.js, which requires a.js back while it is still loading.
fn write_project(root: &Path) {
    fs::create_dir_all(root.join("lib")).expect("lib dir");
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::write(
        root.join("app.js"),
        "const math = require('./lib/math');\n\
         const a = require('./lib/a');\n\
         console.log(math.add(2, 3), typeof __dirname, typeof __filename, require.main === module);\n\
         console.log(a.loaded, a.fromB);\n\
         module.exports = { ok: true };\n\
         console.log(JSON.stringify(module.exports), this === module.exports);\n",
    )
    .expect("app.js");
    fs::write(
        root.join("lib").join("math.js"),
        "const c = require('./c');\nmodule.exports = { add: (x, y) => x + y + c.zero };\n",
    )
    .expect("math.js");
    fs::write(root.join("lib").join("c.js"), "exports.zero = 0;\n").expect("c.js");
    fs::write(
        root.join("lib").join("a.js"),
        "exports.loaded = false;\n\
         const b = require('./b');\n\
         exports.loaded = true;\n\
         module.exports.fromB = b.sawA;\n",
    )
    .expect("a.js");
    fs::write(
        root.join("lib").join("b.js"),
        "const a = require('./a');\nexports.sawA = a.loaded;\n",
    )
    .expect("b.js");
    fs::write(
        root.join("src").join("main.js"),
        "const math = require('../lib/math');\nconsole.log(math.add(20, 22));\n",
    )
    .expect("main.js");
}

#[test]
fn commonjs_entry_requires_sibling_files_and_replays_strictly_bd_rff5g() {
    let root = temp_dir("fe_run_cjs");
    write_project(&root);
    let report = root.join("app.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&root.join("app.js")),
        "--extension-id",
        "cjs-ext",
        "--goal",
        "commonjs",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "run failed: {}",
        stderr_of(&output)
    );
    assert_eq!(
        console_messages(&report),
        ["5 string string true", "true false", "{\"ok\":true} false"]
    );

    let replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        utf8(&report),
        "--mode",
        "strict",
        "--out",
        utf8(&root.join("app.replay.json")),
    ]);
    assert!(
        replay.status.success(),
        "strict replay of a CommonJS run failed: {}",
        stderr_of(&replay)
    );
}

/// Without `--goal commonjs` the entry stays a script: `require` is an
/// ambient identifier and a relative require is refused at lowering.
#[test]
fn script_goal_still_refuses_relative_require_bd_rff5g() {
    let root = temp_dir("fe_run_cjs_script");
    write_project(&root);
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&root.join("app.js")),
        "--extension-id",
        "cjs-ext",
    ]);
    assert!(
        !output.status.success(),
        "a script entry must not load modules"
    );
    assert!(
        stderr_of(&output).contains("ambient authority violation"),
        "expected the lowering refusal, got: {}",
        stderr_of(&output)
    );
}

/// Module loads stay inside the entry's directory unless `--module-root`
/// names a wider one.
#[test]
fn module_root_bounds_relative_requires_bd_rff5g() {
    let root = temp_dir("fe_run_cjs_root");
    write_project(&root);
    let entry = root.join("src").join("main.js");

    let refused = frankenctl(&[
        "run",
        "--input",
        utf8(&entry),
        "--extension-id",
        "cjs-ext",
        "--goal",
        "commonjs",
    ]);
    assert!(
        !refused.status.success(),
        "a require outside the entry's directory must be refused"
    );
    assert!(
        stderr_of(&refused).contains("escapes module root"),
        "expected the module-root refusal, got: {}",
        stderr_of(&refused)
    );

    let report = root.join("main.run.json");
    let allowed = frankenctl(&[
        "run",
        "--input",
        utf8(&entry),
        "--extension-id",
        "cjs-ext",
        "--goal",
        "commonjs",
        "--module-root",
        utf8(&root),
        "--out",
        utf8(&report),
    ]);
    assert!(
        allowed.status.success(),
        "run with --module-root failed: {}",
        stderr_of(&allowed)
    );
    assert_eq!(console_messages(&report), ["42"]);
}

/// A CommonJS module's wrapper bindings (`module`, `exports`, `require`,
/// `__dirname`, `__filename`) are visible inside its nested functions, also
/// when an exported function runs later from another module, and a nested
/// `module` declaration or parameter still shadows them. They read undefined
/// there, so every UMD wrapper (`typeof module === 'object' &&
/// module.exports`) took its browser branch and a nested `require(...)` was
/// "expected function, got undefined".
#[test]
fn nested_functions_see_the_commonjs_wrapper_bindings_bd_rff5g() {
    let root = temp_dir("fe_run_cjs_nested");
    fs::create_dir_all(root.join("lib")).expect("lib dir");
    fs::write(
        root.join("lib/c.js"),
        r#"exports.zero = 0;
"#,
    )
    .expect("lib/c.js");
    fs::write(root.join("lib/umd.js"), r#"(function (root, factory) {
  if (typeof module === 'object' && module.exports) { module.exports = factory(); }
  else { root.Umd = factory(); }
}(this, function () {
  return { name: 'umd', who: function () { return typeof module + ',' + typeof exports + ',' + typeof require; } };
}));
"#).expect("lib/umd.js");
    fs::write(
        root.join("lib/later.js"),
        r#"exports.check = function () { return module.exports === exports; };
exports.load = function () { return require('./c').zero; };
exports.shadow = function (module) { return module; };
exports.inner = function () { var module = 'local'; return (function () { return module; })(); };
"#,
    )
    .expect("lib/later.js");
    fs::write(
        root.join("app.js"),
        r#"const umd = require('./lib/umd');
const later = require('./lib/later');
console.log(umd.name, umd.who());
console.log(later.check(), later.load(), later.shadow('mine'), later.inner());
const nested = () => (() => typeof require + ',' + typeof __dirname + ',' + typeof __filename)();
console.log(nested(), (function () { return require.main === module; })());
"#,
    )
    .expect("app.js");
    let report = root.join("app.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&root.join("app.js")),
        "--extension-id",
        "cjs-nested",
        "--goal",
        "commonjs",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "run failed: {}",
        stderr_of(&output)
    );
    assert_eq!(
        console_messages(&report),
        [
            "umd object,object,function",
            "true 0 mine local",
            "function,string,string true"
        ]
    );
}

/// Writes `files` (path relative to a fresh root, source) and runs `app.js`
/// as the CommonJS entry; the run must succeed.
fn run_tree(name: &str, files: &[(&str, &str)]) -> Vec<String> {
    let root = temp_dir(name);
    for (path, source) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("file parent")).expect("parent dir");
        fs::write(&path, source).expect("write tree file");
    }
    let report = root.join("app.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&root.join("app.js")),
        "--extension-id",
        name,
        "--goal",
        "commonjs",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "run failed: {}",
        stderr_of(&output)
    );
    console_messages(&report)
}

/// A function of one module, called while another module evaluates, reads
/// the wrapper bindings of its own module (bd-9vouw.180). Every scope push
/// had declared the evaluating module's `module` and `exports` on top of the
/// function's captured chain, so a babel helper's lazy
/// `module.exports = _typeof = ...` replaced the CALLER's exports (date-fns:
/// "Super expression must either be null or a function") and zod's
/// `(0, exports.makeIssue)(...)` read the caller's `exports`.
#[test]
fn wrapper_bindings_stay_with_the_module_that_defines_the_function_bd_9vouw_180() {
    let lines = run_tree(
        "fe_run_cjs_owner_bindings",
        &[
            (
                "lib/helper.js",
                r#"var prefix = 'p:'
function readOwn() { return prefix + exports.own }
function setExports() { module.exports = setExports; module.exports.tag = 'helper'; return prefix + module.exports.tag }
exports.own = 'helper-own'
exports.readOwn = readOwn
exports.setExports = setExports
"#,
            ),
            (
                "lib/typeof.js",
                r#"function _typeof(o) {
  return module.exports = _typeof = function (o) { return typeof o }, module.exports.__esModule = true, module.exports['default'] = module.exports, _typeof(o)
}
module.exports = _typeof, module.exports.__esModule = true, module.exports['default'] = module.exports
"#,
            ),
            (
                "lib/user.js",
                r#"var t = require('./typeof')
exports.kind = t(1)
exports.mark = 'user'
"#,
            ),
            (
                "app.js",
                r#"exports.own = 'app-own'
const h = require('./lib/helper')
console.log(h.readOwn(), h.setExports(), typeof module.exports, module.exports.own)
const u = require('./lib/user')
console.log(u.kind, u.mark, Object.keys(u).join())
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "p:helper-own p:helper object app-own",
            "number user kind,mark"
        ]
    );
}

/// `module.exports` may be an accessor (ansi-styles 4, under chalk 4:
/// `Object.defineProperty(module, 'exports', { get: assembleStyles })`); the
/// loader runs the getter in a module context, on every require, as Node
/// does (bd-9vouw.192). It was "expected module-backed
/// Function.prototype.call/apply dispatch, got missing module context".
#[test]
fn a_module_exports_getter_runs_on_require_bd_9vouw_192() {
    let lines = run_tree(
        "fe_run_cjs_exports_getter",
        &[
            (
                "lib/getter.js",
                r#"'use strict'
function make() { return { x: [1, 2].map(function (v) { return v * 2 }).join() } }
Object.defineProperty(module, 'exports', { enumerable: true, get: make })
"#,
            ),
            (
                "app.js",
                r#"console.log(require('./lib/getter').x, require('./lib/getter') !== require('./lib/getter'))
"#,
            ),
        ],
    );
    assert_eq!(lines, ["2,4 true"]);
}

/// Node v22.2.0's Module.prototype.load sets loaded before consuming the
/// exports accessor for its ESM snapshot. Avoid counting accessor reads here:
/// Node also reads exports while checking its circular-require warning proxy.
#[test]
fn commonjs_exports_getters_observe_loaded_wrappers_and_partial_cycles() {
    let lines = run_tree(
        "fe_run_cjs_exports_loaded",
        &[
            (
                "lib/getter.cjs",
                r#"
Object.defineProperty(module, 'exports', { get() {
    if (!module.loaded) throw new Error('exports consumed before wrapper loaded');
    return { loaded: module.loaded, owner: this === module };
} });
"#,
            ),
            (
                "lib/a.cjs",
                r#"
Object.defineProperty(module, 'exports', { get() {
    return module.loaded ? 'ready' : 'partial';
} });
const observed = require('./b.cjs');
console.log('cycle', observed);
"#,
            ),
            ("lib/b.cjs", "module.exports = require('./a.cjs');"),
            (
                "app.js",
                r#"
const first = require('./lib/getter.cjs');
const second = require('./lib/getter.cjs');
console.log(first.loaded, first.owner, second.loaded, first !== second);
console.log('complete', require('./lib/a.cjs'), require('./lib/b.cjs'));
Object.defineProperty(module, 'exports', { get() {
    if (!module.loaded) throw new Error('entry exports consumed before loaded');
    return 42;
} });
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "true true true true",
            "cycle partial",
            "complete ready partial"
        ]
    );
}

#[test]
fn commonjs_wrapper_throw_retries_with_fresh_bindings_and_retained_closures() {
    let lines = run_tree(
        "fe_run_cjs_wrapper_retry",
        &[
            (
                "state.cjs",
                "module.exports = { attempts: 0, saved: [], modules: [], failure: { code: 'retry' } };",
            ),
            (
                "retry.cjs",
                r#"
const state = require('./state.cjs');
state.attempts += 1;
const ownAttempt = state.attempts;
state.saved.push(function () { return ownAttempt + ':' + (module === state.modules[ownAttempt - 1]); });
state.modules.push(module);
if (ownAttempt === 1) throw state.failure;
module.exports = { attempt: ownAttempt };
"#,
            ),
            (
                "app.js",
                r#"
const state = require('./state.cjs');
try { require('./retry.cjs'); } catch (error) { console.log('caught', error === state.failure); }
console.log('escaped before retry', state.saved[0]());
const result = require('./retry.cjs');
console.log('retry', result.attempt, state.attempts, state.saved[0](), state.saved[1]());
console.log('wrappers', state.modules[0] !== state.modules[1], state.modules[0].loaded, state.modules[1].loaded);
console.log('cached', require('./retry.cjs') === result, state.attempts);
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "caught true",
            "escaped before retry 1:true",
            "retry 2 2 1:true 2:true",
            "wrappers true false true",
            "cached true 2",
        ]
    );
}

#[test]
fn commonjs_exports_snapshot_failure_retries_without_poisoning_cached_getters() {
    let lines = run_tree(
        "fe_run_cjs_exports_retry",
        &[
            (
                "state.cjs",
                "module.exports = { attempts: 0, fail: true, modules: [], failure: { code: 'exports' } };",
            ),
            (
                "getter.cjs",
                r#"
const state = require('./state.cjs');
state.attempts += 1;
state.modules.push(module);
Object.defineProperty(module, 'exports', { get() {
    if (!module.loaded) throw new Error('early exports read');
    if (state.fail) throw state.failure;
    return { attempt: state.attempts, owner: this === module };
} });
"#,
            ),
            (
                "app.js",
                r#"
const state = require('./state.cjs');
try { require('./getter.cjs'); } catch (error) { console.log('snapshot failed', error === state.failure); }
state.fail = false;
const value = require('./getter.cjs');
console.log('retry', value.attempt, value.owner, state.modules[0] !== state.modules[1]);
console.log('loaded', state.modules[0].loaded, state.modules[1].loaded);
state.fail = true;
try { require('./getter.cjs'); } catch (error) { console.log('cached getter failed', error === state.failure); }
state.fail = false;
console.log('same wrapper', require('./getter.cjs').attempt, state.attempts);
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "snapshot failed true",
            "retry 2 true true",
            "loaded true true",
            "cached getter failed true",
            "same wrapper 2 2",
        ]
    );
}

#[test]
fn commonjs_native_guest_error_can_retry_the_same_program() {
    let lines = run_tree(
        "fe_run_cjs_native_error_retry",
        &[
            ("state.cjs", "module.exports = { attempts: 0 };"),
            (
                "retry.cjs",
                r#"
const state = require('./state.cjs');
state.attempts += 1;
if (state.attempts === 1) { const absent = null; absent.value; }
module.exports = state.attempts;
"#,
            ),
            (
                "app.js",
                r#"
try { require('./retry.cjs'); } catch (error) { console.log(error.name); }
console.log(require('./retry.cjs'), require('./retry.cjs'));
"#,
            ),
        ],
    );
    assert_eq!(lines, ["TypeError", "2 2"]);
}

#[test]
fn commonjs_esm_snapshot_stays_at_successful_wrapper_completion() {
    let lines = run_tree(
        "fe_run_cjs_esm_exports_snapshot",
        &[
            ("state.cjs", "module.exports = { value: 1 };"),
            (
                "getter.cjs",
                r#"
const state = require('./state.cjs');
Object.defineProperty(module, 'exports', { get() {
    if (!module.loaded) throw new Error('early exports read');
    return state.value;
} });
"#,
            ),
            (
                "app.js",
                r#"
const state = require('./state.cjs');
console.log('initial', require('./getter.cjs'));
state.value = 2;
console.log('live', require('./getter.cjs'));
import('./getter.cjs').then(function (namespace) {
    console.log('snapshot', namespace.default, require('./getter.cjs'));
    state.value = 3;
    return import('./getter.cjs').then(function (again) {
        console.log('stable', again === namespace, again.default, require('./getter.cjs'));
    });
});
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        ["initial 1", "live 2", "snapshot 1 2", "stable true 1 3"]
    );
}

#[test]
fn failed_commonjs_import_keeps_its_exception_after_require_recovers() {
    let lines = run_tree(
        "fe_run_cjs_import_retry_separation",
        &[
            (
                "state.cjs",
                "module.exports = { attempts: 0, nativeAttempts: 0, failure: { code: 'first' } };",
            ),
            (
                "throw.cjs",
                r#"
const state = require('./state.cjs');
state.attempts += 1;
if (state.attempts === 1) throw state.failure;
module.exports = state.attempts;
"#,
            ),
            (
                "native.cjs",
                r#"
const state = require('./state.cjs');
state.nativeAttempts += 1;
if (state.nativeAttempts === 1) { const absent = null; absent.value; }
module.exports = state.nativeAttempts;
"#,
            ),
            (
                "app.js",
                r#"
const state = require('./state.cjs');
import('./throw.cjs').then(function () {
    console.log('unexpected first success');
}, function (first) {
    console.log('first throw', first === state.failure);
    console.log('require recovered', require('./throw.cjs'), state.attempts);
    return import('./throw.cjs').then(function () {
        console.log('unexpected cached success');
    }, function (again) {
        console.log('same throw', again === first, state.attempts);
    });
}).then(function () {
    return import('./native.cjs').then(function () {
        console.log('unexpected native success');
    }, function (first) {
        console.log('native throw', first.name);
        console.log('native require recovered', require('./native.cjs'), state.nativeAttempts);
        return import('./native.cjs').then(function () {
            console.log('unexpected native cached success');
        }, function (again) {
            console.log('same native throw', again === first, again.name, state.nativeAttempts);
        });
    });
});
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "first throw true",
            "require recovered 2 2",
            "same throw true 2",
            "native throw TypeError",
            "native require recovered 2 2",
            "same native throw true TypeError 2",
        ]
    );
}

#[test]
fn handled_reactions_cannot_replace_a_cached_commonjs_import_failure() {
    for (fault, expected) in [
        ("throw { tag: 'original' };", "original"),
        ("null.field;", "TypeError"),
    ] {
        let failed = format!(
            "console.log('evaluate once');
const state = require('./state.cjs');
Promise.resolve().then(function () {{ throw {{ tag: 'other' }}; }}).catch(function () {{
    state.nestedHandled = true;
}});
{fault}"
        );
        let lines = run_tree(
            "fe_run_cjs_import_failure_checkpoint",
            &[
                ("state.cjs", "module.exports = { nestedHandled: false };"),
                ("failed.cjs", &failed),
                (
                    "app.js",
                    r#"
const state = require('./state.cjs');
async function main() {
    let first;
    try { await import('./failed.cjs'); } catch (error) {
        first = error;
        console.log(error.tag || error.name);
    }
    try { await import('./failed.cjs'); } catch (error) {
        console.log(error === first, error.tag || error.name);
    }
    await Promise.resolve();
    console.log(state.nestedHandled);
}
main();
"#,
                ),
            ],
        );
        assert_eq!(
            lines,
            [
                "evaluate once".to_string(),
                expected.to_string(),
                format!("true {expected}"),
                "true".to_string(),
            ]
        );
    }
}

/// `require('buffer')` is Node's buffer module over the engine's `Buffer`,
/// `atob` and `btoa` (bd-9vouw.193): safe-buffer, under jws and
/// jsonwebtoken, reads `require('buffer').Buffer`. It was "Cannot find module
/// 'buffer'". The limits are Node v22.2.0's.
#[test]
fn require_buffer_is_the_buffer_module_bd_9vouw_193() {
    let lines = run_tree(
        "fe_run_cjs_buffer_module",
        &[(
            "app.js",
            r#"const b = require('buffer')
console.log(b.Buffer === Buffer, typeof b.atob, b.btoa('hi'), b.kMaxLength, b.constants.MAX_STRING_LENGTH, require('buffer') === b, require('node:buffer') === b, b.Buffer.from('hi').toString('hex'))
"#,
        )],
    );
    assert_eq!(
        lines,
        ["true function aGk= 9007199254740991 536870888 true true 6869"]
    );
}

/// `require('buffer').Blob` is the global Blob (bd-9vouw.226), as in Node.
#[test]
fn require_buffer_has_the_global_blob_bd_9vouw_226() {
    let lines = run_tree(
        "fe_run_cjs_buffer_blob",
        &[(
            "app.js",
            r#"const { Blob: B } = require('buffer')
console.log(B === Blob, new B(['ab']).size, Object.keys(require('buffer')).includes('Blob'))
"#,
        )],
    );
    assert_eq!(lines, ["true 2 true"]);
}

/// A class may extend a class or constructor function of another module
/// (bd-9vouw.203): `super()` and an implicit constructor construct the parent
/// in its own module with new.target, as Reflect.construct does. The parent's
/// function index was looked up in the child module's table, which ran
/// whatever function had that index: "super() in a base constructor", a
/// silently missing base initialization (implicit constructor), "function#5
/// not found (table size 2)" (p-queue extends eventemitter3).
#[test]
fn classes_extend_parents_of_other_modules_bd_9vouw_203() {
    let lines = run_tree(
        "fe_run_cjs_foreign_parent",
        &[
            (
                "lib/fnbase.js",
                r#"function Base(x) { this.x = x; }
Base.prototype.hi = function () { return 'hi' + this.x; };
module.exports = Base;
"#,
            ),
            (
                "lib/clsbase.js",
                r#"class Root { constructor(v) { this.root = v; } }
class Mid extends Root { constructor(v) { super(v * 10); this.mid = v; } who() { return 'mid'; } }
module.exports = { Root, Mid };
"#,
            ),
            (
                "app.js",
                r#"const Base = require('./lib/fnbase');
const { Mid } = require('./lib/clsbase');
class A extends Base { constructor() { super(1); this.y = 2; } }
class B extends Base {}
class C extends Mid { field = 'f'; constructor() { super(3); this.c = this.root + this.mid; } }
class D extends Mid {}
const a = new A(), b = new B(7), c = new C(), d = new D(4);
console.log(a.x, a.y, a.hi(), a instanceof Base, a instanceof A);
console.log(b.x, b.hi(), b instanceof B);
console.log(c.root, c.mid, c.c, c.field, c.who(), c instanceof Mid);
console.log(d.root, d.mid, d.who(), Object.getPrototypeOf(D) === Mid);
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "1 2 hi1 true true",
            "7 hi7 true",
            "30 3 33 f mid true",
            "40 4 mid true"
        ]
    );
}

/// `require('os')` is Node's os module over the os facade's HostCalls
/// (bd-9vouw.204), whatever form the program uses: hjson's `var os =
/// require('os')` read `os.EOL || '\\n'` inside an object literal, which the
/// facade does not lower, so the require reached the runtime and found no
/// module. `os.platform()` returns the engine's fixed value, so only its type
/// is compared with Node's.
#[test]
fn require_os_is_the_os_module_bd_9vouw_204() {
    let lines = run_tree(
        "fe_run_cjs_os_module",
        &[(
            "app.js",
            r#"var os = require('os');
var o = { EOL: os.EOL || 'x' };
console.log(JSON.stringify(o.EOL), typeof os.platform, os.platform.name, require('os') === os, require('node:os') === os, typeof os.constants.signals.SIGINT, os.devNull, typeof os.platform(), Object.keys(os).length);
"#,
        )],
    );
    assert_eq!(
        lines,
        ["\"\\n\" function platform true true number /dev/null string 23"]
    );
}

/// `require.resolve` (bd-9vouw.199) returns the filename `require` would load,
/// relative to the module that holds the `require`, the request itself for a
/// core module, and throws a catchable MODULE_NOT_FOUND Error for a miss. It
/// was undefined ("expected function, got undefined").
#[test]
fn native_module_callable_prototype_links_preserve_identity_and_provenance() {
    let lines = run_tree(
        "fe_run_cjs_native_callable_identity",
        &[(
            "app.js",
            r#"const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const values = [path.join, http.Agent, net.Socket];
const checks = [];
for (const value of values) {
    const keys = Reflect.ownKeys(value).join();
    const inherited = Object.create(value);
    checks.push(Object.getPrototypeOf(inherited) === value,
        Reflect.ownKeys(value).join() === keys, inherited.call === Function.prototype.call);
    delete value.name;
    delete value.length;
    checks.push(Reflect.getPrototypeOf(inherited) === value);
}
class AgentChild extends http.Agent {}
class SocketChild extends net.Socket {}
console.log(checks.join());
console.log(Object.getPrototypeOf(AgentChild) === http.Agent,
    Object.getPrototypeOf(SocketChild) === net.Socket);
console.log(Object.getPrototypeOf(Object.create(path.join))('a', 'b'));
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "true,true,true,true,true,true,true,true,true,true,true,true",
            "true true",
            "a/b",
        ]
    );
}

#[test]
fn require_own_members_survive_callable_materialization() {
    let lines = run_tree(
        "fe_run_cjs_callable_backing",
        &[(
            "app.js",
            r#"const main = require.main;
const resolve = require.resolve;
require.marker = 1;
Object.setPrototypeOf(require, null);
console.log(require.main === main, Reflect.get(require, 'main') === main,
    require.resolve === resolve, Reflect.get(require, 'resolve') === resolve,
    typeof require.resolve.paths, require.call);
require.resolve = () => 'own';
require.main = { custom: true };
console.log(require.resolve(), require.main.custom,
    Reflect.get(require, 'resolve') === require.resolve);
"#,
        )],
    );
    assert_eq!(
        lines,
        ["true true true true function undefined", "own true true"]
    );
}

#[test]
fn require_resolve_names_the_module_require_would_load_bd_9vouw_199() {
    let lines = run_tree(
        "fe_run_cjs_require_resolve",
        &[
            (
                "lib/x.js",
                r#"exports.here = () => require.resolve('./y');
"#,
            ),
            (
                "lib/y.js",
                r#"exports.y = 1;
"#,
            ),
            (
                "app.js",
                r#"const x = require('./lib/x');
const short = (p) => p.slice(__dirname.length);
let missing; try { require.resolve('./nope'); } catch (e) { missing = e.code; }
console.log(typeof require.resolve, short(require.resolve('./lib/x')), short(x.here()), require.resolve('fs'), require.resolve('node:path'), missing);
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        ["function /lib/x.js /lib/y.js fs node:path MODULE_NOT_FOUND"]
    );
}

/// A function's [[Prototype]] may be a function of another module (babel's
/// `_inherits` does `Object.setPrototypeOf(Child, Parent)` and its
/// `_createSuper` reads it back to construct the parent; date-fns 2.30).
/// Object.getPrototypeOf returned the parent's internal backing object
/// instead of the parent ("expected constructor, got object" from
/// Reflect.construct) (bd-9vouw.209).
#[test]
fn a_function_prototype_may_be_a_function_of_another_module_bd_9vouw_209() {
    let lines = run_tree(
        "fe_run_cjs_foreign_function_prototype",
        &[
            (
                "lib/parser.js",
                r#"function Parser() { this.base = 1; }
Parser.prototype.hi = function () { return 'hi'; };
exports.Parser = Parser;
"#,
            ),
            (
                "lib/era.js",
                r#"var P = require('./parser').Parser;
function Era() { var Super = Object.getPrototypeOf(Era); var r = Reflect.construct(Super, [], Era); r.era = 2; return r; }
Object.setPrototypeOf(Era, P);
Era.prototype = Object.create(P.prototype, { constructor: { value: Era, writable: true, configurable: true } });
exports.Era = Era;
exports.check = function () { return Object.getPrototypeOf(Era) === P; };
"#,
            ),
            (
                "app.js",
                r#"const { Era, check } = require('./lib/era');
const e = new Era();
console.log(check(), typeof Object.getPrototypeOf(Era), e.base, e.era, e.hi(), e instanceof Era);
"#,
            ),
        ],
    );
    assert_eq!(lines, ["true function 1 2 hi true"]);
}

/// `require('events')` (bd-9vouw.210) is the EventEmitter constructor with
/// its statics (`EventEmitter`, `once`, `defaultMaxListeners`,
/// `errorMonitor`), and EventEmitter.prototype holds the methods, so xml2js's
/// CoffeeScript `extend(Parser, events)` (statics copied by for-in,
/// `ctor.prototype = parent.prototype`, the constructor never run) and
/// `Object.create(EventEmitter.prototype)` emit and listen. The require found
/// no module (or, where the events facade claimed the alias, bound it to
/// undefined).
#[test]
fn require_events_is_the_event_emitter_constructor_bd_9vouw_210() {
    let lines = run_tree(
        "fe_run_cjs_events_module",
        &[(
            "app.js",
            r#"const events = require('events');
const EE = require('node:events');
console.log(typeof events, events === EE, events.EventEmitter === events, typeof events.once, events.defaultMaxListeners, typeof events.errorMonitor);
var extend = function (child, parent) { for (var key in parent) { if ({}.hasOwnProperty.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };
var Parser = (function (superClass) { extend(Parser, superClass); function Parser() { this.n = 0; } Parser.prototype.feed = function (x) { this.emit('item', x); }; return Parser; })(events);
var p = new Parser(); var got = [];
p.on('item', function (x) { got.push(x); });
p.feed(1); p.feed(2);
console.log(got.join(), p instanceof events, typeof Parser.once, Parser.defaultMaxListeners, p.listenerCount('item'), Object.keys(events.prototype).includes('emit'), events.prototype.constructor === events);
const o = Object.create(events.prototype); let hit = 0; o.once('x', () => hit++); o.emit('x'); o.emit('x');
events.once(p, 'done').then(([v]) => console.log('once', v)); p.emit('done', 7);
console.log(hit, o.eventNames().length);
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "function true true function 10 symbol",
            "1,2 true function 10 1 true true",
            "1 0",
            "once 7"
        ]
    );
}

/// A nested function that assigns `exports` (or `module`, `require`) reads
/// and writes the module's binding (bd-9vouw.211). The assignment made the
/// name a fresh function-local, undefined until written, so the UMD header
/// `if (typeof exports === "object") { module.exports = exports = factory(); }`
/// took its browser branch in every crypto-js file, and the write never
/// reached the module. Declarations of the body (var, let, parameter, catch
/// parameter) stay local and leave the module's `exports` alone.
#[test]
fn nested_functions_assign_the_commonjs_wrapper_bindings_bd_9vouw_211() {
    let lines = run_tree(
        "fe_run_cjs_wrapper_assignment",
        &[
            (
                "lib/core.js",
                r#";(function (root, factory) {
  if (typeof exports === "object") {
    module.exports = exports = factory();
  }
  else if (typeof define === "function" && define.amd) {
    define([], factory);
  }
  else {
    root.Lib = factory();
  }
}(this, function () {
  var Lib = Lib || { parts: ['core'] };
  return Lib;
}));
"#,
            ),
            (
                "lib/ext.js",
                r#";(function (root, factory) {
  if (typeof exports === "object") {
    module.exports = exports = factory(require("./core"));
  }
  else {
    factory(root.Lib);
  }
}(this, function (Lib) {
  Lib.parts.push('ext');
  return Lib;
}));
"#,
            ),
            (
                "lib/assign.js",
                r#"function set() { exports = { b: 2 }; }
function get() { return exports; }
function clear() { exports = null; }
function fill() { exports ||= { filled: typeof require }; }
const viaArrow = () => { const inner = () => { module.exports.arrow = typeof exports; }; inner(); };
set();
viaArrow();
module.exports.sawWrite = JSON.stringify(get()) + ' ' + JSON.stringify(exports);
clear();
fill();
module.exports.filled = JSON.stringify(exports);
"#,
            ),
            (
                "lib/locals.js",
                r#"exports.v = function () { var exports = 3; exports = 4; return exports; };
exports.l = function () { let exports = 5; { exports = 6; } return exports; };
exports.p = function (exports) { exports = 7; return exports; };
exports.c = function () { try { throw 8; } catch (exports) { exports = exports + 1; return exports; } };
exports.after = function () { return typeof exports.v; };
"#,
            ),
            (
                "app.js",
                r#"const ext = require('./lib/ext');
const assign = require('./lib/assign');
const locals = require('./lib/locals');
console.log(ext.parts.join(), require('./lib/core') === ext, Object.keys(ext).join());
console.log(assign.sawWrite, assign.arrow, assign.filled, Object.keys(assign).join());
console.log(locals.v(), locals.l(), locals.p(1), locals.c(), locals.after(), Object.keys(locals).join());
(function () { console.log(typeof module, typeof require, typeof exports); if (0) { module = 1; require = 2; exports = 3; } })();
"#,
            ),
        ],
    );
    assert_eq!(
        lines,
        [
            "core,ext true parts",
            r#"{"b":2} {"b":2} object {"filled":"function"} arrow,sawWrite,filled"#,
            "4 6 7 9 function v,l,p,c,after",
            "object function object"
        ]
    );
}

/// `require('url')` (bd-9vouw.224) is Node's url module: the realm's `URL`
/// and `URLSearchParams`, and `fileURLToPath`, `parse` and `format` as values
/// over the url facade's HostCalls. joi's `@sideway/address` reads
/// `require('url').URL`; the require found no module. Here the alias also
/// has calls the facade recognizes, which used to make it skip the require.
#[test]
fn require_url_is_the_url_module_bd_9vouw_224() {
    let lines = run_tree(
        "fe_run_cjs_url_module",
        &[(
            "app.js",
            r#"const url = require('url');
const U = require('node:url');
console.log(typeof url, url === U, url.URL === URL, url.URLSearchParams === URLSearchParams, typeof url.fileURLToPath, url.fileURLToPath.name);
const Url = require('url');
const settings = { URL: Url.URL || URL };
console.log(new settings.URL('https://e.org/a/../b?x=1').href, new url.URLSearchParams('a=1&b=2').get('b'));
const parsed = url.parse('http://u@h.com:8080/p/a?x=1#f');
console.log(url.fileURLToPath('file:///a/b%20c.txt'), parsed.port, parsed.pathname, url.format({ protocol: 'https', hostname: 'e.org', pathname: '/x' }));
const f = url.fileURLToPath;
console.log(f('file:///tmp/z'), typeof url.parse, typeof url.format);
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "object true true true function fileURLToPath",
            "https://e.org/b?x=1 2",
            "/a/b c.txt 8080 /p/a https://e.org/x",
            "/tmp/z function function"
        ]
    );
}

/// The URL setters (bd-9vouw.225) update the URL: `hostname`, `port`,
/// `username`, `password`, `protocol`, `host`, `search` (which also refreshes
/// `searchParams`) and `href` (which throws ERR_INVALID_URL for a bad URL),
/// and a value a setter cannot apply is ignored. Only `pathname` and `hash`
/// were handled; any other assignment made an own property that shadowed the
/// getter while `href` kept the old value (normalize-url left `www.` in
/// place). Expected lines are Node v22.2.0's output; Bun 1.4.2 agrees.
#[test]
fn url_setters_update_the_url_bd_9vouw_225() {
    let lines = run_tree(
        "fe_run_cjs_url_setters",
        &[(
            "app.js",
            r#"const u = new URL('http://user:pw@www.example.com:8080/a/b?x=1&y=2#h');
u.hostname = 'example.org';
console.log(u.href, u.host, Object.keys(u).length);
u.port = '81'; u.username = 'me'; u.password = ''; u.protocol = 'https';
console.log(u.href, u.origin);
u.port = '443'; u.host = 'other.net:9000';
console.log(u.href, u.port);
u.search = '?q=a b&r=2';
console.log(u.href, u.searchParams.get('q'), [...u.searchParams.keys()].join(','));
u.searchParams.append('s', '3');
console.log(u.search);
u.href = 'http://z.io/p?k=v#f';
console.log(u.hostname, u.pathname, u.searchParams.get('k'), u.hash);
u.protocol = 'nope:/'; u.port = 'abc'; u.hostname = '';
console.log(u.href);
try { u.href = 'not a url'; } catch (e) { console.log(e instanceof TypeError, e.code); }
console.log(u.href);
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "http://user:pw@example.org:8080/a/b?x=1&y=2#h example.org:8080 0",
            "https://me@example.org:81/a/b?x=1&y=2#h https://example.org:81",
            "https://me@other.net:9000/a/b?x=1&y=2#h 9000",
            "https://me@other.net:9000/a/b?q=a%20b&r=2#h a b q,r",
            "?q=a+b&r=2&s=3",
            "z.io /p v #f",
            "http://z.io/p?k=v#f",
            "true ERR_INVALID_URL",
            "http://z.io/p?k=v#f"
        ]
    );
}

/// `require('timers')` (bd-9vouw.231) is Node's timers module, whose timer
/// functions are the realm's own: xml2js reads
/// `require('timers').setImmediate`, which found no module. The alias also
/// has calls the timers facade recognizes. Expected lines are Node
/// v22.2.0's output for the test's source; Bun 1.4.2 agrees.
#[test]
fn require_timers_is_the_timers_module_bd_9vouw_231() {
    let lines = run_tree(
        "fe_run_cjs_timers_module",
        &[(
            "app.js",
            r#"const timers = require('timers');
const T = require('node:timers');
const si = require('timers').setImmediate;
console.log(typeof timers, timers === T, timers.setTimeout === setTimeout, si === setImmediate, Object.keys(timers).filter((k) => /^(set|clear)/.test(k)).sort().join());
const order = [];
si(() => order.push('immediate'));
let ticks = 0;
const h = timers.setInterval(() => { ticks += 1; if (ticks === 2) timers.clearInterval(h); }, 1);
timers.setTimeout(() => console.log(order.join(), ticks), 30);
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "object true true true clearImmediate,clearInterval,clearTimeout,setImmediate,setInterval,setTimeout",
            "immediate 2"
        ]
    );
}

/// `require('perf_hooks')` (bd-9vouw.302) is Node's perf_hooks module, whose
/// `performance` is the realm's global: cannon-es reads
/// `require('perf_hooks') && require('perf_hooks').performance || {}`,
/// which found no module. Expected line is Node v22.2.0's output for the
/// test's source.
#[test]
fn require_perf_hooks_is_the_perf_hooks_module_bd_9vouw_302() {
    let lines = run_tree(
        "fe_run_cjs_perf_hooks_module",
        &[(
            "app.js",
            r#"const ph = require('perf_hooks');
const P = require('node:perf_hooks');
const performance = require('perf_hooks') && require('perf_hooks').performance || {};
console.log(typeof ph, ph === P, ph.performance === globalThis.performance, typeof performance.now, performance.now() >= 0);
"#,
        )],
    );
    assert_eq!(lines, ["object true true function true"]);
}

/// `require('vm')` (bd-9vouw.303) is a module of Node's shape, so a package
/// that loads vm for an optional feature (jsonpath-plus's eval 'native')
/// loads; the module found none. The first line is Node v22.2.0's output.
/// The engine has no vm contexts: every entry point that would run code
/// refuses with an EvalError when called (Node runs them: "ran ran ran"),
/// as eval does without the runtime.eval grant.
#[test]
fn require_vm_loads_and_refuses_to_run_code_bd_9vouw_303() {
    let lines = run_tree(
        "fe_run_cjs_vm_module",
        &[(
            "app.js",
            r#"const vm = require('vm');
const V = require('node:vm');
function k(f) { try { f(); return 'ran'; } catch (e) { return e.constructor.name; } }
console.log(typeof vm, vm === V, typeof vm.Script, typeof vm.runInNewContext, vm.isContext({}), k(() => vm.isContext(1)));
console.log(k(() => vm.runInNewContext('1 + 1', {})), k(() => new vm.Script('1')), k(() => vm.runInThisContext('2')));
"#,
        )],
    );
    assert_eq!(
        lines,
        [
            "object true function function false TypeError",
            "EvalError EvalError EvalError"
        ]
    );
}
