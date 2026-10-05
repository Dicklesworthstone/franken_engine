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
