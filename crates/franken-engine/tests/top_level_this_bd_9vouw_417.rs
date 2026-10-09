//! bd-9vouw.417: top-level `this` is the global object in a script, strict
//! code and arrows included (ES2020 15.1.10 ScriptEvaluation), undefined in
//! an ES module, the entry and an imported one (15.2.1.17.4 GetThisBinding),
//! and `module.exports` in a CommonJS module. The engine gave top-level code
//! one stand-in object in scripts and modules alike, so `this.x = 1` did not
//! make a global `x` and `this === undefined` was false in a module.
//! Functions, class elements and object methods keep their own `this`.
//!
//! Expected lines are Node v22.2.0's: the scripts run as classic scripts
//! (`vm.runInThisContext`), main.mjs as an ES module and main.cjs as a
//! CommonJS module.

use std::path::Path;
use std::process::Command;

fn run(dir: &Path, file: &str, goal: Option<&str>) -> Vec<String> {
    let report = dir.join(format!("{file}.report.json"));
    let mut args = vec![
        "run".to_string(),
        "--input".to_string(),
        dir.join(file).to_str().expect("utf8 path").to_string(),
        "--extension-id".to_string(),
        "top-level-this".to_string(),
        "--out".to_string(),
        report.to_str().expect("utf8 path").to_string(),
    ];
    if let Some(goal) = goal {
        args.extend(["--goal".to_string(), goal.to_string()]);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(&args)
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed on {file}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn script_top_level_this_is_the_global_object() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("sloppy.js"),
        r#"console.log(this === globalThis, (() => this)() === globalThis, (() => () => this)()() === globalThis);
console.log((function () { return this; })() === globalThis, (function () { 'use strict'; return this; })() === undefined);
var o = { m() { return this; }, f: function () { return () => this; } };
console.log(o.m() === o, o.f()() === o);
this.viaThis = 5;
console.log(viaThis, typeof this.Math);
"#,
    )
    .expect("write sloppy.js");
    assert_eq!(
        run(root.path(), "sloppy.js", None),
        ["true true true", "true true", "true true", "5 object"]
    );
}

#[test]
fn strict_script_top_level_this_is_the_global_object() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("strict.js"),
        r#"'use strict';
console.log(this === globalThis, (() => this)() === globalThis);
console.log((function () { return this; })() === undefined, (function () { return (() => this)(); }).call(7) === 7);
class A { static s = this; static { A.t = this; } f = this; [this === globalThis ? 'g' : 'x']() { return this; } }
var a = new A();
console.log(A.s === A, A.t === A, a.f === a, a.g() === a);
this.viaThis = 6;
console.log(viaThis);
"#,
    )
    .expect("write strict.js");
    assert_eq!(
        run(root.path(), "strict.js", None),
        ["true true", "true true", "true true true true", "6"]
    );
}

#[test]
fn module_top_level_this_is_undefined() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("dep.mjs"),
        r#"export const depThis = this === undefined;
export const depArrow = (() => this)() === undefined;
"#,
    )
    .expect("write dep.mjs");
    std::fs::write(
        root.path().join("main.mjs"),
        r#"import { depThis, depArrow } from './dep.mjs';
console.log(this === undefined, (() => this)() === undefined, depThis, depArrow);
console.log((function () { return this; })() === undefined, typeof globalThis);
class B { static s = this; m() { return this; } }
console.log(B.s === B, new B().m() instanceof B);
"#,
    )
    .expect("write main.mjs");
    assert_eq!(
        run(root.path(), "main.mjs", Some("module")),
        ["true true true true", "true object", "true true"]
    );
}

#[test]
fn commonjs_top_level_this_is_module_exports() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("main.cjs"),
        r#"exports.k = 1;
console.log(this === module.exports, (() => this)() === module.exports, this.k);
"#,
    )
    .expect("write main.cjs");
    assert_eq!(
        run(root.path(), "main.cjs", Some("commonjs")),
        ["true true 1"]
    );
}
