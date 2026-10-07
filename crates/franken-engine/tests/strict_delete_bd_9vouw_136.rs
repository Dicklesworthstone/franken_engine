//! bd-9vouw.136: `delete` in strict-mode code.
//!
//! A strict-mode delete of a property that cannot be deleted (a
//! non-configurable property, a frozen object's, one whose Proxy
//! `deleteProperty` trap answers false) is a TypeError (ES2020 12.5.3.2 step
//! 5.d); the engine answered `false` as sloppy code does. And a strict-mode
//! `delete` of a bare identifier is an early SyntaxError (12.5.3.1), which
//! the engine reported only in modules. Each program runs through the real
//! `frankenctl` binary; expected lines were produced by Node v22.2.0 on the
//! identical text. The sloppy case guards the unchanged behaviour.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// (name, source, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "strict_function_throws",
        "function t(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar fr = Object.freeze({ a: 1 });\nvar ro = {}; Object.defineProperty(ro, 'x', { value: 1 });\nvar px = new Proxy({ k: 1 }, { deleteProperty: function () { return false; } });\nconsole.log((function () { 'use strict'; return [t(function () { return delete Array.prototype.length; }), t(function () { return delete [].length; }), t(function () { return delete ro.x; }), t(function () { return delete Math.PI; }), t(function () { return delete fr.a; }), t(function () { return delete px.k; })].join(' '); })());",
        "TypeError TypeError TypeError TypeError TypeError TypeError",
    ),
    (
        "strict_success_is_true",
        "console.log((function () { 'use strict'; var o = { a: 1 }; var r = [delete o.a, 'a' in o, delete o.missing, delete o['b' + 'c'], delete 1, delete (0, o).a]; return r.join(' '); })());",
        "true false true true true true",
    ),
    (
        "sloppy_answers_false",
        "var ro = {}; Object.defineProperty(ro, 'x', { value: 1 }); console.log([delete Array.prototype.length, delete ro.x, delete Math.PI, delete Object.freeze({ a: 1 }).a].join(' '));",
        "false false false false",
    ),
    (
        "script_and_class_bodies",
        "'use strict';\nvar out = [];\ntry { delete Math.E; out.push('no'); } catch (e) { out.push(e.constructor.name); }\nclass C { static d(o) { return delete o.k; } }\nvar o = {}; Object.defineProperty(o, 'k', { value: 0 });\ntry { C.d(o); out.push('no'); } catch (e) { out.push(e instanceof TypeError); }\nout.push(C.d({ k: 1 }));\nconsole.log(out.join(' '));",
        "TypeError true true",
    ),
    (
        "optional_chain",
        "console.log((function () { 'use strict'; var n = null, o = { a: 1 }; var ro = {}; Object.defineProperty(ro, 'x', { value: 1 }); var r = [delete n?.a, delete o?.a, 'a' in o]; try { delete ro?.x; r.push('no'); } catch (e) { r.push(e.constructor.name); } return r.join(' '); })());",
        "true true false TypeError",
    ),
];

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_delete136_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run(dir: &Path, name: &str, source: &str) -> std::process::Output {
    let input = dir.join(format!("{name}.js"));
    fs::write(&input, source).expect("program");
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "delete136",
            "--instruction-budget",
            "10000000",
            "--out",
            dir.join(format!("{name}.run.json")).to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute")
}

#[test]
fn strict_mode_delete_throws_where_sloppy_answers_false() {
    let dir = scratch_dir();
    let mut mismatches = Vec::new();
    for (name, source, node_output) in CASES {
        let output = run(&dir, name, source);
        if !output.status.success() {
            mismatches.push(format!(
                "{name}: run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        }
        let report = fs::read_to_string(dir.join(format!("{name}.run.json"))).expect("report");
        let parsed: serde_json::Value = serde_json::from_str(&report).expect("json");
        let printed: Vec<&str> = parsed["console_output"]
            .as_array()
            .expect("console")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect();
        if printed != [*node_output] {
            mismatches.push(format!("{name}: got {printed:?}, node {node_output:?}"));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Node: "SyntaxError: Delete of an unqualified identifier in strict mode."
/// before anything runs, in a strict script and in a strict function; also
/// for `NaN` and `Infinity`, which parse as number literals elsewhere.
#[test]
fn strict_mode_delete_of_an_identifier_is_an_early_error() {
    let dir = scratch_dir();
    for (name, source) in [
        (
            "script",
            "'use strict'; var x = 1; console.log('ran'); delete x;",
        ),
        (
            "function",
            "console.log('ran'); (function () { 'use strict'; var y = 1; return delete (y); })();",
        ),
        ("nan", "'use strict'; console.log('ran'); delete NaN;"),
        (
            "infinity",
            "console.log('ran'); (function () { 'use strict'; return delete (Infinity); })();",
        ),
    ] {
        let output = run(&dir, name, source);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains("delete of an unqualified identifier"),
            "{name}: expected an early error, got status {:?}: {stderr}",
            output.status
        );
    }
}
