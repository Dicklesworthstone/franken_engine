//! bd-9vouw.481: Array.prototype.join / toString keep one join stack per
//! interpreter, so an array met again while it is being joined renders "" even
//! when the nested conversion re-entered through a guest-visible toString (a
//! fresh set per call never saw the cycle: `a.push(a); a.join()` overflowed the
//! call stack). This pins Node v22.2.0's output for self, double, mutual and
//! deep cycles, a throwing element and a later join of the same array, guest
//! toString hooks on nested elements, and a hook that joins its own array.

use std::process::Command;

const PROGRAM: &str = r#"function t(name, f) { try { console.log(name, f()); } catch (e) { console.log(name, "threw", e instanceof RangeError ? "RangeError" : String(e)); } }
var a = [1, 2]; a.push(a);
console.log(a.toString(), a.join(), String(a), "" + a, Array.prototype.join.call(a, "|"));
var w = [0]; w.push(w); w.push(w);
t("double", function () { return w.join(); });
var c = [1]; var d = [c]; c.push(d);
t("mutual", function () { return c.join("-") + " " + d.join("+"); });
var m = [1]; m.push([m, [m]]);
t("deep", function () { return m.join(); });
var boom = [1, { toString: function () { throw new Error("boom"); } }, 3];
t("throws", function () { return boom.join(); });
boom[1] = 2;
t("after-throw", function () { return boom.join(); });
var hooked = [[{ toString: function () { return "H"; } }, 4], 5];
t("hook", function () { return hooked.join(";"); });
var selfHook = [7]; selfHook.push({ toString: function () { return "[" + selfHook.join() + "]"; } });
t("self-hook", function () { return selfHook.join(); });
"#;

const EXPECTED: &[&str] = &[
    "1,2, 1,2, 1,2, 1,2, 1|2|",
    "double 0,,",
    "mutual 1- 1,",
    "deep 1,,",
    "throws threw Error: boom",
    "after-throw 1,2,3",
    "hook H,4;5",
    "self-hook 7,[]",
];

#[test]
fn cyclic_array_joins_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("cyclic_array_join_stack_bd_9vouw_481.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "cyclic-array-join",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(printed, EXPECTED);
}
