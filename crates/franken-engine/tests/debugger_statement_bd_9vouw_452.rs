//! bd-9vouw.452: the `debugger` statement (ES2020 13.16) does nothing when
//! no debugger is attached, as the empty statement does. It was read as a
//! reference to a variable named `debugger`, so every `debugger;` threw
//! "ReferenceError: debugger is not defined" and stopped the program, in
//! any statement position. Expected lines are Node v22.2.0's.

use std::process::Command;

const PROGRAM: &str = r#"debugger;
console.log("after1");
function f() { debugger
  return 2; }
console.log(f());
if (true) debugger;
label: debugger;
switch (1) { case 1: debugger; }
for (let i = 0; i < 2; i++) debugger
console.log("after3");
"#;

const EXPECTED: &[&str] = &["after1", "2", "after3"];

#[test]
fn debugger_statements_do_nothing() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("debugger.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "debugger-statement",
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
