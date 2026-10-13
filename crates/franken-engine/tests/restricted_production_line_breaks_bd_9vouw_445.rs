//! bd-9vouw.445: `return`, `break`, `continue`, `throw` and `yield` are
//! restricted productions (ES2020 11.9.1): after a line break, a token that
//! could begin their operand gets a semicolon inserted before it. The line
//! merger continued an expression onto any line starting with `+`, `-` or
//! `*`, so `return` newline `+ 1` returned 1 (Node: undefined) and `yield`
//! newline `* 1` was a delegation instead of a SyntaxError. Operators that
//! cannot begin an operand still continue (`c ? yield` newline `: yield`),
//! and so does a property named like the keyword (`obj.return` newline
//! `+ 3`). Expected lines are Node v22.2.0's for the same script.

use std::process::Command;

const PROGRAM: &str = r#"function plus() {
  return
  + 1
}
function minus() {
  return
  - 1
}
function* conditional(c) {
  const x = c ? yield
  : yield;
  return x;
}
const it = conditional(true);
it.next();
const obj = { return: 2 };
const sum = obj.return
  + 3;
let n = 0;
for (let i = 0; i < 3; i++) {
  if (i === 1) continue
  - 1
  n += 1;
}
console.log(String(plus()), String(minus()));
console.log(JSON.stringify(it.next(5)));
console.log(sum, n);
"#;

const EXPECTED: &[&str] = &["undefined undefined", "{\"value\":5,\"done\":true}", "5 2"];

#[test]
fn restricted_keywords_end_before_a_line_starting_their_operand() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("restricted.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "restricted-production-line-breaks",
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
