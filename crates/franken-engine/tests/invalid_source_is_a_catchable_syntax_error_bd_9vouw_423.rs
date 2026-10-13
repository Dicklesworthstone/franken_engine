//! bd-9vouw.420 / .421 / .423: source that is invalid by the specification
//! is a SyntaxError a program can catch. `Function(body)` turns the parser's
//! InvalidSyntax into a SyntaxError; these bodies were rejected as
//! unsupported syntax instead, which aborts the whole run (an uncatchable
//! module parse failure). The expected line is Node v22.2.0's.

use std::process::Command;

#[test]
fn invalid_function_bodies_throw_catchable_syntax_errors() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("catchable.js");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"var bodies = [
  "super.x",
  "'\\x0'",
  "`\\u{110000}`",
  "({ __proto__: 1, __proto__: 2 })",
  "({ a = 1 })",
  "class A { get # m() {} }",
  "do x; y",
  "() => {}.x",
  "a?.1",
];
console.log(bodies.map(function (body) {
  try { Function(body); return 'parsed'; } catch (error) { return error.name; }
}).join(' '));
"#,
    )
    .expect("write catchable.js");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "catchable",
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
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError"
        ]
    );
}
