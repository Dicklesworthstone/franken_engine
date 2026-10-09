//! bd-9vouw.424: a for-in/of head may assign a member of an array or object
//! literal (`for ([t][0].k in o)`, sloppy `for ([let][0] in o)`): the bracket
//! group is the member's object, not a destructuring pattern. The parser
//! took it for a pattern and rejected the loop. A binding pattern the parser
//! cannot read is invalid source, a SyntaxError a program can catch from
//! `Function(...)`; it was refused as unsupported syntax, which ended the
//! run. The expected line is Node v22.2.0's.

use std::process::Command;

#[test]
fn literal_member_heads_assign_and_invalid_bindings_are_syntax_errors() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("forin_member.js");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"var t = {};
for ([t][0].k in { a: 1, b: 2 });
var u = {};
for ({ x: u }.x.v of [7, 8]);
var let = 'unused';
for ([let][0] in { c: 1 });
console.log(t.k, u.v, ['z;x', 'var x / = 1;', 'var a.b = 1', 'let [a]b = 1'].map(function (source, index) {
  try { index === 0 ? Function(source, '') : Function(source); return 'parsed'; } catch (error) { return error.name; }
}).join(' '));
"#,
    )
    .expect("write forin_member.js");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "for-in-member",
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
        ["b 8 SyntaxError SyntaxError SyntaxError SyntaxError"]
    );
}
