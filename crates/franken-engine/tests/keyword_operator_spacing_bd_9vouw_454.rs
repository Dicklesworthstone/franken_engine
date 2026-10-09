//! bd-9vouw.454: `new` directly followed by a parenthesized callee
//! (`new(function () {...})`, `new(F)(2)`, as minifiers write it) is a new
//! expression; it was read as a call of a reference to `new` ("an operator
//! keyword needs an operand"). And every ECMAScript white space ends a
//! keyword operator: the line merger counted only ASCII white space, so a
//! line ending in `delete` and an NBSP before a line break ended the
//! statement at `delete`. Expected lines are Node v22.2.0's for the same
//! program.

use std::process::Command;

const PROGRAM: &str = "var o = new(function () { this.a = 1; });\nfunction F(x) { this.b = x; }\nvar p = new(F)(2);\nvar q = new(F)(3).b;\nconsole.log(o.a, p.b, q);\nvar d_tab = delete\u{9}0;\nvar t_tab = typeof\u{9}o;\nconsole.log('tab', d_tab, t_tab);\nvar d_vt = delete\u{b}0;\nvar t_vt = typeof\u{b}o;\nconsole.log('vt', d_vt, t_vt);\nvar d_ff = delete\u{c}0;\nvar t_ff = typeof\u{c}o;\nconsole.log('ff', d_ff, t_ff);\nvar d_nbsp = delete\u{a0}0;\nvar t_nbsp = typeof\u{a0}o;\nconsole.log('nbsp', d_nbsp, t_nbsp);\nvar d_mixed = delete\u{9}\u{b}\u{c} \u{a0}\n\u{2028}\u{2029}0;\nvar t_mixed = typeof\u{9}\u{b}\u{c} \u{a0}\n\u{2028}\u{2029}o;\nconsole.log('mixed', d_mixed, t_mixed);\n";

const EXPECTED: &[&str] = &[
    "1 2 3",
    "tab true object",
    "vt true object",
    "ff true object",
    "nbsp true object",
    "mixed true object",
];

#[test]
fn keyword_operators_end_at_any_white_space_and_new_takes_a_parenthesized_callee() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("keyword_spacing.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "keyword-operator-spacing",
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
