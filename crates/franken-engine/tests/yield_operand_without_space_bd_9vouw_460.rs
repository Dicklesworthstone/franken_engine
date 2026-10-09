//! bd-9vouw.460: in a generator, `yield` directly followed by a token
//! that can only begin its operand is a yield expression with that operand:
//! `yield(1)`, `yield[1, 2]`, `yield/ab/g`, `yield{a: 1}`, `yield!0`,
//! `yield"s"`, as minifiers write them. They were read as a call or member
//! access of a bare `yield`: `const r = yield(1)` yielded undefined and then
//! called the resumed value ("expected function, got number"), and
//! `yield/ab/g` threw "unsupported expression syntax". Expected lines are
//! Node v22.2.0's.

use std::process::Command;

const PROGRAM: &str = r#"function* g() { const r = yield(1); return r; }
const it = g();
console.log(JSON.stringify(it.next()), JSON.stringify(it.next(5)));
function* h() { yield[1, 2]; yield/ab/g; yield{a: 1}; yield!0; yield"s"; yield`t`; }
console.log(JSON.stringify([...h()].map(String)));
function* k() { const x = yield; yield x; }
const ki = k(); ki.next(); console.log(JSON.stringify(ki.next(7)));
"#;

const EXPECTED: &[&str] = &[
    "{\"value\":1,\"done\":false} {\"value\":5,\"done\":true}",
    "[\"1,2\",\"/ab/g\",\"[object Object]\",\"true\",\"s\",\"t\"]",
    "{\"value\":7,\"done\":false}",
];

#[test]
fn yield_takes_an_operand_that_follows_without_a_space() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("yield_operand.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "yield-operand-without-space",
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
