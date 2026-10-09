//! bd-9vouw.439: require('querystring') is a module object. The
//! querystring facade lowered the member calls of a program-level alias in
//! the program body only: a function reading the alias saw undefined
//! ("reading 'escape'"), and a require inside a function found no module.
//! Under the CommonJS wrapper the require now returns an engine-owned
//! module over the facade's HostCalls (as bd-9vouw.204 did for os).
//! Expected lines are Node v22.2.0's (frankenctl runs the .cjs file as
//! CommonJS, Node's own rule).

use std::process::Command;

const PROGRAM: &str = r#"const qs = require('querystring');
qs.escape('warm');
const h = () => qs.escape('a b');
console.log(h(), typeof qs, typeof qs.parse);
function onlyInside(s) {
  const q = require('node:querystring');
  return JSON.stringify(q.parse(s)) + ' ' + q.stringify({ x: [1, 2], y: 'z w' });
}
console.log(onlyInside('a=1&b=2&a=3'));
const q3 = require('querystring');
const tools = { enc: (o) => q3.encode(o), dec: (s) => q3.decode(s), un: (s) => q3.unescape(s) };
console.log(tools.enc({ k: 'v' }), JSON.stringify(tools.dec('m=n')), tools.un('%41%20b'));
"#;

const EXPECTED: &[&str] = &[
    "a%20b object function",
    "{\"a\":[\"1\",\"3\"],\"b\":\"2\"} x=1&x=2&y=z%20w",
    "k=v {\"m\":\"n\"} A b",
];

#[test]
fn querystring_module_object_serves_functions() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("querystring.cjs");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "querystring-module-object",
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
    let printed: Vec<String> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .flat_map(|message| message.split('\n').map(str::to_string))
        .collect();
    assert_eq!(printed, EXPECTED);
}
