//! String access regressions through the production frankenctl path.
//! The semantic oracle was captured with Node v22.16.0. This is not a
//! comparative benchmark: no timing or V8-performance claim is made here.

use std::process::Command;

const PROGRAM: &str = r#"var s = "";
var sum = 0;
for (var i = 0; i < 30000; i++) {
  s += "abcdefg";
  sum += s.charCodeAt(s.length - 1);
  sum += s.codePointAt(s.length - 1);
  if (s.slice(-3) !== "efg") throw "wrong ASCII suffix";
  if (i > 0 && s.slice(-12) !== "cdefgabcdefg") throw "wrong cross-piece suffix";
}
console.log(s.length, sum, s.slice(-7));
var t = "";
var unicodeSum = 0;
for (var j = 0; j < 3000; j++) {
  t = "hé😀" + t;
  unicodeSum += t.codePointAt(2);
  if (t.charCodeAt(3) !== 56832) throw "wrong low surrogate";
  if (t.substring(2, 3).charCodeAt(0) !== 55357) throw "wrong high surrogate";
}
console.log(t.length, unicodeSum, t.charCodeAt(3), t.slice(0, 4) === "hé😀");
var u = "";
for (var k = 0; k < 3000; k++) {
  u += "hé😀";
  if (u.codePointAt(u.length - 2) !== 128512) throw "wrong suffix code point";
  if (u.slice(-1).charCodeAt(0) !== 56832) throw "wrong suffix code unit";
}
console.log(u.length, u.slice(-4) === "hé😀", u.codePointAt(u.length - 1));
var joined = s + t;
console.log(joined.slice(s.length - 1, s.length + 3).charCodeAt(3), joined.length);
console.log(s.charCodeAt(s.length) !== s.charCodeAt(s.length), t.codePointAt(t.length) === undefined);
console.log(u.slice(u.length, u.length).length, u.substring(3, 2).charCodeAt(0));
var flat = JSON.parse(JSON.stringify(u));
console.log(flat.length, flat.codePointAt(flat.length - 2), flat.slice(-3) === "é😀", flat.slice(-1).charCodeAt(0));
var flatMixed = JSON.parse(JSON.stringify(s + "😀xyz"));
console.log(flatMixed.codePointAt(flatMixed.length - 5), flatMixed.codePointAt(flatMixed.length - 4), flatMixed.slice(-3), flatMixed.slice(-4).charCodeAt(0));
var exact = flat + "\ud800x😀\udc00";
console.log(exact.codePointAt(flat.length), exact.codePointAt(flat.length + 2), exact.codePointAt(exact.length - 1), exact.slice(flat.length, flat.length + 1).charCodeAt(0));
"#;

const EXPECTED: &[&str] = &[
    "210000 6180000 abcdefg",
    "12000 385536000 56832 true",
    "12000 true 56832",
    "55357 222000",
    "true true",
    "0 55357",
    "12000 128512 true 56832",
    "128512 56832 xyz 56832",
    "55296 128512 56320 55296",
];

#[test]
fn rope_slices_and_flat_unicode_access_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("string_utf16_access.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "string-utf16-access",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect();
    assert_eq!(printed, EXPECTED);
}
