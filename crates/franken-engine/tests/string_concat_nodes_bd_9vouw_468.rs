//! bd-9vouw.468: a long string concatenation is a node over its two parts,
//! joined on first read, so `s += piece` in a loop copies each piece about
//! once instead of the whole accumulated string per append. This pins what
//! programs observe to Node v22.2.0: appends, prepends, reads between
//! appends, a node shared by both operands, lone surrogates and healing
//! after a concatenation, JSON, property keys, comparison, sort, chained
//! `a + b + ","` and template-literal accumulation.

use std::process::Command;

const PROGRAM: &str = r#"var s = "";
for (var i = 0; i < 30000; i++) s += "abcdefg";
var t = "";
for (var j = 0; j < 3000; j++) t = "hé😀" + t;
var u = "";
for (var k = 0; k < 2000; k++) {
  u += "x" + k;
  if (k % 500 === 0) u.charCodeAt(u.length - 1);
}
var both = s + s;
var lone = s + "\ud800";
var healed = (s + "\ud83d") + "\ude00";
console.log(s.length, s.slice(-8), s.charCodeAt(140000), s.indexOf("gab"), s.lastIndexOf("abc"));
console.log(t.length, t.slice(0, 5) === "hé😀h", t.codePointAt(2).toString(16), t.at(-1).charCodeAt(0).toString(16));
console.log(u.length, u.slice(0, 10), u.slice(-10), u.split("x").length);
console.log(both.length, both === s + s, both.slice(209990, 210010));
console.log(lone.length, lone.charCodeAt(lone.length - 1).toString(16), healed.length, healed.codePointAt(healed.length - 2).toString(16));
console.log(JSON.stringify(s.slice(0, 3) + t.slice(0, 3)), [s.length, s].join(":").length);
var m = {};
m[s] = 1;
console.log(Object.keys(m)[0].length, m[s + ""], m[both.slice(0, 210000)]);
console.log(s < s + "a", s.endsWith("fg"), (s + "!").length, typeof s, s == both.slice(7), [s, t].sort()[0] === s);
var parts = [];
for (var n = 0; n < 50; n++) parts.push(s.slice(n * 7, n * 7 + 7) + n);
var joined = "";
for (var p = 0; p < parts.length; p++) joined = joined + parts[p] + ",";
console.log(joined.length, joined.slice(0, 30), joined.split(",").length);
var tpl = "";
for (var q = 0; q < 400; q++) tpl = `${tpl}<li>${q}</li>`;
console.log(tpl.length, tpl.slice(-22), tpl.indexOf("<li>399</li>"));
"#;

const EXPECTED: &[&str] = &[
    "210000 gabcdefg 97 6 209993",
    "12000 true 1f600 de00",
    "8890 x0x1x2x3x4 x1998x1999 2001",
    "420000 true efgabcdefgabcdefgabc",
    "210001 d800 210002 1f600",
    "\"abch\u{e9}\\ud83d\" 210007",
    "210000 1 1",
    "true true 210001 string false true",
    "490 abcdefg0,abcdefg1,abcdefg2,abc 51",
    "4690 i>398</li><li>399</li> 4678",
];

#[test]
fn string_concatenation_nodes_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("string_concat.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "string-concat-nodes",
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
