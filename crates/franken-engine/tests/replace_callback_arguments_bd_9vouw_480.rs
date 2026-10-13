//! bd-9vouw.480: a replace/replaceAll callback's offset is counted on from the
//! previous match and its string argument is made once per call to replace.
//! This pins callback arguments to Node v22.2.0: 20,000 matches over 129 KB
//! (call count, offset sum, string length), offsets in a string with
//! two-byte and supplementary characters, named-group callbacks, replaceAll
//! with a string needle (ASCII and CJK), empty-pattern matches (with and
//! without the u flag), no match and a non-global replace.

use std::process::Command;

const PROGRAM: &str = r#"var s = "";
for (var i = 0; i < 20000; i++) s += "x" + i + " ";
var calls = 0, offsetSum = 0, lastLen = 0;
var out = s.replace(/x(\d+)/g, function (m, d, offset, str) { calls++; offsetSum += offset; lastLen = str.length; return d; });
console.log(calls, offsetSum, lastLen, out.length, out.slice(0, 12));
var u = "éa😀béa😀b";
var seen = [];
u.replace(/a|b/g, function (m, offset, str) { seen.push(m + offset); return m; });
console.log(seen.join(","), u.replace(/b/g, function (m, offset, str) { return "[" + offset + ":" + str.length + "]"; }));
var named = "k1=v1;k2=v2";
console.log(named.replace(/(?<k>\w+)=(?<v>\w+)/g, function () { var a = arguments; var g = a[a.length - 1]; return g.v + "=" + g.k + "@" + a[a.length - 3]; }));
console.log("a.b.c.b".replaceAll("b", function (m, offset, str) { return offset + "/" + str.length; }));
console.log("日x日x".replaceAll("x", function (m, offset) { return "(" + offset + ")"; }));
console.log("abc".replace(/(?:)/g, function (m, offset) { return "<" + offset + ">"; }), "😀z".replace(/(?:)/gu, function (m, offset) { return offset; }));
console.log("no match".replace(/q/g, function () { return "!"; }), "first".replace(/i|s/, function (m, offset) { return offset; }));
"#;

const EXPECTED: &[&str] = &[
    "20000 1228240605 128890 108890 0 1 2 3 4 5 ",
    "a1,b4,a6,b9 \u{e9}a\u{1f600}[4:10]\u{e9}a\u{1f600}[9:10]",
    "v1=k1@0;v2=k2@6",
    "a.2/7.c.6/7",
    "\u{65e5}(1)\u{65e5}(3)",
    "<0>a<1>b<2>c<3> 0\u{1f600}2z3",
    "no match f1rst",
];

#[test]
fn replace_callback_arguments_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root
        .path()
        .join("replace_callback_arguments_bd_9vouw_480.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "replace-callback-args",
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
