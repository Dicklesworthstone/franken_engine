//! Native RegExp workspace and assertion capture regressions through frankenctl.
//! Expected console output was checked with Node v22.16.0, independently of
//! the native executor. Node execution is not a native Rust test result.

use std::process::Command;

const GLOBAL: &str = r#"var text = 'abab';
var regexp = /(?<=(a))(b)|a/g;
console.log(JSON.stringify(text.match(regexp)), regexp.lastIndex);
var calls = [];
var replaced = text.replace(regexp, function(whole, left, b, offset, source) {
  calls.push([whole, left, b, offset, source === text]);
  return '[' + whole + ']';
});
console.log(replaced, JSON.stringify(calls), regexp.lastIndex);
console.log(JSON.stringify(text.split(/(?<=(a))(b)/)));
console.log(JSON.stringify('abc'.match(/(?=)b*/g)));
var long = 'abab'.repeat(256);
var count = 0;
var checksum = 0;
var result = long.replace(regexp, function(whole, left, b, offset) {
  if (whole === 'a') {
    if (left !== undefined || b !== undefined) throw 'stale capture';
  } else if (left !== 'a' || b !== 'b') throw 'lost lookbehind capture';
  checksum += offset + (left === undefined ? 1 : 3);
  count++;
  return whole;
});
console.log(result === long, count, checksum, regexp.lastIndex);
"#;

const GLOBAL_EXPECTED: &[&str] = &[
    r#"["a","b","a","b"] 0"#,
    r#"[a][b][a][b] [["a",null,null,0,true],["b","a","b",1,true],["a",null,null,2,true],["b","a","b",3,true]] 0"#,
    r#"["a","a","b","a","a","b",""]"#,
    r#"["","b","",""]"#,
    r#"true 1024 525824 0"#,
];

const ASSERTIONS: &str = r#"var cases = [
  [/(?=(a|ab))\1c/, 'abc'],
  [/(?=(a+))a*b\1/, 'baaabac'],
  [/(.*?)a(?!(a+)b\2c)\2(.*)/, 'baaabaac'],
  [/(?<=(\d+)(\d+))$/, '1053'],
  [/(?<=\1(a))b/, 'aab'],
  [/((?=(a+))a*b\2)|a/, 'baaabac'],
  [/(?=(a(?=(b))))ab|b/, 'ab'],
  [/(?!(?=(a))a)b|a/, 'ab'],
  [/(?=((a)|(b))+)/, 'ab'.repeat(512)],
  [/(?:(a)|(b)){17,20}(?=)/, 'a'.repeat(10) + 'b'.repeat(8)],
  [/(?<=(a){17,20})b/, 'a'.repeat(25) + 'b'],
  [/(?=(a|b)+)\1/, 'abba'],
  [/(?<!(a|b))c|(a)/, 'ac'],
  [/(?=(é(😀)))é😀/u, 'xé😀z']
];
for (var i = 0; i < cases.length; i++) {
  var match = cases[i][0].exec(cases[i][1]);
  console.log(JSON.stringify(match === null ? null : [match.index, match]));
}
var sticky = /(?<=(a))(b)|a/y;
sticky.lastIndex = 1;
var found = sticky.exec('abab');
console.log(JSON.stringify([found.index, found]), sticky.lastIndex);
sticky.lastIndex = 4;
console.log(sticky.exec('abab'), sticky.lastIndex);
"#;

const ASSERTIONS_EXPECTED: &[&str] = &[
    r#"null"#,
    r#"[3,["aba","a"]]"#,
    r#"[0,["baaabaac","ba",null,"abaac"]]"#,
    r#"[4,["","1","053"]]"#,
    r#"[2,["b","a"]]"#,
    r#"[1,["a",null,null]]"#,
    r#"[0,["ab","a","b"]]"#,
    r#"[0,["a",null]]"#,
    r#"[0,["","b",null,"b"]]"#,
    r#"[0,["aaaaaaaaaabbbbbbbb",null,"b"]]"#,
    r#"[25,["b","a"]]"#,
    r#"[0,["a","a"]]"#,
    r#"[0,["a",null,"a"]]"#,
    r#"[1,["é😀","é😀","😀"]]"#,
    r#"[1,["b","a","b"]] 2"#,
    r#"null 0"#,
];

fn run(source: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("temporary directory");
    let entry = root.path().join("regexp_workspace.js");
    let report = root.path().join("report.json");
    std::fs::write(&entry, source).expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("UTF-8 path"),
            "--extension-id",
            "regexp-workspace",
            "--instruction-budget",
            "10000000",
            "--out",
            report.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run frankenctl");
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read report")).expect("JSON report");
    let actual = report["console_output"]
        .as_array()
        .expect("console output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn global_match_replace_split_and_capture_reset_match_node() {
    run(GLOBAL, GLOBAL_EXPECTED);
}

#[test]
fn atomic_nested_backward_and_sticky_assertions_match_node() {
    run(ASSERTIONS, ASSERTIONS_EXPECTED);
}
