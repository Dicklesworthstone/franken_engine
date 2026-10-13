//! bd-9vouw.475: RegExp exec with lastIndex and indexOf/lastIndexOf with a
//! position no longer decode or copy the whole string per call (ASCII subjects
//! use byte offsets as unit offsets; the subject is shared, not copied). This
//! pins what programs observe to Node v22.2.0: a /g exec loop over 18,000
//! characters (count, index sum, lastIndex), exec from a set lastIndex with the
//! match's input and the legacy statics, a /y tokenizer, named groups, /d
//! indices, the same loop over a non-ASCII string with supplementary
//! characters, a subject with a lone surrogate (its match's input is the
//! subject itself), an advancing indexOf scan over 22,890 characters, and
//! indexOf/lastIndexOf/includes edge positions (past the end, negative,
//! empty, non-ASCII and lone-surrogate needles) on ASCII and non-ASCII strings.

use std::process::Command;

const PROGRAM: &str = r#"var s = "";
for (var i = 0; i < 3000; i++) s += "word" + (i % 10) + " ";
var re = /(\w)(\w*)/g, m, count = 0, lastIdx = 0, indexSum = 0;
while ((m = re.exec(s)) !== null) { count++; indexSum += m.index; lastIdx = re.lastIndex; }
console.log(count, indexSum, lastIdx, re.lastIndex, s.length);
re.lastIndex = 6;
m = re.exec(s);
console.log(m.index, m[0], m[1], m[2], m.input === s, m.input.length, re.lastIndex, RegExp.$1, RegExp.lastMatch, RegExp.input.length, RegExp.leftContext.length, RegExp.rightContext.length);
var sticky = /word|\d|\s+/y, tokens = 0;
sticky.lastIndex = 0;
while (sticky.lastIndex < s.length && sticky.exec(s)) tokens++;
console.log(tokens, sticky.lastIndex);
var named = /(?<w>w\w+)(?<d>\d)/g;
var nm = named.exec(s);
console.log(nm.groups.w, nm.groups.d, nm.index, named.lastIndex);
var withIndices = /o(r)d/dg;
withIndices.lastIndex = 5;
var di = withIndices.exec(s);
console.log(JSON.stringify(di.indices), di.index, withIndices.lastIndex);
var u = "été 😀 café 日本 ";
var ut = "";
for (var j = 0; j < 200; j++) ut += u;
var ure = /(\S+)/g, uc = 0, ulast = 0, uidx = 0;
while ((m = ure.exec(ut)) !== null) { uc++; uidx += m.index; ulast = ure.lastIndex; }
console.log(uc, uidx, ulast, ut.length, ure.lastIndex);
var lone = "a\ud800b a\ud800b";
var lre = /a.b/g, lm = lre.exec(lone);
console.log(lm.index, lre.lastIndex, lm[0].length, lm.input.length, lm.input.charCodeAt(1).toString(16));
var csv = "";
for (var k = 0; k < 4000; k++) csv += "f" + k + ",";
var p = 0, fields = 0, lastField = -1;
while ((p = csv.indexOf(",", p)) !== -1) { fields++; lastField = p; p++; }
console.log(fields, lastField, csv.indexOf("f3999"), csv.lastIndexOf("f1,"), csv.lastIndexOf(",", 10), csv.indexOf(",", -5), csv.indexOf("", 99999), csv.lastIndexOf("", 7), csv.indexOf("é"), csv.lastIndexOf("é"), csv.includes("f2000,"), csv.indexOf("\ud800"), csv.lastIndexOf("f", 0), csv.lastIndexOf("f0", 0));
var ascii = "abcabcabc";
console.log(ascii.indexOf("abc", 1), ascii.indexOf("abc", 7), ascii.lastIndexOf("abc"), ascii.lastIndexOf("abc", 5), ascii.lastIndexOf("abc", -1), ascii.lastIndexOf("abcabcabcd"), ascii.indexOf("c", 8), ascii.indexOf("c", 9), ascii.lastIndexOf("c", 100));
var mixed = "xéyxéy";
console.log(mixed.indexOf("x", 1), mixed.lastIndexOf("é"), mixed.indexOf("y", 3), mixed.lastIndexOf("xé", 2));
"#;

const EXPECTED: &[&str] = &[
    "3000 26991000 17999 0 18000",
    "6 word1 w ord1 true 18000 11 w word1 18000 6 17989",
    "9000 18000",
    "word 0 0 5",
    "[[7,10],[8,9]] 7 10",
    "800 1198600 2999 3000 0",
    "0 3 3 7 d800",
    "4000 22889 22884 3 8 2 22890 7 -1 -1 true -1 0 0",
    "3 -1 6 3 0 -1 8 -1 8",
    "3 4 5 0",
];

#[test]
fn regexp_exec_and_index_of_scans_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("string_scan_loops_bd_9vouw_475.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "string-scan-loops",
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
