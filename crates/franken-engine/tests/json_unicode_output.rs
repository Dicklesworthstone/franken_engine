//! Unicode JSON output through the production CLI, not a codec-only model.
//! Expected console lines were executed under Node v22.16.0. Native execution
//! must be checked separately; this test contains no comparative timing claim.

use std::process::Command;

fn assert_json_program(program: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("json_unicode_output.js");
    std::fs::write(&entry, program).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("UTF-8 entry path"),
            "--extension-id",
            "json-unicode-output",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("UTF-8 report path"),
        ])
        .output()
        .expect("execute frankenctl");
    assert!(
        output.status.success(),
        "frankenctl failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("JSON report");
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect();
    assert_eq!(lines, expected);
}

const QUOTES_AND_RAW: &str = r#"
function checksum(text) {
  var sum = 0;
  for (var i = 0; i < text.length; i++) sum += text.charCodeAt(i);
  return sum;
}
var specials = String.fromCharCode(0, 8, 9, 10, 12, 13, 34, 92, 0xd800, 65, 0xdc00, 0xd83d, 0xde00);
var texts = ['aé日😀'.repeat(3000), specials.repeat(400), 'ascii'.repeat(2000) + '日'];
for (var t = 0; t < texts.length; t++) {
  var text = texts[t];
  var quoted = JSON.stringify(text);
  var raw = JSON.rawJSON(quoted);
  var array = JSON.stringify([text, raw]);
  console.log(text.length, quoted.length, checksum(quoted), JSON.parse(quoted) === text,
    array === '[' + quoted + ',' + quoted + ']');
}
var digits = '12345' + '67890'.repeat(400);
var numeric = JSON.stringify({number: JSON.rawJSON(digits)});
console.log(numeric.length, numeric === '{"number":' + digits + '}');
var spelling = '"\\u00e9' + '日😀'.repeat(500) + '\\ud800"';
var preserved = JSON.stringify({raw: JSON.rawJSON(spelling)});
console.log(preserved.length, preserved === '{"raw":' + spelling + '}',
  JSON.parse(preserved).raw.charCodeAt(1501));
"#;

const HOOKS_AND_RECOVERY: &str = r#"
var text = 'aé日😀'.repeat(300);
var events = [];
var child = {toJSON: function (key) { events.push('toJSON:' + key); return text + 'X'; }};
var root = {first: child, middle: 0, last: 'old'};
Object.defineProperty(root, 'middle', {enumerable: true, get: function () {
  events.push('get:middle');
  root.last = JSON.parse(JSON.stringify(text + 'Y'));
  root.added = 'not enumerated';
  return JSON.rawJSON(JSON.stringify(text + 'Z'));
}});
var output = JSON.stringify(root, function (key, value) {
  events.push('replace:' + key);
  return key === 'first' ? value + 'R' : value;
}, '  ');
var decoded = JSON.parse(output);
console.log(events.join('|'));
console.log(decoded.first === text + 'XR', decoded.middle === text + 'Z', decoded.last === text + 'Y',
  Object.keys(decoded).join(','));
var thrown = {tag: 'original'};
var dangerous = {before: text};
Object.defineProperty(dangerous, 'after', {enumerable: true, get: function () {
  JSON.stringify({nested: text});
  throw thrown;
}});
var same = false;
try { JSON.stringify(dangerous); } catch (error) { same = error === thrown; }
var cycle = {before: text}; cycle.self = cycle;
var cycleError = false;
try { JSON.stringify(cycle); } catch (error) { cycleError = error instanceof TypeError; }
var bigintError = false;
try { JSON.stringify({before: text, after: 1n}); } catch (error) { bigintError = error instanceof TypeError; }
console.log(same, cycleError, bigintError, JSON.parse(JSON.stringify(text)) === text);
var nested = JSON.stringify([text, text], function (key, value) {
  return typeof value === 'string' ? JSON.stringify(value) : value;
});
var restored = JSON.parse(nested);
console.log(restored.length, JSON.parse(restored[0]) === text, JSON.parse(restored[1]) === text);
"#;

const EXACT_INDENTATION: &str = r#"
function checksum(text) {
  var sum = 0;
  for (var i = 0; i < text.length; i++) sum += text.charCodeAt(i);
  return sum;
}
var text = '日😀'.repeat(300);
var value = {a: {b: text}, c: ['é', text]};
var gap = 'é'.repeat(9) + '😀';
var truncated = JSON.stringify(value, null, gap);
console.log(truncated.length, checksum(truncated), truncated.split('\n')[1].charCodeAt(9));
var halves = JSON.stringify(value, null, '\udc00é\ud800');
console.log(halves.length, checksum(halves), halves.indexOf('\ud800\udc00') >= 0);
var pretty = JSON.stringify(value, null, 10);
console.log(JSON.parse(pretty).a.b === text, JSON.parse(pretty).c[0] === 'é', pretty.length);
"#;

#[test]
fn large_unicode_quotes_and_raw_json_preserve_exact_spelling() {
    assert_json_program(
        QUOTES_AND_RAW,
        &[
            "15000 15002 415812068 true true",
            "5200 14002 45972068 true true",
            "10001 10003 1068153 true true",
            "2016 true",
            "1522 true 55296",
        ],
    );
}

#[test]
fn unicode_output_preserves_reentrant_hooks_and_abrupt_recovery() {
    assert_json_program(
        HOOKS_AND_RECOVERY,
        &[
            "replace:|toJSON:first|replace:first|get:middle|replace:middle|replace:last",
            "true true true first,middle,last",
            "true true true true",
            "2 true true",
        ],
    );
}

#[test]
fn unicode_indentation_keeps_exact_utf16_and_the_ten_unit_limit() {
    assert_json_program(
        EXACT_INDENTATION,
        &[
            "1938 83540993 55357",
            "1868 84084943 true",
            "true true 1938",
        ],
    );
}
