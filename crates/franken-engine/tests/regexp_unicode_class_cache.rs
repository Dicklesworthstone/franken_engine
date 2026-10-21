//! Regression coverage for Unicode class reuse in the native backtracker.
//! Expected outputs were independently executed with Node v22.16.0.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &[&str]) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome.console_output.iter()
        .map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, expected);
}

#[test]
fn unicode_repetitions_keep_captures_case_folding_and_last_index() {
    let source = r#"
var summaries = [];
for (var c of ['é', 'Σ', 'Ж', '😀']) {
  var word = c.repeat(1024);
  var text = '?' + word + '!' + word + '!';
  var re = /(?=)([éΣЖ😀]+?)(?=!)/gu;
  var first = re.exec(text);
  var firstEnd = re.lastIndex;
  var second = re.exec(text);
  var secondEnd = re.lastIndex;
  var ended = re.exec(text) === null && re.lastIndex === 0;
  summaries.push([first.index, first[0].length, first[1] === word,
    firstEnd, second.index, second[1] === word, secondEnd, ended].join(':'));
}
console.log(summaries.join('|'));
var behind = [], re = /(?<=([\p{L}]+))!/gu;
var text = 'éÉ!Σσς!Жя!';
var match;
while ((match = re.exec(text)) !== null) behind.push(match.index + ':' + match[1]);
console.log(behind.join('|'));
var repeated = /(?=)([éΣ]+)\1(?=!)/giu.exec('éΣÉσ!');
var word = /(?=)([\w]+)(?=!)/iu.exec('KſkS!');
console.log(repeated[0] + ':' + repeated[1] + '|' + word[0] + ':' + word[1]);
var sticky = /(?=)([é😀]+)(?=!)/uy;
sticky.lastIndex = 1;
var found = sticky.exec('xé😀!y');
console.log(found.index + ':' + found[0].length + ':' + sticky.lastIndex + '|' +
  (sticky.exec('xé😀!y') === null) + ':' + sticky.lastIndex);
"#;
    check(source, &[
        r#"1:1024:true:1025:1026:true:2050:true|1:1024:true:1025:1026:true:2050:true|1:1024:true:1025:1026:true:2050:true|1:2048:true:2049:2050:true:4098:true"#,
        r#"2:éÉ|6:Σσς|9:Жя"#,
        r#"éΣÉσ:éΣ|KſkS:KſkS"#,
        r#"1:3:4|true:0"#,
    ]);
}

#[test]
fn unicode_class_collisions_keep_negation_replace_split_and_bit_edges() {
    let source = r#"
var choices = ['é', 'ũ', 'ǩ', '\u{10ffe9}'];
var text = choices.map(function (c) { return c + '!'; }).join('').repeat(64);
var positive = /(?=)([é]|[ũ]|[ǩ]|[\u{10ffe9}])(?=!)/gu;
var negative = /(?=)([^é!]+)(?=!)/gu;
var p = Array.from(text.matchAll(positive));
var n = Array.from(text.matchAll(negative));
console.log(p.length + ':' + n.length + ':' + p[0][1] + ':' + p[255][1] + ':' + n[0][1]);
console.log('aéΣbΣc'.split(/(?=)[éΣ]+/u).join('|') + ':' +
  'éΣ!Жя!'.replace(/(?=)([\p{L}]+)(?=!)/gu, function (_, group) { return '[' + group.length + ']'; }));
var checks = [];
for (var c of ['é', 'É', 'Σ', 'σ', 'ς', 'Ж', '😀', '\u0080', '\u{10ffff}']) {
  checks.push([/(?=)[\p{L}]/u.test(c), /(?=)[^\p{L}]/u.test(c),
    /(?=)[é]/u.test(c), /(?=)[É]/iu.test(c)].map(Number).join(''));
}
console.log(checks.join('|'));
var edge = '\u00bf\u00c0\u00ff\u0100\u03bf\u03c0\u03ff\u0400';
var result = edge.match(/(?=)[\u00c0-\u00ff\u03c0-\u03ff]/gu);
console.log(result.map(function (c) { return c.codePointAt(0); }).join(','));
"#;
    check(source, &[
        r#"256:192:é:􏿩:ũ"#,
        r#"a|b|c:[2]![2]!"#,
        r#"1011|1001|1000|1000|1000|1000|0100|0100|0100"#,
        r#"192,255,960,1023"#,
    ]);
}
