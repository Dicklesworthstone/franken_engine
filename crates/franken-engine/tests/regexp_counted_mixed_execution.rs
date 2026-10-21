//! Mixed fixed-width counted bodies through the production JavaScript pipeline.
//! Assertions and backreferences select the native backtracking backend.
//! These literal outputs were independently verified with Node v22.16.0;
//! native execution is a separate required check, not supplied by that oracle.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &str) {
    let outcome = HybridRouter::default().eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome.console_output.iter()
        .map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [expected]);
}

#[test]
fn counted_mixed_execution_and_backtracking() {
    check(r#"
var out = [];
function shape(re, text) {
  var m = re.exec(text);
  return m === null ? null : [m.index, m[0].length, m[1] === undefined ? null : m[1].length];
}
var twenty = 'a7z'.repeat(20) + '!';
out.push(shape(/((?:a[0-9].){17,20})a[0-9].(?=!)/, twenty));
out.push(shape(/(?=a)((?:a[0-9].){17,20}?)a[0-9]./, twenty));
out.push(shape(/(?<=((?:a[0-9].){17,20}))!/, twenty));
out.push(shape(/(?<=((?:a[0-9].){17,20}?))!/, twenty));
out.push(shape(/^((?:a[0-9].){17,20})\1(?=!)/, 'a7z'.repeat(38) + '!'));
out.push(shape(/^(?:(?:a[0-9].){17,20}q|((?:a[0-9].){17,20}))(?=!)/, 'a7z'.repeat(19) + '!'));
var text = twenty + 'x' + 'a8y'.repeat(18) + '!';
var re = /((?:a[0-9].){17,20}?)a[0-9].(?=!)/g;
var matches = [], m;
while ((m = re.exec(text)) !== null) matches.push([m.index, m[0].length, m[1].length, re.lastIndex]);
out.push(matches);
out.push(re.lastIndex);
re = /((?:a[0-9].){17,20})(?=!)/y;
re.lastIndex = 1;
out.push(shape(re, twenty));
out.push(re.lastIndex);
out.push(shape(re, twenty));
out.push(re.lastIndex);
out.push(('x' + 'a7z'.repeat(19) + '!y').replace(/((?:a[0-9].){17,20})(?=!)/g,
  function (whole, capture) { return '[' + whole.length + ':' + capture.length + ']'; }));
text = 'a7z'.repeat(18) + '!' + 'a8y'.repeat(19) + '!';
out.push(text.split(/((?:a[0-9].){17,20})(?=!)/).map(function (value) { return value.length; }));
out.push(text.match(/(?:a[0-9].){17,20}(?=!)/g).map(function (value) { return value.length; }));
out.push(shape(/(?=)((?:[0-9].){0,32}?)/, twenty));
out.push(shape(/^(?:a[0-9].){17,20}(?=!)/, 'a7z'.repeat(21) + '!'));
out.push(shape(/^((?:[a-z]\d.){512})(?=!)/, 'a7z'.repeat(512) + '!'));
console.log(JSON.stringify(out));
"#, r#"[[0,60,57],[0,54,51],[60,1,60],[60,1,51],[0,114,57],[0,57,57],[[0,60,57,60],[62,54,51,116]],0,null,0,[0,60,60],60,"x[57:57]!y",[0,54,1,57,1],[54,57],[0,0,0],null,[0,1536,1536]]"#);
}

#[test]
fn counted_mixed_unicode_and_observable_regex_protocols() {
    check(r#"
var out = [];
function shape(re, text) {
  var m = re.exec(text);
  return m === null ? null : [m.index, m[0].length, m[1] === undefined ? null : m[1].length];
}
var text = '😀éz'.repeat(20) + '!';
out.push(shape(/(?<=((?:😀[é].){17,20}?))!/u, text));
out.push(shape(/(?<=((?:😀[é].){17,20}))!/u, text));
out.push(shape(/((?:😀[é].){17,20})😀[é].(?=!)/u, text));
out.push(shape(/((?:k[ſ].){17})(?=!)/isu, 'Ks\n'.repeat(17) + '!'));
out.push(shape(/((?:k[ſ].){17})(?=!)/iu, 'Ks\n'.repeat(17) + '!'));
out.push(shape(/((?:k[ſ].){17})(?=!)/is, 'Ks\n'.repeat(17) + '!'));
out.push(shape(/(?<=((?:[A-Z]\d.){17,20}?))!/i, 'a7z'.repeat(20) + '!'));
out.push(shape(/((?:\p{Letter}\d.){17})(?=!)/u, 'é7z'.repeat(17) + '!'));
out.push(shape(/((?:\ud800[0-9].){17})(?=!)/, '\ud8007z'.repeat(17) + '!'));
out.push(shape(/^(a[0-9].){17}(?=!)/, 'a7z'.repeat(17) + '!'));
out.push(shape(/^(?:a[0-9]|bc){17}(?=!)/, 'a7'.repeat(17) + '!'));
out.push(shape(/^((?:[0-9]?a){17})(?=!)/, 'a'.repeat(17) + '!'));
var endings = ['\n', '\r', '\u2028', '\u2029'];
var dotChecks = [];
for (var i = 0; i < endings.length; i++) {
  text = ('a7' + endings[i]).repeat(17) + '!';
  dotChecks.push([/^(?:a[0-9].){17}(?=!)/.test(text), /^(?:a[0-9].){17}(?=!)/s.test(text)]);
}
out.push(dotChecks);
console.log(JSON.stringify(out));
"#, r#"[[80,1,68],[80,1,80],[0,80,76],[0,51,51],null,null,[60,1,51],[0,51,51],[0,51,51],[0,51,3],[0,34,null],[0,17,17],[[false,true],[false,true],[false,true],[false,true]]]"#);
}
