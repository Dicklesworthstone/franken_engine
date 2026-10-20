//! Counted literal fast paths through the public parser/lowerer/interpreter.
//! Lookaround or backreferences require the production backtracking backend.
//! Expected output was captured from live Node; these Rust tests must also
//! execute successfully before treating the change as native-validated.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &str) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome.console_output.iter()
        .map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [expected]);
}

#[test]
fn public_counted_literals() {
    check(r#"
var out = [];
function shape(re, text) {
  var m = re.exec(text);
  return m === null ? null : [m.index, m[0].length, m[1] === undefined ? null : m[1].length];
}
var twenty = 'ab'.repeat(20) + '!';
out.push(shape(/((?:ab){17,20})ab(?=!)/, twenty));
out.push(shape(/(?=a)((?:ab){17,20}?)ab/, twenty));
out.push(shape(/(?<=((?:ab){17,20}))!/, twenty));
out.push(shape(/(?<=((?:ab){17,20}?))!/, twenty));
out.push(shape(/^((?:ab){17,20})\1(?=!)/, 'ab'.repeat(38) + '!'));
out.push(shape(/^(?:(?:ab){17,20}z|((?:ab){17,20}))(?=!)/, 'ab'.repeat(19) + '!'));
var text = twenty + 'x' + 'ab'.repeat(18) + '!';
var re = /((?:ab){17,20}?)ab(?=!)/g;
var matches = [], m;
while ((m = re.exec(text)) !== null) matches.push([m.index, m[0].length, m[1].length, re.lastIndex]);
out.push(matches);
out.push(re.lastIndex);
re = /((?:ab){17,20})(?=!)/y;
re.lastIndex = 1;
out.push(shape(re, twenty));
out.push(re.lastIndex);
out.push(shape(re, twenty));
out.push(re.lastIndex);
out.push(('x' + 'ab'.repeat(19) + '!y').replace(/((?:ab){17,20})(?=!)/g,
  function (whole, capture) { return '[' + whole.length + ':' + capture.length + ']'; }));
text = 'ab'.repeat(18) + '!' + 'ab'.repeat(19) + '!';
out.push(text.split(/((?:ab){17,20})(?=!)/).map(function (value) { return value.length; }));
out.push(text.match(/(?:ab){17,20}(?=!)/g).map(function (value) { return value.length; }));
out.push(shape(/(?=)((?:ab){0,32}?)/, twenty));
out.push(shape(/^(?:ab){17,20}(?=!)/, 'ab'.repeat(21) + '!'));
console.log(JSON.stringify(out));
"#, r#"[[0,40,38],[0,36,34],[40,1,40],[40,1,34],[0,76,38],[0,38,38],[[0,40,38,40],[42,36,34,78]],0,null,0,[0,40,40],40,"x[38:38]!y",[0,36,1,38,1],[36,38],[0,0,0],null]"#);
}

#[test]
fn public_counted_unicode() {
    check(r#"
var out = [];
function shape(re, text) {
  var m = re.exec(text);
  return m === null ? null : [m.index, m[0].length, m[1] === undefined ? null : m[1].length];
}
var text = '😀é'.repeat(20) + '!';
out.push(shape(/(?<=((?:😀é){17,20}?))!/u, text));
out.push(shape(/(?<=((?:😀é){17,20}))!/u, text));
out.push(shape(/((?:😀é){17,20})😀é(?=!)/u, text));
out.push(shape(/((?:kſ){17,20})(?=!)/iu, 'Ks'.repeat(19) + '!'));
out.push(shape(/((?:kſ){17,20})(?=!)/i, 'Ks'.repeat(19) + '!'));
out.push(shape(/(?<=((?:kſ){17,20}?))!/iu, 'Ks'.repeat(20) + '!'));
out.push(shape(/(?=)((?:ab){0,32}?)(?:ab){17}(?=!)/, 'ab'.repeat(20) + '!'));
out.push(shape(/(?:(?:ab){17,20}?z|((?:ab){17,20}?))(?=!)/, 'ab'.repeat(20) + '!'));
out.push(shape(/^(?!(?:ab){17,20}z)((?:ab){17,20})(?=!)/, 'ab'.repeat(19) + '!'));
console.log(JSON.stringify(out));
"#, r#"[[60,1,51],[60,1,60],[0,60,57],[0,38,38],null,[40,1,34],[0,40,6],[0,40,40],[0,38,38]]"#);
}
