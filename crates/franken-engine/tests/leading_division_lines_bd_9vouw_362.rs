//! bd-9vouw.362: a line starting with `/` after a line that ends an
//! expression continues it as a division (ES2020 11.9.1: no semicolon is
//! inserted; the goal symbol after an expression is InputElementDiv).
//! `x = 18⏎/⏎2⏎/⏎9` is 1 and `a⏎/g/i` is a / g / i; the parser started a
//! new statement with a regex literal, which computed 18 and, for
//! `(total)⏎  / count;`, failed the whole script. A comment line in between
//! is skipped; after a block `}`, `return` and `;` a leading `/` still starts
//! a regex statement. The line is Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn a_line_starting_with_a_slash_continues_as_division() {
    let source = r#"
var out = [];
var x = 18
/
2
/
9
;
out.push('chain=' + x);
var a = 10, g = 2, i = 1;
var y = a
/g/i;
out.push('flags-like=' + y);
var total = 84, count = 4;
var avg = (total)
  / count;
out.push('paren=' + avg);
var arr = [9, 3];
var q = arr[0]
  // a comment line in between
  / arr[1];
out.push('comment=' + q);
var s = 'abcabc';
var str = s.length
/ 3;
out.push('member=' + str);
function f() { return 7 }
var r = f()
/ 7;
out.push('call=' + r);
var tpl = `${4}`
/ 2;
out.push('template=' + tpl);
var block = {};
if (true) {}
/b/.test('abc') && out.push('regex-after-block');
function h() {
  return
  /x/.test('x');
}
out.push('return=' + h());
var u;
;/y/.test('y') && out.push('regex-after-semicolon');
var re = /a/g
/ 1;
out.push('regex-then-division=' + re);
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "chain=1 flags-like=5 paren=21 comment=3 member=2 call=1 template=2 regex-after-block return=undefined regex-after-semicolon regex-then-division=NaN",
        ]
    );
}
