//! bd-9vouw.404: a function declared in a block, a switch's case clauses, a
//! try, catch or finally block is a lexically declared name of that block
//! (ES2020 13.2.1, 13.12.1, 13.15.1), so a `var` of the same name anywhere
//! in the block (nested blocks and loop heads included, nested functions
//! not), a catch parameter of that name, or a second declaration of the
//! name is a SyntaxError, except two plain function declarations in
//! non-strict code (B.3.3.4). The engine ran all of these. Valid forms
//! (function-level `var` + function, plain duplicates in sloppy blocks and
//! switches, B.3.5 catch `var`, class static blocks) still compile and run.
//! The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn block_function_redeclarations_are_syntax_errors() {
    let source = r#"
var cases = [
  "{ function f() {} var f; }",
  "{ var f; function f() {} }",
  "'use strict'; { function f() {} function f() {} }",
  "{ function* f() {} function f() {} }",
  "{ async function f() {} async function f() {} }",
  "{ function f() {} async function* f() {} }",
  "switch (0) { case 1: function f() {} default: var f }",
  "switch (0) { case 1: var f; default: function* f() {} }",
  "{ function f() {} { var f; } }",
  "{ { var f; } function f() {} }",
  "{ for (var f of []) {} function f() {} }",
  "{ function f() {} for (var f in {}) ; }",
  "{ function f() {} if (0) var f; }",
  "{ function f() {} label: var f; }",
  "{ function f() {} try {} catch (f) { var f; } }",
  "try {} catch (f) { function f() {} }",
  "try { function f() {} var f; } catch (e) {}",
  "try {} finally { function f() {} var f; }",
  "l: { function f() {} var f; }",
  "{ class f {} let f; }",
  "{ let f; function f() {} }",
  "switch (0) { case 1: class f {} default: const f = 1; }",
  "{ async function f() {} let f; }",
  "{ function f() {} function f() {} }",
  "switch (0) { case 1: function f() {} default: function f() {} }",
  "var f; function f() {}",
  "{ function f() {} } var f;",
  "var f; { function f() {} }",
  "{ function f() {} } { var f; }",
  "for (var f;;) { function f() {} break; }",
  "{ function f() {} (function () { var f; }); }",
  "try {} catch (f) { var f; }",
  "{ let g; function f() { var g; } }",
  "class C { static { var f; function f() {} } }",
];
console.log(cases.map(function (src, i) {
  try { Function(src); return i + ":ok"; } catch (e) { return i + ":" + e.name; }
}).join(" "));
var r = [];
{ function a() { return 1; } function a() { return 2; } r.push(a()); }
switch (1) { case 1: function b() { return "b1"; } default: function b() { return "b2"; } }
r.push(b());
function g() { var h; function h() { return "h"; } return typeof h; }
r.push(g());
try { throw 1; } catch (e) { var e = 2; r.push(e); }
console.log(r.join());
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
            "0:SyntaxError 1:SyntaxError 2:SyntaxError 3:SyntaxError 4:SyntaxError 5:SyntaxError 6:SyntaxError 7:SyntaxError 8:SyntaxError 9:SyntaxError 10:SyntaxError 11:SyntaxError 12:SyntaxError 13:SyntaxError 14:SyntaxError 15:SyntaxError 16:SyntaxError 17:SyntaxError 18:SyntaxError 19:SyntaxError 20:SyntaxError 21:SyntaxError 22:SyntaxError 23:ok 24:ok 25:ok 26:ok 27:ok 28:ok 29:ok 30:ok 31:ok 32:ok 33:ok",
            "2,b2,function,2",
        ]
    );
}
