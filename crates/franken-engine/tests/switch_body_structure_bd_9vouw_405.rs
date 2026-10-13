//! bd-9vouw.405: a switch body holds case clauses and at most one default
//! clause (ES2020 13.12). A second `default`, a `default` without its colon
//! and a statement before the first clause are SyntaxErrors. The engine
//! accepted a second default, and on any other content it stopped reading
//! clauses and silently dropped the rest of the body. Valid bodies (empty,
//! default between cases, nested switches, `default` as a property name)
//! still compile and run in clause order. The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn switch_bodies_hold_only_clauses_and_one_default() {
    let source = r#"
var cases = [
  "switch (0) { default: default: }",
  "switch (0) { case 0: default: break; default: break; }",
  "switch (0) { x = 1; case 0: }",
  "switch (0) { default }",
  "switch (0) { default 1: }",
  "switch (0) { }",
  "switch (0) { default: }",
  "switch (0) { case 0: default: case 1: }",
  "switch (0) { case 0: var o = { default: 1 }; o.default; }",
  "switch (1) { case 1: x = 1; default: }",
  "switch (0) { case 0: switch (1) { default: } default: }",
];
console.log(cases.map(function (src, i) {
  try { Function(src); return i + ":ok"; } catch (e) { return i + ":" + e.name; }
}).join(" "));
function run(v) {
  var out = [];
  switch (v) {
    case 0: out.push("zero");
    default: out.push("default");
    case 1: out.push("one"); break;
    case 2: out.push("two");
  }
  return out.join("+");
}
console.log(run(0), run(1), run(2), run(3));
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
            "0:SyntaxError 1:SyntaxError 2:SyntaxError 3:SyntaxError 4:SyntaxError 5:ok 6:ok 7:ok 8:ok 9:ok 10:ok",
            "zero+default+one one two default+one",
        ]
    );
}
