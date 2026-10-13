//! bd-9vouw.391: a line that starts with a relational or shift operator
//! (`>>`, `>>>`, `<`, `>=`, `<<`, `>`) continues the expression on the
//! previous line: `<` and `>` cannot begin an expression, so no semicolon
//! is inserted. Such a line was parsed as a new statement ("expression
//! begins with a binary operator with no left-hand operand"). The line is
//! Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn lines_starting_with_relational_or_shift_operators_continue() {
    let source = r#"
var y = 16;
var z = 3;
var a
=
y
>>
z
;
var b = y
  >>> 1;
var c = z
  < y;
var d = y
  >= z;
var e = 1
  << 4;
var f = y
  > 100
  ? "big"
  : "small";
console.log(a, b, c, d, e, f);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["2 8 true true 16 small",]);
}
