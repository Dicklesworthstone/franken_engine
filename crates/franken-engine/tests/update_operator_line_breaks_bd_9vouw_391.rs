//! bd-9vouw.391: a `++` / `--` alone on its line (or after an operator) is
//! the prefix of the next line's operand, since no line terminator may
//! precede a postfix operator (ES2020 11.9.1): `x\n++\ny` is `x; ++y` and
//! `z =\na\n+\n++\nb` is `z = a + ++b`. A postfix update right after its
//! operand still ends the line. The bare `++` line was its own statement
//! ("unsupported expression syntax: +"). The line is Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn bare_update_operator_lines_prefix_the_next_operand() {
    let source = r#"
var x = 0, y = 0;
x
++
y
var a = 5, b = 1;
var z =
a
+
++
b
var p = [1];
p[0]++
var q = 1
q--
console.log(x, y, z, b, p[0], q);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["0 1 7 2 2 0",]);
}
