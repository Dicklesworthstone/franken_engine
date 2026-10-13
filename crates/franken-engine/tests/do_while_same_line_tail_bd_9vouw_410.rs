//! bd-9vouw.410: a do-while statement ends at its condition's `)` (and a
//! `;` right after it); ES2020 11.9.1 inserts the semicolon there even on
//! the same line, so a statement may follow directly. The engine dropped
//! that statement after a braced body (`do { } while (0) x = 42;` never
//! assigned) and refused an unbraced body as unsupported syntax. Bodies:
//! block, simple statement (with `;` inside a string or regular
//! expression), nested do-while. The line is Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn a_statement_after_a_do_while_condition_runs() {
    let source = r#"
var out = [];
var x;
do { break; } while (0) x = 42;
out.push(x);
x = 0;
do x++; while (x < 3) out.push(x);
x = 0;
do do do ; while (x) while (x) while (x) x = 39;
out.push(x);
var s = "", n = 0;
do s += "a;b"; while (s.length < 6) n++;
out.push(s, n);
var r = 0;
do r++; while (/;/.test("x") && r < 5) out.push("re" + r);
x = 0;
do x += 2; while (x < 5); out.push("semi" + x);
x = 0;
do { x++; } while (x < 2)
out.push("next" + x);
console.log(out.join(" "));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["42 3 39 a;ba;b 1 re1 semi6 next2",]);
}
