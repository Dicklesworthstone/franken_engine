//! bd-9vouw.294: a Statement (the body of an if, else, loop or `with`
//! header, or of a label) is never a lexical declaration, so a sloppy `let`
//! there is an identifier, and a line break after it ends that expression
//! statement unless the next line continues the expression (ES2020 13.5
//! lookahead, 11.9.1). The parser joined `if (true) let` with the next line
//! `x = 1;` and refused `let x = 1` as a declaration in statement position
//! (14 Node-passing Test262 tests, language/statements/*/let-*-with-newline).
//! A following `(` still continues (`let` is called), a following `[` still
//! makes the refused `let [`, a `let` heading a statement list still
//! declares across a line break, and strict code still refuses `let`.
//! Node v22.2.0 gives these lines and verdicts; Bun 1.4.2 agrees on the
//! output.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::parser_api_stability::parse_script;

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

#[test]
fn a_statement_position_let_ends_at_its_line_break() {
    let source = r#"
var out = [];
var let = 'L', x, y, z, w, q, r;
if (true) let
x = 1;
out.push(x);
for (var i in { a: 1 }) let // ASI
y = 2;
out.push(y);
while (false) let
{ z = 3; }
out.push(z);
L: let
w = 4;
out.push(w);
if (false) ; else let
q = 5;
out.push(q);
do let
while (false);
if (false) let // ASI
{ out.push('block'); }
let = function (v) { out.push('called ' + v); return 'r'; };
if (true) let
('arg');
with ({}) let
r = 6;
out.push(r);
let = 7;
out.push(let);
console.log(out.join(' '));
"#;
    assert_eq!(console_lines(source), ["1 2 3 4 5 block called arg 6 7"]);
}

#[test]
fn a_let_heading_a_statement_list_still_declares_across_a_line_break() {
    let source = r#"
let
v = 6;
{
  let
  k = 7;
  console.log(typeof v, v, k);
}
"#;
    assert_eq!(console_lines(source), ["number 6 7"]);
}

#[test]
fn let_bracket_in_statement_position_and_strict_let_stay_errors() {
    for source in [
        "if (false) let\n[a] = 1;",
        "L: let\n[a] = 1;",
        "while (false) let\n[a] = 1;",
        "\"use strict\"; if (false) let\nx = 1;",
        "\"use strict\"; let = 1;",
    ] {
        assert!(
            parse_script(source).is_err(),
            "Node refuses {source:?}, the parser accepted it"
        );
    }
}
