//! bd-9vouw.28 (second cluster): a brace on its own line after a statement
//! header (Allman style) opens that header's body.
//!
//! The line merger ended the logical line at `function f(a)` / `if (x)` /
//! `else`, so the header was parsed without its body ("function declaration
//! requires a braced body"). Nine Node-passing Test262 sample tests declare
//! `function callbackfn(...)` this way. Expected strings are what Node v22.2.0
//! prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn function_and_class_bodies_on_the_next_line() {
    check("function f(a)\n{\n  return a + 1;\n}\nf(1);", "2");
    check("class A\n{\n  m() { return 1; }\n}\nnew A().m();", "1");
    check("var f = function (a)\n{\n  return a * 2;\n};\nf(3);", "6");
}

#[test]
fn control_statement_bodies_on_the_next_line() {
    check(
        "var r;\nif (true)\n{\n  r = 'y';\n}\nelse\n{\n  r = 'n';\n}\nr;",
        "y",
    );
    check(
        "var r = 0;\nfor (var i = 0; i < 3; i++)\n{\n  r += i;\n}\nr;",
        "3",
    );
    check(
        "var r;\ntry\n{\n  throw 1;\n}\ncatch (e)\n{\n  r = e;\n}\nr;",
        "1",
    );
}

#[test]
fn a_block_after_a_complete_statement_stays_a_block() {
    // `if (false) r = 1` already has its body; the next-line block is a
    // separate statement (ASI), not the if's body.
    check("var r = 0;\nif (false) r = 1\n{ var q = 2; }\nq;", "2");
}
