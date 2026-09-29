//! Unbraced statement bodies on the line after their header, `else` on its
//! own line after an unbraced consequent, and a `do` body's `while` on its
//! own line. Before this change every one of these failed to parse ("empty
//! expression statement", "unseparated expression sequence", "invalid
//! assignment target"): the logical-line merger joined a header's next line
//! only when it started with `{` (Allman style), and joined `else` only
//! after a `}`. Test262 statements/if/S12.5_A1.2_T1.js, S12.5_A12_T1.js and
//! statements/for/scope-head-lex-open.js failed from it in the 2026-09-27
//! sample; it is a very common style in ES5-era packages. Expected values
//! are Node v22.2.0's for the same programs.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn bodies_and_clauses_on_following_lines() {
    for (source, node) in [
        ("var n = 0;\nif (!n)\n\tn = 1;\nn;", "1"),
        ("var n = 0;\nif (n)\n  n = 1;\nelse\n  n = 2;\nn;", "2"),
        ("var n = 0;\nif (n) n = 1;\nelse n = 3;\nn;", "3"),
        (
            "var n = 5, r;\nif (n < 3) r = 'a';\nelse if (n < 6) r = 'b';\nelse r = 'c';\nr;",
            "b",
        ),
        (
            "var s = 0;\nfor (var i = 0; i < 3; i++)\n  s += i;\ns;",
            "3",
        ),
        ("var k = 0;\nwhile (k < 4)\n  k++;\nk;", "4"),
        ("var e = 0;\ndo\n  e++;\nwhile (e < 3);\ne;", "3"),
        // One line, and an empty-statement body.
        ("var e = 0; do e++; while (e < 3); e;", "3"),
        ("var f = 0; do ; while (f++ < 2); f;", "3"),
        ("var n = 0;\nif (!n)\n  // set it\n  n = 7;\nn;", "7"),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
}

#[test]
fn completed_statements_are_not_extended() {
    for (source, node) in [
        // A block after a completed unbraced if is its own statement.
        ("var n = 0;\nif (!n)\n  n = 1;\n{ n += 10; }\nn;", "11"),
        // A do-while that relies on ASI ends at its condition.
        ("var d = 0;\ndo {\n  d++;\n} while (d < 2)\nd;", "2"),
        // Allman-style do-while: the condition joins its do statement.
        ("var a = 0;\ndo {\n  a++;\n}\nwhile (a < 3);\na;", "3"),
        // An empty-statement loop body is complete on its own line.
        ("var p = 0;\nwhile (p++ < 2);\np;", "3"),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
}

#[test]
fn empty_statement_bodies() {
    // `while (x);` / `for (...);` failed with "empty expression statement":
    // the splitter treated the body `;` as a terminator.
    for (source, node) in [
        ("for (var i = 0; i < 3; i++); i;", "3"),
        ("var a = [1, 2, 0, 4], j; for (j = 0; a[j]; j++); j;", "2"),
        ("var z = 0; if (z) ; else z = 9; z;", "9"),
        ("var w = 3; while (w-- > 0) ; w;", "-1"),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
}
