//! bd-9vouw.90: a `while` loop that follows a block on the same line never
//! ran. The statement splitter treated `while` after any closing brace as a
//! do statement's condition, so `if (a) {...} while (c) {...}` became one if
//! statement and the loop was silently dropped (`function f(a) { let n = 0;
//! if (a) { n = 10; } while (n < 3) { n++; } return n; }` returned 0 for
//! f(0)). Minifiers emit exactly this shape (`if(a){b=5}while(b<4){b++}`);
//! punycode 2.3.1 encoded 'mañana' as 'xn--maana-.com' because of it. A line
//! break before the `while` hid the bug. Expected values are Node v22.2.0's
//! completion values for the same programs (`vm.runInThisContext`).

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn a_while_after_a_block_is_its_own_loop() {
    for (source, node) in [
        (
            "function f(a) { let n = 0; if (a) { n = 10; } while (n < 3) { n++; } return n; } \
             [f(0), f(1)].join();",
            "3,10",
        ),
        (
            "var n = 0; if (0) { n = 10; } while (n < 3) { n++; } n;",
            "3",
        ),
        (
            "function f(a) { let n = 0; if (a) { n = 10; } else { n = 1; } \
             while (n < 3) { n++; } return n; } [f(0), f(1)].join();",
            "3,10",
        ),
        ("var a = 0, b = 0; if(a){b=5}while(b<4){b++} b;", "4"),
        (
            "var i; for (i = 0; i < 2; i++) {} while (i < 5) { i++; } i;",
            "5",
        ),
        (
            "var k = 0; try { k = 1; } catch (e) {} while (k < 4) { k++; } k;",
            "4",
        ),
        ("var m = 0; function g() {} while (m < 2) { m++; } m;", "2"),
        ("var q = 0; { q = 1; } while (q < 3) { q++; } q;", "3"),
        (
            "var z = 0; outer: { z = 1; } while (z < 3) { z++; } z;",
            "3",
        ),
    ] {
        assert_eq!(eval_to_string(source), node, "{source}");
    }
}

#[test]
fn a_do_statement_keeps_its_while() {
    // No-claim: a statement right after a do-while's condition on the same
    // line, with no `;` (`do {..} while (c) while (d) {..}`, legal through
    // the automatic semicolon after a do-while), still loses that statement.
    assert_eq!(
        eval_to_string("var d = 0; do { d++; } while (d < 3); d;"),
        "3"
    );
    assert_eq!(
        eval_to_string(
            "var d = 0, w = 0; do { d++; } while (d < 2); while (w < 3) { w++; } [d, w].join();"
        ),
        "2,3"
    );
}
