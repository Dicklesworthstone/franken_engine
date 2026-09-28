//! An if statement whose consequent is an unbraced statement ending in `;`
//! (`if (c) x = 1; else x = 2;`, `if (a) return 1; else return 2;`,
//! `if(t)t=1;else t=5`) failed to parse with "unseparated expression
//! sequence": the statement splitter ended the statement at the `;`, leaving
//! `else ...` as a statement of its own. Only braced consequents worked.
//! This is everyday code and endemic in minified packages; Test262
//! statements/for/head-init-expr-check-empty-inc-empty-syntax.js and
//! built-ins/Array/prototype/some/15.4.4.17-8-10.js are two sample failures
//! from it. Expected values are Node v22.2.0's for the same programs.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn unbraced_consequents_keep_their_else() {
    for (source, node) in [
        ("var c = 0; if (c) c = 1; else c = 2; c;", "2"),
        (
            "function f(a) { if (a) return 1; else return 2; } f(0);",
            "2",
        ),
        (
            "function g(a) { if (a) return; else a = 1; return a; } g(0);",
            "1",
        ),
        (
            "var c = 0; for (;;) { if (c === 1) break; else c++; } c;",
            "1",
        ),
        (
            "var c = 0; for (;;) { c++; if (c < 2) continue; else break; } c;",
            "2",
        ),
        (
            "var c = 0; L: for (;;) { if (c === 1) break L; else c++; } c;",
            "1",
        ),
        (
            "function h(a) { if (a) throw new Error('x'); else return 3; } h(0);",
            "3",
        ),
        (
            "var r = ''; for (var i = 0; i < 3; i++) if (i === 0) r += 'a'; \
             else if (i === 1) r += 'b'; else r += 'c'; r;",
            "abc",
        ),
        ("var s = 0; if (1) if (0) s = 1; else s = 2; s;", "2"),
        ("var t = 0; if(t)t=1;else t=5; t;", "5"),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
}
