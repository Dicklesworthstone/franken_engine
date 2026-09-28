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

/// The consequent keeps its terminating `;` through the splitter; it must
/// still parse as a statement. These run the consequent (the cases above
/// mostly take the else branch), which used to throw "SyntaxError:
/// unsupported expression syntax: g();" at run time.
#[test]
fn unbraced_consequents_run_when_their_branch_is_taken() {
    for (source, node) in [
        (
            "function g() { return 'g'; } \
             function f(n) { if (n > 1) return g(); else return 'e'; } f(2) + f(0);",
            "ge",
        ),
        (
            "var out = []; function f(n) { if (n > 1) out.push(n); else out.push(-n); } \
             f(2); f(1); out.join(',');",
            "2,-1",
        ),
        (
            "function h(v){if(v===1)return'one';else if(v===2)return'two';else return'many'} \
             [h(1),h(2),h(3)].join(' ');",
            "one two many",
        ),
        ("var c = 0; if (c === 0) c++; else c--; c;", "1"),
        (
            "var s = ''; if (true) s = 'x'.toUpperCase(); else s = 'y'; s;",
            "X",
        ),
        ("var x = 0; if (x === 0) ; else x = 9; x;", "0"),
        (
            "var n = 0; if (1) for (var i = 0; i < 3; i++) n += i; else n = -1; n;",
            "3",
        ),
        (
            "let s = 5; var out = []; function f(n) { if (n > 1) g(); else out.push(s); } \
             function g() { out.push('g'); } f(2); f(0); out.join(',');",
            "g,5",
        ),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
}
