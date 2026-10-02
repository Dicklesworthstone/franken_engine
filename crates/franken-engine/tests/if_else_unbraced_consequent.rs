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

/// An `else` binds to the nearest unmatched `if` (ES2020 13.6): with an
/// unbraced nested `if` in the consequent, the first `else` is the inner
/// one's. And `return` / `throw` written directly against their operand, as
/// minifiers emit them (`return'x'`, `return[1]`, `return{a:1}`, `return!0`,
/// `return-1`, `return/a+/.test(s)`, `throw"e"`), are statements; they fell
/// through to expression parsing and threw "unsupported expression syntax"
/// when the function ran. Expected string is Node v22.2.0's output.
#[test]
fn dangling_else_and_keyword_adjacent_operands() {
    let source = r#"function f(){return'x'} function g(){return"y"} function h(){return[1]} function k(){return{a:1}} function n(){return!0} function m(){return-1} function r(){return/a+/.test('aa')} function t(){return`t${1}`}
let e; try { (function(){throw"boom"})(); } catch (x) { e = x; }
var a = 0; if (1) if (0) a = 1; else a = 2;
var b = 0; if (0) if (1) b = 1; else b = 2; else b = 3;
var c = 0; if (1) if (1) c = 1; else c = 2; else c = 3;
const o = { if: 5 }; var d = 0; if (1) d = o.if; else d = 9;
[f(), g(), h()[0], k().a, n(), m(), r(), t(), e, a, b, c, d].join(' ');"#;
    assert_eq!(
        eval_to_string(source),
        "x y 1 1 true -1 true t1 boom 2 3 1 5",
        "must match Node v22.2.0"
    );
}

/// Two shapes from jszip's minified bundle that failed to parse, so the
/// whole package failed to load: a loop with an empty body (`;`) as the
/// consequent before `else` ("empty expression statement": the `;` was
/// stripped as if it ended an expression), and a function expression inside
/// an unbraced consequent (`r = c ? function () {...} : 2`), whose body brace
/// ended the if statement. Expected string is Node v22.2.0's output.
#[test]
fn empty_loop_bodies_and_function_expressions_in_unbraced_consequents() {
    let source = r#"var n = 0, o = 3, u = 1; if (u) for (; n++, 0 != --o;); else n = 9;
var w = 2; if (w) while (--w); else w = 9;
var l = 1, r; if (l) r = l ? function () { return 'f'; } : 2; else { r = 3; }
var s; if (0) {} else if (l) s = 'x' in {} ? function () {} : function () { return 'g'; }; else { s = 1; }
var q = 0; if (q) q = 5; else q = function* g(a) { yield a; }; var a2 = [1].map(function (v) { return v + 1; }); if (1) a2 = a2 ? async function () {} : 0;
[n, o, w, r(), s(), typeof q, q(7).next().value, typeof a2].join(' ');"#;
    assert_eq!(
        eval_to_string(source),
        "3 0 0 f g function 7 function",
        "must match Node v22.2.0"
    );
}
