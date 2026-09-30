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

/// A loop or `if` whose unbraced body is another header with its own
/// unbraced body on the following line, the layout bundlers (bun, esbuild)
/// emit for single-statement bodies: `for (...)\n  if (x)\n    return;`.
/// Only the first header was joined with its next line, so the inner `if`
/// got an empty consequent ("empty expression statement"); 9 of 37 bundled
/// npm packages (immer, zod, marked, underscore, decimal.js, ...) stopped
/// there. An `else` line pairs with such a nested `if`.
#[test]
fn nested_unbraced_headers_on_following_lines() {
    for (source, node) in [
        (
            "var a = [1, 2], hit = 0, i;\nfor (i = 2;i-- !== 0; )\n  if (a[i] === 2)\n    hit++;\nhit;",
            "1",
        ),
        (
            "function f(a) {\n  var i;\n  for (i = 2;i-- !== 0; )\n    if (!a[i])\n      return false;\n  return true;\n}\n[f([1, 1]), f([0, 1])].join();",
            "true,false",
        ),
        (
            "var n = 0;\nfor (var i = 0; i < 3; i++)\n  for (var j = 0; j < 2; j++)\n    n++;\nn;",
            "6",
        ),
        (
            "var i = 3, c = 0;\nwhile (i-- !== 0)\n  if (i % 2)\n    c++;\n  else\n    c += 10;\nc;",
            "21",
        ),
        (
            "var o = {a: 1, b: 2}, s = '';\nfor (var k in o)\n  if (o[k] > 1)\n    s += k;\ns;",
            "b",
        ),
        (
            "var t = 0;\nif (t === 0)\n  for (var q = 0; q < 3; q++)\n    t += q;\nt;",
            "3",
        ),
        // A `{` inside a header's parentheses (an object literal argument,
        // a destructuring pattern) is not a braced body; js-yaml's bundled
        // visitNode writes `if (visitNode(item, visitor, {` across lines.
        (
            "function visit(n, ctx) { return n === ctx.stop; }\nfunction f(items) {\n  for (const item of items)\n    if (visit(item, {\n      stop: 3\n    }))\n      return \"hit \" + item;\n  return \"none\";\n}\n[f([1, 2, 3]), f([1])].join();",
            "hit 3,none",
        ),
        (
            "var seen = [];\nfor (const { k, v } of [{ k: \"a\", v: 1 }, { k: \"b\", v: 2 }])\n  seen.push(k + v);\nseen.join();",
            "a1,b2",
        ),
        (
            "var o = { a: 1 }, r = \"no\";\nif ({ a: 1 }.a === o.a)\n  r = \"yes\";\nr;",
            "yes",
        ),
        ("var n = 0;\nwhile ([{ x: 1 }][n])\n  n++;\nn;", "1"),
    ] {
        assert_eq!(eval_to_string(source), node, "{source}");
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

/// A do statement as the unbraced body of an `if` or a loop, which js-yaml's
/// bundle writes as `if (...)\n  do\n    ch = ...;\n  while (...);`. The
/// splitter recognised a do statement waiting for its `while` only when the
/// clause began with `do`, so the `;` after the do body ended the whole if
/// statement ("do-while statement requires 'while' after body") and the
/// `while` became a loop of its own.
#[test]
fn do_while_as_an_unbraced_body() {
    for (source, node) in [
        (
            "var x = 0, c = true;\nif (c)\n  do\n    x++;\n  while (x < 3);\nx;",
            "3",
        ),
        (
            "var x = 0, c = true;\nif (c) do x++; while (x < 3);\nx;",
            "3",
        ),
        (
            "var x = 0, c = true;\nif (c) do { x++; } while (x < 3);\nx;",
            "3",
        ),
        (
            "var x = 0, c = false;\nif (c)\n  do\n    x++;\n  while (x < 3);\nelse x = 9;\nx;",
            "9",
        ),
        (
            "var x = 0, n = 0;\nwhile (n++ < 2)\n  do x++; while (x % 3);\n[x, n].join();",
            "6,3",
        ),
        (
            "var s = \"ab#cd\\nef\", p = 2, ch = s.charCodeAt(p), hits = [];\nif (ch === 35)\n  do\n    ch = s.charCodeAt(++p);\n  while (ch !== 10 && ch === ch);\nhits.push(p);\nwhile (p < 4) p++;\n[p, hits].join();",
            "5,5",
        ),
        ("var x = 0;\nl: do x++; while (x < 2);\nx;", "2"),
        // The do statement is the body of the last `else if` (pako's
        // deflate): its `while` lines up with the else clause, not the if.
        (
            "var count = 3, out = [];\nif (false) out.push('a');\nelse if (count > 0)\n  do\n    out.push(count);\n  while (--count !== 0);\nelse out.push('z');\nout.join();",
            "3,2,1",
        ),
        (
            "var n = 2, o = [];\nfor (let i = 0; i < 2; i++)\n  if (i) o.push('x');\n  else if (n)\n    do\n      o.push(n);\n    while (--n);\n  else o.push('z');\no.join();",
            "2,1,x",
        ),
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

/// An unbraced consequent that ends in an object literal or a function body
/// (zod: `if (mime.length === 0) _json.not = {}; else if ...`). The splitter
/// ended the `if` at that closing brace, so `; else ...` became a statement
/// of its own ("unseparated expression sequence").
#[test]
fn unbraced_consequent_ending_in_a_brace() {
    for (source, node) in [
        (
            "var j = {}; if (1) j.x = {}; else j.y = 2; JSON.stringify(j);",
            r#"{"x":{}}"#,
        ),
        (
            "var j = {}, m = [7]; if (m.length === 0) j.not = {}; else if (m.length === 1) \
             j.c = m[0]; else j.a = m.map((v) => ({ c: v })); JSON.stringify(j);",
            r#"{"c":7}"#,
        ),
        (
            "var j = {}, m = [];\nif (m.length === 0)\n  j.not = {};\nelse if (m.length === 1)\n  \
             j.c = m[0];\nelse\n  j.a = 1;\nJSON.stringify(j);",
            r#"{"not":{}}"#,
        ),
        (
            "var f; if (0) f = function () { return 1; }; else f = () => { return 2; }; f();",
            "2",
        ),
        (
            "var o, n = 0; if (1) o = { a: 1 }, n = 5; [o.a, n].join();",
            "1,5",
        ),
    ] {
        assert_eq!(
            eval_to_string(source),
            node,
            "`{source}` must match Node v22.2.0"
        );
    }
    // `if (a) {}; else b` stays a syntax error: that `;` is an empty
    // statement after the if.
    assert!(
        eval_to_string("var b = 0; if (1) { b = 1 }; else b = 2; b;").starts_with("ERROR"),
        "an else after `{{}};` has no if"
    );
}
