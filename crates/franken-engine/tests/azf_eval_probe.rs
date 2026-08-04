//! AzureFinch eval-probe sweep (REVIEW mode, surface new engine gaps).
//! Read-only: evaluates many small JS snippets through HybridRouter and prints
//! value-or-error. NOT assertions — a triage aid to find unimplemented/wrong
//! behavior. Run with --nocapture.
use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => format!("OK={}", o.value),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn azf_probe() {
    let cases: &[(&str, &str)] = &[
        // control flow / errors
        (
            "try/catch",
            "let x = 0; try { throw 1; } catch (e) { x = e; } x;",
        ),
        (
            "try/finally",
            "let x = 0; try { x = 1; } finally { x = x + 10; } x;",
        ),
        ("throw/catch value", "try { throw 42; } catch (e) { e; }"),
        (
            "switch",
            "let x = 2; let r = 0; switch (x) { case 1: r = 10; break; case 2: r = 20; break; default: r = 99; } r;",
        ),
        (
            "do-while",
            "let i = 0; let s = 0; do { s = s + i; i = i + 1; } while (i < 4); s;",
        ),
        ("ternary", "let x = 5; x > 3 ? 1 : 0;"),
        ("nullish", "let a = null; a ?? 7;"),
        ("optional-chain", "let o = {a: {b: 3}}; o.a?.b;"),
        ("logical-and-value", "let a = 2; a && 9;"),
        // functions
        ("arrow", "let f = (x) => x + 1; f(4);"),
        ("arrow-block", "let f = (x) => { return x * 2; }; f(4);"),
        ("default-param", "let f = (x = 5) => x; f();"),
        ("rest-param", "let f = (...xs) => xs.length; f(1,2,3);"),
        (
            "closure-counter",
            "let mk = () => { let c = 0; return () => { c = c + 1; return c; }; }; let g = mk(); g(); g();",
        ),
        ("iife", "(function(){ return 7; })();"),
        // destructuring / spread
        ("array-destructure", "let [a, b] = [1, 2]; a + b;"),
        ("object-destructure", "let {x, y} = {x: 3, y: 4}; x + y;"),
        (
            "spread-array",
            "let a = [1, 2]; let b = [...a, 3]; b.length;",
        ),
        (
            "spread-call",
            "let f = (a,b,c) => a+b+c; let xs = [1,2,3]; f(...xs);",
        ),
        // literals / objects
        ("template-literal", "let n = 3; `v=${n}`;"),
        ("computed-member", "let o = {k: 9}; let k = \"k\"; o[k];"),
        ("object-shorthand", "let x = 5; let o = {x}; o.x;"),
        ("getter", "let o = { get v() { return 11; } }; o.v;"),
        ("object-method", "let o = { m() { return 13; } }; o.m();"),
        (
            "computed-key-literal",
            "let o = { [\"a\"+\"b\"]: 1 }; o.ab;",
        ),
        // numbers / coercion
        ("parseInt", "parseInt(\"42\");"),
        ("number-method", "let n = 3.14159; n.toFixed(2);"),
        ("string-concat-coerce", "\"n\" + 1;"),
        ("bool-coerce", "!!0;"),
        ("typeof-fn", "typeof (() => 1);"),
        ("instanceof", "let o = {}; o instanceof Object;"),
        // iteration
        (
            "for-of-array",
            "let s = 0; for (const x of [1,2,3]) { s = s + x; } s;",
        ),
        (
            "for-in-object",
            "let o = {a:1,b:2}; let n = 0; for (const k in o) { n = n + 1; } n;",
        ),
        (
            "while-break",
            "let i = 0; while (true) { if (i >= 3) break; i = i + 1; } i;",
        ),
        // higher-order over array (depends on Array methods — known bd-962ev)
        ("array-map", "[1,2,3].map(x => x * 2).length;"),
    ];
    let mut faults = 0;
    for (name, src) in cases {
        let r = ev(src);
        if r.starts_with("ERR") {
            faults += 1;
        }
        eprintln!("{name:32} => {r}");
    }
    eprintln!("\nFAULTS: {faults}/{}", cases.len());
}
