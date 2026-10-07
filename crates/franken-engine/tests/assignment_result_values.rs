#![forbid(unsafe_code)]

//! An assignment used as a value (`x = v`, `x += v`, `++x`, `--x`) whose
//! expression then writes the same register-resident binding again: the value
//! the first assignment left on the stack was the binding's register itself, so
//! the later write changed it. `[i = 2, i = 3]` was [3, 3], `f(++i, ++i)`
//! passed i's final value twice, `(j = 1) + (j = 2)` was 4, and
//! `--b ** --b ** 2` with b = 4 was 16 (Test262
//! exp-operator-precedence-update-expression-semantics). Covers the top-level
//! lowering loop (the first block) and function bodies (the IIFEs).

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn assignment_results_are_values_not_binding_registers() {
    let source = r#"var i = 1; console.log([i = 2, i = 3].join(), i);
i = 1; console.log([i += 1, i += 1].join());
i = 1; console.log([i, i = 5].join());
i = 1; console.log([i++, i++].join());
function h() { let j = 1; return [j = 2, j = 3].join() + "|" + [++j, ++j].join() + "|" + [j, ++j].join(); } console.log(h());
(function () {
function f(a, b) { return a + ":" + b; }
var i = 1; console.log(f(i, i = 5), f(i, i++), f(i, ++i));
function g() { var j = 1; return [f(j, j = 5), f(j, ++j), j + (j = 10), (j = 1) + (j = 2)].join(" "); } console.log(g());
var y = 1, x; console.log([x = y, y = 7, x].join());
})();
(function () {
var b = 4; console.log(--b + --b, b);
var i = 1; console.log(++i * ++i, i);
i = 1; console.log(++i - i, i);
i = 1; console.log([++i, ++i].join(), i);
i = 1; function f(a, c) { return a + ":" + c; } console.log(f(++i, ++i));
var o = { v: 1 }; console.log(++o.v + ++o.v, o.v);
let L = 1; console.log(++L + ++L, L);
function g() { var z = 1; return [++z + ++z, z]; } console.log(g().join());
})();
(function () {
var b = 4; console.log(--b ** 2, b);
b = 4; console.log(--b ** --b, b);
b = 4; console.log(2 ** --b ** 2, b);
b = 4; console.log(--b ** --b ** 2, b);
b = 4; console.log((--b) ** ((--b) ** 2), b);
b = 4; console.log(b-- ** 2, b);
b = 4; console.log(++b ** 2 ** 1, b);
})();
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "2,3 3",
            "2,3",
            "1,5",
            "1,2",
            "2,3|4,5|5,6",
            "1:5 5:5 6:7",
            "1:5 5:6 16 3",
            "1,7,1",
            "5 2",
            "6 3",
            "0 2",
            "2,3 3",
            "2:3",
            "5 3",
            "5 3",
            "5,3",
            "9 3",
            "9 2",
            "512 3",
            "81 2",
            "81 2",
            "16 3",
            "25 5",
        ]
    );
}
