#![forbid(unsafe_code)]

//! ES2020 Number::exponentiate and -0 results of Math.pow / Math.trunc /
//! Math.sqrt. `**` and Math.pow used IEEE-754 pow, which answers 1 for
//! `1 ** NaN` and `(-1) ** Infinity` where JavaScript answers NaN, and
//! Math.pow / Math.trunc / Math.sqrt turned a whole result into an integer
//! value by hand, so `Math.trunc(-0.9)`, `Math.sqrt(-0)` and
//! `Math.pow(-0, 3)` lost the sign of zero (10 Node-passing Test262 tests in
//! the rc-next33 merged-tree census: Math/pow, Math/trunc,
//! expressions/exponentiation).

use frankenengine_engine::HybridRouter;

/// The NaN cases of Number::exponentiate (a NaN exponent, a base of ±1 to an
/// infinite exponent) next to the cases IEEE pow already gets right, signed
/// zero results, whole results past 2^53, and string operands. Expected
/// lines are Node v22.2.0's output, captured programmatically.
#[test]
fn exponentiation_and_math_results_follow_number_semantics() {
    let source = r#"function sign(x) { return Object.is(x, -0) ? '-0' : String(x); }
console.log(sign(Math.pow(1, NaN)), sign(1 ** NaN), sign(Math.pow(-1, Infinity)), sign((-1) ** -Infinity), sign(Math.pow(1, -Infinity)), sign(Math.pow(NaN, 0)), sign(NaN ** -0));
console.log(sign(Math.pow(-0, 3)), sign(Math.pow(-Infinity, -3)), sign(Math.pow(-0, -3)), sign((-0) ** 3), sign(Math.pow(-8, 1 / 3)), sign(Math.pow(0.5, Infinity)));
console.log(sign(Math.trunc(-0.9)), sign(Math.trunc(-0)), sign(Math.trunc(-1.5)), sign(Math.trunc(2.7)), sign(Math.sqrt(-0)), sign(Math.sqrt(16)), sign(Math.sqrt(-1)));
var big = Math.pow(2, 60);
console.log(big === 2 ** 60, big + 1 === big, Number.isSafeInteger(big), sign(Math.pow('2', '3')), sign(Math.pow(2, 0.5) * Math.pow(2, 0.5)));
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
            "NaN NaN NaN NaN NaN 1 1",
            "-0 -0 -Infinity -0 NaN 0",
            "-0 -0 -1 2 -0 4 NaN",
            "true true false 8 2.0000000000000004",
        ]
    );
}
