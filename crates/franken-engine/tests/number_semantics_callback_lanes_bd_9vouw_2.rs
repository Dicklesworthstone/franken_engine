//! bd-9vouw.2 (residual): Number semantics in the callback mini-lanes and in
//! Number-to-string conversion.
//!
//! ecb8ef02f fixed the main evaluator's integer fast path, but the
//! `reduce` / `Array.from` callback lanes (`eval_add_values`,
//! `eval_arith_values`, `number_value`) still wrapped as i64 and lost -0, and
//! `Float64`'s Display used Rust formatting instead of ECMAScript
//! Number::toString. Every expected string below was produced by Node v22.2.0
//! evaluating the same expression (`String(expr)`).
//!
//! No mocks: real source is parsed, lowered IR0->IR3, and executed on a real
//! `QuickJsLane`; the completion value's string form is compared.

use frankenengine_engine::baseline_interpreter::QuickJsLane;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "number_semantics_bd_9vouw_2.js");
    let context = LoweringContext::new("num-trace", "num-decision", "num-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    QuickJsLane::new()
        .execute(&module, "num-trace")
        .expect("source should execute")
        .value
        .to_string()
}

fn check(name: &str, source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "{name}: `{source}` must match Node v22.2.0"
    );
}

#[test]
fn reduce_callback_lane_uses_number_semantics() {
    check(
        "reduce_add_overflow",
        "[9007199254740991, 2].reduce((a, b) => a + b);",
        "9007199254740992",
    );
    check(
        "reduce_mul_overflow",
        "[4294967296, 4294967296].reduce((a, b) => a * b);",
        "18446744073709552000",
    );
    check(
        "reduce_sub_overflow",
        "[-9007199254740991, 3].reduce((a, b) => a - b);",
        "-9007199254740994",
    );
    check(
        "reduce_neg_zero",
        "1 / [0, -1].reduce((a, b) => a * b);",
        "-Infinity",
    );
    check(
        "float_sum_whole",
        "[0.5, 0.5].reduce((a, b) => a + b);",
        "1",
    );
    // Positive control: small integers stay exact.
    check(
        "reduce_small_ints",
        "[1, 2, 3].reduce((a, b) => a + b);",
        "6",
    );
}

#[test]
fn array_from_callback_lane_uses_number_semantics() {
    check(
        "array_from_mul_overflow",
        "Array.from([4294967296], x => x * 4294967296)[0];",
        "18446744073709552000",
    );
}

#[test]
fn number_to_string_follows_ecmascript() {
    check(
        "pow70_loop",
        "let x = 1; for (let i = 0; i < 70; i++) x = x * 2; x;",
        "1.1805916207174113e+21",
    );
    check("tiny_float", "1e-7;", "1e-7");
    check("mod_neg_zero", "1 / (-5 % 5);", "-Infinity");
}
