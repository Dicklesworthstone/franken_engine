//! Number semantics through the public parser -> lowering -> execution path.
//! Expected values use ECMAScript binary64 semantics, not agreement between
//! the two profiles (which previously shared the same wrapping-i64 defect).

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, QuickJsLane, V8Lane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ir_contract::{Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn execute_both(source: &str) -> [Result<Value, InterpreterError>; 2] {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("parse {source:?}: {error:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, "number-semantics");
    let context = LoweringContext::new("number-test", "number-decision", "number-policy");
    let ir3 = lower_ir0_to_ir3(&ir0, &context)
        .unwrap_or_else(|error| panic!("lower {source:?}: {error:?}"))
        .ir3;
    let grant = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    let mut quickjs_config = InterpreterConfig::quickjs_defaults();
    quickjs_config.granted_capabilities = grant.clone();
    let mut v8_config = InterpreterConfig::v8_defaults();
    v8_config.granted_capabilities = grant;
    [
        QuickJsLane::with_config(quickjs_config)
            .execute(&ir3, "number-test")
            .map(|result| result.value),
        V8Lane::with_config(v8_config)
            .execute(&ir3, "number-test")
            .map(|result| result.value),
    ]
}

fn assert_number(source: &str, expected: f64) {
    for (lane, result) in execute_both(source).into_iter().enumerate() {
        let value = result.unwrap_or_else(|error| panic!("lane {lane}, {source:?}: {error:?}"));
        let actual = match value {
            Value::Int(value) => {
                assert!(value.unsigned_abs() <= 9_007_199_254_740_991);
                value as f64
            }
            Value::Float(value) => value.inner(),
            value => panic!("lane {lane}, {source:?}: expected Number, got {value:?}"),
        };
        assert!(
            (actual.is_nan() && expected.is_nan()) || actual.to_bits() == expected.to_bits(),
            "lane {lane}, {source:?}: actual={actual:?} ({:#x}), expected={expected:?} ({:#x})",
            actual.to_bits(),
            expected.to_bits()
        );
    }
}

#[test]
fn integer_ingress_and_arithmetic_round_as_numbers() {
    for (source, expected) in [
        ("9007199254740993;", 9_007_199_254_740_992.0),
        ("9007199254740992 + 1;", 9_007_199_254_740_992.0),
        ("(2 ** 53) + 1;", 9_007_199_254_740_992.0),
        ("9007199254740993 - 9007199254740992;", 0.0),
        ("4294967296 * 4294967296;", 2_f64.powi(64)),
        ("9223372036854775807 + 1;", 2_f64.powi(63)),
        ("18446744073709551616;", 2_f64.powi(64)),
        ("-9223372036854775808 / -1;", 2_f64.powi(63)),
        ("(-9223372036854775808) % -1;", -0.0),
        ("+\"9007199254740993\";", 9_007_199_254_740_992.0),
        ("JSON.parse('9007199254740993') - 9007199254740992;", 0.0),
    ] {
        assert_number(source, expected);
    }
}

#[test]
fn negative_zero_survives_every_numeric_path() {
    for source in [
        "-0;",
        "-(0);",
        "0 * -1;",
        "-1 * 0;",
        "0 / -5;",
        "-5 % 5;",
        "(-0) ** 3;",
        "+'-0';",
        "-'0';",
        "-null;",
        "JSON.parse('-0');",
        "JSON.parse('-0.0');",
    ] {
        assert_number(source, -0.0);
    }
    assert_number("1 / (0 * -1);", f64::NEG_INFINITY);
    assert_number("-(-0);", 0.0);
    assert_number("Math.abs(-0);", 0.0);
}

#[test]
fn exponentiation_and_nonfinite_results_follow_ecmascript() {
    for source in [
        "1 ** NaN;",
        "(-1) ** Infinity;",
        "1 ** -Infinity;",
        "0 / 0;",
    ] {
        assert_number(source, f64::NAN);
    }
    assert_number("NaN ** 0;", 1.0);
    assert_number("0 ** 0;", 1.0);
    assert_number("1 / 0;", f64::INFINITY);
}

#[test]
fn exponent_signs_stay_with_numeric_tokens() {
    for (source, expected) in [
        ("1e-7 + 2e-7;", 3e-7),
        ("1E+7 + 2;", 10_000_002.0),
        ("1.5e-3 * 2;", 0.003),
        ("var name1e = 10; name1e-2;", 8.0),
        ("var e = 10; e-7;", 3.0),
        ("0x1e-2;", 28.0),
        ("0xe+2;", 16.0),
    ] {
        assert_number(source, expected);
    }
}

#[test]
fn repeated_arithmetic_and_function_calls_keep_number_semantics() {
    assert_number(
        "(function () { var x = 1; for (var i = 0; i < 70; i++) { x *= 2; } return x; })();",
        2_f64.powi(70),
    );
    assert_number(
        "function multiply(a, b) { return a * b; } multiply(4294967296, 4294967296);",
        2_f64.powi(64),
    );
}

#[test]
fn number_stringification_uses_ecmascript_exponent_thresholds() {
    for (source, expected) in [
        ("'' + (2 ** 70);", "1.1805916207174113e+21"),
        ("'' + 1e-7;", "1e-7"),
        ("'' + 1e-6;", "0.000001"),
        ("'' + 1e+21;", "1e+21"),
        ("JSON.stringify(2 ** 70);", "1.1805916207174113e+21"),
        ("JSON.stringify(-0);", "0"),
        ("JSON.stringify(1 / 0);", "null"),
    ] {
        for (lane, result) in execute_both(source).into_iter().enumerate() {
            assert_eq!(
                result.expect(source),
                Value::str(expected),
                "lane {lane}: {source}"
            );
        }
    }
}

#[test]
fn symbol_numeric_coercion_still_throws() {
    for source in ["Symbol('n') + 1;", "Symbol('n') * 2;", "+Symbol('n');"] {
        for (lane, result) in execute_both(source).into_iter().enumerate() {
            assert!(
                matches!(result, Err(InterpreterError::TypeError { .. })),
                "lane {lane}: {source}: {result:?}"
            );
        }
    }
}

#[test]
fn seeded_ieee754_oracle_through_public_execution() {
    // The source tests above exercise parser and lowering. This larger oracle
    // uses public IR3 execution so it can cover 70,000 operation results without
    // needing private interpreter access or reparsing each generated operand.
    const SEED: u64 = 0x9f02_b17d_53e0_2026;
    const CASES: usize = 10_000;
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    let mut state = SEED;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as i64
    };
    let boundaries = [
        (0, -1),
        (-5, 5),
        (MAX_SAFE_INTEGER, 2),
        (-MAX_SAFE_INTEGER, -2),
        (4_294_967_296, 4_294_967_296),
        (i64::MIN, -1),
        (i64::MAX, 1),
        (i64::MAX, i64::MAX - 1),
        (MAX_SAFE_INTEGER + 1, MAX_SAFE_INTEGER + 2),
    ];
    let mut module = Ir3Module::new(ContentHash::compute(b"number-oracle"), "number-oracle");
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 3,
        name: Some("number-oracle".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    module.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 },
        Ir3Instruction::LoadInt { dst: 1, value: 0 },
        Ir3Instruction::UnaryPlus { dst: 2, src: 0 },
        Ir3Instruction::Return { value: 2 },
    ];
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    let mut core = InterpreterCore::new(config, "number-oracle");

    for case in 0..CASES {
        let (lhs, rhs) = if let Some(pair) = boundaries.get(case) {
            *pair
        } else {
            let (left, right) = (next(), next());
            match case % 3 {
                0 => (left, right),
                1 => (left >> 11, right >> 11),
                _ => (left as i32 as i64, right as i32 as i64),
            }
        };
        module.instructions[0] = Ir3Instruction::LoadInt { dst: 0, value: lhs };
        module.instructions[1] = Ir3Instruction::LoadInt { dst: 1, value: rhs };
        let left = lhs as f64;
        let right = rhs as f64;
        for (operation, instruction, expected) in [
            (
                "+",
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                left + right,
            ),
            (
                "-",
                Ir3Instruction::Sub {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                left - right,
            ),
            (
                "*",
                Ir3Instruction::Mul {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                left * right,
            ),
            (
                "/",
                Ir3Instruction::Div {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                left / right,
            ),
            (
                "%",
                Ir3Instruction::Mod {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                left % right,
            ),
            (
                "unary -",
                Ir3Instruction::UnaryNeg { dst: 2, src: 0 },
                -left,
            ),
            (
                "unary +",
                Ir3Instruction::UnaryPlus { dst: 2, src: 0 },
                left,
            ),
        ] {
            module.instructions[2] = instruction;
            let actual = core
                .execute(&module)
                .unwrap_or_else(|error| {
                    panic!("seed={SEED:#x}, case={case}, op={operation}: {error:?}")
                })
                .value;
            let number = match actual {
                Value::Int(value) => {
                    assert!(
                        value.unsigned_abs() <= MAX_SAFE_INTEGER as u64,
                        "unsafe integer result: {value}, seed={SEED:#x}, case={case}"
                    );
                    value as f64
                }
                Value::Float(value) => value.inner(),
                other => panic!("Number operation returned {other:?}"),
            };
            assert!(
                (number.is_nan() && expected.is_nan()) || number.to_bits() == expected.to_bits(),
                "seed={SEED:#x}, case={case}, lhs={lhs}, rhs={rhs}, op={operation}: \
                 actual={number:?} ({:#x}), expected={expected:?} ({:#x})",
                number.to_bits(),
                expected.to_bits()
            );
        }
    }
}
