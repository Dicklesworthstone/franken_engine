//! bd-2vzgi — franken-core lone-surrogate string parity with the engine's
//! JsString model (bd-neika), pinned end-to-end through real source
//! execution: parse → IR0 → IR3 → QuickJsLane.
//!
//! These mirror the engine-side acceptance tests in
//! `crates/franken-engine/tests/js_string_integration.rs` for the surface
//! franken-core executes: `length`, `charAt`, `charCodeAt`, `codePointAt`,
//! `at`, `String.fromCharCode`, `+` concatenation healing, and template
//! literals. The differential-oracle seed corpus consensus over the same
//! programs lives in the engine crate
//! (`differential_oracle::default_engine_core_corpus`).

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::js_string::JsString;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

const HIGH: u16 = 0xD83D;
const LOW: u16 = 0xDE00;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities, returning the full execution result.
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_2vzgi");
    let context = LoweringContext::new("bd-2vzgi-trace", "bd-2vzgi-decision", "bd-2vzgi-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-2vzgi-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

/// Execute source that must FAIL at runtime, returning the interpreter error.
fn completion_err(source: &str) -> InterpreterError {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_7zwar");
    let context = LoweringContext::new("bd-7zwar-trace", "bd-7zwar-decision", "bd-7zwar-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-7zwar-trace")
        .expect_err("execution should fail")
}

fn lone(units: &[u16]) -> Value {
    Value::Str(JsString::from_code_units(units))
}

// --- length is the UTF-16 code-unit count -----------------------------------

#[test]
fn string_length_counts_utf16_code_units() {
    assert_eq!(completion("\"a\u{1F600}b\".length;"), Value::Int(4));
    assert_eq!(completion("\"abc\".length;"), Value::Int(3));
    assert_eq!(completion("\"\".length;"), Value::Int(0));
}

// --- charAt over exact code units --------------------------------------------

#[test]
fn char_at_surrogate_half_is_a_real_lone_surrogate() {
    let result = completion("\"a\u{1F600}b\".charAt(1);");
    assert_eq!(result, lone(&[HIGH]));
    let Value::Str(s) = result else {
        panic!("charAt must return a string value");
    };
    assert!(!s.is_well_formed());
    assert_eq!(s.code_units_vec(), vec![HIGH]);
    assert_eq!(s.as_utf8_projection(), "\u{FFFD}");
}

#[test]
fn char_at_bmp_unit_stays_well_formed() {
    assert_eq!(completion("\"a\u{1F600}b\".charAt(0);"), Value::str("a"));
    assert_eq!(completion("\"a\u{1F600}b\".charAt(3);"), Value::str("b"));
}

#[test]
fn char_at_out_of_range_and_negative_yield_empty_string() {
    assert_eq!(completion("\"ab\".charAt(9);"), Value::str(""));
    assert_eq!(completion("\"ab\".charAt(-1);"), Value::str(""));
}

// --- concatenation healing (the bd-2vzgi acceptance criterion) ---------------

#[test]
fn char_at_halves_heal_on_concatenation_to_strict_equal_original() {
    let src = "var s = \"a\u{1F600}b\"; (s.charAt(1) + s.charAt(2)) === \"\u{1F600}\";";
    assert_eq!(completion(src), Value::Bool(true));
}

#[test]
fn char_at_halves_heal_into_well_formed_value() {
    let result = completion("var s = \"a\u{1F600}b\"; s.charAt(1) + s.charAt(2);");
    assert_eq!(result, Value::str("\u{1F600}"));
    let Value::Str(healed) = result else {
        panic!("concat must return a string value");
    };
    assert!(healed.is_well_formed());
    assert_eq!(healed.code_units_vec(), vec![HIGH, LOW]);
}

#[test]
fn template_literal_heals_split_surrogate_parts() {
    let src = "var s = \"a\u{1F600}b\"; `${s.charAt(1)}${s.charAt(2)}` === \"\u{1F600}\";";
    assert_eq!(completion(src), Value::Bool(true));
}

// --- charCodeAt / codePointAt / at -------------------------------------------

#[test]
fn char_code_at_reads_exact_code_units() {
    assert_eq!(
        completion("\"a\u{1F600}b\".charCodeAt(1);"),
        Value::Int(i64::from(HIGH))
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".charCodeAt(2);"),
        Value::Int(i64::from(LOW))
    );
    assert_eq!(completion("\"a\u{1F600}b\".charCodeAt(0);"), Value::Int(97));
}

#[test]
fn char_code_at_out_of_range_is_nan() {
    let result = completion("\"ab\".charCodeAt(9);");
    let Value::Float(f) = result else {
        panic!("out-of-range charCodeAt must be a float NaN, got {result:?}");
    };
    assert!(f.inner().is_nan());
}

#[test]
fn code_point_at_is_utf16_unit_indexed() {
    // UTF-16 code-unit indexed per ES2015 CodePointAt, matching the engine
    // seams upgraded by bd-rdnhc: index 1 lands on the high surrogate of the
    // pair (combines to U+1F600), index 2 lands on the unpaired view of the
    // low surrogate (yields its own unit value), index 3 is 'b'.
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(1);"),
        Value::Int(0x1F600)
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(2);"),
        Value::Int(i64::from(LOW))
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(3);"),
        Value::Int(98)
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(4);"),
        Value::Undefined
    );
    assert_eq!(completion("\"ab\".codePointAt(9);"), Value::Undefined);
}

#[test]
fn string_at_supports_relative_code_unit_indexing() {
    assert_eq!(completion("\"a\u{1F600}b\".at(1);"), lone(&[HIGH]));
    assert_eq!(completion("\"a\u{1F600}b\".at(-1);"), Value::str("b"));
    assert_eq!(completion("\"a\u{1F600}b\".at(9);"), Value::Undefined);
}

// --- String.fromCharCode ------------------------------------------------------

#[test]
fn from_char_code_lone_surrogate_is_exact() {
    let result = completion("String.fromCharCode(55357);");
    assert_eq!(result, lone(&[HIGH]));
    let Value::Str(s) = result else {
        panic!("fromCharCode must return a string value");
    };
    assert!(!s.is_well_formed());
}

#[test]
fn from_char_code_pair_heals_to_supplementary() {
    assert_eq!(
        completion("String.fromCharCode(55357, 56832);"),
        Value::str("\u{1F600}")
    );
}

#[test]
fn from_char_code_round_trips_through_char_code_at() {
    assert_eq!(
        completion("String.fromCharCode(97, 55357).charCodeAt(1);"),
        Value::Int(i64::from(HIGH))
    );
}

#[test]
fn distinct_lone_surrogates_are_not_strictly_equal() {
    assert_eq!(
        completion("String.fromCharCode(55296) === String.fromCharCode(55297);"),
        Value::Bool(false)
    );
    assert_eq!(
        completion("String.fromCharCode(55296) === String.fromCharCode(55296);"),
        Value::Bool(true)
    );
}

#[test]
fn lone_surrogate_never_equals_its_lossy_projection() {
    assert_eq!(
        completion("String.fromCharCode(55357) === \"\u{FFFD}\";"),
        Value::Bool(false)
    );
}

// --- length/charAt through the healed value -----------------------------------

#[test]
fn healed_concat_has_supplementary_length_two() {
    assert_eq!(
        completion("var s = \"a\u{1F600}b\"; (s.charAt(1) + s.charAt(2)).length;"),
        Value::Int(2)
    );
    assert_eq!(
        completion("String.fromCharCode(55357).length;"),
        Value::Int(1)
    );
}

// --- bd-7zwar: core string-surface residual upgrades ---------------------------
//
// String.fromCodePoint, ES2024 isWellFormed/toWellFormed, JSON.stringify
// reachability from source, unknown-property-yields-undefined, code-unit
// relational order, and code-point-grain for..of / spread — all engine
// parity with bd-rdnhc.

#[test]
fn from_code_point_lone_surrogate_and_supplementary() {
    let result = completion("String.fromCodePoint(55296);");
    assert_eq!(result, lone(&[0xD800]));
    assert_eq!(
        completion("String.fromCodePoint(128512);"),
        Value::str("\u{1F600}")
    );
    assert_eq!(
        completion("String.fromCodePoint(97, 128512, 98);"),
        Value::str("a\u{1F600}b")
    );
}

#[test]
fn from_code_point_out_of_range_is_a_range_error() {
    let err = completion_err("String.fromCodePoint(1114112);"); // 0x110000
    assert!(
        matches!(err, InterpreterError::RangeError { .. }),
        "out-of-range code point must be a RangeError, got {err:?}"
    );
    let err = completion_err("String.fromCodePoint(1.5);");
    assert!(
        matches!(err, InterpreterError::RangeError { .. }),
        "non-integral code point must be a RangeError, got {err:?}"
    );
}

#[test]
fn is_well_formed_and_to_well_formed_report_real_surrogate_state() {
    assert_eq!(
        completion("\"a\u{1F600}b\".isWellFormed();"),
        Value::Bool(true)
    );
    assert_eq!(
        completion("String.fromCharCode(55296).isWellFormed();"),
        Value::Bool(false)
    );
    assert_eq!(
        completion("String.fromCharCode(55296).toWellFormed();"),
        Value::str("\u{FFFD}")
    );
    assert_eq!(completion("\"ok\".toWellFormed();"), Value::str("ok"));
}

#[test]
fn json_stringify_is_reachable_from_source_and_escapes_lone_surrogates() {
    let result = completion("JSON.stringify(String.fromCharCode(55296));");
    let Value::Str(s) = result else {
        panic!("JSON.stringify must return a string value");
    };
    assert_eq!(s.as_str(), Some("\"\\ud800\""));
    assert_eq!(completion("JSON.stringify(\"hi\");"), Value::str("\"hi\""));
}

#[test]
fn unknown_property_on_string_receiver_yields_undefined() {
    assert_eq!(completion("\"abc\".nope;"), Value::Undefined);
    assert_eq!(
        completion("\"abc\".nope === \"abc\".alsoNope;"),
        Value::Bool(true)
    );
}

#[test]
fn string_relational_order_uses_utf16_code_units() {
    // Lone surrogates order by exact unit (0xD800 < 0xE000), not by the
    // U+FFFD projection (which would sort above U+E000).
    assert_eq!(
        completion("String.fromCharCode(55296) < String.fromCharCode(57344);"),
        Value::Bool(true)
    );
    assert_eq!(
        completion("String.fromCharCode(55296) < String.fromCharCode(55297);"),
        Value::Bool(true)
    );
    // Astral sorts below high-BMP under code-unit order.
    assert_eq!(
        completion("\"\u{1F600}\" < \"\u{FF5A}\";"),
        Value::Bool(true)
    );
    // Well-formed BMP ordering is unchanged.
    assert_eq!(completion("\"a\" < \"b\";"), Value::Bool(true));
    assert_eq!(completion("\"b\" <= \"a\";"), Value::Bool(false));
}

#[test]
fn for_of_iterates_code_points_and_preserves_lone_surrogates() {
    assert_eq!(
        completion("var n = 0; for (var c of \"a\u{1F600}b\") { n = n + 1; } n;"),
        Value::Int(3)
    );
    assert_eq!(
        completion(
            "var s = \"a\" + String.fromCharCode(55357) + \"b\"; \
             var codes = \"\"; \
             for (var c of s) { codes = codes + c.charCodeAt(0) + \",\"; } \
             codes;"
        ),
        Value::str("97,55357,98,")
    );
}

#[test]
fn spread_of_string_produces_code_point_elements() {
    assert_eq!(
        completion("var a = [...\"a\u{1F600}b\"]; a.length;"),
        Value::Int(3)
    );
    assert_eq!(
        completion("var a = [...String.fromCharCode(55296)]; a[0].charCodeAt(0);"),
        Value::Int(55296)
    );
}
