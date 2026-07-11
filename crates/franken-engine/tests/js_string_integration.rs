#![forbid(unsafe_code)]
//! Integration coverage for the lone-surrogate string model (bd-neika).
//!
//! Each test parses, lowers, and executes real JS source end-to-end on a
//! fresh `InterpreterCore`, then asserts on the exact resulting `Value`.
//! The acceptance criteria exercised here:
//!
//! - `"😀"` literals round-trip as U+1F600 (well-formed, two code units);
//! - `charAt` surrogate halves are real lone-surrogate values that heal
//!   back to the original string on concatenation;
//! - `String.fromCharCode(0xD83D)` produces a lone surrogate, and the
//!   paired form heals;
//! - `JSON.parse`/`JSON.stringify` round-trip lone surrogates exactly.
//!
//! Source-literal lone-surrogate ESCAPES (`"\uD800"` in JS source) remain
//! fail-closed in the parser, so JSON tests construct their inputs at
//! runtime via `String.fromCharCode` / `JSON.stringify`.

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::js_string::JsString;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

fn surrogate_test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

/// Parse, lower, and execute one JS source end-to-end on a fresh core and
/// return the completion value.
fn execute_source(label: &str, source: &str) -> ExecutionResult {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .unwrap_or_else(|err| panic!("program `{label}` should parse: {err:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("js-string-{label}.js"));
    let ctx = LoweringContext::new(
        format!("trace-js-string-{label}"),
        format!("decision-js-string-{label}"),
        format!("policy-js-string-{label}"),
    );
    let lowering = lower_ir0_to_ir3(&ir0, &ctx)
        .unwrap_or_else(|err| panic!("program `{label}` should lower to IR3: {err:?}"));

    let mut core =
        InterpreterCore::new(surrogate_test_config(), format!("trace-js-string-{label}"));
    core.execute(&lowering.ir3)
        .unwrap_or_else(|err| panic!("program `{label}` should execute: {err:?}"))
}

fn expect_string(label: &str, source: &str) -> JsString {
    match execute_source(label, source).value {
        Value::Str(s) => s,
        other => panic!("program `{label}` should complete with a string, got {other:?}"),
    }
}

fn expect_true(label: &str, source: &str) {
    assert_eq!(
        execute_source(label, source).value,
        Value::Bool(true),
        "program `{label}` should complete true"
    );
}

#[test]
fn emoji_literal_round_trips_as_supplementary_code_point() {
    let s = expect_string("emoji-literal", "'😀';");
    assert!(s.is_well_formed());
    assert_eq!(s.as_str(), Some("😀"));
    assert_eq!(s.code_units_vec(), vec![0xD83D, 0xDE00]);
    assert_eq!(s.utf16_len(), 2);
}

#[test]
fn char_at_surrogate_half_is_a_real_lone_surrogate() {
    let s = expect_string("charat-high-half", "'😀'.charAt(0);");
    assert!(!s.is_well_formed());
    assert_eq!(s.code_units_vec(), vec![0xD83D]);
    assert_eq!(s.as_utf8_projection(), "\u{FFFD}");

    let s = expect_string("charat-low-half", "'😀'.charAt(1);");
    assert_eq!(s.code_units_vec(), vec![0xDE00]);
}

#[test]
fn char_at_halves_heal_on_concatenation_to_strict_equal_original() {
    expect_true(
        "charat-heal",
        "var s = '😀'; s.charAt(0) + s.charAt(1) === s;",
    );
}

#[test]
fn template_literal_heals_split_surrogate_parts() {
    expect_true(
        "template-heal",
        "var h = '😀'.charAt(0); var l = '😀'.charAt(1); `${h}${l}` === '😀';",
    );
}

#[test]
fn char_code_at_reads_exact_unit_through_lone_surrogate_value() {
    expect_true(
        "charcodeat-lone",
        "'😀'.charAt(0).charCodeAt(0) === 0xD83D;",
    );
}

#[test]
fn lone_surrogate_length_is_one_code_unit() {
    expect_true("lone-length", "String.fromCharCode(0xD800).length === 1;");
}

#[test]
fn from_char_code_lone_surrogate_and_healing() {
    let s = expect_string("fromcharcode-lone", "String.fromCharCode(0xD83D);");
    assert!(!s.is_well_formed());
    assert_eq!(s.code_units_vec(), vec![0xD83D]);

    expect_true(
        "fromcharcode-heal",
        "String.fromCharCode(0xD83D, 0xDE00) === '😀';",
    );
}

#[test]
fn distinct_lone_surrogates_are_not_strictly_equal() {
    expect_true(
        "lone-distinct",
        "String.fromCharCode(0xD800) !== String.fromCharCode(0xD801);",
    );
}

#[test]
fn json_stringify_escapes_lone_surrogate() {
    // ES2019 well-formed JSON.stringify: the lone surrogate is emitted as a
    // \uXXXX escape rather than raw text.
    let s = expect_string(
        "json-stringify-lone",
        "JSON.stringify(String.fromCharCode(0xD800));",
    );
    assert_eq!(s.as_str(), Some("\"\\ud800\""));
}

#[test]
fn json_round_trips_lone_surrogate_value_exactly() {
    expect_true(
        "json-roundtrip-lone",
        "var v = String.fromCharCode(0xD800); \
         JSON.parse(JSON.stringify(v)) === v;",
    );
}

#[test]
fn json_parse_combines_paired_surrogate_escapes_in_json_text() {
    // The JSON text is built at runtime ('\\u' is a literal backslash + u in
    // JS source), so the parser's fail-closed posture on source-literal lone
    // escapes is not involved.
    expect_true(
        "json-parse-paired",
        "JSON.parse('\"' + '\\\\uD83D' + '\\\\uDE00' + '\"') === '😀';",
    );
}

#[test]
fn is_well_formed_and_to_well_formed_report_real_surrogate_state() {
    expect_true("iswellformed-true", "'😀'.isWellFormed() === true;");
    expect_true(
        "iswellformed-false",
        "String.fromCharCode(0xD800).isWellFormed() === false;",
    );
    expect_true(
        "towellformed-projects",
        "String.fromCharCode(0xD800).toWellFormed() === '\\uFFFD';",
    );
}
