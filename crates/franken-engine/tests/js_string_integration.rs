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

// --- bd-rdnhc: residual boundary upgrades ------------------------------------
//
// for..of / Array.from iterate per code point with lone surrogates preserved;
// relational operators use exact UTF-16 code-unit order; codePointAt is
// code-unit indexed; the indexOf family searches exact code units and treats
// positions inside a surrogate pair as legal offsets (previously TypeError).

#[test]
fn for_of_groups_surrogate_pairs_into_one_element() {
    expect_true(
        "for-of-groups-pairs",
        "var out = []; for (var c of 'a😀b') { out.push(c); } \
         out.length === 3 && out[0] === 'a' && out[1] === '😀' && out[2] === 'b';",
    );
}

#[test]
fn for_of_preserves_lone_surrogate_elements_exactly() {
    expect_true(
        "for-of-lone-surrogate",
        "var s = 'a' + String.fromCharCode(0xD83D) + 'b'; \
         var out = []; for (var c of s) { out.push(c); } \
         out.length === 3 && out[1].charCodeAt(0) === 0xD83D && out[1].length === 1;",
    );
}

#[test]
fn spread_of_string_produces_code_point_elements() {
    // A string iterable in array spread yields per-code-point elements
    // (previously a string spread was silently skipped, producing []).
    expect_true(
        "spread-string",
        "var a = ['x', ...'a😀b']; a.length === 4 && a[2] === '😀';",
    );
    expect_true(
        "spread-lone-surrogate",
        "var a = [...String.fromCharCode(0xD800)]; \
         a.length === 1 && a[0].charCodeAt(0) === 0xD800;",
    );
}

#[test]
fn array_from_string_iterates_code_points_exactly() {
    expect_true(
        "array-from-string",
        "var a = Array.from('a😀b'); a.length === 3 && a[1] === '😀';",
    );
    expect_true(
        "array-from-lone-surrogate",
        "var a = Array.from('x' + String.fromCharCode(0xDC00)); \
         a.length === 2 && a[1].charCodeAt(0) === 0xDC00;",
    );
}

#[test]
fn string_relational_operators_use_utf16_code_unit_order() {
    // U+1F600 encodes as [0xD83D, 0xDE00]; 0xD83D < 0xFF5A, so the astral
    // string sorts BELOW the high-BMP one under ES code-unit order (the old
    // code-point order said the opposite).
    expect_true("relational-astral-lt", "'😀' < '\u{FF5A}';");
    expect_true("relational-astral-gt", "'\u{FF5A}' > '😀';");
    // Lone surrogates order by their exact unit, not the U+FFFD projection
    // (under the projection, U+FFFD would sort above U+E000).
    expect_true(
        "relational-lone-vs-bmp",
        "String.fromCharCode(0xD800) < String.fromCharCode(0xE000);",
    );
    expect_true(
        "relational-lone-vs-lone",
        "String.fromCharCode(0xD800) < String.fromCharCode(0xD801);",
    );
    // Well-formed BMP ordering is unchanged.
    expect_true(
        "relational-bmp-unchanged",
        "'a' < 'b' && 'abc' <= 'abc' && !('b' < 'a') && 'ab' < 'b';",
    );
}

#[test]
fn code_point_at_is_utf16_code_unit_indexed() {
    expect_true(
        "code-point-at-units",
        "var s = 'a😀b'; \
         s.codePointAt(0) === 97 && s.codePointAt(1) === 128512 && \
         s.codePointAt(2) === 56832 && s.codePointAt(3) === 98 && \
         s.codePointAt(4) === undefined;",
    );
    expect_true(
        "code-point-at-lone",
        "String.fromCharCode(0xD83D).codePointAt(0) === 0xD83D;",
    );
}

#[test]
fn index_of_family_uses_code_unit_offsets() {
    expect_true(
        "index-of-units",
        "var s = 'a😀b'; \
         s.indexOf('b') === 3 && s.indexOf('a', 1) === -1 && s.indexOf('b', 2) === 3;",
    );
    expect_true(
        "index-of-lone-needle",
        "'a😀b'.indexOf(String.fromCharCode(0xD83D)) === 1;",
    );
    expect_true(
        "last-index-of-units",
        "'abab'.lastIndexOf('ab') === 2 && \
         'a😀b'.lastIndexOf(String.fromCharCode(0xDE00)) === 2;",
    );
}

#[test]
fn search_positions_inside_a_surrogate_pair_are_legal_offsets() {
    expect_true(
        "includes-split-pair",
        "'😀z'.includes('z', 1) && !('😀z'.includes('😀', 1));",
    );
    expect_true(
        "starts-with-inside-pair",
        "'😀z'.startsWith(String.fromCharCode(0xDE00), 1) && '😀z'.startsWith('😀');",
    );
    expect_true(
        "ends-with-split-pair-length",
        "'😀z'.endsWith(String.fromCharCode(0xD83D), 1) && '😀z'.endsWith('z');",
    );
}
