#![forbid(unsafe_code)]

//! Locale-aware Date formatting (bd-1j1wy) through real programs:
//! `Date.prototype.toLocaleString` / `toLocaleDateString` /
//! `toLocaleTimeString` for en-US, en-GB and ja-JP. Expected lines are Node
//! v22.2.0's output (TZ=UTC, explicit `timeZone: 'UTC'`), captured as JSON.
//!
//! These tests used to hand-build IR objects carrying `__type: "Date"` and
//! `__timestamp` properties; Dates now live in internal slots that guest
//! properties cannot forge, so those objects were never Dates and every test
//! failed. Their expectations were not Node's either (hyphenated ja-JP dates
//! with day abbreviations). Component options other than en-US, and unknown
//! locales, are refused with a TypeError (see unsupported_locale_fallback).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "locale.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "locale.js"),
        &LoweringContext::new("locale-trace", "locale-decision", "locale-policy"),
    )
    .expect("source lowers")
    .ir3
}

fn run(source: &str) -> Result<Vec<String>, String> {
    let module = lower(source);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "locale");
    core.execute(&module)
        .map(|result| {
            result
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect()
        })
        .map_err(|error| error.to_string())
}

fn assert_output(source: &str, expected: &[&str]) {
    let first = run(source).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(first, expected);
    // Formatting is deterministic across executions too.
    assert_eq!(run(source).expect("second run"), first);
}

/// en-US numeric date, and the weekday/month-name form.
#[test]
fn en_us_locale_date_formatting() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nconsole.log(d.toLocaleDateString('en-US', utc));\nconsole.log(d.toLocaleDateString('en-US', { ...utc, weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }));\n",
        &["3/15/2024", "Fri, Mar 15, 2024"],
    );
}

/// en-GB orders day/month/year with zero padding.
#[test]
fn en_gb_locale_date_formatting() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nconsole.log(d.toLocaleDateString('en-GB', utc));\nconsole.log(d.toLocaleString('en-GB', utc));\n",
        &["15/03/2024", "15/03/2024, 13:05:09"],
    );
}

/// ja-JP orders year/month/day with slashes.
#[test]
fn ja_jp_locale_date_formatting() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nconsole.log(d.toLocaleDateString('ja-JP', utc));\nconsole.log(d.toLocaleString('ja-JP', utc));\n",
        &["2024/3/15", "2024/3/15 13:05:09"],
    );
}

/// 12-hour en-US time; 24-hour en-GB and ja-JP time.
#[test]
fn time_formatting_across_locales() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nfor (const locale of ['en-US', 'en-GB', 'ja-JP']) console.log(locale, d.toLocaleTimeString(locale, utc));\n",
        &["en-US 1:05:09 PM", "en-GB 13:05:09", "ja-JP 13:05:09"],
    );
}

/// toLocaleString joins the date and time per locale.
#[test]
fn full_datetime_formatting() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nfor (const locale of ['en-US', 'en-GB', 'ja-JP']) console.log(locale, d.toLocaleString(locale, utc));\n",
        &[
            "en-US 3/15/2024, 1:05:09 PM",
            "en-GB 15/03/2024, 13:05:09",
            "ja-JP 2024/3/15 13:05:09",
        ],
    );
}

/// Equal times format identically (also across runs: see the helper).
#[test]
fn locale_formatting_determinism() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nconst a = d.toLocaleString('en-GB', utc);\nconst b = new Date(d.getTime()).toLocaleString('en-GB', utc);\nconsole.log(a === b, a);\n",
        &["true 15/03/2024, 13:05:09"],
    );
}

/// An invalid Date formats as "Invalid Date" in every locale method.
#[test]
fn invalid_date_handling() {
    assert_output(
        "const bad = new Date(NaN);\nconsole.log(bad.toLocaleDateString('en-US'), bad.toLocaleTimeString('en-GB'), bad.toLocaleString('ja-JP'));\n",
        &["Invalid Date Invalid Date Invalid Date"],
    );
}

/// Long and short weekday and month names (en-US).
#[test]
fn month_and_day_name_localization() {
    assert_output(
        "const d = new Date(Date.UTC(2024, 2, 15, 13, 5, 9));\nconst utc = { timeZone: 'UTC' };\nconsole.log(d.toLocaleDateString('en-US', { ...utc, weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }));\nconsole.log(new Date(Date.UTC(2024, 11, 1)).toLocaleDateString('en-US', { ...utc, weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }));\n",
        &["Friday, March 15, 2024", "Sun, Dec 1, 2024"],
    );
}

/// Three hundred formatted dates in one run.
#[test]
fn memory_safety_stress_test() {
    assert_output(
        "let last = '';\nfor (let i = 0; i < 300; i++) last = new Date(Date.UTC(2000, 0, 1) + i * 86400000).toLocaleDateString('en-GB', { timeZone: 'UTC' });\nconsole.log(last);\n",
        &["26/10/2000"],
    );
}

/// Node falls back to the default locale for a well-formed but unknown tag;
/// the engine refuses it with a typed TypeError naming the locale instead of
/// guessing (a known gap of the Intl formatter surface, bd-9vouw.171).
#[test]
fn unsupported_locale_fallback() {
    let error =
        run("new Date(Date.UTC(2024, 2, 15)).toLocaleDateString('zz-ZZ', { timeZone: 'UTC' });")
            .expect_err("an unknown locale is refused");
    assert!(error.contains("zz-ZZ"), "{error}");
}
