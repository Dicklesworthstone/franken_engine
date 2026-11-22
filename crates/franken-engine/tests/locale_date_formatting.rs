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

/// Direct `builtin:DatePrototypeToLocale{,Date,Time}String` hostcalls route
/// through `date_locale` with exact proleptic-Gregorian UTC arithmetic and
/// match Node v22/v26 output (including leap years, pre-epoch timestamps, and
/// omitted locale arguments) (bd-9vouw.106).
#[test]
fn direct_locale_date_hostcalls_match_node_outputs() {
    use frankenengine_engine::baseline_interpreter::Value;
    use frankenengine_engine::ir_contract::{
        CapabilityTag, Ir3Instruction, IrHeader, IrLevel, IrSchemaVersion, RegRange,
    };

    let run_hostcall = |timestamp_ms: i64, tag: &str, locale: Option<&str>| -> Value {
        let mut instructions = vec![
            Ir3Instruction::LoadInt {
                dst: 0,
                value: timestamp_ms,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:Date".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
        ];
        let mut constant_pool = Vec::new();
        let arg_count = if let Some(locale_str) = locale {
            constant_pool.push(locale_str.into());
            instructions.push(Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            });
            2
        } else {
            // Seed r2 with a non-default locale to verify count == 1 does not
            // read past the argument range.
            constant_pool.push("ja-JP".into());
            instructions.push(Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            });
            1
        };
        instructions.push(Ir3Instruction::HostCall {
            capability: CapabilityTag(tag.to_string()),
            args: RegRange {
                start: 1,
                count: arg_count,
            },
            dst: 0,
        });
        instructions.push(Ir3Instruction::Halt);

        let module = Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "locale-hostcall.js".to_string(),
            },
            instructions,
            constant_pool,
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        };
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "locale-hostcall");
        core.execute(&module)
            .expect("locale hostcall should execute")
            .value
    };

    // Date.UTC(2024, 2, 15, 13, 5, 9) = 1710507909000 ms (post-leap-day 2024).
    let march_2024 = 1_710_507_909_000_i64;
    assert_eq!(
        run_hostcall(march_2024, "builtin:DatePrototypeToLocaleString", None),
        Value::str("3/15/2024, 1:05:09 PM")
    );
    assert_eq!(
        run_hostcall(
            march_2024,
            "builtin:DatePrototypeToLocaleString",
            Some("en-US")
        ),
        Value::str("3/15/2024, 1:05:09 PM")
    );
    assert_eq!(
        run_hostcall(
            march_2024,
            "builtin:DatePrototypeToLocaleDateString",
            Some("en-GB")
        ),
        Value::str("15/03/2024")
    );
    assert_eq!(
        run_hostcall(
            march_2024,
            "builtin:DatePrototypeToLocaleTimeString",
            Some("en-GB")
        ),
        Value::str("13:05:09")
    );
    assert_eq!(
        run_hostcall(
            march_2024,
            "builtin:DatePrototypeToLocaleString",
            Some("ja-JP")
        ),
        Value::str("2024/3/15 13:05:09")
    );

    // Pre-epoch: Date.UTC(1969, 11, 31, 23, 59, 59) = -1000 ms.
    assert_eq!(
        run_hostcall(-1_000, "builtin:DatePrototypeToLocaleString", Some("en-US")),
        Value::str("12/31/1969, 11:59:59 PM")
    );
    assert_eq!(
        run_hostcall(
            -1_000,
            "builtin:DatePrototypeToLocaleDateString",
            Some("ja-JP")
        ),
        Value::str("1969/12/31")
    );
}
