#![forbid(unsafe_code)]

//! `Intl.RelativeTimeFormat` and `Intl.ListFormat` (bd-9vouw.171) for the
//! pattern languages (en, de, ja, zh, ko). The expected lines are Node
//! v22.2.0's output for the same programs, captured programmatically (the
//! pattern tables themselves are generated from the same Node). Each program
//! runs on both interpreter profiles.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str, v8_profile: bool) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "intl.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "intl.js"),
        &LoweringContext::new("intl-trace", "intl-decision", "intl-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut config = if v8_profile {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "intl");
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

fn assert_lines(source: &str, expected: &[&str]) {
    for v8_profile in [false, true] {
        assert_eq!(
            console_lines(source, v8_profile),
            expected,
            "v8 profile {v8_profile}"
        );
    }
}

/// The constructors, their methods' names and lengths, and resolvedOptions.
#[test]
fn shape_and_resolved_options() {
    assert_lines(
        "console.log(typeof Intl.RelativeTimeFormat, typeof Intl.ListFormat, Intl.RelativeTimeFormat.length, Intl.ListFormat.length, Intl.RelativeTimeFormat.name, Intl.ListFormat.name);\nconst r = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' });\nconst l = new Intl.ListFormat();\nconsole.log(Object.prototype.toString.call(r), Object.prototype.toString.call(l), r.format.name, r.format.length, r.formatToParts.name, r.formatToParts.length, l.format.length, new Intl.DateTimeFormat('en-US').formatToParts.name);\nconsole.log(JSON.stringify(r.resolvedOptions()), JSON.stringify(l.resolvedOptions()));\nconsole.log(JSON.stringify(new Intl.RelativeTimeFormat().resolvedOptions()), JSON.stringify(new Intl.ListFormat('en-GB', { type: 'disjunction', style: 'short' }).resolvedOptions()));\nconsole.log(JSON.stringify(new Intl.RelativeTimeFormat('de-DE', { style: 'narrow' }).resolvedOptions()));\n",
        &[
            "function function 0 0 RelativeTimeFormat ListFormat",
            "[object Intl.RelativeTimeFormat] [object Intl.ListFormat] format 2 formatToParts 2 1 formatToParts",
            "{\"locale\":\"en-US\",\"style\":\"long\",\"numeric\":\"auto\",\"numberingSystem\":\"latn\"} {\"locale\":\"en-US\",\"type\":\"conjunction\",\"style\":\"long\"}",
            "{\"locale\":\"en-US\",\"style\":\"long\",\"numeric\":\"always\",\"numberingSystem\":\"latn\"} {\"locale\":\"en-GB\",\"type\":\"disjunction\",\"style\":\"short\"}",
            "{\"locale\":\"de-DE\",\"style\":\"narrow\",\"numeric\":\"always\",\"numberingSystem\":\"latn\"}",
        ],
    );
}

/// Every pattern language, style and numeric setting over past, future, zero,
/// -0, fractions and grouping.
#[test]
fn relative_time_matrix() {
    assert_lines(
        "const values = [-2, -1, -0, 0, 1, 2, 1.5, -1234.5678];\nconst units = ['second', 'days', 'quarter', 'year'];\nfor (const loc of ['en-US', 'de-DE', 'ja-JP', 'zh-CN', 'ko-KR']) {\n  for (const style of ['long', 'short', 'narrow']) {\n    for (const numeric of ['always', 'auto']) {\n      const f = new Intl.RelativeTimeFormat(loc, { style, numeric });\n      const out = [];\n      for (const unit of units) for (const v of values) out.push(f.format(v, unit));\n      console.log(loc, style, numeric, JSON.stringify(out));\n    }\n  }\n}\n",
        &[
            "en-US long always [\"2 seconds ago\",\"1 second ago\",\"0 seconds ago\",\"in 0 seconds\",\"in 1 second\",\"in 2 seconds\",\"in 1.5 seconds\",\"1,234.568 seconds ago\",\"2 days ago\",\"1 day ago\",\"0 days ago\",\"in 0 days\",\"in 1 day\",\"in 2 days\",\"in 1.5 days\",\"1,234.568 days ago\",\"2 quarters ago\",\"1 quarter ago\",\"0 quarters ago\",\"in 0 quarters\",\"in 1 quarter\",\"in 2 quarters\",\"in 1.5 quarters\",\"1,234.568 quarters ago\",\"2 years ago\",\"1 year ago\",\"0 years ago\",\"in 0 years\",\"in 1 year\",\"in 2 years\",\"in 1.5 years\",\"1,234.568 years ago\"]",
            "en-US long auto [\"2 seconds ago\",\"1 second ago\",\"now\",\"now\",\"in 1 second\",\"in 2 seconds\",\"in 1.5 seconds\",\"1,234.568 seconds ago\",\"2 days ago\",\"yesterday\",\"today\",\"today\",\"tomorrow\",\"in 2 days\",\"in 1.5 days\",\"1,234.568 days ago\",\"2 quarters ago\",\"last quarter\",\"this quarter\",\"this quarter\",\"next quarter\",\"in 2 quarters\",\"in 1.5 quarters\",\"1,234.568 quarters ago\",\"2 years ago\",\"last year\",\"this year\",\"this year\",\"next year\",\"in 2 years\",\"in 1.5 years\",\"1,234.568 years ago\"]",
            "en-US short always [\"2 sec. ago\",\"1 sec. ago\",\"0 sec. ago\",\"in 0 sec.\",\"in 1 sec.\",\"in 2 sec.\",\"in 1.5 sec.\",\"1,234.568 sec. ago\",\"2 days ago\",\"1 day ago\",\"0 days ago\",\"in 0 days\",\"in 1 day\",\"in 2 days\",\"in 1.5 days\",\"1,234.568 days ago\",\"2 qtrs. ago\",\"1 qtr. ago\",\"0 qtrs. ago\",\"in 0 qtrs.\",\"in 1 qtr.\",\"in 2 qtrs.\",\"in 1.5 qtrs.\",\"1,234.568 qtrs. ago\",\"2 yr. ago\",\"1 yr. ago\",\"0 yr. ago\",\"in 0 yr.\",\"in 1 yr.\",\"in 2 yr.\",\"in 1.5 yr.\",\"1,234.568 yr. ago\"]",
            "en-US short auto [\"2 sec. ago\",\"1 sec. ago\",\"now\",\"now\",\"in 1 sec.\",\"in 2 sec.\",\"in 1.5 sec.\",\"1,234.568 sec. ago\",\"2 days ago\",\"yesterday\",\"today\",\"today\",\"tomorrow\",\"in 2 days\",\"in 1.5 days\",\"1,234.568 days ago\",\"2 qtrs. ago\",\"last qtr.\",\"this qtr.\",\"this qtr.\",\"next qtr.\",\"in 2 qtrs.\",\"in 1.5 qtrs.\",\"1,234.568 qtrs. ago\",\"2 yr. ago\",\"last yr.\",\"this yr.\",\"this yr.\",\"next yr.\",\"in 2 yr.\",\"in 1.5 yr.\",\"1,234.568 yr. ago\"]",
            "en-US narrow always [\"2s ago\",\"1s ago\",\"0s ago\",\"in 0s\",\"in 1s\",\"in 2s\",\"in 1.5s\",\"1,234.568s ago\",\"2d ago\",\"1d ago\",\"0d ago\",\"in 0d\",\"in 1d\",\"in 2d\",\"in 1.5d\",\"1,234.568d ago\",\"2q ago\",\"1q ago\",\"0q ago\",\"in 0q\",\"in 1q\",\"in 2q\",\"in 1.5q\",\"1,234.568q ago\",\"2y ago\",\"1y ago\",\"0y ago\",\"in 0y\",\"in 1y\",\"in 2y\",\"in 1.5y\",\"1,234.568y ago\"]",
            "en-US narrow auto [\"2s ago\",\"1s ago\",\"now\",\"now\",\"in 1s\",\"in 2s\",\"in 1.5s\",\"1,234.568s ago\",\"2d ago\",\"yesterday\",\"today\",\"today\",\"tomorrow\",\"in 2d\",\"in 1.5d\",\"1,234.568d ago\",\"2q ago\",\"last qtr.\",\"this qtr.\",\"this qtr.\",\"next qtr.\",\"in 2q\",\"in 1.5q\",\"1,234.568q ago\",\"2y ago\",\"last yr.\",\"this yr.\",\"this yr.\",\"next yr.\",\"in 2y\",\"in 1.5y\",\"1,234.568y ago\"]",
            "de-DE long always [\"vor 2 Sekunden\",\"vor 1 Sekunde\",\"vor 0 Sekunden\",\"in 0 Sekunden\",\"in 1 Sekunde\",\"in 2 Sekunden\",\"in 1,5 Sekunden\",\"vor 1.234,568 Sekunden\",\"vor 2 Tagen\",\"vor 1 Tag\",\"vor 0 Tagen\",\"in 0 Tagen\",\"in 1 Tag\",\"in 2 Tagen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Quartalen\",\"vor 1 Quartal\",\"vor 0 Quartalen\",\"in 0 Quartalen\",\"in 1 Quartal\",\"in 2 Quartalen\",\"in 1,5 Quartalen\",\"vor 1.234,568 Quartalen\",\"vor 2 Jahren\",\"vor 1 Jahr\",\"vor 0 Jahren\",\"in 0 Jahren\",\"in 1 Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "de-DE long auto [\"vor 2 Sekunden\",\"vor 1 Sekunde\",\"jetzt\",\"jetzt\",\"in 1 Sekunde\",\"in 2 Sekunden\",\"in 1,5 Sekunden\",\"vor 1.234,568 Sekunden\",\"vorgestern\",\"gestern\",\"heute\",\"heute\",\"morgen\",\"\u{fc}bermorgen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Quartalen\",\"letztes Quartal\",\"dieses Quartal\",\"dieses Quartal\",\"n\u{e4}chstes Quartal\",\"in 2 Quartalen\",\"in 1,5 Quartalen\",\"vor 1.234,568 Quartalen\",\"vor 2 Jahren\",\"letztes Jahr\",\"dieses Jahr\",\"dieses Jahr\",\"n\u{e4}chstes Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "de-DE short always [\"vor 2 Sek.\",\"vor 1 Sek.\",\"vor 0 Sek.\",\"in 0 Sek.\",\"in 1 Sek.\",\"in 2 Sek.\",\"in 1,5 Sek.\",\"vor 1.234,568 Sek.\",\"vor 2 Tagen\",\"vor 1 Tag\",\"vor 0 Tagen\",\"in 0 Tagen\",\"in 1 Tag\",\"in 2 Tagen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Quart.\",\"vor 1 Quart.\",\"vor 0 Quart.\",\"in 0 Quart.\",\"in 1 Quart.\",\"in 2 Quart.\",\"in 1,5 Quart.\",\"vor 1.234,568 Quart.\",\"vor 2 Jahren\",\"vor 1 Jahr\",\"vor 0 Jahren\",\"in 0 Jahren\",\"in 1 Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "de-DE short auto [\"vor 2 Sek.\",\"vor 1 Sek.\",\"jetzt\",\"jetzt\",\"in 1 Sek.\",\"in 2 Sek.\",\"in 1,5 Sek.\",\"vor 1.234,568 Sek.\",\"vorgestern\",\"gestern\",\"heute\",\"heute\",\"morgen\",\"\u{fc}bermorgen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Quart.\",\"letztes Quartal\",\"dieses Quartal\",\"dieses Quartal\",\"n\u{e4}chstes Quartal\",\"in 2 Quart.\",\"in 1,5 Quart.\",\"vor 1.234,568 Quart.\",\"vor 2 Jahren\",\"letztes Jahr\",\"dieses Jahr\",\"dieses Jahr\",\"n\u{e4}chstes Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "de-DE narrow always [\"vor 2 s\",\"vor 1 s\",\"vor 0 s\",\"in 0 s\",\"in 1 s\",\"in 2 s\",\"in 1,5 s\",\"vor 1.234,568 s\",\"vor 2 Tagen\",\"vor 1 Tag\",\"vor 0 Tagen\",\"in 0 Tagen\",\"in 1 Tag\",\"in 2 Tagen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Q\",\"vor 1 Q\",\"vor 0 Q\",\"in 0 Q\",\"in 1 Q\",\"in 2 Q\",\"in 1,5 Q\",\"vor 1.234,568 Q\",\"vor 2 Jahren\",\"vor 1 Jahr\",\"vor 0 Jahren\",\"in 0 Jahren\",\"in 1 Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "de-DE narrow auto [\"vor 2 s\",\"vor 1 s\",\"jetzt\",\"jetzt\",\"in 1 s\",\"in 2 s\",\"in 1,5 s\",\"vor 1.234,568 s\",\"vorgestern\",\"gestern\",\"heute\",\"heute\",\"morgen\",\"\u{fc}bermorgen\",\"in 1,5 Tagen\",\"vor 1.234,568 Tagen\",\"vor 2 Q\",\"letztes Quartal\",\"dieses Quartal\",\"dieses Quartal\",\"n\u{e4}chstes Quartal\",\"in 2 Q\",\"in 1,5 Q\",\"vor 1.234,568 Q\",\"vor 2 Jahren\",\"letztes Jahr\",\"dieses Jahr\",\"dieses Jahr\",\"n\u{e4}chstes Jahr\",\"in 2 Jahren\",\"in 1,5 Jahren\",\"vor 1.234,568 Jahren\"]",
            "ja-JP long always [\"2 \u{79d2}\u{524d}\",\"1 \u{79d2}\u{524d}\",\"0 \u{79d2}\u{524d}\",\"0 \u{79d2}\u{5f8c}\",\"1 \u{79d2}\u{5f8c}\",\"2 \u{79d2}\u{5f8c}\",\"1.5 \u{79d2}\u{5f8c}\",\"1,234.568 \u{79d2}\u{524d}\",\"2 \u{65e5}\u{524d}\",\"1 \u{65e5}\u{524d}\",\"0 \u{65e5}\u{524d}\",\"0 \u{65e5}\u{5f8c}\",\"1 \u{65e5}\u{5f8c}\",\"2 \u{65e5}\u{5f8c}\",\"1.5 \u{65e5}\u{5f8c}\",\"1,234.568 \u{65e5}\u{524d}\",\"2 \u{56db}\u{534a}\u{671f}\u{524d}\",\"1 \u{56db}\u{534a}\u{671f}\u{524d}\",\"0 \u{56db}\u{534a}\u{671f}\u{524d}\",\"0 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"2 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568 \u{56db}\u{534a}\u{671f}\u{524d}\",\"2 \u{5e74}\u{524d}\",\"1 \u{5e74}\u{524d}\",\"0 \u{5e74}\u{524d}\",\"0 \u{5e74}\u{5f8c}\",\"1 \u{5e74}\u{5f8c}\",\"2 \u{5e74}\u{5f8c}\",\"1.5 \u{5e74}\u{5f8c}\",\"1,234.568 \u{5e74}\u{524d}\"]",
            "ja-JP long auto [\"2 \u{79d2}\u{524d}\",\"1 \u{79d2}\u{524d}\",\"\u{4eca}\",\"\u{4eca}\",\"1 \u{79d2}\u{5f8c}\",\"2 \u{79d2}\u{5f8c}\",\"1.5 \u{79d2}\u{5f8c}\",\"1,234.568 \u{79d2}\u{524d}\",\"\u{4e00}\u{6628}\u{65e5}\",\"\u{6628}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{660e}\u{65e5}\",\"\u{660e}\u{5f8c}\u{65e5}\",\"1.5 \u{65e5}\u{5f8c}\",\"1,234.568 \u{65e5}\u{524d}\",\"2 \u{56db}\u{534a}\u{671f}\u{524d}\",\"\u{524d}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{7fcc}\u{56db}\u{534a}\u{671f}\",\"2 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568 \u{56db}\u{534a}\u{671f}\u{524d}\",\"2 \u{5e74}\u{524d}\",\"\u{6628}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{6765}\u{5e74}\",\"2 \u{5e74}\u{5f8c}\",\"1.5 \u{5e74}\u{5f8c}\",\"1,234.568 \u{5e74}\u{524d}\"]",
            "ja-JP short always [\"2 \u{79d2}\u{524d}\",\"1 \u{79d2}\u{524d}\",\"0 \u{79d2}\u{524d}\",\"0 \u{79d2}\u{5f8c}\",\"1 \u{79d2}\u{5f8c}\",\"2 \u{79d2}\u{5f8c}\",\"1.5 \u{79d2}\u{5f8c}\",\"1,234.568 \u{79d2}\u{524d}\",\"2 \u{65e5}\u{524d}\",\"1 \u{65e5}\u{524d}\",\"0 \u{65e5}\u{524d}\",\"0 \u{65e5}\u{5f8c}\",\"1 \u{65e5}\u{5f8c}\",\"2 \u{65e5}\u{5f8c}\",\"1.5 \u{65e5}\u{5f8c}\",\"1,234.568 \u{65e5}\u{524d}\",\"2 \u{56db}\u{534a}\u{671f}\u{524d}\",\"1 \u{56db}\u{534a}\u{671f}\u{524d}\",\"0 \u{56db}\u{534a}\u{671f}\u{524d}\",\"0 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"2 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568 \u{56db}\u{534a}\u{671f}\u{524d}\",\"2 \u{5e74}\u{524d}\",\"1 \u{5e74}\u{524d}\",\"0 \u{5e74}\u{524d}\",\"0 \u{5e74}\u{5f8c}\",\"1 \u{5e74}\u{5f8c}\",\"2 \u{5e74}\u{5f8c}\",\"1.5 \u{5e74}\u{5f8c}\",\"1,234.568 \u{5e74}\u{524d}\"]",
            "ja-JP short auto [\"2 \u{79d2}\u{524d}\",\"1 \u{79d2}\u{524d}\",\"\u{4eca}\",\"\u{4eca}\",\"1 \u{79d2}\u{5f8c}\",\"2 \u{79d2}\u{5f8c}\",\"1.5 \u{79d2}\u{5f8c}\",\"1,234.568 \u{79d2}\u{524d}\",\"\u{4e00}\u{6628}\u{65e5}\",\"\u{6628}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{660e}\u{65e5}\",\"\u{660e}\u{5f8c}\u{65e5}\",\"1.5 \u{65e5}\u{5f8c}\",\"1,234.568 \u{65e5}\u{524d}\",\"2 \u{56db}\u{534a}\u{671f}\u{524d}\",\"\u{524d}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{7fcc}\u{56db}\u{534a}\u{671f}\",\"2 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5 \u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568 \u{56db}\u{534a}\u{671f}\u{524d}\",\"2 \u{5e74}\u{524d}\",\"\u{6628}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{6765}\u{5e74}\",\"2 \u{5e74}\u{5f8c}\",\"1.5 \u{5e74}\u{5f8c}\",\"1,234.568 \u{5e74}\u{524d}\"]",
            "ja-JP narrow always [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"0\u{79d2}\u{524d}\",\"0\u{79d2}\u{5f8c}\",\"1\u{79d2}\u{5f8c}\",\"2\u{79d2}\u{5f8c}\",\"1.5\u{79d2}\u{5f8c}\",\"1,234.568\u{79d2}\u{524d}\",\"2\u{65e5}\u{524d}\",\"1\u{65e5}\u{524d}\",\"0\u{65e5}\u{524d}\",\"0\u{65e5}\u{5f8c}\",\"1\u{65e5}\u{5f8c}\",\"2\u{65e5}\u{5f8c}\",\"1.5\u{65e5}\u{5f8c}\",\"1,234.568\u{65e5}\u{524d}\",\"2\u{56db}\u{534a}\u{671f}\u{524d}\",\"1\u{56db}\u{534a}\u{671f}\u{524d}\",\"0\u{56db}\u{534a}\u{671f}\u{524d}\",\"0\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"2\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568\u{56db}\u{534a}\u{671f}\u{524d}\",\"2\u{5e74}\u{524d}\",\"1\u{5e74}\u{524d}\",\"0\u{5e74}\u{524d}\",\"0\u{5e74}\u{5f8c}\",\"1\u{5e74}\u{5f8c}\",\"2\u{5e74}\u{5f8c}\",\"1.5\u{5e74}\u{5f8c}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "ja-JP narrow auto [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"\u{4eca}\",\"\u{4eca}\",\"1\u{79d2}\u{5f8c}\",\"2\u{79d2}\u{5f8c}\",\"1.5\u{79d2}\u{5f8c}\",\"1,234.568\u{79d2}\u{524d}\",\"\u{4e00}\u{6628}\u{65e5}\",\"\u{6628}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{4eca}\u{65e5}\",\"\u{660e}\u{65e5}\",\"\u{660e}\u{5f8c}\u{65e5}\",\"1.5\u{65e5}\u{5f8c}\",\"1,234.568\u{65e5}\u{524d}\",\"2\u{56db}\u{534a}\u{671f}\u{524d}\",\"\u{524d}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{4eca}\u{56db}\u{534a}\u{671f}\",\"\u{7fcc}\u{56db}\u{534a}\u{671f}\",\"2\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1.5\u{56db}\u{534a}\u{671f}\u{5f8c}\",\"1,234.568\u{56db}\u{534a}\u{671f}\u{524d}\",\"2\u{5e74}\u{524d}\",\"\u{6628}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{6765}\u{5e74}\",\"2\u{5e74}\u{5f8c}\",\"1.5\u{5e74}\u{5f8c}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN long always [\"2\u{79d2}\u{949f}\u{524d}\",\"1\u{79d2}\u{949f}\u{524d}\",\"0\u{79d2}\u{949f}\u{524d}\",\"0\u{79d2}\u{949f}\u{540e}\",\"1\u{79d2}\u{949f}\u{540e}\",\"2\u{79d2}\u{949f}\u{540e}\",\"1.5\u{79d2}\u{949f}\u{540e}\",\"1,234.568\u{79d2}\u{949f}\u{524d}\",\"2\u{5929}\u{524d}\",\"1\u{5929}\u{524d}\",\"0\u{5929}\u{524d}\",\"0\u{5929}\u{540e}\",\"1\u{5929}\u{540e}\",\"2\u{5929}\u{540e}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"1\u{5e74}\u{524d}\",\"0\u{5e74}\u{524d}\",\"0\u{5e74}\u{540e}\",\"1\u{5e74}\u{540e}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN long auto [\"2\u{79d2}\u{949f}\u{524d}\",\"1\u{79d2}\u{949f}\u{524d}\",\"\u{73b0}\u{5728}\",\"\u{73b0}\u{5728}\",\"1\u{79d2}\u{949f}\u{540e}\",\"2\u{79d2}\u{949f}\u{540e}\",\"1.5\u{79d2}\u{949f}\u{540e}\",\"1,234.568\u{79d2}\u{949f}\u{524d}\",\"\u{524d}\u{5929}\",\"\u{6628}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{660e}\u{5929}\",\"\u{540e}\u{5929}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"\u{4e0a}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{4e0b}\u{5b63}\u{5ea6}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"\u{53bb}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{660e}\u{5e74}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN short always [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"0\u{79d2}\u{524d}\",\"0\u{79d2}\u{540e}\",\"1\u{79d2}\u{540e}\",\"2\u{79d2}\u{540e}\",\"1.5\u{79d2}\u{540e}\",\"1,234.568\u{79d2}\u{524d}\",\"2\u{5929}\u{524d}\",\"1\u{5929}\u{524d}\",\"0\u{5929}\u{524d}\",\"0\u{5929}\u{540e}\",\"1\u{5929}\u{540e}\",\"2\u{5929}\u{540e}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"1\u{5e74}\u{524d}\",\"0\u{5e74}\u{524d}\",\"0\u{5e74}\u{540e}\",\"1\u{5e74}\u{540e}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN short auto [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"\u{73b0}\u{5728}\",\"\u{73b0}\u{5728}\",\"1\u{79d2}\u{540e}\",\"2\u{79d2}\u{540e}\",\"1.5\u{79d2}\u{540e}\",\"1,234.568\u{79d2}\u{524d}\",\"\u{524d}\u{5929}\",\"\u{6628}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{660e}\u{5929}\",\"\u{540e}\u{5929}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"\u{4e0a}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{4e0b}\u{5b63}\u{5ea6}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"\u{53bb}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{660e}\u{5e74}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN narrow always [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"0\u{79d2}\u{524d}\",\"0\u{79d2}\u{540e}\",\"1\u{79d2}\u{540e}\",\"2\u{79d2}\u{540e}\",\"1.5\u{79d2}\u{540e}\",\"1,234.568\u{79d2}\u{524d}\",\"2\u{5929}\u{524d}\",\"1\u{5929}\u{524d}\",\"0\u{5929}\u{524d}\",\"0\u{5929}\u{540e}\",\"1\u{5929}\u{540e}\",\"2\u{5929}\u{540e}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"0\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"1\u{5e74}\u{524d}\",\"0\u{5e74}\u{524d}\",\"0\u{5e74}\u{540e}\",\"1\u{5e74}\u{540e}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "zh-CN narrow auto [\"2\u{79d2}\u{524d}\",\"1\u{79d2}\u{524d}\",\"\u{73b0}\u{5728}\",\"\u{73b0}\u{5728}\",\"1\u{79d2}\u{540e}\",\"2\u{79d2}\u{540e}\",\"1.5\u{79d2}\u{540e}\",\"1,234.568\u{79d2}\u{524d}\",\"\u{524d}\u{5929}\",\"\u{6628}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{4eca}\u{5929}\",\"\u{660e}\u{5929}\",\"\u{540e}\u{5929}\",\"1.5\u{5929}\u{540e}\",\"1,234.568\u{5929}\u{524d}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"\u{4e0a}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{672c}\u{5b63}\u{5ea6}\",\"\u{4e0b}\u{5b63}\u{5ea6}\",\"2\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1.5\u{4e2a}\u{5b63}\u{5ea6}\u{540e}\",\"1,234.568\u{4e2a}\u{5b63}\u{5ea6}\u{524d}\",\"2\u{5e74}\u{524d}\",\"\u{53bb}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{4eca}\u{5e74}\",\"\u{660e}\u{5e74}\",\"2\u{5e74}\u{540e}\",\"1.5\u{5e74}\u{540e}\",\"1,234.568\u{5e74}\u{524d}\"]",
            "ko-KR long always [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"0\u{cd08} \u{c804}\",\"0\u{cd08} \u{d6c4}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"2\u{c77c} \u{c804}\",\"1\u{c77c} \u{c804}\",\"0\u{c77c} \u{c804}\",\"0\u{c77c} \u{d6c4}\",\"1\u{c77c} \u{d6c4}\",\"2\u{c77c} \u{d6c4}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"1\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{d6c4}\",\"1\u{bd84}\u{ae30} \u{d6c4}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"1\u{b144} \u{c804}\",\"0\u{b144} \u{c804}\",\"0\u{b144} \u{d6c4}\",\"1\u{b144} \u{d6c4}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
            "ko-KR long auto [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"\u{c9c0}\u{ae08}\",\"\u{c9c0}\u{ae08}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"\u{adf8}\u{c800}\u{aed8}\",\"\u{c5b4}\u{c81c}\",\"\u{c624}\u{b298}\",\"\u{c624}\u{b298}\",\"\u{b0b4}\u{c77c}\",\"\u{baa8}\u{b808}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"\u{c9c0}\u{b09c} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{b2e4}\u{c74c} \u{bd84}\u{ae30}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"\u{c791}\u{b144}\",\"\u{c62c}\u{d574}\",\"\u{c62c}\u{d574}\",\"\u{b0b4}\u{b144}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
            "ko-KR short always [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"0\u{cd08} \u{c804}\",\"0\u{cd08} \u{d6c4}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"2\u{c77c} \u{c804}\",\"1\u{c77c} \u{c804}\",\"0\u{c77c} \u{c804}\",\"0\u{c77c} \u{d6c4}\",\"1\u{c77c} \u{d6c4}\",\"2\u{c77c} \u{d6c4}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"1\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{d6c4}\",\"1\u{bd84}\u{ae30} \u{d6c4}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"1\u{b144} \u{c804}\",\"0\u{b144} \u{c804}\",\"0\u{b144} \u{d6c4}\",\"1\u{b144} \u{d6c4}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
            "ko-KR short auto [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"\u{c9c0}\u{ae08}\",\"\u{c9c0}\u{ae08}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"\u{adf8}\u{c800}\u{aed8}\",\"\u{c5b4}\u{c81c}\",\"\u{c624}\u{b298}\",\"\u{c624}\u{b298}\",\"\u{b0b4}\u{c77c}\",\"\u{baa8}\u{b808}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"\u{c9c0}\u{b09c} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{b2e4}\u{c74c} \u{bd84}\u{ae30}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"\u{c791}\u{b144}\",\"\u{c62c}\u{d574}\",\"\u{c62c}\u{d574}\",\"\u{b0b4}\u{b144}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
            "ko-KR narrow always [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"0\u{cd08} \u{c804}\",\"0\u{cd08} \u{d6c4}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"2\u{c77c} \u{c804}\",\"1\u{c77c} \u{c804}\",\"0\u{c77c} \u{c804}\",\"0\u{c77c} \u{d6c4}\",\"1\u{c77c} \u{d6c4}\",\"2\u{c77c} \u{d6c4}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"1\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{c804}\",\"0\u{bd84}\u{ae30} \u{d6c4}\",\"1\u{bd84}\u{ae30} \u{d6c4}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"1\u{b144} \u{c804}\",\"0\u{b144} \u{c804}\",\"0\u{b144} \u{d6c4}\",\"1\u{b144} \u{d6c4}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
            "ko-KR narrow auto [\"2\u{cd08} \u{c804}\",\"1\u{cd08} \u{c804}\",\"\u{c9c0}\u{ae08}\",\"\u{c9c0}\u{ae08}\",\"1\u{cd08} \u{d6c4}\",\"2\u{cd08} \u{d6c4}\",\"1.5\u{cd08} \u{d6c4}\",\"1,234.568\u{cd08} \u{c804}\",\"\u{adf8}\u{c800}\u{aed8}\",\"\u{c5b4}\u{c81c}\",\"\u{c624}\u{b298}\",\"\u{c624}\u{b298}\",\"\u{b0b4}\u{c77c}\",\"\u{baa8}\u{b808}\",\"1.5\u{c77c} \u{d6c4}\",\"1,234.568\u{c77c} \u{c804}\",\"2\u{bd84}\u{ae30} \u{c804}\",\"\u{c9c0}\u{b09c} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{c774}\u{bc88} \u{bd84}\u{ae30}\",\"\u{b2e4}\u{c74c} \u{bd84}\u{ae30}\",\"2\u{bd84}\u{ae30} \u{d6c4}\",\"1.5\u{bd84}\u{ae30} \u{d6c4}\",\"1,234.568\u{bd84}\u{ae30} \u{c804}\",\"2\u{b144} \u{c804}\",\"\u{c791}\u{b144}\",\"\u{c62c}\u{d574}\",\"\u{c62c}\u{d574}\",\"\u{b0b4}\u{b144}\",\"2\u{b144} \u{d6c4}\",\"1.5\u{b144} \u{d6c4}\",\"1,234.568\u{b144} \u{c804}\"]",
        ],
    );
}

/// formatToParts splits the number into integer, group, decimal and fraction
/// parts tagged with the unit.
#[test]
fn relative_time_parts() {
    assert_lines(
        "const r = new Intl.RelativeTimeFormat('en');\nconsole.log(JSON.stringify(r.formatToParts(-1000.5, 'days')));\nconsole.log(JSON.stringify(r.formatToParts(100, 'second')));\nconsole.log(JSON.stringify(new Intl.RelativeTimeFormat('de').formatToParts(1234.25, 'hour')));\nconsole.log(JSON.stringify(new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).formatToParts(-1, 'day')));\nconsole.log(JSON.stringify(new Intl.RelativeTimeFormat('ja').formatToParts(3, 'month')));\n",
        &[
            "[{\"type\":\"integer\",\"value\":\"1\",\"unit\":\"day\"},{\"type\":\"group\",\"value\":\",\",\"unit\":\"day\"},{\"type\":\"integer\",\"value\":\"000\",\"unit\":\"day\"},{\"type\":\"decimal\",\"value\":\".\",\"unit\":\"day\"},{\"type\":\"fraction\",\"value\":\"5\",\"unit\":\"day\"},{\"type\":\"literal\",\"value\":\" days ago\"}]",
            "[{\"type\":\"literal\",\"value\":\"in \"},{\"type\":\"integer\",\"value\":\"100\",\"unit\":\"second\"},{\"type\":\"literal\",\"value\":\" seconds\"}]",
            "[{\"type\":\"literal\",\"value\":\"in \"},{\"type\":\"integer\",\"value\":\"1\",\"unit\":\"hour\"},{\"type\":\"group\",\"value\":\".\",\"unit\":\"hour\"},{\"type\":\"integer\",\"value\":\"234\",\"unit\":\"hour\"},{\"type\":\"decimal\",\"value\":\",\",\"unit\":\"hour\"},{\"type\":\"fraction\",\"value\":\"25\",\"unit\":\"hour\"},{\"type\":\"literal\",\"value\":\" Stunden\"}]",
            "[{\"type\":\"literal\",\"value\":\"yesterday\"}]",
            "[{\"type\":\"integer\",\"value\":\"3\",\"unit\":\"month\"},{\"type\":\"literal\",\"value\":\" \u{304b}\u{6708}\u{5f8c}\"}]",
        ],
    );
}

/// Every pattern language, type and style over lists of zero to five items.
#[test]
fn list_matrix() {
    assert_lines(
        "const lists = [[], ['a'], ['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd', 'e']];\nfor (const loc of ['en-US', 'de-DE', 'ja-JP', 'zh-CN', 'ko-KR']) {\n  for (const type of ['conjunction', 'disjunction', 'unit']) {\n    for (const style of ['long', 'short', 'narrow']) {\n      const f = new Intl.ListFormat(loc, { type, style });\n      console.log(loc, type, style, JSON.stringify(lists.map((xs) => f.format(xs))));\n    }\n  }\n}\n",
        &[
            "en-US conjunction long [\"\",\"a\",\"a and b\",\"a, b, and c\",\"a, b, c, d, and e\"]",
            "en-US conjunction short [\"\",\"a\",\"a & b\",\"a, b, & c\",\"a, b, c, d, & e\"]",
            "en-US conjunction narrow [\"\",\"a\",\"a, b\",\"a, b, c\",\"a, b, c, d, e\"]",
            "en-US disjunction long [\"\",\"a\",\"a or b\",\"a, b, or c\",\"a, b, c, d, or e\"]",
            "en-US disjunction short [\"\",\"a\",\"a or b\",\"a, b, or c\",\"a, b, c, d, or e\"]",
            "en-US disjunction narrow [\"\",\"a\",\"a or b\",\"a, b, or c\",\"a, b, c, d, or e\"]",
            "en-US unit long [\"\",\"a\",\"a, b\",\"a, b, c\",\"a, b, c, d, e\"]",
            "en-US unit short [\"\",\"a\",\"a, b\",\"a, b, c\",\"a, b, c, d, e\"]",
            "en-US unit narrow [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
            "de-DE conjunction long [\"\",\"a\",\"a und b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "de-DE conjunction short [\"\",\"a\",\"a und b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "de-DE conjunction narrow [\"\",\"a\",\"a und b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "de-DE disjunction long [\"\",\"a\",\"a oder b\",\"a, b oder c\",\"a, b, c, d oder e\"]",
            "de-DE disjunction short [\"\",\"a\",\"a oder b\",\"a, b oder c\",\"a, b, c, d oder e\"]",
            "de-DE disjunction narrow [\"\",\"a\",\"a oder b\",\"a, b oder c\",\"a, b, c, d oder e\"]",
            "de-DE unit long [\"\",\"a\",\"a, b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "de-DE unit short [\"\",\"a\",\"a, b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "de-DE unit narrow [\"\",\"a\",\"a, b\",\"a, b und c\",\"a, b, c, d und e\"]",
            "ja-JP conjunction long [\"\",\"a\",\"a\u{3001}b\",\"a\u{3001}b\u{3001}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}e\"]",
            "ja-JP conjunction short [\"\",\"a\",\"a\u{3001}b\",\"a\u{3001}b\u{3001}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}e\"]",
            "ja-JP conjunction narrow [\"\",\"a\",\"a\u{3001}b\",\"a\u{3001}b\u{3001}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}e\"]",
            "ja-JP disjunction long [\"\",\"a\",\"a\u{307e}\u{305f}\u{306f}b\",\"a\u{3001}b\u{3001}\u{307e}\u{305f}\u{306f}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}\u{307e}\u{305f}\u{306f}e\"]",
            "ja-JP disjunction short [\"\",\"a\",\"a\u{307e}\u{305f}\u{306f}b\",\"a\u{3001}b\u{3001}\u{307e}\u{305f}\u{306f}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}\u{307e}\u{305f}\u{306f}e\"]",
            "ja-JP disjunction narrow [\"\",\"a\",\"a\u{307e}\u{305f}\u{306f}b\",\"a\u{3001}b\u{3001}\u{307e}\u{305f}\u{306f}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}\u{307e}\u{305f}\u{306f}e\"]",
            "ja-JP unit long [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
            "ja-JP unit short [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
            "ja-JP unit narrow [\"\",\"a\",\"ab\",\"abc\",\"abcde\"]",
            "zh-CN conjunction long [\"\",\"a\",\"a\u{548c}b\",\"a\u{3001}b\u{548c}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{548c}e\"]",
            "zh-CN conjunction short [\"\",\"a\",\"a\u{548c}b\",\"a\u{3001}b\u{548c}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{548c}e\"]",
            "zh-CN conjunction narrow [\"\",\"a\",\"a\u{3001}b\",\"a\u{3001}b\u{3001}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{3001}e\"]",
            "zh-CN disjunction long [\"\",\"a\",\"a\u{6216}b\",\"a\u{3001}b\u{6216}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{6216}e\"]",
            "zh-CN disjunction short [\"\",\"a\",\"a\u{6216}b\",\"a\u{3001}b\u{6216}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{6216}e\"]",
            "zh-CN disjunction narrow [\"\",\"a\",\"a\u{6216}b\",\"a\u{3001}b\u{6216}c\",\"a\u{3001}b\u{3001}c\u{3001}d\u{6216}e\"]",
            "zh-CN unit long [\"\",\"a\",\"ab\",\"abc\",\"abcde\"]",
            "zh-CN unit short [\"\",\"a\",\"ab\",\"abc\",\"abcde\"]",
            "zh-CN unit narrow [\"\",\"a\",\"ab\",\"abc\",\"abcde\"]",
            "ko-KR conjunction long [\"\",\"a\",\"a \u{bc0f} b\",\"a, b \u{bc0f} c\",\"a, b, c, d \u{bc0f} e\"]",
            "ko-KR conjunction short [\"\",\"a\",\"a \u{bc0f} b\",\"a, b \u{bc0f} c\",\"a, b, c, d \u{bc0f} e\"]",
            "ko-KR conjunction narrow [\"\",\"a\",\"a \u{bc0f} b\",\"a, b \u{bc0f} c\",\"a, b, c, d \u{bc0f} e\"]",
            "ko-KR disjunction long [\"\",\"a\",\"a \u{b610}\u{b294} b\",\"a, b \u{b610}\u{b294} c\",\"a, b, c, d \u{b610}\u{b294} e\"]",
            "ko-KR disjunction short [\"\",\"a\",\"a \u{b610}\u{b294} b\",\"a, b \u{b610}\u{b294} c\",\"a, b, c, d \u{b610}\u{b294} e\"]",
            "ko-KR disjunction narrow [\"\",\"a\",\"a \u{b610}\u{b294} b\",\"a, b \u{b610}\u{b294} c\",\"a, b, c, d \u{b610}\u{b294} e\"]",
            "ko-KR unit long [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
            "ko-KR unit short [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
            "ko-KR unit narrow [\"\",\"a\",\"a b\",\"a b c\",\"a b c d e\"]",
        ],
    );
}

/// formatToParts, any iterable of strings, and an absent list.
#[test]
fn list_parts_and_iterables() {
    assert_lines(
        "const l = new Intl.ListFormat('en');\nconsole.log(JSON.stringify(l.formatToParts(['a', 'b', 'c'])));\nconsole.log(l.format(new Set(['x', 'y'])), l.format('ab'), JSON.stringify(l.format()), JSON.stringify(l.format(undefined)));\nconsole.log(JSON.stringify(new Intl.ListFormat('de', { type: 'disjunction' }).formatToParts(['Rot', 'Gelb'])));\n",
        &[
            "[{\"type\":\"element\",\"value\":\"a\"},{\"type\":\"literal\",\"value\":\", \"},{\"type\":\"element\",\"value\":\"b\"},{\"type\":\"literal\",\"value\":\", and \"},{\"type\":\"element\",\"value\":\"c\"}]",
            "x and y a and b \"\" \"\"",
            "[{\"type\":\"element\",\"value\":\"Rot\"},{\"type\":\"literal\",\"value\":\" oder \"},{\"type\":\"element\",\"value\":\"Gelb\"}]",
        ],
    );
}

/// Bad units, non-finite values and out-of-range options are RangeErrors with
/// Node's messages; a non-string list item is a TypeError.
#[test]
fn errors() {
    assert_lines(
        "const show = (fn) => { try { return 'ok ' + fn(); } catch (e) { return e.constructor.name + (e instanceof RangeError ? ': ' + e.message : ''); } };\nconsole.log(show(() => new Intl.RelativeTimeFormat('en').format(1, 'decade')));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en').formatToParts(1, 'decades')));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en').format(Infinity, 'day')));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en').format(NaN, 'day')));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en', { style: 'tiny' })));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en', { numeric: 'sometimes' })));\nconsole.log(show(() => new Intl.ListFormat('en', { type: 'x' })));\nconsole.log(show(() => new Intl.ListFormat('en', { style: 'wide' })));\nconsole.log(show(() => new Intl.ListFormat('en').format(['a', 1])));\nconsole.log(show(() => new Intl.RelativeTimeFormat('en').format('2', 'weeks')));\n",
        &[
            "RangeError: Invalid unit argument for Intl.RelativeTimeFormat.prototype.format() 'decade'",
            "RangeError: Invalid unit argument for Intl.RelativeTimeFormat.prototype.formatToParts() 'decades'",
            "RangeError: Value need to be finite number for Intl.RelativeTimeFormat.prototype.format()",
            "RangeError: Value need to be finite number for Intl.RelativeTimeFormat.prototype.format()",
            "RangeError: Value tiny out of range for Intl.RelativeTimeFormat options property style",
            "RangeError: Value sometimes out of range for Intl.RelativeTimeFormat options property numeric",
            "RangeError: Value x out of range for Intl.ListFormat options property type",
            "RangeError: Value wide out of range for Intl.ListFormat options property style",
            "TypeError",
            "ok in 2 weeks",
        ],
    );
}
