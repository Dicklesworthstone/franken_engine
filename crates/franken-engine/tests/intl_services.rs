//! ECMA-402 `Intl`: NumberFormat, DateTimeFormat, Collator, PluralRules and
//! getCanonicalLocales over the engine's locale formatters.
//!
//! Date.prototype.toLocale*String with options are DateTimeFormats over
//! ToDateTimeOptions (they refused every option but a UTC timeZone).
//!
//! `Intl` was not defined, so `new Intl.NumberFormat(...)`,
//! `Intl.DateTimeFormat().resolvedOptions().timeZone` and luxon threw a
//! ReferenceError. Expected output is Node v22.2.0's (TZ=UTC) for the same
//! programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn console_output(source: &str) -> Result<String, String> {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(source).map_err(|error| error.to_string())?;
    Ok(outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "namespace",
        r#"console.log(typeof Intl, Object.prototype.toString.call(Intl), typeof Intl.NumberFormat, Intl.NumberFormat.length, Intl.NumberFormat.name, typeof globalThis.Intl);"#,
        r#"object [object Intl] function 0 NumberFormat object"#,
    ),
    (
        "number_format",
        r#"const nf = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }); console.log(nf.format(1234.5), [1234.5, 0.5].map(new Intl.NumberFormat('en-US').format).join('|'), new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(2.5), new Intl.NumberFormat('de-DE', { minimumFractionDigits: 2 }).format(1234.5), new Intl.NumberFormat('en', { style: 'percent' }).format(0.256), Intl.NumberFormat().format(1e6), Object.prototype.toString.call(nf), Object.keys(nf).length);"#,
        r#"$1,234.50 1,234.5|0.5 3 1.234,50 26% 1,000,000 [object Intl.NumberFormat] 0"#,
    ),
    (
        "number_format_resolved_options",
        r#"console.log(JSON.stringify(new Intl.NumberFormat().resolvedOptions())); console.log(JSON.stringify(new Intl.NumberFormat('en-US', { style: 'currency', currency: 'usd' }).resolvedOptions())); console.log(JSON.stringify(new Intl.NumberFormat('de-DE', { minimumFractionDigits: 2, useGrouping: false }).resolvedOptions()));"#,
        r#"{"locale":"en-US","numberingSystem":"latn","style":"decimal","minimumIntegerDigits":1,"minimumFractionDigits":0,"maximumFractionDigits":3,"useGrouping":"auto","notation":"standard","signDisplay":"auto","roundingIncrement":1,"roundingMode":"halfExpand","roundingPriority":"auto","trailingZeroDisplay":"auto"}
{"locale":"en-US","numberingSystem":"latn","style":"currency","currency":"USD","currencyDisplay":"symbol","currencySign":"standard","minimumIntegerDigits":1,"minimumFractionDigits":2,"maximumFractionDigits":2,"useGrouping":"auto","notation":"standard","signDisplay":"auto","roundingIncrement":1,"roundingMode":"halfExpand","roundingPriority":"auto","trailingZeroDisplay":"auto"}
{"locale":"de-DE","numberingSystem":"latn","style":"decimal","minimumIntegerDigits":1,"minimumFractionDigits":2,"maximumFractionDigits":3,"useGrouping":false,"notation":"standard","signDisplay":"auto","roundingIncrement":1,"roundingMode":"halfExpand","roundingPriority":"auto","trailingZeroDisplay":"auto"}"#,
    ),
    (
        "date_time_format_layouts",
        r#"const a = new Date(Date.UTC(2026, 8, 30, 15, 4, 5)), b = new Date(Date.UTC(2021, 0, 3, 0, 7, 9)); const f = (o) => [a, b].map((d) => new Intl.DateTimeFormat('en-US', o).format(d)).join(' / '); console.log([f(), f({ dateStyle: 'full' }), f({ dateStyle: 'medium', timeStyle: 'short' }), f({ dateStyle: 'long', timeStyle: 'short' }), f({ timeStyle: 'long' }), f({ year: 'numeric', month: 'long', day: 'numeric' }), f({ weekday: 'short', month: 'short', day: 'numeric' }), f({ year: 'numeric', month: '2-digit', day: '2-digit' }), f({ month: 'long', year: 'numeric' }), f({ hour: '2-digit', minute: '2-digit' }), f({ hour: 'numeric', minute: '2-digit', hour12: false }), f({ year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }), f({ weekday: 'long', hour: 'numeric', minute: '2-digit' }), f({ month: 'narrow' }), f({ minute: '2-digit', second: '2-digit' })].join('\n'));"#,
        r#"9/30/2026 / 1/3/2021
Wednesday, September 30, 2026 / Sunday, January 3, 2021
Sep 30, 2026, 3:04 PM / Jan 3, 2021, 12:07 AM
September 30, 2026 at 3:04 PM / January 3, 2021 at 12:07 AM
3:04:05 PM UTC / 12:07:09 AM UTC
September 30, 2026 / January 3, 2021
Wed, Sep 30 / Sun, Jan 3
09/30/2026 / 01/03/2021
September 2026 / January 2021
03:04 PM / 12:07 AM
15:04 / 00:07
Sep 30, 2026, 3:04 PM / Jan 3, 2021, 12:07 AM
Wednesday 3:04 PM / Sunday 12:07 AM
S / J
04:05 / 07:09"#,
    ),
    (
        "date_time_format_defaults",
        r#"console.log(JSON.stringify(new Intl.DateTimeFormat().resolvedOptions()), Intl.DateTimeFormat().resolvedOptions().timeZone, new Intl.DateTimeFormat().format(0), new Intl.DateTimeFormat('en-GB').format(0), new Intl.DateTimeFormat('de').format(0)); console.log(JSON.stringify(new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', hour: 'numeric' }).resolvedOptions()));"#,
        r#"{"locale":"en-US","calendar":"gregory","numberingSystem":"latn","timeZone":"UTC","year":"numeric","month":"numeric","day":"numeric"} UTC 1/1/1970 01/01/1970 1.1.1970
{"locale":"en-US","calendar":"gregory","numberingSystem":"latn","timeZone":"UTC","hourCycle":"h12","hour12":true,"month":"long","day":"numeric","hour":"numeric"}"#,
    ),
    (
        "collator",
        r#"console.log(['a', 'B', 'c', 'á'].sort(new Intl.Collator().compare).join(), ['item10', 'item2'].sort(new Intl.Collator(undefined, { numeric: true }).compare).join(), new Intl.Collator('en', { sensitivity: 'base' }).compare('a', 'A'), JSON.stringify(new Intl.Collator().resolvedOptions()));"#,
        r#"a,á,B,c item2,item10 0 {"locale":"en-US","usage":"sort","sensitivity":"variant","ignorePunctuation":false,"collation":"default","numeric":false,"caseFirst":"false"}"#,
    ),
    (
        "plural_rules",
        r#"const pr = new Intl.PluralRules('en-US'), po = new Intl.PluralRules('en-US', { type: 'ordinal' }); console.log([0, 1, 2, 3, 4, 11, 12, 13, 21, 22, 23, 101, 1.5, -1].map((n) => pr.select(n) + '/' + po.select(n)).join(' '), new Intl.PluralRules('fr').select(0), new Intl.PluralRules('de').select(1), new Intl.PluralRules('ja').select(1), JSON.stringify(new Intl.PluralRules().resolvedOptions()));"#,
        r#"other/other one/one other/two other/few other/other other/other other/other other/other other/one other/two other/few other/one other/other one/one one one other {"locale":"en-US","type":"cardinal","minimumIntegerDigits":1,"minimumFractionDigits":0,"maximumFractionDigits":3,"pluralCategories":["one","other"],"roundingIncrement":1,"roundingMode":"halfExpand","roundingPriority":"auto","trailingZeroDisplay":"auto"}"#,
    ),
    (
        "canonical_locales",
        r#"console.log(JSON.stringify(Intl.getCanonicalLocales(['EN-us', 'de-de', 'zh-hant-tw', 'en-US'])), JSON.stringify(Intl.getCanonicalLocales('ja')), JSON.stringify(Intl.getCanonicalLocales()));"#,
        r#"["en-US","de-DE","zh-Hant-TW"] ["ja"] []"#,
    ),
    (
        "option_errors",
        r#"const out = []; for (const f of [() => new Intl.NumberFormat('en', { style: 'bogus' }), () => Intl.getCanonicalLocales('not a locale'), () => new Intl.DateTimeFormat('en', { dateStyle: 'medium', year: 'numeric' }), () => new Intl.NumberFormat('en', { style: 'currency' }), () => new Intl.DateTimeFormat('en', { month: 'bogus' })]) { try { f(); out.push('none'); } catch (e) { out.push(e.constructor.name); } } console.log(out.join());"#,
        r#"RangeError,RangeError,TypeError,TypeError,RangeError"#,
    ),
    // A five-to-eight-letter language names no ICU locale: Node falls back
    // to en-US (fast-levenshtein builds `new Intl.Collator('generic', ...)`
    // in a try/catch and logged a warning when it threw).
    (
        "unknown_language_falls_back",
        r#"console.log(new Intl.Collator('generic').resolvedOptions().locale, new Intl.Collator('generic', { sensitivity: 'base' }).compare('a', 'A'), new Intl.NumberFormat('generic').format(1234.5), new Intl.DateTimeFormat('abcdefgh').resolvedOptions().locale, new Intl.PluralRules('generic').select(1), Intl.getCanonicalLocales('generic').join());"#,
        "en-US 0 1,234.5 en-US one generic",
    ),
    (
        "date_to_locale_with_options",
        r#"const d = new Date(Date.UTC(2026, 8, 30, 15, 4, 5)); console.log([d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }), d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), d.toLocaleDateString(undefined, { timeZone: 'UTC' }), d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }), d.toLocaleTimeString('en-US', { hour12: false }), d.toLocaleString('en-US', { timeZone: 'UTC' }), d.toLocaleString('de-DE', { timeZone: 'UTC' }), d.toLocaleDateString('en-GB', { timeZone: 'UTC' }), d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }), d.toLocaleDateString('en-US', { dateStyle: 'long' }), d.toLocaleTimeString('en-US', { timeStyle: 'short' }), d.toLocaleDateString('en-US', { hour: 'numeric' }), d.toLocaleTimeString('en-US', { weekday: 'short' }), d.toLocaleString('en-US', { month: 'long' })].join(' | ')); for (const f of [() => d.toLocaleDateString('en-US', { timeStyle: 'short' }), () => d.toLocaleTimeString('en-US', { dateStyle: 'short' })]) { try { f(); console.log('none'); } catch (e) { console.log(e.constructor.name); } } console.log(new Date(NaN).toLocaleDateString('en-US', { month: 'long' }));"#,
        r#"Wednesday, September 30, 2026 | Sep 30 | 9/30/2026 | 03:04 PM | 15:04:05 | 9/30/2026, 3:04:05 PM | 30.9.2026, 15:04:05 | 30/09/2026 | Sep 30, 2026, 3:04 PM | September 30, 2026 | 3:04 PM | 9/30/2026, 3 PM | Wed 3:04:05 PM | September
TypeError
TypeError
Invalid Date"#,
    ),
];

#[test]
fn intl_services_match_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// A locale or option the formatters do not cover is a TypeError at
/// construction (Node would format `es-ES` in Spanish; the engine must not
/// print an English string instead).
#[test]
fn unsupported_locales_and_options_are_refused() {
    for source in [
        "new Intl.NumberFormat('es-ES').format(1);",
        "new Intl.NumberFormat('en', { notation: 'compact' });",
        "new Intl.DateTimeFormat('de', { month: 'long' });",
        "new Intl.DateTimeFormat('en', { timeZone: 'America/New_York' });",
        "new Intl.Collator('sv');",
        "new Intl.PluralRules('ru');",
    ] {
        let program = format!(
            "try {{ {source} console.log('none'); }} catch (e) {{ console.log(e.constructor.name); }}"
        );
        assert_eq!(
            console_output(&program).as_deref(),
            Ok("TypeError"),
            "`{source}` must be refused"
        );
    }
}
