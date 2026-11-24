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
    (
        // Number.prototype.toLocaleString formats as NumberFormat does: a
        // defaulted option (`currencyDisplay: 'symbol'`, dinero), the en-US
        // fallback for a five-to-eight-letter language (`fullwide`,
        // temporal-polyfill), string useGrouping and a null options object.
        "number_to_locale_string_as_number_format",
        r#"function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } } console.log([(53.75).toLocaleString('en-US', { style: 'currency', currency: 'USD', currencyDisplay: 'symbol' }), (1234.5).toLocaleString('fullwide', { useGrouping: false }), (12).toLocaleString('fullwide'), (0.5).toLocaleString('en-US', { style: 'percent', signDisplay: 'auto' }), (1234.5).toLocaleString(undefined, { useGrouping: 'always' }), attempt(() => (1).toLocaleString('en', null))].join(' | '));"#,
        r#"$53.75 | 1234.5 | 12 | 50% | 1,234.5 | TypeError"#,
    ),
    (
        // DateTimeFormat formatToParts (bd-9vouw.142): the typed pieces format
        // lays out; croner reads the UTC fields of a date through it. The
        // literal before a day period is U+202F in the parts while format()
        // has an ASCII space there (V8), so those two do not join equal.
        "date_time_format_to_parts",
        r#"const f = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: false }); const d = new Date(Date.UTC(2024, 5, 7, 10, 0, 5)); const p = f.formatToParts(d); const show = (parts) => parts.map(x => x.type + '=' + x.value.replace(/\u202f/g, '<NNBSP>')).join('|'); console.log(show(p), p.map(x => x.value).join('') === f.format(d), Object.keys(p[0]).join()); console.log(new Intl.DateTimeFormat('en-US', { dateStyle: 'full', timeStyle: 'long', timeZone: 'UTC' }).formatToParts(d).map(x => x.type).join(',')); console.log(show(new Intl.DateTimeFormat('en-US', { timeZone: 'UTC' }).formatToParts(0))); const g = new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }); console.log(show(g.formatToParts(d)), JSON.stringify(g.format(d)), g.formatToParts(d).map(x => x.value).join('') === g.format(d));"#,
        r#"month=6|literal=/|day=7|literal=/|year=2024|literal=, |hour=10|literal=:|minute=00|literal=:|second=05 true type,value
weekday,literal,month,literal,day,literal,year,literal,hour,literal,minute,literal,second,literal,dayPeriod,literal,timeZoneName
month=1|literal=/|day=1|literal=/|year=1970
weekday=Fri|literal=, |month=June|literal= |day=7|literal= at |hour=10|literal=:|minute=00|literal=<NNBSP>|dayPeriod=AM|literal= |timeZoneName=UTC "Fri, June 7 at 10:00 AM UTC" false"#,
    ),
    (
        // useGrouping as ES2023 GetBooleanOrStringNumberFormatOption reads
        // it: true "always", any falsy value false, "true"/"false" the
        // default (temporal-polyfill: `toLocaleString('fullwide', {
        // useGrouping: 0 })`), anything else outside the list a RangeError.
        "number_format_use_grouping_values",
        r#"function g(v) { try { const f = new Intl.NumberFormat('en', { useGrouping: v }); return f.format(1234567) + ':' + f.resolvedOptions().useGrouping; } catch (e) { return e.constructor.name; } } console.log([0, 1, '', 'true', 'false', 'always', 'auto', null, NaN, 'x'].map(g).join(' | '), (1234).toLocaleString('fullwide', { useGrouping: 0 }));"#,
        r#"1234567:false | RangeError | 1234567:false | 1,234,567:auto | 1,234,567:auto | 1,234,567:always | 1,234,567:auto | 1234567:false | 1234567:false | RangeError 1234"#,
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

#[test]
fn intl_services_use_shared_intrinsic_prototypes() {
    let source = r#"
        for (const name of ['NumberFormat', 'DateTimeFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'Segmenter']) {
            const C = Intl[name], p = C.prototype, value = new C('en');
            const descriptor = Object.getOwnPropertyDescriptor(C, 'prototype');
            console.log(name, value instanceof C, Object.getPrototypeOf(value) === p,
                Object.getPrototypeOf(p) === Object.prototype, p.constructor === C,
                Object.getOwnPropertyNames(value).length, Object.getOwnPropertySymbols(value).length,
                Object.prototype.toString.call(p), descriptor.writable,
                descriptor.enumerable, descriptor.configurable);
        }
    "#;
    let expected = [
        "NumberFormat true true true true 0 0 [object Intl.NumberFormat] false false false",
        "DateTimeFormat true true true true 0 0 [object Intl.DateTimeFormat] false false false",
        "Collator true true true true 0 0 [object Intl.Collator] false false false",
        "PluralRules true true true true 0 0 [object Intl.PluralRules] false false false",
        "RelativeTimeFormat true true true true 0 0 [object Intl.RelativeTimeFormat] false false false",
        "ListFormat true true true true 0 0 [object Intl.ListFormat] false false false",
        "Segmenter true true true true 0 0 [object Intl.Segmenter] false false false",
    ].join("\n");
    assert_eq!(console_output(source).unwrap(), expected);
}

#[test]
fn intl_bound_accessors_preserve_identity_and_receiver() {
    let source = r#"
        for (const entry of [['NumberFormat', 'format', 1], ['DateTimeFormat', 'format', 1], ['Collator', 'compare', 2]]) {
            const C = Intl[entry[0]], key = entry[1], a = new C('en'), b = new C('en');
            const descriptor = Object.getOwnPropertyDescriptor(C.prototype, key), f = a[key];
            f.marker = 23;
            console.log(entry[0], f === a[key], f !== b[key], descriptor.get.call(a) === f,
                a[key].marker, f.name === '', f.length === entry[2],
                descriptor.get.name, descriptor.get.length, descriptor.set === undefined,
                descriptor.enumerable, descriptor.configurable, a.hasOwnProperty(key),
                f.hasOwnProperty('prototype'));
        }
        const nf = new Intl.NumberFormat('en-US'), format = nf.format;
        console.log(format.call(new Intl.NumberFormat('de-DE'), 1234.5));
        const dtf = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC' }), dateFormat = dtf.format;
        console.log(dateFormat.call(new Intl.DateTimeFormat('de-DE'), 0));
        const collator = new Intl.Collator('en', { sensitivity: 'base' }), compare = collator.compare;
        console.log(compare.call(new Intl.Collator('en', { sensitivity: 'variant' }), 'a', 'A'));
    "#;
    assert_eq!(
        console_output(source).unwrap(),
        "NumberFormat true true true 23 true true get format 0 true false true false false\n\
         DateTimeFormat true true true 23 true true get format 0 true false true false false\n\
         Collator true true true 23 true true get compare 0 true false true false false\n\
         1,234.5\n1/1/1970\n0"
    );
}

#[test]
fn intl_prototype_methods_require_authentic_matching_receivers() {
    let source = r#"
        function attempt(f) { try { f(); return 'accepted'; } catch (e) { return e.name; } }
        for (const name of ['NumberFormat', 'DateTimeFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'Segmenter']) {
            const C = Intl[name], a = new C('en'), method = C.prototype.resolvedOptions;
            console.log(name, method === a.resolvedOptions,
                method.call(a).locale === a.resolvedOptions().locale, method.length,
                attempt(() => method()), attempt(() => method.call(C.prototype)),
                attempt(() => method.call(Object.create(C.prototype))),
                attempt(() => method.call(new Proxy(a, {}))),
                attempt(() => method.call({ [Symbol.toStringTag]: 'Intl.' + name })));
        }
        const dtf = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC' });
        console.log(Intl.DateTimeFormat.prototype.formatToParts.call(dtf, 0).map(p => p.value).join(''));
        console.log(Intl.PluralRules.prototype.select.call(new Intl.PluralRules('en'), 1));
        console.log(Intl.RelativeTimeFormat.prototype.format.call(new Intl.RelativeTimeFormat('en'), -1, 'day'));
        console.log(Intl.ListFormat.prototype.format.call(new Intl.ListFormat('en'), ['a', 'b']));
        console.log([...Intl.Segmenter.prototype.segment.call(new Intl.Segmenter('en'), 'ab')].length);
        let conversions = 0;
        const value = { valueOf() { conversions++; return 0; } };
        console.log(attempt(() => Intl.DateTimeFormat.prototype.formatToParts.call(new Intl.NumberFormat('en'), value)), conversions);
        console.log(attempt(() => Object.getOwnPropertyDescriptor(Intl.Collator.prototype, 'compare').get.call(dtf)));
    "#;
    let mut expected = Vec::new();
    for name in [
        "NumberFormat",
        "DateTimeFormat",
        "Collator",
        "PluralRules",
        "RelativeTimeFormat",
        "ListFormat",
        "Segmenter",
    ] {
        expected.push(format!(
            "{name} true true 0 TypeError TypeError TypeError TypeError TypeError"
        ));
    }
    expected.extend(
        [
            "1/1/1970",
            "one",
            "1 day ago",
            "a and b",
            "2",
            "TypeError 0",
            "TypeError",
        ]
        .map(str::to_string),
    );
    assert_eq!(console_output(source).unwrap(), expected.join("\n"));
}

#[test]
fn intl_construction_preserves_new_target_prototypes_and_order() {
    let source = r#"
        for (const name of ['NumberFormat', 'DateTimeFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'Segmenter']) {
            const C = Intl[name];
            class Derived extends C {}
            const derived = new Derived('en');
            function Target() {}
            Target.prototype = { marker: name };
            const replacement = Reflect.construct(C, ['en'], Target);
            Target.prototype = 7;
            const fallback = Reflect.construct(C, ['en'], Target);
            console.log(name, derived instanceof Derived, derived instanceof C,
                derived.constructor === Derived, replacement.marker === name,
                typeof C.prototype.resolvedOptions.call(replacement).locale,
                Object.getPrototypeOf(fallback) === C.prototype);
        }
        const order = [];
        const target = new Proxy(function () {}, { get(target, key) { order.push(key); return target[key]; } });
        const options = { get localeMatcher() { order.push('options'); return 'lookup'; } };
        Reflect.construct(Intl.NumberFormat, ['en', options], target);
        console.log(order.join(','));
    "#;
    let expected = [
        "NumberFormat",
        "DateTimeFormat",
        "Collator",
        "PluralRules",
        "RelativeTimeFormat",
        "ListFormat",
        "Segmenter",
    ]
    .map(|name| format!("{name} true true true true string true"))
    .into_iter()
    .chain(["prototype,options".to_string()])
    .collect::<Vec<_>>()
    .join("\n");
    assert_eq!(console_output(source).unwrap(), expected);
}

#[test]
fn intl_constructor_callability_matches_each_service() {
    let source = r#"
        for (const name of ['NumberFormat', 'DateTimeFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'Segmenter']) {
            const C = Intl[name];
            try { console.log(name, C('en') instanceof C); }
            catch (error) { console.log(name, error.name); }
        }
    "#;
    assert_eq!(
        console_output(source).unwrap(),
        "NumberFormat true\nDateTimeFormat true\nCollator true\nPluralRules TypeError\nRelativeTimeFormat TypeError\nListFormat TypeError\nSegmenter TypeError"
    );
}

#[test]
fn number_format_parts_match_node_for_supported_locales_and_styles() {
    // These exact source programs and outputs were checked on Node v24.22.3.
    let source = r#"
        function show(locale, options, value) {
            const formatter = new Intl.NumberFormat(locale, options);
            const parts = formatter.formatToParts(value);
            console.log(parts.map(p => p.type + '=' + p.value).join('|'),
                parts.map(p => p.value).join('') === formatter.format(value));
        }
        show('en-US', {}, -1234567.891);
        show('de-DE', {}, 1234567.891);
        show('en-IN', {}, 1234567.891);
        show('en-GB', { style: 'currency', currency: 'USD' }, -1234.5);
        show('ja-JP', { style: 'currency', currency: 'JPY' }, 1234.5);
        show('en-US', { style: 'percent', signDisplay: 'always' }, 0.256);
        show('de-DE', { useGrouping: false, minimumFractionDigits: 2 }, 1234.5);
        show('en-US', { maximumSignificantDigits: 3 }, 999.95);
    "#;
    let expected = [
        "minusSign=-|integer=1|group=,|integer=234|group=,|integer=567|decimal=.|fraction=891 true",
        "integer=1|group=.|integer=234|group=.|integer=567|decimal=,|fraction=891 true",
        "integer=12|group=,|integer=34|group=,|integer=567|decimal=.|fraction=891 true",
        "minusSign=-|currency=US$|integer=1|group=,|integer=234|decimal=.|fraction=50 true",
        "currency=￥|integer=1|group=,|integer=235 true",
        "plusSign=+|integer=26|percentSign=% true",
        "integer=1234|decimal=,|fraction=50 true",
        "integer=1|group=,|integer=000 true",
    ]
    .join("\n");
    assert_eq!(console_output(source).unwrap(), expected);
}

#[test]
fn number_format_parts_preserve_signed_zero_and_nonfinite_types() {
    let source = r#"
        const formatter = new Intl.NumberFormat('en-US');
        const show = parts => parts.map(p => p.type + '=' + p.value).join('|');
        for (const value of [-0, -0.0001, NaN, Infinity, -Infinity, undefined]) {
            console.log(show(formatter.formatToParts(value)));
        }
        console.log(show(new Intl.NumberFormat('en-US', { signDisplay: 'always' }).formatToParts(NaN)));
        console.log(show(new Intl.NumberFormat('en-US', { signDisplay: 'exceptZero' }).formatToParts(-0.0001)));
        console.log(show(new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).formatToParts(NaN)));
        console.log(show(new Intl.NumberFormat('en-US', { style: 'percent' }).formatToParts(Infinity)));
    "#;
    assert_eq!(
        console_output(source).unwrap(),
        "minusSign=-|integer=0\nminusSign=-|integer=0\nnan=NaN\ninfinity=∞\nminusSign=-|infinity=∞\nnan=NaN\nplusSign=+|nan=NaN\ninteger=0\ncurrency=$|nan=NaN\ninfinity=∞|percentSign=%"
    );
}

#[test]
fn number_format_parts_are_unbound_and_validate_brand_before_conversion() {
    let source = r#"
        const formatter = new Intl.NumberFormat('en-US');
        const other = new Intl.NumberFormat('de-DE');
        const method = Intl.NumberFormat.prototype.formatToParts;
        const descriptor = Object.getOwnPropertyDescriptor(Intl.NumberFormat.prototype, 'formatToParts');
        console.log(method === formatter.formatToParts, method.name, method.length,
            descriptor.writable, descriptor.enumerable, descriptor.configurable,
            method.hasOwnProperty('prototype'));
        console.log(method.call(other, 1234.5).map(p => p.value).join(''));
        let conversions = 0;
        const input = { valueOf() { conversions++; return 0; } };
        for (const receiver of [undefined, null, {}, Intl.NumberFormat.prototype,
            Object.create(Intl.NumberFormat.prototype), new Proxy(formatter, {}),
            new Intl.DateTimeFormat('en'), { [Symbol.toStringTag]: 'Intl.NumberFormat' }]) {
            try { method.call(receiver, input); console.log('missed'); }
            catch (error) { console.log(error.name, conversions); }
        }
        const before = formatter.formatToParts(1), after = formatter.formatToParts(1);
        before[0].value = 'changed';
        console.log(before !== after, before[0] !== after[0], after[0].value,
            Object.keys(after[0]).join(','), Object.getPrototypeOf(after[0]) === Object.prototype);
    "#;
    let expected = [
        "true formatToParts 1 true false true false",
        "1.234,5",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "TypeError 0",
        "true true 1 type,value true",
    ]
    .join("\n");
    assert_eq!(console_output(source).unwrap(), expected);
}

#[test]
fn number_format_parts_observe_numeric_conversion_and_preserve_abrupt_completion() {
    let source = r#"
        const formatter = new Intl.NumberFormat('en-US');
        const log = [];
        const value = {
            [Symbol.toPrimitive](hint) { log.push(hint); return -0; },
            valueOf() { log.push('unreachable'); return 1; }
        };
        console.log(formatter.formatToParts(value).map(p => p.type + '=' + p.value).join('|'), log.join(','));
        const marker = {};
        const throwing = { valueOf() { log.push('throw'); throw marker; }, toString() { log.push('unreachable'); return '3'; } };
        try { formatter.formatToParts(throwing); } catch (error) { console.log(error === marker, log.join(',')); }
        try { formatter.formatToParts(Symbol('number')); } catch (error) { console.log(error.name); }
        console.log(formatter.formatToParts({ valueOf() { return {}; }, toString() { return '1234.5'; } }).map(p => p.value).join(''));
        console.log(formatter.formatToParts(2).map(p => p.value).join(''));
    "#;
    assert_eq!(
        console_output(source).unwrap(),
        "minusSign=-|integer=0 number\ntrue number,throw\nTypeError\n1,234.5\n2"
    );
}
