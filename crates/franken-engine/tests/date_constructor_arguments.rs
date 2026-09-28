//! ES2020 20.4.2: `new Date(value)` and `new Date(year, month, ...)`.
//!
//! The Date constructor only understood a number: every string gave an
//! invalid date (`new Date('2020-03-04')`, `new Date('2020-03-04T05:06:07Z')`
//! — the JSON timestamp form — included, although Date.parse already parsed
//! them), a Date argument gave NaN instead of a copy, `new Date(2020, 2, 4)`
//! was read as 2020 milliseconds, and the time value was not TimeClipped
//! (`new Date(1.7).getTime()` was 1.7). Local time is UTC in FrankenEngine,
//! so the expected strings are Node v22.2.0's output under TZ=UTC.
//!
//! No-claim: string forms outside the ES2020 date-time string format and the
//! toUTCString form (`March 4, 2020`, `2020/03/04`, toString output) are
//! implementation-defined and still give an invalid date here.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

const ISO: &str = "var iso = d => isNaN(d.getTime()) ? 'NaN' : d.toISOString();\n";

#[test]
fn string_arguments_are_parsed_like_date_parse() {
    let source = format!(
        "{ISO}['2020-03-04T05:06:07Z', '2020-03-04T05:06:07.5Z', '2020-03-04', '2020-03', '2020', \
         '2020-03-04T05:06:07+02:00', '2020-03-04T05:06', 'Thu, 01 Jan 1970 00:00:00 GMT', \
         'garbage', ''].map(s => iso(new Date(s))).join('|');"
    );
    assert_eq!(
        eval(&source),
        "2020-03-04T05:06:07.000Z|2020-03-04T05:06:07.500Z|2020-03-04T00:00:00.000Z|\
         2020-03-01T00:00:00.000Z|2020-01-01T00:00:00.000Z|2020-03-04T03:06:07.000Z|\
         2020-03-04T05:06:00.000Z|1970-01-01T00:00:00.000Z|NaN|NaN"
    );
}

#[test]
fn date_copies_components_time_clip_and_to_primitive() {
    let source = format!(
        "{ISO}var t; try {{ new Date(Symbol()); t = 'no throw'; }} catch (e) {{ \
         t = e instanceof TypeError ? 'TypeError' : 'other'; }}\n\
         [new Date(new Date(5)).getTime(), iso(new Date(2020, 2, 4)), \
         new Date(99, 0).getUTCFullYear(), iso(new Date(2020, 0, 31, 25)), \
         new Date(1.7).getTime(), new Date({{valueOf() {{ return 42; }}}}).getTime(), \
         new Date(8.64e15 + 1).getTime(), t, Date.parse('2020-03-04T05:06:07Z')].join('|');"
    );
    assert_eq!(
        eval(&source),
        "5|2020-03-04T00:00:00.000Z|1999|2020-02-01T01:00:00.000Z|1|42|NaN|TypeError|1583298367000"
    );
}
