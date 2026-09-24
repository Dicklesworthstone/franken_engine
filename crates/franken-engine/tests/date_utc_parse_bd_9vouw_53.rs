//! bd-9vouw.53 follow-up: `Date.UTC` and `Date.parse` (ES2020 20.4.3).
//!
//! Before this both were `undefined`. Date-only strings are UTC; date-time
//! strings without an offset are local time, which is UTC in this hermetic
//! engine. Expected strings are what Node v22.2.0 prints for the same
//! programs under `TZ=UTC`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node_utc: &str) {
    assert_eq!(
        eval_to_string(source),
        node_utc,
        "`{source}` must match Node v22.2.0 (TZ=UTC)"
    );
}

#[test]
fn date_utc() {
    check(
        "[Date.UTC(2020, 1, 29, 12), Date.UTC(2020), Date.UTC(99, 0), \
         Date.UTC(2020, 11, 31, 23, 59, 59, 999)].join();",
        "1582977600000,1577836800000,915148800000,1609459199999",
    );
    check(
        "var d = new Date(Date.UTC(2020, 1, 29, 12, 0, 0)); \
         d.toISOString() + ' ' + d.getUTCDay() + ' ' + Date.parse('2020-01-01T00:00:00Z');",
        "2020-02-29T12:00:00.000Z 6 1577836800000",
    );
}

#[test]
fn date_parse_forms() {
    check(
        "[Date.parse('2020-01-01T00:00:00Z'), Date.parse('2020-02-29'), Date.parse('2020-02'), \
         Date.parse('2020'), Date.parse('2020-01-01T12:30')].join();",
        "1577836800000,1582934400000,1580515200000,1577836800000,1577881800000",
    );
    check(
        "[Date.parse('2020-01-01T00:00:00.5+01:00'), Date.parse('+010000-01-01T00:00:00Z'), \
         Date.parse('Thu, 01 Jan 1970 00:00:00 GMT'), isNaN(Date.parse('garbage'))].join();",
        "1577833200500,253402300800000,0,true",
    );
    // toISOString and toUTCString round-trip through Date.parse.
    check(
        "Date.parse(new Date(1582977600123).toISOString()) + ':' + \
         Date.parse(new Date(0).toUTCString());",
        "1582977600123:0",
    );
}
